//! Built-in RDP client: the remote desktop is drawn inside a Shellyard tab.
//!
//! The protocol is IronRDP's (connector, session, graphics). This file drives
//! it on a background thread and connects it to egui: frames become a texture,
//! egui keyboard and mouse events become RDP fast-path input.
//!
//! Server certificates: IronRDP's TLS layer accepts any certificate, so this
//! driver pins one per host instead (trust on first use, like SSH's
//! known_hosts). After the TLS handshake, and before CredSSP sends anything
//! derived from the password, the certificate's SHA-256 fingerprint is
//! compared with the one saved for the host. An unknown or changed certificate
//! stops the connection until the user accepts it in the tab.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, FontId, Key, Rect, RichText, Sense, Stroke, Vec2};
use ironrdp::connector::connection_activation::ConnectionActivationState;
use ironrdp::connector::{self, ClientConnector, ConnectionResult, ConnectorResult, Credentials, DesktopSize};
use ironrdp::core::WriteBuf;
use ironrdp::displaycontrol::client::DisplayControlClient;
use ironrdp::displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp::input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp::pdu::input::fast_path::FastPathInputEvent;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{fast_path, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::FramedWrite as _;
use smallvec::SmallVec;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::theme;

/// What to connect to.
pub struct Params {
    pub host: String,
    pub port: u16,
    /// `user`, `DOMAIN\user` or `user@domain`.
    pub user: String,
    pub password: Zeroizing<String>,
    /// SHA-256 fingerprint saved for this host, if any.
    pub known_fingerprint: Option<String>,
}

#[derive(Clone)]
enum Status {
    Connecting,
    /// Waiting for the user to accept this certificate.
    Trust { fingerprint: String, changed: bool },
    Connected,
    Ended { message: String, error: bool },
}

struct Frame {
    rgba: Vec<u8>,
    width: usize,
    height: usize,
}

struct Shared {
    status: Status,
    frame: Option<Frame>,
    frame_new: bool,
    trust_reply: Option<oneshot::Sender<bool>>,
    /// A fingerprint the user accepted, for the app to save on the host.
    accepted: Option<String>,
}

enum Input {
    Fast(SmallVec<[FastPathInputEvent; 2]>),
    Resize { width: u16, height: u16, scale: u32 },
    Close,
}

pub struct RdpView {
    id: egui::Id,
    pub title: String,
    shared: Arc<Mutex<Shared>>,
    tx: mpsc::UnboundedSender<Input>,
    texture: Option<egui::TextureHandle>,
    frame_size: (usize, usize),
    keys: Database,
    /// Modifier keys currently held down on the remote side.
    held: egui::Modifiers,
    /// Last size asked of the server, and when the view last changed size.
    asked_size: (u16, u16),
    resized_at: Option<Instant>,
    /// Enter (or the button) after the session ended: the owner reconnects.
    pub restart_requested: bool,
}

impl RdpView {
    pub fn connect(params: Params, title: String, ctx: &egui::Context) -> Self {
        let shared = Arc::new(Mutex::new(Shared { status: Status::Connecting, frame: None, frame_new: false, trust_reply: None, accepted: None }));
        let (tx, rx) = mpsc::unbounded_channel();
        // Start at the window's size in physical pixels; the tab resizes it later.
        let ppp = ctx.pixels_per_point();
        let screen = ctx.screen_rect().size() * ppp;
        let size = desktop_size(screen.x as u32, screen.y as u32);
        let scale = (ppp * 100.0).round() as u32;
        let (s, repaint) = (shared.clone(), ctx.clone());
        let spawned = std::thread::Builder::new().name("rdp".into()).spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())
                .and_then(|rt| rt.block_on(run(params, size, scale, s.clone(), rx, repaint.clone())));
            let (message, error) = match result {
                Ok(reason) => (reason, false),
                Err(e) => (e, true),
            };
            if let Ok(mut sh) = s.lock() {
                sh.status = Status::Ended { message, error };
                sh.trust_reply = None;
            }
            repaint.request_repaint();
        });
        if let Err(e) = spawned {
            if let Ok(mut sh) = shared.lock() {
                sh.status = Status::Ended { message: format!("cannot start the RDP thread: {e}"), error: true };
            }
        }
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            id: egui::Id::new(("rdp", n)),
            title,
            shared,
            tx,
            texture: None,
            frame_size: (0, 0),
            keys: Database::new(),
            held: egui::Modifiers::NONE,
            asked_size: size,
            resized_at: None,
            restart_requested: false,
        }
    }

    pub fn focus(&self, ctx: &egui::Context) {
        ctx.memory_mut(|m| m.request_focus(self.id));
    }

    pub fn exited(&self) -> bool {
        self.shared.lock().is_ok_and(|s| matches!(s.status, Status::Ended { .. }))
    }

    /// A certificate fingerprint the user just accepted (taken once).
    pub fn take_accepted_fingerprint(&self) -> Option<String> {
        self.shared.lock().ok().and_then(|mut s| s.accepted.take())
    }

    /// Types `text` on the remote side (used for pasting the local clipboard).
    pub fn type_text(&mut self, text: &str) {
        let mut ops: Vec<Operation> = Vec::new();
        for c in text.chars() {
            let c = if c == '\n' { '\r' } else { c };
            if c == '\r' {
                ops.extend([Operation::KeyPressed(Scancode::from_u8(false, 0x1C)), Operation::KeyReleased(Scancode::from_u8(false, 0x1C))]);
            } else if !c.is_control() {
                ops.extend([Operation::UnicodeKeyPressed(c), Operation::UnicodeKeyReleased(c)]);
            }
        }
        self.send_ops(ops);
    }

    fn send_ops(&mut self, ops: Vec<Operation>) {
        if ops.is_empty() {
            return;
        }
        let events = self.keys.apply(ops);
        if !events.is_empty() {
            let _ = self.tx.send(Input::Fast(events));
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        let rect = ui.available_rect_before_wrap();
        ui.allocate_rect(rect, Sense::hover());
        let resp = ui.interact(rect, self.id, Sense::click_and_drag());
        ui.painter().rect_filled(rect, 0.0, Color32::from_rgb(0x0d, 0x10, 0x15));

        let (status, frame) = {
            let mut sh = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            let frame = if sh.frame_new {
                sh.frame_new = false;
                sh.frame.as_ref().map(|f| egui::ColorImage::from_rgba_unmultiplied([f.width, f.height], &f.rgba))
            } else {
                None
            };
            (sh.status.clone(), frame)
        };
        if let Some(image) = frame {
            self.frame_size = (image.size[0], image.size[1]);
            match &mut self.texture {
                Some(t) => t.set(image, egui::TextureOptions::LINEAR),
                None => self.texture = Some(ui.ctx().load_texture(format!("rdp-{:?}", self.id), image, egui::TextureOptions::LINEAR)),
            }
        }

        match status {
            Status::Connected => self.show_desktop(ui, &resp, rect),
            Status::Connecting => {
                centered(ui, rect, |ui| {
                    ui.spinner();
                    ui.label(RichText::new(format!("Connecting to {}…", self.title)).color(theme::MUTED));
                });
            }
            Status::Trust { fingerprint, changed } => self.show_trust(ui, rect, &fingerprint, changed),
            Status::Ended { message, error } => {
                if self.texture.is_some() && !error {
                    self.paint_frame(ui, rect);
                }
                if resp.clicked() {
                    resp.request_focus();
                }
                let enter = resp.has_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                centered(ui, rect, |ui| {
                    let (glyph, color) = if error { (egui_phosphor::regular::WARNING_CIRCLE, theme::DANGER) } else { (egui_phosphor::regular::PLUG, theme::MUTED) };
                    ui.label(RichText::new(format!("{glyph}  {}", if error { "Could not connect" } else { "Session ended" })).size(15.0).strong().color(color));
                    ui.label(RichText::new(message).color(theme::MUTED));
                    ui.add_space(6.0);
                    if ui.button("Reconnect  (Enter)").clicked() || enter {
                        self.restart_requested = true;
                    }
                });
            }
        }
    }

    fn show_trust(&mut self, ui: &mut egui::Ui, rect: Rect, fingerprint: &str, changed: bool) {
        let mut answer: Option<bool> = None;
        centered(ui, rect, |ui| {
            ui.set_max_width(520.0);
            if changed {
                ui.label(RichText::new(format!("{}  The server's certificate has changed", egui_phosphor::regular::WARNING)).size(15.0).strong().color(theme::DANGER));
                ui.label(RichText::new("This happens when the certificate was renewed, but it is also what an attacker in the middle looks like. Accept only if you expected it.").color(theme::MUTED));
            } else {
                ui.label(RichText::new(format!("{}  First connection to {}", egui_phosphor::regular::SHIELD_CHECK, self.title)).size(15.0).strong().color(theme::TEXT));
                ui.label(RichText::new("Check that this fingerprint matches the server's certificate (on the server: certlm.msc → Remote Desktop, or ask its admin). It is saved, and you will be warned if it changes.").color(theme::MUTED));
            }
            ui.add_space(6.0);
            ui.label(RichText::new("SHA-256").size(11.0).color(theme::FAINT));
            ui.label(RichText::new(fingerprint).monospace().size(11.5).color(theme::TEXT));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if crate::widgets::primary_button(ui, if changed { "  Accept new certificate  " } else { "  Trust and connect  " }).clicked() {
                    answer = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    answer = Some(false);
                }
            });
        });
        if let Some(yes) = answer {
            if let Ok(mut sh) = self.shared.lock() {
                if let Some(tx) = sh.trust_reply.take() {
                    let _ = tx.send(yes);
                }
                if yes {
                    sh.accepted = Some(fingerprint.to_string());
                }
            }
        }
    }

    /// Where the frame is drawn: scaled to fit, centred, aspect kept.
    fn frame_rect(&self, rect: Rect) -> Option<Rect> {
        let (w, h) = self.frame_size;
        if w == 0 || h == 0 {
            return None;
        }
        let scale = (rect.width() / w as f32).min(rect.height() / h as f32);
        Some(Rect::from_center_size(rect.center(), Vec2::new(w as f32, h as f32) * scale))
    }

    fn paint_frame(&self, ui: &egui::Ui, rect: Rect) {
        if let (Some(tex), Some(r)) = (&self.texture, self.frame_rect(rect)) {
            ui.painter().image(tex.id(), r, Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)), Color32::WHITE);
        }
    }

    fn show_desktop(&mut self, ui: &mut egui::Ui, resp: &egui::Response, rect: Rect) {
        self.paint_frame(ui, rect);
        if resp.clicked() || resp.drag_started() {
            resp.request_focus();
        }
        self.follow_size(ui, rect);
        let focused = resp.has_focus();
        if focused {
            ui.memory_mut(|m| m.set_focus_lock_filter(self.id, egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true }));
            ui.painter().rect_stroke(rect.shrink(0.5), 0.0, Stroke::new(1.0_f32, theme::ACCENT.gamma_multiply(0.4)));
        } else if self.held != egui::Modifiers::NONE || !self.keys.keyboard_state().not_any() {
            // Focus moved away: release everything so no key stays stuck down remotely.
            let events = self.keys.release_all();
            let _ = self.tx.send(Input::Fast(events));
            self.held = egui::Modifiers::NONE;
        }
        if resp.hovered() {
            // The server draws the pointer into the picture.
            ui.ctx().set_cursor_icon(egui::CursorIcon::None);
        }
        let Some(frame) = self.frame_rect(rect) else { return };
        let (fw, fh) = self.frame_size;
        let to_remote = |p: egui::Pos2| MousePosition {
            x: (((p.x - frame.min.x) / frame.width()).clamp(0.0, 1.0) * (fw.saturating_sub(1)) as f32) as u16,
            y: (((p.y - frame.min.y) / frame.height()).clamp(0.0, 1.0) * (fh.saturating_sub(1)) as f32) as u16,
        };
        let (events, mods) = ui.input(|i| (i.events.clone(), i.modifiers));
        let mut ops: Vec<Operation> = Vec::new();
        for ev in &events {
            match ev {
                egui::Event::PointerMoved(p) if resp.hovered() || resp.dragged() => ops.push(Operation::MouseMove(to_remote(*p))),
                egui::Event::PointerButton { pos, button, pressed, .. } if resp.hovered() || !*pressed => {
                    let b = match button {
                        egui::PointerButton::Primary => MouseButton::Left,
                        egui::PointerButton::Secondary => MouseButton::Right,
                        egui::PointerButton::Middle => MouseButton::Middle,
                        egui::PointerButton::Extra1 => MouseButton::X1,
                        egui::PointerButton::Extra2 => MouseButton::X2,
                    };
                    ops.push(Operation::MouseMove(to_remote(*pos)));
                    ops.push(if *pressed { Operation::MouseButtonPressed(b) } else { Operation::MouseButtonReleased(b) });
                }
                egui::Event::MouseWheel { unit, delta, .. } if resp.hovered() => {
                    // Windows counts 120 units per wheel notch.
                    let per = match unit {
                        egui::MouseWheelUnit::Line => 120.0,
                        egui::MouseWheelUnit::Page => 360.0,
                        egui::MouseWheelUnit::Point => 4.0,
                    };
                    for (is_vertical, d) in [(true, delta.y), (false, -delta.x)] {
                        let units = (d * per).round().clamp(-1200.0, 1200.0) as i16;
                        if units != 0 {
                            ops.push(Operation::WheelRotations(WheelRotations { is_vertical, rotation_units: units }));
                        }
                    }
                }
                _ => {}
            }
        }
        if focused {
            self.sync_modifiers(mods, &mut ops);
            for ev in &events {
                match ev {
                    egui::Event::Key { key, physical_key, pressed, .. } => {
                        if let Some(sc) = scancode(physical_key.unwrap_or(*key)) {
                            ops.push(if *pressed { Operation::KeyPressed(sc) } else { Operation::KeyReleased(sc) });
                        }
                    }
                    // egui turns ⌘/Ctrl + C, X into these and swallows the key itself.
                    egui::Event::Copy => ops.extend(tap(0x2E)),
                    egui::Event::Cut => ops.extend(tap(0x2D)),
                    egui::Event::Paste(text) => {
                        // Type the local clipboard with modifiers up, then put them back.
                        let held = self.held;
                        let mut up = Vec::new();
                        self.sync_modifiers(egui::Modifiers::NONE, &mut up);
                        ops.extend(up);
                        self.send_ops(std::mem::take(&mut ops));
                        self.type_text(text);
                        self.sync_modifiers(held, &mut ops);
                    }
                    _ => {}
                }
            }
        }
        self.send_ops(ops);
    }

    /// Presses or releases Ctrl, Shift and Alt on the remote side to match.
    /// On macOS ⌘ acts as Ctrl, so ⌘C / ⌘V do what they do on the Mac.
    fn sync_modifiers(&mut self, now: egui::Modifiers, ops: &mut Vec<Operation>) {
        let ctrl = |m: egui::Modifiers| m.ctrl || m.mac_cmd;
        for (was, is, code) in [(ctrl(self.held), ctrl(now), 0x1D), (self.held.shift, now.shift, 0x2A), (self.held.alt, now.alt, 0x38)] {
            if was != is {
                let sc = Scancode::from_u8(false, code);
                ops.push(if is { Operation::KeyPressed(sc) } else { Operation::KeyReleased(sc) });
            }
        }
        self.held = now;
    }

    /// Asks the server for a new desktop size once the tab has kept its size for a moment.
    fn follow_size(&mut self, ui: &egui::Ui, rect: Rect) {
        let ppp = ui.ctx().pixels_per_point();
        let want = desktop_size((rect.width() * ppp) as u32, (rect.height() * ppp) as u32);
        if want == self.asked_size {
            self.resized_at = None;
            return;
        }
        let since = *self.resized_at.get_or_insert_with(Instant::now);
        if since.elapsed() > Duration::from_millis(400) {
            self.asked_size = want;
            self.resized_at = None;
            let _ = self.tx.send(Input::Resize { width: want.0, height: want.1, scale: (ppp * 100.0).round() as u32 });
        } else {
            ui.ctx().request_repaint_after(Duration::from_millis(450));
        }
    }
}

impl Drop for RdpView {
    fn drop(&mut self) {
        let _ = self.tx.send(Input::Close);
        if let Ok(mut sh) = self.shared.lock() {
            if let Some(tx) = sh.trust_reply.take() {
                let _ = tx.send(false);
            }
        }
    }
}

fn centered(ui: &mut egui::Ui, rect: Rect, add: impl FnOnce(&mut egui::Ui)) {
    let inner = Rect::from_center_size(rect.center(), Vec2::new(rect.width().min(560.0), rect.height().min(260.0)));
    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(inner).layout(egui::Layout::top_down(egui::Align::Center)));
    child.style_mut().override_font_id = Some(FontId::proportional(13.0));
    add(&mut child);
}

fn tap(code: u8) -> [Operation; 2] {
    let sc = Scancode::from_u8(false, code);
    [Operation::KeyPressed(sc), Operation::KeyReleased(sc)]
}

/// A size the server accepts: even width, 200..=8192 pixels each way.
fn desktop_size(w: u32, h: u32) -> (u16, u16) {
    let (w, h) = MonitorLayoutEntry::adjust_display_size(w.clamp(200, 8192), h.clamp(200, 8192));
    (w as u16, h as u16)
}

/// SHA-256 of the certificate, as colon-separated hex (like Windows shows it).
pub fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// PC/AT set-1 scancodes for egui's keys (by physical position).
fn scancode(key: Key) -> Option<Scancode> {
    use Key::*;
    let (ext, code) = match key {
        Escape => (false, 0x01),
        Num1 => (false, 0x02),
        Num2 => (false, 0x03),
        Num3 => (false, 0x04),
        Num4 => (false, 0x05),
        Num5 => (false, 0x06),
        Num6 => (false, 0x07),
        Num7 => (false, 0x08),
        Num8 => (false, 0x09),
        Num9 => (false, 0x0A),
        Num0 => (false, 0x0B),
        Minus => (false, 0x0C),
        Equals | Plus => (false, 0x0D),
        Backspace => (false, 0x0E),
        Tab => (false, 0x0F),
        Q => (false, 0x10),
        W => (false, 0x11),
        E => (false, 0x12),
        R => (false, 0x13),
        T => (false, 0x14),
        Y => (false, 0x15),
        U => (false, 0x16),
        I => (false, 0x17),
        O => (false, 0x18),
        P => (false, 0x19),
        OpenBracket => (false, 0x1A),
        CloseBracket => (false, 0x1B),
        Enter => (false, 0x1C),
        A => (false, 0x1E),
        S => (false, 0x1F),
        D => (false, 0x20),
        F => (false, 0x21),
        G => (false, 0x22),
        H => (false, 0x23),
        J => (false, 0x24),
        K => (false, 0x25),
        L => (false, 0x26),
        Semicolon | Colon => (false, 0x27),
        Quote => (false, 0x28),
        Backtick => (false, 0x29),
        Backslash | Pipe => (false, 0x2B),
        Z => (false, 0x2C),
        X => (false, 0x2D),
        C => (false, 0x2E),
        V => (false, 0x2F),
        B => (false, 0x30),
        N => (false, 0x31),
        M => (false, 0x32),
        Comma => (false, 0x33),
        Period => (false, 0x34),
        Slash | Questionmark => (false, 0x35),
        Space => (false, 0x39),
        F1 => (false, 0x3B),
        F2 => (false, 0x3C),
        F3 => (false, 0x3D),
        F4 => (false, 0x3E),
        F5 => (false, 0x3F),
        F6 => (false, 0x40),
        F7 => (false, 0x41),
        F8 => (false, 0x42),
        F9 => (false, 0x43),
        F10 => (false, 0x44),
        F11 => (false, 0x57),
        F12 => (false, 0x58),
        Home => (true, 0x47),
        ArrowUp => (true, 0x48),
        PageUp => (true, 0x49),
        ArrowLeft => (true, 0x4B),
        ArrowRight => (true, 0x4D),
        End => (true, 0x4F),
        ArrowDown => (true, 0x50),
        PageDown => (true, 0x51),
        Insert => (true, 0x52),
        Delete => (true, 0x53),
        _ => return None,
    };
    Some(Scancode::from_u8(ext, code))
}

// ---------------------------------------------------------------------------
// Connection (background thread)

/// CredSSP asks for a network client only for Kerberos (KDC lookups), which
/// is not used: sign-in is NTLM against the server itself.
struct NoNetwork;

impl ironrdp_tokio::NetworkClient for NoNetwork {
    async fn send(&mut self, _: &connector::sspi::generator::NetworkRequest) -> ConnectorResult<Vec<u8>> {
        Err(connector::general_err!("Kerberos is not supported; sign in with a local or domain user name and password"))
    }
}

/// `DOMAIN\user` → (user, Some(DOMAIN)); `user@domain` stays as is (NTLM accepts UPNs).
fn split_domain(user: &str) -> (String, Option<String>) {
    match user.split_once('\\') {
        Some((domain, name)) if !domain.is_empty() => (name.to_string(), Some(domain.to_string())),
        _ => (user.to_string(), None),
    }
}

fn connector_config(p: &Params, size: (u16, u16), scale: u32) -> connector::Config {
    use ironrdp::pdu::rdp::capability_sets::{client_codecs_capabilities, MajorPlatformType};
    use ironrdp::pdu::rdp::client_info::{CompressionType, PerformanceFlags, TimezoneInfo};
    let (username, domain) = split_domain(&p.user);
    let platform = if cfg!(target_os = "macos") { MajorPlatformType::MACINTOSH } else { MajorPlatformType::UNIX };
    connector::Config {
        credentials: Credentials::UsernamePassword { username, password: p.password.to_string() },
        domain,
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: ironrdp::pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize { width: size.0, height: size.1 },
        desktop_scale_factor: scale,
        bitmap: Some(connector::BitmapConfig {
            color_depth: 32,
            lossy_compression: true,
            codecs: client_codecs_capabilities(&[]).unwrap_or_default(),
        }),
        client_build: 0,
        client_name: "Shellyard".into(),
        client_dir: String::new(),
        platform,
        hardware_id: None,
        license_cache: None,
        enable_server_pointer: true,
        // The server's pointer is drawn into the picture, so it matches exactly.
        pointer_software_rendering: true,
        autologon: false,
        enable_audio_playback: false,
        request_data: None,
        multitransport_flags: None,
        compression_type: Some(CompressionType::K64),
        performance_flags: PerformanceFlags::default(),
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

async fn run(
    p: Params,
    size: (u16, u16),
    scale: u32,
    shared: Arc<Mutex<Shared>>,
    mut rx: mpsc::UnboundedReceiver<Input>,
    ctx: egui::Context,
) -> Result<String, String> {
    let set = |status: Status| {
        if let Ok(mut s) = shared.lock() {
            s.status = status;
        }
        ctx.request_repaint();
    };
    let stream = tokio::time::timeout(Duration::from_secs(15), tokio::net::TcpStream::connect((p.host.as_str(), p.port)))
        .await
        .map_err(|_| format!("{}:{} did not answer within 15 seconds", p.host, p.port))?
        .map_err(|e| format!("cannot reach {}:{}: {e}", p.host, p.port))?;
    let client_addr = stream.local_addr().map_err(|e| e.to_string())?;
    let mut framed = ironrdp_tokio::TokioFramed::new(stream);

    let drdynvc = ironrdp::dvc::DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
    let mut connector = ClientConnector::new(connector_config(&p, size, scale), client_addr).with_static_channel(drdynvc);
    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await.map_err(describe)?;

    let (plain, leftover) = framed.into_inner();
    let (tls, cert) = ironrdp_tls::upgrade(plain, &p.host).await.map_err(|e| format!("TLS: {e}"))?;
    let der = x509_cert::der::Encode::to_der(&cert).map_err(|e| format!("server certificate: {e}"))?;
    let fp = fingerprint(&der);
    if p.known_fingerprint.as_deref() != Some(fp.as_str()) {
        let (tx, answer) = oneshot::channel();
        if let Ok(mut s) = shared.lock() {
            s.trust_reply = Some(tx);
        }
        set(Status::Trust { fingerprint: fp, changed: p.known_fingerprint.is_some() });
        if !answer.await.unwrap_or(false) {
            return Err("The certificate was not accepted, so nothing was sent to the server.".into());
        }
        set(Status::Connecting);
    }

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = ironrdp_tokio::TokioFramed::new_with_leftover(tls, leftover);
    let server_key = ironrdp_tls::extract_tls_server_public_key(&cert).ok_or("cannot read the server's public key")?.to_owned();
    let result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut NoNetwork,
        connector::ServerName::new(p.host.clone()),
        server_key,
        None,
    )
    .await
    .map_err(describe)?;
    drop(p);
    set(Status::Connected);
    session(framed, result, &shared, &mut rx, &ctx).await
}

/// A connector error as a sentence a user can act on.
fn describe(e: connector::ConnectorError) -> String {
    let text = format!("{e}");
    let lower = text.to_lowercase();
    if lower.contains("logon") || lower.contains("credssp") || lower.contains("authentication") || lower.contains("sec_e") {
        format!("Sign-in failed. Check the user name and password. ({text})")
    } else {
        text
    }
}

async fn session<S>(
    framed: ironrdp_tokio::TokioFramed<S>,
    result: ConnectionResult,
    shared: &Arc<Mutex<Shared>>,
    rx: &mut mpsc::UnboundedReceiver<Input>,
    ctx: &egui::Context,
) -> Result<String, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let err = |e: ironrdp::session::SessionError| e.to_string();
    let (mut reader, mut writer) = ironrdp_tokio::split_tokio_framed(framed);
    let size = result.desktop_size;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, size.width, size.height);
    let activation = result.activation_factory;
    let mut stage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();

    let reason = 'outer: loop {
        let outputs = tokio::select! {
            frame = reader.read_pdu() => {
                let (action, payload) = frame.map_err(|e| format!("connection lost: {e}"))?;
                stage.process(&mut image, action, &payload).map_err(err)?
            }
            input = rx.recv() => match input {
                None | Some(Input::Close) => stage.graceful_shutdown().map_err(err)?,
                Some(Input::Fast(events)) => stage.process_fastpath_input(&mut image, &events).map_err(err)?,
                Some(Input::Resize { width, height, scale }) => match stage.encode_resize(u32::from(width), u32::from(height), Some(scale), None) {
                    Some(frame) => vec![ActiveStageOutput::ResponseFrame(frame.map_err(err)?)],
                    // The server cannot resize live; keep the current size.
                    None => Vec::new(),
                },
            },
        };
        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => writer.write_all(&frame).await.map_err(|e| format!("connection lost: {e}"))?,
                ActiveStageOutput::GraphicsUpdate(_) => publish(&image, shared, ctx),
                ActiveStageOutput::DeactivateAll => {
                    // Deactivation-Reactivation (e.g. the desktop size changed).
                    let mut seq = activation.create();
                    let mut buf = WriteBuf::new();
                    loop {
                        let written = ironrdp_tokio::single_sequence_step_read(&mut reader, &mut seq, &mut buf).await.map_err(describe)?;
                        if written.size().is_some() {
                            writer.write_all(buf.filled()).await.map_err(|e| format!("connection lost: {e}"))?;
                        }
                        if let ConnectionActivationState::Finalized { desktop_size, share_id, enable_server_pointer, pointer_software_rendering } =
                            seq.connection_activation_state()
                        {
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            stage.set_fastpath_processor(
                                fast_path::ProcessorBuilder {
                                    io_channel_id: seq.io_channel_id(),
                                    user_channel_id: seq.user_channel_id(),
                                    share_id,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                    bulk_decompressor: None,
                                }
                                .build(),
                            );
                            stage.set_share_id(share_id);
                            stage.set_enable_server_pointer(enable_server_pointer);
                            break;
                        }
                    }
                }
                ActiveStageOutput::Terminate(reason) => break 'outer reason,
                _ => {}
            }
        }
    };
    Ok(match reason.description() {
        d if d.is_empty() => "The session ended.".into(),
        d => format!("The session ended ({d})."),
    })
}

/// Hands the current picture to the UI thread.
fn publish(image: &DecodedImage, shared: &Arc<Mutex<Shared>>, ctx: &egui::Context) {
    let (w, h) = (usize::from(image.width()), usize::from(image.height()));
    if let Ok(mut s) = shared.lock() {
        let frame = s.frame.get_or_insert_with(|| Frame { rgba: Vec::new(), width: w, height: h });
        frame.width = w;
        frame.height = h;
        frame.rgba.clear();
        frame.rgba.extend_from_slice(image.data());
        // The alpha byte is not meaningful in RDP pictures.
        for px in frame.rgba.as_chunks_mut::<4>().0 {
            px[3] = 255;
        }
        s.frame_new = true;
    }
    ctx.request_repaint();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_names_and_domains() {
        assert_eq!(split_domain("CORP\\ops"), ("ops".into(), Some("CORP".into())));
        assert_eq!(split_domain("ops@corp.example"), ("ops@corp.example".into(), None));
        assert_eq!(split_domain("Administrator"), ("Administrator".into(), None));
    }

    #[test]
    fn fingerprints_look_like_windows_shows_them() {
        let fp = fingerprint(b"abc");
        assert!(fp.starts_with("BA:78:16:BF:"), "{fp}");
        assert_eq!(fp.len(), 32 * 3 - 1);
    }

    #[test]
    fn keys_map_to_scancodes() {
        assert_eq!(scancode(Key::A).map(Scancode::as_u8), Some((false, 0x1E)));
        assert_eq!(scancode(Key::ArrowLeft).map(Scancode::as_u8), Some((true, 0x4B)));
        assert_eq!(scancode(Key::Enter).map(Scancode::as_u8), Some((false, 0x1C)));
    }

    #[test]
    fn desktop_sizes_are_valid() {
        let (w, h) = desktop_size(3001, 50);
        assert!(w % 2 == 0 && w >= 200 && h >= 200);
    }

    /// A server that never answers the RDP handshake gives a clear error, and
    /// no certificate prompt.
    #[test]
    fn unreachable_server_ends_with_an_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // nothing listens there now
        let ctx = egui::Context::default();
        let params = Params { host: "127.0.0.1".into(), port, user: "u".into(), password: Zeroizing::new("p".into()), known_fingerprint: None };
        let view = RdpView::connect(params, "t".into(), &ctx);
        let start = Instant::now();
        while !view.exited() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let status = view.shared.lock().unwrap().status.clone();
        assert!(matches!(status, Status::Ended { error: true, ref message } if message.contains("cannot reach")), "{}", match status {
            Status::Ended { message, .. } => message,
            _ => "not ended".into(),
        });
    }
}
