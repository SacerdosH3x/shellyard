//! A terminal session: a child process on a PTY, parsed by alacritty_terminal,
//! drawn with the egui painter.

use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};

use alacritty_terminal::event::{Event as TermEvent, EventListener};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::color::Colors;
use alacritty_terminal::term::{viewport_to_point, Config, TermMode};
use alacritty_terminal::vte::ansi::{Color as AnsiColor, CursorShape, NamedColor, Processor, Rgb};
use alacritty_terminal::Term;
use anyhow::{anyhow, Result};
use eframe::egui::{self, Color32, FontId, Key, Modifiers, Pos2, Rect, Sense, Stroke, Vec2};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

use crate::theme;

const PAD: f32 = 8.0;
/// Bytes parsed per frame before yielding, so a flood of output cannot freeze the UI.
const MAX_BYTES_PER_FRAME: usize = 1 << 20;
/// Chunks (of up to 16 KiB) buffered between the PTY reader and the parser.
const READ_QUEUE_CHUNKS: usize = 64;

#[derive(Clone, Default)]
struct Listener(Arc<Mutex<Vec<TermEvent>>>);

impl EventListener for Listener {
    fn send_event(&self, event: TermEvent) {
        if let Ok(mut q) = self.0.lock() {
            q.push(event);
        }
    }
}

struct Size {
    cols: usize,
    rows: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.rows
    }
    fn screen_lines(&self) -> usize {
        self.rows
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

pub struct Terminal {
    id: egui::Id,
    pub title: String,
    pub exited: bool,
    term: Term<Listener>,
    parser: Processor,
    events: Listener,
    rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    writer: Box<dyn Write + Send>,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    cols: usize,
    rows: usize,
    font_size: f32,
    /// Private key files written for this session; removed when it ends.
    temp_files: Vec<std::path::PathBuf>,
    /// Whether OSC 52 clipboard writes from the program are honored.
    pub allow_clipboard: bool,
    /// The process has been waited for (no zombie left behind).
    reaped: bool,
}

impl SshSpec {
    /// Arguments after the program name.
    pub fn args(&self) -> Vec<std::ffi::OsString> {
        let mut a: Vec<std::ffi::OsString> = Vec::new();
        a.push(if self.program == "sftp" { "-P" } else { "-p" }.into());
        a.push(self.port.to_string().into());
        if let Some(key) = &self.identity {
            a.push("-i".into());
            a.push(key.into());
            if self.program != "ssh-copy-id" {
                // Use only this key, so agent keys don't trigger "too many authentication failures".
                a.push("-o".into());
                a.push("IdentitiesOnly=yes".into());
            }
        }
        a.extend(self.options.iter().map(Into::into));
        if self.program != "ssh-copy-id" {
            a.push("--".into());
        }
        let host = destination_host(self.program, &self.address);
        a.push(if self.user.is_empty() { host } else { format!("{}@{}", self.user, host) }.into());
        a
    }
}

/// The host part of the destination as each OpenSSH program expects it: `ssh`
/// takes a bare IPv6 address (`::1`), while `sftp` treats `:` as the start of
/// a path unless the address is in brackets (`[::1]`).
fn destination_host(program: &str, address: &str) -> String {
    let bare = address.strip_prefix('[').and_then(|a| a.strip_suffix(']')).unwrap_or(address);
    if program == "sftp" && bare.contains(':') {
        format!("[{bare}]")
    } else {
        bare.to_string()
    }
}

/// What to run for an OpenSSH-based session.
pub struct SshSpec {
    pub program: &'static str,
    pub user: String,
    pub address: String,
    pub port: u16,
    pub identity: Option<std::path::PathBuf>,
    /// Extra arguments placed before the destination, built by Shellyard from validated values.
    pub options: Vec<String>,
    pub temp_files: Vec<std::path::PathBuf>,
}

impl Terminal {
    pub fn spawn(mut cmd: CommandBuilder, title: String, ctx: &egui::Context) -> Result<Self> {
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        if cmd.get_cwd().is_none() {
            if let Some(home) = dirs::home_dir() {
                cmd.cwd(home);
            }
        }

        let (cols, rows) = (80, 24);
        let pair = native_pty_system()
            .openpty(PtySize { rows: rows as u16, cols: cols as u16, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| anyhow!("cannot open a pty: {e}"))?;
        let child = pair.slave.spawn_command(cmd).map_err(|e| anyhow!("cannot start process: {e}"))?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().map_err(|e| anyhow!("{e}"))?;
        let writer = pair.master.take_writer().map_err(|e| anyhow!("{e}"))?;

        // Bounded, so a process flooding output into a tab nobody is drawing
        // blocks on its PTY instead of growing this process's memory without limit.
        let (tx, rx) = mpsc::sync_channel(READ_QUEUE_CHUNKS);
        let repaint = ctx.clone();
        std::thread::Builder::new().name("pty-reader".into()).spawn(move || {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                        repaint.request_repaint();
                    }
                }
            }
            repaint.request_repaint();
        })?;

        let events = Listener::default();
        let config = Config { scrolling_history: 10_000, ..Config::default() };
        let term = Term::new(config, &Size { cols, rows }, events.clone());

        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(Self {
            id: egui::Id::new(("terminal", n)),
            title,
            exited: false,
            term,
            parser: Processor::new(),
            events,
            rx,
            pending: Vec::new(),
            writer,
            master: pair.master,
            child,
            cols,
            rows,
            font_size: 13.5,
            temp_files: Vec::new(),
            allow_clipboard: false,
            reaped: false,
        })
    }

    /// A login shell on this machine.
    pub fn local(shell: &str, ctx: &egui::Context) -> Result<Self> {
        let mut cmd = CommandBuilder::new(shell);
        if !cfg!(windows) {
            cmd.arg("-l");
        }
        let name = std::path::Path::new(shell)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| shell.to_string());
        Self::spawn(cmd, name, ctx)
    }

    /// Runs a system OpenSSH program (`ssh`, `sftp` or `ssh-copy-id`) in the terminal.
    /// OpenSSH handles host-key verification, agents, keys and passphrase prompts.
    pub fn openssh(spec: SshSpec, title: String, ctx: &egui::Context) -> Result<Self> {
        // Values starting with '-' would be parsed as options (e.g. -oProxyCommand=...).
        if !crate::model::safe_arg(&spec.address) || (!spec.user.is_empty() && !crate::model::safe_arg(&spec.user)) {
            return Err(anyhow!("host address or user contains characters that are not allowed"));
        }
        let mut cmd = CommandBuilder::new(spec.program);
        cmd.args(spec.args());
        match Self::spawn(cmd, title, ctx) {
            Ok(mut t) => {
                t.temp_files = spec.temp_files;
                Ok(t)
            }
            Err(e) => {
                crate::store::remove_temp_files(&spec.temp_files);
                Err(e)
            }
        }
    }

    /// Sends text as if pasted, honoring bracketed-paste mode.
    pub fn paste(&mut self, text: &str) {
        let out = paste_bytes(text, self.term.mode().contains(TermMode::BRACKETED_PASTE));
        self.term.scroll_display(Scroll::Bottom);
        self.write(&out);
    }

    /// Processes pending output without drawing (for tunnels shown elsewhere).
    pub fn poll(&mut self, ctx: &egui::Context) {
        self.pump(ctx);
    }

    /// The last non-empty line on screen, for status display.
    pub fn last_line(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut last = None;
        for ind in self.term.renderable_content().display_iter {
            if last.is_some_and(|l| l != ind.point.line.0) {
                lines.push(std::mem::take(&mut cur));
            }
            last = Some(ind.point.line.0);
            cur.push(ind.cell.c);
        }
        lines.push(cur);
        lines.into_iter().map(|l| l.trim().to_string()).rfind(|l| !l.is_empty()).unwrap_or_default()
    }

    pub fn focus(&self, ctx: &egui::Context) {
        ctx.memory_mut(|m| m.request_focus(self.id));
    }

    pub fn write(&mut self, bytes: &[u8]) {
        if self.exited || bytes.is_empty() {
            return;
        }
        if self.writer.write_all(bytes).and_then(|_| self.writer.flush()).is_err() {
            self.exited = true;
        }
    }

    /// Cleanup once the program has ended: a key written for this session is
    /// wiped right away instead of when the tab is closed, and the process is
    /// waited for so it does not linger as a zombie.
    fn after_exit(&mut self) {
        if !self.exited {
            return;
        }
        if !self.temp_files.is_empty() {
            crate::store::remove_temp_files(&std::mem::take(&mut self.temp_files));
        }
        if !self.reaped {
            self.reaped = matches!(self.child.try_wait(), Ok(Some(_)) | Err(_));
        }
    }

    /// The selected text, if any.
    pub fn selection_text(&self) -> Option<String> {
        self.term.selection_to_string().filter(|s| !s.is_empty())
    }

    fn pump(&mut self, ctx: &egui::Context) {
        let mut budget = MAX_BYTES_PER_FRAME;
        if !self.pending.is_empty() {
            let chunk = std::mem::take(&mut self.pending);
            self.parser.advance(&mut self.term, &chunk);
            budget = budget.saturating_sub(chunk.len());
        }
        while budget > 0 {
            match self.rx.try_recv() {
                Ok(bytes) => {
                    budget = budget.saturating_sub(bytes.len());
                    self.parser.advance(&mut self.term, &bytes);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.exited = true;
                    break;
                }
            }
        }
        if budget == 0 {
            ctx.request_repaint();
        }
        self.after_exit();

        let events: Vec<TermEvent> = self.events.0.lock().map(|mut q| q.drain(..).collect()).unwrap_or_default();
        for ev in events {
            match ev {
                TermEvent::PtyWrite(s) => self.write(s.as_bytes()),
                TermEvent::Title(t) => self.title = t,
                TermEvent::ClipboardStore(_, text) if self.allow_clipboard => ctx.copy_text(text),
                _ => {}
            }
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        self.pump(ui.ctx());

        let font = FontId::monospace(self.font_size);
        let (cw, ch) = ui.fonts(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
        let rect = ui.available_rect_before_wrap();
        ui.allocate_rect(rect, Sense::hover());
        let resp = ui.interact(rect, self.id, Sense::click_and_drag()).on_hover_cursor(egui::CursorIcon::Text);
        if resp.clicked() || resp.drag_started() {
            resp.request_focus();
        }

        let cols = (((rect.width() - 2.0 * PAD) / cw).floor() as usize).max(2);
        let rows = (((rect.height() - 2.0 * PAD) / ch).floor() as usize).max(1);
        if (cols, rows) != (self.cols, self.rows) {
            self.cols = cols;
            self.rows = rows;
            self.term.resize(Size { cols, rows });
            let _ = self.master.resize(PtySize { rows: rows as u16, cols: cols as u16, pixel_width: 0, pixel_height: 0 });
        }

        if resp.has_focus() {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    self.id,
                    egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true },
                )
            });
            self.handle_input(ui);
        }
        self.handle_selection(ui, &resp, rect, cw, ch);
        if resp.hovered() {
            let dy = ui.input(|i| i.raw_scroll_delta.y);
            if dy != 0.0 {
                let lines = (dy / ch).round() as i32;
                let lines = if lines == 0 { dy.signum() as i32 } else { lines };
                let cell = resp.hover_pos().map(|p| self.cell_at(p, rect, cw, ch).0);
                self.wheel(lines, cell);
            }
        }

        let has_selection = self.term.selection.as_ref().is_some_and(|s| !s.is_empty());
        resp.context_menu(|ui| {
            if ui.add_enabled(has_selection, egui::Button::new(format!("{}  Copy", egui_phosphor::regular::COPY))).clicked() {
                if let Some(text) = self.selection_text() {
                    ui.ctx().copy_text(text);
                }
                ui.close_menu();
            }
        });

        self.paint(ui, rect, &font, cw, ch, resp.has_focus());
    }

    /// The viewport cell under `pos` (row, column) and which half of it was hit.
    fn cell_at(&self, pos: Pos2, rect: Rect, cw: f32, ch: f32) -> ((usize, usize), Side) {
        let x = (pos.x - rect.min.x - PAD) / cw;
        let y = (pos.y - rect.min.y - PAD) / ch;
        let col = (x.max(0.0) as usize).min(self.cols.saturating_sub(1));
        let row = (y.max(0.0) as usize).min(self.rows.saturating_sub(1));
        let side = if x - x.floor() < 0.5 { Side::Left } else { Side::Right };
        ((row, col), side)
    }

    /// Mouse selection: drag selects, double-click selects a word, triple-click a line.
    fn handle_selection(&mut self, ui: &egui::Ui, resp: &egui::Response, rect: Rect, cw: f32, ch: f32) {
        let Some(pos) = resp.interact_pointer_pos() else { return };
        let ((row, col), side) = self.cell_at(pos, rect, cw, ch);
        let offset = self.term.grid().display_offset();
        let point = viewport_to_point(offset, Point::new(row, Column(col)));
        let start = |ty| Some(Selection::new(ty, point, side));
        if resp.triple_clicked() {
            self.term.selection = start(SelectionType::Lines);
        } else if resp.double_clicked() {
            self.term.selection = start(SelectionType::Semantic);
        } else if resp.drag_started_by(egui::PointerButton::Primary) {
            self.term.selection = start(SelectionType::Simple);
        } else if resp.dragged_by(egui::PointerButton::Primary) {
            if let Some(sel) = self.term.selection.as_mut() {
                sel.update(point, side);
            }
            // Keep selecting past the top or bottom edge by scrolling.
            let edge = if pos.y < rect.top() + PAD { 1 } else if pos.y > rect.bottom() - PAD { -1 } else { 0 };
            if edge != 0 && !self.term.mode().contains(TermMode::ALT_SCREEN) {
                self.term.scroll_display(Scroll::Delta(edge));
                ui.ctx().request_repaint();
            }
        } else if resp.clicked() && !ui.input(|i| i.modifiers.shift) {
            self.term.selection = None;
        }
    }

    /// Mouse wheel: scrollback normally; inside full-screen programs (less,
    /// vim, tmux) the wheel goes to the program, as in other terminals.
    fn wheel(&mut self, lines: i32, cell: Option<(usize, usize)>) {
        let mode = *self.term.mode();
        let n = lines.unsigned_abs().min(20) as usize;
        if mode.intersects(TermMode::MOUSE_MODE) && mode.contains(TermMode::SGR_MOUSE) {
            let (row, col) = cell.unwrap_or((0, 0));
            let button = if lines > 0 { 64 } else { 65 };
            let report = format!("\x1b[<{button};{};{}M", col + 1, row + 1);
            self.write(report.repeat(n).as_bytes());
        } else if mode.contains(TermMode::ALT_SCREEN) && mode.contains(TermMode::ALTERNATE_SCROLL) {
            let arrow = match (lines > 0, mode.contains(TermMode::APP_CURSOR)) {
                (true, true) => "\x1bOA",
                (true, false) => "\x1b[A",
                (false, true) => "\x1bOB",
                (false, false) => "\x1b[B",
            };
            self.write(arrow.repeat(n).as_bytes());
        } else {
            self.term.scroll_display(Scroll::Delta(lines));
        }
    }

    fn handle_input(&mut self, ui: &egui::Ui) {
        let mode = *self.term.mode();
        let (events, shift) = ui.input(|i| (i.events.clone(), i.modifiers.shift));
        let mut out: Vec<u8> = Vec::new();
        for ev in events {
            match edit_command(&ev, shift, cfg!(target_os = "macos")) {
                Some(EditCommand::Copy) => {
                    if let Some(text) = self.selection_text() {
                        ui.ctx().copy_text(text);
                    }
                    continue;
                }
                Some(EditCommand::Send(b)) => {
                    out.push(b);
                    continue;
                }
                None => {}
            }
            match ev {
                egui::Event::Text(t) => out.extend_from_slice(t.as_bytes()),
                egui::Event::Paste(t) => out.extend_from_slice(&paste_bytes(&t, mode.contains(TermMode::BRACKETED_PASTE))),
                egui::Event::Key { key, pressed: true, modifiers, .. } => {
                    if let Some(bytes) = key_bytes(key, modifiers, mode.contains(TermMode::APP_CURSOR)) {
                        out.extend_from_slice(&bytes);
                    }
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            self.term.selection = None;
            self.term.scroll_display(Scroll::Bottom);
            self.write(&out);
        }
    }

    fn paint(&self, ui: &egui::Ui, rect: Rect, font: &FontId, cw: f32, ch: f32, focused: bool) {
        let painter = ui.painter_at(rect);
        let default_bg = TERM_BG;
        painter.rect_filled(rect, 0.0, default_bg);

        let content = self.term.renderable_content();
        let colors = content.colors;
        let selection = content.selection;
        let offset = content.display_offset as i32;
        let origin = rect.min + Vec2::splat(PAD);
        let cell_pos = |row: usize, col: usize| origin + Vec2::new(col as f32 * cw, row as f32 * ch);

        // A run is a stretch of cells on one row sharing colors and flags.
        struct Run {
            row: usize,
            col: usize,
            text: String,
            fg: Color32,
            underline: bool,
            strike: bool,
        }
        let mut runs: Vec<Run> = Vec::new();

        for ind in content.display_iter {
            let line = ind.point.line.0 + offset;
            if line < 0 {
                continue;
            }
            let row = line as usize;
            let col = ind.point.column.0;
            let cell = ind.cell;
            if cell.flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER) {
                continue;
            }

            let mut fg = resolve(cell.fg, colors);
            let mut bg = resolve(cell.bg, colors);
            if cell.flags.contains(Flags::BOLD) {
                if let AnsiColor::Named(n) = cell.fg {
                    if (n as usize) < 8 {
                        fg = resolve(AnsiColor::Named(n.to_bright()), colors);
                    }
                }
            }
            if cell.flags.contains(Flags::DIM) {
                fg = fg.gamma_multiply(0.66);
            }
            if cell.flags.contains(Flags::INVERSE) {
                std::mem::swap(&mut fg, &mut bg);
            }
            if cell.flags.contains(Flags::HIDDEN) {
                fg = bg;
            }
            if selection.is_some_and(|s| s.contains(ind.point)) {
                bg = SELECTION_BG;
                fg = TERM_FG;
            }

            let width = if cell.flags.contains(Flags::WIDE_CHAR) { 2.0 } else { 1.0 };
            if bg != default_bg {
                let p = cell_pos(row, col);
                painter.rect_filled(Rect::from_min_size(p, Vec2::new(cw * width, ch)), 0.0, bg);
            }

            let c = if cell.c == '\0' { ' ' } else { cell.c };
            let underline = cell.flags.intersects(Flags::ALL_UNDERLINES);
            let strike = cell.flags.contains(Flags::STRIKEOUT);
            match runs.last_mut() {
                Some(r)
                    if r.row == row
                        && r.fg == fg
                        && r.underline == underline
                        && r.strike == strike
                        && width == 1.0
                        && r.col + r.text.chars().count() == col =>
                {
                    r.text.push(c);
                }
                _ => runs.push(Run { row, col, text: c.to_string(), fg, underline, strike }),
            }
        }

        for r in &runs {
            let trimmed = r.text.trim_end();
            if trimmed.is_empty() && !r.underline {
                continue;
            }
            let p = cell_pos(r.row, r.col);
            painter.text(p, egui::Align2::LEFT_TOP, trimmed, font.clone(), r.fg);
            let w = r.text.chars().count() as f32 * cw;
            if r.underline {
                painter.hline(p.x..=p.x + w, p.y + ch - 1.5, Stroke::new(1.0_f32, r.fg));
            }
            if r.strike {
                painter.hline(p.x..=p.x + w, p.y + ch * 0.5, Stroke::new(1.0_f32, r.fg));
            }
        }

        // Cursor.
        let cur = content.cursor;
        let line = cur.point.line.0 + offset;
        if line >= 0 && (line as usize) < self.rows && !self.exited {
            let p = cell_pos(line as usize, cur.point.column.0);
            let cell = Rect::from_min_size(p, Vec2::new(cw, ch));
            let color = theme::ACCENT;
            match (cur.shape, focused) {
                (CursorShape::Hidden, _) => {}
                (_, false) | (CursorShape::HollowBlock, _) => {
                    painter.rect_stroke(cell.shrink(0.5), 1.0, Stroke::new(1.0_f32, color));
                }
                (CursorShape::Block, true) => {
                    painter.rect_filled(cell, 1.0, color.gamma_multiply(0.75));
                }
                (CursorShape::Beam, true) => {
                    painter.rect_filled(Rect::from_min_size(p, Vec2::new(2.0, ch)), 0.0, color);
                }
                (CursorShape::Underline, true) => {
                    painter.rect_filled(Rect::from_min_size(p + Vec2::new(0.0, ch - 2.0), Vec2::new(cw, 2.0)), 0.0, color);
                }
            }
        }

        if self.exited {
            let msg = "Session ended. Close this tab or reconnect.";
            let pos = Pos2::new(rect.center().x, rect.bottom() - 28.0);
            let g = painter.layout_no_wrap(msg.into(), FontId::proportional(13.0), theme::TEXT);
            let bg = Rect::from_center_size(pos, g.size() + Vec2::new(24.0, 12.0));
            painter.rect_filled(bg, 6.0, theme::SURFACE);
            painter.rect_stroke(bg, 6.0, Stroke::new(1.0_f32, theme::BORDER));
            painter.galley(bg.min + Vec2::new(12.0, 6.0), g, theme::TEXT);
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.child.kill();
        crate::store::remove_temp_files(&self.temp_files);
    }
}

// ---------------------------------------------------------------------------
// Colors

const TERM_BG: Color32 = Color32::from_rgb(0x0d, 0x10, 0x15);
const TERM_FG: Color32 = Color32::from_rgb(0xd5, 0xda, 0xe1);
const SELECTION_BG: Color32 = Color32::from_rgb(0x2c, 0x4a, 0x6e);

const ANSI: [Color32; 16] = [
    Color32::from_rgb(0x1e, 0x23, 0x2b),
    Color32::from_rgb(0xf0, 0x6a, 0x6a),
    Color32::from_rgb(0xa8, 0xd8, 0x4a),
    Color32::from_rgb(0xe8, 0xc0, 0x6a),
    Color32::from_rgb(0x6b, 0xa6, 0xf5),
    Color32::from_rgb(0xc6, 0x86, 0xe8),
    Color32::from_rgb(0x56, 0xc2, 0xc6),
    Color32::from_rgb(0xc8, 0xcd, 0xd5),
    Color32::from_rgb(0x5c, 0x66, 0x75),
    Color32::from_rgb(0xff, 0x8a, 0x8a),
    Color32::from_rgb(0xc5, 0xf0, 0x35),
    Color32::from_rgb(0xf5, 0xd4, 0x8a),
    Color32::from_rgb(0x8f, 0xbd, 0xff),
    Color32::from_rgb(0xdd, 0xa6, 0xf5),
    Color32::from_rgb(0x7f, 0xdd, 0xe0),
    Color32::from_rgb(0xf2, 0xf4, 0xf7),
];

fn rgb(c: Rgb) -> Color32 {
    Color32::from_rgb(c.r, c.g, c.b)
}

fn indexed(i: u8) -> Color32 {
    match i {
        0..=15 => ANSI[i as usize],
        16..=231 => {
            let i = i - 16;
            let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
            Color32::from_rgb(level(i / 36), level((i / 6) % 6), level(i % 6))
        }
        _ => {
            let v = 8 + (i - 232) * 10;
            Color32::from_rgb(v, v, v)
        }
    }
}

fn resolve(color: AnsiColor, colors: &Colors) -> Color32 {
    match color {
        AnsiColor::Spec(c) => rgb(c),
        AnsiColor::Indexed(i) => colors[i as usize].map(rgb).unwrap_or_else(|| indexed(i)),
        AnsiColor::Named(n) => {
            if let Some(c) = colors[n] {
                return rgb(c);
            }
            let idx = n as usize;
            match n {
                NamedColor::Foreground | NamedColor::BrightForeground => TERM_FG,
                NamedColor::Background => TERM_BG,
                NamedColor::Cursor => theme::ACCENT,
                NamedColor::DimForeground => TERM_FG.gamma_multiply(0.66),
                _ if idx < 16 => ANSI[idx],
                // Dim variants follow the foreground block in NamedColor.
                _ => {
                    let base = idx.saturating_sub(NamedColor::DimBlack as usize).min(7);
                    ANSI[base].gamma_multiply(0.66)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Keyboard

/// What a clipboard shortcut means inside the terminal.
#[derive(Debug, PartialEq, Eq)]
enum EditCommand {
    /// Copy the selection to the clipboard.
    Copy,
    /// Send this control byte to the program instead.
    Send(u8),
}

/// egui turns ⌘C/⌘X/⌘V (macOS) and Ctrl+C/X/V (elsewhere) into Copy, Cut and
/// Paste events. On macOS those are the clipboard. Elsewhere a terminal keeps
/// Ctrl+C/X/V for the program (^C interrupts, ^V is literal-next) and uses
/// Ctrl+Shift+C/V for the clipboard. `None` means: handle the event normally
/// (a Paste event pastes).
fn edit_command(ev: &egui::Event, shift: bool, mac: bool) -> Option<EditCommand> {
    match ev {
        egui::Event::Copy if mac || shift => Some(EditCommand::Copy),
        egui::Event::Copy => Some(EditCommand::Send(0x03)),
        egui::Event::Cut if mac => None,
        egui::Event::Cut => Some(EditCommand::Send(0x18)),
        egui::Event::Paste(_) if !mac && !shift => Some(EditCommand::Send(0x16)),
        _ => None,
    }
}

/// Bytes to send for pasted text. With bracketed paste on, escape characters
/// are dropped so the text cannot end the bracket early and run as commands.
fn paste_bytes(text: &str, bracketed: bool) -> Vec<u8> {
    if bracketed {
        let mut out = b"\x1b[200~".to_vec();
        out.extend(text.replace(['\x1b', '\u{9b}'], "").as_bytes());
        out.extend_from_slice(b"\x1b[201~");
        out
    } else {
        text.replace("\r\n", "\r").replace('\n', "\r").into_bytes()
    }
}

fn key_bytes(key: Key, m: Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    if m.mac_cmd {
        return None;
    }
    if m.ctrl {
        let name = key.name();
        if name.len() == 1 {
            let c = name.as_bytes()[0].to_ascii_lowercase();
            if c.is_ascii_lowercase() {
                let b = c - b'a' + 1;
                return Some(if m.alt { vec![0x1b, b] } else { vec![b] });
            }
        }
        let b = match key {
            Key::Space => Some(0x00),
            Key::OpenBracket => Some(0x1b),
            Key::Backslash => Some(0x1c),
            Key::CloseBracket => Some(0x1d),
            _ => None,
        };
        if let Some(b) = b {
            return Some(vec![b]);
        }
    }

    let modcode = 1 + (m.shift as u8) + 2 * (m.alt as u8) + 4 * (m.ctrl as u8);
    let csi = |c: char| -> Vec<u8> {
        if modcode > 1 {
            format!("\x1b[1;{modcode}{c}").into_bytes()
        } else if app_cursor {
            format!("\x1bO{c}").into_bytes()
        } else {
            format!("\x1b[{c}").into_bytes()
        }
    };
    let tilde = |n: u8| -> Vec<u8> {
        if modcode > 1 {
            format!("\x1b[{n};{modcode}~").into_bytes()
        } else {
            format!("\x1b[{n}~").into_bytes()
        }
    };

    Some(match key {
        Key::Enter => b"\r".to_vec(),
        Key::Backspace => {
            if m.alt {
                b"\x1b\x7f".to_vec()
            } else {
                vec![0x7f]
            }
        }
        Key::Tab => {
            if m.shift {
                b"\x1b[Z".to_vec()
            } else {
                b"\t".to_vec()
            }
        }
        Key::Escape => b"\x1b".to_vec(),
        Key::ArrowUp => csi('A'),
        Key::ArrowDown => csi('B'),
        Key::ArrowRight => csi('C'),
        Key::ArrowLeft => csi('D'),
        Key::Home => csi('H'),
        Key::End => csi('F'),
        Key::Insert => tilde(2),
        Key::Delete => tilde(3),
        Key::PageUp => tilde(5),
        Key::PageDown => tilde(6),
        Key::F1 => b"\x1bOP".to_vec(),
        Key::F2 => b"\x1bOQ".to_vec(),
        Key::F3 => b"\x1bOR".to_vec(),
        Key::F4 => b"\x1bOS".to_vec(),
        Key::F5 => tilde(15),
        Key::F6 => tilde(17),
        Key::F7 => tilde(18),
        Key::F8 => tilde(19),
        Key::F9 => tilde(20),
        Key::F10 => tilde(21),
        Key::F11 => tilde(23),
        Key::F12 => tilde(24),
        _ => return None,
    })
}

/// Shells available on this machine, as (display name, path).
pub fn available_shells() -> Vec<(String, String)> {
    #[cfg(windows)]
    {
        let mut out: Vec<(String, String)> = Vec::new();
        for (name, exe) in [("PowerShell", "powershell.exe"), ("pwsh", "pwsh.exe"), ("CMD", "cmd.exe"), ("WSL", "wsl.exe")] {
            if which(exe).is_some() {
                out.push((name.into(), exe.into()));
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        let wanted = ["zsh", "bash", "fish", "nu", "pwsh", "sh"];
        let mut found: Vec<(usize, String, String)> = Vec::new();
        for name in wanted {
            if let Some(path) = which(name) {
                let rank = wanted.iter().position(|w| *w == name).unwrap_or(99);
                let label = match name {
                    "zsh" => "Zsh",
                    "bash" => "Bash",
                    "fish" => "Fish",
                    "nu" => "Nushell",
                    "pwsh" => "PowerShell",
                    _ => "sh",
                };
                found.push((rank, label.into(), path));
            }
        }
        found.sort_by_key(|f| f.0);
        found.into_iter().map(|(_, l, p)| (l, p)).collect()
    }
}

pub fn default_shell() -> String {
    if cfg!(windows) {
        return "powershell.exe".into();
    }
    std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/sh".into())
}

fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    let mut dirs: Vec<std::path::PathBuf> = std::env::split_paths(&path).collect();
    // GUI apps on macOS get a minimal PATH; also look in the usual places.
    for extra in ["/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"] {
        dirs.push(extra.into());
    }
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file()).map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen_text(t: &Terminal) -> String {
        let mut s = String::new();
        let mut last_line = 0;
        for ind in t.term.renderable_content().display_iter {
            if ind.point.line.0 != last_line {
                s.push('\n');
                last_line = ind.point.line.0;
            }
            s.push(ind.cell.c);
        }
        s
    }

    #[cfg(unix)]
    #[test]
    fn runs_process_and_parses_output() {
        let ctx = egui::Context::default();
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.args(["-c", "printf 'hello \\033[31mred\\033[0m world\\n'; printf '\\033]0;my-title\\007'"]);
        let mut t = Terminal::spawn(cmd, "test".into(), &ctx).unwrap();
        let start = std::time::Instant::now();
        while !t.exited && start.elapsed() < std::time::Duration::from_secs(5) {
            t.pump(&ctx);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        t.pump(&ctx);
        assert!(t.exited, "process should have exited");
        let text = screen_text(&t);
        assert!(text.contains("hello red world"), "screen was: {text:?}");
        assert_eq!(t.title, "my-title");
    }

    /// Runs `script` in a shell and pumps until it exits.
    #[cfg(unix)]
    fn run_script(script: &str, allow_clipboard: bool) -> (egui::Context, Terminal) {
        let ctx = egui::Context::default();
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.args(["-c", script]);
        let mut t = Terminal::spawn(cmd, "test".into(), &ctx).unwrap();
        t.allow_clipboard = allow_clipboard;
        let start = std::time::Instant::now();
        while !t.exited && start.elapsed() < std::time::Duration::from_secs(5) {
            t.pump(&ctx);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        t.pump(&ctx);
        (ctx, t)
    }

    #[cfg(unix)]
    #[test]
    fn osc52_clipboard_writes_are_blocked_unless_allowed() {
        // OSC 52 with base64("rm -rf ~").
        let script = "printf '\\033]52;c;cm0gLXJmIH4=\\007'";
        let copied = |allow| {
            let (ctx, mut t) = run_script(script, allow);
            ctx.begin_pass(Default::default());
            t.pump(&ctx);
            let out = ctx.end_pass();
            out.platform_output.copied_text
        };
        assert_eq!(copied(false), "");
        assert_eq!(copied(true), "rm -rf ~");
    }

    /// A flood of output into a tab that is never drawn must not grow memory.
    #[cfg(unix)]
    #[test]
    fn output_queue_is_bounded() {
        let ctx = egui::Context::default();
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.args(["-c", "yes 0123456789012345678901234567890123456789"]);
        let t = Terminal::spawn(cmd, "flood".into(), &ctx).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(700));
        let mut chunks = 0;
        while t.rx.try_recv().is_ok() {
            chunks += 1;
        }
        // Draining races with the reader refilling the queue, so allow some
        // slack; an unbounded queue would hold thousands of chunks by now.
        assert!(chunks <= READ_QUEUE_CHUNKS * 2, "queue held {chunks} chunks");
        assert!(chunks > 0);
    }

    /// Random and hostile byte streams must never panic the parser or renderer helpers.
    #[cfg(unix)]
    #[test]
    fn fuzz_parser_with_random_output() {
        use rand::{Rng, SeedableRng};
        let (_ctx, mut t) = run_script("true", false);
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let pieces: [&[u8]; 12] = [
            b"\x1b[", b"\x1b]", b"\x07", b"\x1b\\", b"999999999", b";", b"?1049h", b"\x1b[2J", b"\x1bP", b"\xff\xfe", b"\x1b[38;2;",
            "é漢🙂".as_bytes(),
        ];
        for _ in 0..3000 {
            let mut buf = Vec::new();
            for _ in 0..rng.gen_range(1..40) {
                if rng.gen_bool(0.5) {
                    buf.extend_from_slice(pieces[rng.gen_range(0..pieces.len())]);
                } else {
                    buf.extend((0..rng.gen_range(1..16)).map(|_| rng.gen::<u8>()));
                }
            }
            t.parser.advance(&mut t.term, &buf);
            let _ = t.last_line();
            let content = t.term.renderable_content();
            for ind in content.display_iter.take(50) {
                let _ = resolve(ind.cell.fg, content.colors);
            }
        }
        // Also survive resizes to extremes after the noise.
        for (c, r) in [(2, 1), (500, 300), (80, 24)] {
            t.term.resize(Size { cols: c, rows: r });
        }
    }

    #[test]
    fn keys_encode() {
        let none = Modifiers::NONE;
        assert_eq!(key_bytes(Key::Enter, none, false).unwrap(), b"\r");
        assert_eq!(key_bytes(Key::ArrowUp, none, false).unwrap(), b"\x1b[A");
        assert_eq!(key_bytes(Key::ArrowUp, none, true).unwrap(), b"\x1bOA");
        assert_eq!(key_bytes(Key::C, Modifiers::CTRL, false).unwrap(), vec![3]);
        assert_eq!(key_bytes(Key::ArrowLeft, Modifiers::SHIFT, false).unwrap(), b"\x1b[1;2D");
        assert!(key_bytes(Key::A, none, false).is_none(), "plain letters arrive as Text events");
    }

    #[cfg(unix)]
    #[test]
    fn tunnel_and_key_args_reach_openssh() {
        use crate::model::{ForwardKind, Tunnel};
        let t = Tunnel {
            id: "t".into(),
            name: "db".into(),
            host_id: "h".into(),
            kind: ForwardKind::Local,
            bind_addr: "127.0.0.1".into(),
            bind_port: 15432,
            dest_host: "10.0.0.5".into(),
            dest_port: 5432,
            auto_start: false,
        };
        // OpenSSH ignores -i files that don't exist, so make one.
        let key = std::env::temp_dir().join(format!("shellyard-test-key-{}", std::process::id()));
        std::fs::write(&key, "not a real key").unwrap();
        let mut options = vec!["-N".to_string()];
        options.extend(t.ssh_args());
        let socks = Tunnel { kind: ForwardKind::Dynamic, bind_port: 1080, ..t.clone() };
        options.extend(socks.ssh_args());
        let spec = SshSpec {
            program: "ssh",
            user: "ops".into(),
            address: "db.example.test".into(),
            port: 2222,
            identity: Some(key.clone()),
            options,
            temp_files: Vec::new(),
        };
        // `ssh -G` prints the resolved configuration without connecting.
        let out = std::process::Command::new("ssh").arg("-G").args(spec.args()).output().expect("ssh not installed");
        let _ = std::fs::remove_file(&key);
        let cfg = String::from_utf8_lossy(&out.stdout).replace(&*key.to_string_lossy(), "KEY");
        for want in [
            "user ops",
            "hostname db.example.test",
            "port 2222",
            "identityfile KEY",
            "identitiesonly yes",
            "localforward [127.0.0.1]:15432 [10.0.0.5]:5432",
            "dynamicforward [127.0.0.1]:1080",
        ] {
            assert!(cfg.contains(want), "missing {want:?} in ssh -G output");
        }
    }

    #[test]
    fn clipboard_shortcuts_follow_platform_conventions() {
        let paste = egui::Event::Paste("x".into());
        // macOS: ⌘C copies, ⌘V pastes; Ctrl+C never arrives as Copy there.
        assert_eq!(edit_command(&egui::Event::Copy, false, true), Some(EditCommand::Copy));
        assert_eq!(edit_command(&paste, false, true), None);
        // Linux/Windows: Ctrl+C interrupts, Ctrl+Shift+C copies.
        assert_eq!(edit_command(&egui::Event::Copy, false, false), Some(EditCommand::Send(0x03)));
        assert_eq!(edit_command(&egui::Event::Copy, true, false), Some(EditCommand::Copy));
        // Ctrl+V is literal-next for the shell or vim, Ctrl+Shift+V pastes.
        assert_eq!(edit_command(&paste, false, false), Some(EditCommand::Send(0x16)));
        assert_eq!(edit_command(&paste, true, false), None);
        assert_eq!(edit_command(&egui::Event::Cut, false, false), Some(EditCommand::Send(0x18)));
    }

    #[test]
    fn bracketed_paste_cannot_escape_the_bracket() {
        let evil = "ls\x1b[201~rm -rf ~\n\u{9b}201~";
        let out = String::from_utf8(paste_bytes(evil, true)).unwrap();
        assert_eq!(out.matches("\x1b[201~").count(), 1, "{out:?}");
        assert!(out.ends_with("\x1b[201~") && !out.contains('\u{9b}'));
        assert_eq!(paste_bytes("a\r\nb\nc", false), b"a\rb\rc");
    }

    #[cfg(unix)]
    #[test]
    fn ipv6_destinations_reach_openssh() {
        assert_eq!(destination_host("ssh", "[::1]"), "::1");
        assert_eq!(destination_host("ssh", "::1"), "::1");
        assert_eq!(destination_host("sftp", "::1"), "[::1]");
        assert_eq!(destination_host("sftp", "[fe80::1]"), "[fe80::1]");
        assert_eq!(destination_host("sftp", "db.example"), "db.example");
        let spec = SshSpec {
            program: "ssh",
            user: "ops".into(),
            address: "[2001:db8::5]".into(),
            port: 22,
            identity: None,
            options: Vec::new(),
            temp_files: Vec::new(),
        };
        let out = std::process::Command::new("ssh").arg("-G").args(spec.args()).output().expect("ssh not installed");
        assert!(String::from_utf8_lossy(&out.stdout).contains("hostname 2001:db8::5"));
    }

    /// A key written for a session is wiped as soon as the program exits,
    /// not only when the tab is closed, and the process is reaped.
    #[cfg(unix)]
    #[test]
    fn temp_files_are_wiped_when_the_program_exits() {
        let key = std::env::temp_dir().join(format!("shellyard-test-exit-{}", crate::model::Host::new_id()));
        std::fs::write(&key, "secret").unwrap();
        let ctx = egui::Context::default();
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.args(["-c", "exit 0"]);
        let mut t = Terminal::spawn(cmd, "x".into(), &ctx).unwrap();
        t.temp_files = vec![key.clone()];
        let start = std::time::Instant::now();
        while !(t.exited && t.reaped) && start.elapsed() < std::time::Duration::from_secs(5) {
            t.pump(&ctx);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(t.exited && t.reaped);
        assert!(!key.exists(), "key file still on disk after the session ended");
    }

    #[cfg(unix)]
    #[test]
    fn selection_copies_screen_text() {
        let (_ctx, mut t) = run_script("printf 'hello world'", false);
        assert_eq!(t.selection_text(), None);
        let at = |c| Point::new(alacritty_terminal::index::Line(0), Column(c));
        let mut sel = Selection::new(SelectionType::Simple, at(0), Side::Left);
        sel.update(at(4), Side::Right);
        t.term.selection = Some(sel);
        assert_eq!(t.selection_text().as_deref(), Some("hello"));
        t.term.selection = Some(Selection::new(SelectionType::Semantic, at(8), Side::Left));
        assert_eq!(t.selection_text().as_deref(), Some("world"));
    }

    #[test]
    fn rejects_option_injection() {
        let ctx = egui::Context::default();
        let spec = |user: &str, address: &str| SshSpec {
            program: "ssh",
            user: user.into(),
            address: address.into(),
            port: 22,
            identity: None,
            options: Vec::new(),
            temp_files: Vec::new(),
        };
        assert!(Terminal::openssh(spec("ops", "-oProxyCommand=touch /tmp/x"), "x".into(), &ctx).is_err());
        assert!(Terminal::openssh(spec("-l", "host"), "x".into(), &ctx).is_err());
    }
}
