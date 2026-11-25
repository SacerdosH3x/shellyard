//! SSH keys, tunnels and notes pages, plus their dialogs.

use std::path::{Path, PathBuf};

use super::*;
use crate::model::{safe_arg, Credential, ForwardKind, Secret, Tunnel};

pub(super) fn expand_home(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(p),
    }
}

pub(super) fn collapse_home(p: &Path) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Ok(rest) = p.strip_prefix(&home) {
            return format!("~/{}", rest.display());
        }
    }
    p.display().to_string()
}

fn pub_path(private: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", private.display()))
}

fn read_public(private: &Path) -> Option<String> {
    std::fs::read_to_string(pub_path(private)).ok().map(|s| s.trim().to_string()).filter(|s| s.starts_with("ssh-") || s.starts_with("ecdsa-"))
}

fn key_public(c: &Credential) -> Option<String> {
    c.public.clone().or_else(|| match &c.source {
        Some(KeySource::File(p)) => read_public(&expand_home(p)),
        _ => None,
    })
}

/// A masked text field with a show/hide toggle.
pub(super) fn secret_field(ui: &mut Ui, text: &mut Zeroizing<String>, show: &mut bool, hint: &str, width: f32) {
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut **text).password(!*show).hint_text(hint).desired_width(width - 30.0));
        let glyph = if *show { icon::EYE_SLASH } else { icon::EYE };
        if widgets::icon_button(ui, glyph, if *show { "Hide" } else { "Show" }).clicked() {
            *show = !*show;
        }
    });
}

/// `Err` if `s` cannot be passed to OpenSSH as a user name.
pub(super) fn check_user(s: &str) -> Result<(), String> {
    if s.starts_with('-') || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("User name must not contain spaces or start with '-'.".into());
    }
    Ok(())
}

/// Private keys in ~/.ssh, recognised by a matching `.pub` file.
fn detected_keys() -> Vec<PathBuf> {
    let Some(dir) = dirs::home_dir().map(|h| h.join(".ssh")) else { return Vec::new() };
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_none_or(|e| e != "pub") && pub_path(p).is_file())
        .collect();
    out.sort();
    out
}

fn page_header(ui: &mut Ui, glyph: &str, title: &str, subtitle: &str) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
        widgets::icon_tile(ui, r, glyph, theme::ACCENT, theme::accent_soft());
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(RichText::new(title).size(17.0).strong().color(theme::TEXT));
            ui.label(RichText::new(subtitle).size(11.5).color(theme::MUTED));
        });
    });
    ui.add_space(12.0);
}

/// A trash button that asks for confirmation in a small popup menu.
fn delete_menu(ui: &mut Ui, question: &str) -> bool {
    let mut confirmed = false;
    ui.menu_button(RichText::new(icon::TRASH).color(theme::MUTED), |ui| {
        ui.set_min_width(220.0);
        ui.label(question);
        if ui.button(RichText::new("Delete").color(theme::DANGER)).clicked() {
            confirmed = true;
            ui.close_menu();
        }
    });
    confirmed
}

fn host_chars_ok(s: &str) -> bool {
    let bracketed = s.starts_with('[') && s.ends_with(']');
    safe_arg(s)
        && s.chars().all(|c| c.is_ascii_alphanumeric() || ".-_[]:".contains(c))
        && (!s.contains(':') || bracketed)
}

/// True for addresses only this machine can connect to.
pub(crate) fn is_loopback(addr: &str) -> bool {
    let a = addr.trim_start_matches('[').trim_end_matches(']');
    a.eq_ignore_ascii_case("localhost") || a.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

// ---------------------------------------------------------------------------
// Forms

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyMode {
    None,
    File,
    Vault,
}

pub(crate) struct CredentialForm {
    /// Name, user name and id; secrets live in the fields below while editing.
    c: Credential,
    is_new: bool,
    password: Zeroizing<String>,
    passphrase: Zeroizing<String>,
    key_mode: KeyMode,
    /// The key file (or, for a key stored in the vault, a file to import).
    key_path: String,
    /// Editing a credential whose key is already stored in the vault.
    has_embedded: bool,
    show: bool,
    error: Option<String>,
}

impl CredentialForm {
    fn new() -> Self {
        Self::edit(&Credential { id: Host::new_id(), ..Credential::default() }).with_new()
    }

    fn with_new(mut self) -> Self {
        self.is_new = true;
        self
    }

    fn edit(c: &Credential) -> Self {
        let (key_mode, key_path, has_embedded) = match &c.source {
            None => (KeyMode::None, String::new(), false),
            Some(KeySource::File(p)) => (KeyMode::File, p.clone(), false),
            Some(KeySource::Embedded(_)) => (KeyMode::Vault, String::new(), true),
        };
        let reveal = |s: &Option<Secret>| Zeroizing::new(s.as_ref().map(|s| s.expose().to_string()).unwrap_or_default());
        Self {
            c: Credential { id: c.id.clone(), name: c.name.clone(), username: c.username.clone(), ..Credential::default() },
            is_new: false,
            password: reveal(&c.password),
            passphrase: reveal(&c.passphrase),
            key_mode,
            key_path,
            has_embedded,
            show: false,
            error: None,
        }
    }

    /// Builds the credential to save; `existing` supplies a key already stored in the vault.
    fn validate(&self, existing: Option<&Credential>) -> Result<Credential, String> {
        let username = self.c.username.trim().to_string();
        check_user(&username)?;
        let path = expand_home(self.key_path.trim());
        let read_key = || -> Result<Zeroizing<String>, String> {
            if !path.is_file() {
                return Err(format!("{} is not a file.", path.display()));
            }
            let contents = Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| format!("Cannot read the key: {e}"))?);
            if !contents.contains("PRIVATE KEY") {
                return Err("That file is not a private key (pick the file without .pub).".into());
            }
            Ok(contents)
        };
        let (source, public) = match self.key_mode {
            KeyMode::None => (None, None),
            KeyMode::File => {
                read_key()?;
                (Some(KeySource::File(collapse_home(&path))), read_public(&path))
            }
            KeyMode::Vault if self.key_path.trim().is_empty() => match existing.and_then(|c| c.source.as_ref()) {
                Some(src @ KeySource::Embedded(_)) => (Some(src.clone()), existing.and_then(|c| c.public.clone())),
                _ => return Err("Pick the key file to store in the vault.".into()),
            },
            KeyMode::Vault => (Some(KeySource::Embedded(read_key()?.to_string())), read_public(&path)),
        };
        let password = Secret::non_empty(&self.password);
        if source.is_none() && password.is_none() && username.is_empty() {
            return Err("Add a user name, a password or an SSH key.".into());
        }
        let mut name = self.c.name.trim().to_string();
        if name.is_empty() {
            name = match (&source, username.is_empty()) {
                (Some(_), _) if !self.key_path.trim().is_empty() => path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                (_, false) => username.clone(),
                _ => "credential".into(),
            };
        }
        let passphrase = if source.is_some() { Secret::non_empty(&self.passphrase) } else { None };
        Ok(Credential { id: self.c.id.clone(), name, username, password, source, passphrase, public })
    }
}

pub(crate) struct NewKeyForm {
    name: String,
    comment: String,
    error: Option<String>,
}

pub(crate) struct TunnelForm {
    t: Tunnel,
    is_new: bool,
    bind_port: String,
    dest_port: String,
    error: Option<String>,
}

impl TunnelForm {
    pub(super) fn new_for(host_id: Option<String>, inv: &Inventory) -> Self {
        let host_id = host_id
            .or_else(|| inv.hosts.iter().find(|h| h.has(Protocol::Ssh)).map(|h| h.id.clone()))
            .unwrap_or_default();
        let t = Tunnel {
            id: Host::new_id(),
            name: String::new(),
            host_id,
            kind: ForwardKind::Local,
            bind_addr: "127.0.0.1".into(),
            bind_port: 8080,
            dest_host: "127.0.0.1".into(),
            dest_port: 80,
            auto_start: false,
        };
        Self { bind_port: t.bind_port.to_string(), dest_port: t.dest_port.to_string(), t, is_new: true, error: None }
    }

    pub(super) fn edit(t: Tunnel) -> Self {
        Self { bind_port: t.bind_port.to_string(), dest_port: t.dest_port.to_string(), t, is_new: false, error: None }
    }

    fn validate(&self, inv: &Inventory) -> Result<Tunnel, String> {
        let mut t = self.t.clone();
        t.bind_addr = t.bind_addr.trim().to_string();
        t.dest_host = t.dest_host.trim().to_string();
        if inv.hosts.iter().all(|h| h.id != t.host_id) {
            return Err("Pick the SSH host the tunnel goes through.".into());
        }
        if !host_chars_ok(&t.bind_addr) {
            return Err("Listen address must be a host name or IP (IPv6 in [brackets]).".into());
        }
        let port = |s: &str, what: &str| match s.trim().parse::<u16>() {
            Ok(p) if p > 0 => Ok(p),
            _ => Err(format!("{what} must be a number from 1 to 65535.")),
        };
        t.bind_port = port(&self.bind_port, "Listen port")?;
        if t.kind != ForwardKind::Dynamic {
            if !host_chars_ok(&t.dest_host) {
                return Err("Destination must be a host name or IP (IPv6 in [brackets]).".into());
            }
            t.dest_port = port(&self.dest_port, "Destination port")?;
        }
        t.name = t.name.trim().to_string();
        if t.name.is_empty() {
            t.name = t.describe();
        }
        Ok(t)
    }
}

impl App {
    // -----------------------------------------------------------------------
    // Credentials

    pub(super) fn credentials_page(&mut self, ui: &mut Ui) {
        page_frame(ui, |ui, _w| {
            page_header(
                ui,
                icon::IDENTIFICATION_CARD,
                "Credentials",
                "User names, passwords, SSH keys and passphrases, encrypted in the vault. Pick one per host in Edit host.",
            );
            ui.horizontal(|ui| {
                if widgets::primary_button(ui, &format!("  {}  New credential  ", icon::PLUS)).clicked() {
                    self.credential_form = Some(CredentialForm::new());
                }
                if ui.button(format!("{}  Generate SSH key", icon::STAR_FOUR)).clicked() {
                    self.new_key_form = Some(NewKeyForm { name: "shellyard_ed25519".into(), comment: "shellyard".into(), error: None });
                }
            });
            ui.add_space(12.0);

            let mut copy: Option<Option<String>> = None;
            let mut delete: Option<String> = None;
            let mut edit: Option<String> = None;
            if self.inventory.credentials.is_empty() {
                ui.label(RichText::new("No credentials yet. Hosts without one use your SSH agent and ~/.ssh defaults, and ask for passwords in the terminal.").color(theme::FAINT));
            }
            for c in &self.inventory.credentials {
                let used = self.inventory.hosts.iter().filter(|h| h.credential_id.as_ref() == Some(&c.id)).count();
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
                        let glyph = if c.source.is_some() { icon::KEY } else { icon::IDENTIFICATION_CARD };
                        widgets::icon_tile(ui, r, glyph, theme::BLUE, theme::BLUE_BG);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.label(RichText::new(&c.name).strong().color(theme::TEXT));
                            ui.label(RichText::new(format!("{} · used by {used} host{}", c.summary(), if used == 1 { "" } else { "s" })).size(11.0).color(theme::FAINT));
                            if let Some(KeySource::File(p)) = &c.source {
                                if !expand_home(p).is_file() {
                                    ui.label(RichText::new(format!("{}  Key file not found", icon::WARNING)).size(11.0).color(theme::DANGER));
                                }
                            }
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if delete_menu(ui, "Delete this credential? Key files on disk are not touched.") {
                                delete = Some(c.id.clone());
                            }
                            if widgets::icon_button(ui, icon::PENCIL_SIMPLE, "Edit").clicked() {
                                edit = Some(c.id.clone());
                            }
                            if c.source.is_some() && ui.button(format!("{}  Copy public key", icon::COPY)).clicked() {
                                copy = Some(key_public(c));
                            }
                        });
                    });
                });
                ui.add_space(6.0);
            }

            // Keys found in ~/.ssh that are not registered yet.
            let known: Vec<PathBuf> = self
                .inventory
                .credentials
                .iter()
                .filter_map(|c| match &c.source {
                    Some(KeySource::File(p)) => Some(expand_home(p)),
                    _ => None,
                })
                .collect();
            let found: Vec<PathBuf> = detected_keys().into_iter().filter(|p| !known.contains(p)).collect();
            let mut add: Option<PathBuf> = None;
            if !found.is_empty() {
                section_label(ui, None, "SSH keys found in ~/.ssh");
                for p in &found {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(icon::KEY).color(theme::FAINT));
                        ui.monospace(collapse_home(p));
                        if ui.small_button("Add").clicked() {
                            add = Some(p.clone());
                        }
                    });
                }
                ui.add_space(12.0);
            }

            card(ui, |ui| {
                ui.label(RichText::new("How sign-in works").strong().color(theme::TEXT));
                for line in [
                    "A credential can hold a user name, a password, an SSH key and the key's passphrase. Leave out what you don't need.",
                    "A host can also have its own password (Edit host); it wins over the credential's.",
                    "Saved passwords and passphrases are handed to OpenSSH only when it asks for them, for that host and that key. If one is wrong, OpenSSH asks again in the terminal.",
                    "Key file: only the path is stored. Stored in vault: the key is encrypted in the vault and written to a private file (0600) only while a session runs.",
                    "To put a public key on a server, right-click the host → Install SSH key on host (runs ssh-copy-id).",
                ] {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("•").color(theme::FAINT));
                        ui.label(RichText::new(line).color(theme::MUTED));
                    });
                }
            });

            if let Some(p) = add {
                let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                self.inventory.credentials.push(Credential::key(name, KeySource::File(collapse_home(&p)), read_public(&p)));
                self.dirty = true;
            }
            if let Some(id) = edit {
                if let Some(c) = self.inventory.credentials.iter().find(|c| c.id == id) {
                    self.credential_form = Some(CredentialForm::edit(c));
                }
            }
            if let Some(id) = delete {
                self.inventory.credentials.retain(|c| c.id != id);
                for h in &mut self.inventory.hosts {
                    if h.credential_id.as_ref() == Some(&id) {
                        h.credential_id = None;
                    }
                }
                self.dirty = true;
            }
            match copy {
                Some(Some(public)) => {
                    ui.ctx().copy_text(public);
                    self.toast(ui.ctx(), "Public key copied.", false);
                }
                Some(None) => self.toast(ui.ctx(), "No public key found for this key (no .pub file next to it).", true),
                None => {}
            }
        });
    }

    pub(super) fn credential_form_ui(&mut self, ctx: &egui::Context) {
        let Some(form) = self.credential_form.as_mut() else { return };
        let (mut save, mut close) = (false, false);
        egui::Window::new(if form.is_new { "New credential" } else { "Edit credential" })
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(460.0)
            .show(ctx, |ui| {
                egui::Grid::new("credform").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label("Name");
                    ui.add(egui::TextEdit::singleline(&mut form.c.name).hint_text("prod admin").desired_width(270.0));
                    ui.end_row();
                    ui.label("User name");
                    ui.add(egui::TextEdit::singleline(&mut form.c.username).hint_text("optional, e.g. ops or CORP\\ops").desired_width(270.0));
                    ui.end_row();
                    ui.label("Password");
                    secret_field(ui, &mut form.password, &mut form.show, "optional", 270.0);
                    ui.end_row();
                    ui.label("SSH key");
                    ui.horizontal(|ui| {
                        for (mode, label) in [(KeyMode::None, "None"), (KeyMode::File, "Key file"), (KeyMode::Vault, "Stored in vault")] {
                            ui.selectable_value(&mut form.key_mode, mode, label);
                        }
                    });
                    ui.end_row();
                    if form.key_mode != KeyMode::None {
                        ui.label("");
                        ui.horizontal(|ui| {
                            let hint = if form.key_mode == KeyMode::Vault && form.has_embedded {
                                "keep the stored key, or pick a file to replace it"
                            } else {
                                "~/.ssh/id_ed25519"
                            };
                            ui.add(egui::TextEdit::singleline(&mut form.key_path).hint_text(hint).desired_width(200.0));
                            if ui.button("Browse…").clicked() {
                                let start = dirs::home_dir().map(|h| h.join(".ssh")).unwrap_or_default();
                                if let Some(p) = rfd::FileDialog::new().set_directory(start).set_title("Choose a private key").pick_file() {
                                    if form.c.name.trim().is_empty() {
                                        form.c.name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                                    }
                                    form.key_path = collapse_home(&p);
                                }
                            }
                        });
                        ui.end_row();
                        ui.label("Passphrase");
                        secret_field(ui, &mut form.passphrase, &mut form.show, "only if the key has one", 270.0);
                        ui.end_row();
                    }
                });
                ui.add_space(4.0);
                let note = match form.key_mode {
                    KeyMode::None => "Without a key, OpenSSH also tries your SSH agent and ~/.ssh keys.",
                    KeyMode::File => "Only the path is stored. The file must stay where it is.",
                    KeyMode::Vault => "The key is copied into the encrypted vault and travels with it (backups, other computers).",
                };
                ui.label(RichText::new(note).size(11.0).color(theme::FAINT));
                if let Some(e) = &form.error {
                    ui.label(RichText::new(e.as_str()).color(theme::DANGER));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if widgets::primary_button(ui, "  Save  ").clicked() {
                        save = true;
                    }
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                        close = true;
                    }
                });
            });

        if save {
            let existing = self.inventory.credentials.iter().find(|c| c.id == form.c.id);
            match form.validate(existing) {
                Ok(c) => {
                    if let Some(slot) = self.inventory.credentials.iter_mut().find(|x| x.id == c.id) {
                        *slot = c;
                    } else {
                        self.inventory.credentials.push(c);
                    }
                    self.dirty = true;
                    self.credential_form = None;
                }
                Err(e) => form.error = Some(e),
            }
        } else if close {
            self.credential_form = None;
        }
    }

    pub(super) fn new_key_form_ui(&mut self, ctx: &egui::Context, actions: &mut Vec<Action>) {
        let Some(form) = self.new_key_form.as_mut() else { return };
        let (mut create, mut close) = (false, false);
        egui::Window::new("Generate SSH key")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(420.0)
            .show(ctx, |ui| {
                egui::Grid::new("newkey").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label("File name");
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("~/.ssh/").color(theme::FAINT));
                        ui.add(egui::TextEdit::singleline(&mut form.name).desired_width(200.0));
                    });
                    ui.end_row();
                    ui.label("Comment");
                    ui.add(egui::TextEdit::singleline(&mut form.comment).desired_width(260.0));
                    ui.end_row();
                });
                ui.label(
                    RichText::new("Creates an Ed25519 key with ssh-keygen in a terminal tab. It asks for an optional passphrase there.")
                        .size(11.0)
                        .color(theme::FAINT),
                );
                if let Some(e) = &form.error {
                    ui.label(RichText::new(e.as_str()).color(theme::DANGER));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if widgets::primary_button(ui, "  Generate  ").clicked() {
                        create = true;
                    }
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                        close = true;
                    }
                });
            });
        if create {
            let name = form.name.trim().to_string();
            let comment = form.comment.trim().to_string();
            let exists = dirs::home_dir().is_some_and(|h| h.join(".ssh").join(&name).exists());
            if name.is_empty() || name.starts_with(['-', '.']) || !name.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)) {
                form.error = Some("Use letters, digits, '_', '-' and '.' only.".into());
            } else if exists {
                form.error = Some(format!("~/.ssh/{name} already exists."));
            } else if comment.chars().any(|c| c.is_control()) {
                form.error = Some("The comment cannot contain control characters.".into());
            } else {
                actions.push(Action::GenerateKey(name, comment));
                self.new_key_form = None;
            }
        } else if close {
            self.new_key_form = None;
        }
    }

    // -----------------------------------------------------------------------
    // Tunnels

    pub(super) fn tunnels_page(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        page_frame(ui, |ui, w| {
            page_header(ui, icon::ARROWS_LEFT_RIGHT, "Tunnels", "Port forwarding over SSH. Each tunnel runs `ssh -N` in the background.");
            if widgets::primary_button(ui, &format!("  {}  New tunnel  ", icon::PLUS)).clicked() {
                actions.push(Action::NewTunnel(None));
            }
            ui.add_space(12.0);

            if self.inventory.tunnels.is_empty() {
                card(ui, |ui| {
                    ui.label(RichText::new("No tunnels yet").strong().color(theme::TEXT));
                    for (k, d) in [
                        ("Local (-L)", "Reach a service behind a host, e.g. a database: 127.0.0.1:15432 on this computer → 127.0.0.1:5432 on the server."),
                        ("Remote (-R)", "Expose something on this computer to the server, e.g. a dev web server."),
                        ("SOCKS proxy (-D)", "Browse through the host: point an app at the SOCKS5 port."),
                    ] {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(k).strong().color(theme::MUTED));
                            ui.label(RichText::new(d).color(theme::FAINT));
                        });
                    }
                });
            }

            let tunnels = self.inventory.tunnels.clone();
            let mut delete: Option<String> = None;
            for t in &tunnels {
                let host = self.host(&t.host_id).map(|h| h.name.clone()).unwrap_or_else(|| "(deleted host)".into());
                let run = self.tunnels_running.get(&t.id).map(|r| r.exited);
                let last = self.tunnels_running.get(&t.id).map(|r| r.last_line()).unwrap_or_default();
                let lower = last.to_lowercase();
                let waiting = lower.contains("password") || lower.contains("passphrase") || lower.contains("(yes/no");
                let (dot, status) = match run {
                    None => (theme::FAINT, "Stopped".to_string()),
                    Some(true) => (theme::DANGER, if last.is_empty() { "Exited".into() } else { format!("Exited: {last}") }),
                    Some(_) if waiting => (theme::FOLDER_COLORS[2], "Waiting for input. Open the console to answer.".into()),
                    Some(_) => (theme::ACCENT, "Running".into()),
                };
                let running = run == Some(false);
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(Vec2::new(14.0, 30.0), Sense::hover());
                        ui.painter().circle_filled(r.center(), 5.0, dot);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.label(RichText::new(&t.name).strong().color(theme::TEXT));
                            ui.label(RichText::new(format!("{} · via {host}", t.describe())).size(11.5).color(theme::MUTED));
                            let status = if status.chars().count() > 90 { format!("{}…", status.chars().take(89).collect::<String>()) } else { status.clone() };
                            ui.label(RichText::new(status).size(11.0).color(if dot == theme::DANGER { theme::DANGER } else { theme::FAINT }));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if delete_menu(ui, "Delete this tunnel?") {
                                delete = Some(t.id.clone());
                            }
                            if widgets::icon_button(ui, icon::PENCIL_SIMPLE, "Edit").clicked() {
                                actions.push(Action::EditTunnel(t.id.clone()));
                            }
                            if run.is_some() {
                                let open = self.tunnel_console.as_ref() == Some(&t.id);
                                if widgets::icon_button(ui, icon::TERMINAL, if open { "Hide console" } else { "Show console" }).clicked() {
                                    self.tunnel_console = if open { None } else { Some(t.id.clone()) };
                                }
                            }
                            if running {
                                if ui.button(format!("{}  Stop", icon::STOP)).clicked() {
                                    actions.push(Action::StopTunnel(t.id.clone()));
                                }
                            } else if widgets::primary_button(ui, &format!("  {}  Start  ", icon::PLAY)).clicked() {
                                actions.push(Action::StartTunnel(t.id.clone()));
                                self.tunnel_console = Some(t.id.clone());
                            }
                            if running && t.kind != ForwardKind::Remote {
                                let endpoint = format!("{}:{}", t.bind_addr, t.bind_port);
                                if widgets::icon_button(ui, icon::COPY, &format!("Copy {endpoint}")).clicked() {
                                    ui.ctx().copy_text(endpoint);
                                }
                            }
                        });
                    });
                    if self.tunnel_console.as_ref() == Some(&t.id) {
                        if let Some(term) = self.tunnels_running.get_mut(&t.id) {
                            ui.add_space(6.0);
                            let (rect, _) = ui.allocate_exact_size(Vec2::new(w - 32.0, 200.0), Sense::hover());
                            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(rect));
                            term.show(&mut child);
                        }
                    }
                });
                ui.add_space(6.0);
            }
            if let Some(id) = delete {
                self.tunnels_running.remove(&id);
                self.inventory.tunnels.retain(|t| t.id != id);
                self.dirty = true;
            }
        });
    }

    pub(super) fn tunnel_form_ui(&mut self, ctx: &egui::Context) {
        let Some(form) = self.tunnel_form.as_mut() else { return };
        let hosts: Vec<(String, String)> =
            self.inventory.hosts.iter().filter(|h| h.has(Protocol::Ssh)).map(|h| (h.id.clone(), h.name.clone())).collect();
        let running = self.tunnels_running.get(&form.t.id).is_some_and(|r| !r.exited);
        let (mut save, mut close) = (false, false);
        egui::Window::new(if form.is_new { "New tunnel" } else { "Edit tunnel" })
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(440.0)
            .show(ctx, |ui| {
                let t = &mut form.t;
                egui::Grid::new("tunnelform").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label("Name");
                    ui.add(egui::TextEdit::singleline(&mut t.name).hint_text("Postgres on prod").desired_width(260.0));
                    ui.end_row();
                    ui.label("Through host");
                    let current = hosts.iter().find(|(id, _)| *id == t.host_id).map(|(_, n)| n.clone()).unwrap_or_else(|| "Pick a host".into());
                    egui::ComboBox::from_id_salt("tunnelhost").width(260.0).selected_text(current).show_ui(ui, |ui| {
                        for (id, name) in &hosts {
                            ui.selectable_value(&mut t.host_id, id.clone(), name.as_str());
                        }
                    });
                    ui.end_row();
                    ui.label("Type");
                    egui::ComboBox::from_id_salt("tunnelkind").width(260.0).selected_text(t.kind.label()).show_ui(ui, |ui| {
                        for k in ForwardKind::ALL {
                            ui.selectable_value(&mut t.kind, k, k.label());
                        }
                    });
                    ui.end_row();
                    let listen = if t.kind == ForwardKind::Remote { "Listen on host" } else { "Listen here" };
                    ui.label(listen);
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut t.bind_addr).desired_width(150.0));
                        ui.label(":");
                        ui.add(egui::TextEdit::singleline(&mut form.bind_port).desired_width(70.0));
                    });
                    ui.end_row();
                    if t.kind != ForwardKind::Dynamic {
                        ui.label(if t.kind == ForwardKind::Remote { "Forward to (here)" } else { "Forward to (from host)" });
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut t.dest_host).desired_width(150.0));
                            ui.label(":");
                            ui.add(egui::TextEdit::singleline(&mut form.dest_port).desired_width(70.0));
                        });
                        ui.end_row();
                    }
                    ui.label("");
                    ui.checkbox(&mut t.auto_start, "Start when the vault is unlocked");
                    ui.end_row();
                });
                let host = hosts.iter().find(|(id, _)| *id == t.host_id).map(|(_, n)| n.as_str()).unwrap_or("the host");
                let explain = match t.kind {
                    ForwardKind::Local => format!(
                        "Connections to {}:{} on this computer go through {host} to {}:{}.",
                        t.bind_addr, form.bind_port, t.dest_host, form.dest_port
                    ),
                    ForwardKind::Remote => format!(
                        "Connections to {}:{} on {host} come back through this computer to {}:{}.",
                        t.bind_addr, form.bind_port, t.dest_host, form.dest_port
                    ),
                    ForwardKind::Dynamic => format!("Point apps at SOCKS5 proxy {}:{}; their traffic leaves from {host}.", t.bind_addr, form.bind_port),
                };
                ui.add_space(4.0);
                ui.label(RichText::new(explain).size(11.5).color(theme::MUTED));
                if !is_loopback(t.bind_addr.trim()) {
                    let who = if t.kind == ForwardKind::Remote { "Anyone who can reach the host" } else { "Other computers on your network" };
                    let what = if t.kind == ForwardKind::Dynamic { "use this proxy" } else { "use this tunnel" };
                    ui.label(
                        RichText::new(format!("{} {who} can {what}. Use 127.0.0.1 to keep it private.", icon::WARNING))
                            .size(11.5)
                            .color(theme::DANGER),
                    );
                }
                if running {
                    ui.label(RichText::new("This tunnel is running. Stop and start it to apply changes.").size(11.0).color(theme::FAINT));
                }
                if let Some(e) = &form.error {
                    ui.label(RichText::new(e.as_str()).color(theme::DANGER));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if widgets::primary_button(ui, "  Save  ").clicked() {
                        save = true;
                    }
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                        close = true;
                    }
                });
            });
        if save {
            match form.validate(&self.inventory) {
                Ok(t) => {
                    if let Some(existing) = self.inventory.tunnels.iter_mut().find(|x| x.id == t.id) {
                        *existing = t;
                    } else {
                        self.inventory.tunnels.push(t);
                    }
                    self.dirty = true;
                    self.tunnel_form = None;
                    self.page = Page::Tunnels;
                    self.active = None;
                }
                Err(e) => form.error = Some(e),
            }
        } else if close {
            self.tunnel_form = None;
        }
    }

    // -----------------------------------------------------------------------
    // Notes

    pub(super) fn notes_page(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let hosts: Vec<(String, String)> = self.inventory.hosts.iter().map(|h| (h.id.clone(), h.name.clone())).collect();
        let host_name = |id: &Option<String>| id.as_ref().and_then(|id| hosts.iter().find(|(h, _)| h == id)).map(|(_, n)| n.clone());

        egui::SidePanel::left("notes-list")
            .resizable(true)
            .default_width(270.0)
            .width_range(200.0..=420.0)
            .frame(Frame::none().fill(theme::PANEL).inner_margin(Margin::same(10.0)).stroke(Stroke::new(1.0_f32, theme::BORDER)))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Notes").strong().size(14.0).color(theme::TEXT));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::icon_button(ui, icon::PLUS, "New note").clicked() {
                            actions.push(Action::NewNote(None));
                        }
                    });
                });
                ui.add_space(4.0);
                widgets::search_box(ui, &mut self.note_search, "Search notes…", 32.0, false, egui::Id::new("note-search"));
                ui.add_space(6.0);
                let q = self.note_search.trim().to_lowercase();
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    let mut notes: Vec<&crate::model::Note> = self
                        .inventory
                        .notes
                        .iter()
                        .filter(|n| {
                            q.is_empty()
                                || n.title.to_lowercase().contains(&q)
                                || n.body.to_lowercase().contains(&q)
                                || host_name(&n.host_id).is_some_and(|h| h.to_lowercase().contains(&q))
                        })
                        .collect();
                    notes.sort_by_key(|n| std::cmp::Reverse(n.updated));
                    for n in notes {
                        let selected = self.note_selected.as_ref() == Some(&n.id);
                        let (rect, r) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 40.0), Sense::click());
                        if selected {
                            ui.painter().rect_filled(rect, 6.0, theme::accent_soft());
                        } else if r.hovered() {
                            ui.painter().rect_filled(rect, 6.0, theme::SURFACE_HOVER);
                        }
                        let title = if n.title.trim().is_empty() { "Untitled" } else { n.title.as_str() };
                        let color = if selected { theme::ACCENT } else { theme::TEXT };
                        let g = widgets::elided(ui, title, FontId::proportional(13.0), color, rect.width() - 20.0);
                        ui.painter().galley(rect.min + Vec2::new(10.0, 4.0), g, color);
                        let mut sub = widgets::relative_time(n.updated);
                        if let Some(h) = host_name(&n.host_id) {
                            sub = format!("{h} · {sub}");
                        }
                        let g = widgets::elided(ui, &sub, FontId::proportional(10.5), theme::FAINT, rect.width() - 20.0);
                        ui.painter().galley(rect.min + Vec2::new(10.0, 22.0), g, theme::FAINT);
                        if r.clicked() {
                            self.note_selected = Some(n.id.clone());
                        }
                    }
                });
            });

        egui::CentralPanel::default().frame(Frame::none().fill(theme::BG).inner_margin(Margin::same(20.0))).show_inside(ui, |ui| {
            let idx = self.note_selected.as_ref().and_then(|id| self.inventory.notes.iter().position(|n| &n.id == id));
            let Some(idx) = idx else {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new(icon::NOTE).size(32.0).color(theme::FAINT));
                    ui.label(RichText::new("Commands, runbooks and reminders, encrypted in your vault.").color(theme::MUTED));
                    ui.add_space(8.0);
                    if widgets::primary_button(ui, "  New note  ").clicked() {
                        actions.push(Action::NewNote(None));
                    }
                });
                return;
            };
            let sessions: Vec<(usize, String)> = self.sessions.iter().enumerate().map(|(i, s)| (i, s.label.clone())).collect();
            let mut changed = false;
            let mut delete = false;
            let note = &mut self.inventory.notes[idx];

            ui.horizontal(|ui| {
                let r = ui.add(
                    egui::TextEdit::singleline(&mut note.title)
                        .hint_text("Title")
                        .font(FontId::proportional(18.0))
                        .frame(false)
                        .desired_width(ui.available_width() - 330.0),
                );
                changed |= r.changed();
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if delete_menu(ui, "Delete this note?") {
                        delete = true;
                    }
                    if widgets::icon_button(ui, icon::COPY, "Copy note").clicked() {
                        ui.ctx().copy_text(note.body.clone());
                    }
                    ui.add_enabled_ui(!sessions.is_empty(), |ui| {
                        ui.menu_button(format!("{}  Paste into terminal", icon::TERMINAL), |ui| {
                            for (i, label) in &sessions {
                                if ui.button(label.as_str()).clicked() {
                                    actions.push(Action::PasteNote(note.id.clone(), *i));
                                    ui.close_menu();
                                }
                            }
                        })
                        .response
                        .on_disabled_hover_text("Open a terminal tab first");
                    });
                });
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new("Host").size(11.5).color(theme::FAINT));
                let current = host_name(&note.host_id).unwrap_or_else(|| "None".into());
                egui::ComboBox::from_id_salt("notehost").selected_text(current).show_ui(ui, |ui| {
                    changed |= ui.selectable_value(&mut note.host_id, None, "None").changed();
                    for (id, name) in &hosts {
                        changed |= ui.selectable_value(&mut note.host_id, Some(id.clone()), name.as_str()).changed();
                    }
                });
                if let Some(id) = note.host_id.clone() {
                    if ui.link(RichText::new(format!("{}  Connect", icon::PLAY)).size(11.5)).clicked() {
                        actions.push(Action::Connect(id, Protocol::Ssh));
                    }
                }
            });
            ui.add_space(8.0);
            egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                let r = ui.add_sized(
                    ui.available_size(),
                    egui::TextEdit::multiline(&mut note.body)
                        .code_editor()
                        .hint_text("Write commands or notes. \"Paste into terminal\" sends the whole note.")
                        .margin(Vec2::new(12.0, 10.0)),
                );
                changed |= r.changed();
            });
            if changed {
                note.updated = now();
                self.dirty = true;
            }
            if delete {
                self.inventory.notes.remove(idx);
                self.note_selected = None;
                self.dirty = true;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        for a in ["127.0.0.1", "localhost", "[::1]", "::1", "127.1.2.3"] {
            assert!(is_loopback(a), "{a}");
        }
        for a in ["0.0.0.0", "*", "", "192.168.1.5", "[::]", "example.com"] {
            assert!(!is_loopback(a), "{a}");
        }
    }

    #[test]
    fn host_chars_block_injection() {
        for bad in ["-oProxyCommand=x", "a b", "a;b", "a$(x)", "a`x`", "::1", "a\nb", "", "host:22"] {
            assert!(!host_chars_ok(bad), "{bad:?} accepted");
        }
        for ok in ["db.internal", "10.0.0.5", "[::1]", "[fe80::1]", "my_host-1"] {
            assert!(host_chars_ok(ok), "{ok:?} rejected");
        }
    }
}
