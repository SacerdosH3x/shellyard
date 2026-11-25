use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Ssh,
    Sftp,
    Rdp,
    Local,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Protocol::Ssh => "SSH",
            Protocol::Sftp => "SFTP",
            Protocol::Rdp => "RDP",
            Protocol::Local => "LOCAL",
        }
    }
}

/// What a host is, used only to pick an icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HostKind {
    #[default]
    Server,
    Database,
    LoadBalancer,
    Bastion,
    Windows,
}

impl HostKind {
    pub const ALL: [HostKind; 5] = [
        HostKind::Server,
        HostKind::Database,
        HostKind::LoadBalancer,
        HostKind::Bastion,
        HostKind::Windows,
    ];

    pub fn label(self) -> &'static str {
        match self {
            HostKind::Server => "Server",
            HostKind::Database => "Database",
            HostKind::LoadBalancer => "Load balancer",
            HostKind::Bastion => "Bastion",
            HostKind::Windows => "Windows",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub user: String,
    pub protocols: Vec<Protocol>,
    /// Slash-separated path, e.g. "Production/Web". Empty means top level.
    pub folder: String,
    pub favorite: bool,
    #[serde(default)]
    pub kind: HostKind,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Unix seconds of the last connection started from Shellyard.
    #[serde(default)]
    pub last_connected: Option<u64>,
    /// Credential to sign in with (user name, password, SSH key). `None`
    /// means the SSH agent and default keys. Called `key_id` before version 3.
    #[serde(default, alias = "key_id")]
    pub credential_id: Option<String>,
    /// A password for this host only. It wins over the credential's password.
    #[serde(default)]
    pub password: Option<Secret>,
    /// Port for RDP; `port` is the SSH/SFTP port.
    #[serde(default = "default_rdp_port")]
    pub rdp_port: u16,
    /// SHA-256 of the RDP server's certificate, accepted on first connect.
    #[serde(default)]
    pub rdp_fingerprint: Option<String>,
}

pub fn default_rdp_port() -> u16 {
    3389
}

impl Host {
    pub fn new_id() -> String {
        use rand::RngCore;
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    pub fn has(&self, p: Protocol) -> bool {
        self.protocols.contains(&p)
    }

    pub fn protocol_badge(&self) -> String {
        let labels: Vec<&str> = self.protocols.iter().map(|p| p.label()).collect();
        labels.join("+")
    }

    pub fn target(&self) -> String {
        if self.user.is_empty() {
            format!("{}:{}", self.address, self.port)
        } else {
            format!("{}@{}:{}", self.user, self.address, self.port)
        }
    }

    pub fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        self.name.to_lowercase().contains(&q)
            || self.address.to_lowercase().contains(&q)
            || self.user.to_lowercase().contains(&q)
            || self.folder.to_lowercase().contains(&q)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&q))
            || self.protocols.iter().any(|p| p.label().to_lowercase() == q)
    }
}

/// A password or passphrase. Never printed (even in debug output) and wiped
/// from memory when dropped. Stored as a plain string inside the encrypted vault.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// `None` for an empty string, so empty form fields store nothing.
    pub fn non_empty(s: &str) -> Option<Self> {
        (!s.is_empty()).then(|| Self::new(s))
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Where a private key lives.
#[derive(Clone, Serialize, Deserialize)]
pub enum KeySource {
    /// A key file on this computer; only the path is stored.
    File(String),
    /// The key itself, stored inside the encrypted vault. Written to a private
    /// temporary file only while a session that uses it is open.
    Embedded(String),
}

// Never print key material, even in debug output.
impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::File(p) => f.debug_tuple("File").field(p).finish(),
            KeySource::Embedded(_) => f.write_str("Embedded(<redacted>)"),
        }
    }
}

// Wipe key material from memory when the value goes away (lock, save copies).
impl Drop for KeySource {
    fn drop(&mut self) {
        match self {
            KeySource::File(s) | KeySource::Embedded(s) => s.zeroize(),
        }
    }
}

/// What a host signs in with: any mix of a user name, a password, and an SSH
/// key with its passphrase. Before version 3 these were SSH keys only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    /// Used when the host's own user field is empty.
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: Option<Secret>,
    /// The SSH key, if any.
    #[serde(default)]
    pub source: Option<KeySource>,
    /// Passphrase of the SSH key, if it has one and it is saved.
    #[serde(default)]
    pub passphrase: Option<Secret>,
    /// OpenSSH public key line, if known.
    #[serde(default)]
    pub public: Option<String>,
}

impl Credential {
    /// A credential holding only an SSH key.
    pub fn key(name: impl Into<String>, source: KeySource, public: Option<String>) -> Self {
        Self { id: Host::new_id(), name: name.into(), source: Some(source), public, ..Self::default() }
    }

    /// A short list of what it contains, e.g. "user ops · password · key file".
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.username.is_empty() {
            parts.push(format!("user {}", self.username));
        }
        if self.password.is_some() {
            parts.push("password".into());
        }
        match &self.source {
            Some(KeySource::File(p)) => parts.push(format!("key {p}")),
            Some(KeySource::Embedded(_)) => parts.push("key stored in vault".into()),
            None => {}
        }
        if self.passphrase.is_some() {
            parts.push("passphrase".into());
        }
        if parts.is_empty() {
            "empty".into()
        } else {
            parts.join(" · ")
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub updated: u64,
}

// Notes often hold commands with secrets in them: keep bodies out of debug
// output and wipe them from memory on drop.
impl std::fmt::Debug for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Note").field("id", &self.id).field("title", &self.title).finish_non_exhaustive()
    }
}

impl Drop for Note {
    fn drop(&mut self) {
        self.title.zeroize();
        self.body.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwardKind {
    /// `-L`: a port on this computer reaches a destination through the host.
    Local,
    /// `-R`: a port on the host reaches a destination through this computer.
    Remote,
    /// `-D`: a SOCKS5 proxy on this computer that exits through the host.
    Dynamic,
}

impl ForwardKind {
    pub const ALL: [ForwardKind; 3] = [ForwardKind::Local, ForwardKind::Remote, ForwardKind::Dynamic];

    pub fn label(self) -> &'static str {
        match self {
            ForwardKind::Local => "Local (-L)",
            ForwardKind::Remote => "Remote (-R)",
            ForwardKind::Dynamic => "SOCKS proxy (-D)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub host_id: String,
    pub kind: ForwardKind,
    pub bind_addr: String,
    pub bind_port: u16,
    /// Unused for `Dynamic`.
    pub dest_host: String,
    pub dest_port: u16,
    #[serde(default)]
    pub auto_start: bool,
}

impl Tunnel {
    /// The `-L` / `-R` / `-D` argument pair for OpenSSH.
    pub fn ssh_args(&self) -> Vec<String> {
        let bind = format!("{}:{}", self.bind_addr, self.bind_port);
        match self.kind {
            ForwardKind::Local => vec!["-L".into(), format!("{bind}:{}:{}", self.dest_host, self.dest_port)],
            ForwardKind::Remote => vec!["-R".into(), format!("{bind}:{}:{}", self.dest_host, self.dest_port)],
            ForwardKind::Dynamic => vec!["-D".into(), bind],
        }
    }

    pub fn describe(&self) -> String {
        match self.kind {
            ForwardKind::Local => format!("{}:{} → {}:{}", self.bind_addr, self.bind_port, self.dest_host, self.dest_port),
            ForwardKind::Remote => format!("remote {}:{} → {}:{}", self.bind_addr, self.bind_port, self.dest_host, self.dest_port),
            ForwardKind::Dynamic => format!("SOCKS5 on {}:{}", self.bind_addr, self.bind_port),
        }
    }
}

/// True if `s` is safe to pass to OpenSSH as a host, user or forward part:
/// not empty, no whitespace or control characters, and not starting with '-'.
pub fn safe_arg(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// 3: SSH keys became credentials (user, password, key, passphrase); hosts
/// got a password and an RDP port.
pub const INVENTORY_VERSION: u32 = 3;

/// Preferences stored inside the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Lock the vault after this many minutes without keyboard or mouse input. 0 = never.
    pub auto_lock_minutes: u32,
    /// Let programs in a terminal write to the clipboard with OSC 52. Off by
    /// default: a compromised server could otherwise plant a command there.
    pub allow_osc52: bool,
    /// Which program opens RDP connections.
    pub rdp_client: RdpClient,
    /// tmux-style prefix for pane shortcuts.
    pub pane_prefix: PanePrefix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PanePrefix {
    #[default]
    CtrlB,
    CtrlA,
    Off,
}

impl PanePrefix {
    pub const ALL: [PanePrefix; 3] = [PanePrefix::CtrlB, PanePrefix::CtrlA, PanePrefix::Off];

    pub fn label(self) -> &'static str {
        match self {
            PanePrefix::CtrlB => "Ctrl+B (tmux default)",
            PanePrefix::CtrlA => "Ctrl+A (screen style)",
            PanePrefix::Off => "Off",
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self { auto_lock_minutes: 15, allow_osc52: false, rdp_client: RdpClient::Builtin, pane_prefix: PanePrefix::CtrlB }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RdpClient {
    /// Shellyard's own client, inside a tab. Vaults saved before it existed
    /// say "Auto" (which then meant an external client); they get this.
    #[default]
    #[serde(alias = "Auto")]
    Builtin,
    /// FreeRDP when a password is saved (it can sign in with it), otherwise
    /// the system's RDP app.
    #[serde(rename = "ExternalAuto")]
    Auto,
    /// FreeRDP (xfreerdp / sdl-freerdp) in a terminal tab.
    FreeRdp,
    /// Windows App / Microsoft Remote Desktop on macOS, Remmina on Linux.
    System,
}

impl RdpClient {
    pub const ALL: [RdpClient; 4] = [RdpClient::Builtin, RdpClient::Auto, RdpClient::FreeRdp, RdpClient::System];

    pub fn label(self) -> &'static str {
        match self {
            RdpClient::Builtin => "Built-in (in a tab)",
            RdpClient::Auto => "External, automatic",
            RdpClient::FreeRdp => "FreeRDP",
            RdpClient::System => if cfg!(target_os = "macos") { "Windows App" } else { "Remmina" },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    #[serde(default = "default_version")]
    pub version: u32,
    pub hosts: Vec<Host>,
    /// Called `keys` before version 3.
    #[serde(default, alias = "keys")]
    pub credentials: Vec<Credential>,
    #[serde(default)]
    pub notes: Vec<Note>,
    #[serde(default)]
    pub tunnels: Vec<Tunnel>,
    #[serde(default)]
    pub settings: Settings,
}

fn default_version() -> u32 {
    INVENTORY_VERSION
}

impl Default for Inventory {
    fn default() -> Self {
        Self { version: INVENTORY_VERSION, hosts: Vec::new(), credentials: Vec::new(), notes: Vec::new(), tunnels: Vec::new(), settings: Settings::default() }
    }
}

fn host(name: &str, address: &str, user: &str, folder: &str, kind: HostKind, favorite: bool) -> Host {
    Host {
        id: Host::new_id(),
        name: name.into(),
        address: address.into(),
        port: 22,
        user: user.into(),
        protocols: vec![Protocol::Ssh],
        folder: folder.into(),
        favorite,
        kind,
        tags: Vec::new(),
        last_connected: None,
        credential_id: None,
        password: None,
        rdp_port: default_rdp_port(),
        rdp_fingerprint: None,
    }
}

impl Inventory {
    pub fn credential(&self, id: Option<&String>) -> Option<&Credential> {
        id.and_then(|id| self.credentials.iter().find(|c| &c.id == id))
    }
}

impl Inventory {
    /// Example hosts offered when a new vault is created. Addresses are from
    /// the RFC 5737 documentation ranges, so connecting to them goes nowhere.
    pub fn sample() -> Self {
        use HostKind::*;
        let mut staging = host("staging-app", "198.51.100.40", "deploy", "Staging", Server, true);
        staging.protocols.push(Protocol::Sftp);
        let mut backup = host("backup", "192.0.2.40", "backup", "Infra", Server, false);
        backup.protocols = vec![Protocol::Sftp];
        let mut windows = host("win-desktop", "192.0.2.50", "Administrator", "Infra", Windows, false);
        windows.protocols = vec![Protocol::Rdp];
        let inv = Self {
            version: INVENTORY_VERSION,
            hosts: vec![
                host("lb-01", "198.51.100.10", "ops", "Production/Web", LoadBalancer, true),
                host("web-01", "198.51.100.11", "ops", "Production/Web", Server, true),
                host("web-02", "198.51.100.12", "ops", "Production/Web", Server, false),
                host("pg-primary", "198.51.100.20", "dba", "Production/Databases", Database, true),
                host("pg-replica", "198.51.100.21", "dba", "Production/Databases", Database, false),
                host("redis-cache", "198.51.100.22", "ops", "Production/Databases", Database, false),
                staging,
                host("staging-db", "198.51.100.41", "dba", "Staging", Database, false),
                host("bastion", "203.0.113.10", "ops", "Infra", Bastion, false),
                backup,
                windows,
            ],
            ..Self::default()
        };
        let mut inv = inv;
        let db = inv.hosts.iter().find(|h| h.name == "pg-primary").map(|h| h.id.clone()).unwrap_or_default();
        inv.tunnels.push(Tunnel {
            id: Host::new_id(),
            name: "Postgres via pg-primary".into(),
            host_id: db.clone(),
            kind: ForwardKind::Local,
            bind_addr: "127.0.0.1".into(),
            bind_port: 15432,
            dest_host: "127.0.0.1".into(),
            dest_port: 5432,
            auto_start: false,
        });
        inv.notes.push(Note {
            id: Host::new_id(),
            title: "Restart the app on web hosts".into(),
            body: "sudo systemctl restart app.service\nsudo journalctl -u app.service -n 50 --no-pager\n".into(),
            host_id: None,
            updated: 0,
        });
        inv
    }
}
