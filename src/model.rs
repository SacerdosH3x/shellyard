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
    /// SSH key to sign in with. `None` means the SSH agent and default keys.
    #[serde(default)]
    pub key_id: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub id: String,
    pub name: String,
    pub source: KeySource,
    /// OpenSSH public key line, if known.
    #[serde(default)]
    pub public: Option<String>,
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

pub const INVENTORY_VERSION: u32 = 2;

/// Preferences stored inside the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Lock the vault after this many minutes without keyboard or mouse input. 0 = never.
    pub auto_lock_minutes: u32,
    /// Let programs in a terminal write to the clipboard with OSC 52. Off by
    /// default: a compromised server could otherwise plant a command there.
    pub allow_osc52: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { auto_lock_minutes: 15, allow_osc52: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    #[serde(default = "default_version")]
    pub version: u32,
    pub hosts: Vec<Host>,
    #[serde(default)]
    pub keys: Vec<SshKey>,
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
        Self { version: INVENTORY_VERSION, hosts: Vec::new(), keys: Vec::new(), notes: Vec::new(), tunnels: Vec::new(), settings: Settings::default() }
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
        key_id: None,
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
