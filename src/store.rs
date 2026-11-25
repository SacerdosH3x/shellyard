//! Reads and writes the sealed inventory file on this machine.

use std::path::PathBuf;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::{model::Inventory, vault};

pub fn vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("SHELLYARD_VAULT") {
        return PathBuf::from(p);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Shellyard")
        .join("shellyard.vault")
}

/// Moves the data folder from before the rename (Hostdeck → Shellyard) to the
/// new location, once, if only the old one exists.
pub fn migrate_legacy() {
    if std::env::var_os("SHELLYARD_VAULT").is_some() {
        return;
    }
    let Some(data) = dirs::data_dir() else { return };
    let (old_dir, new_dir) = (data.join("Hostdeck"), data.join("Shellyard"));
    let old_vault = old_dir.join("hostdeck.vault");
    if new_dir.exists() || !old_vault.is_file() {
        return;
    }
    if std::fs::rename(&old_dir, &new_dir).is_ok() {
        let _ = std::fs::rename(new_dir.join("hostdeck.vault"), new_dir.join("shellyard.vault"));
    }
}

pub fn exists() -> bool {
    vault_path().is_file()
}

pub fn load(password: &str) -> Result<Inventory> {
    load_from(&vault_path(), password)
}

fn load_from(path: &std::path::Path, password: &str) -> Result<Inventory> {
    let blob = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let plain = vault::open(password, &blob)?;
    let inv: Inventory = serde_json::from_slice(&plain).context("vault contents are not valid")?;
    check_version(&inv)?;
    Ok(inv)
}

/// Refuses vaults written by a newer Shellyard: saving them here would silently
/// drop the fields this version does not know about.
fn check_version(inv: &Inventory) -> Result<()> {
    if inv.version > crate::model::INVENTORY_VERSION {
        anyhow::bail!("this vault was saved by a newer version of Shellyard; update Shellyard to open it");
    }
    Ok(())
}

/// Seals and writes atomically (temp file, then rename).
pub fn save(password: &str, inventory: &Inventory) -> Result<()> {
    save_to(&vault_path(), password, inventory)
}

fn save_to(path: &std::path::Path, password: &str, inventory: &Inventory) -> Result<()> {
    let json = Zeroizing::new(serde_json::to_vec(inventory)?);
    let blob = vault::seal(password, &json)?;

    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        // Make the folder private only if Shellyard creates it: SHELLYARD_VAULT
        // may point into a folder the user owns for other reasons (Documents, a
        // synced folder), and its permissions are theirs to choose.
        if !dir.exists() {
            std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
    }
    let tmp = path.with_extension("vault.tmp");
    // A leftover from a crash; never write through whatever is there.
    let _ = std::fs::remove_file(&tmp);
    let f = write_private(&tmp, &blob)?;
    // Make sure the bytes are on disk before the rename makes them the vault,
    // so a power loss cannot leave a truncated vault behind.
    f.sync_all().with_context(|| format!("cannot write {}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Private directory for short-lived key files, askpass sockets and .rdp files.
pub fn run_dir() -> PathBuf {
    vault_path().parent().map(|p| p.join("run")).unwrap_or_else(|| PathBuf::from("run"))
}

/// Writes a key from the vault to a private file (0600, in a 0700 directory)
/// so OpenSSH can read it. The caller must remove it with [`remove_temp_files`].
pub fn write_temp_key(contents: &str, public: Option<&str>) -> Result<Vec<PathBuf>> {
    write_temp_key_in(&run_dir(), contents, public)
}

fn write_temp_key_in(dir: &std::path::Path, contents: &str, public: Option<&str>) -> Result<Vec<PathBuf>> {
    let dir = dir.to_path_buf();
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    // Never follow a symlink here: someone who can write to the vault folder
    // could otherwise point `run` at a folder they can read.
    let meta = std::fs::symlink_metadata(&dir)?;
    if !meta.file_type().is_dir() {
        anyhow::bail!("{} is not a plain directory; refusing to write a key there", dir.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Fails unless this user owns the directory.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot make {} private", dir.display()))?;
    }
    let name = crate::model::Host::new_id();
    let path = dir.join(format!("key-{name}"));
    let mut body = Zeroizing::new(contents.trim_end().to_string());
    body.push('\n');
    write_private(&path, body.as_bytes())?;
    let mut files = vec![path.clone()];
    if let Some(public) = public {
        let pub_path = dir.join(format!("key-{name}.pub"));
        write_private(&pub_path, format!("{}\n", public.trim()).as_bytes())?;
        files.push(pub_path);
    }
    Ok(files)
}

/// Creates a new file readable only by this user (it must not exist yet) and writes `bytes`.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<std::fs::File> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("cannot write {}", path.display()))?;
    f.write_all(bytes).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(f)
}

/// Overwrites then deletes temporary key files. Symlinks are removed without
/// writing through them.
pub fn remove_temp_files(files: &[PathBuf]) {
    for f in files {
        if let Ok(meta) = std::fs::symlink_metadata(f) {
            if meta.is_file() {
                if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(f) {
                    use std::io::Write;
                    let _ = file.write_all(&vec![0u8; meta.len() as usize]);
                    let _ = file.sync_all();
                }
            }
        }
        let _ = std::fs::remove_file(f);
    }
}

/// Removes files left behind by a crash. Only what Shellyard itself creates
/// (`key-*`, `rdp-*` files and `ask-*` socket folders) is touched, in case the
/// directory is shared.
pub fn clean_run_dir() {
    let dir = run_dir();
    remove_temp_files(&own_temp_files(&dir));
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
        if is_dir && e.file_name().to_string_lossy().starts_with("ask-") {
            let _ = std::fs::remove_file(e.path().join("s"));
            let _ = std::fs::remove_dir(e.path());
        }
    }
}

fn own_temp_files(dir: &std::path::Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
                    !is_dir && (name.starts_with("key-") || name.starts_with("rdp-"))
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_key_is_private_and_removed() {
        let dir = std::env::temp_dir().join(format!("shellyard-test-{}", crate::model::Host::new_id()));
        let files = write_temp_key_in(&dir.join("run"), "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", Some("ssh-ed25519 AAAA test")).unwrap();
        assert_eq!(files.len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(files[0].parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        assert!(std::fs::read_to_string(&files[0]).unwrap().ends_with('\n'));
        remove_temp_files(&files);
        assert!(files.iter().all(|f| !f.exists()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn saved_vault_is_private_encrypted_and_reloads() {
        let dir = std::env::temp_dir().join(format!("shellyard-test-{}", crate::model::Host::new_id()));
        let path = dir.join("sub").join("t.vault");
        let mut inv = Inventory::sample();
        inv.credentials.push(crate::model::Credential {
            password: Some(crate::model::Secret::new("PASSWORDDATA")),
            passphrase: Some(crate::model::Secret::new("PHRASEDATA")),
            ..crate::model::Credential::key("k", crate::model::KeySource::Embedded("-----BEGIN OPENSSH PRIVATE KEY-----SECRETKEYDATA".into()), None)
        });
        inv.hosts[0].password = Some(crate::model::Secret::new("HOSTPWDATA"));
        save_to(&path, "a long test password", &inv).unwrap();
        save_to(&path, "a long test password", &inv).unwrap(); // replaces cleanly
        let raw = std::fs::read(&path).unwrap();
        for needle in ["pg-primary", "198.51.100", "SECRETKEYDATA", "systemctl", "PASSWORDDATA", "PHRASEDATA", "HOSTPWDATA"] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle.as_bytes()), "{needle} found in plaintext");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        assert!(!path.with_extension("vault.tmp").exists());
        let back = load_from(&path, "a long test password").unwrap();
        assert_eq!(back.hosts.len(), inv.hosts.len());
        assert!(load_from(&path, "wrong password!!").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// SHELLYARD_VAULT may point into a folder the user owns (Documents, a
    /// synced folder): saving must not change that folder's permissions.
    #[cfg(unix)]
    #[test]
    fn existing_vault_folder_keeps_its_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("shellyard-test-{}", crate::model::Host::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        save_to(&dir.join("t.vault"), "a long test password", &Inventory::default()).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(std::fs::metadata(dir.join("t.vault")).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A `run` symlink planted in a shared vault folder must not receive keys.
    #[cfg(unix)]
    #[test]
    fn temp_key_refuses_symlinked_run_dir() {
        let dir = std::env::temp_dir().join(format!("shellyard-test-{}", crate::model::Host::new_id()));
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join("run")).unwrap();
        assert!(write_temp_key_in(&dir.join("run"), "-----BEGIN OPENSSH PRIVATE KEY-----", None).is_err());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0, "a key was written through the symlink");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn newer_vault_version_is_refused() {
        let mut inv = Inventory::default();
        assert!(check_version(&inv).is_ok());
        inv.version = crate::model::INVENTORY_VERSION + 1;
        assert!(check_version(&inv).is_err());
    }

    #[test]
    fn clean_run_dir_only_touches_own_files() {
        let dir = std::env::temp_dir().join(format!("shellyard-test-{}", crate::model::Host::new_id()));
        std::fs::create_dir_all(dir.join("run")).unwrap();
        std::fs::write(dir.join("run").join("notes.txt"), "keep me").unwrap();
        std::fs::write(dir.join("run").join("key-dead"), "secret").unwrap();
        remove_temp_files(&own_temp_files(&dir.join("run")));
        assert!(!dir.join("run").join("key-dead").exists());
        assert_eq!(std::fs::read_to_string(dir.join("run").join("notes.txt")).unwrap(), "keep me");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Decrypted-but-malformed contents must give an error, never a panic.
    #[test]
    fn fuzz_inventory_json_never_panics() {
        use rand::{Rng, SeedableRng};
        let good = serde_json::to_vec(&Inventory::sample()).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        for _ in 0..2000 {
            let mut b = good.clone();
            for _ in 0..rng.gen_range(1..6) {
                let at = rng.gen_range(0..b.len());
                match rng.gen_range(0..3) {
                    0 => b[at] = rng.gen(),
                    1 => {
                        b.remove(at);
                    }
                    _ => {
                        let junk = b"{}[]\",:0-e\x00";
                        b.insert(at, junk[rng.gen_range(0..junk.len())]);
                    }
                }
            }
            if let Ok(inv) = serde_json::from_slice::<Inventory>(&b) {
                let _ = check_version(&inv);
            }
        }
    }

    #[test]
    fn version_1_inventory_still_loads() {
        let v1 = r#"{"version":1,"hosts":[{"id":"1","name":"a","address":"h","port":22,"user":"u","protocols":["Ssh"],"folder":"","favorite":false}]}"#;
        let inv: Inventory = serde_json::from_str(v1).unwrap();
        assert_eq!(inv.hosts.len(), 1);
        assert!(inv.credentials.is_empty() && inv.notes.is_empty() && inv.tunnels.is_empty());
        assert!(inv.hosts[0].credential_id.is_none());
        assert_eq!(inv.hosts[0].rdp_port, 3389);
    }

    /// Version 2 stored SSH keys as `keys` and hosts pointed at them with
    /// `key_id`; they must come back as credentials.
    #[test]
    fn version_2_keys_become_credentials() {
        let v2 = r#"{"version":2,"hosts":[{"id":"1","name":"a","address":"h","port":22,"user":"u","protocols":["Ssh"],"folder":"","favorite":false,"key_id":"k1"}],
            "keys":[{"id":"k1","name":"laptop","source":{"File":"~/.ssh/id_ed25519"},"public":"ssh-ed25519 AAAA"}]}"#;
        let inv: Inventory = serde_json::from_str(v2).unwrap();
        assert_eq!(inv.hosts[0].credential_id.as_deref(), Some("k1"));
        let c = &inv.credentials[0];
        assert_eq!(c.name, "laptop");
        assert!(matches!(&c.source, Some(crate::model::KeySource::File(p)) if p == "~/.ssh/id_ed25519"));
        assert!(c.password.is_none() && c.passphrase.is_none() && c.username.is_empty());
        // Saved again, it uses the new names.
        let json = serde_json::to_string(&inv).unwrap();
        assert!(json.contains("\"credentials\"") && json.contains("\"credential_id\"") && !json.contains("\"keys\""));
    }

    /// 0.1.0-beta.2 saved `"rdp_client":"Auto"` (an external window); RDP now
    /// opens in a tab unless an external client is picked again.
    #[test]
    fn old_rdp_setting_opens_rdp_in_a_tab() {
        let st: crate::model::Settings = serde_json::from_str(r#"{"rdp_client":"Auto"}"#).unwrap();
        assert_eq!(st.rdp_client, crate::model::RdpClient::Builtin);
        let ext = serde_json::to_string(&crate::model::Settings { rdp_client: crate::model::RdpClient::Auto, ..Default::default() }).unwrap();
        let back: crate::model::Settings = serde_json::from_str(&ext).unwrap();
        assert_eq!(back.rdp_client, crate::model::RdpClient::Auto, "{ext}");
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let mut inv = Inventory::sample();
        inv.hosts[0].password = Some(crate::model::Secret::new("HOSTPWDATA"));
        assert!(!format!("{inv:?}").contains("HOSTPWDATA"));
    }
}
