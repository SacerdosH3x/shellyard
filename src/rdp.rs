//! RDP through an installed client: FreeRDP in a terminal tab (it can sign in
//! with a saved password and asks about certificates there), or the system's
//! RDP app (Windows App on macOS, Remmina on Linux).

use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};

use crate::model::{RdpClient, Secret};

pub struct Target {
    pub address: String,
    pub port: u16,
    pub user: String,
    pub password: Option<Secret>,
    pub title: String,
}

/// How a connection was started.
pub enum Launch {
    /// Run this in a terminal tab.
    Terminal(portable_pty::CommandBuilder),
    /// Handed to another app; nothing more to do.
    External(String),
}

/// A FreeRDP executable and whether it is version 3 (needed to pass the
/// password without putting it on the command line).
struct FreeRdp {
    path: String,
    v3: bool,
}

fn find_freerdp() -> Option<FreeRdp> {
    // sdl-freerdp is native on macOS; xfreerdp there needs XQuartz.
    let names: &[&str] = if cfg!(target_os = "macos") {
        &["sdl-freerdp3", "sdl-freerdp", "xfreerdp3", "xfreerdp"]
    } else {
        &["xfreerdp3", "xfreerdp", "sdl-freerdp3", "sdl-freerdp", "wlfreerdp3", "wlfreerdp"]
    };
    names.iter().find_map(|n| {
        let path = crate::terminal::which(n)?;
        let v3 = n.ends_with('3') || {
            let out = std::process::Command::new(&path).arg("--version").output().ok()?;
            String::from_utf8_lossy(&out.stdout).contains("version 3")
        };
        Some(FreeRdp { path, v3 })
    })
}

#[cfg(target_os = "macos")]
fn system_app() -> Option<&'static str> {
    ["Windows App", "Microsoft Remote Desktop"].into_iter().find(|app| {
        std::process::Command::new("open").args(["-Ra", app]).status().is_ok_and(|s| s.success())
    })
}

/// The `/v:` value; IPv6 addresses need brackets before the port.
fn server_arg(t: &Target) -> String {
    let bare = t.address.trim_start_matches('[').trim_end_matches(']');
    if bare.contains(':') {
        format!("/v:[{bare}]:{}", t.port)
    } else {
        format!("/v:{bare}:{}", t.port)
    }
}

pub fn launch(t: &Target, client: RdpClient, run_dir: &std::path::Path) -> Result<Launch> {
    if !crate::model::safe_arg(&t.address) || t.user.chars().any(|c| c.is_control()) {
        bail!("host address or user contains characters that are not allowed");
    }
    let freerdp = find_freerdp();
    let use_freerdp = match client {
        RdpClient::FreeRdp => true,
        RdpClient::System => false,
        RdpClient::Auto | RdpClient::Builtin => freerdp.is_some() && (t.password.is_some() || !system_available()),
    };
    if use_freerdp {
        let f = freerdp.ok_or_else(|| anyhow!("FreeRDP is not installed ({})", install_hint()))?;
        return Ok(Launch::Terminal(freerdp_command(&f, t)?));
    }
    system_launch(t, run_dir)
}

fn freerdp_command(f: &FreeRdp, t: &Target) -> Result<portable_pty::CommandBuilder> {
    // Clipboard sharing is on by default in FreeRDP.
    let mut args = vec![server_arg(t), "+dynamic-resolution".to_string(), format!("/t:{}", t.title)];
    if !t.user.is_empty() {
        args.push(format!("/u:{}", t.user));
    }
    let mut cmd = portable_pty::CommandBuilder::new(&f.path);
    match (&t.password, f.v3) {
        (Some(pw), true) => {
            if pw.expose().contains(['\n', '\r', '\0']) {
                bail!("the saved password contains a line break, which FreeRDP cannot read");
            }
            // FreeRDP 3 reads its arguments from this variable (one per line),
            // which only this user can read, instead of the visible command line.
            args.push(format!("/p:{}", pw.expose()));
            let joined = zeroize::Zeroizing::new(args.join("\n"));
            args.iter_mut().for_each(zeroize::Zeroize::zeroize);
            cmd.env("SHELLYARD_RDP_ARGS", joined.as_str());
            cmd.arg("/args-from:env:SHELLYARD_RDP_ARGS");
        }
        _ => {
            // No saved password (or FreeRDP 2): FreeRDP asks in the tab.
            cmd.args(&args);
            cmd.arg("/from-stdin");
        }
    }
    Ok(cmd)
}

#[cfg(target_os = "macos")]
fn system_available() -> bool {
    system_app().is_some()
}

#[cfg(not(target_os = "macos"))]
fn system_available() -> bool {
    crate::terminal::which("remmina").is_some()
}

fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "install Windows App from the App Store, or FreeRDP with `brew install freerdp`"
    } else {
        "install FreeRDP (`xfreerdp`, package freerdp3-x11 or freerdp2-x11) or Remmina"
    }
}

/// Writes an .rdp file (no password: the format can only hold one encrypted
/// for Windows) and opens it in Windows App.
#[cfg(target_os = "macos")]
fn system_launch(t: &Target, run_dir: &std::path::Path) -> Result<Launch> {
    let app = system_app().ok_or_else(|| anyhow!("no RDP app found; {}", install_hint()))?;
    let bare = t.address.trim_start_matches('[').trim_end_matches(']');
    let host = if bare.contains(':') { format!("[{bare}]") } else { bare.to_string() };
    let mut body = format!("full address:s:{host}:{}\r\nscreen mode id:i:2\r\ndynamic resolution:i:1\r\n", t.port);
    if !t.user.is_empty() {
        body.push_str(&format!("username:s:{}\r\n", t.user));
    }
    let path = rdp_file(run_dir, &body)?;
    let status = std::process::Command::new("open").arg("-a").arg(app).arg(&path).status()?;
    if !status.success() {
        bail!("{app} could not open the connection");
    }
    let note = if t.password.is_some() { " It asks for the password itself (right-click the host → Copy password)." } else { "" };
    Ok(Launch::External(format!("Opened {} in {app}.{note}", t.title)))
}

#[cfg(not(target_os = "macos"))]
fn system_launch(t: &Target, _run_dir: &std::path::Path) -> Result<Launch> {
    let remmina = crate::terminal::which("remmina").ok_or_else(|| anyhow!("no RDP client found; {}", install_hint()))?;
    let bare = t.address.trim_start_matches('[').trim_end_matches(']');
    let host = if bare.contains(':') { format!("[{bare}]") } else { bare.to_string() };
    let user = if t.user.is_empty() { String::new() } else { format!("{}@", t.user.replace('@', "%40")) };
    std::process::Command::new(remmina)
        .arg("-c")
        .arg(format!("rdp://{user}{host}:{}", t.port))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(Launch::External(format!("Opened {} in Remmina.", t.title)))
}

/// `rdp-*` files are removed at the next start, like key files.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn rdp_file(run_dir: &std::path::Path, body: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(run_dir)?;
    let path = run_dir.join(format!("rdp-{}.rdp", crate::model::Host::new_id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&path)?.write_all(body.as_bytes())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(password: Option<&str>) -> Target {
        Target { address: "win.example".into(), port: 3390, user: "CORP\\ops".into(), password: password.map(Secret::new), title: "win".into() }
    }

    #[test]
    fn password_never_reaches_the_command_line() {
        let f = FreeRdp { path: "xfreerdp".into(), v3: true };
        let cmd = freerdp_command(&f, &target(Some("s3cret-pass"))).unwrap();
        let argv: Vec<String> = cmd.get_argv().iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert!(argv.iter().all(|a| !a.contains("s3cret-pass")), "{argv:?}");
        assert!(argv.contains(&"/args-from:env:SHELLYARD_RDP_ARGS".to_string()));
        let env = cmd.get_env("SHELLYARD_RDP_ARGS").unwrap().to_string_lossy().into_owned();
        let lines: Vec<&str> = env.lines().collect();
        assert!(lines.contains(&"/v:win.example:3390") && lines.contains(&"/u:CORP\\ops") && lines.contains(&"/p:s3cret-pass"), "{lines:?}");
    }

    #[test]
    fn without_password_freerdp_asks_in_the_tab() {
        for v3 in [true, false] {
            let cmd = freerdp_command(&FreeRdp { path: "xfreerdp".into(), v3 }, &target(None)).unwrap();
            let argv: Vec<String> = cmd.get_argv().iter().map(|a| a.to_string_lossy().into_owned()).collect();
            assert!(argv.contains(&"/from-stdin".to_string()) && cmd.get_env("SHELLYARD_RDP_ARGS").is_none());
        }
    }

    #[test]
    fn ipv6_and_injection() {
        let mut t = target(None);
        t.address = "[fe80::1]".into();
        assert_eq!(server_arg(&t), "/v:[fe80::1]:3390");
        t.address = "-o/evil".into();
        assert!(launch(&t, RdpClient::FreeRdp, std::path::Path::new("/nonexistent")).is_err());
    }

    /// The installed FreeRDP 3 accepts exactly the arguments we build. With
    /// `/version` it parses them all and exits without connecting.
    /// (Skipped where FreeRDP 3 is not installed, e.g. CI.)
    #[test]
    fn installed_freerdp_accepts_our_arguments() {
        let Some(f) = find_freerdp().filter(|f| f.v3) else { return };
        let cmd = freerdp_command(&f, &target(Some("pw"))).unwrap();
        let args = cmd.get_env("SHELLYARD_RDP_ARGS").unwrap().to_string_lossy().into_owned();
        let parses = |args: &str| {
            std::process::Command::new(&f.path)
                .env("SHELLYARD_RDP_ARGS", format!("{args}\n/version"))
                .arg("/args-from:env:SHELLYARD_RDP_ARGS")
                .output()
                .unwrap()
                .status
                .success()
        };
        assert!(!parses("/not-a-real-option"), "this check would not catch a bad option");
        assert!(parses(&args), "FreeRDP rejected: {args:?}");
    }
}
