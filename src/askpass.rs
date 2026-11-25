//! Saved passwords and key passphrases for the system OpenSSH.
//!
//! OpenSSH never takes a password on its command line. Instead, when a session
//! has a saved password or passphrase, Shellyard sets `SSH_ASKPASS` to its own
//! executable with `SSH_ASKPASS_REQUIRE=force`. When `ssh` (also `sftp` and
//! `ssh-copy-id`, which run `ssh`) needs a secret it runs
//! `shellyard "<prompt>"`, which asks this process for it over a Unix socket:
//!
//! - The socket lives in a private (0700) directory and is removed when the
//!   session ends. Each request must carry a random per-session token.
//! - A password is given only for prompts that name the host being connected
//!   to (`user@host's password:`, `(user@host) Password:`), so a jump host never
//!   receives the target's password. A passphrase is given only for the key
//!   file this session passes with `-i`.
//! - Each secret is given once. If it is wrong, OpenSSH asks again and the
//!   prompt goes to the terminal, as do all other prompts (host-key
//!   confirmation, one-time codes), so nothing ever loops or locks an account.

use std::path::PathBuf;

#[cfg(unix)]
pub use unix::*;

const ENV_SOCK: &str = "SHELLYARD_ASKPASS_SOCK";
const ENV_TOKEN: &str = "SHELLYARD_ASKPASS_TOKEN";

/// What one session may answer.
#[derive(Default)]
pub struct Secrets {
    pub password: Option<crate::model::Secret>,
    /// Host names a password prompt must name (the address and the name
    /// OpenSSH resolves it to, compared case-insensitively).
    pub hosts: Vec<String>,
    pub passphrase: Option<crate::model::Secret>,
    /// The `-i` key file the passphrase belongs to.
    pub key_path: Option<PathBuf>,
}

impl Secrets {
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.passphrase.is_none()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Ask {
    Password,
    Passphrase,
    /// Anything else: the user answers in the terminal.
    Other,
}

fn classify(prompt: &str, s: &Secrets) -> Ask {
    let p = prompt.to_lowercase();
    if p.contains("yes/no") || p.contains("new password") || p.contains("retype") {
        return Ask::Other;
    }
    if p.contains("passphrase") {
        // ssh prints at most 100 bytes of the path ("for key '%.100s'").
        let for_our_key = s.key_path.as_ref().is_some_and(|k| {
            let k = k.to_string_lossy();
            let mut end = k.len().min(100);
            while !k.is_char_boundary(end) {
                end -= 1;
            }
            end > 0 && prompt.contains(&k[..end])
        });
        return if for_our_key { Ask::Passphrase } else { Ask::Other };
    }
    if p.contains("password") {
        let names_host = s.hosts.iter().any(|h| {
            let h = h.to_lowercase();
            !h.is_empty() && (p.contains(&format!("@{h}'s password")) || p.contains(&format!("@{h})")))
        });
        return if names_host { Ask::Password } else { Ask::Other };
    }
    Ask::Other
}

/// Answers one prompt, giving each secret at most once.
struct Answerer {
    secrets: Secrets,
    gave_password: bool,
    gave_passphrase: bool,
}

impl Answerer {
    fn answer(&mut self, prompt: &str) -> Option<&str> {
        match classify(prompt, &self.secrets) {
            Ask::Password if !self.gave_password => {
                self.gave_password = true;
                self.secrets.password.as_ref().map(|s| s.expose())
            }
            Ask::Passphrase if !self.gave_passphrase => {
                self.gave_passphrase = true;
                self.secrets.passphrase.as_ref().map(|s| s.expose())
            }
            _ => None,
        }
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::{BufRead, Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use zeroize::Zeroizing;

    /// Answers askpass requests for one session until dropped.
    pub struct Server {
        dir: PathBuf,
        sock: PathBuf,
        token: Zeroizing<String>,
        stop: Arc<AtomicBool>,
    }

    impl Server {
        /// Listens in a new private directory under `parent`.
        pub fn start(parent: &std::path::Path, secrets: Secrets) -> Result<Server> {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            std::fs::create_dir_all(parent)?;
            let id = crate::model::Host::new_id();
            // Unix socket paths are limited to about 100 bytes; fall back to the
            // (per-user, private on macOS) temp dir for a deep vault folder.
            let mut dir = parent.join(format!("ask-{id}"));
            if dir.join("s").as_os_str().len() > 100 {
                dir = std::env::temp_dir().join(format!("shellyard-ask-{id}"));
            }
            std::fs::DirBuilder::new().mode(0o700).create(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            let sock = dir.join("s");
            let listener = UnixListener::bind(&sock).with_context(|| format!("cannot listen on {}", sock.display()))?;
            listener.set_nonblocking(true)?;

            let token = Zeroizing::new(crate::model::Host::new_id() + &crate::model::Host::new_id());
            let stop = Arc::new(AtomicBool::new(false));
            let (want, halt) = (token.clone(), stop.clone());
            std::thread::Builder::new().name("askpass".into()).spawn(move || {
                let mut answerer = Answerer { secrets, gave_password: false, gave_passphrase: false };
                let mut served = 0;
                while !halt.load(Ordering::Relaxed) && served < 32 {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            served += 1;
                            let _ = serve(stream, &want, &mut answerer);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
                        Err(_) => break,
                    }
                }
                // `answerer` (and the secrets in it) is dropped and wiped here.
            })?;
            Ok(Server { dir, sock, token, stop })
        }

        /// Environment for the OpenSSH process.
        pub fn env(&self) -> Result<Vec<(&'static str, std::ffi::OsString)>> {
            let exe = std::env::current_exe().context("cannot find the Shellyard executable for SSH_ASKPASS")?;
            Ok(vec![
                ("SSH_ASKPASS", exe.into_os_string()),
                ("SSH_ASKPASS_REQUIRE", "force".into()),
                (ENV_SOCK, self.sock.clone().into_os_string()),
                (ENV_TOKEN, self.token.as_str().into()),
            ])
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            let _ = std::fs::remove_file(&self.sock);
            let _ = std::fs::remove_dir(&self.dir);
        }
    }

    /// Request: `token\nprompt`. Reply: `OK\nsecret` or `NO\n`.
    fn serve(mut stream: UnixStream, token: &str, answerer: &mut Answerer) -> std::io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut req = Zeroizing::new(Vec::new());
        (&mut stream).take(64 * 1024).read_to_end(&mut req)?;
        let text = String::from_utf8_lossy(&req);
        let (got, prompt) = text.split_once('\n').unwrap_or((&text, ""));
        let reply = if constant_time_eq(got.as_bytes(), token.as_bytes()) { answerer.answer(prompt) } else { None };
        match reply {
            Some(secret) => {
                let mut out = Zeroizing::new(b"OK\n".to_vec());
                out.extend_from_slice(secret.as_bytes());
                stream.write_all(&out)
            }
            None => stream.write_all(b"NO\n"),
        }
    }

    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }

    /// Called first thing in `main`: if this process was started by OpenSSH as
    /// its askpass program, answer the prompt and return the exit code.
    pub fn run_if_requested() -> Option<i32> {
        let sock = std::env::var_os(ENV_SOCK)?;
        let token = Zeroizing::new(std::env::var(ENV_TOKEN).unwrap_or_default());
        let prompt = std::env::args().nth(1).unwrap_or_default();
        if let Ok(Some(secret)) = ask(std::path::Path::new(&sock), &token, &prompt) {
            let mut out = std::io::stdout().lock();
            let ok = out.write_all(secret.as_bytes()).and_then(|_| out.write_all(b"\n")).and_then(|_| out.flush());
            return Some(if ok.is_ok() { 0 } else { 1 });
        }
        Some(ask_terminal(&prompt))
    }

    fn ask(sock: &std::path::Path, token: &str, prompt: &str) -> std::io::Result<Option<Zeroizing<String>>> {
        let mut stream = UnixStream::connect(sock)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(format!("{token}\n{prompt}").as_bytes())?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut reply = Zeroizing::new(Vec::new());
        stream.read_to_end(&mut reply)?;
        Ok(reply.strip_prefix(b"OK\n").map(|s| Zeroizing::new(String::from_utf8_lossy(s).into_owned())))
    }

    /// Asks on the terminal OpenSSH runs in (a Shellyard tab), with echo off
    /// unless the prompt is a yes/no question.
    fn ask_terminal(prompt: &str) -> i32 {
        let Ok(mut tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") else { return 1 };
        let kind = std::env::var("SSH_ASKPASS_PROMPT").unwrap_or_default();
        let _ = tty.write_all(prompt.as_bytes());
        if kind == "none" {
            // A notice (e.g. "touch your security key"), no answer wanted.
            let _ = tty.write_all(b"\r\n");
            return 0;
        }
        let echo = kind == "confirm" || prompt.to_lowercase().contains("yes/no");
        let restore = if echo { None } else { echo_off(&tty) };
        let mut line = Zeroizing::new(String::new());
        let read = std::io::BufReader::new(&tty).read_line(&mut line);
        if let Some(t) = restore {
            use std::os::fd::AsRawFd;
            // SAFETY: restores the attributes read from the same open terminal.
            unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSANOW, &t) };
            let _ = tty.write_all(b"\r\n");
        }
        if read.is_err() {
            return 1;
        }
        let answer = line.trim_end_matches(['\r', '\n']);
        let mut out = std::io::stdout().lock();
        if out.write_all(answer.as_bytes()).and_then(|_| out.write_all(b"\n")).is_err() {
            return 1;
        }
        0
    }

    fn echo_off(tty: &std::fs::File) -> Option<libc::termios> {
        use std::os::fd::AsRawFd;
        let fd = tty.as_raw_fd();
        // SAFETY: termios is plain data; tcgetattr fills it for an open fd.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) != 0 {
                return None;
            }
            let saved = t;
            t.c_lflag &= !libc::ECHO;
            t.c_lflag |= libc::ECHONL;
            (libc::tcsetattr(fd, libc::TCSANOW, &t) == 0).then_some(saved)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::model::Secret;

        fn secrets() -> Secrets {
            Secrets {
                password: Some(Secret::new("hunter2-long")),
                hosts: vec!["db.example".into(), "10.0.0.5".into()],
                passphrase: Some(Secret::new("key-phrase")),
                key_path: Some("/run/key-abc".into()),
            }
        }

        #[test]
        fn prompts_are_matched_to_the_right_secret() {
            let s = secrets();
            for (prompt, want) in [
                ("ops@db.example's password: ", Ask::Password),
                ("ops@DB.EXAMPLE's password: ", Ask::Password),
                ("(ops@10.0.0.5) Password: ", Ask::Password),
                ("Enter passphrase for key '/run/key-abc': ", Ask::Passphrase),
                // A jump host or another key must not receive these secrets.
                ("ops@bastion's password: ", Ask::Other),
                ("(ops@bastion) Password: ", Ask::Other),
                ("Password: ", Ask::Other),
                ("Enter passphrase for key '/Users/me/.ssh/id_rsa': ", Ask::Other),
                ("Are you sure you want to continue connecting (yes/no/[fingerprint])? ", Ask::Other),
                ("(ops@db.example) New password: ", Ask::Other),
                ("(ops@db.example) Verification code: ", Ask::Other),
            ] {
                assert_eq!(classify(prompt, &s), want, "{prompt}");
            }
        }

        #[test]
        fn long_key_paths_match_the_truncated_prompt() {
            let long = format!("/{}/key-abc", "d".repeat(120));
            let s = Secrets { passphrase: Some(Secret::new("p")), key_path: Some(long.clone().into()), ..Default::default() };
            let prompt = format!("Enter passphrase for key '{}': ", &long[..100]);
            assert_eq!(classify(&prompt, &s), Ask::Passphrase);
        }

        /// The real chain: OpenSSH runs the Shellyard binary as SSH_ASKPASS,
        /// which gets the passphrase from this process's server.
        #[test]
        fn openssh_gets_the_passphrase_through_the_binary() {
            // The test executable is somewhere below target/<profile>/, where
            // Cargo puts the binary (always built, because tests/ uses it).
            let exe = std::env::current_exe().unwrap();
            let bin = exe
                .ancestors()
                .skip(1)
                .map(|d| d.join("shellyard"))
                .find(|p| p.is_file() && *p != exe)
                .expect("the shellyard binary was not built");
            let dir = std::env::temp_dir().join(format!("shellyard-test-{}", crate::model::Host::new_id()));
            std::fs::create_dir_all(&dir).unwrap();
            let key = dir.join("k");
            let ok = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "pp-secret-1", "-C", "t", "-f"])
                .arg(&key)
                .status()
                .unwrap();
            assert!(ok.success());
            let run = |passphrase: &str| {
                let secrets = Secrets { passphrase: Some(Secret::new(passphrase)), key_path: Some(key.clone()), ..Default::default() };
                let server = Server::start(&dir, secrets).unwrap();
                let mut cmd = std::process::Command::new("ssh-keygen");
                cmd.arg("-y").arg("-f").arg(&key).stdin(std::process::Stdio::null());
                for (k, v) in server.env().unwrap() {
                    cmd.env(k, v);
                }
                cmd.env("SSH_ASKPASS", &bin);
                // No controlling terminal, so a refused prompt cannot fall back to one.
                use std::os::unix::process::CommandExt;
                // SAFETY: setsid is async-signal-safe.
                unsafe { cmd.pre_exec(|| (libc::setsid() != -1).then_some(()).ok_or_else(std::io::Error::last_os_error)) };
                cmd.output().unwrap()
            };
            // What this ssh-keygen asks: newer versions name the key file
            // (`Enter passphrase for "<path>":`), older ones (8.9) do not.
            let probe = dir.join("probe.sh");
            std::fs::write(&probe, format!("#!/bin/sh\nprintf '%s' \"$1\" > '{}'\nexit 1\n", dir.join("prompt").display())).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let _ = std::process::Command::new("ssh-keygen")
                .arg("-y")
                .arg("-f")
                .arg(&key)
                .env("SSH_ASKPASS", &probe)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .stdin(std::process::Stdio::null())
                .output();
            let prompt = std::fs::read_to_string(dir.join("prompt")).unwrap_or_default();
            let out = run("pp-secret-1");
            if prompt.contains(&*key.to_string_lossy()) {
                assert!(String::from_utf8_lossy(&out.stdout).starts_with("ssh-ed25519 "), "{out:?}");
                assert!(!run("wrong").status.success(), "a wrong passphrase must not unlock the key");
            } else {
                // A prompt that does not name our key must not get the passphrase.
                assert!(!out.status.success() && out.stdout.is_empty(), "passphrase given to {prompt:?}: {out:?}");
            }
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn each_secret_is_given_once() {
            let mut a = Answerer { secrets: secrets(), gave_password: false, gave_passphrase: false };
            assert_eq!(a.answer("ops@db.example's password: "), Some("hunter2-long"));
            assert_eq!(a.answer("ops@db.example's password: "), None, "a wrong password must fall back to the terminal");
            assert_eq!(a.answer("Enter passphrase for key '/run/key-abc': "), Some("key-phrase"));
            assert_eq!(a.answer("Enter passphrase for key '/run/key-abc': "), None);
        }

        #[test]
        fn socket_needs_the_token_and_is_removed() {
            let parent = std::env::temp_dir().join(format!("shellyard-test-{}", crate::model::Host::new_id()));
            let server = Server::start(&parent, secrets()).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(&server.dir).unwrap().permissions().mode() & 0o777, 0o700);
            }
            let prompt = "ops@db.example's password: ";
            assert!(ask(&server.sock, "wrong-token", prompt).unwrap().is_none());
            assert_eq!(ask(&server.sock, &server.token, prompt).unwrap().as_deref().map(String::as_str), Some("hunter2-long"));
            assert!(ask(&server.sock, &server.token, prompt).unwrap().is_none());
            let (sock, dir) = (server.sock.clone(), server.dir.clone());
            drop(server);
            assert!(!sock.exists() && !dir.exists());
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}
