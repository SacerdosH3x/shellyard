//! The binary started as an askpass program answers and exits without opening
//! a window. (This file also makes `cargo test` build the binary, which the
//! end-to-end askpass unit test runs.)

#[cfg(unix)]
#[test]
fn binary_in_askpass_mode_does_not_open_a_window() {
    // No server at this socket and no terminal: it must fail fast, not hang or start the GUI.
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_shellyard"));
    cmd.arg("Password: ")
        .env("SHELLYARD_ASKPASS_SOCK", "/nonexistent/shellyard-test.sock")
        .env("SHELLYARD_ASKPASS_TOKEN", "x")
        .stdin(std::process::Stdio::null());
    use std::os::unix::process::CommandExt;
    // SAFETY: setsid is async-signal-safe; it detaches from any terminal.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
    };
    let start = std::time::Instant::now();
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}
