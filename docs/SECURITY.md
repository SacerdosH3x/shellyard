# Shellyard security

## What is protected, and from whom

Shellyard keeps hosts, SSH keys stored in the vault, tunnels, notes and settings
in one encrypted file (`shellyard.vault`). The goal is that someone who gets a
copy of that file (a stolen laptop, a backup, a synced folder) learns nothing
without the master password, and cannot change it without being detected.

Out of scope: malware running as your user while the vault is unlocked (it can
read process memory or log keystrokes), and a compromised OpenSSH install.

## Encryption

| Part | Choice |
|------|--------|
| Key derivation | Argon2id, 256 MiB memory, 3 passes, 1 lane, 16-byte random salt (`argon2` crate) |
| Cipher | AES-256-GCM, 12-byte random nonce (`aes-gcm` crate, RustCrypto) |
| Integrity | GCM tag over the contents; the whole header (magic, KDF cost, salt, nonce) is associated data |
| Randomness | `OsRng` (the operating system's CSPRNG) |

- Every save picks a new salt and nonce, so every save uses a new key; nonce reuse is not possible.
- The cost is stored in the header. Older vaults (64 MiB) still open and are re-sealed with the current cost on the next save.
- A header asking for more than 1 GiB, 64 passes or 16 lanes is refused, so a crafted file cannot exhaust memory.
- New master passwords need 12+ characters and a pessimistic strength estimate of 60+ bits; common passwords, repeats and sequences are rejected.

File handling: the vault is written to a new 0600 temp file (in a 0700 directory when Shellyard creates the folder; an existing folder, e.g. one picked with `SHELLYARD_VAULT`, keeps its permissions), `fsync`ed, then renamed over the old one, so a crash or power loss leaves either the old or the new vault, never a partial one.

## Secrets in memory

- The master password, password fields, decrypted JSON, derived keys, embedded private keys and note bodies are wiped (`zeroize`) when dropped. Locking drops all of them.
- Unlock runs on a background thread; the UI stays responsive.
- Auto-lock after 15 minutes without keyboard or mouse input (1–60 min or never, in Settings → Security).
- `Debug` output of keys and notes is redacted.

## SSH

- Shellyard runs the system OpenSSH, so host-key checking (`known_hosts`), agents and passphrase prompts work as usual. Shellyard never disables host-key checking.
- Hosts, users and tunnel addresses are validated, and `--` is put before the destination, so values cannot be turned into options such as `-oProxyCommand=`.
- A key stored in the vault is written to a 0600 file in a 0700 directory only while a session uses it, overwritten and deleted as soon as the program exits (or the tab closes, or Shellyard quits, including ⌘Q), and leftovers (`key-*` only) are removed at startup. A `run` folder that is a symlink is refused.
- IPv6 addresses are passed bare to `ssh` and in brackets to `sftp`, which would otherwise read the address as a path.
- The tunnel editor warns when a forward listens on a non-loopback address.

## Terminal

- OSC 52 (a program setting the clipboard) is off by default.
- Pasted text has escape characters (ESC and the 8-bit CSI) removed when bracketed paste is on, so it cannot end the bracket early.
- On Linux and Windows, Ctrl+C/Ctrl+V go to the program (^C, ^V); the clipboard is Ctrl+Shift+C/V.
- Output between the PTY and the parser is bounded (64 × 16 KiB), so a flood in a hidden tab cannot exhaust memory.

## Analysis done (2026-11-24, repeated 2026-11-25)

**Static**
- `cargo clippy --all-targets`: 0 warnings. A pedantic pass found style issues only.
- `cargo audit` (RustSec): 2 advisories, both in `quick-xml` 0.30 (RUSTSEC-2026-0194, -0195, denial of service on hostile XML). It comes in only on Linux, via `eframe → accesskit_unix → atspi-common → zbus-lockstep`, which runs in atspi's proc macros and tests at compile time on the XML files shipped with that crate; Shellyard never parses XML at run time. Both are ignored in [.cargo/audit.toml](../.cargo/audit.toml) with this reason, until egui/accesskit move to `quick-xml` ≥ 0.41. Also 8 "unmaintained" warnings (`paste`, `ttf-parser`, `zbus_names`, `zvariant`), no vulnerabilities. CI runs `cargo audit` on every push.
- The project contains no `unsafe` code.
- Manual review of vault, storage, SSH argument building, temp key files, terminal event handling and forms.

**Dynamic** (`cargo test`, 30 tests, also run 8× in a row for flakiness)
- Vault: round trip, wrong password, tampered header, fresh salt/nonce, old-cost compatibility, 400 random and bit-flipped blobs (must error, never panic).
- Store: the saved file is 0600 in a 0700 directory, an existing folder keeps its permissions, a symlinked `run` folder is refused, contains no host names, addresses, key or note text in plaintext, no temp file is left, and a newer-version vault is refused. 2000 mutated inventory JSON documents parse or error without panicking. Startup cleanup removes only `key-*` files.
- Terminal: real processes on a PTY; key files wiped when the program exits; clipboard shortcuts per platform; bracketed paste cannot be escaped; selection copies screen text; 3000 random/hostile escape-sequence streams fed to the parser plus extreme resizes; OSC 52 blocked unless allowed; output queue stays bounded under `yes`.
- SSH: generated arguments (including IPv6) are checked with real `ssh -G`; option injection is rejected.
- App launch with a throwaway vault: starts, no errors, stale `key-*` file removed and other files kept.

## Bugs fixed by this review

| Problem | Fix |
|---------|-----|
| Startup cleanup deleted every file in `<vault dir>/run` (data loss if `SHELLYARD_VAULT` pointed into a shared folder) | Only `key-*` files; symlinks are deleted without writing through them |
| Vault temp file was briefly world-readable (0644 before chmod) and not fsynced | Created as 0600, `fsync` before rename, directory synced |
| A failed background save cleared the "unsaved" flag, so changes were silently lost | Kept pending and retried every ~5 s; locking reports a failed save |
| Opening a vault from a newer version and saving it would drop unknown data | Refused with a clear message |
| Hidden tabs were never read, so a noisy program could grow memory without limit | All sessions are polled each frame; the queue is bounded |
| Any server could write to the clipboard via OSC 52 | Off by default, setting to allow |
| Argon2 at 64 MiB; 8-character minimum password | 256 MiB; 12+ characters with a strength check and meter |
| Unlock blocked the UI | Background thread with a spinner |
| No auto-lock | Auto-lock after idle time |
| Password fields were plain `String`s | `Zeroizing<String>` |
| Generating a key changed permissions of an existing `~/.ssh` | Only set when Shellyard creates the directory |
| Saving chmod-ed the vault's parent folder to 0700, even an existing one chosen with `SHELLYARD_VAULT` (e.g. `~/Documents`) | Only a folder Shellyard creates is made private |
| A `run` symlink in a shared vault folder could redirect where decrypted keys are written | Refused unless `run` is a real directory this user owns |
| Decrypted key files stayed on disk until the tab was closed, even after `ssh` had exited | Wiped as soon as the program exits |
| ⌘Q on macOS skipped the final save (edits from the last second, or an in-flight save, were lost) | Saved in `on_exit`, which runs on every way out; sessions and their key files are closed there too |
| Exited child processes were never waited for (zombies until the tab closed) | Reaped when they exit |
| Linux: Ctrl+Shift+C (copy) sent ^C to the program, and Ctrl+V could never send ^V | Ctrl+Shift+C/V use the clipboard, Ctrl+C/V go to the program |
| `sftp` to an IPv6 host failed ("Missing hostname") | Address is bracketed for `sftp`, bare for `ssh` |
| A cancelled ssh-keygen still added a key entry pointing at a missing file | The key is added only once its file exists |
| A changed master password was applied only on the next coalesced save | Re-encrypted right away |

## Known limits

- egui keeps its own copies of text being edited (layout caches, undo), which `zeroize` cannot reach; they are freed but not wiped.
- While a session or tunnel is open it keeps running when the vault is locked; terminal scrollback stays in memory until the tab is closed.
- A decrypted key file exists for as long as `ssh` runs (OpenSSH has to be able to read it), not only during sign-in.
- Text copied from notes, public keys or the terminal stays on the system clipboard; Shellyard does not clear it.
- The master password is used exactly as typed (no Unicode normalization), so a password with accented letters typed differently on another system may not unlock the vault.
- The unlock screen does not slow down repeated guesses; the protection against guessing is Argon2 itself, since an attacker with the file can guess offline anyway.
- Without a code signature or notarization, macOS cannot vouch that the binary is the one you built.
- Not covered by tests: the egui UI itself (no headless UI harness for egui 0.29). It was checked by launching the app, not by automated clicks.
