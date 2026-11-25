# Shellyard: build plan

A local, native (no webview) SSH, SFTP and terminal manager written in Rust.
Nothing runs on a server. Hosts and credentials live in an encrypted file on this machine.

## Stack

| Concern            | Crate                         |
|--------------------|-------------------------------|
| UI                 | eframe / egui                 |
| Terminal emulation | alacritty_terminal            |
| Local shells       | portable-pty                  |
| SSH / SFTP         | system OpenSSH today; russh, russh-sftp next |
| Icons              | egui-phosphor                 |
| Key derivation     | argon2 (Argon2id, 256 MiB, t=3, p=1) |
| Encryption         | aes-gcm (AES-256-GCM)         |
| Storage format     | serde_json, sealed by vault.rs |

## Security rules

1. The master password is never written to disk. Keys are zeroed after use.
2. Each save uses a fresh random salt and nonce.
3. No telemetry and no automatic network calls. The only network traffic is an SSH or SFTP connection the user starts.
4. Credentials are never shown in the UI, logs or error messages.
5. Vault file format is versioned so it can be migrated later. A vault from a newer version is refused, not silently downgraded.
6. New master passwords need 12+ characters and must pass a guessability check.
7. The vault locks after 15 minutes idle by default (Settings → Security).
8. Programs in a terminal cannot set the clipboard (OSC 52) unless the user turns it on.

See [SECURITY.md](SECURITY.md) for the threat model, the analysis results and known limits.

## Milestones

1. **Shell (done):** dark UI with icon rail, top bar with tabs, hosts sidebar (protocol filter, search, favorites, folder tree), home page (search, favorites, recent, local terminals, hosts by folder), command palette.
2. **Vault (mostly done):** create/unlock screen, sealed inventory saved in the background on every change, lock button, change master password. *Still to do:* unlock-policy setting (each launch, once per session, new device only), which needs the OS keychain.
3. **Local terminal (done):** PTY via portable-pty, VT grid via alacritty_terminal, drawn with the egui painter, keyboard input, resize, scrollback, OSC title.
4. **SSH (interim):** hosts open the system OpenSSH client (`ssh` / `sftp`) inside a terminal tab, so known_hosts, agents and keys already work.
   - **SSH keys (done):** Keys page; per-host key picker. A key is either a file path or stored encrypted in the vault (written to a 0600 temp file only while a session runs, wiped on close, leftovers wiped at startup). Generate with ssh-keygen in a tab; install on a host with ssh-copy-id.
   - *Still to do:* russh for saved passwords and auto-login, reconnect without a new process.
4b. **Tunnels (done):** local (-L), remote (-R) and SOCKS (-D) forwards run as `ssh -N` with ExitOnForwardFailure and keepalives; start/stop, status, live console for passphrase prompts, auto-start on unlock.
4c. **Notes (done):** notes in the vault, optionally linked to a host, searchable, paste into a terminal tab.
5. **Tabs and panes (partial):** tabs, reconnect, keyboard shortcuts. *Still to do:* split up to 16 panes, broadcast input.
6. **SFTP:** dual-pane browser, drag-and-drop transfers, chmod, inline editor, live tail. (Today: the `sftp` CLI in a tab.)
7. **Organize and personalize (partial):** host editor (folder, type, tags, protocols, favorite), command palette. *Still to do:* drag-and-drop folders, custom colors and icons, themes, keybinding editor, PuTTY/WinSCP/MobaXterm import.
8. **Backup:** encrypted export and import, Git or cloud-folder sync of ciphertext.
9. **Later:** RDP, Docker management, auto-update. The Docker page is a placeholder in the UI.

## Running

    cargo run            # debug build
    cargo test           # unit, fuzz-style and process tests (vault, store, terminal, ssh args)
    cargo clippy --all-targets
    cargo audit          # known-vulnerable dependencies (cargo install cargo-audit)
    SHELLYARD_VAULT=/tmp/test.vault cargo run   # use a throwaway vault
    cargo build --release
