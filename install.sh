#!/usr/bin/env bash
# Shellyard installer.
#
#   curl -fsSL https://raw.githubusercontent.com/SacerdosH3x/shellyard/main/install.sh | bash
#
# Options (after `bash -s --` when piping):
#   --version v0.1.0   install a specific release instead of the latest
#   --uninstall        remove Shellyard (your vault is kept)
#
# Installs without sudo:
#   macOS: Shellyard.app into /Applications (or ~/Applications), `shellyard` into ~/.local/bin
#   Linux: `shellyard` into ~/.local/bin, plus a desktop entry and icon in ~/.local/share
# Every download is checked against the SHA-256 published with the release.

set -euo pipefail

REPO="SacerdosH3x/shellyard"
BIN_DIR="${SHELLYARD_BIN_DIR:-$HOME/.local/bin}"   # SHELLYARD_APP_DIR overrides the macOS app folder

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

app_dir() {
  if [ -n "${SHELLYARD_APP_DIR:-}" ]; then echo "$SHELLYARD_APP_DIR"; return; fi
  if [ -w /Applications ]; then echo /Applications; else echo "$HOME/Applications"; fi
}

uninstall() {
  rm -f "$BIN_DIR/shellyard"
  case "$(uname -s)" in
    Darwin)
      for d in ${SHELLYARD_APP_DIR:+"$SHELLYARD_APP_DIR"} /Applications "$HOME/Applications"; do
        if [ -d "$d/Shellyard.app" ]; then rm -rf "$d/Shellyard.app" && say "removed $d/Shellyard.app"; fi
      done
      ;;
    Linux)
      rm -f "$HOME/.local/share/applications/shellyard.desktop" \
        "$HOME/.local/share/icons/hicolor/256x256/apps/shellyard.png"
      ;;
  esac
  say "Shellyard removed. Your encrypted vault was kept (delete it yourself if you want it gone)."
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

main() {
  local version="" action="install"
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) version="${2:-}"; shift 2 ;;
      --uninstall) action="uninstall"; shift ;;
      -h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  if [ "$action" = uninstall ]; then uninstall; return; fi

  command -v curl >/dev/null 2>&1 || die "curl is required"
  command -v tar >/dev/null 2>&1 || die "tar is required"

  local platform
  case "$(uname -s)/$(uname -m)" in
    Darwin/*) platform="macos-universal" ;;
    Linux/x86_64|Linux/amd64) platform="linux-x86_64" ;;
    Linux/aarch64|Linux/arm64) platform="linux-aarch64" ;;
    *) die "no prebuilt Shellyard for $(uname -s) $(uname -m); build from source: https://github.com/$REPO" ;;
  esac

  if [ -z "$version" ]; then
    # Prefer the newest stable release (the /releases/latest redirect, no API
    # rate limit). While Shellyard is in beta there is none, so fall back to
    # the newest release of any kind, including pre-releases.
    local url
    url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" 2>/dev/null || true)
    version="${url##*/}"
    case "$version" in
      v*) ;;
      *)
        version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=1" \
          | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
        [ -n "$version" ] || die "no published release found (or the GitHub API rate limit was hit; use --version)"
        ;;
    esac
  fi
  case "$version" in *-*) warn "installing a pre-release ($version): keep a backup of your vault" ;; esac
  case "$version" in v*) ;; *) version="v$version" ;; esac

  local asset="shellyard-${version#v}-$platform.tar.gz"
  local base="https://github.com/$REPO/releases/download/$version"
  # Global (not local): the EXIT trap runs after main has returned.
  tmp=$(mktemp -d)
  trap 'rm -rf "${tmp:-}"' EXIT

  say "Downloading Shellyard $version ($platform)"
  curl -fSL --progress-bar "$base/$asset" -o "$tmp/$asset" || die "download failed: $base/$asset"
  curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256" || die "checksum download failed"

  local expected actual
  expected=$(cut -d' ' -f1 < "$tmp/$asset.sha256")
  actual=$(sha256_of "$tmp/$asset")
  [ -n "$expected" ] && [ "$expected" = "$actual" ] || die "checksum mismatch: expected $expected, got $actual"
  say "Checksum OK"

  mkdir -p "$tmp/x" "$BIN_DIR"
  tar -xzf "$tmp/$asset" -C "$tmp/x"

  case "$platform" in
    macos-*)
      local dest
      dest="$(app_dir)"
      mkdir -p "$dest"
      rm -rf "$dest/Shellyard.app"
      mv "$tmp/x/Shellyard.app" "$dest/"
      ln -sf "$dest/Shellyard.app/Contents/MacOS/shellyard" "$BIN_DIR/shellyard"
      say "Installed $dest/Shellyard.app"
      ;;
    linux-*)
      install -m 0755 "$tmp/x/shellyard" "$BIN_DIR/shellyard"
      mkdir -p "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/256x256/apps"
      install -m 0644 "$tmp/x/shellyard.png" "$HOME/.local/share/icons/hicolor/256x256/apps/shellyard.png"
      sed "s|^Exec=.*|Exec=$BIN_DIR/shellyard|" "$tmp/x/shellyard.desktop" > "$HOME/.local/share/applications/shellyard.desktop"
      say "Installed $BIN_DIR/shellyard and a desktop entry"
      ;;
  esac

  command -v ssh >/dev/null 2>&1 || warn "OpenSSH (ssh) was not found; Shellyard uses it for SSH, SFTP and tunnels."
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) warn "$BIN_DIR is not on your PATH. Add it: echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.zshrc" ;;
  esac
  say "Done. Start it from your apps or run: shellyard"
}

# Everything runs from here, so a partially downloaded script does nothing.
main "$@"
