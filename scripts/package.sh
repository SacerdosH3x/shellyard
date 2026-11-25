#!/usr/bin/env bash
# Builds a release archive into dist/.
#   scripts/package.sh macos   # universal (arm64 + x86_64) Shellyard.app
#   scripts/package.sh linux   # binary for the host architecture
# Output: dist/shellyard-<version>-<platform>.tar.gz and a matching .sha256 file.
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
# macOS bundle versions must be plain numbers: 0.1.0-beta.1 -> 0.1.0
SHORT_VERSION="${VERSION%%-*}"
DIST=dist
mkdir -p "$DIST"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}

case "${1:-}" in
  macos)
    rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
    cargo build --release --locked --target aarch64-apple-darwin
    cargo build --release --locked --target x86_64-apple-darwin
    STAGE=$(mktemp -d)
    APP="$STAGE/Shellyard.app"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
    lipo -create -output "$APP/Contents/MacOS/shellyard" \
      target/aarch64-apple-darwin/release/shellyard target/x86_64-apple-darwin/release/shellyard
    sed -e "s/@VERSION@/$SHORT_VERSION/g" -e "s/@FULL_VERSION@/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"
    cp packaging/macos/Shellyard.icns "$APP/Contents/Resources/"
    # Ad-hoc signature: required for arm64 code, not a Developer ID signature.
    codesign --force --deep --sign - "$APP"
    cp LICENSE-MIT LICENSE-APACHE README.md "$STAGE/"
    NAME="shellyard-$VERSION-macos-universal"
    tar -C "$STAGE" -czf "$DIST/$NAME.tar.gz" Shellyard.app LICENSE-MIT LICENSE-APACHE README.md
    ;;
  linux)
    cargo build --release --locked
    ARCH=$(uname -m)
    STAGE=$(mktemp -d)
    cp target/release/shellyard packaging/linux/shellyard.desktop packaging/linux/shellyard.png \
      LICENSE-MIT LICENSE-APACHE README.md "$STAGE/"
    NAME="shellyard-$VERSION-linux-$ARCH"
    tar -C "$STAGE" -czf "$DIST/$NAME.tar.gz" .
    ;;
  *)
    echo "usage: $0 macos|linux" >&2
    exit 2
    ;;
esac

(cd "$DIST" && sha256 "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "$DIST/$NAME.tar.gz"
