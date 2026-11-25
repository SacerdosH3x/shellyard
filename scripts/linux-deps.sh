#!/usr/bin/env bash
# System packages needed to build Shellyard on Debian/Ubuntu.
set -euo pipefail
SUDO=""
[ "$(id -u)" = 0 ] || SUDO=sudo
$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
  build-essential pkg-config curl ca-certificates \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libwayland-dev libgl1-mesa-dev
