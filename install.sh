#!/usr/bin/env bash
# Installs hotspot-cli, hotspot-ui, the polkit policy, the menu entry and the icon.
# Usage: ./install.sh             build and install
#        ./install.sh --service   also install the background service: the app then runs the
#                                 hotspot without a password, and it survives closing the window
#        ./install.sh --uninstall
set -euo pipefail
cd "$(dirname "$0")"

PREFIX=/usr/local
# polkit only reads actions from /usr/share; the policy's exec.path points at $PREFIX/bin
POLICY=/usr/share/polkit-1/actions/org.hotspot.policy
UNIT=/etc/systemd/system/hotspot.service
FILES=(
  "$UNIT"
  "$PREFIX/bin/hotspot-cli"
  "$PREFIX/bin/hotspot-ui"
  "$POLICY"
  "$PREFIX/share/applications/hotspot.desktop"
  "$PREFIX/share/icons/hicolor/scalable/apps/hotspot.svg"
)

if [[ "${1:-}" == "--uninstall" ]]; then
  sudo systemctl disable --now hotspot.service 2>/dev/null || true
  sudo rm -f "${FILES[@]}"
  rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/hotspot.desktop"
  sudo systemctl daemon-reload
  echo "uninstalled"
  exit 0
fi

cargo build --release
sudo install -Dm755 target/release/hotspot-cli "$PREFIX/bin/hotspot-cli"
sudo install -Dm755 target/release/hotspot-ui "$PREFIX/bin/hotspot-ui"
sudo install -Dm644 packaging/org.hotspot.policy "$POLICY"
sudo install -Dm644 packaging/hotspot.desktop "$PREFIX/share/applications/hotspot.desktop"
sudo install -Dm644 packaging/hotspot.svg "$PREFIX/share/icons/hicolor/scalable/apps/hotspot.svg"
sudo gtk-update-icon-cache -q "$PREFIX/share/icons/hicolor" 2>/dev/null || true
# a running service still uses the old binary: restart it (this stops a running hotspot)
sudo systemctl try-restart hotspot.service 2>/dev/null || true
if [[ "${1:-}" == "--service" ]]; then
  sudo groupadd -f hotspot
  sudo usermod -aG hotspot "$USER"
  sudo install -Dm644 packaging/hotspot.service "$UNIT"
  sudo systemctl daemon-reload
  sudo systemctl enable --now hotspot.service
  echo "service enabled. Log out and back in once so your account joins the 'hotspot' group."
fi
echo "installed: run 'hotspot-ui' or open Hotspot from the applications menu"
