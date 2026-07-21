#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/aliyun-cdt-guard}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo bash uninstall.sh"
  exit 1
fi

systemctl disable --now cdt-guard.timer >/dev/null 2>&1 || true
systemctl disable --now cdt-guard-web.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/cdt-guard.service
rm -f /etc/systemd/system/cdt-guard.timer
rm -f /etc/systemd/system/cdt-guard-web.service
rm -f /usr/local/bin/cdt-guard
systemctl daemon-reload

echo "Services removed."
echo "Data directory is kept at: $INSTALL_DIR"
echo "Remove it manually if you no longer need configs, secrets, status and history."
