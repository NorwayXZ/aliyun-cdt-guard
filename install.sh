#!/usr/bin/env bash
set -euo pipefail

APP_NAME="aliyun-cdt-guard"
INSTALL_DIR="${INSTALL_DIR:-/opt/aliyun-cdt-guard}"
REPO_URL="${REPO_URL:-https://github.com/NorwayXZ/aliyun-cdt-guard.git}"
WEB_PORT="${WEB_PORT:-8787}"
WEB_USER="${WEB_USER:-admin}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo bash install.sh"
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_packages() {
  if need_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y python3 python3-venv python3-pip git curl openssl cron ca-certificates
  elif need_cmd dnf; then
    dnf install -y python3 python3-pip git curl openssl
  elif need_cmd yum; then
    yum install -y python3 python3-pip git curl openssl
  else
    echo "Unsupported Linux distribution. Please install python3, python3-venv, git, curl and openssl first."
    exit 1
  fi
}

prepare_source() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -f "$script_dir/guard.py" ] && [ -f "$script_dir/web.py" ]; then
    echo "$script_dir"
    return
  fi

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  git clone --depth 1 "$REPO_URL" "$tmp_dir"
  echo "$tmp_dir"
}

install_packages
SRC_DIR="$(prepare_source)"

install -d -m 700 "$INSTALL_DIR"
install -m 755 "$SRC_DIR/guard.py" "$INSTALL_DIR/guard.py"
install -m 755 "$SRC_DIR/web.py" "$INSTALL_DIR/web.py"
install -m 755 "$SRC_DIR/notifications.py" "$INSTALL_DIR/notifications.py"
install -m 644 "$SRC_DIR/cdt-guard.service" /etc/systemd/system/cdt-guard.service
install -m 644 "$SRC_DIR/cdt-guard.timer" /etc/systemd/system/cdt-guard.timer
install -m 644 "$SRC_DIR/cdt-guard-web.service" /etc/systemd/system/cdt-guard-web.service

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$SRC_DIR/requirements.txt"

if [ ! -f "$INSTALL_DIR/guard.env" ]; then
  umask 077
  cat > "$INSTALL_DIR/guard.env" <<'EOF'
# Optional global fallback credentials.
# New servers can be added completely from the web panel, so these may stay empty.
ALIYUN_ACCESS_KEY_ID=
ALIYUN_ACCESS_KEY_SECRET=
ALIYUN_REGION_ID=cn-hongkong
EOF
fi

if [ ! -f "$INSTALL_DIR/instances.json" ]; then
  umask 077
  cat > "$INSTALL_DIR/instances.json" <<'EOF'
{
  "defaults": {
    "enabled": true,
    "start_threshold_gb": 175,
    "stop_threshold_gb": 180,
    "traffic_region_id": "cn-hongkong",
    "warning_threshold_gb": 160
  },
  "instances": [],
  "version": 1
}
EOF
fi

if [ ! -f "$INSTALL_DIR/web.env" ]; then
  WEB_PASS="$(openssl rand -base64 24 | tr -d '\n')"
  WEB_SESSION_SECRET="$(openssl rand -hex 32)"
  umask 077
  cat > "$INSTALL_DIR/web.env" <<EOF
WEB_USERNAME=$WEB_USER
WEB_PASSWORD=$WEB_PASS
WEB_SESSION_SECRET=$WEB_SESSION_SECRET
CDT_GUARD_HOST=0.0.0.0
CDT_GUARD_PORT=$WEB_PORT
EOF
else
  WEB_PASS="$(sed -n 's/^WEB_PASSWORD=//p' "$INSTALL_DIR/web.env" | head -n 1)"
  if ! grep -q '^WEB_SESSION_SECRET=' "$INSTALL_DIR/web.env"; then
    WEB_SESSION_SECRET="$(openssl rand -hex 32)"
    umask 077
    printf '\nWEB_SESSION_SECRET=%s\n' "$WEB_SESSION_SECRET" >> "$INSTALL_DIR/web.env"
  fi
fi

chmod 700 "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/guard.env" "$INSTALL_DIR/instances.json" "$INSTALL_DIR/web.env"

rm -f /usr/local/bin/cdt-guard
cat > /usr/local/bin/cdt-guard <<EOF
#!/bin/sh
exec "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/guard.py" "\$@"
EOF
chmod 755 /usr/local/bin/cdt-guard

systemctl daemon-reload
systemctl enable --now cdt-guard.timer
systemctl enable --now cdt-guard-web.service

IP_ADDR="$(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"

cat <<EOF

$APP_NAME installed.

Web panel:
  URL:      http://$IP_ADDR:$WEB_PORT
  Username: $WEB_USER
  Password: $WEB_PASS

Commands:
  cdt-guard status
  systemctl status cdt-guard.timer
  systemctl status cdt-guard-web.service

EOF
