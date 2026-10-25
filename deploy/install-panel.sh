#!/bin/bash
# Установка панели на Ubuntu/Debian. Запускать из папки panel/ на сервере:
#   DOMAIN=panel.example.com PORT=443 bash deploy/install-panel.sh
# Без DOMAIN используется <ip>.sslip.io (бесплатный домен, сертификат Let's Encrypt).
set -e
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
SRC="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-9443}"
IP=$(curl -4 -fsS https://ifconfig.me)
DOMAIN="${DOMAIN:-${IP//./-}.sslip.io}"
URL="https://$DOMAIN$([ "$PORT" = 443 ] || echo ":$PORT")"

echo "[1/5] Пакеты"
apt-get update -qq && apt-get install -y -qq python3 python3-venv curl ufw >/dev/null

echo "[2/5] Код панели → /opt/vpnpanel"
mkdir -p /opt/vpnpanel /etc/vpnpanel /var/lib/vpnpanel
cp -r "$SRC/server" "$SRC/agent" /opt/vpnpanel/
python3 -m venv /opt/vpnpanel/venv
/opt/vpnpanel/venv/bin/pip install -q -r /opt/vpnpanel/server/requirements.txt

if [ ! -f /etc/vpnpanel/env ]; then
  PASS=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
  cat > /etc/vpnpanel/env <<ENV
PANEL_PUBLIC_URL=$URL
PANEL_DATA=/var/lib/vpnpanel
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$PASS
SUB_TITLE=VPN
ENV
  chmod 600 /etc/vpnpanel/env
  echo "Пароль админа: $PASS (сохранён в /etc/vpnpanel/env)"
fi

echo "[3/5] Сервис панели"
cat > /etc/systemd/system/vpnpanel.service <<UNIT
[Unit]
Description=VPN Panel
After=network-online.target

[Service]
EnvironmentFile=/etc/vpnpanel/env
WorkingDirectory=/opt/vpnpanel/server
ExecStart=/opt/vpnpanel/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips 127.0.0.1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now vpnpanel >/dev/null 2>&1
systemctl restart vpnpanel

echo "[4/5] Caddy (HTTPS)"
if ! command -v caddy >/dev/null; then
  case "$(uname -m)" in x86_64) A=amd64 ;; aarch64|arm64) A=arm64 ;; esac
  curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=$A" -o /usr/local/bin/caddy
  chmod +x /usr/local/bin/caddy
fi
mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<CADDY
$DOMAIN:$PORT {
  encode gzip
  reverse_proxy 127.0.0.1:8000
}

# :80 занят Caddy — агент ноды выпускает сертификаты (XHTTP+TLS) через acme.sh на 8402
http:// {
  reverse_proxy /.well-known/acme-challenge/* 127.0.0.1:8402
}
CADDY
cat > /etc/systemd/system/caddy.service <<UNIT
[Unit]
Description=Caddy
After=network-online.target

[Service]
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile
Environment=XDG_DATA_HOME=/var/lib XDG_CONFIG_HOME=/etc
Restart=always
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now caddy >/dev/null 2>&1
systemctl restart caddy

echo "[5/5] Фаервол"
ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow "$PORT/tcp" >/dev/null
ufw --force enable >/dev/null

echo "Панель: $URL"
