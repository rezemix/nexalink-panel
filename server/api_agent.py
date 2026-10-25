"""Эндпоинты для агентов на нодах и скрипты установки."""
import json
import os
import re
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse

import core
import db
from auth import require_node
from config import PUBLIC_URL

router = APIRouter()

AGENT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent", "agent.py")


def _agent_version() -> str | None:
    with open(AGENT_PATH, encoding="utf-8") as f:
        m = re.search(r'^AGENT_VERSION = "([^"]+)"', f.read(), re.M)
    return m.group(1) if m else None


@router.get("/api/agent/config")
def agent_config(version: str = "", node: dict = Depends(require_node)):
    cfg = core.build_node_config(node)
    # агент сам обновится, если версия в файле agent.py на панели другая
    extra = {"agent_version": _agent_version()}
    if version and version == cfg["version"]:
        return {"version": cfg["version"], "unchanged": True, **extra}
    return {**cfg, **extra}


@router.post("/api/agent/report")
async def agent_report(request: Request, node: dict = Depends(require_node)):
    body = await request.json()
    traffic = body.get("traffic") or {}
    if traffic:
        core.apply_traffic(node["uuid"], traffic)
    uptime = body.get("core_uptime")
    db.execute(
        "UPDATE nodes SET last_seen=?, core_version=?, core_started=?, agent_version=?, "
        "applied_version=?, last_error=?, users_online=?, sys_stats=? WHERE uuid=?",
        (time.time(), body.get("core_version"),
         time.time() - uptime if isinstance(uptime, (int, float)) else None,
         body.get("agent_version"), body.get("applied_version"), body.get("error"),
         int(body.get("users_online") or 0),
         json.dumps(body["sys"]) if isinstance(body.get("sys"), dict) else None, node["uuid"]))
    return {"ok": True}


@router.get("/api/agent/asset/{name}")
def agent_asset(name: str, node: dict = Depends(require_node)):
    """Доп. файлы для xray (расширенный список рекламы) — агент сверяет sha256 из конфига."""
    if name != core.adlists.ASSET_NAME or not os.path.exists(core.ADS_PATH):
        raise HTTPException(404, "Not found")
    return FileResponse(core.ADS_PATH, media_type="application/octet-stream")


@router.get("/install/agent.py", response_class=PlainTextResponse)
def agent_source():
    with open(AGENT_PATH, encoding="utf-8") as f:
        return f.read()


@router.get("/install/node.sh", response_class=PlainTextResponse)
def install_script():
    return NODE_INSTALL.replace("__PANEL__", PUBLIC_URL)


NODE_INSTALL = r"""#!/bin/bash
# Установка ноды: xray + агент панели. Использование: bash -s -- <NODE_TOKEN>
set -e
TOKEN="$1"
PANEL="__PANEL__"
[ -z "$TOKEN" ] && { echo "usage: bash -s -- <NODE_TOKEN>"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
export TERM=${TERM:-xterm}

echo "[1/4] Пакеты"
apt-get update -qq && apt-get install -y -qq curl python3 ufw ca-certificates >/dev/null

echo "[2/4] Xray"
if ! command -v /usr/local/bin/xray >/dev/null; then
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null
fi

echo "[3/4] Агент"
mkdir -p /opt/vpnagent /etc/vpnagent /var/lib/vpnagent
curl -fsSL "$PANEL/install/agent.py" -o /opt/vpnagent/agent.py
cat > /etc/vpnagent/agent.json <<JSON
{"panel": "$PANEL", "token": "$TOKEN"}
JSON
chmod 600 /etc/vpnagent/agent.json
cat > /etc/systemd/system/vpnagent.service <<UNIT
[Unit]
Description=VPN panel node agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/vpnagent/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

echo "[4/4] Сеть"
grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf || {
  echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
}
SSH_PORT=$(ss -tlnp | awk '/sshd/ {split($4,a,":"); print a[length(a)]; exit}')
ufw allow "${SSH_PORT:-22}/tcp" >/dev/null
ufw --force enable >/dev/null

systemctl daemon-reload
systemctl enable --now vpnagent >/dev/null 2>&1
systemctl restart vpnagent
echo "Готово. Логи агента: journalctl -u vpnagent -f"
"""
