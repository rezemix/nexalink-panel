"""
Hysteria2 — пример протокола на собственном ядре (не xray).
Агент сам скачает бинарник, положит конфиг и сертификат и запустит юнит.
"""
import json
import random
import secrets
from urllib.parse import quote, urlencode

from ._crypto import self_signed_cert
from .base import Protocol

INSTALL_SCRIPT = r"""
set -e
case "$(uname -m)" in
  x86_64) A=amd64 ;; aarch64|arm64) A=arm64 ;; *) echo "unsupported arch"; exit 1 ;;
esac
curl -fsSL -o /usr/local/bin/hysteria.new "https://download.hysteria.network/app/latest/hysteria-linux-$A"
chmod +x /usr/local/bin/hysteria.new
mv /usr/local/bin/hysteria.new /usr/local/bin/hysteria
"""


class Hysteria2(Protocol):
    id = "hysteria2"
    title = "Hysteria2 (UDP)"
    core = "service"
    transport = "udp"
    default_port = 8443
    fields = [
        {"key": "sni",        "title": "SNI / сайт-маскировка", "default": "dl.google.com"},
        {"key": "up_mbps",    "title": "Лимит upload, Мбит/с (0 — без)",   "default": 0},
        {"key": "down_mbps",  "title": "Лимит download, Мбит/с (0 — без)", "default": 0},
    ]

    def generate_settings(self, given):
        s = super().generate_settings(given)
        if not s.get("private_key_pem"):
            s["cert_pem"], s["private_key_pem"], s["pin_sha256"] = self_signed_cert(s["sni"])
        s.setdefault("stats_port", random.randint(40000, 49999))
        s.setdefault("private_stats_secret", secrets.token_hex(16))
        s.setdefault("obfs_password", "")
        return s

    def service(self, ib, node, users):
        s = ib["settings"]
        base = f"/etc/vpnagent/hy2-{ib['tag']}"
        # YAML — надмножество JSON, hysteria читает такой конфиг
        cfg = {
            "listen": f":{ib['port']}",
            "tls": {"cert": f"{base}.crt", "key": f"{base}.key"},
            "auth": {"type": "userpass", "userpass": {u["uuid"]: u["uuid"] for u in users}},
            "masquerade": {"type": "proxy", "proxy": {"url": f"https://{s['sni']}", "rewriteHost": True}},
            "trafficStats": {"listen": f"127.0.0.1:{s['stats_port']}", "secret": s["private_stats_secret"]},
        }
        if int(s.get("up_mbps") or 0) or int(s.get("down_mbps") or 0):
            cfg["bandwidth"] = {"up": f"{int(s['up_mbps'] or 0)} mbps", "down": f"{int(s['down_mbps'] or 0)} mbps"}
        if not users:
            # hysteria не стартует с пустым списком — заглушка. Значение стабильное,
            # иначе версия конфига менялась бы на каждом опросе агента
            cfg["auth"]["userpass"] = {"_none": s["private_stats_secret"]}
        unit = f"vpn-hy2-{ib['tag']}.service"
        return {
            "name": f"hy2-{ib['tag']}",
            "install": {"check": "test -x /usr/local/bin/hysteria", "script": INSTALL_SCRIPT},
            "files": [
                {"path": f"{base}.crt", "content": s["cert_pem"], "mode": "644"},
                {"path": f"{base}.key", "content": s["private_key_pem"], "mode": "600"},
                {"path": f"{base}.yaml", "content": json.dumps(cfg, indent=2), "mode": "600"},
            ],
            "unit": {
                "name": unit,
                "content": (
                    "[Unit]\nDescription=Hysteria2 " + ib["tag"] + "\nAfter=network-online.target\n\n"
                    "[Service]\nExecStart=/usr/local/bin/hysteria server -c " + base + ".yaml\n"
                    "Restart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n"
                    "[Install]\nWantedBy=multi-user.target\n"
                ),
            },
            "stats": {"type": "hysteria2", "url": f"http://127.0.0.1:{s['stats_port']}/traffic?clear=1",
                      "secret": s["private_stats_secret"]},
        }

    def _auth(self, user):
        return f"{user['uuid']}:{user['uuid']}"

    def link(self, ib, node, user, name):
        s = ib["settings"]
        params = {"sni": s["sni"], "insecure": "1", "pinSHA256": s["pin_sha256"]}
        return f"hysteria2://{quote(self._auth(user), safe='')}@{node['address']}:{ib['port']}?{urlencode(params)}#{quote(name)}"

    def singbox(self, ib, node, user, name):
        s = ib["settings"]
        return {"type": "hysteria2", "tag": name, "server": node["address"], "server_port": ib["port"],
                "password": self._auth(user),
                "tls": {"enabled": True, "server_name": s["sni"], "insecure": True}}

    def clash(self, ib, node, user, name):
        s = ib["settings"]
        return {"name": name, "type": "hysteria2", "server": node["address"], "port": ib["port"],
                "password": self._auth(user), "sni": s["sni"], "skip-cert-verify": True,
                "fingerprint": s["pin_sha256"]}


PROTOCOL = Hysteria2()
