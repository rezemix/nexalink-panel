import secrets
from urllib.parse import quote, urlencode

from .base import Protocol

CERT_DIR = "/etc/vpnagent/certs"


class VlessWsTls(Protocol):
    id = "vless_ws_tls"
    title = "VLESS + WebSocket + TLS"
    core = "xray"
    transport = "tcp"
    default_port = 443
    fields = [
        {"key": "domain",      "title": "Домен (A-запись на IP ноды)", "default": ""},
        {"key": "path",        "title": "Path",                        "default": ""},
        {"key": "fingerprint", "title": "uTLS fingerprint",            "default": "chrome"},
        {"key": "exit_node",   "title": "Выход через ноду (имя, пусто — напрямую)", "default": ""},
    ]

    def generate_settings(self, given):
        s = super().generate_settings(given)
        if not s.get("domain"):
            raise ValueError("Для WebSocket+TLS нужен домен")
        s["path"] = s.get("path") or "/" + secrets.token_hex(6)
        if not s["path"].startswith("/"):
            s["path"] = "/" + s["path"]
        return s

    def certificates(self, ib):
        return [ib["settings"]["domain"]]

    def xray_inbound(self, ib, users):
        s = ib["settings"]
        d = f"{CERT_DIR}/{s['domain']}"
        return {
            "tag": ib["tag"],
            "listen": "0.0.0.0",
            "port": ib["port"],
            "protocol": "vless",
            "settings": {
                "clients": [{"id": u["uuid"], "email": u["uuid"]} for u in users],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": s["path"]},
                "tlsSettings": {
                    "serverName": s["domain"],
                    "alpn": ["http/1.1"],
                    "certificates": [{"certificateFile": f"{d}/fullchain.pem", "keyFile": f"{d}/key.pem"}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        }

    def link(self, ib, node, user, name):
        s = ib["settings"]
        params = {
            "encryption": "none", "security": "tls", "sni": s["domain"], "fp": s["fingerprint"],
            "alpn": "http/1.1", "type": "ws", "host": s["domain"], "path": s["path"],
        }
        return f"vless://{user['uuid']}@{s['domain']}:{ib['port']}?{urlencode(params)}#{quote(name)}"

    def singbox(self, ib, node, user, name):
        s = ib["settings"]
        return {
            "type": "vless", "tag": name, "server": s["domain"], "server_port": ib["port"], "uuid": user["uuid"],
            "tls": {"enabled": True, "server_name": s["domain"], "alpn": ["http/1.1"],
                    "utls": {"enabled": True, "fingerprint": s["fingerprint"]}},
            "transport": {"type": "ws", "path": s["path"], "headers": {"Host": s["domain"]}},
        }

    def clash(self, ib, node, user, name):
        s = ib["settings"]
        return {
            "name": name, "type": "vless", "server": s["domain"], "port": ib["port"], "uuid": user["uuid"],
            "udp": True, "tls": True, "servername": s["domain"], "client-fingerprint": s["fingerprint"],
            "network": "ws", "ws-opts": {"path": s["path"], "headers": {"Host": s["domain"]}},
        }


PROTOCOL = VlessWsTls()
