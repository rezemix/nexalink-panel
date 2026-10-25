from urllib.parse import quote, urlencode

from ._crypto import short_id, x25519_keypair
from .base import Protocol


class VlessReality(Protocol):
    id = "vless_reality"
    title = "VLESS + Reality"
    core = "xray"
    transport = "tcp"
    default_port = 443
    fields = [
        {"key": "sni",         "title": "SNI (сайт для маскировки)", "default": "dl.google.com"},
        {"key": "fingerprint", "title": "uTLS fingerprint",          "default": "chrome"},
        {"key": "flow",        "title": "Flow",                      "default": "xtls-rprx-vision"},
    ]

    def generate_settings(self, given):
        s = super().generate_settings(given)
        if not s.get("private_key"):
            s["private_key"], s["public_key"] = x25519_keypair()
        s.setdefault("short_id", short_id())
        return s

    def xray_inbound(self, ib, users):
        s = ib["settings"]
        return {
            "tag": ib["tag"],
            "listen": "0.0.0.0",
            "port": ib["port"],
            "protocol": "vless",
            "settings": {
                "clients": [{"id": u["uuid"], "email": u["uuid"], "flow": s["flow"]} for u in users],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": f"{s['sni']}:443",
                    "serverNames": [s["sni"]],
                    "privateKey": s["private_key"],
                    "shortIds": [s["short_id"]],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        }

    def xray_outbound(self, ib, node, client_id, tag):
        """Клиентский outbound на этот инбаунд — для цепочек нод (exit_node)."""
        s = ib["settings"]
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {"vnext": [{"address": node["address"], "port": ib["port"],
                                    "users": [{"id": client_id, "flow": s["flow"], "encryption": "none"}]}]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {"serverName": s["sni"], "fingerprint": s["fingerprint"],
                                    "publicKey": s["public_key"], "shortId": s["short_id"]},
            },
        }

    def link(self, ib, node, user, name):
        s = ib["settings"]
        params = {
            "encryption": "none", "flow": s["flow"], "security": "reality", "sni": s["sni"],
            "fp": s["fingerprint"], "pbk": s["public_key"], "sid": s["short_id"], "type": "tcp",
        }
        return f"vless://{user['uuid']}@{node['address']}:{ib['port']}?{urlencode(params)}#{quote(name)}"

    def singbox(self, ib, node, user, name):
        s = ib["settings"]
        return {
            "type": "vless", "tag": name, "server": node["address"], "server_port": ib["port"],
            "uuid": user["uuid"], "flow": s["flow"],
            "tls": {
                "enabled": True, "server_name": s["sni"],
                "utls": {"enabled": True, "fingerprint": s["fingerprint"]},
                "reality": {"enabled": True, "public_key": s["public_key"], "short_id": s["short_id"]},
            },
        }

    def clash(self, ib, node, user, name):
        s = ib["settings"]
        return {
            "name": name, "type": "vless", "server": node["address"], "port": ib["port"],
            "uuid": user["uuid"], "network": "tcp", "udp": True, "tls": True, "flow": s["flow"],
            "servername": s["sni"], "client-fingerprint": s["fingerprint"],
            "reality-opts": {"public-key": s["public_key"], "short-id": s["short_id"]},
        }


PROTOCOL = VlessReality()
