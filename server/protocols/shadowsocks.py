import base64
import secrets
import uuid as uuidlib
from urllib.parse import quote

from .base import Protocol


def _user_key(user_uuid: str) -> str:
    # 2022-blake3-aes-128-gcm требует 16-байтный ключ — это ровно UUID пользователя
    return base64.b64encode(uuidlib.UUID(user_uuid).bytes).decode()


class Shadowsocks2022(Protocol):
    id = "shadowsocks"
    title = "Shadowsocks 2022"
    core = "xray"
    transport = "both"
    default_port = 8388
    fields = [
        {"key": "method", "title": "Метод", "default": "2022-blake3-aes-128-gcm"},
    ]

    def generate_settings(self, given):
        s = super().generate_settings(given)
        if s["method"] != "2022-blake3-aes-128-gcm":
            raise ValueError("Поддерживается только 2022-blake3-aes-128-gcm")
        s.setdefault("server_key", base64.b64encode(secrets.token_bytes(16)).decode())
        return s

    def _password(self, ib, user):
        return f"{ib['settings']['server_key']}:{_user_key(user['uuid'])}"

    def xray_inbound(self, ib, users):
        s = ib["settings"]
        return {
            "tag": ib["tag"],
            "listen": "0.0.0.0",
            "port": ib["port"],
            "protocol": "shadowsocks",
            "settings": {
                "method": s["method"],
                "password": s["server_key"],
                "clients": [{"password": _user_key(u["uuid"]), "email": u["uuid"]} for u in users],
                "network": "tcp,udp",
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        }

    def link(self, ib, node, user, name):
        userinfo = base64.urlsafe_b64encode(
            f"{ib['settings']['method']}:{self._password(ib, user)}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{node['address']}:{ib['port']}#{quote(name)}"

    def singbox(self, ib, node, user, name):
        return {"type": "shadowsocks", "tag": name, "server": node["address"], "server_port": ib["port"],
                "method": ib["settings"]["method"], "password": self._password(ib, user)}

    def clash(self, ib, node, user, name):
        return {"name": name, "type": "ss", "server": node["address"], "port": ib["port"],
                "cipher": ib["settings"]["method"], "password": self._password(ib, user), "udp": True}


PROTOCOL = Shadowsocks2022()
