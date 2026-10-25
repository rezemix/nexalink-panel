import json
import secrets
from urllib.parse import quote, urlencode

from .base import Protocol

CERT_DIR = "/etc/vpnagent/certs"


class VlessXhttpTls(Protocol):
    id = "vless_xhttp_tls"
    title = "VLESS + XHTTP + TLS"
    core = "xray"
    transport = "tcp"
    default_port = 443
    fields = [
        {"key": "domain",      "title": "Домен (A-запись на IP ноды)", "default": ""},
        {"key": "path",        "title": "Path",                        "default": ""},
        {"key": "mode",        "title": "XHTTP mode",                  "default": "auto"},
        {"key": "fingerprint", "title": "uTLS fingerprint",            "default": "chrome"},
        {"key": "exit_node",   "title": "Выход через ноду (имя, пусто — напрямую)", "default": ""},
        # CDN без метода POST (CDN Яндекс Облака): клиент шлёт данные GET-запросами в заголовке,
        # а в ссылке вместо домена ноды — домен CDN на 443 (CDN проксирует на этот инбаунд)
        {"key": "cdn_domain",  "title": "Домен CDN для ссылок (пусто — напрямую)", "default": ""},
        {"key": "uplink_get",  "title": "Отправка через GET (для CDN без POST): true/false", "default": ""},
    ]

    @staticmethod
    def _uplink_get(s) -> dict:
        """Настройки XHTTP для отправки GET-запросами — одинаковые у сервера и клиента."""
        if str(s.get("uplink_get") or "").lower() not in ("1", "true", "yes", "on"):
            return {}
        # данные пакета — в одном заголовке: при нескольких заголовках на запрос Xray 26.x
        # отправку ломает, поэтому кусок (16000) больше лимита на запрос (6000 → ~8 КБ base64)
        return {"uplinkHTTPMethod": "GET", "uplinkDataPlacement": "header", "uplinkChunkSize": 16000,
                "scMaxEachPostBytes": 6000, "scMinPostsIntervalMs": 5}

    def generate_settings(self, given):
        s = super().generate_settings(given)
        if not s.get("domain"):
            raise ValueError("Для XHTTP+TLS нужен домен")
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
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": s["path"], "mode": s["mode"], **self._uplink_get(s)},
                "tlsSettings": {
                    "serverName": s["domain"],
                    "alpn": ["h2", "http/1.1"],
                    "certificates": [{"certificateFile": f"{d}/fullchain.pem", "keyFile": f"{d}/key.pem"}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        }

    def link(self, ib, node, user, name):
        s = ib["settings"]
        host = s.get("cdn_domain") or s["domain"]
        port = 443 if s.get("cdn_domain") else ib["port"]
        params = {
            "encryption": "none", "security": "tls", "sni": host, "fp": s["fingerprint"],
            "alpn": "h2,http/1.1", "type": "xhttp", "host": host, "path": s["path"], "mode": s["mode"],
        }
        extra = self._uplink_get(s)
        if extra:
            params["extra"] = json.dumps(extra, separators=(",", ":"))
        return f"vless://{user['uuid']}@{host}:{port}?{urlencode(params)}#{quote(name)}"

    def singbox(self, ib, node, user, name):
        # в sing-box нет транспорта XHTTP
        return None

    def clash(self, ib, node, user, name):
        s = ib["settings"]
        if s.get("cdn_domain") or self._uplink_get(s):
            return None  # Clash не умеет XHTTP с отправкой через GET
        return {
            "name": name, "type": "vless", "server": s["domain"], "port": ib["port"], "uuid": user["uuid"],
            "udp": True, "tls": True, "servername": s["domain"], "client-fingerprint": s["fingerprint"],
            "alpn": ["h2", "http/1.1"], "network": "xhttp",
            "xhttp-opts": {"path": s["path"], "host": s["domain"], "mode": s["mode"]},
        }


PROTOCOL = VlessXhttpTls()
