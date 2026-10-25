"""
Базовый класс протокола.

Чтобы добавить свой протокол, создайте файл в этой папке с классом-наследником
Protocol и переменной PROTOCOL = MyProtocol(). Панель подхватит его при запуске.

Обозначения в методах:
    ib    — инбаунд: {"uuid", "tag", "port", "remark", "settings": {...}}
    node  — нода:    {"uuid", "name", "address", "country", ...}
    user  — пользователь: {"uuid", "username", ...}
    users — список активных пользователей

Любой xray-инбаунд можно пустить «через другую ноду»: поле exit_node в настройках
(имя или uuid ноды) — трафик уйдёт с этой ноды на её VLESS Reality инбаунд.

Протокол работает либо внутри xray (core = "xray", реализуйте xray_inbound),
либо на своём ядре (core = "service", реализуйте service — агент на ноде
сам поставит бинарник, разложит файлы и перезапустит systemd-юнит).
"""


class Protocol:
    id = ""
    title = ""
    core = "xray"            # "xray" | "service"
    transport = "tcp"        # для фаервола ноды: tcp | udp | both
    default_port = 443

    # Поля, которые можно задать в админке. Остальные настройки
    # (ключи, сертификаты) протокол генерирует сам в generate_settings.
    # [{"key": "sni", "title": "SNI", "default": "dl.google.com"}]
    fields: list[dict] = []

    def generate_settings(self, given: dict) -> dict:
        """Заполнить настройки нового инбаунда: дефолты полей + секреты."""
        out = {f["key"]: f.get("default") for f in self.fields}
        out.update({k: v for k, v in (given or {}).items() if v not in (None, "")})
        return out

    def public_settings(self, settings: dict) -> dict:
        """Что показать в админке (без приватных ключей)."""
        return {k: v for k, v in settings.items() if not k.startswith("private")}

    # --- серверная часть ---

    def xray_inbound(self, ib: dict, users: list[dict]) -> dict:
        raise NotImplementedError

    def certificates(self, ib: dict) -> list[str]:
        """Домены, для которых агент должен выпустить сертификат Let's Encrypt.
        Файлы: /etc/vpnagent/certs/<domain>/fullchain.pem и key.pem."""
        return []

    def service(self, ib: dict, node: dict, users: list[dict]) -> dict:
        """
        Описание сервиса для агента:
        {
          "name": "hy2-main",
          "install": {"check": "test -x /usr/local/bin/x", "script": "..."},
          "files": [{"path": "/etc/x.yaml", "content": "...", "mode": "600"}],
          "unit": {"name": "vpn-x.service", "content": "[Unit]..."},
          "stats": {"type": "hysteria2", "url": "...", "secret": "..."}
        }
        """
        raise NotImplementedError

    # --- клиентская часть (подписка) ---

    def link(self, ib: dict, node: dict, user: dict, name: str) -> str | None:
        return None

    def singbox(self, ib: dict, node: dict, user: dict, name: str) -> dict | None:
        return None

    def clash(self, ib: dict, node: dict, user: dict, name: str) -> dict | None:
        return None
