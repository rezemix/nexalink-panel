import os

DATA_DIR   = os.getenv("PANEL_DATA", "/var/lib/vpnpanel")
DB_PATH    = os.path.join(DATA_DIR, "panel.db")

# Публичный адрес панели: из него строятся ссылки подписок и команда установки ноды
PUBLIC_URL = os.getenv("PANEL_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/")

# Префикс ссылок подписки: <SUB_PUBLIC_URL>/<shortUuid>. Можно вынести на отдельный
# домен (например https://sub.example.com), проксируя его на <PUBLIC_URL>/sub/
SUB_PUBLIC_URL = os.getenv("SUB_PUBLIC_URL", PUBLIC_URL + "/sub").rstrip("/")

# Первый админ создаётся из этих переменных при пустой базе
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

# Нода считается онлайн, если агент отчитывался не позже стольких секунд назад
NODE_ONLINE_TIMEOUT = int(os.getenv("NODE_ONLINE_TIMEOUT", "60"))

# Порт gRPC API xray на ноде (слушает только 127.0.0.1)
XRAY_API_PORT = 10085

SUB_TITLE           = os.getenv("SUB_TITLE", "VPN")
SUB_UPDATE_HOURS    = int(os.getenv("SUB_UPDATE_HOURS", "1"))
SUB_SUPPORT_URL     = os.getenv("SUB_SUPPORT_URL", "")
# Бесплатная публичная выдача подписок (POST /api/public/register).
# Адреса прокси, которым доверяем заголовок X-Real-IP (например, сервер, проксирующий sub-домен)
TRUSTED_PROXIES     = {ip.strip() for ip in os.getenv("TRUSTED_PROXIES", "").split(",") if ip.strip()}
# Сайты, с которых браузер может вызывать выдачу (CORS), через запятую
PUBLIC_CORS_ORIGINS = {o.strip() for o in os.getenv("PUBLIC_CORS_ORIGINS", "").split(",") if o.strip()}
# Android-приложение для кнопки «Открыть в приложении» на странице подписки
APP_NAME            = os.getenv("APP_NAME", "NEXALINK")
APP_PACKAGE         = os.getenv("APP_PACKAGE", "online.nexalink.app.fdroid")
APP_SCHEME          = os.getenv("APP_SCHEME", "nexalink")
APP_DOWNLOAD_URL    = os.getenv("APP_DOWNLOAD_URL", "https://nexalink.online/dl/nexalink-test.apk")
# true — без заголовка x-hwid подписка не выдаётся пользователям с лимитом устройств
HWID_STRICT         = os.getenv("HWID_STRICT", "false").lower() == "true"
