# NEXALINK Panel

Панель управления VPN-нодами на Xray: пользователи, подписки, ноды и протоколы-плагины.
На ней работает бесплатный VPN [NEXALINK](https://nexalink.online); Android-клиент — [rezemix/nexalink-android](https://github.com/rezemix/nexalink-android).

- FastAPI + SQLite, один процесс, без внешних зависимостей вроде Redis или Postgres
- агент на нодах — один файл на стандартной библиотеке Python, сам ставит Xray, выпускает сертификаты и открывает порты
- протоколы: VLESS + WebSocket + TLS, VLESS + Reality, VLESS + XHTTP + TLS (в т. ч. через CDN без POST), Shadowsocks, Hysteria2
- цепочки нод (вход в одной стране, выход в другой) — мост на Reality собирается автоматически
- бесплатная выдача доступа без регистрации (`POST /api/public/register`, лимит на IP)
- блокировка рекламы на нодах: `geosite:category-ads-all` + собственный список из AdGuard DNS filter и RU AdList, пересобирается раз в сутки
- статистика: онлайн, активные пользователи, новые по источникам, трафик по нодам
- API пользователей и нод совместим с RemnaWave

API пользователей и нод совместим с RemnaWave.

```
nexalink-panel/
├── server/                 FastAPI + SQLite
│   ├── app.py              точка входа
│   ├── core.py             статусы пользователей, сборка конфига ноды, учёт трафика
│   ├── api_users.py        /api/users… (формат RemnaWave)
│   ├── api_nodes.py        /api/nodes, /api/inbounds, /api/tokens, /api/admin
│   ├── api_agent.py        /api/agent/* для нод, /install/node.sh
│   ├── subscription.py     /sub/<shortUuid>[/base64|plain|singbox|clash|json]
│   ├── protocols/          плагины протоколов (подхватываются автоматически)
│   └── static/admin.html   админка
├── agent/agent.py          агент ноды (только stdlib Python)
└── deploy/install-panel.sh установка / обновление панели
```

## Как это работает

- **Агент** на ноде раз в 10 с забирает с панели желаемое состояние (`/api/agent/config`)
  и применяет его, затем отправляет трафик (`/api/agent/report`). Входящие порты на ноде
  для панели не нужны.
- Пользователи добавляются/удаляются в xray **через API без перезапуска** (`xray api adu/rmu`).
  Перезапуск только при изменении самих инбаундов.
- Протоколы на своём ядре (пример — `hysteria2.py`): агент сам ставит бинарник,
  раскладывает файлы, создаёт systemd-юнит, открывает порт в ufw и снимает статистику.
- Когда меняется `AGENT_VERSION` в `agent/agent.py` на панели, агенты обновляются сами.
- Истечение срока / лимит трафика / сброс по DAY|WEEK|MONTH — фоновая задача раз в 30 с.

## Подписка

`https://<панель>/sub/<shortUuid>` — формат выбирается по User-Agent:

| Клиент | Формат |
|---|---|
| Happ, v2rayNG, v2RayTun, Hiddify, Streisand, NekoBox | base64 со ссылками |
| sing-box (SFA/SFI/SFM) | JSON-конфиг sing-box |
| Clash / mihomo / Stash | YAML |
| Браузер | страница с QR и кнопками импорта |

Явно: `/sub/<id>/base64|plain|singbox|clash|json`.
`json` — для своего приложения: данные пользователя + список серверов с готовыми
`link`, `singbox`, `clash` для каждого.

Заголовки `subscription-userinfo`, `profile-title`, `profile-update-interval` отдаются —
приложения показывают трафик/срок и сами обновляют список серверов. Новая нода появляется
у клиентов при следующем обновлении подписки.

Лимит устройств: заголовок `x-hwid` (Happ, v2RayTun и др.). При превышении вместо серверов
отдаётся заглушка «⛔ Лимит устройств». `HWID_STRICT=true` — не выдавать подписку без `x-hwid`.

## Протоколы

| id | Что | Ядро |
|---|---|---|
| `vless_reality` | VLESS + Reality | xray |
| `vless_xhttp_tls` | VLESS + XHTTP + TLS (сертификат Let's Encrypt выпускает агент) | xray |
| `shadowsocks` | Shadowsocks 2022 | xray |
| `hysteria2` | Hysteria2 (UDP) | своё (пример `core = "service"`) |

**Цепочка нод (`exit_node`).** Любому xray-инбаунду можно указать в настройках
`exit_node` — имя ноды выхода. Трафик пойдёт на её VLESS Reality инбаунд под служебным
пользователем, которого панель сама заведёт на ноде выхода. Так сделан вход в РФ
(XHTTP+TLS на московской ноде) с выходом в интернет через Финляндию.

**Сертификаты.** Протокол возвращает домены в `certificates()`, агент выпускает их через
acme.sh (`/etc/vpnagent/certs/<домен>/`), автопродление — cron acme.sh. Если :80 занят
(Caddy панели), acme.sh слушает 8402, а Caddy проксирует туда `/.well-known/acme-challenge/`.
Пока сертификата нет, агент временно выключает только этот инбаунд и пишет ошибку в статус ноды.

## Свой протокол

Файл `server/protocols/my_proto.py`:

```python
from .base import Protocol

class MyProto(Protocol):
    id = "my_proto"
    title = "My Protocol"
    core = "xray"             # или "service" — своё ядро
    transport = "tcp"         # tcp | udp | both — для фаервола ноды
    default_port = 2053
    fields = [{"key": "sni", "title": "SNI", "default": "example.com"}]   # редактируется в админке

    def generate_settings(self, given):      # ключи/сертификаты при создании
        s = super().generate_settings(given); ...; return s
    def xray_inbound(self, ib, users): ...   # для core = "xray"
    def service(self, ib, node, users): ...  # для core = "service" (см. hysteria2.py)
    def link(self, ib, node, user, name): ...     # ссылка для base64-подписки
    def singbox(self, ib, node, user, name): ...  # outbound sing-box
    def clash(self, ib, node, user, name): ...    # proxy для Clash

PROTOCOL = MyProto()
```

После перезапуска панели протокол появится в админке («+» у ноды).

## Установка

Нужен сервер с Ubuntu/Debian и root.

```bash
git clone https://github.com/rezemix/nexalink-panel.git
cd nexalink-panel
bash deploy/install-panel.sh            # домен <ip>.sslip.io и HTTPS через Caddy
# или свой домен:
DOMAIN=panel.example.com PORT=443 bash deploy/install-panel.sh
```

Скрипт выведет адрес админки и пароль. Повторный запуск — обновление: база и пароль сохраняются.
База — `/var/lib/vpnpanel/panel.db`, настройки — `/etc/vpnpanel/env`.

### Настройки (`/etc/vpnpanel/env`)

| Переменная | Назначение |
|---|---|
| `PANEL_PUBLIC_URL` | публичный адрес панели (ссылки подписок, команда установки ноды) |
| `SUB_PUBLIC_URL` | префикс ссылок подписки, если подписки отдаются с отдельного домена |
| `SUB_TITLE`, `SUB_SUPPORT_URL`, `SUB_UPDATE_HOURS` | заголовок подписки, ссылка поддержки, интервал обновления |
| `HWID_STRICT` | требовать идентификатор устройства при запросе подписки |
| `TRUSTED_PROXIES` | IP прокси, которым доверять `X-Real-IP` (например, nginx сайта) |
| `PUBLIC_CORS_ORIGINS` | сайты, которым разрешён `POST /api/public/register` из браузера |
| `APP_NAME`, `APP_PACKAGE`, `APP_SCHEME`, `APP_DOWNLOAD_URL` | своё приложение на странице подписки («Открыть в …») |
| `SITE_STATS_URL` | JSON со статистикой сайта для раздела «Статистика» (необязательно) |

## Новая нода

Админка → «Ноды» → «+ Добавить ноду» → выполнить показанную команду на сервере ноды под root.
Затем добавить протоколы кнопкой «+ Протокол».

## Интеграция с сайтом или ботом

Админка → «Настройки» → создать API-токен. Методы `POST/PATCH /api/users`, `GET /api/users/{uuid}`,
`GET /api/nodes`, `POST /api/users/bulk/reset-traffic` работают в формате RemnaWave, поэтому
сайт или бот, написанный под RemnaWave, подключается без изменений. `activeInternalSquads`
принимается и игнорируется — пользователь получает все ноды.

## Лицензия

GPL-3.0.
