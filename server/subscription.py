import base64
import html
import json
from urllib.parse import quote

import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

import core
import db
import protocols
from config import APP_DOWNLOAD_URL, APP_NAME, APP_PACKAGE, APP_SCHEME, SUB_PUBLIC_URL

router = APIRouter()

FORMATS = ("base64", "plain", "singbox", "clash", "json")


def flag(country: str) -> str:
    c = (country or "").upper()
    if len(c) != 2 or not c.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in c) + " "


def _entries(user: dict):
    """(protocol, inbound, node, name) для всех включённых нод и инбаундов."""
    out = []
    for node in db.query("SELECT * FROM nodes WHERE disabled=0 ORDER BY sort, created_at"):
        inbounds = core.load_inbounds(node["uuid"])
        for ib in inbounds:
            proto = protocols.PROTOCOLS.get(ib["protocol"])
            # hidden — инбаунд работает (например, как мост для цепочки нод), но клиентам не выдаётся
            if not proto or ib["settings"].get("hidden"):
                continue
            # allowed_users — инбаунд выдаётся только этим пользователям (тест, платный трафик)
            allowed = ib["settings"].get("allowed_users") or []
            if allowed and user["username"] not in allowed:
                continue
            name = ib["remark"] or f"{flag(node['country'])}{node['name']}"
            if not ib["remark"] and len(inbounds) > 1:
                name += f" · {proto.title}"
            out.append((proto, ib, node, name))
    return out


def _stub_entries(reason: str):
    """Неактивная подписка: одна нерабочая «нода», в имени которой написана причина."""
    proto = protocols.get("vless_reality")
    ib = {"port": 1, "settings": {"sni": "example.com", "fingerprint": "chrome", "flow": "xtls-rprx-vision",
                                  "public_key": "A" * 43, "short_id": "00"}}
    node = {"address": "0.0.0.0", "country": ""}
    return [(proto, ib, node, reason)]


def _detect_format(request: Request, fmt: str | None) -> str:
    fmt = fmt or request.query_params.get("format")
    if fmt:
        if fmt not in FORMATS:
            raise HTTPException(400, f"format: {', '.join(FORMATS)}")
        return fmt
    ua = request.headers.get("user-agent", "").lower()
    # Hiddify пишет в UA «like ClashMeta v2ray sing-box», но лучше всего разбирает обычные ссылки
    if ua.startswith(("hiddify", "happ", "v2rayng", "v2raytun", "streisand", "nekobox", "v2box")):
        return "base64"
    if any(k in ua for k in ("sing-box", "sfa/", "sfi/", "sfm/", "sft/")):
        return "singbox"
    if any(k in ua for k in ("clash", "mihomo", "stash")):
        return "clash"
    if ua.startswith("mozilla") and "text/html" in request.headers.get("accept", ""):
        return "html"
    return "base64"


def _check_hwid(user: dict, request: Request) -> str | None:
    """Регистрирует устройство. Возвращает причину отказа или None."""
    limit = user["hwid_limit"]
    hwid = request.headers.get("x-hwid", "").strip()[:128]
    if not limit:
        return None
    if not hwid:
        return "⛔ Обновите приложение (нет HWID)" if core.panel_settings()["hwid_strict"] == "true" else None
    known = db.query_one("SELECT 1 FROM hwid_devices WHERE user_uuid=? AND hwid=?", (user["uuid"], hwid))
    if known:
        return None
    count = db.query_one("SELECT COUNT(*) AS n FROM hwid_devices WHERE user_uuid=?", (user["uuid"],))["n"]
    if count >= limit:
        return f"⛔ Лимит устройств: {limit}"
    h = request.headers
    db.execute("INSERT OR IGNORE INTO hwid_devices(user_uuid, hwid, platform, os_version, model, user_agent, created_at) "
               "VALUES(?,?,?,?,?,?,?)",
               (user["uuid"], hwid, h.get("x-device-os"), h.get("x-ver-os"), h.get("x-device-model"),
                h.get("user-agent", "")[:256], core.iso(core.now())))
    return None


def _headers(user: dict) -> dict:
    st = core.panel_settings()
    title = st["sub_title"] or "VPN"
    expire = int(core.parse_dt(user["expire_at"]).timestamp())
    hdr = {
        "subscription-userinfo": f"upload=0; download={user['used_bytes']}; "
                                 f"total={user['traffic_limit_bytes']}; expire={expire}",
        "profile-title": "base64:" + base64.b64encode(title.encode()).decode(),
        "profile-update-interval": str(st["sub_update_hours"] or 1),
        "profile-web-page-url": f"{SUB_PUBLIC_URL}/{user['short_uuid']}",
        "content-disposition": f"attachment; filename*=UTF-8''{quote(title)}",
    }
    if st["sub_support_url"]:
        hdr["support-url"] = st["sub_support_url"]
    return hdr


def _singbox_config(outbounds: list[dict]) -> dict:
    tags = [o["tag"] for o in outbounds]
    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [{"tag": "remote", "address": "tls://1.1.1.1", "detour": "proxy"},
                        {"tag": "local", "address": "local", "detour": "direct"}],
            "rules": [{"outbound": "any", "server": "local"}],
            "final": "remote",
        },
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                      "auto_route": True, "strict_route": True, "stack": "mixed"},
                     {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
        "outbounds": [{"type": "selector", "tag": "proxy", "outbounds": ["auto"] + tags, "default": "auto"},
                      {"type": "urltest", "tag": "auto", "outbounds": tags,
                       "url": "https://www.gstatic.com/generate_204", "interval": "5m"},
                      *outbounds,
                      {"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{"action": "sniff"},
                      {"protocol": "dns", "action": "hijack-dns"},
                      {"ip_is_private": True, "outbound": "direct"}],
            "final": "proxy",
            "auto_detect_interface": True,
        },
    }


def _clash_config(proxies: list[dict]) -> dict:
    names = [p["name"] for p in proxies]
    return {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "proxies": names,
             "url": "https://www.gstatic.com/generate_204", "interval": 300},
        ],
        "rules": ["GEOIP,private,DIRECT,no-resolve", "MATCH,PROXY"],
    }


def _user_info(user: dict) -> dict:
    return {"username": user["username"], "status": user["status"], "expireAt": user["expire_at"],
            "usedTrafficBytes": user["used_bytes"], "trafficLimitBytes": user["traffic_limit_bytes"],
            "hwidDeviceLimit": user["hwid_limit"], "subscriptionUrl": f"{SUB_PUBLIC_URL}/{user['short_uuid']}"}


def _html_page(user: dict, links: list[str]) -> str:
    SUB_TITLE = core.panel_settings()["sub_title"] or "VPN"
    sub = f"{SUB_PUBLIC_URL}/{user['short_uuid']}"
    used = user["used_bytes"] / 1024 ** 3
    limit = f"{user['traffic_limit_bytes'] / 1024 ** 3:.0f} ГБ" if user["traffic_limit_bytes"] else "∞"
    apps = [("Happ", f"happ://add/{sub}"), ("v2RayTun", f"v2raytun://import/{sub}"),
            ("Hiddify", f"hiddify://import/{sub}#{SUB_TITLE}"),
            ("sing-box", f"sing-box://import-remote-profile?url={sub}#{SUB_TITLE}")]
    buttons = "".join(f'<a class="btn alt" href="{html.escape(u)}">{n}</a>' for n, u in apps)
    # Своё приложение: импортирует подписку и само входит в аккаунт. На Android —
    # intent:// с переходом на скачивание APK, если приложение не установлено.
    app_link = f"{APP_SCHEME}://install-sub?url={quote(sub, safe='')}"
    app_intent = (f"intent://install-sub?url={quote(sub, safe='')}#Intent;scheme={APP_SCHEME};"
                  f"package={APP_PACKAGE};S.browser_fallback_url={quote(APP_DOWNLOAD_URL, safe='')};end")
    status_text = {"ACTIVE": "активна", "EXPIRED": "истекла", "LIMITED": "трафик закончился",
                   "DISABLED": "отключена"}.get(core.computed_status(user), user["status"])
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(SUB_TITLE)}</title>
<style>
:root{{--bg:#f6f7f9;--fg:#15171a;--muted:#667085;--card:#fff;--line:#e4e7ec;--acc:#2563eb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1115;--fg:#e8eaed;--muted:#98a2b3;--card:#171a21;--line:#262b35;--acc:#60a5fa}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}}
.wrap{{max-width:640px;margin:0 auto;padding:24px 16px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}}
.muted{{color:var(--muted)}} code{{word-break:break-all;font-size:12px}} ul{{padding-left:18px}}
.btn{{display:inline-block;margin:4px 6px 4px 0;padding:8px 14px;border-radius:8px;background:var(--acc);color:#fff;text-decoration:none}}
.btn.alt{{background:transparent;color:var(--acc);border:1px solid var(--line)}}
.btn.main{{display:block;margin:12px 0 8px;padding:14px;text-align:center;font-size:17px;font-weight:600}}
.muted a{{color:var(--acc)}}
#qr{{display:flex;justify-content:center;padding:8px;background:#fff;border-radius:8px;width:fit-content;margin:auto}}
</style></head><body><div class="wrap">
<h2 style="margin-bottom:4px">{html.escape(SUB_TITLE)}</h2>
<div class="muted">Подписка {status_text} · до {user['expire_at'][:10]} · трафик {used:.2f} ГБ / {limit}</div>
<a class="btn main" id="open-app" href="{html.escape(app_link)}">Открыть в {html.escape(APP_NAME)}</a>
<div class="muted" style="margin-bottom:16px">Приложение само добавит серверы и войдёт в аккаунт.
Нет приложения? <a href="{html.escape(APP_DOWNLOAD_URL)}">Скачать для Android</a></div>
<div class="card"><div style="margin-bottom:8px">iPhone и другие приложения:</div>{buttons}
<p class="muted">Или скопируйте ссылку подписки:</p><code>{html.escape(sub)}</code>
<div id="qr" style="margin-top:12px"></div></div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>try{{new QRCode(document.getElementById("qr"),{{text:{json.dumps(sub)},width:200,height:200}})}}catch(e){{}}
if(/android/i.test(navigator.userAgent))document.getElementById("open-app").href={json.dumps(app_intent)};</script>
</body></html>"""


@router.get("/sub/{short_uuid}")
@router.get("/sub/{short_uuid}/{fmt}")
def subscription(short_uuid: str, request: Request, fmt: str | None = None):
    user = db.query_one("SELECT * FROM users WHERE short_uuid=?", (short_uuid,))
    if not user:
        raise HTTPException(404, "Not found")
    fmt = _detect_format(request, fmt)

    status = core.computed_status(user)
    reason = None
    if status != "ACTIVE":
        reason = {"EXPIRED": "⛔ Подписка истекла", "LIMITED": "⛔ Трафик закончился",
                  "DISABLED": "⛔ Подписка отключена"}[status]
    elif fmt != "html":
        reason = _check_hwid(user, request)
    db.execute("UPDATE users SET sub_updated_at=? WHERE uuid=?", (core.iso(core.now()), user["uuid"]))
    # статистика: кто и сколько раз за день обновлял подписку (открывал приложение)
    db.execute("INSERT INTO sub_fetch_daily(day, user_uuid, n) VALUES(?,?,1) "
               "ON CONFLICT(day, user_uuid) DO UPDATE SET n=n+1", (core.now().strftime("%Y-%m-%d"), user["uuid"]))

    entries = _stub_entries(reason) if reason else _entries(user)
    headers = _headers(user)

    if fmt == "html":
        links = [p.link(ib, n, user, name) for p, ib, n, name in entries if not reason]
        return HTMLResponse(_html_page(user, [l for l in links if l]))

    if fmt == "json":
        servers = []
        for p, ib, n, name in entries:
            servers.append({"name": name, "country": n.get("country", ""), "protocol": p.id,
                            "address": n["address"], "port": ib["port"],
                            "link": p.link(ib, n, user, name),
                            "singbox": p.singbox(ib, n, user, name),
                            "clash": p.clash(ib, n, user, name)})
        return JSONResponse({"user": _user_info(user), "active": reason is None, "message": reason,
                             "servers": servers}, headers=headers)

    if fmt == "singbox":
        outbounds = [o for p, ib, n, name in entries if (o := p.singbox(ib, n, user, name))]
        return JSONResponse(_singbox_config(outbounds), headers=headers)

    if fmt == "clash":
        proxies = [c for p, ib, n, name in entries if (c := p.clash(ib, n, user, name))]
        text = yaml.safe_dump(_clash_config(proxies), allow_unicode=True, sort_keys=False)
        return Response(text, media_type="text/yaml; charset=utf-8", headers=headers)

    links = "\n".join(l for p, ib, n, name in entries if (l := p.link(ib, n, user, name)))
    if fmt == "plain":
        return PlainTextResponse(links, headers=headers)
    return PlainTextResponse(base64.b64encode(links.encode()).decode(), headers=headers)
