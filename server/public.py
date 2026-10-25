"""
Бесплатная публичная выдача подписок — без регистрации, email и паролей.

POST /api/public/register  {"hwid": "...", "source": "app|web"}  (hwid можно и заголовком x-hwid)
→ {"subscriptionUrl", "shortUuid", "expireAt", "trafficLimitBytes", "existing"}

Устройство с тем же hwid всегда получает ту же подписку. С одного IP — не больше
free_per_ip_day новых подписок в сутки. Включается в настройках панели (free_registration).
"""
import hashlib
import os
import secrets
from datetime import timedelta

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse, Response

import core
import db
from config import PUBLIC_CORS_ORIGINS, SUB_PUBLIC_URL, TRUSTED_PROXIES

router = APIRouter()


def _client_ip(request: Request) -> str:
    ip = request.client.host if request.client else ""
    # запрос пришёл через наш же прокси (sub-домен на другом сервере) — верим его X-Real-IP
    if ip in TRUSTED_PROXIES:
        ip = request.headers.get("x-real-ip", "").strip() or ip
    return ip


def _cors(request: Request) -> dict:
    origin = request.headers.get("origin", "")
    if origin in PUBLIC_CORS_ORIGINS:
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, X-Hwid"}
    return {}


def _out(user: dict, existing: bool) -> dict:
    return {"subscriptionUrl": f"{SUB_PUBLIC_URL}/{user['short_uuid']}", "shortUuid": user["short_uuid"],
            "expireAt": user["expire_at"], "trafficLimitBytes": user["traffic_limit_bytes"], "existing": existing}


@router.get("/api/public/nexalink-ads.dat", include_in_schema=False)
def public_adlist():
    """Расширенный список рекламы для приложений (тот же, что на нодах). sha256 — в заголовке."""
    sha = db.get_setting("ads_sha")
    if not sha or not os.path.exists(core.ADS_PATH):
        return Response(status_code=404)
    return FileResponse(core.ADS_PATH, media_type="application/octet-stream",
                        headers={"X-Content-SHA256": sha, "ETag": f'"{sha}"', "Cache-Control": "public, max-age=3600"})


@router.options("/api/public/register", include_in_schema=False)
def register_preflight(request: Request):
    return Response(status_code=204, headers=_cors(request))


@router.post("/api/public/register")
async def register(request: Request):
    headers = _cors(request)
    s = core.panel_settings()
    if s["free_registration"] != "true":
        return JSONResponse({"detail": "Бесплатная выдача отключена"}, status_code=403, headers=headers)
    try:
        body = await request.json()
    except Exception:
        body = {}
    raw_hwid = str(body.get("hwid") or request.headers.get("x-hwid", "")).strip()[:128]
    # храним не сам идентификатор устройства, а его хеш
    hwid = hashlib.sha256(raw_hwid.encode()).hexdigest() if raw_hwid else None
    source = str(body.get("source", "web"))[:16]
    ip = _client_ip(request)
    now = core.now()

    with db.tx() as c:
        if hwid:
            row = c.execute("SELECT u.* FROM free_signups f JOIN users u ON u.uuid = f.user_uuid "
                            "WHERE f.hwid = ? ORDER BY f.created_at DESC LIMIT 1", (hwid,)).fetchone()
            if row:
                return JSONResponse(_out(dict(row), True), headers=headers)

        since = core.iso(now - timedelta(days=1))
        count = c.execute("SELECT COUNT(*) FROM free_signups WHERE ip = ? AND created_at > ?", (ip, since)).fetchone()[0]
        if count >= int(s["free_per_ip_day"] or 0):
            return JSONResponse({"detail": "Слишком много новых подписок с вашего адреса, попробуйте завтра"},
                                status_code=429, headers=headers)

        days = int(s["free_days"] or 0)
        expire = now + timedelta(days=days) if days > 0 else core.parse_dt("2099-12-31T23:59:59Z")
        t = core.iso(now)
        user = {
            "uuid": core.new_uuid(), "short_uuid": core.new_short_uuid(),
            "username": "free_" + secrets.token_hex(5), "status": "ACTIVE", "expire_at": core.iso(expire),
            "traffic_limit_bytes": int(float(s["free_traffic_gb"] or 0) * 1024 ** 3),
            "traffic_strategy": "MONTH" if float(s["free_traffic_gb"] or 0) > 0 else "NO_RESET",
            "hwid_limit": None, "description": f"free ({source})", "used_bytes": 0, "lifetime_used_bytes": 0,
            "last_reset_at": t, "created_at": t,
        }
        c.execute(f"INSERT INTO users({','.join(user)}) VALUES({','.join('?' * len(user))})", list(user.values()))
        c.execute("INSERT INTO free_signups(user_uuid, ip, hwid, source, created_at) VALUES(?,?,?,?,?)",
                  (user["uuid"], ip, hwid, source, t))
    return JSONResponse(_out(user, False), status_code=201, headers=headers)
