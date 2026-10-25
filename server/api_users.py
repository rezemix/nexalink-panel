"""
API пользователей. Пути и формат ответов совместимы с RemnaWave
({"response": ...}), поэтому nexalink-web работает без изменений —
достаточно поменять RW_URL и RW_TOKEN.
"""
import re
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request

import core
import db
from auth import require_api
from config import SUB_PUBLIC_URL

router = APIRouter(prefix="/api", dependencies=[Depends(require_api)])

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,36}$")


def user_out(u: dict) -> dict:
    return {
        "uuid":                     u["uuid"],
        "shortUuid":                u["short_uuid"],
        "username":                 u["username"],
        "status":                   u["status"],
        "expireAt":                 u["expire_at"],
        "trafficLimitBytes":        u["traffic_limit_bytes"],
        "trafficLimitStrategy":     u["traffic_strategy"],
        "usedTrafficBytes":         u["used_bytes"],
        "lifetimeUsedTrafficBytes": u["lifetime_used_bytes"],
        "userTraffic": {
            "usedTrafficBytes":         u["used_bytes"],
            "lifetimeUsedTrafficBytes": u["lifetime_used_bytes"],
            "onlineAt":                 u["online_at"],
        },
        "hwidDeviceLimit":          u["hwid_limit"],
        "description":              u["description"],
        "subscriptionUrl":          f"{SUB_PUBLIC_URL}/{u['short_uuid']}",
        "onlineAt":                 u["online_at"],
        "subLastOpenedAt":          u["sub_updated_at"],
        "lastTrafficResetAt":       u["last_reset_at"],
        "createdAt":                u["created_at"],
        "activeInternalSquads":     [],
        "isOnline":                 bool(u["online_at"]) and core.parse_dt(u["online_at"]).timestamp() > core.now().timestamp() - 180,
    }


def _get_user(user_uuid: str) -> dict:
    u = db.query_one("SELECT * FROM users WHERE uuid=?", (user_uuid,))
    if not u:
        raise HTTPException(404, "User not found")
    return u


def _ok(data, status=200):
    return {"response": data}


def _validate_common(body: dict, out: dict):
    """Общие поля POST/PATCH → колонки таблицы users."""
    if "expireAt" in body:
        try:
            out["expire_at"] = core.iso(core.parse_dt(body["expireAt"]))
        except Exception:
            raise HTTPException(400, "Invalid expireAt")
    if "trafficLimitBytes" in body:
        out["traffic_limit_bytes"] = max(0, int(body["trafficLimitBytes"] or 0))
    if "trafficLimitStrategy" in body:
        if body["trafficLimitStrategy"] not in core.TRAFFIC_STRATEGIES:
            raise HTTPException(400, "Invalid trafficLimitStrategy")
        out["traffic_strategy"] = body["trafficLimitStrategy"]
    if "hwidDeviceLimit" in body:
        v = body["hwidDeviceLimit"]
        out["hwid_limit"] = None if v in (None, "") else max(0, int(v))
    if "description" in body:
        out["description"] = str(body["description"] or "")
    if "status" in body:
        if body["status"] not in core.USER_STATUSES:
            raise HTTPException(400, "Invalid status")
        # LIMITED/EXPIRED — вычисляемые, извне имеет смысл только ACTIVE или DISABLED
        out["status"] = "DISABLED" if body["status"] == "DISABLED" else "ACTIVE"


@router.get("/users")
def list_users(start: int = 0, size: int = 50, search: str = "", status: str = ""):
    where, args = [], []
    if search:
        where.append("(username LIKE ? OR uuid LIKE ? OR short_uuid LIKE ? OR description LIKE ?)")
        args += [f"%{search}%"] * 4
    if status == "ONLINE":
        where.append("online_at>=?")
        args.append(core.iso(core.from_ts(core.now().timestamp() - 180)))
    elif status:
        where.append("status=?")
        args.append(status)
    w = (" WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one(f"SELECT COUNT(*) AS n FROM users{w}", args)["n"]
    rows = db.query(f"SELECT * FROM users{w} ORDER BY created_at DESC LIMIT ? OFFSET ?", args + [size, start])
    return _ok({"users": [user_out(u) for u in rows], "total": total})


@router.post("/users", status_code=201)
async def create_user(request: Request):
    body = await request.json()
    username = str(body.get("username", ""))
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "username: 3-36 символов, латиница, цифры, _ и -")
    if "expireAt" not in body:
        raise HTTPException(400, "expireAt is required")
    fields = {}
    _validate_common(body, fields)
    t = core.iso(core.now())
    row = {
        "uuid":                body.get("uuid") or core.new_uuid(),
        "short_uuid":          body.get("shortUuid") or core.new_short_uuid(),
        "username":            username,
        "status":              fields.get("status", "ACTIVE"),
        "expire_at":           fields["expire_at"],
        "traffic_limit_bytes": fields.get("traffic_limit_bytes", 0),
        "traffic_strategy":    fields.get("traffic_strategy", "NO_RESET"),
        "hwid_limit":          fields.get("hwid_limit"),
        "description":         fields.get("description", ""),
        "used_bytes":          0,
        "lifetime_used_bytes": 0,
        "last_reset_at":       t,
        "created_at":          t,
    }
    try:
        db.execute(f"INSERT INTO users({','.join(row)}) VALUES({','.join('?' * len(row))})", list(row.values()))
    except sqlite3.IntegrityError:
        raise HTTPException(400, "User with this username/uuid already exists")
    core.refresh_user_status(row["uuid"])
    return _ok(user_out(_get_user(row["uuid"])))


@router.patch("/users")
async def update_user(request: Request):
    body = await request.json()
    if body.get("uuid"):
        u = _get_user(body["uuid"])
    elif body.get("username"):
        u = db.query_one("SELECT * FROM users WHERE username=?", (body["username"],))
        if not u:
            raise HTTPException(404, "User not found")
    else:
        raise HTTPException(400, "uuid or username is required")
    fields = {}
    _validate_common(body, fields)
    if fields:
        sets = ", ".join(f"{k}=?" for k in fields)
        db.execute(f"UPDATE users SET {sets} WHERE uuid=?", list(fields.values()) + [u["uuid"]])
    core.refresh_user_status(u["uuid"])
    return _ok(user_out(_get_user(u["uuid"])))


@router.get("/users/by-username/{username}")
def get_by_username(username: str):
    u = db.query_one("SELECT * FROM users WHERE username=?", (username,))
    if not u:
        raise HTTPException(404, "User not found")
    return _ok(user_out(u))


@router.get("/users/by-short-uuid/{short_uuid}")
def get_by_short_uuid(short_uuid: str):
    u = db.query_one("SELECT * FROM users WHERE short_uuid=?", (short_uuid,))
    if not u:
        raise HTTPException(404, "User not found")
    return _ok(user_out(u))


@router.get("/users/{user_uuid}")
def get_user(user_uuid: str):
    return _ok(user_out(_get_user(user_uuid)))


@router.delete("/users/{user_uuid}")
def delete_user(user_uuid: str):
    _get_user(user_uuid)
    db.execute("DELETE FROM users WHERE uuid=?", (user_uuid,))
    return _ok({"isDeleted": True})


def _reset_traffic(uuids: list[str]):
    t = core.iso(core.now())
    for uid in uuids:
        db.execute("UPDATE users SET used_bytes=0, last_reset_at=? WHERE uuid=?", (t, uid))
        core.refresh_user_status(uid)


@router.post("/users/bulk/reset-traffic")
async def bulk_reset_traffic(request: Request):
    body = await request.json()
    _reset_traffic(body.get("uuids") or [])
    return _ok({"affectedRows": len(body.get("uuids") or [])})


@router.post("/users/{user_uuid}/actions/{action}")
def user_action(user_uuid: str, action: str, days: int = 30):
    u = _get_user(user_uuid)
    if action == "extend":
        # от текущей даты окончания, а если подписка уже истекла — от сегодня
        base = max(core.parse_dt(u["expire_at"]), core.now())
        new = core.iso(core.from_ts(base.timestamp() + days * 86400))
        db.execute("UPDATE users SET expire_at=?, status=CASE WHEN status='DISABLED' THEN status ELSE 'ACTIVE' END "
                   "WHERE uuid=?", (new, user_uuid))
        core.refresh_user_status(user_uuid)
    elif action == "enable":
        db.execute("UPDATE users SET status='ACTIVE' WHERE uuid=?", (user_uuid,))
        core.refresh_user_status(user_uuid)
    elif action == "disable":
        db.execute("UPDATE users SET status='DISABLED' WHERE uuid=?", (user_uuid,))
    elif action == "reset-traffic":
        _reset_traffic([user_uuid])
    elif action == "revoke":
        # новая ссылка подписки; старая перестаёт работать
        db.execute("UPDATE users SET short_uuid=? WHERE uuid=?", (core.new_short_uuid(), user_uuid))
        db.execute("DELETE FROM hwid_devices WHERE user_uuid=?", (user_uuid,))
    else:
        raise HTTPException(404, "Unknown action")
    return _ok(user_out(_get_user(user_uuid)))


# --- HWID-устройства (пути как в RemnaWave) ---

@router.get("/hwid/devices/{user_uuid}")
def list_devices(user_uuid: str):
    rows = db.query("SELECT * FROM hwid_devices WHERE user_uuid=? ORDER BY created_at", (user_uuid,))
    devices = [{"hwid": r["hwid"], "userUuid": r["user_uuid"], "platform": r["platform"],
                "osVersion": r["os_version"], "deviceModel": r["model"], "userAgent": r["user_agent"],
                "createdAt": r["created_at"]} for r in rows]
    return _ok({"devices": devices, "total": len(devices)})


@router.post("/hwid/devices/delete")
async def delete_device(request: Request):
    body = await request.json()
    db.execute("DELETE FROM hwid_devices WHERE user_uuid=? AND hwid=?", (body.get("userUuid"), body.get("hwid")))
    return list_devices(body.get("userUuid"))
