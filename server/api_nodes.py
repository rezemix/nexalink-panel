import asyncio
import json
import secrets
import sqlite3
import time

from fastapi import APIRouter, Depends, HTTPException, Request

import core
import db
import protocols
from auth import hash_password, issue_session, require_admin, require_api, verify_password
from config import PUBLIC_URL

router = APIRouter(prefix="/api")


def _ok(data):
    return {"response": data}


def install_command(node: dict) -> str:
    return f"curl -fsSL {PUBLIC_URL}/install/node.sh | bash -s -- {node['token']}"


def inbound_out(ib: dict) -> dict:
    settings = ib["settings"] if isinstance(ib["settings"], dict) else json.loads(ib["settings"] or "{}")
    proto = protocols.PROTOCOLS.get(ib["protocol"])
    return {
        "uuid": ib["uuid"], "protocol": ib["protocol"],
        "protocolTitle": proto.title if proto else ib["protocol"],
        "tag": ib["tag"], "port": ib["port"], "remark": ib["remark"], "enabled": bool(ib["enabled"]), "hidden": bool(settings.get("hidden")),
        "allowedUsers": settings.get("allowed_users") or [],
        "settings": proto.public_settings(settings) if proto else {},
    }


def node_out(n: dict, with_secrets=False) -> dict:
    online = core.node_online(n)
    uptime = int(time.time() - n["core_started"]) if online and n["core_started"] else None
    expected = core.build_node_config(n)["version"]
    out = {
        "uuid":              n["uuid"],
        "name":              n["name"],
        "address":           n["address"],
        "countryCode":       n["country"],
        "isConnected":       online and not n["disabled"],
        "isNodeOnline":      online,
        "isDisabled":        bool(n["disabled"]),
        "isSynced":          n["applied_version"] == expected,
        "xrayVersion":       n["core_version"],
        "xrayUptime":        str(uptime) if uptime is not None else None,
        "agentVersion":      n["agent_version"],
        "lastSeenAt":        core.iso(core.from_ts(n["last_seen"])) if n["last_seen"] else None,
        "lastStatusMessage": n["last_error"],
        "usersOnline":       n["users_online"] if online else 0,
        "trafficUsedBytes":  n["traffic_bytes"],
        "inbounds":          [inbound_out(ib) for ib in core.load_inbounds(n["uuid"], only_enabled=False)],
        "sysStats":          json.loads(n["sys_stats"]) if n.get("sys_stats") and online else None,
        "trafficTodayBytes": (db.query_one("SELECT bytes FROM traffic_daily WHERE day=? AND node_uuid=?",
                                           (core.now().strftime("%Y-%m-%d"), n["uuid"])) or {}).get("bytes", 0),
    }
    if with_secrets:
        out["installCommand"] = install_command(n)
    return out


def _get_node(node_uuid: str) -> dict:
    n = db.query_one("SELECT * FROM nodes WHERE uuid=?", (node_uuid,))
    if not n:
        raise HTTPException(404, "Node not found")
    return n


# --- вход админа ---

@router.post("/admin/login")
async def login(request: Request):
    body = await request.json()
    a = db.query_one("SELECT * FROM admins WHERE username=?", (body.get("username", ""),))
    if not a or not verify_password(body.get("password", ""), a["password"]):
        await asyncio.sleep(1)
        raise HTTPException(401, "Неверный логин или пароль")
    return _ok({"accessToken": issue_session(a["username"])})


@router.post("/admin/password")
async def change_password(request: Request, who: str = Depends(require_admin)):
    body = await request.json()
    if len(body.get("password", "")) < 8:
        raise HTTPException(400, "Пароль минимум 8 символов")
    db.execute("UPDATE admins SET password=? WHERE username=?", (hash_password(body["password"]), who.split(":", 1)[1]))
    return _ok({"ok": True})


# --- API-токены (для сайта, бота) ---

@router.get("/tokens", dependencies=[Depends(require_admin)])
def list_tokens():
    return _ok([{"token": t["token"], "name": t["name"], "createdAt": t["created_at"]}
                for t in db.query("SELECT * FROM api_tokens ORDER BY created_at")])


@router.post("/tokens", dependencies=[Depends(require_admin)])
async def create_token(request: Request):
    body = await request.json()
    token = "pt_" + secrets.token_urlsafe(32)
    db.execute("INSERT INTO api_tokens(token, name, created_at) VALUES(?,?,?)",
               (token, body.get("name") or "token", core.iso(core.now())))
    return _ok({"token": token})


@router.delete("/tokens/{token}", dependencies=[Depends(require_admin)])
def delete_token(token: str):
    db.execute("DELETE FROM api_tokens WHERE token=?", (token,))
    return _ok({"ok": True})


# --- протоколы ---

@router.get("/protocols", dependencies=[Depends(require_api)])
def list_protocols():
    return _ok([{"id": p.id, "title": p.title, "core": p.core, "transport": p.transport,
                 "defaultPort": p.default_port, "fields": p.fields} for p in protocols.PROTOCOLS.values()])


# --- ноды ---

@router.get("/nodes", dependencies=[Depends(require_api)])
def list_nodes():
    return _ok([node_out(n) for n in db.query("SELECT * FROM nodes ORDER BY sort, created_at")])


@router.post("/nodes", dependencies=[Depends(require_api)])
async def create_node(request: Request):
    body = await request.json()
    name, address = str(body.get("name", "")).strip(), str(body.get("address", "")).strip()
    if not name or not address:
        raise HTTPException(400, "name и address обязательны")
    node = {"uuid": core.new_uuid(), "name": name, "address": address,
            "country": str(body.get("countryCode", "")).upper()[:2],
            "token": "nt_" + secrets.token_urlsafe(32), "created_at": core.iso(core.now())}
    db.execute(f"INSERT INTO nodes({','.join(node)}) VALUES({','.join('?' * len(node))})", list(node.values()))
    # по умолчанию — VLESS Reality на 443
    for p in body.get("protocols", [{"protocol": "vless_reality"}]):
        core.create_inbound(node["uuid"], p["protocol"], p.get("port"), p.get("remark", ""), p.get("settings"))
    return _ok(node_out(_get_node(node["uuid"]), with_secrets=True))


@router.get("/nodes/{node_uuid}", dependencies=[Depends(require_api)])
def get_node(node_uuid: str):
    return _ok(node_out(_get_node(node_uuid), with_secrets=True))


@router.patch("/nodes/{node_uuid}", dependencies=[Depends(require_api)])
async def update_node(node_uuid: str, request: Request):
    _get_node(node_uuid)
    body = await request.json()
    mapping = {"name": "name", "address": "address", "countryCode": "country", "sort": "sort"}
    fields = {col: body[key] for key, col in mapping.items() if key in body}
    if "isDisabled" in body:
        fields["disabled"] = 1 if body["isDisabled"] else 0
    if fields:
        db.execute(f"UPDATE nodes SET {', '.join(f'{k}=?' for k in fields)} WHERE uuid=?",
                   list(fields.values()) + [node_uuid])
    return _ok(node_out(_get_node(node_uuid), with_secrets=True))


@router.post("/nodes/{node_uuid}/actions/{action}", dependencies=[Depends(require_api)])
def node_action(node_uuid: str, action: str):
    _get_node(node_uuid)
    if action in ("enable", "disable"):
        db.execute("UPDATE nodes SET disabled=? WHERE uuid=?", (1 if action == "disable" else 0, node_uuid))
    elif action == "rotate-token":
        db.execute("UPDATE nodes SET token=? WHERE uuid=?", ("nt_" + secrets.token_urlsafe(32), node_uuid))
    else:
        raise HTTPException(404, "Unknown action")
    return _ok(node_out(_get_node(node_uuid), with_secrets=True))


@router.delete("/nodes/{node_uuid}", dependencies=[Depends(require_api)])
def delete_node(node_uuid: str):
    _get_node(node_uuid)
    db.execute("DELETE FROM nodes WHERE uuid=?", (node_uuid,))
    return _ok({"isDeleted": True})


# --- инбаунды (протоколы на ноде) ---

@router.post("/nodes/{node_uuid}/inbounds", dependencies=[Depends(require_api)])
async def add_inbound(node_uuid: str, request: Request):
    _get_node(node_uuid)
    body = await request.json()
    try:
        ib = core.create_inbound(node_uuid, body.get("protocol", ""), body.get("port"),
                                 body.get("remark", ""), body.get("settings"))
    except KeyError as e:
        raise HTTPException(400, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Этот порт на ноде уже занят")
    return _ok(inbound_out(ib))


@router.patch("/inbounds/{ib_uuid}", dependencies=[Depends(require_api)])
async def update_inbound(ib_uuid: str, request: Request):
    ib = db.query_one("SELECT * FROM inbounds WHERE uuid=?", (ib_uuid,))
    if not ib:
        raise HTTPException(404, "Inbound not found")
    body = await request.json()
    settings = json.loads(ib["settings"])
    proto = protocols.get(ib["protocol"])
    editable = {f["key"] for f in proto.fields}
    for k, v in (body.get("settings") or {}).items():
        if k in editable:
            settings[k] = v
    if "hidden" in body:
        settings["hidden"] = bool(body["hidden"])
    if "allowedUsers" in body:
        settings["allowed_users"] = [str(u).strip() for u in (body["allowedUsers"] or []) if str(u).strip()]
    try:
        db.execute("UPDATE inbounds SET port=?, remark=?, enabled=?, settings=? WHERE uuid=?",
                   (int(body.get("port", ib["port"])), body.get("remark", ib["remark"]),
                    1 if body.get("enabled", bool(ib["enabled"])) else 0, json.dumps(settings), ib_uuid))
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Этот порт на ноде уже занят")
    return _ok(inbound_out(db.query_one("SELECT * FROM inbounds WHERE uuid=?", (ib_uuid,))))


@router.delete("/inbounds/{ib_uuid}", dependencies=[Depends(require_api)])
def delete_inbound(ib_uuid: str):
    db.execute("DELETE FROM inbounds WHERE uuid=?", (ib_uuid,))
    return _ok({"isDeleted": True})


# --- настройки панели ---

@router.get("/settings", dependencies=[Depends(require_api)])
def get_settings():
    return _ok({**core.panel_settings(), "adlists": core.ads_status()})


@router.post("/settings/adlists/refresh", dependencies=[Depends(require_admin)])
async def refresh_adlists():
    try:
        return _ok(await asyncio.to_thread(core.refresh_adlists, True))
    except Exception as e:
        raise HTTPException(502, f"Не удалось скачать списки: {e}")


@router.patch("/settings", dependencies=[Depends(require_admin)])
async def update_settings(request: Request):
    body = await request.json()
    for k in core.SETTINGS_DEFAULTS:
        if k in body:
            db.set_setting(k, str(body[k]).strip())
    return _ok(core.panel_settings())


# --- история и аналитика ---

@router.get("/system/history", dependencies=[Depends(require_api)])
def history(days: int = 30):
    days = max(1, min(days, 365))
    start = core.datetime.fromtimestamp(time.time() - (days - 1) * 86400, core.timezone.utc).strftime("%Y-%m-%d")
    rows = db.query("SELECT day, node_uuid, bytes FROM traffic_daily WHERE day>=? ORDER BY day", (start,))
    nodes = {n["uuid"]: n["name"] for n in db.query("SELECT uuid, name FROM nodes ORDER BY sort, created_at")}
    series = {}
    for r in rows:
        series.setdefault(r["day"], {})[r["node_uuid"]] = r["bytes"]
    out = []
    for i in range(days):
        d = core.datetime.fromtimestamp(time.time() - (days - 1 - i) * 86400, core.timezone.utc).strftime("%Y-%m-%d")
        per = series.get(d, {})
        out.append({"day": d, "total": sum(per.values()), "nodes": per})
    top = db.query("SELECT u.uuid, u.username, u.description, SUM(t.bytes) AS bytes FROM user_traffic_daily t "
                   "JOIN users u ON u.uuid=t.user_uuid WHERE t.day>=? GROUP BY t.user_uuid ORDER BY bytes DESC LIMIT 8",
                   (start,))
    return _ok({"days": out, "nodes": [{"uuid": k, "name": v} for k, v in nodes.items()], "topUsers": top})


# --- сводка ---

@router.get("/system/stats", dependencies=[Depends(require_api)])
def system_stats():
    by_status = {r["status"]: r["n"] for r in db.query("SELECT status, COUNT(*) AS n FROM users GROUP BY status")}
    nodes = db.query("SELECT * FROM nodes")
    t = core.now()
    today = t.strftime("%Y-%m-%d")
    soon = core.iso(core.from_ts(time.time() + 3 * 86400))
    online_since = core.iso(core.from_ts(time.time() - 180))
    return _ok({
        "users": {"total": sum(by_status.values()), **{s: by_status.get(s, 0) for s in core.USER_STATUSES}},
        "nodes": {"total": len(nodes), "online": sum(1 for n in nodes if core.node_online(n))},
        "onlineUsers": db.query_one("SELECT COUNT(*) AS n FROM users WHERE online_at>=?", (online_since,))["n"],
        "trafficBytes": sum(n["traffic_bytes"] or 0 for n in nodes),
        "trafficTodayBytes": (db.query_one("SELECT SUM(bytes) AS b FROM traffic_daily WHERE day=?", (today,)) or {}).get("b") or 0,
        "newUsersToday": db.query_one("SELECT COUNT(*) AS n FROM users WHERE created_at>=?", (today,))["n"],
        "expiringSoon": db.query("SELECT uuid, username, description, expire_at FROM users WHERE status='ACTIVE' "
                                 "AND expire_at<=? ORDER BY expire_at LIMIT 8", (soon,)),
    })
