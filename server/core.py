import hashlib
import json
import os
import secrets
import time
import uuid as uuidlib
from datetime import datetime, timezone

import adlists
import db
import protocols
from config import (DATA_DIR, HWID_STRICT, NODE_ONLINE_TIMEOUT, SUB_SUPPORT_URL, SUB_TITLE, SUB_UPDATE_HOURS,
                    XRAY_API_PORT)

USER_STATUSES = ("ACTIVE", "DISABLED", "LIMITED", "EXPIRED")
TRAFFIC_STRATEGIES = ("NO_RESET", "DAY", "WEEK", "MONTH")


# --- время ---

def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def from_ts(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, timezone.utc)


def parse_dt(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --- настройки подписки (из админки; по умолчанию — из env) ---

SETTINGS_DEFAULTS = {
    "sub_title": SUB_TITLE,
    "sub_support_url": SUB_SUPPORT_URL,
    "sub_update_hours": str(SUB_UPDATE_HOURS),
    "hwid_strict": "true" if HWID_STRICT else "false",
    # бесплатная выдача: выключена, пока админ не включит
    "free_registration": "false",
    "free_days": "0",          # 0 — бессрочно
    "free_traffic_gb": "0",    # 0 — без лимита
    "free_per_ip_day": "5",    # новых подписок с одного IP за сутки
    "block_ads": "false",      # отбрасывать рекламные/трекерные домены на всех нодах
    "block_ads_extended": "false",  # + AdGuard DNS filter и RU AdList (см. adlists.py), обновляются раз в сутки
}


def panel_settings() -> dict:
    return {k: db.get_setting(k, v) for k, v in SETTINGS_DEFAULTS.items()}


# --- пользователи ---

def computed_status(user: dict) -> str:
    """ACTIVE/LIMITED/EXPIRED по сроку и трафику; DISABLED выставляется только вручную."""
    if user["status"] == "DISABLED":
        return "DISABLED"
    if parse_dt(user["expire_at"]) <= now():
        return "EXPIRED"
    limit = user["traffic_limit_bytes"] or 0
    if limit > 0 and (user["used_bytes"] or 0) >= limit:
        return "LIMITED"
    return "ACTIVE"


def refresh_user_status(user_uuid: str):
    user = db.query_one("SELECT * FROM users WHERE uuid=?", (user_uuid,))
    if user:
        st = computed_status(user)
        if st != user["status"]:
            db.execute("UPDATE users SET status=? WHERE uuid=?", (st, user_uuid))


def _period_key(strategy: str, dt: datetime) -> str | None:
    if strategy == "DAY":
        return dt.strftime("%Y-%m-%d")
    if strategy == "WEEK":
        y, w, _ = dt.isocalendar()
        return f"{y}-W{w}"
    if strategy == "MONTH":
        return dt.strftime("%Y-%m")
    return None


def periodic_maintenance():
    """Сброс трафика по стратегии и пересчёт статусов. Вызывается раз в ~30 с."""
    t = now()
    for u in db.query("SELECT * FROM users"):
        key = _period_key(u["traffic_strategy"], t)
        if key:
            last = u["last_reset_at"] and _period_key(u["traffic_strategy"], parse_dt(u["last_reset_at"]))
            if last is None:
                db.execute("UPDATE users SET last_reset_at=? WHERE uuid=?", (iso(t), u["uuid"]))
            elif last != key:
                db.execute("UPDATE users SET used_bytes=0, last_reset_at=? WHERE uuid=?", (iso(t), u["uuid"]))
                u["used_bytes"] = 0
        st = computed_status(u)
        if st != u["status"]:
            db.execute("UPDATE users SET status=? WHERE uuid=?", (st, u["uuid"]))


ADS_PATH = f"{DATA_DIR}/{adlists.ASSET_NAME}"
ADS_REFRESH_SEC = 24 * 3600


def refresh_adlists(force: bool = False) -> dict:
    """Скачивает и собирает расширенный список рекламы (раз в сутки или по кнопке).
    Блокирующая операция (~5 МБ сети) — вызывать из потока."""
    updated = db.get_setting("ads_updated")
    if not force and updated and time.time() - float(updated) < ADS_REFRESH_SEC:
        return ads_status()
    data, count, sha = adlists.build()
    tmp = ADS_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, ADS_PATH)
    db.set_setting("ads_sha", sha)
    db.set_setting("ads_count", str(count))
    db.set_setting("ads_updated", str(time.time()))
    return ads_status()


def ads_status() -> dict:
    upd = db.get_setting("ads_updated")
    return {"count": int(db.get_setting("ads_count") or 0), "sha256": db.get_setting("ads_sha"),
            "updatedAt": iso(datetime.fromtimestamp(float(upd), timezone.utc)) if upd else None}


def active_users() -> list[dict]:
    return db.query("SELECT uuid, username, short_uuid FROM users WHERE status='ACTIVE' ORDER BY created_at")


def new_short_uuid() -> str:
    return secrets.token_urlsafe(12).replace("-", "a").replace("_", "b")


def new_uuid() -> str:
    return str(uuidlib.uuid4())


# --- ноды и инбаунды ---

def node_online(node: dict) -> bool:
    return bool(node.get("last_seen")) and time.time() - node["last_seen"] < NODE_ONLINE_TIMEOUT


def load_inbounds(node_uuid: str, only_enabled=True) -> list[dict]:
    sql = "SELECT * FROM inbounds WHERE node_uuid=?" + (" AND enabled=1" if only_enabled else "") + " ORDER BY port"
    rows = db.query(sql, (node_uuid,))
    for r in rows:
        r["settings"] = json.loads(r["settings"] or "{}")
    return rows


def create_inbound(node_uuid: str, protocol_id: str, port: int | None = None,
                   remark: str = "", settings: dict | None = None) -> dict:
    proto = protocols.get(protocol_id)
    port = int(port or proto.default_port)
    tag = f"{protocol_id}-{port}"
    full = proto.generate_settings(settings or {})
    ib_uuid = new_uuid()
    db.execute("INSERT INTO inbounds(uuid, node_uuid, protocol, tag, port, remark, settings) VALUES(?,?,?,?,?,?,?)",
               (ib_uuid, node_uuid, protocol_id, tag, port, remark or "", json.dumps(full)))
    return db.query_one("SELECT * FROM inbounds WHERE uuid=?", (ib_uuid,))


def find_node(ref: str) -> dict | None:
    """Нода по uuid или имени (без учёта регистра)."""
    ref = (ref or "").strip()
    if not ref:
        return None
    return (db.query_one("SELECT * FROM nodes WHERE uuid=?", (ref,))
            or db.query_one("SELECT * FROM nodes WHERE lower(name)=lower(?)", (ref,)))


def exit_inbound(node_uuid: str) -> dict | None:
    """Инбаунд ноды, через который принимается транзитный трафик других нод."""
    for ib in load_inbounds(node_uuid):
        if ib["protocol"] == "vless_reality":
            return ib
    return None


def bridge_uuid(ib_uuid: str) -> str:
    """Служебный пользователь цепочки: детерминированный, хранить не нужно."""
    return str(uuidlib.uuid5(uuidlib.NAMESPACE_URL, "vpnpanel-bridge:" + ib_uuid))


def _bridges_to(node_uuid: str) -> list[dict]:
    """Служебные пользователи для инбаундов других нод, выходящих через эту."""
    out = []
    for ib in db.query("SELECT i.uuid, i.settings FROM inbounds i JOIN nodes n ON n.uuid=i.node_uuid "
                       "WHERE i.enabled=1 AND n.disabled=0 AND i.node_uuid<>?", (node_uuid,)):
        target = find_node(json.loads(ib["settings"] or "{}").get("exit_node", ""))
        if target and target["uuid"] == node_uuid:
            out.append({"uuid": bridge_uuid(ib["uuid"]), "username": "bridge"})
    return out


def build_node_config(node: dict) -> dict:
    """Полное желаемое состояние ноды. Агент сравнивает version и применяет."""
    inbounds = load_inbounds(node["uuid"]) if not node["disabled"] else []
    users = active_users()
    exit_ib = exit_inbound(node["uuid"]) if inbounds else None
    bridges = _bridges_to(node["uuid"]) if exit_ib else []

    xray_inbounds, services, firewall, certificates = [], [], [], []
    outbounds, chain_rules = [], []
    for ib in inbounds:
        proto = protocols.get(ib["protocol"])
        if proto.core == "xray":
            ib_users = users + bridges if exit_ib and ib["uuid"] == exit_ib["uuid"] else users
            inbound = proto.xray_inbound(ib, ib_users)
            domains = proto.certificates(ib)
            if domains:
                # агент выкинет инбаунд, если сертификат ещё не выпущен
                inbound["_requires_cert"] = domains
                certificates += [{"domain": d} for d in domains]
            xray_inbounds.append(inbound)

            target = find_node(ib["settings"].get("exit_node", ""))
            if target and target["uuid"] != node["uuid"] and not target["disabled"]:
                tib = exit_inbound(target["uuid"])
                if tib:
                    tag = f"exit-{ib['tag']}"
                    outbounds.append(protocols.get("vless_reality").xray_outbound(
                        tib, target, bridge_uuid(ib["uuid"]), tag))
                    chain_rules.append({"inboundTag": [ib["tag"]], "outboundTag": tag})
        else:
            services.append(proto.service(ib, node, users))
        for p in (("tcp", "udp") if proto.transport == "both" else (proto.transport,)):
            firewall.append({"port": ib["port"], "proto": p})

    # реклама отсекается до правил цепочек — уже на входной ноде (нужен sniffing у инбаундов)
    s = panel_settings()
    ads_rules, assets = [], []
    if s["block_ads"] == "true":
        ad_domains = ["geosite:category-ads-all"]
        ads_sha = db.get_setting("ads_sha")
        if s["block_ads_extended"] == "true" and ads_sha:
            ad_domains.append(f"ext:{adlists.ASSET_NAME}:{adlists.TAG.lower()}")
            assets.append({"name": adlists.ASSET_NAME, "sha256": ads_sha, "path": f"/api/agent/asset/{adlists.ASSET_NAME}"})
        ads_rules = [{"domain": ad_domains, "outboundTag": "block"}]

    xray = None
    if xray_inbounds:
        xray = {
            "log": {"loglevel": "warning"},
            "api": {"tag": "api", "listen": f"127.0.0.1:{XRAY_API_PORT}",
                    "services": ["HandlerService", "StatsService"]},
            "stats": {},
            "policy": {
                "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True}},
                "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
            },
            "inbounds": xray_inbounds,
            "outbounds": [{"protocol": "freedom", "tag": "direct"},
                          {"protocol": "blackhole", "tag": "block"},
                          *outbounds],
            "routing": {"rules": [{"ip": ["geoip:private"], "outboundTag": "block"},
                                  {"protocol": ["bittorrent"], "outboundTag": "block"},
                                  *ads_rules,
                                  *chain_rules]},
        }

    body = {"xray": xray, "services": services, "firewall": firewall, "certificates": certificates}
    if assets and xray:
        body["assets"] = assets
    body["version"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]
    return body


def apply_traffic(node_uuid: str, traffic: dict):
    """traffic = {user_uuid: [uplink, downlink]} — дельта с прошлого отчёта."""
    total, ts, day = 0, iso(now()), now().strftime("%Y-%m-%d")
    with db.tx() as c:
        for user_uuid, (up, down) in traffic.items():
            delta = int(up) + int(down)
            if delta <= 0:
                continue
            total += delta
            c.execute("UPDATE users SET used_bytes=used_bytes+?, lifetime_used_bytes=lifetime_used_bytes+?, "
                      "online_at=? WHERE uuid=?", (delta, delta, ts, user_uuid))
            c.execute("INSERT INTO user_traffic_daily(day, user_uuid, bytes) VALUES(?,?,?) "
                      "ON CONFLICT(day, user_uuid) DO UPDATE SET bytes=bytes+excluded.bytes", (day, user_uuid, delta))
        if total:
            c.execute("UPDATE nodes SET traffic_bytes=traffic_bytes+? WHERE uuid=?", (total, node_uuid))
            c.execute("INSERT INTO traffic_daily(day, node_uuid, bytes) VALUES(?,?,?) "
                      "ON CONFLICT(day, node_uuid) DO UPDATE SET bytes=bytes+excluded.bytes", (day, node_uuid, total))
    for user_uuid in traffic:
        refresh_user_status(user_uuid)
