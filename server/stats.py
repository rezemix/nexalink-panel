"""Статистика использования для админки: активность, новые пользователи, онлайн, источники."""
import json
import os
import time
import urllib.request
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

import core
import db
from auth import require_api

router = APIRouter(prefix="/api")

ONLINE_WINDOW = 180          # «онлайн» = был трафик за последние 3 минуты (как в сводке)
SAMPLE_EVERY = 300           # снимок онлайна раз в 5 минут
SAMPLES_KEEP_DAYS = 120
IMPORTED_PREFIX = "nexalink user_id="   # перенесены со старого сайта — не «новые»

SOURCES = [("app", "Приложение"), ("web", "Сайт"), ("extra", "Другое устройство"), ("manual", "Вручную")]
PLATFORMS = {"app": "Android", "web-android": "Android", "web-ios": "iPhone", "web-desktop": "Компьютер",
             "app-extra": "Другое устройство"}


# JSON со статистикой сайта (посетители, нажатия «Скачать»): {"days": {"YYYY-MM-DD": {...}}}; пусто — не показываем
SITE_STATS_URL = os.getenv("SITE_STATS_URL", "")
_site_cache = {"at": 0.0, "days": {}}


def _site_days() -> dict:
    """Посетители сайта и скачивания APK по дням (собирает site-stats.py на сервере сайта). Кэш 10 мин."""
    if not SITE_STATS_URL:
        return {}
    if time.time() - _site_cache["at"] > 600:
        try:
            with urllib.request.urlopen(SITE_STATS_URL, timeout=5) as r:
                _site_cache["days"] = json.load(r).get("days") or {}
        except Exception as e:
            print(f"[stats] site stats: {e}", flush=True)
        _site_cache["at"] = time.time()
    return _site_cache["days"]


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


def _source_key(src: str | None) -> str:
    if not src:
        return "manual"
    if src == "app-extra":
        return "extra"
    if src.startswith("web"):
        return "web"
    return "app" if src == "app" else "manual"


def sample_online():
    """Вызывается раз в SAMPLE_EVERY секунд из app.py."""
    t = int(time.time())
    since = core.iso(core.from_ts(t - ONLINE_WINDOW))
    n = db.query_one("SELECT COUNT(*) AS n FROM users WHERE online_at>=?", (since,))["n"]
    db.execute("INSERT OR REPLACE INTO online_samples(ts, n) VALUES(?,?)", (t - t % SAMPLE_EVERY, n))
    db.execute("DELETE FROM online_samples WHERE ts<?", (t - SAMPLES_KEEP_DAYS * 86400,))


@router.get("/system/analytics", dependencies=[Depends(require_api)])
def analytics(days: int = 30, online_hours: int = 24):
    days = max(7, min(days, 365))
    online_hours = max(6, min(online_hours, 24 * 30))
    t = time.time()
    day_list = [_day(t - (days - 1 - i) * 86400) for i in range(days)]
    start, today = day_list[0], day_list[-1]
    prev_start = _day(t - (2 * days - 1) * 86400)

    users = db.query("SELECT u.uuid, u.created_at, u.description, f.source FROM users u "
                     "LEFT JOIN free_signups f ON f.user_uuid=u.uuid")
    new_by_day = {d: {k: 0 for k, _ in SOURCES} for d in day_list}
    src_total = {k: 0 for k, _ in SOURCES}
    platforms: dict[str, int] = {}
    new_period = new_prev = new_today = 0
    for u in users:
        if (u["description"] or "").startswith(IMPORTED_PREFIX):
            continue
        d = (u["created_at"] or "")[:10]
        key = _source_key(u["source"])
        if d >= start:
            new_period += 1
            new_by_day[d][key] += 1
            src_total[key] += 1
            name = PLATFORMS.get(u["source"] or "", "Не указано (вручную)")
            platforms[name] = platforms.get(name, 0) + 1
            if d == today:
                new_today += 1
        elif d >= prev_start:
            new_prev += 1

    active = {r["day"]: r["n"] for r in db.query(
        "SELECT day, COUNT(*) AS n FROM user_traffic_daily WHERE day>=? AND bytes>0 GROUP BY day", (start,))}
    opened = {r["day"]: r["n"] for r in db.query(
        "SELECT day, COUNT(*) AS n FROM sub_fetch_daily WHERE day>=? GROUP BY day", (start,))}
    traffic = {r["day"]: r["b"] for r in db.query(
        "SELECT day, SUM(bytes) AS b FROM traffic_daily WHERE day>=? GROUP BY day", (start,))}

    def distinct_active(since_day):
        return db.query_one("SELECT COUNT(DISTINCT user_uuid) AS n FROM user_traffic_daily "
                            "WHERE day>=? AND bytes>0", (since_day,))["n"]

    wau, mau = distinct_active(_day(t - 6 * 86400)), distinct_active(_day(t - 29 * 86400))
    period_active = distinct_active(start)
    period_traffic = sum(traffic.values())

    # удержание: из пришедших 7–60 дней назад — сколько пользовались VPN за последние 7 дней
    cohort = db.query_one(
        "SELECT COUNT(*) AS total, SUM(EXISTS(SELECT 1 FROM user_traffic_daily t WHERE t.user_uuid=u.uuid "
        "AND t.day>=? AND t.bytes>0)) AS kept FROM users u WHERE u.created_at<? AND u.created_at>=? "
        "AND COALESCE(u.description,'') NOT LIKE ?",
        (_day(t - 6 * 86400), core.iso(core.from_ts(t - 7 * 86400)), core.iso(core.from_ts(t - 60 * 86400)),
         IMPORTED_PREFIX + "%"))
    # «никогда не подключались»: пришли за период, но трафика не было ни разу
    never = db.query_one(
        "SELECT COUNT(*) AS n FROM users u WHERE u.created_at>=? AND u.lifetime_used_bytes=0 "
        "AND COALESCE(u.description,'') NOT LIKE ?", (start, IMPORTED_PREFIX + "%"))["n"]

    since = int(t - online_hours * 3600)
    samples = db.query("SELECT ts, n FROM online_samples WHERE ts>=? ORDER BY ts", (since,))
    peak = db.query_one("SELECT ts, n FROM online_samples WHERE ts>=? ORDER BY n DESC, ts DESC LIMIT 1",
                        (int(t - 86400),))
    online_now = db.query_one("SELECT COUNT(*) AS n FROM users WHERE online_at>=?",
                              (core.iso(core.from_ts(t - ONLINE_WINDOW)),))["n"]

    site = _site_days()
    sd = lambda d, k: (site.get(d) or {}).get(k, 0)
    CLICKS = ("click_android", "click_ios", "click_windows", "click_mac")
    clicks = lambda d: sum(sd(d, k) for k in CLICKS)
    site_visitors = sum(sd(d, "visitors") for d in day_list)
    site_dl = sum(clicks(d) for d in day_list)
    return {"response": {
        "days": [{"day": d, "active": active.get(d, 0), "opened": opened.get(d, 0), "traffic": traffic.get(d, 0),
                  "new": new_by_day[d], "siteVisitors": sd(d, "visitors"), "clickAndroid": sd(d, "click_android"),
                  "clickIos": sd(d, "click_ios"), "clickWindows": sd(d, "click_windows"), "clickMac": sd(d, "click_mac"),
                  "dlUpdate": sd(d, "dl_update"), "appChecks": sd(d, "app_checks")} for d in day_list],
        "site": {"available": bool(site), "visitorsPeriod": site_visitors, "visitorsToday": sd(today, "visitors"),
                 "downloadsPeriod": site_dl, "downloadsToday": clicks(today),
                 "updatesPeriod": sum(sd(d, "dl_update") for d in day_list),
                 "appChecksToday": sd(today, "app_checks"),
                 "conversion": round(site_dl / site_visitors * 100, 1) if site_visitors else None},
        "sources": [{"key": k, "name": n, "count": src_total[k]} for k, n in SOURCES],
        "platforms": sorted(({"name": k, "count": v} for k, v in platforms.items()), key=lambda x: -x["count"]),
        "online": samples,
        "kpi": {
            "totalUsers": len(users), "newPeriod": new_period, "newPrev": new_prev, "newToday": new_today,
            "dau": active.get(today, 0), "wau": wau, "mau": mau, "openedToday": opened.get(today, 0),
            "onlineNow": online_now, "onlinePeak24h": peak["n"] if peak else None,
            "onlinePeakAt": peak["ts"] if peak else None,
            "trafficPeriod": period_traffic,
            "trafficPerActive": period_traffic // period_active if period_active else 0,
            "retentionTotal": cohort["total"] or 0, "retentionKept": cohort["kept"] or 0,
            "neverConnected": never,
        },
        "sampleEvery": SAMPLE_EVERY,
    }}
