import asyncio
import os
import secrets
import time

from fastapi import FastAPI
from fastapi.responses import FileResponse

import api_agent
import api_nodes
import api_users
import core
import db
import public
import stats
import subscription
from auth import hash_password
from config import ADMIN_PASSWORD, ADMIN_USERNAME

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = FastAPI(title="VPN Panel", docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
app.include_router(api_users.router)
app.include_router(api_nodes.router)
app.include_router(api_agent.router)
app.include_router(subscription.router)
app.include_router(public.router)
app.include_router(stats.router)


@app.get("/", include_in_schema=False)
def admin_page():
    return FileResponse(os.path.join(STATIC, "admin.html"))


async def _maintenance_loop():
    while True:
        try:
            core.periodic_maintenance()
        except Exception as e:
            print(f"[maintenance] {e}")
        await asyncio.sleep(30)


async def _adlists_loop():
    """Расширенный список рекламы: пересобирается раз в сутки, пока включён."""
    while True:
        s = core.panel_settings()
        if s["block_ads"] == "true" and s["block_ads_extended"] == "true":
            try:
                await asyncio.to_thread(core.refresh_adlists)
            except Exception as e:
                print(f"[adlists] {e}", flush=True)
        await asyncio.sleep(600)


async def _stats_loop():
    """Снимок «онлайн сейчас» раз в 5 минут — для графика онлайна в «Статистике»."""
    while True:
        try:
            stats.sample_online()
        except Exception as e:
            print(f"[stats] {e}", flush=True)
        await asyncio.sleep(stats.SAMPLE_EVERY - time.time() % stats.SAMPLE_EVERY + 1)


@app.on_event("startup")
async def startup():
    db.init_db()
    if not db.query_one("SELECT 1 FROM admins"):
        password = ADMIN_PASSWORD or secrets.token_urlsafe(12)
        db.execute("INSERT INTO admins(username, password) VALUES(?,?)", (ADMIN_USERNAME, hash_password(password)))
        if not ADMIN_PASSWORD:
            print(f"[panel] создан админ {ADMIN_USERNAME} с паролем: {password}", flush=True)
    asyncio.create_task(_maintenance_loop())
    asyncio.create_task(_adlists_loop())
    asyncio.create_task(_stats_loop())
