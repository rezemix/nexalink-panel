import os
import sqlite3
import threading
from contextlib import contextmanager

from config import DATA_DIR, DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS admins (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    token      TEXT PRIMARY KEY,
    name       TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS nodes (
    uuid            TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    address         TEXT NOT NULL,
    country         TEXT DEFAULT '',
    token           TEXT UNIQUE NOT NULL,
    disabled        INTEGER DEFAULT 0,
    sort            INTEGER DEFAULT 0,
    last_seen       REAL,
    core_version    TEXT,
    core_started    REAL,
    agent_version   TEXT,
    applied_version TEXT,
    last_error      TEXT,
    users_online    INTEGER DEFAULT 0,
    traffic_bytes   INTEGER DEFAULT 0,
    created_at      TEXT
);
CREATE TABLE IF NOT EXISTS inbounds (
    uuid      TEXT PRIMARY KEY,
    node_uuid TEXT NOT NULL REFERENCES nodes(uuid) ON DELETE CASCADE,
    protocol  TEXT NOT NULL,
    tag       TEXT NOT NULL,
    port      INTEGER NOT NULL,
    remark    TEXT DEFAULT '',
    settings  TEXT DEFAULT '{}',
    enabled   INTEGER DEFAULT 1,
    UNIQUE (node_uuid, port),
    UNIQUE (node_uuid, tag)
);
CREATE TABLE IF NOT EXISTS users (
    uuid                TEXT PRIMARY KEY,
    short_uuid          TEXT UNIQUE NOT NULL,
    username            TEXT UNIQUE NOT NULL,
    status              TEXT NOT NULL DEFAULT 'ACTIVE',
    expire_at           TEXT NOT NULL,
    traffic_limit_bytes INTEGER DEFAULT 0,
    traffic_strategy    TEXT DEFAULT 'NO_RESET',
    used_bytes          INTEGER DEFAULT 0,
    lifetime_used_bytes INTEGER DEFAULT 0,
    hwid_limit          INTEGER,
    description         TEXT DEFAULT '',
    last_reset_at       TEXT,
    online_at           TEXT,
    sub_updated_at      TEXT,
    created_at          TEXT
);
CREATE TABLE IF NOT EXISTS traffic_daily (
    day       TEXT NOT NULL,
    node_uuid TEXT NOT NULL,
    bytes     INTEGER DEFAULT 0,
    PRIMARY KEY (day, node_uuid)
);
CREATE TABLE IF NOT EXISTS user_traffic_daily (
    day       TEXT NOT NULL,
    user_uuid TEXT NOT NULL,
    bytes     INTEGER DEFAULT 0,
    PRIMARY KEY (day, user_uuid)
);
CREATE TABLE IF NOT EXISTS hwid_devices (
    user_uuid  TEXT NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    hwid       TEXT NOT NULL,
    platform   TEXT,
    os_version TEXT,
    model      TEXT,
    user_agent TEXT,
    created_at TEXT,
    PRIMARY KEY (user_uuid, hwid)
);
CREATE TABLE IF NOT EXISTS free_signups (
    user_uuid  TEXT NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    ip         TEXT,
    hwid       TEXT,
    source     TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS free_signups_ip ON free_signups(ip, created_at);
CREATE INDEX IF NOT EXISTS free_signups_hwid ON free_signups(hwid);
CREATE TABLE IF NOT EXISTS online_samples (
    ts INTEGER PRIMARY KEY,
    n  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sub_fetch_daily (
    day       TEXT NOT NULL,
    user_uuid TEXT NOT NULL,
    n         INTEGER DEFAULT 0,
    PRIMARY KEY (day, user_uuid)
);
"""

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


def init_db():
    global _conn
    os.makedirs(DATA_DIR, exist_ok=True)
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA foreign_keys=ON")
    _conn.executescript(SCHEMA)
    # миграции для баз, созданных старыми версиями
    cols = {r[1] for r in _conn.execute("PRAGMA table_info(nodes)")}
    if "sys_stats" not in cols:
        _conn.execute("ALTER TABLE nodes ADD COLUMN sys_stats TEXT")


@contextmanager
def tx():
    """Одна транзакция под общим локом: SQLite + один процесс uvicorn."""
    with _lock:
        _conn.execute("BEGIN")
        try:
            yield _conn
            _conn.execute("COMMIT")
        except Exception:
            _conn.execute("ROLLBACK")
            raise


def query(sql, args=()):
    with _lock:
        return [dict(r) for r in _conn.execute(sql, args).fetchall()]


def query_one(sql, args=()):
    with _lock:
        row = _conn.execute(sql, args).fetchone()
        return dict(row) if row else None


def execute(sql, args=()):
    with _lock:
        return _conn.execute(sql, args)


def get_setting(key, default=None):
    row = query_one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


def set_setting(key, value):
    execute("INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
