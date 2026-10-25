import base64
import hashlib
import hmac
import json
import secrets
import time

from fastapi import Header, HTTPException

import db

SESSION_TTL = 7 * 86400


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1)
        return hmac.compare_digest(calc.hex(), dk)
    except Exception:
        return False


def _secret() -> bytes:
    s = db.get_setting("session_secret")
    if not s:
        s = secrets.token_hex(32)
        db.set_setting("session_secret", s)
    return bytes.fromhex(s)


def issue_session(username: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"u": username, "exp": int(time.time()) + SESSION_TTL}).encode()).decode()
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"s.{payload}.{sig}"


def _check_session(token: str) -> str | None:
    try:
        _, payload, sig = token.split(".")
    except ValueError:
        return None
    if not hmac.compare_digest(hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest(), sig):
        return None
    data = json.loads(base64.urlsafe_b64decode(payload))
    if data["exp"] < time.time():
        return None
    if not db.query_one("SELECT 1 FROM admins WHERE username=?", (data["u"],)):
        return None
    return data["u"]


def require_api(authorization: str = Header(default="")) -> str:
    """Доступ к API: сессия админа (s.xxx) или API-токен (для сайта / бота)."""
    token = authorization.removeprefix("Bearer ").strip()
    if token.startswith("s."):
        user = _check_session(token)
        if user:
            return f"admin:{user}"
    elif token and db.query_one("SELECT 1 FROM api_tokens WHERE token=?", (token,)):
        return "token"
    raise HTTPException(401, "Unauthorized")


def require_admin(authorization: str = Header(default="")) -> str:
    """Только админ-сессия: управление токенами и паролем."""
    who = require_api(authorization)
    if not who.startswith("admin:"):
        raise HTTPException(403, "Admin session required")
    return who


def require_node(authorization: str = Header(default="")) -> dict:
    token = authorization.removeprefix("Bearer ").strip()
    node = db.query_one("SELECT * FROM nodes WHERE token=?", (token,)) if token else None
    if not node:
        raise HTTPException(401, "Unknown node token")
    return node
