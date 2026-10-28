"""Autenticacion, sesiones y panel de administrador.

Modelo: usuario local con hash scrypt + sesion en cookie HttpOnly. La sesion se
renueva mientras hay actividad y caduca si nadie la usa: un usuario sin actividad
queda expulsado, no sigue teniendo una cookie valida indefinidamente.

No hay claves escritas en el repo. El usuario administrador se crea desde
variables de entorno de Windows (AUDIT_ADMIN_USER / AUDIT_ADMIN_PASSWORD).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Any, Optional

import db

# 30 minutos de inactivity: suficientemente corto para no dejar una sesion abierta
# en una maquina compartida, suficientemente largo para no cortar una auditoria.
SESSION_TTL_MINUTES = 30
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username       TEXT PRIMARY KEY,
    password_hash  TEXT NOT NULL,
    salt           TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'analyst',
    created_at     TEXT NOT NULL,
    last_login     TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until   TEXT,
    active         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sessions (
    token         TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    ip            TEXT,
    revoked       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_trail (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    username  TEXT,
    action    TEXT NOT NULL,
    detail    TEXT,
    ip        TEXT
);
"""


def init_auth() -> None:
    with _LOCK, db.connect() as conn:
        conn.executescript(SCHEMA)


def _now() -> datetime:
    return datetime.now()


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt.encode("utf-8"), n=16384, r=8, p=1)
    return digest.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt.encode("utf-8"), n=16384, r=8, p=1)
    return hmac.compare_digest(digest.hex(), stored_hash)


def create_user(username: str, password: str, role: str = "analyst") -> dict[str, Any]:
    username = (username or "").strip().lower()
    if not username or len(username) < 3:
        raise ValueError("nombre de usuario demasiado corto (minimo 3)")
    if len(password or "") < 8:
        raise ValueError("la contraseña debe tener al menos 8 caracteres")
    if role not in ("admin", "analyst", "viewer"):
        raise ValueError("rol invalido: admin, analyst o viewer")
    stored_hash, salt = hash_password(password)
    with _LOCK, db.connect() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, stored_hash, salt, role, _fmt(_now())),
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"el usuario {username} ya existe")
    record_event(username, "user_created", f"role={role}")
    return {"username": username, "role": role, "created_at": _fmt(_now())}


def list_users() -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = conn.execute(
            """SELECT username, role, created_at, last_login, failed_attempts, locked_until, active
               FROM users ORDER BY username"""
        ).fetchall()
    return [dict(r) for r in rows]


def get_user(username: str) -> Optional[dict[str, Any]]:
    with db.connect() as conn:
        row = conn.execute(
            """SELECT username, password_hash, salt, role, created_at, last_login,
                      failed_attempts, locked_until, active
               FROM users WHERE username = ?""",
            ((username or "").strip().lower(),),
        ).fetchone()
    return dict(row) if row else None


def delete_user(username: str) -> bool:
    username = (username or "").strip().lower()
    with _LOCK, db.connect() as conn:
        cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.execute("UPDATE sessions SET revoked = 1 WHERE username = ?", (username,))
    record_event(username, "user_deleted", "")
    return cur.rowcount > 0


def reset_password(username: str, password: str) -> bool:
    if len(password or "") < 8:
        raise ValueError("la contraseña debe tener al menos 8 caracteres")
    username = (username or "").strip().lower()
    stored_hash, salt = hash_password(password)
    with _LOCK, db.connect() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ?, salt = ?, failed_attempts = 0, locked_until = NULL WHERE username = ?",
            (stored_hash, salt, username),
        )
        conn.execute("UPDATE sessions SET revoked = 1 WHERE username = ?", (username,))
    record_event(username, "password_reset", "")
    return cur.rowcount > 0


def login(username: str, password: str, ip: str = "") -> Optional[dict[str, Any]]:
    """Devuelve la sesion o None. Bloquea tras N intentos fallidos."""
    user = get_user(username)
    now = _now()
    if user is None or not user["active"]:
        record_event(username, "login_failed", "usuario inexistente o inactivo")
        return None

    if user["locked_until"] and datetime.strptime(user["locked_until"], "%Y-%m-%d %H:%M:%S") > now:
        record_event(username, "login_blocked", "cuenta bloqueada por intentos fallidos")
        return None

    if not verify_password(password, user["password_hash"], user["salt"]):
        with _LOCK, db.connect() as conn:
            attempts = user["failed_attempts"] + 1
            locked = _fmt(now + timedelta(minutes=LOCKOUT_MINUTES)) if attempts >= MAX_FAILED_ATTEMPTS else None
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                (attempts, locked, user["username"]),
            )
        record_event(username, "login_failed", f"intento {attempts}")
        return None

    token = secrets.token_hex(32)
    with _LOCK, db.connect() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE username = ?",
            (_fmt(now), user["username"]),
        )
        conn.execute(
            """INSERT INTO sessions (token, username, created_at, last_activity, expires_at, ip)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (token, user["username"], _fmt(now), _fmt(now), _fmt(now + timedelta(minutes=SESSION_TTL_MINUTES)), ip),
        )
    record_event(user["username"], "login", "")
    return {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "expires_at": _fmt(now + timedelta(minutes=SESSION_TTL_MINUTES)),
    }


def touch_session(token: str, ip: str = "") -> Optional[dict[str, Any]]:
    """Renueva la ventana de actividad. Si ha caducado, devuelve None."""
    now = _now()
    with _LOCK, db.connect() as conn:
        row = conn.execute(
            "SELECT token, username, expires_at, revoked FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if row is None or row["revoked"]:
            return None
        if datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S") < now:
            conn.execute("UPDATE sessions SET revoked = 1 WHERE token = ?", (token,))
            return None
        new_expiry = now + timedelta(minutes=SESSION_TTL_MINUTES)
        conn.execute(
            "UPDATE sessions SET last_activity = ?, expires_at = ?, ip = ? WHERE token = ?",
            (_fmt(now), _fmt(new_expiry), ip, token),
        )
        user = conn.execute("SELECT role, active FROM users WHERE username = ?", (row["username"],)).fetchone()
        if user is None or not user["active"]:
            conn.execute("UPDATE sessions SET revoked = 1 WHERE token = ?", (token,)
            )
            return None
    return {"username": row["username"], "role": user["role"], "expires_at": _fmt(new_expiry)}


def revoke_session(token: str) -> bool:
    with _LOCK, db.connect() as conn:
        cur = conn.execute("UPDATE sessions SET revoked = 1 WHERE token = ?", (token,))
    return cur.rowcount > 0


def list_sessions(active_only: bool = True) -> list[dict[str, Any]]:
    now = _fmt(_now())
    with db.connect() as conn:
        if active_only:
            rows = conn.execute(
                """SELECT token, username, created_at, last_activity, expires_at, ip
                   FROM sessions WHERE revoked = 0 AND expires_at > ?
                   ORDER BY last_activity DESC""",
                (now,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT token, username, created_at, last_activity, expires_at, ip, revoked FROM sessions ORDER BY created_at DESC"
            ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        # El token no se muestra entero: basta para identificar la sesion.
        d["token"] = d["token"][:8]
        out.append(d)
    return out


def record_event(username: Optional[str], action: str, detail: str = "", ip: str = "") -> None:
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO audit_trail (at, username, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
            (_fmt(_now()), username, action, detail, ip),
        )


def trail(limit: int = 100) -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id, at, username, action, detail, ip FROM audit_trail ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def bootstrap_admin() -> Optional[dict[str, Any]]:
    """Crea el usuario administrador desde variables de entorno, nunca de un fichero."""
    with db.connect() as conn:
        admins = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()["c"]
    if admins:
        return None
    user = os.environ.get("AUDIT_ADMIN_USER")
    password = os.environ.get("AUDIT_ADMIN_PASSWORD")
    if not user or not password:
        return None
    return create_user(user, password, "admin")
