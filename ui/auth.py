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


def password_hash_string(password: str) -> str:
    """Formato portable para AUDIT_ADMIN_PASSWORD_HASH: scrypt$<salt>$<hash>.

    La clave en claro no tiene que llegar al entorno: se genera el hash en local
    y solo se guarda el digest. El entorno deja de contener la contraseña.
    """
    digest, salt = hash_password(password)
    return f"scrypt${salt}${digest}"


def parse_hash_string(hash_string: str) -> tuple[str, str]:
    """Descomponer 'scrypt$<salt>$<hash>'. Si falla, ValueError con motivo legible."""
    parts = (hash_string or "").strip().split("$")
    if len(parts) != 3 or parts[0] != "scrypt" or not parts[1] or not parts[2]:
        raise ValueError("AUDIT_ADMIN_PASSWORD_HASH debe tener el formato scrypt$<salt>$<hash>")
    return parts[2], parts[1]


def verify_hash_string(password: str, hash_string: str) -> bool:
    digest, salt = parse_hash_string(hash_string)
    return verify_password(password, digest, salt)


def create_user_from_hash(username: str, hash_string: str, role: str = "analyst") -> dict[str, Any]:
    """Crear un usuario a partir de un hash scrypt ya calculado.

    No se necesita conocer la contraseña en claro: el entorno solo almacena el
    digest, y quien no tiene la clave original no puede recuperarla.
    """
    username = (username or "").strip().lower()
    if not username or len(username) < 3:
        raise ValueError("nombre de usuario demasiado corto (minimo 3)")
    if role not in ("admin", "analyst", "viewer"):
        raise ValueError("rol invalido: admin, analyst o viewer")
    stored_hash, salt = parse_hash_string(hash_string)
    with _LOCK, db.connect() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, stored_hash, salt, role, _fmt(_now())),
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"el usuario {username} ya existe")
    record_event(username, "user_created", f"role={role}, hash=precalculado")
    return {"username": username, "role": role, "created_at": _fmt(_now())}


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


def trail(
    limit: int = 100,
    username: Optional[str] = None,
    action: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Registro de actividad con filtros. Sin filtros es el mismo comportamiento anterior."""
    clauses, params = [], []
    if username:
        clauses.append("username = ?")
        params.append(username)
    if action:
        clauses.append("action = ?")
        params.append(action)
    if since:
        clauses.append("at >= ?")
        params.append(since)
    if until:
        clauses.append("at <= ?")
        params.append(until)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(max(1, min(limit, 5000)))
    with db.connect() as conn:
        rows = conn.execute(
            f"SELECT id, at, username, action, detail, ip FROM audit_trail{where} "
            "ORDER BY id DESC LIMIT ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def trail_actions() -> list[str]:
    """Acciones presentes en el registro, para el filtro de la consola."""
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT action, COUNT(*) AS n FROM audit_trail GROUP BY action ORDER BY n DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def purge_trail(days: Optional[int] = None) -> int:
    """Retencion del registro. AUDIT_TRAIL_RETENTION_DAYS (default 90); 0 = no purgar.

    Un trail indefinido es un problema de minimizacion de datos: guarda nombres,
    IPs y detalles de triage indefinidamente si nadie lo poda.
    """
    if days is None:
        raw = os.environ.get("AUDIT_TRAIL_RETENTION_DAYS", "90")
        try:
            days = int(raw)
        except ValueError:
            days = 90
    if days <= 0:
        return 0
    cutoff = _fmt(_now() - timedelta(days=days))
    with db.connect() as conn:
        cur = conn.execute("DELETE FROM audit_trail WHERE at < ?", (cutoff,))
        return cur.rowcount


def trail_stats() -> dict[str, Any]:
    with db.connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM audit_trail").fetchone()["c"]
        oldest = conn.execute("SELECT MIN(at) AS a FROM audit_trail").fetchone()["a"]
    return {"total": total, "oldest": oldest, "retention_days": os.environ.get("AUDIT_TRAIL_RETENTION_DAYS", "90")}


def bootstrap_admin() -> Optional[dict[str, Any]]:
    """Crea el usuario administrador desde variables de entorno, nunca de un fichero.

    Orden de preferencia:
      1. AUDIT_ADMIN_PASSWORD_HASH (scrypt$<salt>$<hash>): el entorno no contiene
         la contraseña, solo su digest.
      2. AUDIT_ADMIN_PASSWORD (en claro): compatible con la configuracion antigua.
    """
    with db.connect() as conn:
        admins = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()["c"]
    if admins:
        return None
    user = (os.environ.get("AUDIT_ADMIN_USER") or "").strip()
    if not user:
        return None
    hash_string = os.environ.get("AUDIT_ADMIN_PASSWORD_HASH", "").strip()
    if hash_string:
        return create_user_from_hash(user, hash_string, "admin")
    password = os.environ.get("AUDIT_ADMIN_PASSWORD")
    if not password:
        return None
    return create_user(user, password, "admin")


def secret_posture() -> dict[str, Any]:
    """Postura de secretos del entorno: nombres y fuente, nunca valores.

    Sirve para saber si la clave sigue en claro o ya se migro a hash, sin exponer
    el contenido de la variable.
    """
    return {
        "admin_user": os.environ.get("AUDIT_ADMIN_USER") or None,
        "admin_password_source": (
            "hash" if os.environ.get("AUDIT_ADMIN_PASSWORD_HASH", "").strip()
            else "claro" if os.environ.get("AUDIT_ADMIN_PASSWORD", "").strip()
            else "none"
        ),
        "sign_key_defined": bool(os.environ.get("AUDIT_SIGN_KEY", "").strip()),
        "trail_retention_days": os.environ.get("AUDIT_TRAIL_RETENTION_DAYS", "90"),
    }
