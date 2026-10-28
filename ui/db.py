"""
Persistencia de la auditoria en SQLite.

Sin base de datos, la "tendencia" es un diff entre dos carpetas y se pierde en
cuando alguien limpia el historial. Esta capa convierte las ejecuciones sueltas
en una serie temporal consultable: cuando aparecio un hallazgo por primera vez,
cuantas veces se ha repetido, si sigue vivo y que estado de triage tiene.

El archivo de origen sigue siendo el JSON que genera PowerShell; la base es un
indice derivado, reconstruible desde cero (reingest_all).
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path(__file__).resolve().parent.parent / "audit_baseline.db"

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id          TEXT PRIMARY KEY,
    folder      TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    duration    TEXT,
    elevated    INTEGER DEFAULT 0,
    risk        TEXT,
    threats     INTEGER DEFAULT 0,
    suppressed  INTEGER DEFAULT 0,
    errors      INTEGER DEFAULT 0,
    warnings    INTEGER DEFAULT 0,
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threats (
    signature        TEXT PRIMARY KEY,
    type             TEXT NOT NULL,
    severity         TEXT NOT NULL,
    description      TEXT,
    mitre_technique  TEXT,
    mitre_tactic     TEXT,
    mitre_url        TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    occurrences      INTEGER NOT NULL DEFAULT 1,
    status           TEXT NOT NULL DEFAULT 'open',
    note             TEXT,
    resolved_at      TEXT,
    details          TEXT,
    sla_days         INTEGER,
    due_at           TEXT,
    acknowledged_at  TEXT
);

CREATE TABLE IF NOT EXISTS allowlist (
    id          TEXT PRIMARY KEY,
    threat_type TEXT NOT NULL,
    process     TEXT,
    path        TEXT,
    ports       TEXT,
    reason      TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'manual',
    signature   TEXT,
    created_at  TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_threats (
    audit_id   TEXT NOT NULL,
    signature  TEXT NOT NULL,
    severity   TEXT,
    PRIMARY KEY (audit_id, signature)
);

CREATE INDEX IF NOT EXISTS idx_threats_first_seen ON threats (first_seen);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats (status);
CREATE INDEX IF NOT EXISTS idx_audit_threats_sig ON audit_threats (signature);
"""

VALID_STATUS = {"open", "investigating", "accepted", "false_positive", "resolved"}

# SLA por severidad (dias). Un hallazgo abierto que no se toca mas alla de su SLA
# esta vencido: la baseline deja de ser un inventario y pasa a tener plazos.
SLA_DAYS = {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 7, "LOW": 30}


def _sla_due(first_seen: str, severity: str) -> str:
    try:
        base = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        base = datetime.now()
    return (base + timedelta(days=SLA_DAYS.get(severity, 7))).strftime("%Y-%m-%d %H:%M:%S")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _LOCK, connect() as conn:
        conn.executescript(SCHEMA)
        # Migracion: las bases creadas antes de la allowlist no tienen estas columnas.
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(threats)")}
        if "details" not in existing:
            conn.execute("ALTER TABLE threats ADD COLUMN details TEXT")
        for col in ("sla_days", "due_at", "acknowledged_at"):
            if col not in existing:
                conn.execute(f"ALTER TABLE threats ADD COLUMN {col} INTEGER" if col == "sla_days" else f"ALTER TABLE threats ADD COLUMN {col} TEXT")
        # Backfill para hallazgos ya indexados sin SLA.
        conn.execute(
            """UPDATE threats SET sla_days = NULL WHERE sla_days IS NULL"""
        )


def signature(threat_type: str, description: str) -> str:
    """Firma de un hallazgo.

    Debe coincidir bit a bit con Get-ThreatSignature en PowerShell: mismo texto
    normalizado (minusculas, sin PID, sin marcas de tiempo, espacios colapsados)
    y primeros 16 hexadecimales de SHA-256 en mayusculas. Si divergen, la baseline
    duplica hallazgos que ya existen.
    """
    norm = f"{threat_type}|{description}".lower()
    norm = re.sub(r"\(pid: \d+\)", "", norm)
    norm = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", "", norm)
    norm = re.sub(r"\s+", " ", norm)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16].upper()


def _parse_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    out: dict[str, Any] = {}
    for key, pattern in {
        "started_at": r"^Fecha Inicio:\s+(.+)$",
        "finished_at": r"^Fecha Fin:\s+(.+)$",
        "duration": r"^Duracion:\s+(.+)$",
        "risk": r"^NIVEL DE RIESGO GENERAL:\s+(.+)$",
        "threats": r"^Amenazas Detectadas:\s+(.+)$",
        "errors": r"^Errores:\s+(.+)$",
        "warnings": r"^Advertencias:\s+(.+)$",
    }.items():
        m = re.search(pattern, text, re.MULTILINE)
        if m:
            out[key] = m.group(1).strip()
    suppressed = re.search(
        r"^Suprimidas:\s+(\d+)", text, re.MULTILINE
    )
    if suppressed:
        out["suppressed"] = int(suppressed.group(1))
    return out


def _load_threats(folder: Path) -> list[dict[str, Any]]:
    data = None
    path = folder / "AMENAZAS_DETECTADAS.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            data = None
    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [t for t in data if isinstance(t, dict)]
    return []


def _load_suppressed(folder: Path) -> list[dict[str, Any]]:
    """Lee las amenazas suprimidas por la allowlist del resumen ejecutivo."""
    path = folder / "RESUMEN_EJECUTIVO.txt"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    match = re.search(
        r"^AMENAZAS SUPRIMIDAS POR ALLOWLIST LOCAL\s*$(.*?)(?=^COBERTURA|^HALLAZGOS|^RECOMENDACIONES)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        return []
    items = []
    current = None
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("Suprimidas:"):
            continue
        if line.startswith("- "):
            m = re.match(r"^- \[([A-Z]+)\] (.*?) \| (.*)$", line)
            if m:
                desc = m.group(3)
                mitre = re.search(r"\[mitre: ([A-Za-z0-9.]+)\]", desc)
                if mitre:
                    desc = desc[: mitre.start()].strip()
                current = {"severity": m.group(1), "type": m.group(2), "description": desc, "mitre": mitre.group(1) if mitre else ""}
                # El resumen no trae los detalles estructurados de una supresion, pero
                # la descripcion contiene el proceso y el puerto: sin eso, marcar un FP
                # no puede traducirse en una regla.
                proc = re.search(r"\(proceso '([^']+)'\)", current["description"])
                port = re.search(r"puerto (\d+)", current["description"], re.IGNORECASE)
                details = {}
                if proc:
                    details["ProcessName"] = proc.group(1)
                if port:
                    details["LocalPort"] = int(port.group(1))
                current["details"] = details
                items.append(current)
        elif line.startswith("Motivo:") and current is not None:
            m = re.match(r"^Motivo: (.*?) \[allowlist: (.*)\]$", line)
            if m:
                current["reason"] = m.group(1)
                current["allowlist_id"] = m.group(2)
    return items


def ingest_audit(folder: Path, force: bool = False) -> dict[str, int]:
    """Indexa una auditoria en la base. Idempotente por id de auditoria."""
    audit_id = folder.name
    summary = _parse_summary(folder / "RESUMEN_EJECUTIVO.txt")
    threats = _load_threats(folder)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with _LOCK, connect() as conn:
        existing = conn.execute(
            "SELECT id FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
        if existing and not force:
            return {"audit_id": audit_id, "new_threats": 0, "updated_threats": 0, "skipped": 1}

        if not existing:
            conn.execute(
                """INSERT INTO audits (id, folder, started_at, finished_at, duration,
                                      elevated, risk, threats, suppressed, errors, warnings, ingested_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    audit_id,
                    str(folder),
                    summary.get("started_at"),
                    summary.get("finished_at"),
                    summary.get("duration"),
                    0,
                    summary.get("risk", ""),
                    int(summary.get("threats", len(threats)) or 0),
                    int(summary.get("suppressed", 0) or 0),
                    int(summary.get("errors", 0) or 0),
                    int(summary.get("warnings", 0) or 0),
                    now,
                ),
            )

        new_count = 0
        updated_count = 0
        seen_at = summary.get("started_at") or now

        for t in threats:
            sig = t.get("Signature") or t.get("signature")
            if not sig:
                continue
            severity = (t.get("Severity") or "LOW").upper()
            row = conn.execute(
                "SELECT signature, occurrences, status, first_seen FROM threats WHERE signature = ?", (sig,)
            ).fetchone()
            if row is None:
                new_count += 1
                conn.execute(
                    """INSERT INTO threats (signature, type, severity, description,
                                           mitre_technique, mitre_tactic, mitre_url,
                                           first_seen, last_seen, occurrences, status, details,
                                           sla_days, due_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'open', ?, ?, ?)""",
                    (
                        sig,
                        t.get("ThreatType") or t.get("type") or "",
                        severity,
                        t.get("Description") or t.get("description") or "",
                        t.get("MitreTechnique") or "",
                        t.get("MitreTactic") or "",
                        t.get("MitreUrl") or "",
                        seen_at,
                        seen_at,
                        json.dumps(t.get("Details") or {}, ensure_ascii=False),
                        SLA_DAYS.get(severity, 7),
                        _sla_due(seen_at, severity),
                    ),
                )
            else:
                updated_count += 1
                # La severidad guardada es la mas alta observada: un hallazgo que
                # empieza como LOW y luego aparece como CRITICAL no debe bajar de nivel.
                best = severity
                if row["status"] in VALID_STATUS and row["status"] != "open":
                    best = row["severity"]
                conn.execute(
                    """UPDATE threats
                       SET severity = ?, last_seen = ?, occurrences = occurrences + 1,
                           type = ?, description = ?, mitre_technique = ?, mitre_tactic = ?, mitre_url = ?,
                           sla_days = ?, due_at = ?,
                           status = CASE WHEN status = 'false_positive' THEN 'open' ELSE status END
                       WHERE signature = ?""",
                    (
                        best,
                        seen_at,
                        t.get("ThreatType") or row["type"],
                        t.get("Description") or row["description"],
                        t.get("MitreTechnique") or row["mitre_technique"],
                        t.get("MitreTactic") or row["mitre_tactic"],
                        t.get("MitreUrl") or row["mitre_url"],
                        SLA_DAYS.get(best, 7),
                        _sla_due(row["first_seen"], best),
                        sig,
                    ),
                )
            conn.execute(
                "INSERT OR IGNORE INTO audit_threats (audit_id, signature, severity) VALUES (?, ?, ?)",
                (audit_id, sig, severity),
            )

        # Lo que la allowlist suprime tambien se registra: una supresion sin
        # trazabilidad es un hallazgo que nadie puede revisar.
        for sup in _load_suppressed(folder):
            sig = signature(sup["type"], sup["description"])
            row = conn.execute(
                "SELECT signature FROM threats WHERE signature = ?", (sig,)
            ).fetchone()
            seen_at = summary.get("started_at") or now
            if row is None:
                new_count += 1
                conn.execute(
                    """INSERT INTO threats (signature, type, severity, description,
                                           first_seen, last_seen, occurrences, status, note, details,
                                           sla_days, due_at, mitre_technique)
                       VALUES (?, ?, ?, ?, ?, ?, 1, 'false_positive', ?, ?, ?, ?, ?)""",
                    (
                        sig,
                        sup["type"],
                        sup["severity"],
                        sup["description"],
                        seen_at,
                        seen_at,
                        sup.get("reason", "") + " [allowlist: " + sup.get("allowlist_id", "") + "]",
                        json.dumps(sup.get("details") or {}, ensure_ascii=False),
                        SLA_DAYS.get(sup["severity"], 7),
                        _sla_due(seen_at, sup["severity"]),
                        sup.get("mitre", ""),
                    ),
                )
            else:
                conn.execute(
                    "UPDATE threats SET last_seen = ?, occurrences = occurrences + 1 WHERE signature = ?",
                    (seen_at, sig),
                )

        # Hallazgos que no vuelven: no se borran, se marcan como resueltos.
        conn.execute(
            """UPDATE threats
               SET status = 'resolved', resolved_at = ?
               WHERE status = 'open'
                 AND signature NOT IN (SELECT signature FROM audit_threats WHERE audit_id = ?)
                 AND last_seen < ?""",
            (seen_at, audit_id, seen_at),
        )

    return {
        "audit_id": audit_id,
        "new_threats": new_count,
        "updated_threats": updated_count,
        "skipped": 0,
    }


def reingest_all(result_dir: Path) -> dict[str, Any]:
    """Reconstruye la base desde las carpetas Auditoria_* existentes."""
    init_db()
    with _LOCK, connect() as conn:
        conn.execute("DELETE FROM audit_threats")
        conn.execute("DELETE FROM audits")
        conn.execute("DELETE FROM threats")
    audits = sorted(
        [c for c in result_dir.iterdir() if c.is_dir() and c.name.startswith("Auditoria_")],
        key=lambda p: p.name,
    )
    total_new = 0
    for folder in audits:
        res = ingest_audit(folder, force=True)
        total_new += res["new_threats"]
    return {"audits_ingested": len(audits), "distinct_threats": total_new}


def forget_audits(audit_ids: list[str]) -> int:
    """Elimina auditorias de la base sin borrar el registro historico de hallazgos.

    La baseline es historia: si se borra la carpeta de una auditoria, las
    ocurrencias de un hallazgo siguen contando, pero el diff deja de ver esa fila.
    """
    if not audit_ids:
        return 0
    with _LOCK, connect() as conn:
        conn.executemany(
            "DELETE FROM audit_threats WHERE audit_id = ?", [(i,) for i in audit_ids]
        )
        conn.executemany("DELETE FROM audits WHERE id = ?", [(i,) for i in audit_ids])
    return len(audit_ids)


def baseline() -> dict[str, Any]:
    """Estado agregado de la base: lo que se repite, lo que desaparecio, lo nuevo."""
    with connect() as conn:
        audits = conn.execute("SELECT COUNT(*) AS c FROM audits").fetchone()["c"]
        total = conn.execute("SELECT COUNT(*) AS c FROM threats").fetchone()["c"]
        recurring = conn.execute(
            "SELECT COUNT(*) AS c FROM threats WHERE occurrences >= 2"
        ).fetchone()["c"]
        open_count = conn.execute(
            "SELECT COUNT(*) AS c FROM threats WHERE status = 'open'"
        ).fetchone()["c"]
        resolved = conn.execute(
            "SELECT COUNT(*) AS c FROM threats WHERE status = 'resolved'"
        ).fetchone()["c"]
        fp = conn.execute(
            "SELECT COUNT(*) AS c FROM threats WHERE status = 'false_positive'"
        ).fetchone()["c"]
        overdue = conn.execute(
            "SELECT COUNT(*) AS c FROM threats WHERE status = 'open' AND due_at < ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
        ).fetchone()["c"]
        by_severity = {
            r["severity"]: r["c"]
            for r in conn.execute(
                "SELECT severity, COUNT(*) AS c FROM threats WHERE status = 'open' GROUP BY severity"
            )
        }
        most_repeated = conn.execute(
            """SELECT signature, type, severity, occurrences, first_seen, last_seen
               FROM threats ORDER BY occurrences DESC, severity LIMIT 10"""
        ).fetchall()
        series = conn.execute(
            """SELECT id, started_at, risk, threats, suppressed, duration
               FROM audits ORDER BY id"""
        ).fetchall()
    return {
        "audits": audits,
        "distinct_threats": total,
        "recurring": recurring,
        "open": open_count,
        "resolved": resolved,
        "false_positive": fp,
        "overdue": overdue,
        "open_by_severity": by_severity,
        "most_repeated": [dict(r) for r in most_repeated],
        "series": [dict(r) for r in series],
    }


def _row_with_sla(row: sqlite3.Row, now: datetime) -> dict[str, Any]:
    d = dict(row)
    due = d.get("due_at")
    if d["status"] == "open" and due:
        due_dt = datetime.strptime(due, "%Y-%m-%d %H:%M:%S")
        d["overdue"] = due_dt < now
        d["days_left"] = (due_dt - now).days
    else:
        d["overdue"] = False
        d["days_left"] = None
    return d


def threat_list(status: Optional[str] = None, limit: int = 200, overdue_only: bool = False) -> list[dict[str, Any]]:
    now = datetime.now()
    select = """SELECT signature, type, severity, description, mitre_technique, mitre_tactic,
                        mitre_url, first_seen, last_seen, occurrences, status, note, resolved_at,
                        sla_days, due_at, acknowledged_at
               FROM threats"""
    clauses = []
    params: list[Any] = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if overdue_only:
        clauses.append("status = 'open' AND due_at < ?")
        params.append(now.strftime("%Y-%m-%d %H:%M:%S"))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with connect() as conn:
        rows = conn.execute(
            f"{select}{where} ORDER BY occurrences DESC, severity, last_seen DESC LIMIT ?",
            params + [limit],
        ).fetchall()
    return [_row_with_sla(r, now) for r in rows]


def sla_report() -> dict[str, Any]:
    """Plazos por severidad. Sin esto la baseline es un inventario, no una gestion."""
    now = datetime.now()
    with connect() as conn:
        rows = conn.execute(
            """SELECT signature, type, severity, first_seen, last_seen, due_at, occurrences, status
               FROM threats WHERE status = 'open'"""
        ).fetchall()
        closed = conn.execute(
            """SELECT severity, AVG(julianday(resolved_at) - julianday(first_seen)) AS avg_days
               FROM threats WHERE resolved_at IS NOT NULL AND status IN ('resolved','false_positive','accepted')
               GROUP BY severity"""
        ).fetchall()
    by_severity: dict[str, dict[str, Any]] = {}
    overdue: list[dict[str, Any]] = []
    for r in rows:
        sev = r["severity"] or "LOW"
        bucket = by_severity.setdefault(sev, {"open": 0, "overdue": 0, "sla_days": SLA_DAYS.get(sev, 7), "oldest": None})
        bucket["open"] += 1
        due = r["due_at"]
        if due and datetime.strptime(due, "%Y-%m-%d %H:%M:%S") < now:
            bucket["overdue"] += 1
            overdue.append(
                {
                    "signature": r["signature"],
                    "type": r["type"],
                    "severity": sev,
                    "first_seen": r["first_seen"],
                    "due_at": due,
                    "days_overdue": (now - datetime.strptime(due, "%Y-%m-%d %H:%M:%S")).days,
                    "occurrences": r["occurrences"],
                }
            )
        if bucket["oldest"] is None or r["first_seen"] < bucket["oldest"]:
            bucket["oldest"] = r["first_seen"]
    overdue.sort(key=lambda x: x["days_overdue"], reverse=True)
    return {
        "policy": SLA_DAYS,
        "open": sum(b["open"] for b in by_severity.values()),
        "overdue": len(overdue),
        "by_severity": by_severity,
        "overdue_list": overdue,
        "mean_days_to_close": {r["severity"]: round(r["avg_days"], 1) for r in closed if r["avg_days"] is not None},
    }


def set_sla(signature: str, days: Optional[int]) -> Optional[dict[str, Any]]:
    """Sobrescribe el SLA de un hallazgo concreto (un HIGH que para el negocio es critico, etc.)."""
    if days is not None and days <= 0:
        raise ValueError("sla_days debe ser un entero positivo")
    now = datetime.now()
    with _LOCK, connect() as conn:
        row = conn.execute("SELECT first_seen FROM threats WHERE signature = ?", (signature,)).fetchone()
        if row is None:
            return None
        due = None if days is None else _sla_due(row["first_seen"], "")
        if days is not None:
            due = (datetime.strptime(row["first_seen"], "%Y-%m-%d %H:%M:%S") + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("UPDATE threats SET sla_days = ?, due_at = ? WHERE signature = ?", (days, due, signature))
        r = conn.execute(
            """SELECT signature, type, severity, first_seen, last_seen, occurrences, status, note,
                      sla_days, due_at, acknowledged_at FROM threats WHERE signature = ?""",
            (signature,),
        ).fetchone()
    return _row_with_sla(r, now)


def set_status(signature: str, status: str, note: str = "") -> Optional[dict[str, Any]]:
    if status not in VALID_STATUS:
        raise ValueError(f"estado invalido: {status}")
    now = datetime.now()
    with _LOCK, connect() as conn:
        row = conn.execute("SELECT signature FROM threats WHERE signature = ?", (signature,)).fetchone()
        if row is None:
            return None
        conn.execute(
            """UPDATE threats SET status = ?, note = ?,
                      resolved_at = CASE WHEN ? = 'resolved' OR ? = 'false_positive'
                                        THEN datetime('now') ELSE resolved_at END,
                      acknowledged_at = CASE WHEN ? = 'open' THEN acknowledged_at
                                            ELSE COALESCE(acknowledged_at, datetime('now')) END
               WHERE signature = ?""",
            (status, note, status, status, status, signature),
        )
        updated = conn.execute(
            """SELECT signature, type, severity, description, mitre_technique, mitre_tactic,
                      mitre_url, first_seen, last_seen, occurrences, status, note, resolved_at,
                      sla_days, due_at, acknowledged_at
               FROM threats WHERE signature = ?""",
            (signature,),
        ).fetchone()

    # El triage tiene efecto real: un falso positivo se traduce en una regla para la
    # proxima auditoria, y reabrirlo retira esa regla. Si no, el triage es decorativo.
    if status == "false_positive":
        entry = derive_allowlist_entry(signature, note)
    elif status in ("open", "investigating", "accepted", "resolved"):
        remove_allowlist_entry(f"fp-{signature.lower()}")
        entry = None
    else:
        entry = None
    return _row_with_sla(updated, now) | {"allowlist_entry": entry}


def _threat_details(signature: str) -> dict[str, Any]:
    with connect() as conn:
        row = conn.execute("SELECT details FROM threats WHERE signature = ?", (signature,)).fetchone()
    if not row or not row["details"]:
        return {}
    try:
        data = json.loads(row["details"])
    except (json.JSONDecodeError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def derive_allowlist_entry(signature: str, reason: str = "") -> Optional[dict[str, Any]]:
    """Cierra el circulo: un hallazgo marcado como falso positivo genera una entrada.

    Sin esto, marcar algo como FP en la UI no tiene efecto en la siguiente auditoria
    y el ruido vuelve en la proxima ejecucion.
    """
    with connect() as conn:
        row = conn.execute(
            "SELECT signature, type, description FROM threats WHERE signature = ?",
            (signature,),
        ).fetchone()
    if row is None:
        return None

    details = _threat_details(signature)
    process = details.get("ProcessName") or details.get("Name") or ""
    ports = sorted({int(p) for p in (details.get("RemotePort"), details.get("LocalPort"), details.get("Port")) if p and int(p) > 0})
    path = details.get("ProcessPath") or details.get("Path") or ""

    if not process and not ports:
        return None

    entry_id = f"fp-{signature.lower()}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reason = reason or f"Marcado como falso positivo en el triage: {row['description']}"
    with _LOCK, connect() as conn:
        conn.execute(
            """INSERT INTO allowlist (id, threat_type, process, path, ports, reason, source, signature, created_at, active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(id) DO UPDATE SET
                   threat_type = excluded.threat_type,
                   process = excluded.process,
                   path = excluded.path,
                   ports = excluded.ports,
                   reason = excluded.reason,
                   active = 1""",
            (entry_id, row["type"], process, path, json.dumps(ports), reason, "triage", signature, now),
        )
    return {
        "id": entry_id,
        "threat_type": row["type"],
        "process": process,
        "path": path,
        "ports": ports,
        "reason": reason,
        "source": "triage",
        "signature": signature,
    }


SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8080, 8888, 9999, 31337, 12345, 1337, 6667}


def allowlist_rule_health(process: str, ports: list[int]) -> dict[str, Any]:
    """Espejo de Get-AllowlistRuleHealth en Invoke-SecurityAudit.ps1.

    Una regla solo vale si puede disparar: si ninguno de sus puertos esta en la lista
    de deteccion, la alarma nunca existe y la regla no suprime nada. No es inocua: da
    una falsa sensacion de cobertura y ensucia el conteo de ruido.
    """
    detectable = sorted({int(p) for p in ports if int(p) in SUSPICIOUS_PORTS})
    if not process and not ports:
        return {"estado": "invalida: sin proceso ni puertos", "puertos_detectables": []}
    if ports and not detectable:
        return {
            "estado": "inerte: ningun puerto de la regla esta en la lista de deteccion",
            "puertos_detectables": [],
        }
    return {"estado": "activable", "puertos_detectables": detectable}


def add_allowlist_entry(entry: dict[str, Any]) -> dict[str, Any]:
    ports = sorted({int(p) for p in (entry.get("ports") or []) if int(p) > 0})
    if not entry.get("process") and not ports:
        raise ValueError("La entrada de allowlist necesita un proceso o un puerto")
    health = allowlist_rule_health(entry.get("process", ""), ports)
    if health["estado"] != "activable":
        raise ValueError(
            f"Regla de allowlist {health['estado']}. Una regla que no puede disparar "
            "no suprime nada: da falsa sensacion de cobertura. Usa un puerto alertado "
            f"({', '.join(str(p) for p in sorted(SUSPICIOUS_PORTS))}) o un proceso."
        )
    entry_id = entry.get("id") or f"manual-{uuid.uuid4().hex[:8]}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _LOCK, connect() as conn:
        conn.execute(
            """INSERT INTO allowlist (id, threat_type, process, path, ports, reason, source, signature, created_at, active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (
                entry_id,
                entry.get("threat_type", ""),
                entry.get("process", ""),
                entry.get("path", ""),
                json.dumps(ports),
                entry.get("reason", "allowlist manual"),
                entry.get("source", "manual"),
                entry.get("signature"),
                now,
            ),
        )
    return {
        "id": entry_id,
        "threat_type": entry.get("threat_type", ""),
        "process": entry.get("process", ""),
        "path": entry.get("path", ""),
        "ports": ports,
        "reason": entry.get("reason", "allowlist manual"),
        "source": entry.get("source", "manual"),
        "created_at": now,
    }


def list_allowlist(active_only: bool = True) -> list[dict[str, Any]]:
    with connect() as conn:
        if active_only:
            rows = conn.execute("SELECT * FROM allowlist WHERE active = 1 ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM allowlist ORDER BY created_at DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["ports"] = json.loads(d.get("ports") or "[]")
        except (json.JSONDecodeError, TypeError):
            d["ports"] = []
        d["health"] = allowlist_rule_health(d.get("process", ""), d["ports"])
        out.append(d)
    return out


def remove_allowlist_entry(entry_id: str) -> bool:
    with _LOCK, connect() as conn:
        cur = conn.execute("DELETE FROM allowlist WHERE id = ?", (entry_id,))
    return cur.rowcount > 0


def write_allowlist_file(path: Path) -> dict[str, Any]:
    """Escribe la allowlist derivada del triage en el JSON que lee Invoke-SecurityAudit.ps1.

    El script PowerShell la fusiona con su allowlist built-in: aqui solo van las
    entradas generadas por el triage, no las built-in.
    """
    entries = [
        {
            "id": e["id"],
            "threatTypes": [e["threat_type"]] if e["threat_type"] else [],
            "ports": e["ports"],
            "process": e["process"],
            "path": e["path"],
            "reason": e["reason"],
        }
        for e in list_allowlist()
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"entries": entries}, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"entries": len(entries), "path": str(path)}


def audit_context(audit_id: str) -> dict[str, Any]:
    """Diff de una auditoria contra la base: nuevo, recurrente, resuelto, conocido."""
    with connect() as conn:
        prev = conn.execute(
            "SELECT id FROM audits WHERE id < ? ORDER BY id DESC LIMIT 1", (audit_id,)
        ).fetchone()
        current_sigs = {
            r["signature"]
            for r in conn.execute(
                "SELECT signature FROM audit_threats WHERE audit_id = ?", (audit_id,)
            )
        }
        new = []
        recurring = []
        for sig in current_sigs:
            t = conn.execute(
                """SELECT signature, type, severity, description, mitre_technique, mitre_tactic,
                          mitre_url, first_seen, last_seen, occurrences, status
                   FROM threats WHERE signature = ?""",
                (sig,),
            ).fetchone()
            if t is None:
                continue
            if t["occurrences"] <= 1:
                new.append(dict(t))
            else:
                recurring.append(dict(t))

        resolved = []
        if prev:
            rows = conn.execute(
                """SELECT t.signature, t.type, t.severity, t.description, t.first_seen, t.last_seen,
                          t.occurrences, t.status
                   FROM threats t
                   WHERE t.status IN ('open', 'resolved')
                     AND t.signature NOT IN (SELECT signature FROM audit_threats WHERE audit_id = ?)
                     AND t.last_seen < (SELECT started_at FROM audits WHERE id = ?)
                   ORDER BY t.last_seen DESC LIMIT 50""",
                (audit_id, audit_id),
            ).fetchall()
            resolved = [dict(r) for r in rows]

    return {
        "previous": prev["id"] if prev else None,
        "new": new,
        "recurring": recurring,
        "resolved": resolved,
    }
