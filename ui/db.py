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
from datetime import datetime
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
    resolved_at      TEXT
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


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _LOCK, connect() as conn:
        conn.executescript(SCHEMA)


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
                current = {"severity": m.group(1), "type": m.group(2), "description": m.group(3)}
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
                "SELECT signature, occurrences, status FROM threats WHERE signature = ?", (sig,)
            ).fetchone()
            if row is None:
                new_count += 1
                conn.execute(
                    """INSERT INTO threats (signature, type, severity, description,
                                           mitre_technique, mitre_tactic, mitre_url,
                                           first_seen, last_seen, occurrences, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'open')""",
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
                                           first_seen, last_seen, occurrences, status, note)
                       VALUES (?, ?, ?, ?, ?, ?, 1, 'false_positive', ?)""",
                    (
                        sig,
                        sup["type"],
                        sup["severity"],
                        sup["description"],
                        seen_at,
                        seen_at,
                        sup.get("reason", "") + " [allowlist: " + sup.get("allowlist_id", "") + "]",
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
        "open_by_severity": by_severity,
        "most_repeated": [dict(r) for r in most_repeated],
        "series": [dict(r) for r in series],
    }


def threat_list(status: Optional[str] = None, limit: int = 200) -> list[dict[str, Any]]:
    with connect() as conn:
        if status:
            rows = conn.execute(
                """SELECT signature, type, severity, description, mitre_technique, mitre_tactic,
                          mitre_url, first_seen, last_seen, occurrences, status, note, resolved_at
                   FROM threats WHERE status = ?
                   ORDER BY occurrences DESC, severity, last_seen DESC LIMIT ?""",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT signature, type, severity, description, mitre_technique, mitre_tactic,
                          mitre_url, first_seen, last_seen, occurrences, status, note, resolved_at
                   FROM threats
                   ORDER BY occurrences DESC, severity, last_seen DESC LIMIT ?""",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def set_status(signature: str, status: str, note: str = "") -> Optional[dict[str, Any]]:
    if status not in VALID_STATUS:
        raise ValueError(f"estado invalido: {status}")
    with _LOCK, connect() as conn:
        row = conn.execute("SELECT signature FROM threats WHERE signature = ?", (signature,)).fetchone()
        if row is None:
            return None
        conn.execute(
            """UPDATE threats SET status = ?, note = ?,
                      resolved_at = CASE WHEN ? = 'resolved' OR ? = 'false_positive'
                                        THEN datetime('now') ELSE resolved_at END
               WHERE signature = ?""",
            (status, note, status, status, signature),
        )
        updated = conn.execute(
            """SELECT signature, type, severity, description, mitre_technique, mitre_tactic,
                      mitre_url, first_seen, last_seen, occurrences, status, note, resolved_at
               FROM threats WHERE signature = ?""",
            (signature,),
        ).fetchone()
    return dict(updated)


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
