"""
Auditoria de Seguridad Empresarial - Interfaz Web (v3.0)

Backend FastAPI que sirve la interfaz de la auditoria de seguridad.
Permite visualizar auditorias generadas y ejecutar nuevas auditorias
con progreso en vivo a traves del script PowerShell en modo headless.
"""

import base64
import csv
import io
import json
import os
import re
import shutil
import subprocess
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from fpdf import FPDF

import db
import auth
import integrations

# ---------------------------------------------------------------------------
# Rutas base
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
SCRIPT_PATH = BASE_DIR / "Invoke-SecurityAudit.ps1"
RESULTS_DIR = Path(os.environ.get("AUDIT_RESULTS_DIR", str(BASE_DIR)))
RUNS_DIR = BASE_DIR / ".runs"

RUNS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Mapa de modulos y severidades
# ---------------------------------------------------------------------------

MODULE_TITLES = {
    "01_Sistema": "Informacion del Sistema",
    "02_Usuarios": "Usuarios y Permisos",
    "03_Procesos": "Procesos y Servicios",
    "04_Red": "Analisis de Red",
    "05_Eventos": "Eventos de Seguridad",
    "06_Archivos": "Archivos y Persistencia",
    "07_Configuracion": "Configuracion de Seguridad",
    "08_LOLBAS": "Deteccion LOLBAS",
    "09_Drivers": "Analisis de Drivers",
    "10_Hardware": "Informacion de Hardware",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Ejecuciones activas en memoria (run_id -> metadata)
RUNS: dict[str, dict[str, Any]] = {}
RUNS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Utilidades de parsing
# ---------------------------------------------------------------------------

def read_json(path: Path) -> Any:
    """Lee un JSON generado por PowerShell (UTF-8 con/sin BOM)."""
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None


def as_list(data: Any) -> list:
    """Normaliza un valor a lista (PowerShell colapsa arrays de 1 elemento)."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return [data]


def humanize(name: str) -> str:
    """Convierte un nombre de archivo en un titulo legible."""
    return " ".join(word.capitalize() for word in name.replace("_", " ").split())


def parse_summary(path: Path) -> dict:
    """Extrae los campos clave del RESUMEN_EJECUTIVO.txt."""
    result: dict[str, Any] = {}
    if not path.exists():
        return result

    text = path.read_text(encoding="utf-8-sig", errors="replace")

    patterns = {
        "sistema": r"^Sistema:\s+(.+)$",
        "usuario": r"^Usuario Ejecutor:\s+(.+)$",
        "privilegios": r"^Privilegios:\s+(.+)$",
        "fecha_inicio": r"^Fecha Inicio:\s+(.+)$",
        "fecha_fin": r"^Fecha Fin:\s+(.+)$",
        "duracion": r"^Duracion:\s+(.+)$",
        "directorio": r"^Directorio:\s+(.+)$",
        "modulos": r"^Modulos Ejecutados:\s+(.+)$",
        "errores": r"^Errores:\s+(.+)$",
        "advertencias": r"^Advertencias:\s+(.+)$",
        "amenazas": r"^Amenazas Detectadas:\s+(.+)$",
        "riesgo": r"^NIVEL DE RIESGO GENERAL:\s+(.+)$",
        "criticas": r"^Amenazas CRITICAS:\s+(.+)$",
        "altas": r"^Amenazas ALTAS:\s+(.+)$",
        "medias": r"^Amenazas MEDIAS:\s+(.+)$",
        "bajas": r"^Amenazas BAJAS:\s+(.+)$",
        "cobertura": r"^Cobertura:\s+(.+)$",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            result[key] = match.group(1).strip()

    return result


def compute_risk_level(severity_counts: dict) -> str:
    """Replica la logica de nivel de riesgo del script PowerShell."""
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    if critical > 0:
        return "CRITICO"
    if high > 5:
        return "ALTO"
    if high > 0:
        return "MEDIO"
    return "BAJO"


def load_threats(folder: Path) -> list:
    """Carga y normaliza las amenazas detectadas."""
    data = read_json(folder / "AMENAZAS_DETECTADAS.json")
    threats = as_list(data)
    normalized = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        normalized.append(
            {
                "timestamp": t.get("Timestamp"),
                "type": t.get("ThreatType"),
                "severity": t.get("Severity", "LOW"),
                "description": t.get("Description"),
                "details": t.get("Details"),
                "mitre_technique": t.get("MitreTechnique", ""),
                "mitre_name": t.get("MitreName", ""),
                "mitre_tactic": t.get("MitreTactic", ""),
                "mitre_url": t.get("MitreUrl", ""),
                "signature": t.get("Signature", ""),
            }
        )
    return normalized


def list_module_dirs(folder: Path) -> list:
    """Lista los directorios de modulo presentes (01_..10_)."""
    dirs = []
    if folder.exists():
        for child in sorted(folder.iterdir()):
            if child.is_dir() and re.match(r"^\d{2}_", child.name):
                dirs.append(child)
    return dirs


def build_audit_meta(folder: Path) -> dict:
    summary = parse_summary(folder / "RESUMEN_EJECUTIVO.txt")
    threats = load_threats(folder)
    severity_counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for t in threats:
        sev = (t.get("severity") or "LOW").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    modules = []
    for mdir in list_module_dirs(folder):
        datasets = sorted(
            [p.stem for p in mdir.glob("*.json") if p.is_file()]
        )
        modules.append(
            {
                "name": mdir.name,
                "title": MODULE_TITLES.get(mdir.name, mdir.name),
                "datasets": datasets,
            }
        )

    return {
        "id": folder.name,
        "folder": folder.name,
        "path": str(folder),
        "summary": summary,
        "threats_count": len(threats),
        "severity_counts": severity_counts,
        "risk_level": compute_risk_level(severity_counts),
        "coverage_gaps": parse_coverage_gaps(folder / "RESUMEN_EJECUTIVO.txt"),
        "suppressed": parse_suppressed(folder / "RESUMEN_EJECUTIVO.txt"),
        "modules": modules,
    }


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="Auditoria de Seguridad Empresarial", version="3.0")


@app.on_event("startup")
def _startup_baseline() -> None:
    """Indexar las auditorias existentes al arrancar (idempotente por id)."""
    db.init_db()
    auth.init_auth()
    auth.bootstrap_admin()
    for folder in _audit_folders():
        try:
            db.ingest_audit(folder)
        except Exception:
            pass


@app.get("/api/config")
def get_config():
    return {
        "version": "3.0",
        "results_dir": str(RESULTS_DIR),
        "script_path": str(SCRIPT_PATH),
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.get("/api/audits")
def list_audits():
    audits = []
    if RESULTS_DIR.exists():
        for child in RESULTS_DIR.iterdir():
            if child.is_dir() and child.name.startswith("Auditoria_"):
                audits.append(build_audit_meta(child))
    audits.sort(key=lambda a: a["folder"], reverse=True)
    return {"audits": audits}


@app.post("/api/audits/cleanup")
def cleanup_audits(request: Request):
    """Elimina todas las carpetas Auditoria_* y los estados viejos de .runs."""
    # No limpiar mientras haya auditorias en curso (borraria la carpeta activa).
    # Un estado "running" solo cuenta si se escribio recientemente; un archivo viejo
    # es huella de una ejecucion matada/cancelada y no debe bloquear el limpieza.
    active = []
    now_ts = datetime.now().timestamp()
    for sf in RUNS_DIR.glob("*.json"):
        try:
            data = read_json(sf) or {}
        except Exception:
            continue
        if not (isinstance(data, dict) and data.get("phase") == "running"):
            continue
        try:
            age_min = (now_ts - sf.stat().st_mtime) / 60
        except OSError:
            continue
        if age_min <= 15:
            active.append(sf.stem)
    if active:
        raise HTTPException(
            status_code=409,
            detail="Hay auditorias en curso; cancele o espere a que terminen antes de limpiar.",
        )

    removed_folders = 0
    removed_ids: list[str] = []
    removed_files = 0
    freed_bytes = 0
    if RESULTS_DIR.exists():
        for child in RESULTS_DIR.iterdir():
            if child.is_dir() and child.name.startswith("Auditoria_"):
                try:
                    freed_bytes += sum(
                        f.stat().st_size for f in child.rglob("*") if f.is_file()
                    )
                    shutil.rmtree(child)
                    removed_folders += 1
                    removed_ids.append(child.name)
                except OSError:
                    pass
    for pattern in ("*.json", "launcher_*.ps1"):
        for f in RUNS_DIR.glob(pattern):
            try:
                freed_bytes += f.stat().st_size
                f.unlink()
                removed_files += 1
            except OSError:
                pass

    db.forget_audits(removed_ids)

    return {
        "audits_removed": removed_folders,
        "run_files_removed": removed_files,
        "freed_mb": round(freed_bytes / (1024 * 1024), 2),
    }

def _safe_audit_dir(audit_id: str) -> Optional[Path]:
    """Resuelve la carpeta de una auditoria validando prefijo y contencion (anti path traversal)."""
    if not audit_id or not audit_id.startswith("Auditoria_"):
        return None
    base = RESULTS_DIR.resolve()
    folder = (RESULTS_DIR / audit_id).resolve()
    try:
        folder.relative_to(base)
    except ValueError:
        return None
    return folder if folder.is_dir() else None


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str):
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")

    meta = build_audit_meta(folder)
    meta["threats"] = sorted(
        load_threats(folder),
        key=lambda t: SEVERITY_ORDER.get((t.get("severity") or "LOW").upper(), 9),
    )
    meta["recommendations"] = parse_recommendations(folder / "RESUMEN_EJECUTIVO.txt")
    meta["trend"] = compute_trend(folder)
    return meta


def _audit_folders() -> list:
    """Auditorias ordenadas de mas antigua a mas nueva (el nombre lleva el timestamp)."""
    if not RESULTS_DIR.exists():
        return []
    return sorted(
        [c for c in RESULTS_DIR.iterdir() if c.is_dir() and c.name.startswith("Auditoria_")],
        key=lambda p: p.name,
    )


def compute_trend(folder: Path) -> dict:
    """Diff de amenazas entre esta auditoria y la inmediatamente anterior.

    La comparacion usa la firma normalizada (ThreatType + descripcion sin PID),
    no la descripcion cruda: un PID distinto no es una amenaza nueva.
    """
    folders = _audit_folders()
    try:
        idx = folders.index(folder)
    except ValueError:
        return {"previous": None, "status": "primera auditoria"}
    if idx == 0:
        return {"previous": None, "status": "primera auditoria"}

    prev = folders[idx - 1]
    prev_meta = build_audit_meta(prev)
    cur_meta = build_audit_meta(folder)

    cur_sigs = {t["signature"] for t in load_threats(folder) if t.get("signature")}
    prev_sigs = {t["signature"] for t in load_threats(prev) if t.get("signature")}
    cur_threats = {t["signature"]: t for t in load_threats(folder) if t.get("signature")}
    prev_threats = {t["signature"]: t for t in load_threats(prev) if t.get("signature")}

    new = [cur_threats[s] for s in sorted(cur_sigs - prev_sigs)]
    resolved = [prev_threats[s] for s in sorted(prev_sigs - cur_sigs)]
    persistent = sorted(cur_sigs & prev_sigs)

    return {
        "previous": prev.name,
        "previous_threats": prev_meta["threats_count"],
        "previous_risk": prev_meta["risk_level"],
        "previous_suppressed": len(prev_meta["suppressed"]),
        "new": new,
        "resolved": resolved,
        "persistent": len(persistent),
        "delta": cur_meta["threats_count"] - prev_meta["threats_count"],
        "risk_change": (prev_meta["risk_level"] if prev_meta["risk_level"] != cur_meta["risk_level"] else "sin cambio"),
    }

@app.get("/api/audits/{audit_id}/trend")
def audit_trend(audit_id: str):
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")
    # El diff de carpetas dice que cambio entre dos ejecuciones; la base de datos
    # dice desde cuando existe el hallazgo y si se repite.
    result = compute_trend(folder)
    result["baseline"] = db.audit_context(audit_id)
    return result


# ---------------------------------------------------------------------------
# Baseline (SQLite)
# ---------------------------------------------------------------------------

@app.get("/api/baseline")
def get_baseline():
    """Estado acumulado de todas las auditorias indexadas."""
    return db.baseline()


@app.get("/api/threats")
def get_threats(status: Optional[str] = None, limit: int = 200, overdue: bool = False):
    """Hallazgos distincts con primera/ultima aparicion, ocurrencias y vencimiento."""
    return {"threats": db.threat_list(status=status, limit=limit, overdue_only=overdue)}


@app.get("/api/sla")
def get_sla():
    """Plazos por severidad y hallazgos vencidos."""
    return db.sla_report()


class SlaRequest(BaseModel):
    sla_days: Optional[int] = None


@app.patch("/api/threats/{signature}/sla")
def set_threat_sla(signature: str, req: SlaRequest):
    try:
        updated = db.set_sla(signature, req.sla_days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if updated is None:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado en la baseline")
    return updated


class StatusRequest(BaseModel):
    status: str
    note: str = ""


@app.patch("/api/threats/{signature}/status")
def set_threat_status(signature: str, req: StatusRequest, request: Request):
    """Triage de un hallazgo: open, investigating, accepted, false_positive, resolved."""
    try:
        updated = db.set_status(signature, req.status.lower(), req.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if updated is None:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado en la baseline")
    auth.record_event(
        getattr(request.state, "user", {}).get("username"),
        "triage",
        f"{signature} -> {req.status.lower()}",
        request.client.host if request.client else "",
    )
    return {"threat": updated, "allowlist_entry": updated.get("allowlist_entry")}


@app.post("/api/baseline/reingest")
def reingest_baseline():
    """Reconstruye la base desde las carpetas Auditoria_* (si se borro el .db)."""
    return db.reingest_all(RESULTS_DIR)


@app.get("/api/trend")
def trend_series():
    """Serie temporal de todas las auditorias: amenazas, riesgo y suprimidas."""
    series = []
    for f in _audit_folders():
        meta = build_audit_meta(f)
        series.append(
            {
                "id": meta["id"],
                "folder": meta["folder"],
                "threats": meta["threats_count"],
                "risk": meta["risk_level"],
                "suppressed": len(meta["suppressed"]),
                "critical": meta["severity_counts"].get("CRITICAL", 0),
                "high": meta["severity_counts"].get("HIGH", 0),
                "medium": meta["severity_counts"].get("MEDIUM", 0),
                "low": meta["severity_counts"].get("LOW", 0),
                "duration": meta["summary"].get("duracion", ""),
            }
        )
    return {"series": series}


@app.get("/api/audits/{audit_id}/modules/{module_name}")
def get_module(audit_id: str, module_name: str):
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")

    mdir = (folder / module_name).resolve()
    try:
        mdir.relative_to(folder.resolve())
    except ValueError:
        raise HTTPException(status_code=404, detail="Modulo no encontrado")
    if not mdir.is_dir():
        raise HTTPException(status_code=404, detail="Modulo no encontrado")

    datasets = []
    for json_file in sorted(mdir.glob("*.json")):
        data = read_json(json_file)
        if data is None:
            continue
        datasets.append(
            {
                "name": json_file.stem,
                "title": humanize(json_file.stem),
                "data": data,
                "is_list": isinstance(data, list),
            }
        )

    return {
        "name": module_name,
        "title": MODULE_TITLES.get(module_name, module_name),
        "datasets": datasets,
    }


# ---------------------------------------------------------------------------
# Descargas de reporte (JSON / CSV / PDF)
# ---------------------------------------------------------------------------


def _threats_sorted(folder: Path) -> list:
    return sorted(
        load_threats(folder),
        key=lambda t: SEVERITY_ORDER.get((t.get("severity") or "LOW").upper(), 9),
    )


def _attachment(filename: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


@app.get("/api/audits/{audit_id}/download/json")
def download_audit_json(audit_id: str):
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")

    meta = build_audit_meta(folder)
    meta["threats"] = _threats_sorted(folder)
    meta["recommendations"] = parse_recommendations(folder / "RESUMEN_EJECUTIVO.txt")
    payload = {
        "formato": "security-audit-export",
        "version": "3.0",
        "generado": datetime.now().isoformat(),
        "auditoria": meta,
    }
    return JSONResponse(
        content=payload,
        media_type="application/json; charset=utf-8",
        headers=_attachment(f"{audit_id}.json"),
    )


@app.get("/api/audits/{audit_id}/download/csv")
def download_audit_csv(audit_id: str):
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")

    threats = _threats_sorted(folder)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "severity", "type", "description", "details", "mitre_technique", "mitre_tactic"])
    for t in threats:
        details = t.get("details")
        if not isinstance(details, str):
            details = json.dumps(details, ensure_ascii=False)
        writer.writerow(
            [
                t.get("timestamp", ""),
                t.get("severity", ""),
                t.get("type", ""),
                t.get("description", ""),
                details or "",
                t.get("mitre_technique", ""),
                t.get("mitre_tactic", ""),
            ]
        )
    return Response(
        content="\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers=_attachment(f"{audit_id}_amenazas.csv"),
    )


@app.get("/api/audits/{audit_id}/download/log")
def download_audit_log(audit_id: str):
    """Exporta la auditoria como log unificado JSON Lines (.jsonl).

    Contrato de correlacion (lo que lee el Visor de Logs Unificado y cualquier
    pipeline posterior): una linea JSON por evento con campos
    ts / level / msg / source. Nivel normalizado: CRIT, ERR, WRN, INF.
    Orden cronologico por timestamp del evento.
    """
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")

    meta = build_audit_meta(folder)
    s = meta.get("summary") or {}
    counts = meta.get("severity_counts") or {}
    level_map = {"CRITICAL": "CRIT", "HIGH": "ERR", "MEDIUM": "WRN", "LOW": "INF"}

    def emit(ts: str, level: str, msg: str) -> dict:
        return {"ts": ts or "", "level": level, "msg": msg, "source": "ps-audit"}

    events = []
    if s.get("fecha_inicio"):
        events.append(
            emit(
                s["fecha_inicio"],
                "INF",
                f"Auditoria iniciada: sistema {s.get('sistema', '?')}, "
                f"usuario {s.get('usuario', '?')}, privilegios {s.get('privilegios', '?')}",
            )
        )

    threats = load_threats(folder)
    threats.sort(key=lambda t: str(t.get("timestamp") or ""))
    for t in threats:
        sev = (t.get("severity") or "LOW").upper()
        level = level_map.get(sev, "INF")
        desc = t.get("description") or ""
        events.append(
            emit(
                str(t.get("timestamp") or ""),
                level,
                f"[{sev}] {t.get('type', 'Amenaza')} - {desc}",
            )
        )

    if s.get("fecha_fin"):
        events.append(
            emit(
                s["fecha_fin"],
                "INF",
                f"Auditoria finalizada: {s.get('modulos', '?')} modulos, "
                f"{meta.get('threats_count', 0)} amenazas "
                f"(CRITICAL {counts.get('CRITICAL', 0)}, HIGH {counts.get('HIGH', 0)}, "
                f"MEDIUM {counts.get('MEDIUM', 0)}, LOW {counts.get('LOW', 0)}), "
                f"riesgo {meta.get('risk_level', '?')}",
            )
        )

    content = "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n"
    return Response(
        content=content,
        media_type="application/x-ndjson; charset=utf-8",
        headers=_attachment(f"{audit_id}_unified.jsonl"),
    )


@app.get("/api/audits/{audit_id}/download/pdf")
def download_audit_pdf(audit_id: str):
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")

    meta = build_audit_meta(folder)
    threats = _threats_sorted(folder)
    recs = parse_recommendations(folder / "RESUMEN_EJECUTIVO.txt")
    s = meta.get("summary") or {}
    counts = meta.get("severity_counts") or {}

    def latin(v) -> str:
        return str(v).encode("latin-1", "replace").decode("latin-1")

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, latin("Auditoria de Seguridad Empresarial"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, latin(audit_id), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, latin(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, latin("Resumen"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for label, key in (
        ("Sistema", "sistema"),
        ("Usuario", "usuario"),
        ("Privilegios", "privilegios"),
        ("Fecha inicio", "fecha_inicio"),
        ("Duracion", "duracion"),
        ("Modulos", "modulos"),
    ):
        pdf.cell(0, 6, latin(f"{label}: {s.get(key, '-')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, latin(f"Nivel de riesgo: {meta.get('risk_level', '-')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, latin("Amenazas por severidad"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        pdf.cell(0, 6, latin(f"{sev}: {counts.get(sev, 0)}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    if recs:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, latin("Recomendaciones"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for i, r in enumerate(recs, 1):
            pdf.multi_cell(0, 5, latin(f"{i}. {r}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, latin(f"Amenazas detectadas ({len(threats)})"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 9)
    for t in threats:
        line = f"[{t.get('severity', '-')}] {t.get('type', '-')} - {t.get('description', '')}"
        pdf.multi_cell(0, 5, latin(line), new_x="LMARGIN", new_y="NEXT")

    return Response(
        content=bytes(pdf.output()),
        media_type="application/pdf",
        headers=_attachment(f"{audit_id}_reporte.pdf"),
    )


def parse_suppressed(path: Path) -> list:
    """Extrae las amenazas suprimidas por la allowlist del RESUMEN_EJECUTIVO.txt.

    No se ocultan: una supresion sin justificacion es un hallazgo perdido.
    """
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
                current = {
                    "severity": m.group(1),
                    "type": m.group(2),
                    "description": desc,
                    "MitreTechnique": mitre.group(1) if mitre else "",
                }
                items.append(current)
        elif line.startswith("Motivo:") and current is not None:
            m = re.match(r"^Motivo: (.*?) \[allowlist: (.*)\]$", line)
            if m:
                current["reason"] = m.group(1)
                current["allowlist_id"] = m.group(2)
    return items


def parse_coverage_gaps(path: Path) -> list:
    """Extrae las comprobaciones omitidas de la seccion COBERTURA del resumen."""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    match = re.search(r"^COBERTURA DE LA AUDITORIA\s*$(.*?)(?=^HALLAZGOS|^RECOMENDACIONES)", text, re.MULTILINE | re.DOTALL)
    if not match:
        return []
    return [line.strip()[2:] for line in match.group(1).splitlines() if line.strip().startswith("- Omision:")]


def parse_recommendations(path: Path) -> list:
    """Extrae las recomendaciones del RESUMEN_EJECUTIVO.txt."""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    match = re.search(r"^RECOMENDACIONES\s*$(.*?)(?:\Z)", text, re.MULTILINE | re.DOTALL)
    if not match:
        return []
    recs = []
    for line in match.group(1).splitlines():
        line = line.strip()
        if line.startswith("*"):
            recs.append(line.lstrip("* ").strip())
    return recs


class AllowlistRequest(BaseModel):
    id: Optional[str] = None
    threat_type: str = ""
    process: str = ""
    path: str = ""
    ports: list[int] = []
    reason: str = ""


@app.get("/api/allowlist")
def get_allowlist():
    """Reglas derivadas del triage (las built-in viven en el script PowerShell)."""
    return {"entries": db.list_allowlist()}


@app.post("/api/allowlist")
def create_allowlist(req: AllowlistRequest):
    try:
        return db.add_allowlist_entry(req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/allowlist/{entry_id}")
def delete_allowlist(entry_id: str):
    if not db.remove_allowlist_entry(entry_id):
        raise HTTPException(status_code=404, detail="Entrada no encontrada")
    return {"deleted": entry_id}


# ---------------------------------------------------------------------------
# Ejecucion de auditorias
# ---------------------------------------------------------------------------

class RunRequest(BaseModel):
    elevated: bool = False


def _status_file(run_id: str) -> Path:
    return RUNS_DIR / f"{run_id}.json"


def _read_status(run_id: str) -> dict:
    path = _status_file(run_id)
    if not path.exists():
        return {"phase": "starting", "percent": 0}
    data = read_json(path)
    return data if isinstance(data, dict) else {"phase": "unknown"}


def _encode_ps_command(script: str) -> str:
    """Codifica un comando PowerShell en base64 UTF-16LE para -EncodedCommand."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


@app.post("/api/audits/run")
def run_audit(req: RunRequest, request: Request):
    run_id = uuid.uuid4().hex[:12]
    status_file = _status_file(run_id)
    auth.record_event(
        getattr(request.state, "user", {}).get("username"),
        "audit_run",
        f"run_id={run_id} elevated={req.elevated}",
        request.client.host if request.client else "",
    )

    # La allowlist generada por el triage se pasa al script: sin esto, marcar un FP
    # en la UI no cambia nada en la siguiente ejecucion.
    allowlist_file = RUNS_DIR / f"allowlist_{run_id}.json"
    try:
        db.write_allowlist_file(allowlist_file)
    except OSError:
        allowlist_file = None

    ps_args = [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", str(SCRIPT_PATH),
        "-Headless",
        "-ResultPath", str(RESULTS_DIR),
        "-StatusFile", str(status_file),
    ]
    if allowlist_file:
        ps_args += ["-AllowlistPath", str(allowlist_file)]

    if req.elevated:
        launcher = RUNS_DIR / f"launcher_{run_id}.ps1"
        launcher.write_text(
            "$launcherPath = $PSCommandPath\n"
            f"& '{SCRIPT_PATH}' -Headless -ResultPath '{RESULTS_DIR}' "
            f"-StatusFile '{status_file}'"
            + (f" -AllowlistPath '{allowlist_file}'" if allowlist_file else "")
            + "\n"
            "Remove-Item -LiteralPath $launcherPath -Force -ErrorAction SilentlyContinue\n",
            encoding="utf-8",
        )
        outer_cmd = (
            "Start-Process powershell.exe -Verb RunAs "
            f"-ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"{launcher}\"'"
        )
        cmd = [
            "powershell.exe", "-NoProfile",
            "-EncodedCommand", _encode_ps_command(outer_cmd),
        ]
    else:
        cmd = ["powershell.exe"] + ps_args

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(BASE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"No se pudo iniciar PowerShell: {exc}")

    with RUNS_LOCK:
        RUNS[run_id] = {
            "run_id": run_id,
            "process": proc,
            "elevated": req.elevated,
            "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    return {"run_id": run_id, "elevated": req.elevated}


@app.get("/api/runs/{run_id}")
def get_run_status(run_id: str):
    with RUNS_LOCK:
        meta = RUNS.get(run_id)
    status = _read_status(run_id)

    finished = status.get("phase") in ("done", "error")
    if meta is not None and not finished:
        finished = meta["process"].poll() is not None and status.get("phase") in ("done", "error")

    # Indexar la auditoria terminada en la baseline: sin esto la tendencia solo
    # compara carpetas sueltas y se pierde al limpiar el historial.
    if finished and status.get("phase") == "done" and status.get("auditPath"):
        audit_folder = Path(str(status["auditPath"])).resolve()
        if audit_folder.is_dir():
            try:
                db.ingest_audit(audit_folder)
            except Exception:
                pass

    return {"run_id": run_id, "status": status, "finished": finished}


@app.get("/api/runs")
def list_runs():
    with RUNS_LOCK:
        return {"runs": list(RUNS.keys())}


@app.post("/api/runs/{run_id}/cancel")
def cancel_run(run_id: str, request: Request):
    auth.record_event(
        getattr(request.state, "user", {}).get("username"),
        "audit_cancel",
        f"run_id={run_id}",
        request.client.host if request.client else "",
    )
    with RUNS_LOCK:
        meta = RUNS.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="Ejecucion no encontrada")
    try:
        if meta["elevated"]:
            subprocess.run(
                ["taskkill", "/PID", str(meta["process"].pid), "/T", "/F"],
                capture_output=True,
            )
        else:
            meta["process"].terminate()
    except OSError:
        pass
    return {"cancelled": True}


# ---------------------------------------------------------------------------
# IA: veredictos Jev + explicaciones tecnicas LLM local (enriquece el informe)
# ---------------------------------------------------------------------------

import ai_enrich  # noqa: E402  (mismo directorio; import aqui para no mover el bloque de arriba)


class AiConfigRequest(BaseModel):
    jev_enabled: Optional[bool] = None
    jev_api_key: Optional[str] = None
    llm_enabled: Optional[bool] = None
    llm_base_url: Optional[str] = None
    llm_model: Optional[str] = None
    # LAYA local (laya-serve): segunda opcion conmutable (cloud|local).
    backend: Optional[str] = None
    laya_base_url: Optional[str] = None
    laya_model: Optional[str] = None


class AiTestRequest(BaseModel):
    target: str  # "jev" | "llm"


class AiEnrichRequest(BaseModel):
    audit_id: str


@app.get("/api/ai/config")
def get_ai_config():
    return ai_enrich.get_ai_config()


@app.post("/api/ai/config")
def set_ai_config(req: AiConfigRequest):
    patch = req.model_dump(exclude_none=True)
    if "llm_base_url" in patch and not ai_enrich.is_loopback_url(patch["llm_base_url"]):
        raise HTTPException(
            status_code=400,
            detail="El LLM local solo puede apuntar a loopback (127.0.0.1 / localhost / ::1)",
        )
    if "laya_base_url" in patch and not ai_enrich.is_loopback_url(patch["laya_base_url"]):
        raise HTTPException(
            status_code=400,
            detail="El backend LAYA local solo puede apuntar a loopback (127.0.0.1 / localhost / ::1)",
        )
    if "backend" in patch and patch["backend"] not in ("cloud", "local"):
        raise HTTPException(status_code=400, detail="backend debe ser 'cloud' o 'local'")
    return ai_enrich.set_ai_config(patch)


@app.post("/api/ai/test")
def test_ai(req: AiTestRequest):
    if req.target == "jev":
        return ai_enrich.test_jev()
    if req.target == "llm":
        return ai_enrich.test_llm()
    raise HTTPException(status_code=400, detail="target debe ser 'jev' o 'llm'")


@app.post("/api/ai/enrich")
def enrich_ai(req: AiEnrichRequest):
    folder = _safe_audit_dir(req.audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")
    meta = build_audit_meta(folder)
    return ai_enrich.enrich_audit(folder, meta)


@app.get("/api/ai/enrich/{audit_id}")
def get_ai_enrich(audit_id: str):
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")
    data = read_json(folder / "IA_ENRICH.json")
    if not isinstance(data, dict):
        raise HTTPException(status_code=404, detail="Sin enriquecimiento IA guardado")
    return data


# ---------------------------------------------------------------------------
# Autenticacion y panel de administrador
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "3.0"}


@app.post("/api/auth/login")
def auth_login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else ""
    session = auth.login(req.username, req.password, ip)
    if session is None:
        user = auth.get_user(req.username)
        if user and user.get("locked_until"):
            raise HTTPException(
                status_code=429,
                detail="Cuenta bloqueada temporalmente por intentos fallidos. Espera 15 minutos.",
            )
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    response = JSONResponse({"username": session["username"], "role": session["role"], "expires_at": session["expires_at"]})
    response.set_cookie(
        key="audit_session",
        value=session["token"],
        httponly=True,
        samesite="lax",
        max_age=auth.SESSION_TTL_MINUTES * 60,
        path="/",
    )
    return response


@app.post("/api/auth/logout")
def auth_logout(request: Request):
    token = request.cookies.get("audit_session", "")
    user = request.state.user if hasattr(request.state, "user") else None
    auth.revoke_session(token)
    auth.record_event(user.get("username") if user else None, "logout", "")
    response = JSONResponse({"logged_out": True})
    response.delete_cookie("audit_session")
    return response


@app.get("/api/auth/me")
def auth_me(request: Request):
    return request.state.user


def _require_admin(request: Request) -> dict[str, Any]:
    user = getattr(request.state, "user", None)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Se requiere rol admin")
    return user


class UserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


@app.get("/api/admin/users")
def admin_users(request: Request):
    _require_admin(request)
    return {"users": auth.list_users(), "session_ttl_minutes": auth.SESSION_TTL_MINUTES}


@app.post("/api/admin/users")
def admin_create_user(req: UserRequest, request: Request):
    _require_admin(request)
    try:
        return auth.create_user(req.username, req.password, req.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/admin/users/{username}")
def admin_delete_user(username: str, request: Request):
    admin = _require_admin(request)
    if username.lower() == admin["username"]:
        raise HTTPException(status_code=400, detail="No puedes borrar tu propio usuario")
    if not auth.delete_user(username):
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {"deleted": username}


@app.patch("/api/admin/users/{username}/password")
def admin_reset_password(username: str, req: UserRequest, request: Request):
    _require_admin(request)
    try:
        if not auth.reset_password(username, req.password):
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"reset": username}


@app.get("/api/admin/sessions")
def admin_sessions(request: Request, all_sessions: bool = False):
    _require_admin(request)
    return {"sessions": auth.list_sessions(active_only=not all_sessions)}


@app.delete("/api/admin/sessions/{token}")
def admin_revoke_session(token: str, request: Request):
    _require_admin(request)
    if not auth.revoke_session(token):
        raise HTTPException(status_code=404, detail="Sesion no encontrada")
    auth.record_event(getattr(request.state, "user", {}).get("username"), "session_revoked", token[:8])
    return {"revoked": True}


@app.get("/api/admin/trail")
def admin_trail(request: Request, limit: int = 100):
    _require_admin(request)
    return {"trail": auth.trail(limit)}


# ---------------------------------------------------------------------------
# Integraciones: Splunk HEC, IOCs y capa MITRE Navigator
# ---------------------------------------------------------------------------


@app.get("/api/integrations")
def integrations_status():
    return integrations.integration_status()


@app.get("/api/audits/{audit_id}/iocs")
def audit_iocs(audit_id: str, enrich: bool = False):
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")
    threats = load_threats(folder)
    # Las suprimidas tambien aportan indicadores: un puerto en escucha sigue siendo
    # un puerto en escucha aunque la allowlist declare que es legitimo.
    threats = threats + parse_suppressed(folder / "RESUMEN_EJECUTIVO.txt")
    iocs = integrations.extract_iocs(threats)
    if enrich:
        iocs = [integrations.enrich_ioc(i) for i in iocs]
    return {"audit_id": audit_id, "count": len(iocs), "iocs": iocs}


@app.get("/api/audits/{audit_id}/navigator")
def audit_navigator(audit_id: str):
    """Capa del MITRE Navigator (formato de layer 2.1) para abrirla en attack.mitre.org."""
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")
    threats = load_threats(folder) + parse_suppressed(folder / "RESUMEN_EJECUTIVO.txt")
    layer = integrations.navigator_layer(f"Auditoria {audit_id}", threats)
    return JSONResponse(
        layer,
        headers={"Content-Disposition": f'attachment; filename="navigator_{audit_id}.json"'},
    )


@app.post("/api/audits/{audit_id}/splunk")
def audit_to_splunk(audit_id: str, request: Request):
    folder = _safe_audit_dir(audit_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada")
    meta = build_audit_meta(folder)
    result = integrations.push_to_splunk(meta, load_threats(folder) + meta["suppressed"])
    auth.record_event(
        getattr(request.state, "user", {}).get("username"),
        "splunk_push",
        f"{audit_id} -> {'ok' if result['ok'] else 'fallido'}",
    )
    return result


# ---------------------------------------------------------------------------
# Archivos estaticos (frontend)
# ---------------------------------------------------------------------------

ALLOWED_ORIGINS = {"http://127.0.0.1:8502", "http://localhost:8502"}


class SecurityMiddleware(BaseHTTPMiddleware):
    """Puerta CSRF (verificacion de Origin/Referer en mutaciones) y headers de seguridad."""

    async def dispatch(self, request, call_next):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.headers.get("origin", "")
            if not origin:
                referer = request.headers.get("referer", "")
                if referer:
                    parts = referer.split("/", 3)
                    origin = parts[0] + "//" + (parts[2] if len(parts) > 2 else "")
            if origin and origin not in ALLOWED_ORIGINS:
                return JSONResponse(status_code=403, content={"detail": "Origen no autorizado (CSRF)"})
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; base-uri 'self'; form-action 'self'",
        )
        return response


class NoCacheStaticMiddleware(BaseHTTPMiddleware):
    """Evita que el navegador cachee app.js/styles tras una actualizacion del backend."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if not request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


PUBLIC_PATHS = {"/api/health", "/api/auth/login"}


class AuthMiddleware(BaseHTTPMiddleware):
    """Sesion por cookie. Sin sesion, la API responde 401; la sesion caduca por
    inactividad, no por un plazo absoluto."""

    async def dispatch(self, request, call_next):
        path = request.url.path
        if path in PUBLIC_PATHS or not path.startswith("/api/"):
            return await call_next(request)
        token = request.cookies.get("audit_session", "")
        ip = request.client.host if request.client else ""
        session = auth.touch_session(token, ip) if token else None
        if session is None:
            return JSONResponse(status_code=401, content={"detail": "No hay sesion activa: iniciar sesion"})
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and session["role"] == "viewer":
            return JSONResponse(status_code=403, content={"detail": "Rol viewer: solo lectura"})
        request.state.user = session
        return await call_next(request)


app.add_middleware(SecurityMiddleware)
app.add_middleware(NoCacheStaticMiddleware)
app.add_middleware(AuthMiddleware)

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
