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

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from fpdf import FPDF

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
        "modules": modules,
    }


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="Auditoria de Seguridad Empresarial", version="3.0")


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
def cleanup_audits():
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
    return meta


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
    writer.writerow(["timestamp", "severity", "type", "description", "details"])
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
            ]
        )
    return Response(
        content="\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers=_attachment(f"{audit_id}_amenazas.csv"),
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
def run_audit(req: RunRequest):
    run_id = uuid.uuid4().hex[:12]
    status_file = _status_file(run_id)

    ps_args = [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", str(SCRIPT_PATH),
        "-Headless",
        "-ResultPath", str(RESULTS_DIR),
        "-StatusFile", str(status_file),
    ]

    if req.elevated:
        launcher = RUNS_DIR / f"launcher_{run_id}.ps1"
        launcher.write_text(
            "$launcherPath = $PSCommandPath\n"
            f"& '{SCRIPT_PATH}' -Headless -ResultPath '{RESULTS_DIR}' "
            f"-StatusFile '{status_file}'\n"
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

    return {"run_id": run_id, "status": status, "finished": finished}


@app.get("/api/runs")
def list_runs():
    with RUNS_LOCK:
        return {"runs": list(RUNS.keys())}


@app.post("/api/runs/{run_id}/cancel")
def cancel_run(run_id: str):
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


app.add_middleware(SecurityMiddleware)
app.add_middleware(NoCacheStaticMiddleware)

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
