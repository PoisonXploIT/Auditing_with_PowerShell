"""Integridad de la evidencia de auditoria.

Un informe sin checksums no es evidencia: cualquiera puede editar un JSON y nadie
lo detecta. El script PowerShell genera MANIFEST_EVIDENCIA.json (schema audit-evidence/1)
con el SHA-256 de cada fichero y un hash de root. Aqui se verifica ese manifiesto y
se firma la salida (PDF/CSV) con HMAC.

La clave de firma vive en la variable de entorno AUDIT_SIGN_KEY. Si no esta definida,
la firma se marca como "no firmada" en lugar de inventar una.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

SCHEMA = "audit-evidence/1"
MANIFEST_NAME = "MANIFEST_EVIDENCIA.json"


def _sign_key() -> Optional[str]:
    key = os.environ.get("AUDIT_SIGN_KEY", "").strip()
    return key or None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(folder: Path) -> Optional[dict[str, Any]]:
    path = folder / MANIFEST_NAME
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return None


def build_manifest(folder: Path) -> dict[str, Any]:
    """Reconstruir el manifiesto desde el disco (para auditorias previas al cambio)."""
    entries = []
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        if path.name in (MANIFEST_NAME, "IA_ENRICH.json"):
            continue
        entries.append(
            {
                "path": path.relative_to(folder).as_posix(),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    root = hashlib.sha256("".join(e["sha256"] for e in entries).encode("utf-8")).hexdigest()
    return {
        "schema": SCHEMA,
        "audit_id": folder.name,
        "file_count": len(entries),
        "total_bytes": sum(e["bytes"] for e in entries),
        "root_sha256": root,
        "files": entries,
    }


def verify_manifest(folder: Path) -> dict[str, Any]:
    """Comparar el manifiesto con lo que hay en disco. Devuelve discrepancias."""
    manifest = load_manifest(folder)
    if manifest is None:
        rebuilt = build_manifest(folder)
        return {
            "ok": True,
            "status": "sin_manifiesto",
            "reason": "Esta auditoria se genero antes de la funcionalidad de evidencia. "
                      "Se recalcula el hash de root; no se puede comparar contra el original.",
            "root_sha256": rebuilt["root_sha256"],
            "file_count": rebuilt["file_count"],
            "mismatches": [],
        }

    mismatches = []
    seen = set()
    for entry in manifest.get("files", []):
        # PowerShell escribe la ruta relativa con backslashes; normalizamos a posix
        # para comparar contra lo que da Path.relative_to.
        rel = entry["path"].replace("\\", "/")
        path = folder / rel
        seen.add(rel)
        if not path.exists():
            mismatches.append({"path": rel, "problem": "fichero ausente"})
            continue
        actual = sha256_file(path)
        if actual != entry["sha256"]:
            mismatches.append({"path": rel, "problem": "hash distinto"})

    extra = [
        p.relative_to(folder).as_posix()
        for p in folder.rglob("*")
        if p.is_file()
        and p.relative_to(folder).as_posix() not in seen
        and p.name not in (MANIFEST_NAME, "IA_ENRICH.json")
    ]
    for path in extra:
        mismatches.append({"path": path, "problem": "fichero no declarado en el manifiesto"})

    actual_hashes = []
    for entry in manifest.get("files", []):
        rel = entry["path"].replace(chr(92), "/")
        path = folder / rel
        if path.exists():
            actual_hashes.append(sha256_file(path))
    recomputed = hashlib.sha256("".join(actual_hashes).encode("utf-8")).hexdigest()

    return {
        "ok": not mismatches,
        "status": "integro" if not mismatches else "alterado",
        "root_sha256": manifest.get("root_sha256"),
        "root_recomputed": recomputed,
        "file_count": manifest.get("file_count"),
        "generated_at": manifest.get("generated_at"),
        "host": manifest.get("host"),
        "elevated": manifest.get("elevated"),
        "mismatches": mismatches,
    }


def sign_payload(payload: bytes) -> dict[str, Any]:
    key = _sign_key()
    if not key:
        return {
            "signed": False,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "reason": "AUDIT_SIGN_KEY no definida en el entorno: se puede comprobar el hash, no la autenticidad",
        }
    return {
        "signed": True,
        "algorithm": "HMAC-SHA256",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "signature": hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest(),
    }


def export_signature(folder: Path, filename: str) -> dict[str, Any]:
    path = folder / filename
    if not path.exists():
        return {"ok": False, "reason": f"{filename} no existe en la auditoria"}
    result = sign_payload(path.read_bytes())
    result["ok"] = True
    result["file"] = filename
    result["bytes"] = path.stat().st_size
    return result


def write_export_signature(folder: Path, filename: str) -> dict[str, Any]:
    """Escribir el sidecar <filename>.sig con el hash y la firma del export.

    Un PDF que se descarga sin firma se puede falsificar igual que el JSON original.
    El sidecar permite verificar el fichero fuera de la consola.
    """
    path = folder / filename
    if not path.exists():
        return {"ok": False, "reason": f"{filename} no existe en la auditoria"}
    payload = path.read_bytes()
    sig = sign_payload(payload)
    record = {
        "schema": "audit-export/1",
        "file": filename,
        "bytes": len(payload),
        "signed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        **sig,
    }
    (folder / (filename + ".sig")).write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


EXPORT_DIR_NAME = ".exports"


def _export_root() -> Path:
    default = Path(__file__).resolve().parent.parent / EXPORT_DIR_NAME
    return Path(os.environ.get("AUDIT_EXPORT_DIR", str(default)))


def signed_export(audit_id: str, filename: str, content: bytes) -> dict[str, Any]:
    """Escribir un export fuera de la carpeta de evidencia y firmarlo.

    Los exports van a .exports/ a proposito: son derivados, no evidencia original.
    Si se metieran en la carpeta de la auditoria, el manifiesto los marcaria como
    ficheros no declarados y la verificacion de integridad perderia sentido.
    """
    root = _export_root()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{audit_id}_{filename}"
    path.write_bytes(content)
    record = {
        "schema": "audit-export/1",
        "file": path.name,
        "bytes": len(content),
        "signed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        **sign_payload(content),
    }
    (root / (path.name + ".sig")).write_text(json.dumps(record, indent=2), encoding="utf-8")
    return {"path": path, "record": record}


def verify_signed_export(filename: str) -> dict[str, Any]:
    """Comparar un export descargado contra su sidecar .sig."""
    root = _export_root()
    path = root / filename
    sidecar = root / (filename + ".sig")
    if not path.exists():
        return {"ok": False, "status": "ausente", "reason": f"{filename} no existe en .exports/"}
    if not sidecar.exists():
        return {
            "ok": True,
            "status": "sin_firma",
            "reason": "Este export no tiene sidecar .sig: no se puede verificar su autenticidad.",
            "sha256": sha256_file(path),
        }
    try:
        record = json.loads(sidecar.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return {"ok": False, "status": "sidecar_invalido", "reason": "El .sig no es JSON valido"}

    actual = sha256_file(path)
    if record.get("sha256") != actual:
        return {"ok": False, "status": "alterado", "reason": "El fichero no coincide con su firma", "sha256": actual}

    key = _sign_key()
    if record.get("signed") and key:
        expected = hmac.new(key.encode("utf-8"), path.read_bytes(), hashlib.sha256).hexdigest()
        if expected != record.get("signature"):
            return {"ok": False, "status": "firma_invalida", "reason": "La firma no corresponde con la clave del entorno"}
    return {
        "ok": True,
        "status": "verificado",
        "sha256": actual,
        "signed": record.get("signed"),
        "signed_at": record.get("signed_at"),
    }
