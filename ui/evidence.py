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
        return {"signed": False, "reason": "AUDIT_SIGN_KEY no definida en el entorno"}
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
