"""Adaptador al SOC de Opervanta. Escrito, pero NO activado.

Condicion del plan: solo se enciende si los P0 de Opervanta estan cerrados. La
auditoria integral (2026-10-21) deja P0 abiertos en autorizacion de POST (SEC-01),
escape de atributos (SEC-02), ultimo administrador (ID-01), auditoria SQLite
(DATA-01) y antirreplay fail-open (SOC-01). Mientras eso no este cerrado, publicar
hallazgos de la auditoria en el SOC de Opervanta amplifica una superficie que aun
no esta resuelta.

Por eso `PILOOP_SOC_ENABLED` vale 0 por defecto: el codigo esta, los tests cubren
el contrato, y activarlo es una decision explícita del operador.

Contrato:
  PILOOP_SOC_DIR     carpeta del SOC (por defecto .soc/ dentro del repo)
  eventos.jsonl      una linea por evento
  severidades        info | baja | media | alta | critica

Mapeo de severidad:
  CRITICAL -> critica, HIGH -> alta, MEDIUM -> media, LOW -> baja
  hallazgos suprimidos por allowlist -> info (se declaran, no se ocultan)

No se duplica el envio a Splunk: Opervanta ya tiene su cola HEC con reintentos.
Este modulo escribe el outbox; quien consume el outbox decide el transporte.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

SCHEMA = "soc-event/1"
EVENTS_FILE = "eventos.jsonl"

SEVERITY_MAP = {
    "CRITICAL": "critica",
    "HIGH": "alta",
    "MEDIUM": "media",
    "LOW": "baja",
}
SOC_SEVERITIES = ("info", "baja", "media", "alta", "critica")

_TRUE = ("1", "true", "on", "si", "yes")


def soc_enabled() -> bool:
    """El adaptador esta apagado salvo que PILOOP_SOC_ENABLED diga lo contrario."""
    return os.environ.get("PILOOP_SOC_ENABLED", "0").strip().lower() in _TRUE


def soc_dir() -> Path:
    default = Path(__file__).resolve().parent.parent / ".soc"
    return Path(os.environ.get("PILOOP_SOC_DIR", str(default)))


def to_soc_severity(severity: str, suppressed: bool = False) -> str:
    if suppressed:
        return "info"
    return SEVERITY_MAP.get((severity or "LOW").upper(), "baja")


def event_id(threat: dict[str, Any]) -> str:
    """Identificador estable derivado de la Signature del hallazgo.

    La Signature ya normaliza PID y marcas de tiempo, asi que el mismo hallazgo
    detectado en dos ejecuciones produce el mismo event_id: el SOC puede deduplicar
    sin depender de cuando se ejecuto la auditoria.
    """
    signature = (threat.get("signature") or "").strip()
    if signature:
        return signature.upper()
    import hashlib

    norm = f"{threat.get('type', '')}|{threat.get('description', '')}".lower()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16].upper()


def build_events(audit_id: str, threats: list[dict[str, Any]], suppressed: Optional[list[dict[str, Any]]] = None) -> list[dict[str, Any]]:
    """Convertir los hallazgos de una auditoria en eventos del contrato del SOC."""
    events: list[dict[str, Any]] = []
    for threat in threats:
        events.append(
            {
                "schema": SCHEMA,
                "event_id": event_id(threat),
                "correlation_id": audit_id,
                "source": "Invoke-SecurityAudit",
                "severity": to_soc_severity(threat.get("severity", "LOW")),
                "type": threat.get("type") or "",
                "description": threat.get("description") or "",
                "mitre_technique": threat.get("mitre_technique") or "",
                "mitre_tactic": threat.get("mitre_tactic") or "",
                "suppressed": False,
                "observed_at": threat.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

    for item in suppressed or []:
        events.append(
            {
                "schema": SCHEMA,
                "event_id": event_id(item),
                "correlation_id": audit_id,
                "source": "Invoke-SecurityAudit",
                "severity": "info",
                "type": item.get("type") or "",
                "description": item.get("description") or "",
                "mitre_technique": item.get("mitre_technique") or item.get("mitre") or "",
                "mitre_tactic": item.get("mitre_tactic") or "",
                "suppressed": True,
                "reason": item.get("reason") or "allowlist local",
                "observed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    return events


def publish(audit_id: str, threats: list[dict[str, Any]], suppressed: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
    """Escribir los eventos en el outbox del SOC.

    Con PILOOP_SOC_ENABLED=0 no se escribe nada: se devuelve el conteo de lo que
    se publicaria, para que la consola pueda mostrar el estado sin efectos laterales.
    """
    events = build_events(audit_id, threats, suppressed)
    if not soc_enabled():
        return {
            "ok": True,
            "enabled": False,
            "written": 0,
            "pending": len(events),
            "reason": "PILOOP_SOC_ENABLED=0: el adaptador al SOC de Opervanta no esta activo (P0 abiertos)",
        }

    root = soc_dir()
    root.mkdir(parents=True, exist_ok=True)
    path = root / EVENTS_FILE
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        for event in events:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    return {
        "ok": True,
        "enabled": True,
        "written": len(events),
        "pending": 0,
        "path": str(path),
        "by_severity": {
            sev: sum(1 for e in events if e["severity"] == sev) for sev in SOC_SEVERITIES
        },
    }


def status() -> dict[str, Any]:
    root = soc_dir()
    path = root / EVENTS_FILE
    return {
        "enabled": soc_enabled(),
        "dir": str(root),
        "file": str(path),
        "exists": path.exists(),
        "events": sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip()) if path.exists() else 0,
        "note": "Opervanta tiene su propia cola HEC con reintentos: este adaptador no envia a Splunk.",
    }
