"""Integraciones externas: Splunk HEC, extraccion de IOCs y capa MITRE Navigator.

Todo es fail-safe: si la integracion no esta configurada, se informa del motivo y
no se interrumpe la auditoria. Las credenciales se leen de variables de entorno de
usuario; nunca se escriben en el repo.

  SPLUNK_HEC_URL    p. ej. http://127.0.0.1:8088
  SPLUNK_HEC_TOKEN  token del collector
  VIRUSTOTAL_API_KEY (opcional, para enriquecer IOCs)
"""

from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Optional

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"puerto (\d+)", re.IGNORECASE)
PROC_RE = re.compile(r"proceso '([^']+)'", re.IGNORECASE)


def _env(name: str, default: str = "") -> Optional[str]:
    value = os.environ.get(name, default).strip()
    return value or None


def integration_status() -> dict[str, Any]:
    """Que esta configurado y que no. Sin exponer valores."""
    return {
        "splunk": {
            "configured": bool(_env("SPLUNK_HEC_URL") and _env("SPLUNK_HEC_TOKEN")),
            "url": _env("SPLUNK_HEC_URL"),
            "token": "definido" if _env("SPLUNK_HEC_TOKEN") else "no definido",
        },
        "virustotal": {
            "configured": bool(_env("VIRUSTOTAL_API_KEY")),
            "key": "definida" if _env("VIRUSTOTAL_API_KEY") else "no definida",
        },
        "navigator": {"configured": True},
    }


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------

def extract_iocs(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convierte hallazgos en indicadores utilizables (IP, puerto, proceso, ruta)."""
    seen: set[tuple[str, str]] = set()
    iocs: list[dict[str, Any]] = []
    for t in threats:
        details = t.get("Details") or {}
        description = t.get("Description") or t.get("description") or ""
        candidates = []

        for key in ("LocalAddress", "RemoteAddress", "Address", "IP"):
            value = details.get(key)
            if value and IP_RE.search(str(value)):
                candidates.append(("ip", str(value).strip()))

        for key in ("LocalPort", "RemotePort", "Port"):
            if details.get(key):
                candidates.append(("port", str(details[key])))

        port_match = PORT_RE.search(description)
        if port_match:
            candidates.append(("port", port_match.group(1)))

        # La descripcion tambien lleva el proceso cuando los Details no estan
        # (es el caso de las amenazas suprimidas por allowlist).
        proc_match = PROC_RE.search(description)
        if proc_match:
            candidates.append(("process", proc_match.group(1).lower()))

        for key in ("ProcessName", "Name"):
            if details.get(key):
                candidates.append(("process", str(details[key]).lower()))

        for key in ("ProcessPath", "Path", "CommandLine"):
            value = details.get(key)
            if value:
                candidates.append(("path", str(value)))

        for kind, value in candidates:
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            iocs.append(
                {
                    "type": kind,
                    "value": value,
                    "severity": (t.get("Severity") or t.get("severity") or "LOW").upper(),
                    "threat_type": t.get("ThreatType") or t.get("type") or "",
                    "mitre_technique": t.get("MitreTechnique") or "",
                    "mitre_tactic": t.get("MitreTactic") or "",
                }
            )
    return iocs


def enrich_ioc(ioc: dict[str, Any], timeout: int = 10) -> dict[str, Any]:
    """Enriquecimiento opcional con VirusTotal. Sin clave, devuelve el IOC sin tocar la red."""
    key = _env("VIRUSTOTAL_API_KEY")
    enriched = dict(ioc)
    enriched["enrichment"] = None
    if not key:
        enriched["enrichment_note"] = "VIRUSTOTAL_API_KEY no definida: no se enriquece"
        return enriched

    if ioc["type"] == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc['value']}"
    elif ioc["type"] == "path" and re.search(r"[a-f0-9]{32,64}", ioc["value"]):
        url = f"https://www.virustotal.com/api/v3/files/{ioc['value']}"
    else:
        enriched["enrichment_note"] = "tipo de IOC no enriquecible"
        return enriched

    try:
        req = urllib.request.Request(url, headers={"x-apikey": key})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        attrs = data.get("data", {}).get("attributes", {})
        enriched["enrichment"] = {
            "source": "virustotal",
            "detection_ratio": attrs.get("statistics", {}),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "name": attrs.get("name"),
        }
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError) as exc:
        enriched["enrichment_note"] = f"enriquecimiento fallido: {exc}"
    return enriched


# ---------------------------------------------------------------------------
# Splunk HEC
# ---------------------------------------------------------------------------

def splunk_event(audit_meta: dict[str, Any], threats: list[dict[str, Any]]) -> dict[str, Any]:
    suppressed = audit_meta.get("suppressed", 0)
    suppressed_count = len(suppressed) if isinstance(suppressed, list) else int(suppressed or 0)

    event: dict[str, Any] = {
        "time": datetime.now().timestamp(),
        "source": "Invoke-SecurityAudit",
        "sourcetype": "audit:security",
        "event": {
            "audit_id": audit_meta.get("id") or audit_meta.get("audit_id"),
            "risk": audit_meta.get("risk_level") or audit_meta.get("risk"),
            "threats": audit_meta.get("threats_count") or audit_meta.get("threats", 0),
            "suppressed": suppressed_count,
            "severity_counts": audit_meta.get("severity_counts", {}),
            "details": [
                {
                    "type": t.get("ThreatType") or t.get("type"),
                    "severity": (t.get("Severity") or t.get("severity") or "LOW").upper(),
                    "description": t.get("Description") or t.get("description"),
                    "mitre": t.get("MitreTechnique") or t.get("mitre") or "",
                }
                for t in threats
            ],
        },
    }
    # Si no se indica indice, Splunk usa el asignado a la fuente HEC (en este caso
    # 'main'). Forzar uno que no existe da 400 "Incorrect index".
    index = _env("SPLUNK_HEC_INDEX")
    if index:
        event["index"] = index
    return event


def _post_hec(event: dict[str, Any], timeout: int = 10) -> dict[str, Any]:
    url = _env("SPLUNK_HEC_URL")
    token = _env("SPLUNK_HEC_TOKEN")
    if not url or not token:
        return {"ok": False, "reason": "SPLUNK_HEC_URL o SPLUNK_HEC_TOKEN no definidos en el entorno"}

    payload = json.dumps(event).encode("utf-8")
    try:
        req = urllib.request.Request(
            url.rstrip("/") + "/services/collector/event",
            data=payload,
            headers={"Authorization": f"Splunk {token}", "Content-Type": "application/json"},
        )
        # Splunk local viene con certificado autofirmado: sin esto, la conexion
        # HTTPS falla por verificacion de cadena de confianza.
        context = None
        if _env("SPLUNK_HEC_INSECURE", "0").lower() in ("1", "true", "si", "yes"):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            body = resp.read().decode("utf-8")
        return {"ok": True, "status": resp.status, "response": json.loads(body) if body else {}}
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError) as exc:
        reason = f"Splunk no responde: {exc}"
        if "certificate" in str(exc).lower() and not _env("SPLUNK_HEC_INSECURE"):
            reason += ". Si Splunk es local con certificado autofirmado, define SPLUNK_HEC_INSECURE=1"
        return {"ok": False, "reason": reason}


def push_to_splunk(audit_meta: dict[str, Any], threats: list[dict[str, Any]], timeout: int = 10) -> dict[str, Any]:
    return _post_hec(splunk_event(audit_meta, threats), timeout)


# ---------------------------------------------------------------------------
# MITRE Navigator
# ---------------------------------------------------------------------------

def navigator_layer(name: str, threats: list[dict[str, Any]]) -> dict[str, Any]:
    """Capa del Navigator: una tecnica por hallazgo, con score por ocurrencias."""
    scores: dict[str, dict[str, Any]] = {}
    for t in threats:
        tech = t.get("MitreTechnique")
        if not tech:
            continue
        entry = scores.setdefault(
            tech,
            {"techniqueID": tech, "score": 0, "comment": "", "tactic": t.get("MitreTactic") or ""},
        )
        entry["score"] += 1
        entry["comment"] = (entry["comment"] + "; " + (t.get("Description") or "")).strip("; ")

    layer = {
        "version": "2.1",
        "name": name,
        "domain": "attack-enterprise",
        "created": datetime.now().isoformat(),
        "techniques": sorted(scores.values(), key=lambda x: (-x["score"], x["techniqueID"])),
    }
    return layer


def _overdue_items(report: dict[str, Any]) -> list[dict[str, Any]]:
    """sla_report() devuelve 'overdue' como contador y 'overdue_list' como detalle."""
    items = report.get("overdue_list")
    if isinstance(items, list):
        return items
    raw = report.get("overdue")
    return raw if isinstance(raw, list) else []


def sla_alert_event(report: dict[str, Any]) -> dict[str, Any]:
    """Evento de alerta para hallazgos con SLA vencido.

    Un SLA que nadie notifica es un SLA que nadie cumple: el vencimiento queda
    enterrado en la baseline hasta que alguien abre la consola.
    """
    event: dict[str, Any] = {
        "time": datetime.now().timestamp(),
        "source": "Invoke-SecurityAudit",
        "sourcetype": "audit:sla",
        "event": {
            "alert": "sla_overdue",
            "overdue_count": len(_overdue_items(report)),
            "by_severity": {s: b["overdue"] for s, b in report.get("by_severity", {}).items() if b.get("overdue")},
            "details": [
                {
                    "signature": o.get("signature"),
                    "type": o.get("type"),
                    "severity": o.get("severity"),
                    "due_at": o.get("due_at"),
                    "days_overdue": o.get("days_overdue"),
                }
                for o in _overdue_items(report)
            ],
        },
    }
    index = _env("SPLUNK_HEC_INDEX")
    if index:
        event["index"] = index
    return event


def push_sla_alert(report: dict[str, Any]) -> dict[str, Any]:
    if not _overdue_items(report):
        return {"ok": True, "reason": "No hay hallazgos con SLA vencido: no hay nada que notificar"}
    return _post_hec(sla_alert_event(report))


def coverage_gap(layer: dict[str, Any], known_techniques: list[str]) -> list[str]:
    """Tecnicas de la referencia que NO aparecen en la capa: huecos de deteccion."""
    present = {t["techniqueID"] for t in layer["techniques"]}
    return [tech for tech in known_techniques if tech not in present]


# Tecnicas que la herramienta pretende cubrir (son las del MitreMap del script PowerShell).
# Comparar la capa observada contra esta lista convierte el "no miramos X" en un hueco
# medible: una tecnica declarada pero no observada en ninguna ejecucion es una deteccion
# que no esta disparando.
TARGET_TECHNIQUES = [
    "T1027.010",  # Command Obfuscation
    "T1059.001",  # PowerShell
    "T1218",      # System Binary Proxy Execution (LOLBAS)
    "T1055",      # Process Injection
    "T1036.005",  # Match Legitimate Resource Name or Location
    "T1095",      # Non-Application Layer Protocol
    "T1078.003",  # Local Accounts
    "T1110.003",  # Password Spraying
    "T1547.001",  # Registry Run Keys / Startup Folder
    "T1564.001",  # Hidden Files and Directories
    "T1557.001",  # Name Resolution Poisoning
    "T1686.003",  # Windows Host Firewall
    "T1685",      # Disable or Modify Tools
    "T1112",      # Modify Registry
    "T1021.002",  # SMB/Windows Admin Shares
    "T1014",      # Rootkit
    "T1571",      # Non-Standard Port
]
