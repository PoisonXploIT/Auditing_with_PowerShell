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
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Optional

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"puerto (\d+)", re.IGNORECASE)
PROC_RE = re.compile(r"proceso '([^']+)'", re.IGNORECASE)


def _env(name: str) -> Optional[str]:
    value = os.environ.get(name, "").strip()
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
    return {
        "time": datetime.now().timestamp(),
        "source": "Invoke-SecurityAudit",
        "sourcetype": "audit:security",
        "index": os.environ.get("SPLUNK_HEC_INDEX", "security"),
        "event": {
            "audit_id": audit_meta.get("id"),
            "risk": audit_meta.get("risk"),
            "threats": audit_meta.get("threats", 0),
            "suppressed": audit_meta.get("suppressed", 0),
            "duration": audit_meta.get("duration"),
            "elevated": audit_meta.get("elevated"),
            "severity_counts": audit_meta.get("severity_counts", {}),
            "details": [
                {
                    "type": t.get("ThreatType"),
                    "severity": t.get("Severity"),
                    "description": t.get("Description"),
                    "mitre": t.get("MitreTechnique"),
                }
                for t in threats
            ],
        },
    }


def push_to_splunk(audit_meta: dict[str, Any], threats: list[dict[str, Any]], timeout: int = 10) -> dict[str, Any]:
    url = _env("SPLUNK_HEC_URL")
    token = _env("SPLUNK_HEC_TOKEN")
    if not url or not token:
        return {"ok": False, "reason": "SPLUNK_HEC_URL o SPLUNK_HEC_TOKEN no definidos en el entorno"}

    payload = json.dumps(splunk_event(audit_meta, threats)).encode("utf-8")
    try:
        req = urllib.request.Request(
            url.rstrip("/") + "/services/collector/event",
            data=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
        return {"ok": True, "status": resp.status, "response": json.loads(body) if body else {}}
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError) as exc:
        return {"ok": False, "reason": f"Splunk no responde: {exc}"}


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


def coverage_gap(layer: dict[str, Any], known_techniques: list[str]) -> list[str]:
    """Tecnicas de la referencia que NO aparecen en la capa: huecos de deteccion."""
    present = {t["techniqueID"] for t in layer["techniques"]}
    return [tech for tech in known_techniques if tech not in present]
