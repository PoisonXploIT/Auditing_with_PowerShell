"""Adaptador al SOC de Opervanta. Escrito, pero NO activado.

Condicion del plan: solo se enciende si los P0 de Opervanta estan cerrados. La
auditoria integral (2026-10-21) deja P0 en autorizacion de POST (SEC-01), escape de
atributos (SEC-02), ultimo administrador (ID-01), auditoria SQLite (DATA-01) y
antirreplay fail-open (SOC-01). Mientras eso no este cerrado, publicar hallazgos de
la auditoria en el SOC de Opervanta amplifica una superficie que aun no esta resuelta.

Por eso `PILOOP_SOC_ENABLED` vale 0 por defecto: el codigo esta, los tests cubren el
contrato, y activarlo es una decision explicita del operador.

Contrato real del ingress (verificado contra C:\Opervanta\buzon\httpd.py y
buzon/soc.py, 2026-10-28):

    POST http://127.0.0.1:8899/alerta
      X-Piloop-Alerta-Sensor:  identidad del sensor
      X-Piloop-Alerta-Ts:      unix seconds
      X-Piloop-Alerta-Nonce:   un solo uso
      X-Piloop-Alerta-Hmac:    HMAC-SHA256(secret, "v2|sensor|ts|nonce|sha256(cuerpo)")
      cuerpo JSON: fuente, tipo, sev, mensaje, firma, evidencia

Severidades admitidas: info | baja | media | alta | critica.

Decision de diseno: el adaptador NO escribe en el directorio del SOC. Escribir
`eventos.jsonl` a mano saltaria la autenticacion, el rate-limit por sensor, el
dedupe y el pre-triaje de Opervanta; es decir, se saltaria precisamente lo que la
auditoria de Opervanta esta corrigiendo (SOC-01). El unico camino admitido es el
ingress firmado.

No se duplica el envio a Splunk: Opervanta ya tiene su cola HEC con reintentos.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

SCHEMA = "soc-event/1"
SEVERITY_MAP = {
    "CRITICAL": "critica",
    "HIGH": "alta",
    "MEDIUM": "media",
    "LOW": "baja",
}
SOC_SEVERITIES = ("info", "baja", "media", "alta", "critica")

_TRUE = ("1", "true", "on", "si", "yes")
DEFAULT_URL = "http://127.0.0.1:8899"
DEFAULT_SENSOR = "audit-powershell"


def soc_enabled() -> bool:
    """El adaptador esta apagado salvo que PILOOP_SOC_ENABLED diga lo contrario."""
    return os.environ.get("PILOOP_SOC_ENABLED", "0").strip().lower() in _TRUE


def soc_url() -> str:
    return (os.environ.get("PILOOP_SOC_URL") or DEFAULT_URL).rstrip("/")


def soc_sensor() -> str:
    return (os.environ.get("PILOOP_SOC_SENSOR") or DEFAULT_SENSOR).strip()[:80]


def alerta_secret() -> str:
    """Secreto del sensor. Puede ser el global de Opervanta o uno propio.

    Se lee de PILOOP_SOC_ALERTA_SECRET; si no existe, se usa el de Opervanta
    (PILOOP_ALERTA_SECRET / PILOOP_ALERTA_SECRETS). El valor nunca se imprime.
    """
    direct = os.environ.get("PILOOP_SOC_ALERTA_SECRET", "").strip()
    if direct:
        return direct
    global_secret = os.environ.get("PILOOP_ALERTA_SECRET", "").strip()
    if global_secret:
        return global_secret
    raw = os.environ.get("PILOOP_ALERTA_SECRETS", "").strip()
    if raw:
        try:
            mapping = json.loads(raw)
            sensor = soc_sensor()
            if isinstance(mapping, dict):
                for key in (sensor, "*"):
                    value = str(mapping.get(key) or "").strip()
                    if value:
                        return value
        except (json.JSONDecodeError, TypeError):
            return ""
    return ""


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
    norm = f"{threat.get('type', '')}|{threat.get('description', '')}".lower()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16].upper()


def build_events(audit_id: str, threats: list[dict[str, Any]],
                 suppressed: Optional[list[dict[str, Any]]] = None) -> list[dict[str, Any]]:
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


def _alerta_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Campo a campo lo que Opervanta conserva de una alerta.

    `firma` es el event_id: Opervanta la usa para deduplicar, asi que el mismo
    hallazgo en dos auditorias no genera dos tareas.
    """
    evidencia = f"audit_id={event['correlation_id']}"
    if event.get("mitre_technique"):
        evidencia += f" | mitre={event['mitre_technique']}"
    if event.get("suppressed"):
        evidencia += f" | suprimida por allowlist: {event.get('reason', '')}"
    return {
        "fuente": event["source"],
        "tipo": event["type"][:40],
        "sev": event["severity"],
        "mensaje": event["description"][:2000],
        "firma": event["event_id"],
        "evidencia": evidencia[:500],
        "tenant": os.environ.get("PILOOP_SOC_TENANT", "local"),
    }


def _tls_context(url: str) -> Optional[ssl.SSLContext]:
    if not url.lower().startswith("https"):
        return None
    if os.environ.get("PILOOP_SOC_INSECURE", "0").strip().lower() in _TRUE:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return None


def _post_alerta(payload: dict[str, Any], timeout: int = 10) -> dict[str, Any]:
    """POST /alerta con firma v2: sensor + ts + nonce + HMAC del cuerpo.

    Sin secreto no se intenta el envio: Opervanta en modo estricto rechaza todo lo
    no firmado, y en modo laxo la alerta entraria sin identidad, que es justo el
    hallazgo SOC-01. Fail closed.
    """
    secret = alerta_secret()
    if not secret:
        return {"ok": False, "motivo": "sin secreto de alerta: define PILOOP_SOC_ALERTA_SECRET"}

    sensor = soc_sensor()
    url = soc_url() + "/alerta"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    digest = hmac.new(
        secret.encode("utf-8"),
        f"v2|{sensor}|{ts}|{nonce}|{hashlib.sha256(body).hexdigest()}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Piloop-Alerta-Sensor": sensor,
            "X-Piloop-Alerta-Ts": ts,
            "X-Piloop-Alerta-Nonce": nonce,
            "X-Piloop-Alerta-Hmac": digest,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_tls_context(url)) as resp:
            text = resp.read().decode("utf-8", "replace")
        result = json.loads(text) if text else {}
        return {"ok": bool(result.get("ok", True)), "motivo": result.get("motivo", ""),
                "status": resp.status, "respuesta": result}
    except urllib.error.HTTPError as exc:
        # Un 401/429 lleva el motivo en el cuerpo: sin leerlo no se puede saber
        # si el problema es la firma, el nonce o el rate-limit.
        try:
            result = json.loads(exc.read().decode("utf-8", "replace") or "{}")
        except (ValueError, OSError):
            result = {}
        return {"ok": False, "motivo": result.get("motivo") or f"Opervanta responde {exc.code}",
                "status": exc.code, "respuesta": result}
    except (urllib.error.URLError, ValueError, TimeoutError) as exc:
        return {"ok": False, "motivo": f"Opervanta no responde: {exc}"}


def publish(audit_id: str, threats: list[dict[str, Any]],
            suppressed: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
    """Publicar los hallazgos en el SOC de Opervanta a traves del ingress firmado.

    Con PILOOP_SOC_ENABLED=0 no se envia nada: se devuelve el conteo de lo que se
    publicaria, para que la consola muestre el estado sin efectos laterales.
    """
    events = build_events(audit_id, threats, suppressed)
    if not soc_enabled():
        return {
            "ok": True,
            "enabled": False,
            "sent": 0,
            "pending": len(events),
            "reason": "PILOOP_SOC_ENABLED=0: el adaptador al SOC de Opervanta no esta activo (P0 abiertos)",
        }

    if not alerta_secret():
        return {
            "ok": False,
            "enabled": True,
            "sent": 0,
            "pending": len(events),
            "reason": "Falta PILOOP_SOC_ALERTA_SECRET: el ingress /alerta exige firma v2. "
                      "No se escribe en el SOC a mano: eso saltaria auth, rate-limit y triaje.",
        }

    sent = 0
    rejected = []
    for event in events:
        result = _post_alerta(_alerta_payload(event))
        if result["ok"]:
            sent += 1
        else:
            rejected.append({"event_id": event["event_id"], "motivo": result["motivo"]})
            # Un 429 de Opervanta significa que el sensor va demasiado rapido: parar
            # y declarar el resto como pendiente es mejor que inundar la cola.
            if result.get("status") == 429:
                break

    return {
        "ok": sent > 0,
        "enabled": True,
        "sent": sent,
        "pending": len(events) - sent,
        "rejected": rejected,
        "url": soc_url() + "/alerta",
        "sensor": soc_sensor(),
        "by_severity": {sev: sum(1 for e in events if e["severity"] == sev) for sev in SOC_SEVERITIES},
    }


def status() -> dict[str, Any]:
    return {
        "enabled": soc_enabled(),
        "url": soc_url() + "/alerta",
        "sensor": soc_sensor(),
        "secret_defined": bool(alerta_secret()),
        "strict_mode": os.environ.get("PILOOP_ALERTA_ESTRICTO", "").strip().lower() in _TRUE,
        "note": "Ingress firmado (firma v2). No se escribe en el directorio del SOC: "
                "eso saltaria autenticacion, rate-limit y pre-triaje de Opervanta.",
    }
