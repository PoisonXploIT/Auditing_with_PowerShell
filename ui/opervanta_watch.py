# -*- coding: utf-8 -*-
r"""opervanta_watch.py - Recepcion de la actividad de Opervanta (direccion B del pack).

Opervanta publica su actividad (auth, alertas, tareas, denegaciones) en este ingress, firmado con el
MISMO esquema v2 de `/alerta` (HMAC sobre `v2|sensor|ts|nonce|sha256(cuerpo)`), con nonce de un solo
uso y ventana de reloj. Se guarda en un JSONL acotado y la UI lo muestra como una vista "Opervanta".

Flags:
  OPERVANTA_WATCH_ENABLED  (default 0)  - con 0 el endpoint no existe (404)
  OPERVANTA_WATCH_SECRET                - secreto compartido con el notificador de Opervanta
  OPERVANTA_WATCH_DIR     (default <repo>/data)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path

_TRUE = ("1", "on", "si", "true", "yes")
ESQUEMA = "opervanta-evento/1"
VENTANA_S = 300
MAX_EVENTOS = 5000
TIPOS = ("auth", "alerta", "tarea", "denegacion", "salud")
SEV = ("info", "baja", "media", "alta", "critica")

WATCH_DIR = Path(os.environ.get("OPERVANTA_WATCH_DIR")
                 or str(Path(__file__).resolve().parent.parent / "data"))
EVENTOS = WATCH_DIR / "opervanta-eventos.jsonl"
NONCES = WATCH_DIR / "opervanta-nonces.json"


def activo() -> bool:
    return str(os.environ.get("OPERVANTA_WATCH_ENABLED") or "0").strip().lower() in _TRUE


def secreto() -> str:
    return str(os.environ.get("OPERVANTA_WATCH_SECRET") or "").strip()


def _cuerpo_bytes(cuerpo: bytes) -> bytes:
    return cuerpo if isinstance(cuerpo, bytes) else str(cuerpo).encode("utf-8")


def verificar(sensor: str, ts: str, nonce: str, digest: str, cuerpo: bytes) -> tuple:
    """(ok, motivo). Firma v2 + nonce de un solo uso + ventana. Fail-closed si falta secreto."""
    sec = secreto()
    if not sec:
        return False, "sin OPERVANTA_WATCH_SECRET"
    if not sensor or not ts or not nonce or not digest:
        return False, "faltan cabeceras de la firma"
    try:
        t = int(float(ts))
    except (TypeError, ValueError):
        return False, "ts invalido"
    if abs(int(time.time()) - t) > VENTANA_S:
        return False, "ts fuera de ventana"
    calc = hmac.new(sec.encode("utf-8"),
                    ("v2|%s|%s|%s|%s" % (sensor, ts, nonce,
                                         hashlib.sha256(_cuerpo_bytes(cuerpo)).hexdigest()))
                    .encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc, digest):
        return False, "firma invalida"
    if _nonce_visto(nonce, t):
        return False, "nonce ya usado"
    return True, ""


def _nonce_visto(nonce: str, ts: int) -> bool:
    """Anti-replay: guarda {nonce: ts}; rechaza si ya se uso. Fail-closed si el almacen falla."""
    try:
        datos = {}
        if NONCES.exists():
            datos = json.loads(NONCES.read_text(encoding="utf-8"))
        ahora = int(time.time())
        datos = {k: v for k, v in datos.items() if isinstance(v, (int, float)) and ahora - int(v) < VENTANA_S}
        if nonce in datos:
            return True
        datos[nonce] = ts
        tmp = NONCES.with_suffix(".tmp")
        tmp.write_text(json.dumps(datos, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, NONCES)
        return False
    except Exception:  # noqa: BLE001  (fail-closed)
        return True


def _validar(evento: dict) -> str:
    if not isinstance(evento, dict):
        return "cuerpo no es objeto"
    if str(evento.get("schema") or "") != ESQUEMA:
        return "schema invalido"
    if str(evento.get("tipo") or "") not in TIPOS:
        return "tipo invalido"
    if str(evento.get("sev") or "") not in SEV:
        return "sev invalida"
    if not str(evento.get("mensaje") or "").strip():
        return "mensaje vacio"
    return ""


def guardar(evento: dict) -> dict:
    """Valida y anade el evento al JSONL acotado (podando los mas viejos)."""
    mot = _validar(evento)
    if mot:
        return {"ok": False, "motivo": mot}
    try:
        WATCH_DIR.mkdir(parents=True, exist_ok=True)
        eventos = []
        if EVENTOS.exists():
            eventos = [json.loads(x) for x in EVENTOS.read_text(encoding="utf-8").splitlines() if x.strip()]
        eventos.append(evento)
        eventos = eventos[-MAX_EVENTOS:]
        tmp = EVENTOS.with_suffix(".tmp")
        tmp.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in eventos), encoding="utf-8")
        os.replace(tmp, EVENTOS)
        return {"ok": True, "guardados": len(eventos)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "motivo": str(e)}


def listar(n: int = 100, tipo: str = "") -> list:
    try:
        if not EVENTOS.exists():
            return []
        out = [json.loads(x) for x in EVENTOS.read_text(encoding="utf-8").splitlines() if x.strip()]
        if tipo:
            out = [e for e in out if e.get("tipo") == tipo]
        return out[-n:]
    except Exception:  # noqa: BLE001
        return []
