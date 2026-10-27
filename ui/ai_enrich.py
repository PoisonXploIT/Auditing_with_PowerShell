"""Enriquecimiento IA de auditorias: veredictos Jev + explicaciones tecnicas LLM local.

Capa opcional y fail-safe sobre las amenazas de una auditoria (AMENAZAS_DETECTADAS.json):

- **Jev (TypeSafe)**: mismo contrato de API que sec-dashboard
  (POST {base_url} con {model, state, questions}; model pin `jev-1.13.0`).
  Calcula por amenaza: veredicto (true_positive/false_positive/noise),
  confianza, severidad IA (0-3) y urgencia de accion (0-1). De eso se deriva
  la **probabilidad de falso positivo**:
    - true_positive -> P(falso positivo) = 1 - confianza
    - false_positive / noise -> P(falso positivo) = confianza
- **LLM local (tecnico)**: servidor OpenAI-compatible SOLO loopback, sin API
  key. Actua como tecnico de ciberseguridad y produce, en espanol:
    - por amenaza: {resumen, porque, sugerencia}
    - resumen ejecutivo de toda la auditoria:
      {resumen_ejecutivo, riesgo_principal, acciones_prioritarias[]}

Reglas (mismas que sec-dashboard):
- Config SOLO en memoria; key Jev maskeda en lecturas; perdida al reiniciar.
- LLM loopback-only (127.0.0.1 / localhost / ::1), cualquier puerto, sin key.
- Cada fase degrada de forma independiente: ningun error rompe la vista de
  la auditoria ni el resto del informe.
- Sin dependencias nuevas: solo stdlib (urllib).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

# ── Constants (un solo archivo para auditar) ────────────────────────────────

PINNED_MODEL = "jev-1.13.0"
DEFAULT_JEV_BASE_URL = "https://api.typesafe.ai/v1/systemone"

# LAYA local (laya-serve en 127.0.0.1:8787, CPU): segunda opcion conmutable.
# Cloud (Jev) sigue siendo el default; el local es opt-in y fail-safe.
DEFAULT_LAYA_BASE_URL = "http://127.0.0.1:8787/v1/systemone"
DEFAULT_LAYA_MODEL = "multilingual"
_LAYA_ENV = Path(r"C:\Users\Sammi\ai-netwatch\data\laya_serve.env")

JEV_MAX_THREATS = 25      # cap de amenazas por llamada Jev (data minimization)
LLM_EXPLAIN_TOP_N = 10   # explicaciones LLM por amenaza (top por severidad)
MAX_FIELD = 300           # chars maximo por campo de explicacion LLM
MAX_ACTIONS = 5          # acciones prioritarias en el resumen ejecutivo

_MAX_TITLE = 200
_MAX_DESCRIPTION = 300
_LLM_MAX_TOKENS = 2048

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

# LAYA: dataset compartido de veredictos Jev (captura pasiva, fail-safe).
_LAYA_CASES_PATH = Path(r"C:\Users\Sammi\AI\laya-data\cases_audit.jsonl")

# Criterios de veredicto (en ingles a proposito: misma precision que
# sec-dashboard; son instrucciones para el modelo, no salida al usuario).
_VERDICT_CRITERIA = {
    "true_positive": {
        "what": "Real exposure or weakness that an attacker could plausibly exploit",
        "not_for": "Informational items with no exploitable impact",
    },
    "false_positive": {
        "what": "Scanner artifact, misreading of the target, or item that is not actually a problem",
        "not_for": "Real but low-impact findings (those are true_positive)",
    },
    "noise": {
        "what": "Routine informational output with no security relevance (versions, banners, defaults)",
        "not_for": "Anything with a concrete risk or misconfiguration",
    },
}

_SEVERITY_LEVELS = [
    "Informational only; no realistic impact",
    "Real but limited exposure; hardening recommended",
    "Active exposure likely exploitable by an external attacker",
    "Compromise or full takeover plausible from this finding alone",
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_ai_config: dict[str, Any] = {
    "jev_enabled": False,
    "jev_api_key": os.environ.get("TYPESAFE_API_KEY", ""),
    "jev_model": PINNED_MODEL,
    "jev_base_url": DEFAULT_JEV_BASE_URL,
    "jev_timeout": 30,
    "llm_enabled": False,
    "llm_base_url": os.environ.get("LOCAL_LLM_BASE_URL", ""),
    "llm_model": os.environ.get("LOCAL_LLM_MODEL", ""),
    "llm_timeout": 120,
    # cloud | local (local = laya-serve; no requiere api_key de TypeSafe).
    "backend": "cloud",
    "laya_base_url": DEFAULT_LAYA_BASE_URL,
    "laya_model": DEFAULT_LAYA_MODEL,
}


# ── Config (solo memoria) ───────────────────────────────────────────────────

def get_ai_config() -> dict:
    """Config actual con la key Jev maskeda."""
    cfg = dict(_ai_config)
    if cfg.get("jev_api_key"):
        cfg["jev_api_key"] = "***"
    return cfg


def set_ai_config(patch: dict) -> dict:
    """Aplica un patch de config. Devuelve la config resultante (maskeda)."""
    for k, v in (patch or {}).items():
        if k not in _ai_config:
            continue
        if k == "jev_api_key" and v in ("", None, "***"):
            # No borrar/invalidar la key con el valor maskedo.
            continue
        _ai_config[k] = v
    return get_ai_config()


def is_loopback_url(url: str) -> bool:
    try:
        parsed = urlparse(str(url or ""))
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    return (parsed.hostname or "").lower() in _LOOPBACK_HOSTS


# ── HTTP (stdlib) ───────────────────────────────────────────────────────────

def _http_post_json(url: str, headers: dict, payload: dict, timeout: float):
    """POST JSON. Devuelve (status_code, body_dict). Lanza Exception si red cae."""
    req = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
        return resp.status, (body if isinstance(body, dict) else {})


# ── Jev ─────────────────────────────────────────────────────────────────────

def _prob_false_positive(verdict: str | None, confidence: Any):
    """Deriva P(falso positivo) de veredicto + confianza. None si no calculable."""
    if verdict not in ("true_positive", "false_positive", "noise"):
        return None
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        return None
    c = max(0.0, min(1.0, c))
    p = (1.0 - c) if verdict == "true_positive" else c
    return round(p, 3)


def _laya_key() -> str:
    """LAYA_API_KEY desde el entorno o data/laya_serve.env (nunca en claro)."""
    k = os.environ.get("LAYA_API_KEY")
    if k:
        return k
    try:
        for line in _LAYA_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("LAYA_API_KEY="):
                os.environ["LAYA_API_KEY"] = line.split("=", 1)[1].strip()
                return os.environ["LAYA_API_KEY"]
    except OSError:
        pass
    return "local"


def _local_questions() -> dict:
    """Plantilla UNICA sin indice para /v1/systemone/batch (patron A3).

    Los criteria van en ORDEN LIVE (true_positive, false_positive, noise):
    el orden es posicional y no debe cambiarse.
    """
    return {
        "verdict": {
            "type": "choice",
            "instructions": "which verdict applies to this security finding?",
            "criteria": _VERDICT_CRITERIA,
        },
        "sev": {
            "type": "score",
            "instructions": "how severe is the risk if left unaddressed?",
            "criteria": _SEVERITY_LEVELS,
        },
        "action": {
            "type": "noul",
            "instructions": "does this finding require immediate operator action?",
            "criteria": {"false": "no immediate action needed",
                         "true": "yes, requires immediate action now"},
        },
    }


def _post_local(states: list[dict]) -> tuple[int, dict]:
    """POST /v1/systemone/batch al laya-serve (states[] + plantilla unica)."""
    url = str(_ai_config["laya_base_url"]).rstrip("/") + "/batch"
    headers = {"Authorization": f"Bearer {_laya_key()}"}
    payload = {
        "model": _ai_config["laya_model"],
        "states": states,
        "questions": _local_questions(),
    }
    total = max(float(_ai_config["jev_timeout"]), 60 + 5 * len(states))
    status, body = _http_post_json(url, headers, payload, total)
    return status, body


def _parse_local(results: list, n: int) -> dict[str, dict]:
    """Parsea results[] del batch local a veredictos por indice."""
    verdicts: dict[str, dict] = {}
    for i in range(n):
        r = results[i] if i < len(results) and isinstance(results[i], dict) else {}
        a = r.get("answers") or {}
        cls = a.get("verdict") or {}
        sev = a.get("sev") or {}
        act = a.get("action") or {}
        choice = cls.get("choice")
        conf = cls.get("answer_confidence")
        try:
            immediate = "yes" if float(act.get("noul")) >= 0.5 else "no"
        except (TypeError, ValueError):
            immediate = None
        verdicts[str(i)] = {
            "verdict": choice,
            "confidence": conf,
            "severity_score": sev.get("score"),
            "immediate_action": immediate,
            "prob_false_positive": _prob_false_positive(choice, conf),
        }
    return verdicts


def _threat_state(threats: list[dict]) -> list[dict]:
    """Estado minimo por amenaza (sin Details: data minimization)."""
    state = []
    for t in threats[:JEV_MAX_THREATS]:
        state.append({
            "tool": "ps_security_audit",
            "category": "Enterprise Audit",
            "severity": str(t.get("severity") or "")[:16].lower(),
            "title": str(t.get("type") or "")[:_MAX_TITLE],
            "description": str(t.get("description") or "")[:_MAX_DESCRIPTION],
        })
    return state


def _build_questions(n: int) -> dict[str, dict]:
    questions: dict[str, dict] = {}
    for i in range(n):
        base = f"About threat {i} (state[{i}]): "
        questions[f"f{i}_verdict"] = {
            "type": "choice",
            "instructions": base + "which verdict applies to this security finding?",
            "criteria": _VERDICT_CRITERIA,
        }
        questions[f"f{i}_sev"] = {
            "type": "score",
            "instructions": base + "how severe is the risk if left unaddressed?",
            "criteria": _SEVERITY_LEVELS,
        }
        questions[f"f{i}_action"] = {
            "type": "noul",
            "instructions": base + "does this finding require immediate operator action?",
        }
    return questions


def _laya_onehot(labels, chosen) -> dict:
    """One-hot desde el argmax cuando Jev no devuelve probabilidades."""
    if not labels or chosen is None:
        return {}
    return {k: (1.0 if k == chosen else 0.0) for k in labels}


def _laya_gold(answers: dict, i: int) -> dict:
    """Gold con probabilidades COMPLETAS (soft targets) para la amenaza i."""
    v = answers.get(f"f{i}_verdict") or {}
    s = answers.get(f"f{i}_sev") or {}
    a = answers.get(f"f{i}_action") or {}

    probs = v.get("probabilities")
    if not isinstance(probs, dict) or not probs:
        probs = _laya_onehot(list(_VERDICT_CRITERIA), v.get("choice"))
    gold: dict[str, dict] = {f"f{i}_verdict": {"probabilities": probs}}

    probs = s.get("probabilities")
    if not isinstance(probs, dict) or not probs:
        score = s.get("score")
        keys = [str(k) for k in range(len(_SEVERITY_LEVELS))]
        probs = _laya_onehot(keys, str(score)) if score is not None else {}
    gold[f"f{i}_sev"] = {"probabilities": probs}

    noul = a.get("noul")
    try:
        noul = float(noul)
    except (TypeError, ValueError):
        noul = None
    if noul is not None:
        probs = {"false": round(1.0 - noul, 6), "true": round(noul, 6)}
    else:
        probs = a.get("probabilities")
        if not isinstance(probs, dict) or not probs:
            probs = {}
    gold[f"f{i}_action"] = {"probabilities": probs}
    return gold


_LAYA_VOLATILE = frozenset((
    "ts", "first_seen", "last_seen", "seen_count", "scan_id", "id",
    "created_at", "timestamp", "run_id", "audit_id", "event_id",
))


def _laya_content_sig(state, questions, gold) -> str:
    """Firma de contenido para dedup (estable entre re-escaneos del mismo target).

    Ignora campos volatiles del state y reduce el gold al argmax por pregunta,
    para que variacion minima de probabilidades no cree casos nuevos.
    Debe permanecer en sincronia con AI/laya-data/merge_dedup.py.
    """
    s = {k: v for k, v in state.items() if k not in _LAYA_VOLATILE} \
        if isinstance(state, dict) else state
    g = {}
    for qid, item in (gold or {}).items():
        probs = item.get("probabilities") if isinstance(item, dict) else None
        if isinstance(probs, dict) and probs:
            g[qid] = max(sorted(probs), key=lambda k: probs[k])
        else:
            g[qid] = None
    q = sorted((questions or {}).items()) if isinstance(questions, dict) else questions
    payload = {"s": s, "q": q, "g": g}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _laya_capture(state: list[dict], questions: dict, answers: dict) -> None:
    """Anexa una linea por amenaza al dataset LAYA. Fail-safe: nunca lanza.

    Dedup por firma de contenido (campos volatiles + argmax del gold),
    no por hash de linea exacta.
    """
    try:
        lines = []
        for i, st in enumerate(state):
            qs = {k: v for k, v in questions.items() if k.startswith(f"f{i}_")}
            lines.append({"state": st, "questions": qs, "gold": _laya_gold(answers, i)})
        sigs = set()
        if _LAYA_CASES_PATH.exists():
            with open(_LAYA_CASES_PATH, encoding="utf-8") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        obj = json.loads(raw)
                        sigs.add(_laya_content_sig(
                            obj.get("state"), obj.get("questions"), obj.get("gold")))
                    except Exception:
                        pass
        new_lines = []
        for obj in lines:
            sig = _laya_content_sig(obj["state"], obj["questions"], obj["gold"])
            if sig not in sigs:
                sigs.add(sig)
                # CRITICO: sin sort_keys. El orden de `criteria` es posicional;
                # ordenarlo desalinea entrenamiento e inferencia (2026-10-04).
                new_lines.append(json.dumps(obj, ensure_ascii=False))
        if not new_lines:
            return
        _LAYA_CASES_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_LAYA_CASES_PATH, "a", encoding="utf-8") as f:
            for line in new_lines:
                f.write(line + "\n")
    except Exception:
        pass  # captura pasiva: nunca rompe la auditoria


def _local_enrich(threats: list[dict]) -> dict:
    """Camino local (laya-serve). Nunca lanza. Devuelve status ok/error/skipped."""
    state = _threat_state(threats)
    try:
        status, body = _post_local(state)
    except Exception as e:  # red caida, timeout, JSON invalido...
        return {"status": "error", "reason": str(e)[:200]}
    if status != 200:
        return {"status": "error", "reason": f"http_{status}"}
    results = body.get("results")
    if not isinstance(results, list):
        return {"status": "error", "reason": "bad_batch_shape"}
    verdicts = _parse_local(results, len(state))
    out: dict[str, dict] = {}
    for i in range(len(state)):
        v = dict(verdicts.get(str(i), {}))
        v["type"] = str(state[i].get("title") or "")
        v["severity"] = str(state[i].get("severity") or "")
        out[str(i)] = v
    return {
        "status": "ok",
        "backend": "local",
        "model": body.get("model"),
        "requested_model": _ai_config["laya_model"],
        "count": len(state),
        "truncated": len(threats) > len(state),
        "verdicts": out,
    }


def jev_enrich(threats: list[dict]) -> dict:
    """Veredictos IA para la lista de amenazas. Nunca lanza.

    backend=local (opt-in): usa laya-serve en loopback; si el serve local cae,
    FAIL-SAFE: se degrada al camino cloud/Jev y la auditoria nunca se rompe.
    backend=cloud (default): Jev TypeSafe, como antes.
    """
    if not _ai_config.get("jev_enabled"):
        return {"status": "skipped", "reason": "disabled"}
    if not threats:
        return {"status": "skipped", "reason": "no_findings"}

    backend = str(_ai_config.get("backend") or "cloud")
    if backend == "local":
        local_res = _local_enrich(threats)
        if local_res.get("status") == "ok":
            return local_res
        # FAIL-SAFE: el serve local no esta o fallo -> intentar cloud/Jev igual.
        fallback_reason = str(local_res.get("reason") or "")[:120]
    if not _ai_config.get("jev_api_key"):
        reason = "no_api_key"
        if backend == "local":
            reason = f"local_fallback_no_api_key ({fallback_reason})"
        return {"status": "skipped", "reason": reason}

    state = _threat_state(threats)
    payload = {
        "model": _ai_config["jev_model"],
        "state": state,
        "questions": _build_questions(len(state)),
    }
    url = str(_ai_config["jev_base_url"]).rstrip("/")
    headers = {"Authorization": f"Bearer {_ai_config['jev_api_key']}"}
    try:
        status, body = _http_post_json(url, headers, payload, float(_ai_config["jev_timeout"]))
    except Exception as e:  # red, timeout, JSON invalido...
        return {"status": "error", "reason": str(e)[:200]}
    if status != 200:
        return {"status": "error", "reason": f"http_{status}"}

    answers = body.get("answers", {})
    _laya_capture(state, payload["questions"], answers)  # LAYA dataset (fail-safe)
    verdicts: dict[str, dict] = {}
    for i in range(len(state)):
        v = answers.get(f"f{i}_verdict") or {}
        s = answers.get(f"f{i}_sev") or {}
        a = answers.get(f"f{i}_action") or {}
        verdict = v.get("choice")
        confidence = v.get("confidence")
        verdicts[str(i)] = {
            "verdict": verdict,
            "confidence": confidence,
            "severity_score": s.get("score"),
            "immediate_action": a.get("noul"),
            "prob_false_positive": _prob_false_positive(verdict, confidence),
            "type": str(state[i].get("title") or ""),
            "severity": str(state[i].get("severity") or ""),
        }
    return {
        "status": "ok",
        "backend": "cloud",
        "model": body.get("model"),
        "requested_model": _ai_config["jev_model"],
        "count": len(state),
        "truncated": len(threats) > len(state),
        "usage": body.get("usage"),
        "verdicts": verdicts,
    }


def test_laya_local() -> dict:
    """Selftest del serve local (mismo patron que sec-dashboard). Nunca lanza."""
    try:
        status, body = _post_local(
            [{"title": "selftest", "tool": "auditing-selftest"}])
    except Exception as e:  # serve caido / loopback cerrado
        return {"ok": False, "error": str(e)[:200]}
    if status != 200:
        return {"ok": False, "error": f"http_{status}"}
    results = body.get("results") or []
    ans = (results[0].get("answers") if results else {}) or {}
    return {"ok": True, "model": body.get("model"),
            "answer": (ans.get("verdict") or {}).get("choice")}


def test_jev() -> dict:
    """Probe minimo para validar key/conexion. Nunca lanza.

    Con backend=local sondea el serve local (sin api_key de TypeSafe);
    con cloud (default) valida la key contra Jev como antes.
    """
    if not _ai_config.get("jev_enabled"):
        return {"ok": False, "error": "not_configured"}
    if str(_ai_config.get("backend") or "cloud") == "local":
        r = test_laya_local()
        r["backend"] = "local"
        return r
    if not _ai_config.get("jev_api_key"):
        return {"ok": False, "error": "not_configured"}
    payload = {
        "model": _ai_config["jev_model"],
        "state": "This is a connectivity test from security audit.",
        "questions": {"probe": {"type": "noul", "instructions": "Is this sentence in English?"}},
    }
    url = str(_ai_config["jev_base_url"]).rstrip("/")
    headers = {"Authorization": f"Bearer {_ai_config['jev_api_key']}"}
    try:
        status, body = _http_post_json(url, headers, payload, float(_ai_config["jev_timeout"]))
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
    if status != 200:
        return {"ok": False, "error": f"http_{status}"}
    answer = (body.get("answers", {}).get("probe") or {})
    return {"ok": True, "model": body.get("model"), "answer": answer.get("noul")}


# ── LLM local (tecnico) ─────────────────────────────────────────────────────

_LLM_SYSTEM_THREAT = (
    "Eres un tecnico de ciberseguridad senior que revisa el resultado de una "
    "auditoria empresarial de Windows. Te dan UNA amenaza detectada y el "
    "veredicto del modelo Jev (oficial; no lo contradigas, solo explicalo). "
    "Explica en espanol claro: que significa esta entrada/amenaza para la "
    "maquina, por que es (o no es) relevante segun el veredicto y la "
    "probabilidad de falso positivo de Jev, y cual es la accion concreta. "
    "Responde SOLO con un objeto JSON (sin markdown) con exactamente estas "
    "claves: resumen (1-2 frases), porque (1-2 frases), sugerencia (1 frase, "
    "una accion concreta). Cada valor en espanol y de menos de 40 palabras."
)

_LLM_SYSTEM_SUMMARY = (
    "Eres un tecnico de ciberseguridad senior que escribe el resumen "
    "ejecutivo de una auditoria empresarial de Windows para la direccion "
    "tecnica. Te dan los datos de la auditoria y, si existen, los veredictos "
    "del modelo Jev por amenaza (oficiales; no los contradigas). Escribe en "
    "espanol claro y conciso. Responde SOLO con un objeto JSON (sin markdown) "
    "con exactamente estas claves: resumen_ejecutivo (3-5 frases: estado "
    "general de seguridad, lo mas importante), riesgo_principal (1 frase: el "
    "riesgo mas relevante o 'ninguno relevante' si no hay amenazas), "
    "acciones_prioritarias (array con 3 a 5 acciones concretas y cortas en "
    "orden de prioridad; vacio si no aplica)."
)


def _llm_chat(messages: list[dict], max_tokens: int) -> tuple[int, dict]:
    url = str(_ai_config["llm_base_url"]).rstrip("/") + "/v1/chat/completions"
    body = {
        "model": _ai_config["llm_model"],
        "messages": messages,
        "temperature": 0,
        "max_tokens": max_tokens,
        # Modelos de razonamiento: presupuesto pequeno. Ignorado si no soportado.
        "reasoning_effort": "low",
    }
    status, data = _http_post_json(url, {}, body, float(_ai_config["llm_timeout"]))
    return status, data


def _parse_json_block(content: str) -> dict | None:
    text = (content or "").strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def llm_explain_threat(threat: dict, jev_verdict: dict | None) -> dict:
    """Explicacion tecnica de UNA amenaza. Nunca lanza."""
    payload = {
        "amenaza": {
            "tipo": str(threat.get("type") or "")[:_MAX_TITLE],
            "severidad": str(threat.get("severity") or "")[:16],
            "descripcion": str(threat.get("description") or "")[:_MAX_DESCRIPTION],
        },
        "veredicto_jev": jev_verdict,
    }
    messages = [
        {"role": "system", "content": _LLM_SYSTEM_THREAT},
        {"role": "user", "content": "Explica esta amenaza. " + json.dumps(payload, ensure_ascii=False)},
    ]
    try:
        status, body = _llm_chat(messages, _LLM_MAX_TOKENS)
    except Exception as e:
        return {"status": "unavailable", "reason": str(e)[:200]}
    if status != 200:
        return {"status": "unavailable", "reason": f"http_{status}"}
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {"status": "unavailable", "reason": "bad_response_shape"}
    data = _parse_json_block(content)
    if data is None:
        return {"status": "unavailable", "reason": "unparseable_output"}
    out = {}
    for key in ("resumen", "porque", "sugerencia"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            return {"status": "unavailable", "reason": f"missing_{key}"}
        out[key] = value.strip()[:MAX_FIELD]
    model = body.get("model") or _ai_config["llm_model"]
    return {"status": "ok", "model": model, **out}


def llm_executive_summary(meta: dict, threats: list[dict], jev: dict) -> dict:
    """Resumen ejecutivo de toda la auditoria. Nunca lanza."""
    counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for t in threats:
        sev = str(t.get("severity") or "LOW").upper()
        if sev in counts:
            counts[sev] += 1
    payload = {
        "auditoria": {
            "sistema": (meta.get("summary") or {}).get("sistema"),
            "modulos_ejecutados": (meta.get("summary") or {}).get("modulos"),
            "nivel_riesgo_script": meta.get("risk_level"),
            "amenazas_por_severidad": counts,
        },
        "amenazas": [
            {
                "tipo": str(t.get("type") or "")[:120],
                "severidad": str(t.get("severity") or "")[:16],
                "descripcion": str(t.get("description") or "")[:160],
                "jev": (jev.get("verdicts") or {}).get(str(i)),
            }
            for i, t in enumerate(threats[:JEV_MAX_THREATS])
        ],
    }
    messages = [
        {"role": "system", "content": _LLM_SYSTEM_SUMMARY},
        {"role": "user", "content": "Escribe el resumen ejecutivo. " + json.dumps(payload, ensure_ascii=False)},
    ]
    try:
        status, body = _llm_chat(messages, _LLM_MAX_TOKENS)
    except Exception as e:
        return {"status": "unavailable", "reason": str(e)[:200]}
    if status != 200:
        return {"status": "unavailable", "reason": f"http_{status}"}
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {"status": "unavailable", "reason": "bad_response_shape"}
    data = _parse_json_block(content)
    if data is None:
        return {"status": "unavailable", "reason": "unparseable_output"}
    resumen = data.get("resumen_ejecutivo")
    riesgo = data.get("riesgo_principal")
    acciones_raw = data.get("acciones_prioritarias")
    if not isinstance(resumen, str) or not resumen.strip():
        return {"status": "unavailable", "reason": "missing_resumen_ejecutivo"}
    acciones: list[str] = []
    if isinstance(acciones_raw, list):
        acciones = [str(x).strip()[:160] for x in acciones_raw if isinstance(x, str) and x.strip()][:MAX_ACTIONS]
    model = body.get("model") or _ai_config["llm_model"]
    return {
        "status": "ok",
        "model": model,
        "resumen_ejecutivo": resumen.strip()[:800],
        "riesgo_principal": (str(riesgo).strip()[:300] if riesgo else ""),
        "acciones_prioritarias": acciones,
    }


def test_llm() -> dict:
    """Round-trip minimo contra el servidor local. Nunca lanza."""
    if not _ai_config.get("llm_enabled"):
        return {"status": "unavailable", "reason": "disabled"}
    if not _ai_config.get("llm_base_url") or not _ai_config.get("llm_model"):
        return {"status": "unavailable", "reason": "not_configured"}
    messages = [{"role": "user", "content": "Responde solo con la palabra: OK"}]
    try:
        status, body = _llm_chat(messages, 16)
    except Exception as e:
        return {"status": "unavailable", "reason": str(e)[:200]}
    if status != 200:
        return {"status": "unavailable", "reason": f"http_{status}"}
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {"status": "unavailable", "reason": "bad_response_shape"}
    model = body.get("model") or _ai_config["llm_model"]
    return {"status": "ok", "model": model, "reply": str(content)[:80]}


# ── Orquestacion: enriquecer una auditoria ──────────────────────────────────

def _normalize_threat(raw: dict) -> dict:
    """Claves del script (ThreatType/Severity/...) -> claves canonicas internas."""
    return {
        "timestamp": raw.get("Timestamp") or raw.get("timestamp"),
        "type": raw.get("ThreatType") or raw.get("type"),
        "severity": str(raw.get("Severity") or raw.get("severity") or "LOW").upper(),
        "description": raw.get("Description") or raw.get("description"),
    }


def enrich_audit(folder: Path, meta: dict) -> dict:
    """Genera el enriquecimiento IA completo para una carpeta Auditoria_*.

    Escribe <folder>/IA_ENRICH.json y <folder>/IA_RESUMEN_EJECUTIVO.md.
    Cada fase degrada de forma independiente; nunca lanza.
    """
    folder = Path(folder)
    threats: list[dict] = []
    data = None
    threats_path = folder / "AMENAZAS_DETECTADAS.json"
    if threats_path.exists():
        try:
            with open(threats_path, encoding="utf-8-sig") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            data = None
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list):
        threats = [_normalize_threat(t) for t in data if isinstance(t, dict)]

    jev = jev_enrich(threats)

    # LLM: explicaciones top-N por severidad + resumen ejecutivo.
    llm_explanations: list[dict] = []
    executive: dict | None = None
    if _ai_config.get("llm_enabled") and _ai_config.get("llm_base_url") and _ai_config.get("llm_model"):
        ordered = sorted(
            range(len(threats)),
            key=lambda i: (SEVERITY_ORDER.get(str(threats[i].get("severity") or "LOW").upper(), 9), i),
        )
        for i in ordered[:LLM_EXPLAIN_TOP_N]:
            t = threats[i]
            verdict = (jev.get("verdicts") or {}).get(str(i)) if jev.get("status") == "ok" else None
            res = llm_explain_threat(t, verdict)
            item: dict[str, Any] = {
                "index": i,
                "type": str(t.get("type") or "")[:_MAX_TITLE],
                "severity": str(t.get("severity") or ""),
            }
            if res.get("status") == "ok":
                item.update({"resumen": res["resumen"], "porque": res["porque"],
                             "sugerencia": res["sugerencia"], "model": res["model"]})
            else:
                item["status"] = "unavailable"
                item["reason"] = str(res.get("reason") or "")[:120]
            llm_explanations.append(item)
        executive = llm_executive_summary(meta, threats, jev if jev.get("status") == "ok" else {"status": jev.get("status")})

    result = {
        "audit_id": folder.name,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threats_total": len(threats),
        "jev": jev,
        "llm_explanations": llm_explanations or None,
        "executive_summary": executive,
    }

    # Persistir en la carpeta de la auditoria (enriquece el informe en disco).
    try:
        (folder / "IA_ENRICH.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        (folder / "IA_RESUMEN_EJECUTIVO.md").write_text(
            _render_markdown(result), encoding="utf-8")
    except OSError:
        pass  # el resultado sigue devolviendose aunque no se pueda escribir

    return result


def _render_markdown(result: dict) -> str:
    lines = [
        "# IA — Resumen Ejecutivo y Veredictos",
        "",
        f"- Auditoria: `{result['audit_id']}`",
        f"- Generado: {result['generated_at']}",
        f"- Amenazas totales: {result['threats_total']}",
        "",
    ]
    exec_sum = result.get("executive_summary") or {}
    if exec_sum.get("status") == "ok":
        lines += ["## Resumen ejecutivo (LLM local, referencial)", "", exec_sum["resumen_ejecutivo"], ""]
        if exec_sum.get("riesgo_principal"):
            lines += [f"**Riesgo principal:** {exec_sum['riesgo_principal']}", ""]
        if exec_sum.get("acciones_prioritarias"):
            lines += ["**Acciones prioritarias:**", ""]
            lines += [f"{i}. {a}" for i, a in enumerate(exec_sum["acciones_prioritarias"], 1)]
            lines.append("")
    jev = result.get("jev") or {}
    if jev.get("status") == "ok":
        lines += ["## Veredictos Jev", "",
                  "| # | Amenaza | Severidad | Veredicto | Confianza | Prob. falso positivo | Severidad IA (0-3) | Accion inmediata (0-1) |",
                  "|---|---------|-----------|-----------|-----------|----------------------|--------------------|------------------------|"]
        for i, v in (jev.get("verdicts") or {}).items():
            lines.append(
                f"| {i} | {v.get('type') or '—'} | {v.get('severity') or '—'} | {v.get('verdict')} | "
                f"{v.get('confidence')} | {v.get('prob_false_positive')} | "
                f"{v.get('severity_score')} | {v.get('immediate_action')} |")
        lines.append("")
    expls = result.get("llm_explanations") or []
    if expls:
        lines += ["## Explicaciones tecnicas (LLM local, referencial)", ""]
        for e in expls:
            lines += [f"### {e.get('type')} ({e.get('severity')})", ""]
            if e.get("status") == "unavailable":
                lines += [f"_Explicacion no disponible ({e.get('reason')})_", ""]
            else:
                lines += [
                    f"- **Que es:** {e.get('resumen')}",
                    f"- **Por que importa:** {e.get('porque')}",
                    f"- **Sugerencia:** {e.get('sugerencia')}",
                    "",
                ]
    return "\n".join(lines)
