# -*- coding: utf-8 -*-
"""Evidencia FASE 2: Auditing_with_PowerShell con backend local (LAYA v4, :8787).

- Toma amenazas REALES de la carpeta Auditoria_* mas reciente (AMENAZAS_DETECTADAS.json).
- Ejecuta ui.ai_enrich.jev_enrich con backend="local" (opt-in; el default del
  sistema sigue siendo cloud/Jev y NO se modifica en disco).
- Selftest local: test_laya_local().
- Compara contra los veredictos cloud (Jev jev-1.13.0) ya guardados en la
  carpeta de auditoria (IA_ENRICH.json): 0 llamadas nuevas a Jev.
- Escribe evidencia en ui/laya-local-evidence.json.

Uso (desde C:\\Users\\Sammi\\Auditing_with_PowerShell):
    python ui\\laya_local_test.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ui"))

import ai_enrich  # noqa: E402

EVIDENCE = REPO / "ui" / "laya-local-evidence.json"


def _latest_audit():
    folders = sorted(p for p in REPO.glob("Auditoria_*") if p.is_dir())
    for folder in reversed(folders):
        threats_path = folder / "AMENAZAS_DETECTADAS.json"
        if threats_path.exists():
            return folder, threats_path
    return None, None


def _load_threats(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = [data]
    threats = []
    for t in data:
        if isinstance(t, dict):
            threats.append(ai_enrich._normalize_threat(t))
    return threats


def main() -> None:
    folder, threats_path = _latest_audit()
    if not folder or not threats_path:
        print("sin auditorias con AMENAZAS_DETECTADAS.json")
        return
    threats = _load_threats(threats_path)
    print(f"auditoria: {folder.name} | amenazas: {len(threats)}")

    # Orden live de criteria (verificacion obligatoria).
    order_live = list(ai_enrich._VERDICT_CRITERIA.keys())
    print("orden criteria en memoria:", order_live)

    # backend=local opt-in (solo memoria de este proceso; default sigue cloud).
    ai_enrich.set_ai_config({
        "jev_enabled": True,
        "backend": "local",
        "laya_base_url": "http://127.0.0.1:8787/v1/systemone",
        "laya_model": "multilingual",
    })

    # Lote pequeno (max 6 amenazas).
    batch = threats[:6]
    result = ai_enrich.jev_enrich(batch)
    print("status:", result.get("status"), "| backend:", result.get("backend"))

    selftest = ai_enrich.test_laya_local()
    print("selftest local:", selftest)

    # Referencia cloud (Jev) ya guardada en la carpeta de auditoria.
    cloud_ref = None
    ia_path = folder / "IA_ENRICH.json"
    if ia_path.exists():
        try:
            d = json.loads(ia_path.read_text(encoding="utf-8"))
            jev_ref = d.get("jev") or {}
            if jev_ref.get("status") == "ok":
                cloud_ref = {
                    "file": str(ia_path.relative_to(REPO)),
                    "model": jev_ref.get("model"),
                    "verdicts": jev_ref.get("verdicts") or {},
                }
        except (json.JSONDecodeError, OSError):
            pass

    cmp_rows = []
    if cloud_ref:
        for i in range(len(batch)):
            lv = (result.get("verdicts") or {}).get(str(i), {})
            cv = (cloud_ref["verdicts"] or {}).get(str(i), {})
            cmp_rows.append({
                "title": str(threats[i].get("type") or "")[:80],
                "severity": threats[i].get("severity"),
                "local": {
                    "verdict": lv.get("verdict"),
                    "confidence": lv.get("confidence"),
                    "severity_score": lv.get("severity_score"),
                    "immediate_action": lv.get("immediate_action"),
                    "prob_false_positive": lv.get("prob_false_positive"),
                },
                "cloud_jev": {
                    "verdict": cv.get("verdict"),
                    "confidence": cv.get("confidence"),
                    "severity_score": cv.get("severity_score"),
                    "immediate_action": cv.get("immediate_action"),
                    "prob_false_positive": cv.get("prob_false_positive"),
                },
            })

    evidence = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "backend_under_test": "local",
        "laya_serve": "http://127.0.0.1:8787/v1/systemone",
        "laya_model": "multilingual (v4, ft-multilingual-2026-10-08-v4)",
        "criteria_order_in_memory": order_live,
        "criteria_order_ok_live": order_live == ["true_positive", "false_positive", "noise"],
        "source_audit": folder.name,
        "batch_size": len(batch),
        "local_result": result,
        "selftest_local": selftest,
        "cloud_reference": {
            "note": "veredictos cloud (Jev jev-1.13.0) ya guardados en IA_ENRICH.json; 0 llamadas nuevas",
            "model": (cloud_ref or {}).get("model"),
        },
    }
    if cmp_rows:
        same = sum(
            1 for r in cmp_rows if r["local"]["verdict"] == r["cloud_jev"]["verdict"])
        evidence["comparison_local_vs_cloud"] = {
            "note": "mismo lote (primeras amenazas de la auditoria): local v4 vs cloud Jev guardado",
            "rows": cmp_rows,
            "verdict_match": f"{same}/{len(cmp_rows)}",
        }

    EVIDENCE.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    print("evidencia ->", EVIDENCE)

    # Quedar con default cloud (solo memoria de este proceso).
    ai_enrich.set_ai_config({"backend": "cloud", "jev_enabled": False})


if __name__ == "__main__":
    main()
