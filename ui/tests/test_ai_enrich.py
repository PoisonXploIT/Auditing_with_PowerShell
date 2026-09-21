"""Tests sin red para ai_enrich (Jev + LLM local) de la UI de Security Audit.

Se parchea `ai_enrich._http_post_json` (el unico punto de salida HTTP).
Ejecutar desde ui/:  python -m unittest tests.test_ai_enrich -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ai_enrich  # noqa: E402


def _cfg(jev=True, key="k", llm=False, url="", model=""):
    ai_enrich._ai_config.update({
        "jev_enabled": jev,
        "jev_api_key": key,
        "jev_model": ai_enrich.PINNED_MODEL,
        "jev_base_url": ai_enrich.DEFAULT_JEV_BASE_URL,
        "jev_timeout": 30,
        "llm_enabled": llm,
        "llm_base_url": url,
        "llm_model": model,
        "llm_timeout": 120,
    })


def _threats():
    return [
        {"timestamp": "t0", "type": "Usuario sin contrasena", "severity": "CRITICAL",
         "description": "El usuario admin no requiere contrasena.", "details": None},
        {"timestamp": "t1", "type": "Proceso sin ruta", "severity": "HIGH",
         "description": "El proceso x.exe no tiene ruta valida.", "details": None},
    ]


class TestProbFalsePositive(unittest.TestCase):
    def test_true_positive_derives_one_minus_confidence(self):
        self.assertEqual(ai_enrich._prob_false_positive("true_positive", 0.9), 0.1)

    def test_false_positive_uses_confidence(self):
        self.assertEqual(ai_enrich._prob_false_positive("false_positive", 0.8), 0.8)

    def test_noise_treated_as_not_real(self):
        self.assertEqual(ai_enrich._prob_false_positive("noise", 0.6), 0.6)

    def test_unknown_verdict_or_bad_confidence(self):
        self.assertIsNone(ai_enrich._prob_false_positive(None, 0.5))
        self.assertIsNone(ai_enrich._prob_false_positive("true_positive", None))
        self.assertIsNone(ai_enrich._prob_false_positive("true_positive", "x"))


class TestJevEnrich(unittest.TestCase):
    def setUp(self):
        _cfg(jev=True, key="k")

    def test_skipped_when_disabled_or_no_key_or_empty(self):
        _cfg(jev=False)
        self.assertEqual(ai_enrich.jev_enrich(_threats())["status"], "skipped")
        _cfg(jev=True, key="")
        self.assertEqual(ai_enrich.jev_enrich(_threats())["status"], "skipped")
        _cfg(jev=True, key="k")
        self.assertEqual(ai_enrich.jev_enrich([])["reason"], "no_findings")

    def test_ok_maps_answers_and_derives_prob_fp(self):
        answers = {
            "f0_verdict": {"choice": "true_positive", "confidence": 0.95},
            "f0_sev": {"score": 3},
            "f0_action": {"noul": 0.9},
            "f1_verdict": {"choice": "false_positive", "confidence": 0.7},
            "f1_sev": {"score": 1},
            "f1_action": {"noul": 0.1},
        }
        with mock.patch.object(ai_enrich, "_http_post_json",
                               return_value=(200, {"model": "jev-1.13.0", "answers": answers})):
            res = ai_enrich.jev_enrich(_threats())
        self.assertEqual(res["status"], "ok")
        v0 = res["verdicts"]["0"]
        v1 = res["verdicts"]["1"]
        self.assertEqual(v0["verdict"], "true_positive")
        self.assertEqual(v0["prob_false_positive"], 0.05)
        self.assertEqual(v0["severity_score"], 3)
        self.assertEqual(v1["prob_false_positive"], 0.7)

    def test_error_on_http_failure_and_network_error(self):
        with mock.patch.object(ai_enrich, "_http_post_json", return_value=(401, {})):
            self.assertEqual(ai_enrich.jev_enrich(_threats())["status"], "error")
        with mock.patch.object(ai_enrich, "_http_post_json", side_effect=OSError("boom")):
            self.assertEqual(ai_enrich.jev_enrich(_threats())["status"], "error")


class TestLlm(unittest.TestCase):
    def setUp(self):
        _cfg(jev=False, llm=True, url="http://127.0.0.1:8099", model="dirk-test")

    def _chat_ok(self, content):
        return mock.patch.object(
            ai_enrich, "_http_post_json",
            return_value=(200, {"model": "dirk-test",
                                "choices": [{"message": {"content": content}}]}))

    def test_explain_threat_parses_bounded_spanish_json(self):
        with self._chat_ok('{"resumen": "R.", "porque": "P.", "sugerencia": "S."}'):
            res = ai_enrich.llm_explain_threat(_threats()[0], {"verdict": "true_positive"})
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["resumen"], "R.")

    def test_explain_threat_unparseable(self):
        with self._chat_ok("esto no es json"):
            res = ai_enrich.llm_explain_threat(_threats()[0], None)
        self.assertEqual(res["status"], "unavailable")

    def test_executive_summary_caps_actions(self):
        content = json.dumps({
            "resumen_ejecutivo": "Resumen general.",
            "riesgo_principal": "Riesgo X",
            "acciones_prioritarias": ["a1", "a2", "a3", "a4", "a5", "a6"],
        })
        with self._chat_ok(content):
            res = ai_enrich.llm_executive_summary({"summary": {}, "risk_level": "ALTO"}, _threats(), {"status": "skipped"})
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(res["acciones_prioritarias"]), 5)

    def test_loopback_only(self):
        self.assertTrue(ai_enrich.is_loopback_url("http://127.0.0.1:8099"))
        self.assertTrue(ai_enrich.is_loopback_url("http://localhost:1/v1"))
        self.assertFalse(ai_enrich.is_loopback_url("http://example.com"))
        self.assertFalse(ai_enrich.is_loopback_url(""))


class TestEnrichAudit(unittest.TestCase):
    def test_clean_audit_writes_files_and_degrades(self):
        _cfg(jev=False, llm=False)
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "Auditoria_20260921"
            folder.mkdir()
            meta = {"summary": {}, "risk_level": "BAJO"}
            res = ai_enrich.enrich_audit(folder, meta)
        self.assertEqual(res["threats_total"], 0)
        self.assertEqual(res["jev"]["status"], "skipped")
        self.assertIsNone(res["llm_explanations"])
        self.assertIsNone(res["executive_summary"])

    def test_full_run_with_threats_writes_json_and_md(self):
        _cfg(jev=True, key="k", llm=True, url="http://127.0.0.1:8099", model="dirk-test")
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "Auditoria_20260921"
            folder.mkdir()
            (folder / "AMENAZAS_DETECTADAS.json").write_text(
                json.dumps(_threats()), encoding="utf-8")
            answers = {
                "f0_verdict": {"choice": "true_positive", "confidence": 0.9},
                "f0_sev": {"score": 3}, "f0_action": {"noul": 0.8},
                "f1_verdict": {"choice": "noise", "confidence": 0.5},
                "f1_sev": {"score": 0}, "f1_action": {"noul": 0.0},
            }
            llm_body = (200, {"model": "dirk-test", "choices": [{"message": {
                "content": '{"resumen": "R.", "porque": "P.", "sugerencia": "S."}'}}]})
            exec_body = (200, {"model": "dirk-test", "choices": [{"message": {
                "content": json.dumps({
                    "resumen_ejecutivo": "Resumen general de la auditoria.",
                    "riesgo_principal": "Usuario sin contrasena",
                    "acciones_prioritarias": ["a1", "a2"],
                })}}]})
            with mock.patch.object(ai_enrich, "_http_post_json", side_effect=[
                (200, {"model": "jev-1.13.0", "answers": answers}),  # jev
                llm_body, llm_body,                                  # 2 explicaciones
                exec_body,                                          # resumen ejecutivo
            ]):
                res = ai_enrich.enrich_audit(folder, {"summary": {}, "risk_level": "CRITICO"})

            self.assertEqual(res["jev"]["status"], "ok")
            self.assertEqual(len(res["llm_explanations"]), 2)
            self.assertEqual(res["executive_summary"]["status"], "ok")
            enrich = json.loads((folder / "IA_ENRICH.json").read_text(encoding="utf-8"))
            self.assertEqual(enrich["audit_id"], "Auditoria_20260921")
            md = (folder / "IA_RESUMEN_EJECUTIVO.md").read_text(encoding="utf-8")
            self.assertIn("Resumen Ejecutivo", md)
            self.assertIn("Veredictos Jev", md)


if __name__ == "__main__":
    unittest.main()
