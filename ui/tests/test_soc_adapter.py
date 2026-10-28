"""Pruebas del adaptador al SOC de Opervanta (stdlib unittest).

Ejecutar:  python -m unittest ui.tests.test_soc_adapter -v

El adaptador esta apagado por defecto: los tests activan PILOOP_SOC_ENABLED en un
directorio temporal, nunca en la carpeta real del SOC.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import integrations  # noqa: E402
import opervanta_soc  # noqa: E402

THREATS = [
    {"type": "Run Key con script", "severity": "HIGH", "description": "Run key apunta a un script",
     "signature": "A1B2C3D4E5F60718", "mitre_technique": "T1547.001", "timestamp": "2026-10-28 10:00:00"},
    {"type": "Puerto sospechoso en escucha", "severity": "CRITICAL", "description": "Puerto 4444 en escucha",
     "signature": "B2C3D4E5F6071829", "mitre_technique": "T1571"},
    {"type": "Firewall deshabilitado", "severity": "MEDIUM", "description": "Firewall off", "signature": ""},
    {"type": "Driver antiguo", "severity": "LOW", "description": "Driver de 2019", "signature": "D4E5F60718293A4B"},
]

SUPPRESSED = [
    {"severity": "MEDIUM", "type": "Puerto sospechoso en escucha", "description": "Puerto 9999 (splunkd)",
     "reason": "regla de allowlist", "mitre": "T1571"},
]


class SocAdapterTests(unittest.TestCase):
    def setUp(self):
        self._dir = os.environ.get("PILOOP_SOC_DIR")
        self._enabled = os.environ.get("PILOOP_SOC_ENABLED")
        os.environ["PILOOP_SOC_DIR"] = str(Path(tempfile.mkdtemp()) / "soc")
        os.environ.pop("PILOOP_SOC_ENABLED", None)

    def tearDown(self):
        if self._dir is not None:
            os.environ["PILOOP_SOC_DIR"] = self._dir
        else:
            os.environ.pop("PILOOP_SOC_DIR", None)
        if self._enabled is not None:
            os.environ["PILOOP_SOC_ENABLED"] = self._enabled
        else:
            os.environ.pop("PILOOP_SOC_ENABLED", None)

    def test_apagado_por_defecto(self):
        self.assertFalse(opervanta_soc.soc_enabled())
        result = opervanta_soc.publish("Auditoria_X", THREATS, SUPPRESSED)
        self.assertFalse(result["enabled"])
        self.assertEqual(result["written"], 0)
        self.assertEqual(result["pending"], len(THREATS) + len(SUPPRESSED))
        self.assertIn("PILOOP_SOC_ENABLED", result["reason"])
        # Nada escrito en disco cuando esta apagado.
        self.assertFalse((Path(os.environ["PILOOP_SOC_DIR"]) / "eventos.jsonl").exists())

    def test_severidades_mapeadas_al_contrato(self):
        mapping = {
            "CRITICAL": "critica",
            "HIGH": "alta",
            "MEDIUM": "media",
            "LOW": "baja",
        }
        for raw, expected in mapping.items():
            self.assertEqual(opervanta_soc.to_soc_severity(raw), expected)
        self.assertEqual(opervanta_soc.to_soc_severity("MEDIUM", suppressed=True), "info")
        self.assertEqual(opervanta_soc.to_soc_severity("desconocida"), "baja")
        self.assertEqual(set(opervanta_soc.SOC_SEVERITIES), {"info", "baja", "media", "alta", "critica"})

    def test_publica_eventos_con_event_id_estable(self):
        os.environ["PILOOP_SOC_ENABLED"] = "1"
        first = opervanta_soc.publish("Auditoria_X", THREATS, SUPPRESSED)
        second = opervanta_soc.publish("Auditoria_X", THREATS, SUPPRESSED)
        self.assertTrue(first["ok"] and first["enabled"])
        self.assertEqual(first["written"], len(THREATS) + len(SUPPRESSED))
        self.assertEqual(first["by_severity"]["critica"], 1)
        self.assertEqual(first["by_severity"]["alta"], 1)
        self.assertEqual(first["by_severity"]["media"], 1)
        self.assertEqual(first["by_severity"]["baja"], 1)
        self.assertEqual(first["by_severity"]["info"], 1)

        path = Path(os.environ["PILOOP_SOC_DIR"]) / "eventos.jsonl"
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), 2 * (len(THREATS) + len(SUPPRESSED)))
        for event in lines:
            self.assertEqual(event["schema"], "soc-event/1")
            self.assertEqual(event["correlation_id"], "Auditoria_X")
            self.assertIn(event["severity"], opervanta_soc.SOC_SEVERITIES)
            self.assertRegex(event["event_id"], r"^[0-9A-F]{16}$")

        # El event_id sale de la Signature: el mismo hallazgo en dos ejecuciones
        # produce el mismo identificador, y el SOC puede deduplicar.
        ids_first = {e["event_id"] for e in lines[: len(lines) // 2]}
        ids_second = {e["event_id"] for e in lines[len(lines) // 2:]}
        self.assertEqual(ids_first, ids_second)

    def test_suprimidas_se_declaran_como_info(self):
        os.environ["PILOOP_SOC_ENABLED"] = "1"
        events = opervanta_soc.build_events("Auditoria_X", [], SUPPRESSED)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], "info")
        self.assertTrue(events[0]["suppressed"])
        self.assertIn("allowlist", events[0]["reason"])

    def test_no_duplica_el_envio_a_splunk(self):
        """El adaptador no debe tocar Splunk: Opervanta ya tiene su cola HEC."""
        os.environ["PILOOP_SOC_ENABLED"] = "1"

        def boom(*args, **kwargs):  # pragma: no cover
            raise AssertionError("el adaptador al SOC no debe enviar a Splunk")

        original = integrations._post_hec
        integrations._post_hec = boom
        try:
            result = opervanta_soc.publish("Auditoria_X", THREATS, SUPPRESSED)
        finally:
            integrations._post_hec = original
        self.assertTrue(result["ok"])
        self.assertEqual(result["written"], len(THREATS) + len(SUPPRESSED))

    def test_status_sin_exponer_claves(self):
        status = opervanta_soc.status()
        self.assertFalse(status["enabled"])
        self.assertEqual(status["events"], 0)
        self.assertIn("cola HEC", status["note"])


if __name__ == "__main__":
    unittest.main()
