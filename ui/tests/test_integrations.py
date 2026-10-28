"""Pruebas de integraciones: IOCs, capa Navigator y Splunk HEC (stdlib unittest).

Ejecutar:  python -m unittest ui.tests.test_integrations -v
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import integrations  # noqa: E402

THREATS = [
    {
        "ThreatType": "Puerto sospechoso en escucha",
        "Severity": "MEDIUM",
        "Description": "Puerto 9999 en escucha en 0.0.0.0 (proceso 'splunkd')",
        "MitreTechnique": "T1571",
        "MitreTactic": "Command and Control",
        "Details": {"LocalPort": 9999, "LocalAddress": "0.0.0.0", "ProcessName": "splunkd"},
    },
    {
        "ThreatType": "Conexion a puerto sospechoso",
        "Severity": "HIGH",
        "Description": "Proceso 'node' (PID: 42) conectado a 198.51.100.7:4444",
        "MitreTechnique": "T1571",
        "MitreTactic": "Command and Control",
        "Details": {"RemotePort": 4444, "RemoteAddress": "198.51.100.7", "ProcessName": "node", "ProcessPath": "C:\\Program Files\\nodejs\\node.exe"},
    },
    {
        "ThreatType": "Run Key con script",
        "Severity": "HIGH",
        "Description": "Run key apunta a un script",
        "MitreTechnique": "T1547.001",
        "MitreTactic": "Persistence",
        "Details": {"Name": "powershell", "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    },
]


class IntegrationTests(unittest.TestCase):
    def test_extract_iocs_deduplicates(self):
        iocs = integrations.extract_iocs(THREATS)
        pairs = {(i["type"], i["value"]) for i in iocs}
        self.assertIn(("port", "9999"), pairs)
        self.assertIn(("ip", "198.51.100.7"), pairs)
        self.assertIn(("process", "splunkd"), pairs)
        self.assertIn(("port", "4444"), pairs)
        # El puerto 9999 aparece en la descripcion y en Details: no debe duplicarse.
        self.assertEqual(len(pairs), len(iocs))

    def test_navigator_layer_scores_by_occurrence(self):
        layer = integrations.navigator_layer("Prueba", THREATS)
        self.assertEqual(layer["version"], "2.1")
        self.assertEqual(layer["domain"], "attack-enterprise")
        by_id = {t["techniqueID"]: t for t in layer["techniques"]}
        self.assertEqual(by_id["T1571"]["score"], 2)
        self.assertEqual(by_id["T1547.001"]["score"], 1)

    def test_coverage_gap(self):
        layer = integrations.navigator_layer("Prueba", THREATS)
        gap = integrations.coverage_gap(layer, ["T1571", "T1547.001", "T1059.001", "T1053.008"])
        self.assertEqual(gap, ["T1059.001", "T1053.008"])

    def test_splunk_push_sin_configuracion_no_crash(self):
        os.environ.pop("SPLUNK_HEC_URL", None)
        os.environ.pop("SPLUNK_HEC_TOKEN", None)
        result = integrations.push_to_splunk({"id": "A", "risk": "MEDIO"}, THREATS)
        self.assertFalse(result["ok"])
        self.assertIn("SPLUNK_HEC", result["reason"])

    def test_splunk_event_shape(self):
        event = integrations.splunk_event({"id": "Auditoria_1", "risk": "MEDIO", "threats": 3, "suppressed": 1}, THREATS)
        self.assertEqual(event["sourcetype"], "audit:security")
        self.assertEqual(event["event"]["threats"], 3)
        self.assertEqual(len(event["event"]["details"]), 3)

    def test_splunk_event_usa_claves_reales_del_meta(self):
        """build_audit_meta devuelve risk_level, threats_count y suppressed como lista."""
        event = integrations.splunk_event(
            {
                "id": "Auditoria_20261028_124556",
                "risk_level": "BAJO",
                "threats_count": 0,
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "suppressed": [{"severity": "MEDIUM", "type": "Puerto", "description": "Puerto 9999"}],
            },
            [{"severity": "MEDIUM", "type": "Puerto", "description": "Puerto 9999", "mitre": "T1571"}],
        )
        self.assertEqual(event["event"]["risk"], "BAJO")
        self.assertEqual(event["event"]["threats"], 0)
        self.assertEqual(event["event"]["suppressed"], 1)
        self.assertEqual(event["event"]["details"][0]["mitre"], "T1571")
        self.assertNotIn("index", event)  # Splunk usa el de la fuente HEC

        os.environ["SPLUNK_HEC_INDEX"] = "security"
        try:
            event = integrations.splunk_event({"id": "A"}, [])
            self.assertEqual(event["index"], "security")
        finally:
            os.environ.pop("SPLUNK_HEC_INDEX")

    def test_status_no_expone_valores(self):
        os.environ["SPLUNK_HEC_URL"] = "http://127.0.0.1:8088"
        os.environ["SPLUNK_HEC_TOKEN"] = "no-se-muestra"
        status = integrations.integration_status()
        self.assertTrue(status["splunk"]["configured"])
        self.assertEqual(status["splunk"]["token"], "definido")
        self.assertNotIn("no-se-muestra", str(status))
        os.environ.pop("SPLUNK_HEC_TOKEN")
        os.environ.pop("SPLUNK_HEC_URL")

    def test_enrich_sin_clave_no_toca_la_red(self):
        os.environ.pop("VIRUSTOTAL_API_KEY", None)
        enriched = integrations.enrich_ioc({"type": "ip", "value": "198.51.100.7", "severity": "HIGH"})
        self.assertIsNone(enriched["enrichment"])
        self.assertIn("VIRUSTOTAL_API_KEY", enriched["enrichment_note"])

    def test_splunk_usa_autenticacion_splunk_no_bearer(self):
        """Splunk HEC rechaza 'Bearer <token>' (401). Solo acepta 'Splunk <token>'."""
        captured = {}

        class FakeResponse:
            status = 200

            def read(self):
                return b'{"text":"Success","code":0}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_urlopen(req, timeout=None, context=None):
            captured["url"] = req.full_url
            captured["auth"] = req.get_header("Authorization")
            return FakeResponse()

        original = integrations.urllib.request.urlopen
        integrations.urllib.request.urlopen = fake_urlopen
        try:
            os.environ["SPLUNK_HEC_URL"] = "https://127.0.0.1:8088"
            os.environ["SPLUNK_HEC_TOKEN"] = "token-de-prueba"
            result = integrations.push_to_splunk({"id": "A", "risk": "BAJO"}, [])
        finally:
            integrations.urllib.request.urlopen = original
            os.environ.pop("SPLUNK_HEC_URL")
            os.environ.pop("SPLUNK_HEC_TOKEN")
        self.assertTrue(result["ok"])
        self.assertEqual(captured["auth"], "Splunk token-de-prueba")
        self.assertTrue(captured["url"].endswith("/services/collector/event"))


if __name__ == "__main__":
    unittest.main()
