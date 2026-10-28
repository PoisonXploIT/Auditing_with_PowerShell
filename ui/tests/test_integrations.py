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


if __name__ == "__main__":
    unittest.main()
