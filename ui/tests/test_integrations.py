"""Pruebas de integraciones: IOCs, capa Navigator y Splunk HEC (stdlib unittest).

Ejecutar:  python -m unittest ui.tests.test_integrations -v
"""

import json
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

    def test_coverage_report_desglosa_por_severidad(self):
        report = integrations.coverage_report(THREATS, ["T1571", "T1547.001", "T1059.001"])
        self.assertEqual(report["gap"], ["T1059.001"])
        self.assertEqual(report["coverage_pct"], 66.7)
        self.assertEqual(report["by_severity"]["HIGH"]["hallazgos"], 2)
        self.assertEqual(report["by_severity"]["HIGH"]["dentro_del_target"], 2)
        # Un hallazgo sin tecnica MITRE es un hueco de mapeo, no una cobertura.
        sin_tecnica = integrations.coverage_report([{"Severity": "LOW", "Description": "ruido"}], ["T1571"])
        self.assertEqual(sin_tecnica["by_severity"]["LOW"]["sin_tecnica"], 1)
        self.assertEqual(sin_tecnica["gap"], ["T1571"])
        self.assertEqual(integrations.coverage_report(THREATS, [])["coverage_pct"], 0.0)

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

    def test_alerta_sla_sin_vencidos_no_envia_nada(self):
        os.environ["SPLUNK_HEC_URL"] = "http://127.0.0.1:8088"
        os.environ["SPLUNK_HEC_TOKEN"] = "token"
        try:
            result = integrations.push_sla_alert({"overdue": []})
            self.assertTrue(result["ok"])
            self.assertIn("no hay nada", result["reason"].lower())
        finally:
            os.environ.pop("SPLUNK_HEC_URL")
            os.environ.pop("SPLUNK_HEC_TOKEN")

    def test_evento_sla_con_vencidos(self):
        report = {
            "overdue": [
                {"signature": "ABC", "type": "Run Key sospechoso", "severity": "HIGH",
                 "due_at": "2026-01-04 00:00:00", "days_overdue": 12}
            ],
            "by_severity": {"HIGH": {"open": 1, "overdue": 1, "sla_days": 3}},
        }
        event = integrations.sla_alert_event(report)
        self.assertEqual(event["sourcetype"], "audit:sla")
        self.assertEqual(event["event"]["alert"], "sla_overdue")
        self.assertEqual(event["event"]["overdue_count"], 1)
        self.assertEqual(event["event"]["by_severity"], {"HIGH": 1})
        self.assertEqual(event["event"]["details"][0]["days_overdue"], 12)

    def test_evento_sla_con_forma_real_de_db_sla_report(self):
        """db.sla_report() devuelve 'overdue' como contador y 'overdue_list' como detalle.

        Si el evento se construyera sobre el contador, el detalle se perderia y Splunk
        recibiria una alerta sin los hallazgos que la motivan.
        """
        report = {
            "policy": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 7, "LOW": 30},
            "open": 4,
            "overdue": 2,
            "overdue_list": [
                {"signature": "AAA", "type": "Run Key sospechoso", "severity": "HIGH",
                 "first_seen": "2026-01-01 00:00:00", "due_at": "2026-01-04 00:00:00",
                 "days_overdue": 12, "occurrences": 3},
                {"signature": "BBB", "type": "Puerto sospechoso", "severity": "MEDIUM",
                 "first_seen": "2026-02-01 00:00:00", "due_at": "2026-02-10 00:00:00",
                 "days_overdue": 4, "occurrences": 1},
            ],
            "by_severity": {
                "HIGH": {"open": 2, "overdue": 1, "sla_days": 3, "oldest": "2026-01-01 00:00:00"},
                "MEDIUM": {"open": 2, "overdue": 1, "sla_days": 7, "oldest": "2026-02-01 00:00:00"},
            },
        }
        event = integrations.sla_alert_event(report)
        self.assertEqual(event["event"]["overdue_count"], 2)
        self.assertEqual(event["event"]["by_severity"], {"HIGH": 1, "MEDIUM": 1})
        self.assertEqual({d["signature"] for d in event["event"]["details"]}, {"AAA", "BBB"})
        self.assertTrue(all(d["due_at"] and d["days_overdue"] >= 0 for d in event["event"]["details"]))

    def test_alerta_sla_end_to_end_con_servidor_hec_real(self):
        """Prueba de extremo a extremo contra un HEC local: la peticion que sale es
        la que Splunk espera (ruta, cabecera de autenticacion, payload parseable).
        """
        import http.server
        import threading
        from urllib.request import Request
        from urllib.error import URLError  # noqa: F401 (usado por el manejo de errores)

        captured = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self, *args):  # pragma: no cover - stub
                length = int(self.headers.get("Content-Length", 0))
                captured["path"] = self.path
                captured["auth"] = self.headers.get("Authorization")
                captured["content_type"] = self.headers.get("Content-Type")
                captured["body"] = self.rfile.read(length).decode("utf-8")
                payload = b'{"text":"Success","code":0}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):  # silenciar el servidor de prueba
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            os.environ["SPLUNK_HEC_URL"] = f"http://127.0.0.1:{port}"
            os.environ["SPLUNK_HEC_TOKEN"] = "token-de-prueba"
            report = {
                "overdue": 1,
                "overdue_list": [
                    {"signature": "AAA", "type": "Run Key sospechoso", "severity": "HIGH",
                     "due_at": "2026-01-04 00:00:00", "days_overdue": 12}
                ],
                "by_severity": {"HIGH": {"open": 1, "overdue": 1, "sla_days": 3}},
            }
            result = integrations.push_sla_alert(report)
        finally:
            server.shutdown()
            server.server_close()
            os.environ.pop("SPLUNK_HEC_URL", None)
            os.environ.pop("SPLUNK_HEC_TOKEN", None)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(captured["path"], "/services/collector/event")
        self.assertEqual(captured["auth"], "Splunk token-de-prueba")
        self.assertEqual(captured["content_type"], "application/json")
        sent = json.loads(captured["body"])
        self.assertEqual(sent["sourcetype"], "audit:sla")
        self.assertEqual(sent["source"], "Invoke-SecurityAudit")
        self.assertEqual(sent["event"]["alert"], "sla_overdue")
        self.assertEqual(sent["event"]["overdue_count"], 1)
        self.assertIn("time", sent)

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
