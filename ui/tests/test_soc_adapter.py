"""Pruebas del adaptador al SOC de Opervanta (stdlib unittest).

Ejecutar:  python -m unittest ui.tests.test_soc_adapter -v

El adaptador esta apagado por defecto. Los tests levantan un ingress stub local y
activan PILOOP_SOC_ENABLED solo dentro del test; nunca se toca la instancia real
de Opervanta.
"""

import hashlib
import hmac
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
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

SECRET = "secreto-de-test-no-real"
NONCES = set()


class StubIngress(BaseHTTPRequestHandler):
    """Reproduce el contrato real de /alerta: firma v2, nonce de un solo uso."""

    def do_POST(self):
        if self.path != "/alerta":
            self.send_response(404)
            self.end_headers()
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        sensor = self.headers.get("X-Piloop-Alerta-Sensor", "")
        ts = self.headers.get("X-Piloop-Alerta-Ts", "")
        nonce = self.headers.get("X-Piloop-Alerta-Nonce", "")
        hmac_hex = self.headers.get("X-Piloop-Alerta-Hmac", "")

        if not sensor or not ts or not nonce or not hmac_hex:
            self._json({"ok": False, "motivo": "falta firma v2 (sensor, ts, nonce, hmac)"}, 401)
            return
        base = f"v2|{sensor}|{ts}|{nonce}|{hashlib.sha256(raw).hexdigest()}".encode("utf-8")
        if not hmac.compare_digest(hmac.new(SECRET.encode(), base, hashlib.sha256).hexdigest(), hmac_hex):
            self._json({"ok": False, "motivo": "firma incorrecta"}, 401)
            return
        if nonce in NONCES:
            self._json({"ok": False, "motivo": "nonce repetido (replay)"}, 401)
            return
        NONCES.add(nonce)
        payload = json.loads(raw.decode("utf-8"))
        self._json({"ok": True, "firma": payload.get("firma"), "resultado": "pre-triaje"}, 200)

    def _json(self, body, status):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silencioso
        pass


class SocAdapterTests(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in
                       ("PILOOP_SOC_ENABLED", "PILOOP_SOC_URL", "PILOOP_SOC_SENSOR",
                        "PILOOP_SOC_ALERTA_SECRET", "PILOOP_ALERTA_SECRET", "PILOOP_ALERTA_SECRETS")}
        NONCES.clear()
        self.server = HTTPServer(("127.0.0.1", 0), StubIngress)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _enable(self):
        os.environ["PILOOP_SOC_ENABLED"] = "1"
        os.environ["PILOOP_SOC_URL"] = f"http://127.0.0.1:{self.port}"
        os.environ["PILOOP_SOC_SENSOR"] = "audit-powershell"
        os.environ["PILOOP_SOC_ALERTA_SECRET"] = SECRET

    def test_apagado_por_defecto(self):
        os.environ.pop("PILOOP_SOC_ENABLED", None)
        result = opervanta_soc.publish("Auditoria_X", THREATS, SUPPRESSED)
        self.assertFalse(result["enabled"])
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["pending"], len(THREATS) + len(SUPPRESSED))
        self.assertIn("PILOOP_SOC_ENABLED", result["reason"])

    def test_severidades_mapeadas_al_contrato(self):
        for raw, expected in {"CRITICAL": "critica", "HIGH": "alta", "MEDIUM": "media", "LOW": "baja"}.items():
            self.assertEqual(opervanta_soc.to_soc_severity(raw), expected)
        self.assertEqual(opervanta_soc.to_soc_severity("MEDIUM", suppressed=True), "info")
        self.assertEqual(opervanta_soc.to_soc_severity("desconocida"), "baja")
        self.assertEqual(set(opervanta_soc.SOC_SEVERITIES), {"info", "baja", "media", "alta", "critica"})

    def test_event_id_estable(self):
        first = opervanta_soc.build_events("Auditoria_X", THREATS, SUPPRESSED)
        second = opervanta_soc.build_events("Auditoria_X", THREATS, SUPPRESSED)
        self.assertEqual({e["event_id"] for e in first}, {e["event_id"] for e in second})
        for event in first:
            self.assertRegex(event["event_id"], r"^[0-9A-F]{16}$")
            self.assertEqual(event["correlation_id"], "Auditoria_X")

    def test_acepta_las_claves_de_powershell(self):
        """PowerShell emite `Severity`, `Type`, `Signature`, `Details`.

        Si el adaptador solo lee claves en minusculas, un HIGH llega como `baja` y la
        Signature se ignora: el SOC tria el hallazgo con la severidad equivocada y no
        puede deduplicar. El adaptador debe aceptar ambas grafias.
        """
        raw = [{"Severity": "HIGH", "Type": "Puerto sospechoso en escucha",
                "Signature": "E2E-PAQUETE-0001", "Details": "4444 en escucha"}]
        eventos = opervanta_soc.build_events("Auditoria_E2E", raw)
        self.assertEqual(len(eventos), 1)
        self.assertEqual(eventos[0]["severity"], "alta")
        self.assertEqual(eventos[0]["event_id"], "E2E-PAQUETE-0001")
        self.assertEqual(eventos[0]["type"], "Puerto sospechoso en escucha")
        self.assertEqual(eventos[0]["description"], "4444 en escucha")

    def test_sin_secreto_no_envia_nada(self):
        """Fail closed: sin secreto no se publica, y no se escribe en el SOC a mano."""
        self._enable()
        os.environ.pop("PILOOP_SOC_ALERTA_SECRET", None)
        os.environ.pop("PILOOP_ALERTA_SECRET", None)
        os.environ.pop("PILOOP_ALERTA_SECRETS", None)
        result = opervanta_soc.publish("Auditoria_X", THREATS, SUPPRESSED)
        self.assertFalse(result["ok"])
        self.assertEqual(result["sent"], 0)
        self.assertIn("PILOOP_SOC_ALERTA_SECRET", result["reason"])

    def test_publica_con_firma_v2(self):
        self._enable()
        result = opervanta_soc.publish("Auditoria_X", THREATS, SUPPRESSED)
        self.assertTrue(result["ok"], result.get("rejected"))
        self.assertEqual(result["sent"], len(THREATS) + len(SUPPRESSED))
        self.assertEqual(result["pending"], 0)
        self.assertEqual(result["by_severity"]["critica"], 1)
        self.assertEqual(result["by_severity"]["alta"], 1)
        self.assertEqual(result["by_severity"]["media"], 1)
        self.assertEqual(result["by_severity"]["baja"], 1)
        self.assertEqual(result["by_severity"]["info"], 1)

    def test_rechaza_firma_incorrecta(self):
        self._enable()
        os.environ["PILOOP_SOC_ALERTA_SECRET"] = "otro-secreto"
        result = opervanta_soc.publish("Auditoria_X", THREATS, [])
        self.assertFalse(result["ok"])
        self.assertEqual(result["sent"], 0)
        self.assertIn("firma incorrecta", result["rejected"][0]["motivo"])

    def test_cada_alerta_lleva_nonce_distinto(self):
        """Un nonce reutilizado es un replay: el stub lo rechaza.

        El adaptador genera un nonce nuevo por alerta, asi que dos publicaciones de
        la misma auditoria no se rechazan por replay.
        """
        self._enable()
        result = opervanta_soc.publish("Auditoria_X", THREATS, SUPPRESSED)
        self.assertTrue(result["ok"], result.get("rejected"))
        self.assertEqual(len(NONCES), len(THREATS) + len(SUPPRESSED))

    def test_no_duplica_el_envio_a_splunk(self):
        self._enable()

        def boom(*args, **kwargs):  # pragma: no cover
            raise AssertionError("el adaptador al SOC no debe enviar a Splunk")

        original = integrations._post_hec
        integrations._post_hec = boom
        try:
            result = opervanta_soc.publish("Auditoria_X", THREATS, SUPPRESSED)
        finally:
            integrations._post_hec = original
        self.assertTrue(result["ok"])
        self.assertEqual(result["sent"], len(THREATS) + len(SUPPRESSED))

    def test_status_sin_exponer_claves(self):
        self._enable()
        status = opervanta_soc.status()
        self.assertTrue(status["enabled"])
        self.assertTrue(status["secret_defined"])
        self.assertNotIn(SECRET, json.dumps(status))
        self.assertIn("firma v2", status["note"])

    def test_secreto_de_opervanta_como_fallback(self):
        """Si no hay secreto propio, se usa el de Opervanta (global o por sensor)."""
        self._enable()
        os.environ.pop("PILOOP_SOC_ALERTA_SECRET", None)
        os.environ["PILOOP_ALERTA_SECRETS"] = json.dumps({"audit-powershell": SECRET})
        result = opervanta_soc.publish("Auditoria_X", THREATS, [])
        self.assertTrue(result["ok"], result.get("rejected"))


if __name__ == "__main__":
    unittest.main()
