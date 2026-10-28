"""Pruebas de la API FastAPI (stdlib unittest + TestClient).

Ejecutar:  python -m unittest ui.tests.test_api -v

La base de datos se pointing a un temporal: las pruebas no tocan audit_baseline.db
ni las carpetas Auditoria_* reales.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import db  # noqa: E402

# Aislar la base antes de importar la app: si no, los tests indexan el historial real.
db.DB_PATH = Path(tempfile.mkdtemp()) / "api_test.db"
db.init_db()  # TestClient no dispara el evento de arranque de la app

from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402

client = TestClient(main.app)

SIG = db.signature("Run Key sospechoso", "Run key 'Z' apunta a un script")


def _seed_threat():
    db.init_db()
    with db.connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO threats
               (signature, type, severity, description, first_seen, last_seen, occurrences,
                status, sla_days, due_at, details)
               VALUES (?, 'Run Key sospechoso', 'HIGH', 'Run key Z', '2026-01-01 00:00:00',
                       '2026-01-02 00:00:00', 3, 'open', 3, '2026-01-04 00:00:00',
                       '{"Name": "powershell"}')""",
            (SIG,),
        )


class ApiTests(unittest.TestCase):
    def test_config_y_baseline(self):
        r = client.get("/api/config")
        self.assertEqual(r.status_code, 200)
        self.assertIn("version", r.json())

        r = client.get("/api/baseline")
        self.assertEqual(r.status_code, 200)
        for key in ("audits", "distinct_threats", "open", "overdue", "series"):
            self.assertIn(key, r.json())

    def test_threats_y_sla(self):
        _seed_threat()
        r = client.get("/api/threats")
        self.assertEqual(r.status_code, 200)
        threats = r.json()["threats"]
        self.assertEqual(len(threats), 1)
        self.assertTrue(threats[0]["overdue"])
        self.assertEqual(threats[0]["sla_days"], 3)

        r = client.get("/api/sla")
        self.assertEqual(r.status_code, 200)
        sla = r.json()
        self.assertEqual(sla["policy"], {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 7, "LOW": 30})
        self.assertEqual(sla["overdue"], 1)

        r = client.get("/api/threats?overdue=true")
        self.assertEqual(len(r.json()["threats"]), 1)

    def test_status_triage_y_allowlist(self):
        _seed_threat()
        r = client.patch(
            f"/api/threats/{SIG}/status",
            json={"status": "false_positive", "note": "ruido conocido"},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["threat"]["status"], "false_positive")
        self.assertIsNotNone(body["allowlist_entry"])

        entries = client.get("/api/allowlist").json()["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["process"], "powershell")

        # Reabrir retira la regla: el triage no puede ser unidireccional.
        client.patch(f"/api/threats/{SIG}/status", json={"status": "open"})
        self.assertEqual(client.get("/api/allowlist").json()["entries"], [])

    def test_invalid_inputs(self):
        _seed_threat()
        self.assertEqual(
            client.patch(f"/api/threats/{SIG}/status", json={"status": "banana"}).status_code,
            400,
        )
        self.assertEqual(
            client.patch("/api/threats/NOEXISTE/status", json={"status": "open"}).status_code,
            404,
        )
        self.assertEqual(
            client.patch(f"/api/threats/{SIG}/sla", json={"sla_days": 0}).status_code,
            400,
        )
        self.assertEqual(
            client.post("/api/allowlist", json={"threat_type": "X", "reason": "sin criterio"}).status_code,
            400,
        )

    def test_allowlist_crud(self):
        r = client.post(
            "/api/allowlist",
            json={"threat_type": "Puerto sospechoso en escucha", "process": "myapp", "ports": [5000], "reason": "servicio interno"},
        )
        self.assertEqual(r.status_code, 200)
        entry_id = r.json()["id"]
        self.assertEqual(client.delete(f"/api/allowlist/{entry_id}").status_code, 200)
        self.assertEqual(client.delete(f"/api/allowlist/{entry_id}").status_code, 404)

    def test_csrf_blocks_origen_ajeno(self):
        r = client.post(
            "/api/allowlist",
            headers={"Origin": "https://evil.example"},
            json={"process": "x", "reason": "y"},
        )
        self.assertEqual(r.status_code, 403)

    def test_trend_series(self):
        r = client.get("/api/trend")
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json()["series"], list)


if __name__ == "__main__":
    unittest.main()
