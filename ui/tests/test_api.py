"""Pruebas de la API FastAPI (stdlib unittest + TestClient).

Ejecutar:  python -m unittest ui.tests.test_api -v

La base de datos se pointing a un temporal: las pruebas no tocan audit_baseline.db
ni las carpetas Auditoria_* reales.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import db  # noqa: E402
import auth  # noqa: E402

# Aislar la base antes de importar la app: si no, los tests indexan el historial real.
db.DB_PATH = Path(tempfile.mkdtemp()) / "api_test.db"
db.init_db()  # TestClient no dispara el evento de arranque de la app
auth.init_auth()

from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402

client = TestClient(main.app)

SIG = db.signature("Run Key sospechoso", "Run key 'Z' apunta a un script")


def _login(username="admin-test", password="clave-de-test", role="admin"):
    try:
        auth.create_user(username, password, role)
    except ValueError:
        pass  # ya existe de un test anterior
    return client.post("/api/auth/login", json={"username": username, "password": password})


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
    def setUp(self):
        # Cada test empieza con una sesion valida: la API ya no es publica.
        client.cookies.clear()
        _login()

    def test_sin_sesion_la_api_responde_401(self):
        fresh = TestClient(main.app)
        self.assertEqual(fresh.get("/api/audits").status_code, 401)
        self.assertEqual(fresh.get("/api/health").status_code, 200)

    def test_login_y_me(self):
        r = client.get("/api/auth/me")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["username"], "admin-test")
        self.assertEqual(r.json()["role"], "admin")

    def test_viewer_no_puede_mutar(self):
        client.cookies.clear()
        _login("observador", "clave-de-test", "viewer")
        self.assertEqual(client.get("/api/audits").status_code, 200)
        self.assertEqual(client.post("/api/allowlist", json={"process": "x", "reason": "y"}).status_code, 403)

    def test_admin_no_privado_no_puede_listar_usuarios(self):
        client.cookies.clear()
        _login("analista", "clave-de-test", "analyst")
        self.assertEqual(client.get("/api/admin/users").status_code, 403)

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


class EvidenceApiTests(unittest.TestCase):
    """Endpoints de evidencia y cobertura contra una auditoria real de ejemplo."""

    FIXTURE = Path(__file__).resolve().parent / "fixtures"

    def setUp(self):
        client.cookies.clear()
        _login()
        self._original = main.RESULTS_DIR
        main.RESULTS_DIR = self.FIXTURE

    def tearDown(self):
        main.RESULTS_DIR = self._original

    def test_manifest(self):
        r = client.get("/api/audits/Auditoria_SAMPLE/manifest")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["schema"], "audit-evidence/1")
        self.assertEqual(data["file_count"], 4)

    def test_verify(self):
        r = client.post("/api/audits/Auditoria_SAMPLE/verify")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"])
        self.assertEqual(r.json()["status"], "integro")

    def test_signature_sin_clave(self):
        os.environ.pop("AUDIT_SIGN_KEY", None)
        r = client.get("/api/audits/Auditoria_SAMPLE/signature?file=RESUMEN_EJECUTIVO.txt")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["signed"])

    def test_coverage(self):
        r = client.get("/api/audits/Auditoria_SAMPLE/coverage")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["observed"], ["T1571"])
        self.assertEqual(len(data["declared_gaps"]), 2)
        self.assertIn("T1059.001", data["gap_vs_target"])

    def test_audit_id_inexistente(self):
        self.assertEqual(client.get("/api/audits/Auditoria_NO_EXISTE/manifest").status_code, 404)
        self.assertEqual(client.get("/api/audits/../etc/manifest").status_code, 404)


if __name__ == "__main__":
    unittest.main()
