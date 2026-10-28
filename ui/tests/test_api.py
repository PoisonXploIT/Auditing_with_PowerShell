"""Pruebas de la API FastAPI (stdlib unittest + TestClient).

Ejecutar:  python -m unittest ui.tests.test_api -v

La base de datos se pointing a un temporal: las pruebas no tocan audit_baseline.db
ni las carpetas Auditoria_* reales.
"""

import json
import os
import re
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
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    # La sesion arrastra su token CSRF: sin la cabecera, el backend rechaza la mutacion.
    client.headers["X-CSRF-Token"] = r.json().get("csrf_token", "")
    return r


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

    def test_alerta_sla_sin_splunk_configurado(self):
        _seed_threat()
        os.environ.pop("SPLUNK_HEC_URL", None)
        os.environ.pop("SPLUNK_HEC_TOKEN", None)
        r = client.post("/api/sla/alert")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["overdue"], 1)
        self.assertFalse(data["ok"])
        self.assertIn("SPLUNK_HEC", data["reason"])

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

    def test_mutacion_sin_token_csrf_rechazada(self):
        """Una peticion sin Origin ni Referer (curl, formulario de terceros) no muta.

        La sesion es valida; lo que falta es el token de doble submission.
        """
        fresh = TestClient(main.app)
        fresh.post("/api/auth/login", json={"username": "admin-test", "password": "clave-de-test"})
        r = fresh.post("/api/allowlist", json={"process": "x", "reason": "y"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("CSRF", r.json()["detail"])
        # El rechazo es previo a la escritura: no queda regla creada.
        self.assertEqual(client.get("/api/allowlist").json()["entries"], [])

    def test_todas_las_mutaciones_pasan_por_el_middleware_csrf(self):
        """Inventario: cada ruta de escritura de la API está protegida, incluida
        /api/sla/alert y los endpoints de exports."""
        mutating = []
        for route in main.app.routes:
            methods = getattr(route, "methods", set())
            if methods & {"POST", "PUT", "PATCH", "DELETE"}:
                mutating.append((route.path, sorted(methods)))
        self.assertIn("/api/sla/alert", [p for p, _ in mutating])
        # /api/exports es de lectura: si algun dia se convierte en escritura, el
        # middleware la cubre porque la puerta se aplica por metodo, no por ruta.
        self.assertNotIn("/api/exports", [p for p, _ in mutating])
        for path, methods in mutating:
            url = re.sub(r"\{[^}]+\}", "x", path)
            for method in methods:
                if method == "GET":
                    continue
                r = client.request(method, url, headers={"Origin": "https://evil.example"}, content=b"")
                self.assertEqual(
                    r.status_code, 403,
                    f"{method} {url} no esta cerrada por el middleware CSRF",
                )

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


class TrailAndExportTests(unittest.TestCase):
    """Registro de actividad filtrado/exportado y firma de los exports."""

    FIXTURE = Path(__file__).resolve().parent / "fixtures"

    def setUp(self):
        client.cookies.clear()
        _login()
        self._original = main.RESULTS_DIR
        main.RESULTS_DIR = self.FIXTURE
        os.environ["AUDIT_EXPORT_DIR"] = str(Path(tempfile.mkdtemp()) / "exports")

    def tearDown(self):
        main.RESULTS_DIR = self._original
        os.environ.pop("AUDIT_EXPORT_DIR", None)

    def test_stream_sse_emite_y_cierra(self):
        run_id = "test-run-sse"
        main.RUNS_DIR = Path(tempfile.mkdtemp())
        (main.RUNS_DIR / f"{run_id}.json").write_text(json.dumps({"phase": "done", "percent": 100}), encoding="utf-8")
        with main.RUNS_LOCK:
            main.RUNS[run_id] = {"process": type("P", (), {"poll": lambda self: 0})(), "started_at": "x"}
        try:
            r = client.get(f"/api/runs/{run_id}/stream")
            self.assertEqual(r.status_code, 200)
            self.assertIn("text/event-stream", r.headers["content-type"])
            self.assertIn('"phase": "done"', r.text)
            self.assertIn("event: end", r.text)
        finally:
            with main.RUNS_LOCK:
                main.RUNS.pop(run_id, None)

    def test_stream_sse_run_inexistente(self):
        self.assertEqual(client.get("/api/runs/no-existe/stream").status_code, 404)

    def test_trail_filtra_por_accion(self):
        auth.record_event("sammi", "triage", "cambio de estado")
        auth.record_event("sammi", "splunk_push", "envio")
        r = client.get("/api/admin/trail?action=triage")
        self.assertEqual(r.status_code, 200)
        actions = {t["action"] for t in r.json()["trail"]}
        self.assertEqual(actions, {"triage"})
        self.assertIn("triage", [a["action"] for a in r.json()["actions"]])

    def test_trail_export_csv(self):
        auth.record_event("sammi", "audit_run", "ejecucion")
        r = client.get("/api/admin/trail/export?format=csv&action=audit_run")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r.headers["content-type"])
        self.assertIn("audit_run", r.text)
        self.assertIn("at,username,action,detail,ip", r.text)

    def test_trail_retencion_purga_lo_antiguo(self):
        os.environ["AUDIT_TRAIL_RETENTION_DAYS"] = "30"
        auth.record_event("sammi", "audit_run", "reciente")
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO audit_trail (at, username, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
                ("2020-01-01 00:00:00", "sammi", "audit_run", "antiguo", ""),
            )
        purged = auth.purge_trail()
        self.assertEqual(purged, 1)
        with db.connect() as conn:
            old = conn.execute("SELECT COUNT(*) AS c FROM audit_trail WHERE at < '2021-01-01'").fetchone()["c"]
        self.assertEqual(old, 0)
        os.environ.pop("AUDIT_TRAIL_RETENTION_DAYS")

    def test_export_se_firma_y_verifica(self):
        os.environ["AUDIT_SIGN_KEY"] = "clave-de-prueba"
        try:
            r = client.get("/api/audits/Auditoria_SAMPLE/download/csv")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers["x-content-signed"], "true")
            listing = client.get("/api/exports").json()["exports"]
            self.assertTrue(listing)
            verify = client.get("/api/exports/" + listing[0]["file"] + "/verify").json()
            self.assertTrue(verify["ok"])
            self.assertEqual(verify["status"], "verificado")
        finally:
            os.environ.pop("AUDIT_SIGN_KEY")

    def test_export_sin_clave_no_finge_firma(self):
        os.environ.pop("AUDIT_SIGN_KEY", None)
        r = client.get("/api/audits/Auditoria_SAMPLE/download/pdf")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["x-content-signed"], "false")
        listing = client.get("/api/exports").json()["exports"]
        pdf = [e for e in listing if e["file"].endswith(".pdf")][0]
        self.assertFalse(pdf["signed"])
        self.assertEqual(pdf["status"], "verificado")

    def test_pdf_incluye_hash_del_cuerpo_y_declara_verificacion_externa(self):
        """El pie del PDF lleva el SHA-256 del cuerpo y dice donde se verifica el
        documento completo. Un PDF no puede contener su propio hash: el pie forma
        parte del documento, por eso se imprime el hash del cuerpo y la firma del
        fichero entero queda en el sidecar .sig.
        """
        import hashlib
        import re
        import zlib

        def pdf_text(data: bytes) -> str:
            chunks = []
            for match in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.DOTALL):
                raw = match.group(1)
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    pass
                chunks.append(raw.decode("latin-1", "replace"))
            return " ".join(chunks)

        r = client.get("/api/audits/Auditoria_SAMPLE/download/pdf")
        self.assertEqual(r.status_code, 200)
        body_hash = r.headers.get("x-body-sha256", "")
        self.assertEqual(len(body_hash), 64)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", body_hash))

        text = pdf_text(r.content)
        self.assertIn(body_hash, text)
        self.assertIn("Cuerpo del informe", text)
        self.assertIn("verificacion externa", text)
        # El hash impreso es del cuerpo, no del fichero completo: no debe coincidir.
        self.assertNotEqual(body_hash, hashlib.sha256(r.content).hexdigest())
        # Y el hash del fichero completo si coincide con el sidecar.
        listing = client.get("/api/exports").json()["exports"]
        pdf = [e for e in listing if e["file"].endswith(".pdf")][0]
        self.assertEqual(pdf["sha256"], hashlib.sha256(r.content).hexdigest())


if __name__ == "__main__":
    unittest.main()
