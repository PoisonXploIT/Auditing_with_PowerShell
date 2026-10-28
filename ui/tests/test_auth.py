"""Pruebas de autenticacion y sesiones (stdlib unittest).

Ejecutar:  python -m unittest ui.tests.test_auth -v
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import db  # noqa: E402
import auth  # noqa: E402

db.DB_PATH = Path(tempfile.mkdtemp()) / "auth_test.db"
db.init_db()
auth.init_auth()


class AuthTests(unittest.TestCase):
    def setUp(self):
        with db.connect() as conn:
            conn.execute("DELETE FROM users")
            conn.execute("DELETE FROM sessions")
            conn.execute("DELETE FROM audit_trail")

    def test_password_hash_verifies(self):
        h, salt = auth.hash_password("correcta-123")
        self.assertTrue(auth.verify_password("correcta-123", h, salt))
        self.assertFalse(auth.verify_password("incorrecta", h, salt))

    def test_login_creates_session_and_records_trail(self):
        auth.create_user("sammi", "clave-de-test", "admin")
        session = auth.login("sammi", "clave-de-test", "127.0.0.1")
        self.assertIsNotNone(session)
        self.assertEqual(session["role"], "admin")
        actions = [t["action"] for t in auth.trail()]
        self.assertIn("login", actions)

    def test_login_fails_with_bad_password(self):
        auth.create_user("sammi", "clave-de-test", "admin")
        self.assertIsNone(auth.login("sammi", "no-es-la-clave"))

    def test_account_locks_after_five_failures(self):
        auth.create_user("sammi", "clave-de-test", "admin")
        for _ in range(auth.MAX_FAILED_ATTEMPTS):
            self.assertIsNone(auth.login("sammi", "mal"))
        user = auth.get_user("sammi")
        self.assertEqual(user["failed_attempts"], auth.MAX_FAILED_ATTEMPTS)
        self.assertIsNotNone(user["locked_until"])
        # Aunque la contraseña sea correcta, la cuenta esta bloqueada.
        self.assertIsNone(auth.login("sammi", "clave-de-test"))

    def test_session_expires_without_activity(self):
        auth.create_user("sammi", "clave-de-test", "admin")
        session = auth.login("sammi", "clave-de-test")
        self.assertIsNotNone(auth.touch_session(session["token"]))
        # Simular que la ventana ya caduco.
        past = (datetime.now() - timedelta(minutes=auth.SESSION_TTL_MINUTES + 1)).strftime("%Y-%m-%d %H:%M:%S")
        with db.connect() as conn:
            conn.execute("UPDATE sessions SET expires_at = ? WHERE token = ?", (past, session["token"]))
        self.assertIsNone(auth.touch_session(session["token"]))
        self.assertEqual(len(auth.list_sessions()), 0)

    def test_revoke_session(self):
        auth.create_user("sammi", "clave-de-test", "admin")
        session = auth.login("sammi", "clave-de-test")
        self.assertTrue(auth.revoke_session(session["token"]))
        self.assertIsNone(auth.touch_session(session["token"]))

    def test_delete_user_revokes_sessions(self):
        auth.create_user("analista", "clave-de-test", "analyst")
        session = auth.login("analista", "clave-de-test")
        self.assertTrue(auth.delete_user("analista"))
        self.assertIsNone(auth.touch_session(session["token"]))

    def test_validation(self):
        with self.assertRaises(ValueError):
            auth.create_user("ab", "clave-de-test", "analyst")
        with self.assertRaises(ValueError):
            auth.create_user("sammi", "corto", "analyst")
        with self.assertRaises(ValueError):
            auth.create_user("sammi", "clave-de-test", "superuser")
        auth.create_user("sammi", "clave-de-test", "analyst")
        with self.assertRaises(ValueError):
            auth.create_user("sammi", "clave-de-test", "analyst")  # duplicado

    def test_bootstrap_admin_reads_env(self):
        os.environ["AUDIT_ADMIN_USER"] = "admin-local"
        os.environ["AUDIT_ADMIN_PASSWORD"] = "clave-de-test"
        created = auth.bootstrap_admin()
        self.assertIsNotNone(created)
        self.assertEqual(created["role"], "admin")
        # Idempotente: no crea otro administrador si ya existe.
        self.assertIsNone(auth.bootstrap_admin())
        del os.environ["AUDIT_ADMIN_USER"]
        del os.environ["AUDIT_ADMIN_PASSWORD"]

    def test_bootstrap_admin_without_env_does_nothing(self):
        with db.connect() as conn:
            conn.execute("DELETE FROM users")
        os.environ.pop("AUDIT_ADMIN_USER", None)
        os.environ.pop("AUDIT_ADMIN_PASSWORD", None)
        self.assertIsNone(auth.bootstrap_admin())


if __name__ == "__main__":
    unittest.main()
