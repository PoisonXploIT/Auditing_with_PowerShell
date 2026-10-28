"""Pruebas de integridad de evidencia y cobertura MITRE (stdlib unittest).

Ejecutar:  python -m unittest ui.tests.test_evidence -v
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import evidence  # noqa: E402
import integrations  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "Auditoria_SAMPLE"


class EvidenceTests(unittest.TestCase):
    def test_manifest_integro(self):
        result = evidence.verify_manifest(FIXTURE)
        self.assertTrue(result["ok"], result["mismatches"])
        self.assertEqual(result["status"], "integro")
        self.assertEqual(result["file_count"], 4)
        self.assertEqual(len(result["root_sha256"]), 64)

    def test_root_hash_cambia_al_editar_un_fichero(self):
        original = evidence.verify_manifest(FIXTURE)["root_sha256"]
        path = FIXTURE / "03_Procesos" / "procesos.json"
        before = path.read_bytes()
        try:
            path.write_bytes(before.replace(b"splunkd", b"backdoor", 1))
            result = evidence.verify_manifest(FIXTURE)
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "alterado")
            self.assertEqual(result["mismatches"][0]["path"], "03_Procesos/procesos.json")
            self.assertNotEqual(result["root_recomputed"], original)
        finally:
            path.write_bytes(before)

    def test_fichero_no_declado_se_detecta(self):
        extra = FIXTURE / "04_Red" / "injectado.json"
        extra.write_bytes(b"{}")
        try:
            result = evidence.verify_manifest(FIXTURE)
            self.assertFalse(result["ok"])
            self.assertIn(
                "fichero no declarado en el manifiesto",
                [m["problem"] for m in result["mismatches"]],
            )
        finally:
            extra.unlink()

    def test_sin_manifiesto_lo_recalcula(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp()) / "Auditoria_SIN_MANIFIESTO"
        tmp.mkdir(parents=True)
        (tmp / "RESUMEN_EJECUTIVO.txt").write_text("hola", encoding="utf-8")
        result = evidence.verify_manifest(tmp)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "sin_manifiesto")
        self.assertEqual(len(result["root_sha256"]), 64)

    def test_firma_verificable(self):
        os.environ["AUDIT_SIGN_KEY"] = "clave-de-prueba"
        try:
            sig = evidence.export_signature(FIXTURE, "RESUMEN_EJECUTIVO.txt")
            self.assertTrue(sig["signed"])
            self.assertEqual(sig["algorithm"], "HMAC-SHA256")
            self.assertEqual(len(sig["signature"]), 64)
            # Verificacion independiente: la firma debe reproducirse con la misma clave.
            import hmac, hashlib
            payload = (FIXTURE / "RESUMEN_EJECUTIVO.txt").read_bytes()
            self.assertEqual(
                sig["signature"],
                hmac.new(b"clave-de-prueba", payload, hashlib.sha256).hexdigest(),
            )
        finally:
            os.environ.pop("AUDIT_SIGN_KEY")

    def test_sin_clave_no_finge_una_firma(self):
        os.environ.pop("AUDIT_SIGN_KEY", None)
        sig = evidence.export_signature(FIXTURE, "RESUMEN_EJECUTIVO.txt")
        self.assertTrue(sig["ok"])
        self.assertFalse(sig["signed"])
        self.assertIn("AUDIT_SIGN_KEY", sig["reason"])
        self.assertNotIn("signature", sig)

    def test_fichero_inexistente(self):
        sig = evidence.export_signature(FIXTURE, "NO_EXISTE.pdf")
        self.assertFalse(sig["ok"])

    def test_coverage_gap_conoce_su_propia_referencia(self):
        layer = integrations.navigator_layer(
            "x", [{"MitreTechnique": "T1571", "MitreTactic": "Command and Control", "Description": "puerto"}]
        )
        gap = integrations.coverage_gap(layer, integrations.TARGET_TECHNIQUES)
        self.assertIn("T1059.001", gap)
        self.assertNotIn("T1571", gap)
        self.assertEqual(len(integrations.TARGET_TECHNIQUES), 17)


if __name__ == "__main__":
    unittest.main()
