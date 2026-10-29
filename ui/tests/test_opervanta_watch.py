# -*- coding: utf-8 -*-
"""Tests de opervanta_watch (direccion B: Opervanta publica su actividad en Auditing)."""
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import opervanta_watch as w  # noqa: E402


def _firmar(secret, sensor, ts, nonce, cuerpo):
    return hmac.new(secret.encode("utf-8"),
                    ("v2|%s|%s|%s|%s" % (sensor, ts, nonce,
                                         hashlib.sha256(cuerpo).hexdigest())).encode("utf-8"),
                    hashlib.sha256).hexdigest()


class TestOpervantaWatch(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="watch-"))
        os.environ["OPERVANTA_WATCH_DIR"] = str(self.tmp)
        os.environ["OPERVANTA_WATCH_SECRET"] = "s" * 64
        os.environ["OPERVANTA_WATCH_ENABLED"] = "1"
        w.WATCH_DIR = self.tmp
        w.EVENTOS = self.tmp / "opervanta-eventos.jsonl"
        w.NONCES = self.tmp / "opervanta-nonces.json"
        self.cuerpo = json.dumps({"schema": "opervanta-evento/1", "event_id": "e1",
                                  "origen": "opervanta", "instancia": "x", "tipo": "auth",
                                  "sev": "info", "mensaje": "login ok", "detalle": {},
                                  "ts": int(time.time())}).encode("utf-8")

    def _h(self, nonce="n1", cuerpo=None):
        cuerpo = cuerpo or self.cuerpo
        ts = str(int(time.time()))
        return {"sensor": "audit-powershell", "ts": ts, "nonce": nonce,
                "digest": _firmar("s" * 64, "audit-powershell", ts, nonce, cuerpo), "cuerpo": cuerpo}

    def test_verificar_ok(self):
        h = self._h()
        ok, mot = w.verificar(h["sensor"], h["ts"], h["nonce"], h["digest"], h["cuerpo"])
        self.assertTrue(ok, mot)

    def test_firma_mala(self):
        h = self._h()
        ok, _ = w.verificar(h["sensor"], h["ts"], h["nonce"], "0" * 64, h["cuerpo"])
        self.assertFalse(ok)

    def test_replay(self):
        h = self._h()
        self.assertTrue(w.verificar(h["sensor"], h["ts"], h["nonce"], h["digest"], h["cuerpo"])[0])
        ok, mot = w.verificar(h["sensor"], h["ts"], h["nonce"], h["digest"], h["cuerpo"])
        self.assertFalse(ok, mot)

    def test_ts_fuera_ventana(self):
        h = self._h()
        ok, mot = w.verificar(h["sensor"], str(int(time.time()) - 9999), h["nonce"], h["digest"], h["cuerpo"])
        self.assertFalse(ok)

    def test_guardar_valida_y_rechaza_tipo_raro(self):
        r = w.guardar(json.loads(self.cuerpo))
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(w.listar()), 1)
        r2 = w.guardar({"schema": "opervanta-evento/1", "tipo": "raro", "sev": "info", "mensaje": "x"})
        self.assertFalse(r2["ok"])

    def test_activo(self):
        self.assertTrue(w.activo())
        os.environ["OPERVANTA_WATCH_ENABLED"] = "0"
        self.assertFalse(w.activo())


if __name__ == "__main__":
    unittest.main()
