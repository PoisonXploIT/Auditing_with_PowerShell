"""Pruebas de la baseline SQLite (stdlib unittest, sin dependencias).

Ejecutar:  python -m unittest ui.tests.test_baseline -v
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import db  # noqa: E402


SUMMARY = """              RESUMEN EJECUTIVO DE AUDITORIA DE SEGURIDAD EMPRESARIAL

INFORMACION GENERAL

Sistema:              TESTHOST
Usuario Ejecutor:     tester
Privilegios:          Usuario Normal
Fecha Inicio:         2026-10-28 10:00:00
Fecha Fin:            2026-10-28 10:03:00
Duracion:             3m 0s
Directorio:           C:\\test\\Auditoria_20261028_100000

ESTADISTICAS DE EJECUCION

Modulos Ejecutados:   10 / 10
Errores:              0
Advertencias:         1
Amenazas Detectadas:  2

NIVEL DE RIESGO GENERAL: MEDIO

Amenazas CRITICAS:    0
Amenazas ALTAS:       2
Amenazas MEDIAS:      0
Amenazas BAJAS:       0

AMENAZAS SUPRIMIDAS POR ALLOWLIST LOCAL

Suprimidas: 1 (no cuentan en el nivel de riesgo)
  - [MEDIUM] Puerto sospechoso en escucha | Puerto 9999 en escucha en 0.0.0.0 (proceso 'splunkd')
    Motivo: Splunk Web [allowlist: splunk-local]

COBERTURA DE LA AUDITORIA

Cobertura: PARCIAL (1 comprobacion omitida)
  - Omision: Procesos sin ruta (requiere elevacion)

HALLAZGOS CRITICOS DETECTADOS
"""

THREATS = [
    {
        "Timestamp": "2026-10-28 10:01:00",
        "ThreatType": "Run Key sospechoso",
        "Severity": "HIGH",
        "Description": "Run key 'X' (PID: 111) apunta a un script",
        "MitreTechnique": "T1547.001",
        "MitreTactic": "Persistence",
        "MitreUrl": "https://attack.mitre.org/techniques/T1547/001",
        "Signature": db.signature("Run Key sospechoso", "Run key 'X' (PID: 111) apunta a un script"),
        "Details": {"Name": "powershell", "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    },
    {
        "Timestamp": "2026-10-28 10:02:00",
        "ThreatType": "Run Key sospechoso",
        "Severity": "HIGH",
        "Description": "Run key 'X' (PID: 222) apunta a un script",
        "MitreTechnique": "T1547.001",
        "MitreTactic": "Persistence",
        "MitreUrl": "https://attack.mitre.org/techniques/T1547/001",
        "Signature": db.signature("Run Key sospechoso", "Run key 'X' (PID: 222) apunta a un script"),
    },
]


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        db.DB_PATH = self.tmp / "baseline.db"
        db.init_db()
        self.audit = self.tmp / "Auditoria_20261028_100000"
        self.audit.mkdir()
        (self.audit / "RESUMEN_EJECUTIVO.txt").write_text(SUMMARY, encoding="utf-8")
        (self.audit / "AMENAZAS_DETECTADAS.json").write_text(json.dumps(THREATS), encoding="utf-8")

    def tearDown(self):
        # El archivo queda: SQLite con WAL puede tener el handle abierto y Windows
        # no permite borrarlo inmediatamente. El directorio temporal se limpia aparte.
        pass

    def test_signature_is_stable_across_pid(self):
        """El mismo hallazgo con distinto PID debe dar la misma firma."""
        self.assertEqual(
            db.signature("Run Key sospechoso", "Run key 'X' (PID: 111) apunta a un script"),
            db.signature("Run Key sospechoso", "Run key 'X' (PID: 222) apunta a un script"),
        )

    def test_signature_format_matches_powershell(self):
        sig = db.signature("Comando codificado", "Proceso 'powershell' (PID: 4) invoca PowerShell")
        self.assertRegex(sig, r"^[0-9A-F]{16}$")

    def test_ingest_deduplicates_by_signature(self):
        res = db.ingest_audit(self.audit)
        # 1 hallazgo real (las dos run keys comparten firma) + 1 suprimido por allowlist
        self.assertEqual(res["new_threats"], 2)
        self.assertEqual(res["updated_threats"], 1)

    def test_ingest_is_idempotent(self):
        db.ingest_audit(self.audit)
        again = db.ingest_audit(self.audit)
        self.assertEqual(again["skipped"], 1)
        base = db.baseline()
        self.assertEqual(base["audits"], 1)
        # 1 hallazgo real + 1 suprimido por allowlist
        self.assertEqual(base["distinct_threats"], 2)
        self.assertEqual(base["false_positive"], 1)

    def test_suppressed_threats_are_recorded_not_hidden(self):
        db.ingest_audit(self.audit)
        threats = db.threat_list(status="false_positive")
        self.assertEqual(len(threats), 1)
        self.assertIn("splunk-local", threats[0]["note"])

    def test_status_transition(self):
        db.ingest_audit(self.audit)
        sig = THREATS[0]["Signature"]
        updated = db.set_status(sig, "investigating", "mirando el registro")
        self.assertEqual(updated["status"], "investigating")
        self.assertEqual(updated["note"], "mirando el registro")
        with self.assertRaises(ValueError):
            db.set_status(sig, "banana")

    def test_second_audit_marks_first_as_recurring(self):
        db.ingest_audit(self.audit)
        audit2 = self.tmp / "Auditoria_20261028_110000"
        audit2.mkdir()
        (audit2 / "RESUMEN_EJECUTIVO.txt").write_text(
            SUMMARY.replace("20261028_100000", "20261028_110000").replace("10:00:00", "11:00:00"),
            encoding="utf-8",
        )
        (audit2 / "AMENAZAS_DETECTADAS.json").write_text(json.dumps(THREATS[:1]), encoding="utf-8")
        db.ingest_audit(audit2)
        ctx = db.audit_context(audit2.name)
        self.assertEqual(len(ctx["recurring"]), 1)
        self.assertEqual(len(ctx["new"]), 0)
        base = db.baseline()
        # Recurrentes: el hallazgo real y la supresion de la allowlist, que se repite
        # en ambas ejecuciones.
        self.assertEqual(base["recurring"], 2)

    def test_false_positive_creates_allowlist_entry(self):
        """El cierre del circulo: triage -> regla para la proxima auditoria."""
        db.ingest_audit(self.audit)
        sig = THREATS[0]["Signature"]
        db.set_status(sig, "false_positive", "el run key es legitimo")
        entry = db.derive_allowlist_entry(sig, "el run key es legitimo")
        self.assertIsNotNone(entry)
        entries = db.list_allowlist()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["threat_type"], "Run Key sospechoso")
        self.assertEqual(entries[0]["process"], "powershell")
        self.assertEqual(entries[0]["source"], "triage")

    def test_reopening_removes_allowlist_entry(self):
        db.ingest_audit(self.audit)
        sig = THREATS[0]["Signature"]
        db.set_status(sig, "false_positive", "ruido")
        db.derive_allowlist_entry(sig, "ruido")
        self.assertEqual(len(db.list_allowlist()), 1)
        db.set_status(sig, "open", "vuelve a aparecer")
        self.assertEqual(len(db.list_allowlist()), 0)

    def test_allowlist_file_matches_powershell_format(self):
        db.ingest_audit(self.audit)
        sig = THREATS[0]["Signature"]
        db.set_status(sig, "false_positive", "ruido")
        out = db.write_allowlist_file(self.tmp / "allowlist.json")
        data = json.loads((self.tmp / "allowlist.json").read_text(encoding="utf-8"))
        self.assertEqual(out["entries"], len(data["entries"]))
        for e in data["entries"]:
            # Invoke-SecurityAudit.ps1 espera Id, ThreatTypes, Ports, Process, Path, Reason.
            for key in ("id", "threatTypes", "ports", "process", "path", "reason"):
                self.assertIn(key, e)

    def test_manual_entry_needs_process_or_port(self):
        with self.assertRaises(ValueError):
            db.add_allowlist_entry({"threat_type": "X", "reason": "sin criterio"})
        self.assertEqual(len(db.list_allowlist()), 0)
        db.add_allowlist_entry({"threat_type": "X", "process": "node", "reason": "dev local"})
        self.assertEqual(len(db.list_allowlist()), 1)

    def test_sla_computed_on_ingest(self):
        db.ingest_audit(self.audit)
        sig = THREATS[0]["Signature"]
        row = [x for x in db.threat_list() if x["signature"] == sig][0]
        self.assertEqual(row["sla_days"], db.SLA_DAYS["HIGH"])
        self.assertEqual(row["due_at"], "2026-10-31 10:00:00")  # first_seen + 3 dias
        self.assertFalse(row["overdue"])
        self.assertIsNotNone(row["days_left"])

    def test_overdue_reported_and_cleared_on_triage(self):
        db.ingest_audit(self.audit)
        sig = THREATS[0]["Signature"]
        with db.connect() as conn:
            conn.execute("UPDATE threats SET due_at = '2026-10-20 10:00:00' WHERE signature = ?", (sig,))
        report = db.sla_report()
        self.assertEqual(report["overdue"], 1)
        self.assertEqual(report["overdue_list"][0]["signature"], sig)
        self.assertTrue(report["overdue_list"][0]["days_overdue"] > 0)
        self.assertEqual(len(db.threat_list(overdue_only=True)), 1)
        # Triarlo cierra el plazo: deja de estar vencido.
        db.set_status(sig, "investigating", "lo vemos hoy")
        self.assertEqual(db.sla_report()["overdue"], 0)
        self.assertEqual(len(db.threat_list(overdue_only=True)), 0)

    def test_sla_override_and_validation(self):
        db.ingest_audit(self.audit)
        sig = THREATS[0]["Signature"]
        updated = db.set_sla(sig, 1)
        self.assertEqual(updated["sla_days"], 1)
        self.assertEqual(updated["due_at"], "2026-10-29 10:00:00")
        with self.assertRaises(ValueError):
            db.set_sla(sig, 0)
        cleared = db.set_sla(sig, None)
        self.assertIsNone(cleared["sla_days"])
        self.assertIsNone(cleared["due_at"])

    def test_forget_audits_removes_rows(self):
        db.ingest_audit(self.audit)
        db.forget_audits([self.audit.name])
        base = db.baseline()
        self.assertEqual(base["audits"], 0)
        # El registro historico del hallazgo sobrevive a la limpieza de carpetas.
        self.assertEqual(base["distinct_threats"], 2)


if __name__ == "__main__":
    unittest.main()
