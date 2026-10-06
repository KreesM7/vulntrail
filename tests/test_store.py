import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest

from vulntrail.models import Finding, Run
from vulntrail.store import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state" / "evidence.sqlite3"
        self.store = Store(self.path)

    def test_save_get_are_independent_validated_snapshots(self):
        run = Run("demo", "trivy", [Finding("CVE-2024-1001", "demo", "1", "pypi", "HIGH")])
        saved = self.store.save_run(run)
        run.findings[0].package = "changed"
        saved.findings[0].severity = "LOW"
        fetched = self.store.get_run(run.id)
        self.assertEqual(fetched.findings[0].package, "demo")
        self.assertEqual(fetched.findings[0].priority, "P2")

    def test_duplicate_id_cannot_overwrite_history(self):
        run = Run("demo", "trivy")
        self.store.save_run(run)
        run.status = "failed"
        with self.assertRaises(ValueError):
            self.store.save_run(run)
        self.assertEqual(self.store.get_run(run.id).status, "complete")

    def test_mutated_invalid_models_and_nonfinite_raw_are_rejected(self):
        run = Run("demo", "trivy")
        run.offline = "yes"
        with self.assertRaises(ValueError):
            self.store.save_run(run)
        with self.assertRaises(ValueError):
            self.store.save_run(Run("demo", "trivy"), {"number": float("nan")})
        self.assertEqual(self.store.count_runs(), 0)

    def test_count_pagination_delete_and_parameterized_identifiers(self):
        older = Run("demo", "trivy", id="' ; DROP TABLE runs; --", started_at="2025-01-01")
        newer = Run("demo", "trivy", started_at="2026-01-01")
        self.store.save_run(older)
        self.store.save_run(newer)
        self.assertEqual(self.store.count_runs(), 2)
        self.assertEqual(self.store.list_runs(limit=1)[0].id, newer.id)
        self.assertEqual(self.store.list_runs(limit=1, offset=1)[0].id, older.id)
        self.assertTrue(self.store.delete_run(older.id))
        self.assertFalse(self.store.delete_run(older.id))
        with self.assertRaises(KeyError):
            self.store.get_run(older.id)
        self.assertEqual(self.store.count_runs(), 1)

    def test_raw_is_optional_and_actions_are_audited(self):
        run = self.store.save_run(Run("demo", "trivy"), {"SchemaVersion": 2})
        self.store.audit("response_planned", {"run_id": run.id})
        self.store.delete_run(run.id)
        with closing(sqlite3.connect(self.path)) as connection:
            events = connection.execute(
                "SELECT event, details_json FROM audit ORDER BY id"
            ).fetchall()
        self.assertEqual(
            [event for event, _ in events], ["run_saved", "response_planned", "run_deleted"]
        )
        self.assertEqual(json.loads(events[0][1])["run_id"], run.id)

    def test_concurrent_operations_use_separate_connections(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            runs = list(
                executor.map(lambda i: self.store.save_run(Run(str(i), "trivy")), range(12))
            )
        self.assertEqual(self.store.count_runs(), len(runs))
        for run in runs:
            self.assertEqual(self.store.get_run(run.id).target, run.target)

    def test_pagination_and_audit_bounds(self):
        for kwargs in ({"limit": 0}, {"limit": 1001}, {"offset": -1}, {"limit": True}):
            with self.assertRaises(ValueError):
                self.store.list_runs(**kwargs)
        with self.assertRaises(ValueError):
            self.store.audit("x", {"api_token": "credential"})
        with self.assertRaises(ValueError):
            self.store.audit("x", {"data": "x" * 65536})

    def test_summaries_return_counts_without_finding_payloads(self):
        run = Run(
            "demo",
            "trivy",
            [
                Finding("CVE-2025-1001", "one", "1", "pypi", "HIGH", description="x" * 16384),
                Finding("CVE-2025-1002", "two", "1", "pypi", "LOW", description="x" * 16384),
            ],
        )
        self.store.save_run(run)
        summary = self.store.list_summaries()[0]
        self.assertNotIn("findings", summary)
        self.assertEqual(summary["id"], run.id)
        self.assertEqual(summary["finding_count"], 2)
        self.assertEqual(summary["severity_counts"], {"HIGH": 1, "LOW": 1})
        self.assertLess(len(json.dumps(summary)), 4096)

    def test_summaries_bound_metadata_and_signal_truncation(self):
        run = Run("demo", "trivy", coverage=["x" * 1000] * 12, warnings=["warning"] * 11)
        self.store.save_run(run)
        summary = self.store.list_summaries()[0]
        self.assertEqual(summary["coverage_count"], 12)
        self.assertEqual(summary["warning_count"], 11)
        self.assertEqual(len(summary["coverage"]), 10)
        self.assertLessEqual(len(summary["coverage"][0]), 512)
        self.assertTrue(summary["summary_truncated"])
        self.assertEqual(len(self.store.get_run(run.id).coverage[0]), 1000)
        with self.assertRaises(ValueError):
            self.store.list_summaries(limit=0)
