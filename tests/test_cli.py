from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulntrail.cli import main
from vulntrail.config import load_settings
from vulntrail.models import Finding, Run
from vulntrail.store import Store
from _windows_fixture import user_owned_creation


class CliTests(unittest.TestCase):
    def setUp(self):
        owners = user_owned_creation()
        owners.__enter__()
        self.addCleanup(owners.__exit__, None, None, None)
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.temp.name)
        self.config = self.root / "config.yaml"
        self.args = ["--config", str(self.config)]
        self.call("init", str(self.config), "--target", f"demo={self.root}")

    def tearDown(self):
        self.temp.cleanup()

    def call(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(list(args))
        return code, output.getvalue(), errors.getvalue()

    def test_init_does_not_overwrite_and_resolves_configuration(self):
        self.assertEqual(load_settings(self.config).targets["demo"], self.root)
        original = self.config.read_bytes()
        code, _, error = self.call("init", str(self.config))
        self.assertEqual(code, 2)
        self.assertIn("exists", error)
        self.assertEqual(self.config.read_bytes(), original)

    def test_doctor_requires_both_offline_database_files(self):
        database = self.root / ".vulntrail/cache/db"
        database.mkdir(parents=True)
        (database / "metadata.json").write_text("{}")
        with patch("vulntrail.cli.shutil.which", return_value="trusted-trivy"):
            code, output, _ = self.call(*self.args, "doctor")
            self.assertEqual(code, 2)
            self.assertFalse(json.loads(output)["database_file_exists"])
            (database / "trivy.db").write_bytes(b"synthetic-presence-check-only")
            code, output, _ = self.call(*self.args, "doctor")
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(output)["database_file_exists"])

    def test_import_list_detail_report_diff_are_persisted(self):
        report = self.root / "report.json"
        report.write_text(
            json.dumps(
                {
                    "SchemaVersion": 2,
                    "Results": [
                        {
                            "Target": "requirements.txt",
                            "Class": "lang-pkgs",
                            "Type": "pip",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-TEST",
                                    "PkgName": "demo",
                                    "InstalledVersion": "1",
                                    "Severity": "HIGH",
                                }
                            ],
                        }
                    ],
                }
            )
        )
        code, output, _ = self.call(
            *self.args, "import", str(report), "--backend", "trivy", "--target", "demo"
        )
        self.assertEqual(code, 0)
        run_id = json.loads(output)["id"]
        code, output, _ = self.call(*self.args, "runs")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["items"][0]["id"], run_id)
        self.assertEqual(self.call(*self.args, "show", run_id)[0], 0)
        code, output, _ = self.call(*self.args, "report", run_id, "--format", "html")
        self.assertEqual(code, 0)
        self.assertIn("CVE-TEST", output)
        code, output, _ = self.call(*self.args, "diff", run_id, run_id)
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(output)["persistent"]), 1)

    def test_scan_failure_and_requested_severity_exit_codes(self):
        def high_scan(*args):
            return Run(
                "demo", "trivy", [Finding("CVE-TEST", "pkg", "1", "pypi", "HIGH")], coverage=["x"]
            )

        with patch("vulntrail.cli.scan_target", side_effect=high_scan):
            self.assertEqual(self.call(*self.args, "scan", "demo")[0], 0)
            self.assertEqual(self.call(*self.args, "scan", "demo", "--fail-on", "HIGH")[0], 1)
        with patch("vulntrail.cli.scan_target", return_value=Run("demo", "trivy", status="failed")):
            self.assertEqual(self.call(*self.args, "scan", "demo")[0], 2)

    def test_watch_count_is_bounded_and_no_sleep_after_final_scan(self):
        store = Store(load_settings(self.config).state_dir / "evidence.sqlite3")
        with (
            patch(
                "vulntrail.cli.scan_target",
                side_effect=lambda *args: Run("demo", "trivy", coverage=["x"]),
            ),
            patch("vulntrail.cli.time.sleep") as sleep,
        ):
            self.assertEqual(
                self.call(*self.args, "watch", "demo", "--count", "2", "--interval", "1")[0], 0
            )
        self.assertEqual(store.count_runs(), 2)
        sleep.assert_called_once_with(1.0)

    def test_enrichment_creates_copy_response_and_holding_roundtrip(self):
        store = Store(load_settings(self.config).state_dir / "evidence.sqlite3")
        run = store.save_run(
            Run(
                "demo",
                "trivy",
                [Finding("CVE-2024-0001", "pkg", "1", "pypi", "HIGH", fixed_version="2")],
                coverage=["x"],
            )
        )
        kev = self.root / "kev.json"
        kev.write_text(
            json.dumps(
                {
                    "catalogVersion": "2026.10.06",
                    "dateReleased": "2026-10-06T00:00:00Z",
                    "vulnerabilities": [{"cveID": "CVE-2024-0001"}],
                }
            )
        )
        code, output, _ = self.call(*self.args, "enrich", run.id, "--kev", str(kev))
        self.assertEqual(code, 0)
        enriched = json.loads(output)
        self.assertNotEqual(enriched["id"], run.id)
        self.assertTrue(enriched["findings"][0]["kev"])
        self.assertFalse(store.get_run(run.id).findings[0].kev)
        self.assertEqual(self.call(*self.args, "response", run.id)[0], 0)
        artifact = self.root / "owned.txt"
        artifact.write_text("owned artifact")
        import hashlib

        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        code, output, error = self.call(
            *self.args, "hold", str(self.root), "owned.txt", "--sha256", digest, "--confirm"
        )
        self.assertEqual(code, 0, error)
        held = json.loads(output)
        self.assertFalse(artifact.exists())
        code, _, error = self.call(
            *self.args, "restore", str(self.root), held["hold_id"], "--sha256", digest, "--confirm"
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(artifact.read_text(), "owned artifact")

    def test_serve_rejects_public_bind_and_short_token_without_starting(self):
        with patch("uvicorn.run") as run:
            self.assertEqual(self.call(*self.args, "serve", "--host", "0.0.0.0")[0], 2)
            with patch.dict("os.environ", {"VULNTRAIL_TOKEN": "short"}):
                self.assertEqual(self.call(*self.args, "serve")[0], 2)
            run.assert_not_called()
