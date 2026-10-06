import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from vulntrail.config import Settings
from vulntrail.scanner import run_bounded, build_command, scan_target

class ScannerTests(unittest.TestCase):
    def test_real_subprocess_output_is_bounded(self):
        with self.assertRaises(ValueError):
            run_bounded([sys.executable, "-c", "print('x'*10000)"], timeout=5, limit=100)

    def test_real_subprocess_timeout_is_enforced(self):
        with self.assertRaises(TimeoutError):
            run_bounded([sys.executable, "-c", "import time; time.sleep(4)"], timeout=0.1, limit=100)

    def test_shell_metacharacters_are_a_single_target_argument(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as root:
            target = Path(root) / "space ; target"
            target.mkdir()
            settings = Settings(state_dir=Path(root)/"state", targets={"app": target})
            command = build_command(settings, target, Path(root)/"config.yaml", Path(root)/"ignore")
            self.assertEqual(command[-1], str(target))
            for flag in ("--offline-scan", "--skip-db-update", "--skip-java-db-update",
                         "--disable-telemetry", "--skip-check-update"):
                self.assertIn(flag, command)

    def test_unknown_target_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_target(Settings(), "missing")

    def test_missing_offline_database_and_missing_binary_are_failed_runs(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as root:
            target = Path(root)/"app"
            target.mkdir()
            settings = Settings(state_dir=Path(root)/"state", targets={"app": target},
                                trivy_path="nonexistent-vulntrail-test-binary")
            self.assertEqual(scan_target(settings, "app").status, "failed")

    def test_successful_backend_json_is_parsed(self):
        from test_adapters import trivy_payload
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as root:
            target = Path(root)/"app"
            target.mkdir()
            settings = Settings(state_dir=Path(root)/"state", targets={"app":target}, offline=False)
            def output(command, **kwargs):
                if "version" in command:
                    return 0, json.dumps({"Version":"test"}).encode(), b""
                return 0, json.dumps(trivy_payload()).encode(), b""
            with patch("vulntrail.scanner.run_bounded", side_effect=output):
                run = scan_target(settings, "app")
            self.assertEqual(run.status, "complete")
            self.assertEqual(len(run.findings), 1)
            self.assertEqual(run.backend_version, "test")
