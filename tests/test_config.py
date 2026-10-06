import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from vulntrail.config import Settings, load_settings


class ConfigTests(unittest.TestCase):
    def test_relative_paths_and_offline_default(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as root:
            path = Path(root) / "config.yaml"
            path.write_text("targets:\n  app: ./project\nstate_dir: ./state\n", encoding="utf-8")
            settings = load_settings(path)
            self.assertEqual(settings.targets["app"], Path(root) / "project")
            self.assertTrue(settings.offline)
            self.assertEqual(settings.state_dir, Path(root) / "state")

    def test_invalid_settings_fail_closed(self):
        for fields in (
            {"offline": "false"},
            {"timeout_seconds": 0},
            {"targets": {"app": "https://example.com"}},
            {"trivy_path": "scan.cmd"},
        ):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                Settings(**fields)

    def test_unknown_yaml_and_unsafe_tags_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as root:
            path = Path(root) / "config.yaml"
            for body in ("typo: true", "!!python/object/apply:os.system ['echo bad']"):
                path.write_text(body, encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_settings(path)

    def test_resolved_network_target_and_invalid_path_shape_rejected(self):
        with patch.object(Path, "resolve", return_value=Path("//server/share")):
            with self.assertRaises(ValueError):
                Settings(targets={"app": "local-link"})
        with self.assertRaises(ValueError):
            Settings(targets={"app": 7})
