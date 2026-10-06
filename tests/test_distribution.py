from pathlib import Path
import unittest

import yaml


class DistributionTests(unittest.TestCase):
    def test_workflow_yaml_parses_and_keeps_shell_commands_as_strings(self):
        root = Path(__file__).resolve().parents[1]
        path = root / ".github/workflows/ci.yml"
        workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        self.assertEqual(workflow["permissions"]["contents"], "read")
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "run" in step:
                    self.assertIsInstance(step["run"], str)
