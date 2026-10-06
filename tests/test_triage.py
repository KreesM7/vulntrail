import unittest
from vulntrail.models import Run, Finding
from vulntrail.triage import compare_runs

class HistoryTests(unittest.TestCase):
    def test_missing_in_partial_scan_is_unresolved(self):
        finding = Finding("CVE-2024-0001", "demo", "1", "pypi", "HIGH")
        before = Run("app", "trivy", [finding], coverage=["pip:requirements.txt"])
        after = Run("app", "trivy", status="partial", coverage=[])
        diff = compare_runs(before, after)
        self.assertFalse(diff["comparable"])
        self.assertEqual(len(diff["unresolved"]), 1)
        self.assertEqual(diff["no_longer_observed"], [])

    def test_complete_matching_coverage_can_describe_absence_not_resolution(self):
        finding = Finding("CVE-2024-0001", "demo", "1", "pypi", "HIGH")
        before = Run("app", "trivy", [finding], coverage=["pip:requirements.txt"])
        after = Run("app", "trivy", coverage=["pip:requirements.txt"])
        diff = compare_runs(before, after)
        self.assertTrue(diff["comparable"])
        self.assertEqual(len(diff["no_longer_observed"]), 1)
        self.assertNotIn("resolved", diff)

    def test_backend_version_and_target_changes_are_not_comparable(self):
        a = Run("app", "trivy", coverage=["scope"], backend_version="1")
        b = Run("app", "trivy", coverage=["scope"], backend_version="2")
        self.assertFalse(compare_runs(a, b)["comparable"])
        b.backend_version = "1"
        b.target = "other"
        self.assertFalse(compare_runs(a, b)["comparable"])
