import unittest
from vulntrail.models import Finding, Run


class ModelTests(unittest.TestCase):
    def test_priority_and_round_trip(self):
        finding = Finding("CVE-2024-0001", "demo", "1.0", "pypi", "HIGH")
        self.assertEqual(finding.priority, "P2")
        self.assertEqual(Finding.from_dict(finding.to_dict()).fingerprint, finding.fingerprint)
        finding.kev = True
        self.assertEqual(finding.priority, "P1")
        run = Run("demo", "trivy", [finding], coverage=["requirements.txt"])
        self.assertEqual(Run.from_dict(run.to_dict()).to_dict(), run.to_dict())

    def test_identity_preserves_ecosystem_version_and_location(self):
        a = Finding("CVE-2024-0001", "demo", "1", "pypi", "HIGH", location="a")
        b = Finding("CVE-2024-0001", "demo", "1", "pypi", "HIGH", location="b")
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_rejects_invalid_probability_severity_and_status(self):
        with self.assertRaises(ValueError):
            Finding("CVE-X", "demo", "1", "pypi", "BOGUS")
        with self.assertRaises(ValueError):
            Finding("CVE-X", "demo", "1", "pypi", "HIGH", epss=float("nan"))
        with self.assertRaises(ValueError):
            Run("demo", "trivy", status="clean")
