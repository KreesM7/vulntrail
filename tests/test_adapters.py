import unittest
from vulntrail.adapters import parse_report


def trivy_payload():
    return {
        "SchemaVersion": 2,
        "ArtifactName": "sample",
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Packages": [{"Name": "example", "Version": "1.0"}],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "example",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "2.0",
                        "Severity": "HIGH",
                        "Description": "<script>bad</script>",
                    }
                ],
            }
        ],
    }


class AdapterTests(unittest.TestCase):
    def test_trivy_preserves_identity_and_missing_database_date(self):
        run = parse_report(trivy_payload(), "trivy", "sample")
        self.assertEqual(run.status, "complete")
        self.assertEqual(run.coverage, ["pip:requirements.txt"])
        self.assertEqual(run.findings[0].fixed_version, "2.0")
        self.assertIsNone(run.data_updated_at)
        self.assertEqual(run.findings[0].ecosystem, "pip")

    def test_no_results_is_partial_not_clean(self):
        run = parse_report({"SchemaVersion": 2, "Results": []}, "trivy", "empty")
        self.assertEqual(run.status, "partial")
        self.assertTrue(run.warnings)

    def test_grype_preserves_vendor_and_location(self):
        data = {
            "descriptor": {"version": "1.0"},
            "source": {"target": "sample"},
            "distro": {"name": "debian", "version": "12"},
            "matches": [
                {
                    "artifact": {
                        "name": "libdemo",
                        "version": "1.0",
                        "type": "deb",
                        "locations": [{"path": "/var/lib/dpkg/status"}],
                    },
                    "vulnerability": {
                        "id": "CVE-2024-0002",
                        "severity": "Medium",
                        "fix": {"versions": ["1.1"]},
                        "dataSource": "https://example.com/advisory",
                    },
                }
            ],
        }
        run = parse_report(data, "grype", "sample")
        self.assertEqual(run.findings[0].ecosystem, "deb:debian:12")
        self.assertEqual(run.findings[0].location, "/var/lib/dpkg/status")

    def test_wrong_shapes_and_limits_fail(self):
        for data in (
            {},
            {"SchemaVersion": 1},
            {"SchemaVersion": 2, "Results": "bad"},
            {"SchemaVersion": 2, "Results": {}},
            {"SchemaVersion": 2, "Results": [{"Target": "x", "Vulnerabilities": {}}]},
            {"SchemaVersion": 2, "Results": [{"Target": "x", "Vulnerabilities": [{}]}]},
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_report(data, "trivy", "sample")
        with self.assertRaises(ValueError):
            parse_report(trivy_payload(), "trivy", "sample", max_findings=0)

    def test_duplicates_are_deduplicated_without_losing_package_context(self):
        data = trivy_payload()
        data["Results"][0]["Vulnerabilities"] *= 2
        self.assertEqual(len(parse_report(data, "trivy", "x").findings), 1)

    def test_secret_only_results_never_count_as_vulnerability_coverage(self):
        data = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Type": "pip",
                    "Class": "secret",
                    "Secrets": [{"RuleID": "demo"}],
                }
            ],
        }
        run = parse_report(data, "trivy", "app")
        self.assertEqual(run.status, "partial")
        self.assertEqual(run.coverage, [])
