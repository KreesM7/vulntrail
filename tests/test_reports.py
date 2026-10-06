import json
import unittest
from html.parser import HTMLParser

from vulntrail.models import Finding, Run
from vulntrail.reports import render_report


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.run = Run(
            '<img src=x onerror="alert(1)">', "trivy",
            [Finding("CVE-2025-0001", "[demo](javascript:evil)|new\nrow", "1", "pypi", "HIGH",
                     fixed_version="2", description="<script>alert(1)</script>",
                     location="a|b", urls=['https://example.test/\" onmouseover=\"evil'])],
            coverage=["requirements.txt"], warnings=["<svg onload=evil>"],
            data_updated_at="2026-01-01", source_digest="abc",
        )

    def test_json_preserves_evidence_and_derived_priority(self):
        value = json.loads(render_report(self.run, "json"))
        self.assertEqual(value, self.run.to_dict())
        self.assertEqual(value["findings"][0]["priority"], "P2")

    def test_html_does_not_interpret_attacker_controlled_content(self):
        report = render_report(self.run, "html")
        tags = Tags()
        tags.feed(report)
        self.assertNotIn("script", tags.tags)
        self.assertNotIn("img", tags.tags)
        self.assertNotIn("svg", tags.tags)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)
        self.assertIn("&quot; onmouseover=&quot;evil", report)
        self.assertIn("data_updated_at", report)

    def test_markdown_escapes_links_html_tables_and_newlines(self):
        report = render_report(self.run, "md")
        self.assertNotIn("<script>", report)
        self.assertNotIn("[demo](javascript:evil)", report)
        self.assertIn(r"\[demo\]\(javascript:evil\)\|new row", report)
        self.assertIn("&lt;svg onload=evil&gt;", report)
        self.assertIn("CVE", report)

    def test_empty_partial_failed_reports_state_limits(self):
        for status in ("complete", "partial", "failed"):
            report = render_report(Run("demo", "trivy", status=status), "md")
            self.assertIn(status, report)
            self.assertIn("No findings were reported", report)
            self.assertIn("does not establish", report)

    def test_unknown_format_and_invalid_mutated_run_are_rejected(self):
        with self.assertRaises(ValueError):
            render_report(self.run, "pdf")
        self.run.findings[0].severity = "invalid"
        with self.assertRaises(ValueError):
            render_report(self.run, "json")
