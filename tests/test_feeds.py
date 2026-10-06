import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulntrail.feeds import enrich_run, load_epss, load_kev
from vulntrail.models import Finding, Run
from vulntrail.store import Store


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_kev_validates_rows_and_keeps_source_date_digest(self):
        path = self.root / "kev.json"
        payload = {"dateReleased": "2026-09-30T12:00:00Z", "count": 1,
                   "vulnerabilities": [{"cveID": "CVE-2025-1001"}]}
        path.write_text(json.dumps(payload), encoding="utf-8")
        values, provenance = load_kev(path)
        self.assertEqual(values, {"CVE-2025-1001"})
        self.assertEqual(provenance["source_date"], "2026-09-30")
        self.assertEqual(provenance["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertNotEqual(provenance["imported_at"], provenance["source_date"])

    def test_epss_reads_official_comment_header(self):
        path = self.root / "epss.csv"
        path.write_text("#model_version:v2025.03.14,score_date:2026-09-30T12:00:00Z\n"
                        "cve,epss,percentile\nCVE-2025-1001,0.25,0.9\n", encoding="utf-8")
        scores, provenance = load_epss(path)
        self.assertEqual(scores, {"CVE-2025-1001": 0.25})
        self.assertEqual(provenance["source_date"], "2026-09-30")

    def test_epss_rejects_nonfinite_out_of_range_duplicate_and_unknown_date(self):
        path = self.root / "epss.csv"
        for body in ("CVE-2025-1001,nan\n", "CVE-2025-1001,inf\n", "CVE-2025-1001,-0.1\n",
                     "CVE-2025-1001,1.1\n", "CVE-2025-1001,0.1\nCVE-2025-1001,0.2\n"):
            path.write_text("#score_date:2026-09-30\ncve,epss\n" + body, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_epss(path)
        path.write_text("cve,epss\nCVE-2025-1001,0.1\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_epss(path)

    def test_feeds_fail_closed_on_invalid_shape_dates_rows_and_byte_limits(self):
        path = self.root / "kev.json"
        for value in ({"dateReleased": "bad", "vulnerabilities": []},
                      {"dateReleased": "2026-01-01", "vulnerabilities": [{"cveID": "bad"}]},
                      {"dateReleased": "2026-01-01", "count": 3, "vulnerabilities": []}):
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_kev(path)
        path.write_text('{"dateReleased":"2026-01-01","vulnerabilities":[]}', encoding="utf-8")
        with patch("vulntrail.feeds.MAX_FEED_BYTES", 10), self.assertRaises(ValueError):
            load_kev(path)
        path.write_text(json.dumps({"dateReleased": "2026-01-01", "vulnerabilities": [
            {"cveID": "CVE-2025-1001"}, {"cveID": "CVE-2025-1002"}]}), encoding="utf-8")
        with patch("vulntrail.feeds.MAX_FEED_ROWS", 1), self.assertRaises(ValueError):
            load_kev(path)

    def test_enrichment_creates_new_snapshot_and_retains_original_assertions(self):
        run = Run("demo", "trivy", [Finding("CVE-2025-1001", "demo", "1", "pypi", "LOW")],
                  source_digest="original", data_updated_at="2026-09-01")
        provenance = {"source": "cisa-kev", "source_date": "2026-09-30", "sha256": "a" * 64,
                      "imported_at": "2026-10-01T00:00:00+00:00", "derived_from": ""}
        store = Store(self.root / "evidence.sqlite3")
        store.save_run(run)
        enriched = enrich_run(run, kev=({"CVE-2025-1001"}, provenance), epss={"CVE-2025-1001": .8})
        store.save_run(enriched)
        self.assertNotEqual(enriched.id, run.id)
        self.assertEqual(enriched.started_at, run.started_at)
        self.assertEqual(enriched.completed_at, run.completed_at)
        self.assertEqual(enriched.source_digest, run.source_digest)
        self.assertEqual(enriched.data_updated_at, run.data_updated_at)
        self.assertEqual(enriched.findings[0].priority, "P1")
        self.assertEqual(enriched.findings[0].epss, .8)
        self.assertEqual(enriched.enrichment[0]["derived_from"], run.id)
        self.assertFalse(store.get_run(run.id).findings[0].kev)
        self.assertEqual(run.enrichment, [])

    def test_enrichment_rejects_invalid_manual_probabilities(self):
        with self.assertRaises(ValueError):
            enrich_run(Run("demo", "trivy"), epss={"CVE-2025-1001": float("nan")})

    def test_enrichment_rejects_nonstring_provenance_and_invalid_data_shape(self):
        provenance = {"source": "cisa-kev", "source_date": "2026-09-30", "sha256": 10,
                      "imported_at": "2026-10-01T00:00:00+00:00", "derived_from": ""}
        with self.assertRaises(ValueError):
            enrich_run(Run("demo", "trivy"), kev=({"CVE-2025-1001"}, provenance))
        with self.assertRaises(ValueError):
            enrich_run(Run("demo", "trivy"), kev=["CVE-2025-1001"])
