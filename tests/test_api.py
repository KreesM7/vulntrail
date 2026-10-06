import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from vulntrail.api import create_app
from vulntrail.config import Settings
from vulntrail.models import Finding, Run
from vulntrail.store import Store


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.temp.name)
        self.settings = Settings(state_dir=self.root / "state", targets={"demo": self.root})
        self.token = "t" * 40
        self.app = create_app(self.settings, self.token)
        self.client = TestClient(
            self.app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)
        )
        self.headers = {"Authorization": f"Bearer {self.token}"}
        self.ui_headers = {"Origin": "http://127.0.0.1:8765", "X-VulnTrail-Client": "dashboard"}
        self.store = Store(self.settings.state_dir / "evidence.sqlite3")

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def test_token_required_and_weak_token_refused(self):
        with self.assertRaises(ValueError):
            create_app(self.settings, "short")
        for headers in ({}, {"Authorization": "Bearer wrong"}):
            response = self.client.get("/api/v1/status", headers=headers)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["error"]["code"], "UNAUTHORIZED")
        self.assertEqual(self.client.get("/api/v1/status", headers=self.headers).status_code, 200)

    def test_rebinding_cross_origin_and_non_loopback_rejected(self):
        for headers in (
            {"Host": "attacker.example"},
            {"Origin": "https://attacker.example"},
            {"Origin": "null"},
        ):
            response = self.client.get("/api/v1/status", headers={**self.headers, **headers})
            self.assertEqual(response.status_code, 403)
        with TestClient(
            self.app, base_url="http://127.0.0.1:8765", client=("10.0.0.1", 5555)
        ) as remote:
            self.assertEqual(remote.get("/", headers=self.headers).status_code, 403)

    def test_session_cookie_is_http_only_strict_and_not_api_bearer(self):
        login = self.client.post("/ui/session", json={"token": self.token}, headers=self.ui_headers)
        self.assertEqual(login.status_code, 200)
        cookie = login.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertNotIn(self.token, cookie)
        self.assertEqual(self.client.get("/api/v1/status").status_code, 401)
        self.assertEqual(
            self.client.get("/ui/api/status", headers=self.ui_headers).status_code, 200
        )
        self.assertEqual(
            self.client.post("/ui/api/scans", json={"target": "demo"}).status_code, 403
        )
        self.client.delete("/ui/session", headers=self.ui_headers)
        self.assertEqual(
            self.client.get("/ui/api/status", headers=self.ui_headers).status_code, 401
        )

    def test_body_limit_validation_and_login_rate_limit(self):
        response = self.client.post("/ui/session", content=b"x" * 32769, headers=self.ui_headers)
        self.assertEqual(response.status_code, 413)
        for _ in range(10):
            self.client.post("/ui/session", json={"token": "wrong"}, headers=self.ui_headers)
        self.assertEqual(
            self.client.post(
                "/ui/session", json={"token": self.token}, headers=self.ui_headers
            ).status_code,
            429,
        )

    def test_real_evidence_pagination_detail_report_comparison_delete(self):
        first = self.store.save_run(
            Run("demo", "trivy", coverage=["requirements.txt"], target_identity="test-project")
        )
        second = self.store.save_run(
            Run(
                "demo",
                "trivy",
                [Finding("CVE-TEST", "pkg", "1", "pypi", "HIGH")],
                coverage=["requirements.txt"],
                target_identity="test-project",
            )
        )
        listing = self.client.get("/api/v1/runs?limit=1&offset=0", headers=self.headers)
        self.assertEqual(listing.json()["total"], 2)
        self.assertEqual(len(listing.json()["items"]), 1)
        detail = self.client.get(f"/api/v1/runs/{second.id}", headers=self.headers)
        self.assertEqual(detail.json()["findings"][0]["package"], "pkg")
        report = self.client.get(
            f"/api/v1/runs/{second.id}/report?format=html", headers=self.headers
        )
        self.assertIn("attachment", report.headers["content-disposition"])
        comparison = self.client.get(
            "/api/v1/comparisons",
            params={"before": first.id, "after": second.id},
            headers=self.headers,
        )
        self.assertTrue(comparison.json()["comparable"])
        self.assertEqual(len(comparison.json()["added"]), 1)
        self.assertEqual(
            self.client.delete(f"/api/v1/runs/{second.id}", headers=self.headers).status_code, 200
        )
        self.assertEqual(
            self.client.get(f"/api/v1/runs/{second.id}", headers=self.headers).status_code, 404
        )

    def test_scan_only_accepts_configured_name_and_saves_result(self):
        for body in (
            {"target": "../elsewhere"},
            {"target": "demo", "path": "/etc"},
            {"target": "demo", "backend": "shell"},
        ):
            self.assertEqual(
                self.client.post("/api/v1/scans", json=body, headers=self.headers).status_code, 422
            )
        with patch("vulntrail.api.scan_target", return_value=Run("demo", "trivy", coverage=["x"])):
            response = self.client.post(
                "/api/v1/scans", json={"target": "demo"}, headers=self.headers
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.store.get_run(response.json()["id"]).target, "demo")

    def test_scan_serialization_and_generic_errors(self):
        entered, release = threading.Event(), threading.Event()

        def slow_scan(*args):
            entered.set()
            release.wait(5)
            return Run("demo", "trivy", coverage=["x"])

        with patch("vulntrail.api.scan_target", side_effect=slow_scan):
            worker = threading.Thread(
                target=lambda: self.client.post(
                    "/api/v1/scans", json={"target": "demo"}, headers=self.headers
                )
            )
            worker.start()
            self.assertTrue(entered.wait(3))
            duplicate = self.client.post(
                "/api/v1/scans", json={"target": "demo"}, headers=self.headers
            )
            self.assertEqual(duplicate.status_code, 409)
            release.set()
            worker.join(5)
        with patch("vulntrail.api.scan_target", side_effect=RuntimeError("secret /private/path")):
            error = self.client.post("/api/v1/scans", json={"target": "demo"}, headers=self.headers)
        self.assertEqual(error.status_code, 500)
        self.assertNotIn("secret", error.text)
        self.assertNotIn("/private", error.text)

    def test_security_headers_and_static_assets(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("VulnTrail", response.text)
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertIn("default-src 'self'", response.headers["content-security-policy"])
        self.assertEqual(self.client.get("/static/app.js").status_code, 200)
        self.assertEqual(
            self.client.get("/api/v1/runs?limit=1000", headers=self.headers).status_code, 422
        )
