from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from textual.widgets import DataTable, Input, Static

from vulntrail.config import Settings
from vulntrail.models import Finding, Run
from vulntrail.store import Store
from vulntrail.tui import VulnTrailApp


class TuiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        root = Path(self.temp.name)
        self.settings = Settings(state_dir=root / "state", targets={"demo": root})
        self.store = Store(self.settings.state_dir / "evidence.sqlite3")

    async def asyncTearDown(self):
        self.temp.cleanup()

    async def test_real_store_empty_refresh_detail_and_search(self):
        app = VulnTrailApp(self.settings, self.store)
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.pause()
            self.assertEqual(app.query_one("#runs", DataTable).row_count, 0)
            self.assertIn("No evidence", str(app.query_one("#status", Static).render()))
            run = self.store.save_run(
                Run(
                    "demo",
                    "trivy",
                    [
                        Finding(
                            "CVE-TEST",
                            "example",
                            "1",
                            "pypi",
                            "HIGH",
                            description="A real stored description",
                        )
                    ],
                    coverage=["requirements.txt"],
                )
            )
            await app.action_refresh()
            await pilot.pause()
            self.assertEqual(app.query_one("#runs", DataTable).row_count, 1)
            self.assertEqual(app.selected_run_id, run.id)
            self.assertEqual(app.query_one("#findings", DataTable).row_count, 1)
            app.query_one("#search", Input).value = "absent"
            await pilot.pause()
            self.assertEqual(app.query_one("#findings", DataTable).row_count, 0)
            app.query_one("#search", Input).value = "example"
            await pilot.pause()
            self.assertEqual(app.query_one("#findings", DataTable).row_count, 1)

    async def test_scan_worker_records_configured_scan_and_refreshes(self):
        app = VulnTrailApp(self.settings, self.store)
        with patch(
            "vulntrail.tui.scan_target",
            side_effect=lambda *args: Run("demo", "trivy", coverage=["requirements.txt"]),
        ):
            async with app.run_test(size=(100, 40)) as pilot:
                await pilot.pause()
                self.assertTrue(await pilot.click("#scan", offset=(3, 1)))
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                self.assertEqual(self.store.count_runs(), 1)
                self.assertEqual(app.query_one("#runs", DataTable).row_count, 1)
                self.assertFalse(app.scanning)

    async def test_failed_worker_displays_error_and_releases_scan_state(self):
        app = VulnTrailApp(self.settings, self.store)
        with patch(
            "vulntrail.tui.scan_target", side_effect=RuntimeError("sensitive internal path")
        ):
            async with app.run_test(size=(100, 40)) as pilot:
                await pilot.pause()
                self.assertTrue(await pilot.click("#scan", offset=(3, 1)))
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                rendered = str(app.query_one("#status", Static).render())
                self.assertIn("could not complete", rendered)
                self.assertNotIn("sensitive", rendered)
                self.assertFalse(app.scanning)
