"""Keyboard-first terminal review over the same real evidence store as the API."""
import asyncio

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select, Static

from .config import Settings
from .models import SEVERITIES
from .scanner import scan_target
from .store import Store


class VulnTrailApp(App):
    TITLE = "VulnTrail · Local evidence"
    SUB_TITLE = "Coverage and source context matter"
    BINDINGS = [("q", "quit", "Quit"), ("r", "refresh", "Refresh"),
                ("s", "scan", "Scan configured target"), ("/", "search", "Search")]
    CSS = """
    Screen { background: #112a36; color: #e8f2ef; }
    #controls { height: 5; padding: 1; }
    #target { width: 1fr; margin-right: 1; }
    Button { margin-right: 1; }
    #status { height: auto; min-height: 2; padding: 0 1; color: #abd8ce; }
    .heading { height: 2; padding: 0 1; text-style: bold; color: #d8eae5; }
    #runs { height: 9; margin: 0 1 1 1; }
    #detail-scroll { height: 8; margin: 0 1; border: solid #32605f; }
    #detail { height: auto; padding: 0 1; }
    #filters { height: 5; padding: 1; }
    #search { width: 2fr; margin-right: 1; }
    #severity { width: 1fr; }
    #findings { height: 1fr; min-height: 5; margin: 0 1; }
    #finding-detail { height: auto; max-height: 6; padding: 1; }
    DataTable { background: #183844; color: #e8f2ef; }
    DataTable > .datatable--header { background: #244950; color: #e8f2ef; }
    Footer { background: #244950; }
    """

    def __init__(self, settings: Settings, store: Store | None = None):
        super().__init__()
        self.settings = settings
        self.store = store or Store(settings.state_dir / "evidence.sqlite3")
        self.selected_run_id = None
        self.selected_run = None
        self.scanning = False
        self.page = 0
        self.page_size = 30
        self.finding_lookup = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="controls"):
            yield Select([(name, name) for name in sorted(self.settings.targets)],
                         prompt="Configured target", allow_blank=not bool(self.settings.targets),
                         value=next(iter(sorted(self.settings.targets)), Select.BLANK), id="target")
            yield Button("Run scan", id="scan", variant="success", disabled=not bool(self.settings.targets))
            yield Button("Refresh", id="refresh")
            yield Button("Previous", id="previous", disabled=True)
            yield Button("Next", id="next", disabled=True)
        yield Static("Loading local evidence…", id="status", markup=False)
        yield Label("Run history — arrows to navigate, Enter to inspect", classes="heading")
        yield DataTable(id="runs", cursor_type="row")
        with VerticalScroll(id="detail-scroll"):
            yield Static("Select a run to inspect coverage and findings.", id="detail", markup=False)
        with Horizontal(id="filters"):
            yield Input(placeholder="Search package, vulnerability, or location", id="search")
            yield Select([("All severities", "")] + [(s, s) for s in reversed(SEVERITIES)],
                         allow_blank=False, value="", id="severity")
        yield DataTable(id="findings", cursor_type="row")
        yield Static("Zero findings do not establish security. Review run coverage and database age.",
                     id="finding-detail", markup=False)
        yield Footer()

    async def on_mount(self):
        self.query_one("#runs", DataTable).add_columns("Started", "Target", "Backend", "Status", "Findings")
        self.query_one("#findings", DataTable).add_columns("Priority", "Severity", "Vulnerability", "Package", "Installed", "Fixed")
        await self.action_refresh()

    def status(self, value):
        self.query_one("#status", Static).update(Text(value))

    async def action_refresh(self):
        try:
            runs = await asyncio.to_thread(self.store.list_summaries, self.page_size, self.page * self.page_size)
            total = await asyncio.to_thread(self.store.count_runs)
            table = self.query_one("#runs", DataTable)
            table.clear()
            for run in runs:
                table.add_row(*[Text(str(value)) for value in (run["started_at"][:19], run["target"],
                    run["backend"], run["status"], run["finding_count"])], key=run["id"])
            self.query_one("#previous", Button).disabled = self.page == 0
            self.query_one("#next", Button).disabled = (self.page + 1) * self.page_size >= total
            if runs:
                selected = next((run for run in runs if run["id"] == self.selected_run_id), runs[0])
                self.show_run(await asyncio.to_thread(self.store.get_run, selected["id"]))
                self.status(f"{total} stored runs · page {self.page + 1} · backend {'offline' if self.settings.offline else 'online'} mode")
            else:
                self.selected_run_id = None
                self.selected_run = None
                self.query_one("#findings", DataTable).clear()
                self.query_one("#detail", Static).update("Select a run to inspect coverage and findings.")
                self.status("No evidence on this page. Run a configured target or import a supported report with the CLI.")
        except Exception:
            self.status("Local evidence could not load. Check the configuration and state directory.")

    def show_run(self, run):
        self.selected_run = run
        self.selected_run_id = run.id
        lines = [f"{run.target} · {run.backend} · {run.status}", f"Run: {run.id}",
                 f"Started: {run.started_at}", f"Completed: {run.completed_at}",
                 f"Database updated: {run.data_updated_at or 'Unknown; scan time is not database age'}",
                 f"Backend version: {run.backend_version or 'Not recorded'}",
                 f"Coverage: {', '.join(run.coverage) or 'No supported coverage recorded'}",
                 f"Source digest: {run.source_digest or 'Not recorded'}"]
        lines.extend(f"Warning: {warning}" for warning in run.warnings)
        self.query_one("#detail", Static).update(Text("\n".join(lines)))
        self.filter_findings()

    def filter_findings(self):
        table = self.query_one("#findings", DataTable)
        table.clear()
        self.finding_lookup = {}
        if not self.selected_run:
            return
        query = self.query_one("#search", Input).value.strip().lower()
        severity = self.query_one("#severity", Select).value
        findings = [f for f in self.selected_run.findings if (not severity or f.severity == severity)
                    and (not query or query in " ".join((f.package, f.vulnerability_id,
                                                        f.location, f.ecosystem)).lower())]
        for index, finding in enumerate(findings):
            key = f"{finding.fingerprint}-{index}"
            self.finding_lookup[key] = finding
            table.add_row(*[Text(value) for value in (finding.priority, finding.severity,
                finding.vulnerability_id, finding.package, finding.version,
                finding.fixed_version or "Not supplied")], key=key)
        self.query_one("#finding-detail", Static).update(Text(
            f"{len(findings)} of {len(self.selected_run.findings)} findings. Enter a finding to inspect its source details."))

    @on(Input.Changed, "#search")
    @on(Select.Changed, "#severity")
    def filter_changed(self):
        if self.is_mounted and self.query("#findings"):
            self.filter_findings()

    @on(DataTable.RowSelected, "#runs")
    async def run_selected(self, event):
        try:
            self.show_run(await asyncio.to_thread(self.store.get_run, event.row_key.value))
        except (KeyError, ValueError, OSError):
            self.status("This evidence run is unavailable. Refresh the history.")

    @on(DataTable.RowSelected, "#findings")
    def finding_selected(self, event):
        finding = self.finding_lookup.get(event.row_key.value)
        if finding:
            text = f"{finding.vulnerability_id} · {finding.package} {finding.version}\nLocation: {finding.location or 'Not supplied'} · Source: {finding.source}\nKEV: {'listed' if finding.kev else 'not marked'} · EPSS: {finding.epss if finding.epss is not None else 'not supplied'}\n{finding.description or 'No description supplied'}"
            self.query_one("#finding-detail", Static).update(Text(text))

    @on(Button.Pressed)
    async def pressed(self, event):
        if event.button.id == "refresh":
            await self.action_refresh()
        elif event.button.id == "previous":
            self.page = max(0, self.page - 1)
            await self.action_refresh()
        elif event.button.id == "next":
            self.page += 1
            await self.action_refresh()
        elif event.button.id == "scan":
            self.action_scan()

    def action_search(self):
        self.query_one("#search", Input).focus()

    def action_scan(self):
        target = self.query_one("#target", Select).value
        if self.scanning or target not in self.settings.targets:
            return
        self.scanning = True
        self.query_one("#scan", Button).disabled = True
        self.status(f"Scanning configured target {target}; a new evidence run will be recorded…")
        self.scan_worker(target)

    @work(exclusive=True, group="scan")
    async def scan_worker(self, target):
        try:
            run = await asyncio.to_thread(scan_target, self.settings, target)
            await asyncio.to_thread(self.store.save_run, run)
            await asyncio.to_thread(self.store.audit, "tui_scan", {"target": target, "run_id": run.id})
            self.page = 0
            self.selected_run_id = run.id
            await self.action_refresh()
            self.status(f"Scan recorded: {run.status} · {len(run.findings)} findings. Review coverage and warnings.")
        except Exception:
            self.status("The configured scan could not complete. Check backend prerequisites and configuration.")
        finally:
            self.scanning = False
            self.query_one("#scan", Button).disabled = not bool(self.settings.targets)
