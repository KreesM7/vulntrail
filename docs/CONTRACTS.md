# v0.1 contracts and architecture

Python 3.11+, standard-library detection orchestration/persistence. PyYAML safe parsing, FastAPI/uvicorn local API, Textual terminal UI. No cloud or AI runtime dependency. CLI/API fields use snake_case consistently.

## Shared objects (vulntrail.models)

Finding: dataclass fields vulnerability_id, package, version, ecosystem, severity (UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL), fixed_version="", location="", description="", urls=[], source="trivy", kev=False, epss=None. fingerprint property hashes source/ecosystem/location/package/version/vulnerability_id. priority property returns P1 if KEV, P2 if HIGH/CRITICAL, P3 otherwise. to_dict()/from_dict() preserve these fields; fingerprint/priority are derived.

Run: dataclass fields target, backend, findings=[], status="complete" (complete/partial/failed), coverage=[], warnings=[], offline=True, data_updated_at=None, source_digest="", backend_version="", id=uuid, started_at=UTC timestamp, completed_at=UTC timestamp. to_dict()/from_dict(). Scan import time is not data update time.

## Provider boundaries

config.Settings: state_dir: Path; targets: dict[str, Path]; trivy_path="trivy"; cache_dir: Path; offline=True; timeout_seconds=300; max_report_bytes=25*1024*1024; max_findings=20000; interval_seconds=3600; max_data_age_days=7. load_settings(path: Path | None)->Settings. Config paths relative to config parent. Unknown keys, invalid limits and remote targets rejected.

adapters.parse_report(payload: dict, backend: str, target: str, offline=True, max_findings=20000)->Run. Trivy SchemaVersion=2 JSON and Grype matches JSON only. Unsupported/malformed shapes fail, absent coverage means partial not clean. No generic version matching.

scanner.scan_target(settings: Settings, target_name: str)->Run. Invoke only configured Trivy local filesystem scanner, fixed argument list, no shell, bounded output/time, explicitly controlled cache and offline flags. Failures return failed Run; successful output is parsed. Runner does not persist; consumers call Store.save_run.

store.Store(path: Path): save_run(run: Run, raw: dict|None=None)->Run; get_run(id)->Run or KeyError; list_runs(limit=50, offset=0)->list[Run]; count_runs()->int; delete_run(id)->bool; audit(event: str, details: dict)->None. SQLite writes transactional/parameterized; one connection per operation, thread safe by separation. Store snapshots immutable, derived priority returned from Finding. Raw source optional; no app secret ever stored.

triage.compare_runs(before: Run, after: Run)->dict with comparable, reason, added, persistent, no_longer_observed, unresolved. Removal not called resolved. Only matching target/backend/coverage with complete runs can yield no_longer_observed. A missing finding in partial/failed/unmatched coverage is unresolved.

reports.render_report(run: Run, format: str)->str for json/md/html. Escape all HTML and Markdown control data. Optional feeds enrich a copy, never rewrite historical source assertions.

feeds.load_kev(path: Path)->(set[str], dict provenance); load_epss(path: Path)->(dict[str,float], dict provenance); enrich_run(run, kev=None, epss=None)->Run. Bounded files/rows, finite probability [0,1], source digest/date retained. No network fetch.

response.plan_response(run: Run)->dict containing only human-readable upgrade/verify advice, never shell commands automatically executed. Artifact holding is CLI-only, approved by exact digest, confined to user-selected project root, reversible and audited. Not a package manager / incident-response replacement.

## REST and UI

create_app(settings, token: str)->FastAPI. Require token >=32 characters; Authorization: Bearer token on /api/v1/*, constant-time compare. UI login exchanges submitted token for same-origin HttpOnly SameSite=Strict cookie (no browser storage, no tokens in URLs). Reject foreign Origin/Host. Bind 127.0.0.1 by default and reject public bind in CLI. Single-process service; no CORS. No arbitrary paths/executable/uploads through API.

GET /api/v1/status, GET /api/v1/runs?limit=&offset=, GET /api/v1/runs/{id}, GET /api/v1/runs/{id}/report?format=json|md|html, GET /api/v1/comparisons?before=&after=.
POST /api/v1/scans body {target: configured-name}; serialized bounded scan; document unsafe-to-retry request. DELETE /api/v1/runs/{id} explicitly removes local evidence.
Errors: {error:{code,message}} with 400/401/403/404/409/422/429/500. No traceback/path/secret leaks. Imported files only via CLI.

Dashboard: semantic neutral navy/teal operations layout, clear real empty/error/loading states, keyboard controls, responsive table, target scan buttons, run details/search/severity filters/history/export. No fabricated counters.
TUI: headless-testable Textual app backed by Store and Settings, refresh/run selection/details; safe scan worker via configured target.

CLI: init, scan TARGET, watch TARGET [--count N] [--interval S], import REPORT --backend trivy|grype --target NAME, runs, show ID, diff BEFORE AFTER, report ID --format json|md|html, serve, tui, doctor, enrich ID [--kev FILE] [--epss FILE], response ID, hold/restore. --config path selects settings. Findings exit 1 only when requested --fail-on severity; execution/data failure exit 2.

## Threat model / honest guarantees

Untrusted report/feed/config/HTTP content is data, never instructions. Bound bytes, depth/shape and findings; no shell or arbitrary fetch; parameterized SQL and escaped rendering. HTTP credentials stay local/in-memory. Private evidence ignored by Git, deletable by user. Offline flags suppress backend update/telemetry; actual air-gap isolation requires OS/container network denial, which the application cannot enforce portably. No zero-finding security assurance or compliance certification.

Backend coverage is whatever supported records the configured Trivy version scans, not all installed applications or whole-host vulnerability coverage. Existing backend binaries/databases must be provisioned separately. Trivy is not bundled or downloaded silently.
