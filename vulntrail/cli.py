"""Local operations: scans, immutable evidence, reports, and explicit artifact holding."""

import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import sys
import time

import yaml

from .adapters import parse_report, read_json
from .config import load_settings
from .feeds import enrich_run, load_epss, load_kev
from .models import SEVERITIES
from .reports import render_report
from .response import hold_artifact, plan_response, restore_artifact
from .scanner import scan_target
from .store import Store
from .triage import compare_runs


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulntrail", description="Local vulnerability evidence and history"
    )
    parser.add_argument(
        "--config", type=Path, help="YAML configuration (default: config.yaml if present)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create a configuration without overwriting")
    init.add_argument("file", type=Path, nargs="?", default=Path("config.yaml"))
    init.add_argument("--target", action="append", default=[], metavar="NAME=PATH")
    for name in ("scan", "watch"):
        command = sub.add_parser(
            name,
            help="Scan a configured local target"
            if name == "scan"
            else "Repeat scans until interrupted or count reached",
        )
        command.add_argument("target")
        command.add_argument(
            "--fail-on", choices=SEVERITIES, help="Exit 1 if this severity or higher is observed"
        )
        if name == "watch":
            command.add_argument(
                "--count", type=int, default=0, help="Number of scans; 0 means until interrupted"
            )
            command.add_argument("--interval", type=float, help="Seconds between completed scans")
    imported = sub.add_parser("import", help="Import a bounded local Trivy or Grype JSON report")
    imported.add_argument("report", type=Path)
    imported.add_argument("--backend", choices=("trivy", "grype"), required=True)
    imported.add_argument("--target", required=True)
    imported.add_argument("--fail-on", choices=SEVERITIES)
    runs = sub.add_parser("runs", help="List stored evidence")
    runs.add_argument("--limit", type=int, default=20)
    runs.add_argument("--offset", type=int, default=0)
    for name in ("show", "response"):
        command = sub.add_parser(
            name, help="Show evidence" if name == "show" else "Plan human-reviewed remediation"
        )
        command.add_argument("id")
    diff = sub.add_parser("diff", help="Compare findings with honest coverage semantics")
    diff.add_argument("before")
    diff.add_argument("after")
    report = sub.add_parser("report", help="Export JSON, Markdown, or escaped HTML")
    report.add_argument("id")
    report.add_argument("--format", choices=("json", "md", "html"), default="json")
    report.add_argument(
        "--output", type=Path, help="Write a new file; existing files are never replaced"
    )
    serve = sub.add_parser("serve", help="Start the local API and dashboard (one process)")
    serve.add_argument("--host", default="127.0.0.1", help="Literal loopback address only")
    serve.add_argument("--port", type=int, default=8765)
    sub.add_parser("tui", help="Open the terminal evidence dashboard")
    sub.add_parser("doctor", help="Inspect local prerequisites without downloading or updating")
    enrich = sub.add_parser("enrich", help="Enrich a new evidence copy using local feed files")
    enrich.add_argument("id")
    enrich.add_argument("--kev", type=Path)
    enrich.add_argument("--epss", type=Path)
    for name in ("hold", "restore"):
        command = sub.add_parser(
            name,
            help="Explicitly hold a project artifact"
            if name == "hold"
            else "Restore a held project artifact",
        )
        command.add_argument("root", type=Path, help="User-selected project root")
        command.add_argument("artifact" if name == "hold" else "hold_id")
        command.add_argument("--sha256", required=True, help="Exact approved SHA-256 digest")
        command.add_argument(
            "--confirm", action="store_true", help="Approve this exact artifact move"
        )
    return parser


def _emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))


def _exit_for_run(run, fail_on):
    if run.status != "complete":
        return 2
    if fail_on and any(
        SEVERITIES.index(f.severity) >= SEVERITIES.index(fail_on) for f in run.findings
    ):
        return 1
    return 0


def _init(args):
    if args.file.exists():
        raise ValueError("Configuration already exists; choose a new file")
    targets = {}
    for entry in args.target:
        if "=" not in entry:
            raise ValueError("Use --target NAME=PATH")
        name, path = entry.split("=", 1)
        if not name or not path or name in targets:
            raise ValueError("Target names and paths must be nonempty and unique")
        targets[name] = str(Path(path).resolve())
    value = {
        "state_dir": "./.vulntrail",
        "cache_dir": "./.vulntrail/cache",
        "targets": targets,
        "offline": True,
        "interval_seconds": 3600,
        "timeout_seconds": 300,
        "max_data_age_days": 7,
        "trivy_path": "trivy",
    }
    from .config import Settings

    Settings(**value)
    args.file.parent.mkdir(parents=True, exist_ok=True)
    with args.file.open("x", encoding="utf-8") as handle:
        yaml.safe_dump(value, handle, sort_keys=False)
    _emit({"config": str(args.file.resolve()), "targets": list(targets)})
    return 0


def _doctor(settings):
    configured = settings.trivy_path
    binary = shutil.which(str(configured))
    if not binary and Path(configured).is_file():
        binary = str(Path(configured).resolve())
    targets = [{"name": name, "exists": path.is_dir()} for name, path in settings.targets.items()]
    cache_exists = settings.cache_dir.is_dir()
    metadata = settings.cache_dir / "db" / "metadata.json"
    checks = {
        "backend_available": bool(binary),
        "configured_targets": targets,
        "cache_exists": cache_exists,
        "database_metadata_exists": metadata.is_file(),
        "offline": settings.offline,
        "notes": [
            "Provision Trivy and its vulnerability database separately.",
            "Offline backend flags do not enforce operating-system network isolation.",
            "Database age and coverage are reported with each supported scan.",
        ],
    }
    _emit(checks)
    return (
        0
        if binary
        and targets
        and all(t["exists"] for t in targets)
        and (not settings.offline or metadata.is_file())
        else 2
    )


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "init":
            return _init(args)
        settings = load_settings(args.config)
        if args.command == "doctor":
            return _doctor(settings)
        if args.command == "serve":
            if args.host not in {"127.0.0.1", "::1"} or not 1 <= args.port <= 65535:
                raise ValueError("Serve requires a literal loopback address and valid port")
            token = os.environ.get("VULNTRAIL_TOKEN")
            if token is None:
                token = getpass.getpass("Local access token (at least 32 characters): ")
            from .api import create_app
            import uvicorn

            app = create_app(settings, token)
            print(
                f"VulnTrail dashboard: http://{'[::1]' if args.host == '::1' else args.host}:{args.port}",
                file=sys.stderr,
            )
            uvicorn.run(
                app,
                host=args.host,
                port=args.port,
                workers=1,
                proxy_headers=False,
                access_log=False,
                log_level="warning",
            )
            return 0
        store = Store(settings.state_dir / "evidence.sqlite3")
        if args.command == "tui":
            from .tui import VulnTrailApp

            VulnTrailApp(settings, store).run()
            return 0
        if args.command in {"scan", "watch"}:
            if args.target not in settings.targets:
                raise ValueError("Choose a configured target")
            count = args.count if args.command == "watch" else 1
            interval = (
                (args.interval if args.interval is not None else settings.interval_seconds)
                if args.command == "watch"
                else 0
            )
            if (
                count < 0
                or count > 100000
                or (args.command == "watch" and not 1 <= interval <= 86400)
            ):
                raise ValueError("Watch count must be 0–100000 and interval 1–86400 seconds")
            completed, code = 0, 0
            while count == 0 or completed < count:
                run = store.save_run(scan_target(settings, args.target))
                store.audit("cli_scan", {"target": args.target, "run_id": run.id})
                _emit(run.to_dict())
                code = max(code, _exit_for_run(run, args.fail_on))
                completed += 1
                if count == 0 or completed < count:
                    time.sleep(interval)
            return code
        if args.command == "import":
            raw = read_json(args.report, settings.max_report_bytes)
            run = parse_report(
                raw,
                args.backend,
                args.target,
                offline=settings.offline,
                max_findings=settings.max_findings,
            )
            store.save_run(run, raw)
            store.audit("cli_import", {"backend": args.backend, "run_id": run.id})
            _emit(run.to_dict())
            return _exit_for_run(run, args.fail_on)
        if args.command == "runs":
            if not 1 <= args.limit <= 100 or not 0 <= args.offset <= 1000000:
                raise ValueError("Limit must be 1–100 and offset 0–1000000")
            _emit(
                {
                    "items": store.list_summaries(args.limit, args.offset),
                    "total": store.count_runs(),
                    "limit": args.limit,
                    "offset": args.offset,
                }
            )
        elif args.command == "show":
            _emit(store.get_run(args.id).to_dict())
        elif args.command == "diff":
            _emit(compare_runs(store.get_run(args.before), store.get_run(args.after)))
        elif args.command == "report":
            rendered = render_report(store.get_run(args.id), args.format)
            if args.output:
                with args.output.open("x", encoding="utf-8") as handle:
                    handle.write(rendered)
                _emit({"output": str(args.output.resolve()), "format": args.format})
            else:
                print(rendered)
        elif args.command == "enrich":
            if not args.kev and not args.epss:
                raise ValueError("Provide at least one local --kev or --epss feed")
            run = enrich_run(
                store.get_run(args.id),
                kev=load_kev(args.kev) if args.kev else None,
                epss=load_epss(args.epss) if args.epss else None,
            )
            store.save_run(run)
            store.audit("cli_enrich", {"source_run": args.id, "run_id": run.id})
            _emit(run.to_dict())
        elif args.command == "response":
            _emit(plan_response(store.get_run(args.id)))
        elif args.command in {"hold", "restore"}:
            if not args.confirm:
                raise ValueError("Exact artifact moves require --confirm and --sha256")
            root = args.root.resolve(strict=True)
            if args.command == "hold":
                artifact = Path(args.artifact)
                if not artifact.is_absolute():
                    artifact = root / artifact
                _emit(hold_artifact(root, artifact, args.sha256, store))
            else:
                _emit(restore_artifact(root, args.hold_id, args.sha256, store))
        return 0
    except KeyboardInterrupt:
        print("Stopped by user; completed scans remain in local evidence.", file=sys.stderr)
        return 130
    except KeyError:
        print("Error: evidence run not found.", file=sys.stderr)
        return 2
    except (ValueError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except Exception:
        print(
            "Error: the local operation could not complete. Check configuration and prerequisites.",
            file=sys.stderr,
        )
        return 2
