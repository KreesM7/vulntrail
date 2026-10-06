"""Bounded invocation of a configured local Trivy engine; no shell or target URL."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
from .adapters import parse_report, read_json
from .config import Settings
from .models import Run, utc_now

def _stop_process(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/taskkill.exe"
        subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                       creationflags=subprocess.CREATE_NO_WINDOW, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
    if process.poll() is None:
        process.kill()

def run_bounded(command: list[str], timeout: float, limit: int, cwd=None, env=None):
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, shell=False, cwd=cwd, env=env, start_new_session=os.name != "nt",
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    def consume(stream, index, cap):
        while chunk := stream.read(8192):
            remaining = cap - len(buffers[index])
            buffers[index].extend(chunk[:max(remaining, 0)])
            if len(chunk) > remaining:
                overflow.set()
                return
    threads = [threading.Thread(target=consume, args=(process.stdout, 0, limit), daemon=True),
               threading.Thread(target=consume, args=(process.stderr, 1, 65536), daemon=True)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if overflow.is_set():
                raise ValueError("Backend output exceeds configured limit")
            if time.monotonic() >= deadline:
                raise TimeoutError("Backend exceeded scan timeout")
            time.sleep(0.01)
        for thread in threads:
            thread.join(timeout=1)
        if overflow.is_set():
            raise ValueError("Backend output exceeds configured limit")
        if any(thread.is_alive() for thread in threads):
            raise TimeoutError("Backend output streams did not close")
        return process.returncode, bytes(buffers[0]), bytes(buffers[1])
    finally:
        _stop_process(process)
        process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=1)
        if all(not thread.is_alive() for thread in threads):
            process.stdout.close()
            process.stderr.close()

def build_command(settings: Settings, target: Path, config_path: Path, ignore_path: Path):
    command = [settings.trivy_path, "filesystem", "--config", str(config_path),
        "--cache-dir", str(settings.cache_dir), "--format", "json", "--scanners", "vuln",
        "--list-all-pkgs", "--disable-telemetry", "--skip-version-check", "--no-progress",
        "--ignorefile", str(ignore_path), "--module-dir", str(config_path.parent / "modules"),
        "--timeout", f"{settings.timeout_seconds}s"]
    if settings.offline:
        command.extend(["--offline-scan", "--skip-db-update", "--skip-java-db-update",
                        "--skip-check-update", "--skip-vex-repo-update"])
    command.extend(["--", str(target)])
    return command

def scan_target(settings: Settings, target_name: str) -> Run:
    if target_name not in settings.targets:
        raise ValueError("Choose a configured authorized target")
    target = settings.targets[target_name]
    run = Run(target_name, "trivy", offline=settings.offline)
    if not target.exists():
        run.status = "failed"
        run.warnings = ["Target does not exist or cannot be accessed."]
        return run
    metadata_path = settings.cache_dir / "db" / "metadata.json"
    if settings.offline and not (metadata_path.is_file() and
                                (settings.cache_dir / "db" / "trivy.db").is_file()):
        run.status = "failed"
        run.warnings = ["Offline vulnerability database missing. Provision Trivy cache before scanning."]
        return run
    settings.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    settings.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    environment = {k: v for k, v in os.environ.items() if k.upper() in
        {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOME",
         "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"}}
    environment["TRIVY_DISABLE_TELEMETRY"] = "true"
    try:
        with tempfile.TemporaryDirectory(prefix="scan-", dir=settings.state_dir) as root:
            config_path, ignore_path = Path(root) / "config.yaml", Path(root) / "ignore.txt"
            config_path.write_text("{}", encoding="utf-8")
            ignore_path.write_text("", encoding="utf-8")
            (Path(root) / "modules").mkdir()
            rc, version, _ = run_bounded([settings.trivy_path, "version", "--format", "json"],
                timeout=min(settings.timeout_seconds, 15), limit=65536, cwd=root, env=environment)
            if rc != 0:
                raise ValueError("Trivy version check failed")
            version_data = json.loads(version)
            rc, report, _ = run_bounded(build_command(settings, target, config_path, ignore_path),
                timeout=settings.timeout_seconds, limit=settings.max_report_bytes,
                cwd=root, env=environment)
            if rc != 0:
                raise ValueError(f"Trivy failed (exit {rc}); verify executable, permissions and cache with doctor")
            payload = json.loads(report)
            parsed = parse_report(payload, "trivy", target_name, offline=settings.offline,
                                  max_findings=settings.max_findings)
            parsed.id, parsed.started_at, parsed.completed_at = run.id, run.started_at, utc_now()
            parsed.backend_version = str(version_data.get("Version", "unknown"))
            if metadata_path.is_file():
                updated = read_json(metadata_path, 65536).get("UpdatedAt")
                if isinstance(updated, str):
                    date = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                    if date.tzinfo is None:
                        raise ValueError("Database timestamp has no timezone")
                    parsed.data_updated_at = date.isoformat()
                    parsed.warnings = [w for w in parsed.warnings if not w.startswith("Database update")]
                    age = (datetime.now(timezone.utc) - date).total_seconds() / 86400
                    if age > settings.max_data_age_days or age < -1:
                        parsed.warnings.append("Database timestamp is stale or in the future; review freshness.")
            return parsed
    except (OSError, ValueError, TypeError, AttributeError, TimeoutError,
            subprocess.SubprocessError, RecursionError) as exc:
        run.status, run.completed_at = "failed", utc_now()
        safe = str(exc) if isinstance(exc, (ValueError, TimeoutError)) else "Backend could not run or returned invalid data."
        run.warnings = [safe[:1024]]
        return run
