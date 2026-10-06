"""Transactional local evidence snapshots; each operation owns its connection."""

from contextlib import contextmanager
from collections import Counter
import json
from pathlib import Path
import sqlite3

from .models import Run, text, utc_now

MAX_EVIDENCE_BYTES = 25 * 1024 * 1024
MAX_AUDIT_BYTES = 64 * 1024
_CREDENTIAL_KEYS = {"token", "api_token", "api_key", "password", "secret", "authorization"}


def _serialize(value: dict, limit: int, credentials: bool = False) -> str:
    if not isinstance(value, dict):
        raise ValueError("Expected an object")

    def inspect(node, depth=0):
        if depth > 32:
            raise ValueError("Object is too deeply nested")
        if isinstance(node, dict):
            for key, child in node.items():
                if not isinstance(key, str):
                    raise ValueError("Object keys must be strings")
                if credentials and key.lower() in _CREDENTIAL_KEYS:
                    raise ValueError("Credentials must not be audited")
                inspect(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                inspect(child, depth + 1)

    try:
        inspect(value)
        payload = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except (TypeError, RecursionError) as error:
        raise ValueError("Invalid evidence object") from error
    if len(payload.encode("utf-8")) > limit:
        raise ValueError("Object exceeds storage limit")
    return payload


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    raw_json TEXT
                );
                CREATE INDEX IF NOT EXISTS runs_started ON runs(started_at DESC, id DESC);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    event TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS immutable_runs
                BEFORE UPDATE ON runs BEGIN
                    SELECT RAISE(ABORT, 'Run snapshots are immutable');
                END;
            """)

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _audit(connection, event: str, details: dict):
        text(event, "audit event", 100, required=True)
        payload = _serialize(details, MAX_AUDIT_BYTES, credentials=True)
        connection.execute(
            "INSERT INTO audit(created_at, event, details_json) VALUES (?, ?, ?)",
            (utc_now(), event, payload),
        )

    def save_run(self, run: Run, raw: dict | None = None) -> Run:
        if not isinstance(run, Run):
            raise ValueError("Expected a validated run")
        try:
            snapshot = Run.from_dict(run.to_dict())
            payload = _serialize(snapshot.to_dict(), MAX_EVIDENCE_BYTES)
        except (TypeError, AttributeError, RecursionError) as error:
            raise ValueError("Invalid run snapshot") from error
        raw_payload = None if raw is None else _serialize(raw, MAX_EVIDENCE_BYTES)
        try:
            with self._connection() as connection:
                connection.execute(
                    "INSERT INTO runs(id, started_at, snapshot_json, raw_json) VALUES (?, ?, ?, ?)",
                    (snapshot.id, snapshot.started_at, payload, raw_payload),
                )
                self._audit(connection, "run_saved", {"run_id": snapshot.id})
        except sqlite3.IntegrityError as error:
            raise ValueError(
                "Run identifier already exists; snapshots cannot be overwritten"
            ) from error
        return Run.from_dict(json.loads(payload))

    def get_run(self, id: str) -> Run:
        text(id, "run identifier", required=True)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT snapshot_json FROM runs WHERE id = ?", (id,)
            ).fetchone()
        if row is None:
            raise KeyError(id)
        return Run.from_dict(json.loads(row[0]))

    @staticmethod
    def _pagination(limit: int, offset: int):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000")
        if type(offset) is not int or offset < 0:
            raise ValueError("Offset must be a nonnegative integer")

    def list_runs(self, limit: int = 50, offset: int = 0) -> list[Run]:
        self._pagination(limit, offset)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT snapshot_json FROM runs ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [Run.from_dict(json.loads(row[0])) for row in rows]

    def list_summaries(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """Read one snapshot at a time and return bounded metadata for history views."""
        self._pagination(limit, offset)
        summaries = []
        with self._connection() as connection:
            cursor = connection.execute(
                "SELECT snapshot_json FROM runs ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            for row in cursor:
                summary = json.loads(row[0])
                findings = summary.pop("findings")
                summary["finding_count"] = len(findings)
                summary["severity_counts"] = dict(
                    Counter(finding["severity"] for finding in findings)
                )
                truncated = False
                for key, count_key in (
                    ("coverage", "coverage_count"),
                    ("warnings", "warning_count"),
                ):
                    values = summary[key]
                    summary[count_key] = len(values)
                    truncated |= len(values) > 10 or any(len(value) > 512 for value in values)
                    summary[key] = [value[:512] for value in values[:10]]
                provenance = summary.get("enrichment", [])
                summary["enrichment_count"] = len(provenance)
                truncated |= len(provenance) > 4 or any(
                    len(value) > 256 for item in provenance for value in item.values()
                )
                summary["enrichment"] = [
                    {key: value[:256] for key, value in item.items()} for item in provenance[-4:]
                ]
                summary["summary_truncated"] = bool(truncated)
                summaries.append(summary)
        return summaries

    def count_runs(self) -> int:
        with self._connection() as connection:
            return connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]

    def delete_run(self, id: str) -> bool:
        text(id, "run identifier", required=True)
        with self._connection() as connection:
            deleted = connection.execute("DELETE FROM runs WHERE id = ?", (id,)).rowcount > 0
            if deleted:
                self._audit(connection, "run_deleted", {"run_id": id})
        return deleted

    def audit(self, event: str, details: dict) -> None:
        with self._connection() as connection:
            self._audit(connection, event, details)
