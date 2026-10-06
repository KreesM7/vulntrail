"""Bounded local CISA KEV JSON and decompressed FIRST EPSS CSV imports.

Digests identify supplied bytes; a local file's publisher is not authenticated.
"""
import csv
from datetime import date, datetime
import hashlib
import io
import json
import math
from pathlib import Path
import re
import uuid

from .models import Run, utc_now

MAX_FEED_BYTES = 25 * 1024 * 1024
MAX_FEED_ROWS = 500000
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")


def _date(value: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Feed source date is required")
    try:
        if len(value) == 10:
            return date.fromisoformat(value).isoformat()
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError as error:
        raise ValueError("Invalid feed source date") from error


def _read(path: Path) -> bytes:
    path = Path(path)
    if not path.is_file():
        raise ValueError("Feed must be a regular file")
    with path.open("rb") as stream:
        content = stream.read(MAX_FEED_BYTES + 1)
    if len(content) > MAX_FEED_BYTES:
        raise ValueError("Feed exceeds byte limit")
    return content


def _provenance(source: str, source_date: str, content: bytes) -> dict:
    return {"source": source, "source_date": source_date,
            "sha256": hashlib.sha256(content).hexdigest(), "imported_at": utc_now(),
            "derived_from": ""}


def _cve(value):
    if not isinstance(value, str) or not _CVE.fullmatch(value):
        raise ValueError("Invalid feed CVE identifier")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def load_kev(path: Path) -> tuple[set[str], dict]:
    content = _read(path)
    try:
        payload = json.loads(content.decode("utf-8-sig"), object_pairs_hook=_pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise ValueError("Expected CISA KEV catalog object")
        entries = payload["vulnerabilities"]
        if len(entries) > MAX_FEED_ROWS:
            raise ValueError("Feed exceeds row limit")
        if "count" in payload and (type(payload["count"]) is not int or payload["count"] != len(entries)):
            raise ValueError("KEV count differs from supplied rows")
        source_date = _date(payload.get("dateReleased"))
        values = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Invalid KEV row")
            identifier = _cve(entry.get("cveID"))
            if identifier in values:
                raise ValueError("Duplicate KEV row")
            values.add(identifier)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Invalid KEV JSON") from error
    return values, _provenance("cisa-kev", source_date, content)


def _probability(value) -> float:
    if type(value) is bool:
        raise ValueError("Invalid EPSS probability")
    try:
        probability = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Invalid EPSS probability") from error
    if not math.isfinite(probability) or not 0 <= probability <= 1:
        raise ValueError("EPSS probability must be finite and between 0 and 1")
    return probability


def load_epss(path: Path) -> tuple[dict[str, float], dict]:
    content = _read(path)
    try:
        stream = io.StringIO(content.decode("utf-8-sig"), newline="")
        source_date = None
        position = stream.tell()
        line = stream.readline()
        while line.startswith("#"):
            for item in line[1:].strip().split(","):
                key, separator, value = item.partition(":")
                if separator and key.strip() == "score_date":
                    if source_date is not None:
                        raise ValueError("Duplicate EPSS source date")
                    source_date = _date(value.strip())
            position = stream.tell()
            line = stream.readline()
        if source_date is None:
            raise ValueError("EPSS score_date metadata is required")
        stream.seek(position)
        reader = csv.DictReader(stream, strict=True)
        fields = reader.fieldnames
        if fields not in (["cve", "epss"], ["cve", "epss", "percentile"]):
            raise ValueError("Expected FIRST EPSS cve,epss[,percentile] header")
        scores = {}
        for index, row in enumerate(reader, 1):
            if index > MAX_FEED_ROWS or None in row or any(value is None for value in row.values()):
                raise ValueError("Too many or malformed EPSS rows")
            identifier = _cve(row["cve"])
            if identifier in scores:
                raise ValueError("Duplicate EPSS row")
            scores[identifier] = _probability(row["epss"])
            if "percentile" in row:
                _probability(row["percentile"])
    except (UnicodeError, csv.Error) as error:
        raise ValueError("Invalid EPSS CSV") from error
    return scores, _provenance("first-epss", source_date, content)


def _unpack(value, name: str):
    data = value[0] if isinstance(value, tuple) and len(value) == 2 else value
    if not isinstance(data, set if name == "kev" else dict) or len(data) > MAX_FEED_ROWS:
        raise ValueError("Invalid enrichment data")
    if isinstance(value, tuple) and len(value) == 2:
        data, provenance = value
        if not isinstance(provenance, dict) or set(provenance) != {
            "source", "source_date", "sha256", "imported_at", "derived_from"
        }:
            raise ValueError("Invalid feed provenance")
        if any(not isinstance(item, str) or len(item) > 4096 for item in provenance.values()):
            raise ValueError("Invalid feed provenance values")
        if not re.fullmatch(r"[0-9a-f]{64}", provenance.get("sha256", "")):
            raise ValueError("Invalid feed digest")
        if provenance.get("source_date"):
            _date(provenance["source_date"])
        return data, dict(provenance)
    normalized = sorted(value) if isinstance(value, set) else value
    content = json.dumps(normalized, sort_keys=True, allow_nan=False).encode("utf-8")
    return value, _provenance(f"local-{name}", "", content)


def enrich_run(run: Run, kev=None, epss=None) -> Run:
    """Derive a new snapshot; scan/database dates and source assertions stay intact."""
    result = Run.from_dict(run.to_dict())
    result.id = str(uuid.uuid4())
    for name, supplied in (("kev", kev), ("epss", epss)):
        if supplied is None:
            continue
        data, provenance = _unpack(supplied, name)
        for identifier in data:
            _cve(identifier)
        if name == "epss":
            data = {key: _probability(value) for key, value in data.items()}
        provenance["derived_from"] = run.id
        result.enrichment.append(provenance)
        for finding in result.findings:
            if name == "kev":
                finding.kev = finding.kev or finding.vulnerability_id in data
            elif finding.vulnerability_id in data:
                finding.epss = data[finding.vulnerability_id]
    return Run.from_dict(result.to_dict())
