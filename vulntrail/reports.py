"""Portable exports: evidence content is encoded, never trusted markup."""
import html
import json
import re

from .models import Run

_LIMITS = (
    "A scan records the supported backend's observed coverage. "
    "It does not establish that the target is secure or that a missing finding is resolved. "
    "Priority is a triage aid, not proof of exploitability."
)
_COLUMNS = ("vulnerability_id", "package", "version", "fixed_version", "ecosystem", "location",
            "severity", "priority", "kev", "epss", "description", "urls")


def _value(value) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, list):
        return "; ".join(str(item) for item in value) or "none"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, allow_nan=False)
    return str(value)


def _markdown(value) -> str:
    encoded = html.escape(_value(value), quote=True).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|\-])", r"\\\1", encoded)


def render_report(run: Run, format: str) -> str:
    if format not in ("json", "md", "html"):
        raise ValueError("Report format must be json, md or html")
    try:
        snapshot = Run.from_dict(run.to_dict()).to_dict()
    except (TypeError, AttributeError) as error:
        raise ValueError("Invalid run") from error
    if format == "json":
        return json.dumps(snapshot, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
    metadata = {key: value for key, value in snapshot.items() if key != "findings"}
    if format == "md":
        lines = ["# VulnTrail evidence report", "", _LIMITS, "", "## Scan record", ""]
        lines.extend(f"- {key}: {_markdown(value)}" for key, value in metadata.items())
        lines.extend(["", "## Findings", ""])
        if not snapshot["findings"]:
            lines.append("No findings were reported in this scan record.")
        else:
            lines.append("| " + " | ".join(_COLUMNS) + " |")
            lines.append("| " + " | ".join("---" for _ in _COLUMNS) + " |")
            for finding in snapshot["findings"]:
                lines.append("| " + " | ".join(_markdown(finding[key]) for key in _COLUMNS) + " |")
        return "\n".join(lines) + "\n"
    def escape(value):
        return html.escape(_value(value), quote=True)
    details = "".join(f"<dt>{key}</dt><dd>{escape(value)}</dd>" for key, value in metadata.items())
    if snapshot["findings"]:
        header = "".join(f"<th scope=\"col\">{key}</th>" for key in _COLUMNS)
        rows = "".join("<tr>" + "".join(f"<td>{escape(finding[key])}</td>" for key in _COLUMNS)
                       + "</tr>" for finding in snapshot["findings"])
        findings = f"<table><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table>"
    else:
        findings = "<p>No findings were reported in this scan record.</p>"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;">'
        '<title>VulnTrail evidence report</title></head><body><main>'
        f"<h1>VulnTrail evidence report</h1><p>{escape(_LIMITS)}</p>"
        f"<h2>Scan record</h2><dl>{details}</dl><h2>Findings</h2>{findings}"
        "</main></body></html>\n"
    )
