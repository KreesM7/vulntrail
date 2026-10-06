"""Adapters preserve backend/vendor assertions; they do not perform version matching."""
import hashlib
import json
from pathlib import Path
from .models import Finding, Run, SEVERITIES

def read_json(path: Path, max_bytes: int = 25*1024*1024) -> dict:
    with Path(path).open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("Report exceeds configured byte limit")
    try:
        value = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError("Nonfinite JSON value")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid JSON report") from exc
    if not isinstance(value, dict):
        raise ValueError("Report must be an object")
    return value

def obj(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value

def array(value, name):
    if not isinstance(value, list) or len(value) > 20000:
        raise ValueError(f"Invalid {name} array")
    return value

def string(value, name, required=False):
    if value is None:
        value = ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValueError(f"Invalid {name}")
    return value

def references(value):
    if value is None:
        return []
    return [u for u in array(value, "references") if isinstance(u, str)
            and len(u) <= 2048 and u.startswith(("http://", "https://"))][:32]

def parse_report(payload: dict, backend: str, target: str, offline=True,
                 max_findings=20000) -> Run:
    obj(payload, "report")
    if backend not in ("trivy", "grype") or type(max_findings) is not int or not 1 <= max_findings <= 20000:
        raise ValueError("Unsupported backend or finding limit")
    try:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Invalid report values") from exc
    if len(canonical.encode()) > 100*1024*1024:
        raise ValueError("Report too large")
    run = Run(target, backend, offline=offline,
              source_digest=hashlib.sha256(canonical.encode()).hexdigest())
    found = {}
    def add(finding):
        found[finding.fingerprint] = finding
        if len(found) > max_findings:
            raise ValueError("Report exceeds finding limit")
    if backend == "trivy":
        if type(payload.get("SchemaVersion")) is not int or payload["SchemaVersion"] != 2:
            raise ValueError("Only Trivy SchemaVersion 2 is supported")
        results = array(payload.get("Results") or [], "Results")
        for result in results:
            obj(result, "result")
            location = string(result.get("Target"), "target", required=True)
            ecosystem = string(result.get("Type"), "ecosystem") or "unknown"
            run.coverage.append(f"{ecosystem}:{location}")
            if result.get("Class") == "os-pkgs":
                osdata = obj(payload.get("Metadata", {}).get("OS", {}), "OS")
                ecosystem += ":" + string(osdata.get("Family"), "OS family") + ":" + string(osdata.get("Name"), "OS name")
            vulnerabilities = result.get("Vulnerabilities")
            for item in array(vulnerabilities or [], "Vulnerabilities"):
                obj(item, "vulnerability")
                severity = string(item.get("Severity"), "severity").upper() or "UNKNOWN"
                if severity not in SEVERITIES:
                    raise ValueError("Unknown backend severity")
                add(Finding(string(item.get("VulnerabilityID"), "vulnerability id", True),
                    string(item.get("PkgName"), "package", True),
                    string(item.get("InstalledVersion"), "version"), ecosystem, severity,
                    fixed_version=string(item.get("FixedVersion"), "fixed version"),
                    location=location, description=string(item.get("Description"), "description"),
                    urls=references(item.get("References")), source=backend))
    else:
        matches = array(payload.get("matches"), "matches")
        descriptor = obj(payload.get("descriptor", {}), "descriptor")
        run.backend_version = string(descriptor.get("version"), "backend version")
        source = obj(payload.get("source", {}), "source")
        source_type = string(source.get("type"), "source type") or "unknown"
        distro = payload.get("distro") or {}
        obj(distro, "distribution")
        distro_name = string(distro.get("name"), "distribution name")
        distro_version = string(distro.get("version"), "distribution version")
        if source:
            run.coverage = [f"grype:{source_type}:{target}:{distro_name}:{distro_version}"]
        for match in matches:
            obj(match, "match")
            artifact = obj(match.get("artifact"), "artifact")
            vulnerability = obj(match.get("vulnerability"), "vulnerability")
            locations = array(artifact.get("locations") or [], "locations")
            location = "|".join(string(obj(loc, "location").get("path"), "path") for loc in locations)
            ecosystem = string(artifact.get("type"), "package type") or "unknown"
            if ecosystem in ("deb", "rpm", "apk"):
                ecosystem += f":{distro_name}:{distro_version}"
            fix = obj(vulnerability.get("fix") or {}, "fix")
            versions = array(fix.get("versions") or [], "fix versions")
            severity = string(vulnerability.get("severity"), "severity").upper() or "UNKNOWN"
            add(Finding(string(vulnerability.get("id"), "vulnerability id", True),
                string(artifact.get("name"), "package", True),
                string(artifact.get("version"), "version"), ecosystem, severity,
                fixed_version=", ".join(string(v, "fixed version") for v in versions),
                location=location, description=string(vulnerability.get("description"), "description"),
                urls=references(vulnerability.get("urls")), source=backend))
    run.findings = sorted(found.values(), key=lambda f: (f.priority, f.package, f.vulnerability_id))
    run.coverage = sorted(set(run.coverage))
    run.warnings.append("Database update time is unknown; import time is not database freshness.")
    if not run.coverage:
        run.status = "partial"
        run.warnings.append("No assessable coverage was declared; zero findings is not a clean scan.")
    return run
