"""Validated shared evidence objects; priority is not exploitability."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import uuid

SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
MAX_FINDINGS = 20000

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def text(value: object, name: str, limit: int = 2048, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise ValueError(f"Invalid {name}")
    if any(ord(c) < 32 and c not in "\n\t\r" for c in value):
        raise ValueError(f"Control characters in {name}")
    return value

@dataclass
class Finding:
    vulnerability_id: str
    package: str
    version: str
    ecosystem: str
    severity: str
    fixed_version: str = ""
    location: str = ""
    description: str = ""
    urls: list[str] = field(default_factory=list)
    source: str = "trivy"
    kev: bool = False
    epss: float | None = None

    def __post_init__(self):
        for name in ("vulnerability_id", "package", "version", "ecosystem", "fixed_version",
                     "location", "source"):
            text(getattr(self, name), name, required=name in ("vulnerability_id", "package", "source"))
        text(self.description, "description", 16384)
        if self.severity not in SEVERITIES or type(self.kev) is not bool:
            raise ValueError("Invalid severity or known-exploitation flag")
        if self.epss is not None and (type(self.epss) not in (int, float)
                or not math.isfinite(self.epss) or not 0 <= self.epss <= 1):
            raise ValueError("Invalid EPSS probability")
        if not isinstance(self.urls, list) or len(self.urls) > 32:
            raise ValueError("Invalid references")
        for url in self.urls:
            text(url, "reference")
            if not url.startswith(("https://", "http://")):
                raise ValueError("Reference must be an HTTP(S) URL")

    @property
    def fingerprint(self) -> str:
        identity = [self.source, self.ecosystem, self.location, self.package, self.version,
                    self.vulnerability_id]
        return hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()

    @property
    def priority(self) -> str:
        return "P1" if self.kev else "P2" if self.severity in ("HIGH", "CRITICAL") else "P3"

    def to_dict(self) -> dict:
        return {**asdict(self), "fingerprint": self.fingerprint, "priority": self.priority}

    @classmethod
    def from_dict(cls, value: dict):
        if not isinstance(value, dict):
            raise ValueError("Finding must be an object")
        return cls(**{k: v for k, v in value.items() if k not in ("fingerprint", "priority")})

@dataclass
class Run:
    target: str
    backend: str
    findings: list[Finding] = field(default_factory=list)
    status: str = "complete"
    coverage: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    offline: bool = True
    data_updated_at: str | None = None
    source_digest: str = ""
    backend_version: str = ""
    enrichment: list[dict] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=utc_now)
    completed_at: str = field(default_factory=utc_now)

    def __post_init__(self):
        for name in ("target", "backend", "id", "started_at", "completed_at",
                     "source_digest", "backend_version"):
            text(getattr(self, name), name, required=name in ("target", "backend", "id"))
        if self.status not in ("complete", "partial", "failed") or type(self.offline) is not bool:
            raise ValueError("Invalid run status or offline flag")
        if not isinstance(self.findings, list) or len(self.findings) > MAX_FINDINGS:
            raise ValueError("Too many or invalid findings")
        if any(not isinstance(f, Finding) for f in self.findings):
            raise ValueError("Invalid finding")
        for name in ("coverage", "warnings"):
            values = getattr(self, name)
            if not isinstance(values, list) or len(values) > MAX_FINDINGS:
                raise ValueError(f"Invalid {name}")
            for value in values:
                text(value, name, 4096)
        if self.data_updated_at is not None:
            text(self.data_updated_at, "data_updated_at", 128)
        if not isinstance(self.enrichment, list) or len(self.enrichment) > 16:
            raise ValueError("Invalid feed provenance")
        for record in self.enrichment:
            if not isinstance(record, dict) or set(record) - {"source", "source_date", "sha256",
                    "imported_at", "derived_from"}:
                raise ValueError("Invalid feed provenance record")
            for value in record.values():
                text(value, "feed provenance", 4096)

    def to_dict(self) -> dict:
        value = asdict(self)
        value["findings"] = [f.to_dict() for f in self.findings]
        return value

    @classmethod
    def from_dict(cls, value: dict):
        if not isinstance(value, dict):
            raise ValueError("Run must be an object")
        fields = dict(value)
        fields["findings"] = [Finding.from_dict(f) for f in fields.get("findings", [])]
        return cls(**fields)
