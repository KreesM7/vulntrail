"""Fail-closed local configuration. No executable commands accepted over HTTP."""

from dataclasses import dataclass, field, fields
from pathlib import Path
import re
import yaml


@dataclass
class Settings:
    state_dir: Path = field(default_factory=lambda: Path(".vulntrail"))
    targets: dict[str, Path] = field(default_factory=dict)
    trivy_path: str = "trivy"
    cache_dir: Path | None = None
    offline: bool = True
    timeout_seconds: int = 300
    max_report_bytes: int = 25 * 1024 * 1024
    max_findings: int = 20000
    interval_seconds: int = 3600
    max_data_age_days: int = 7

    def __post_init__(self):
        if type(self.offline) is not bool:
            raise ValueError("offline must be a boolean")
        for name, maximum in (
            ("timeout_seconds", 3600),
            ("max_report_bytes", 100 * 1024 * 1024),
            ("max_findings", 20000),
            ("interval_seconds", 86400),
            ("max_data_age_days", 3650),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"Invalid {name}")
        if not isinstance(self.targets, dict) or len(self.targets) > 100:
            raise ValueError("targets must be a map of at most 100 local targets")
        resolved = {}
        for name, path in self.targets.items():
            if not isinstance(name, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name
            ):
                raise ValueError("Invalid target name")
            raw = str(path)
            if "://" in raw or raw.startswith(("\\\\", "//")) or "\x00" in raw:
                raise ValueError("Only local filesystem targets are supported")
            if not isinstance(path, (str, Path)):
                raise ValueError("Target paths must be strings or local paths")
            local = Path(path).expanduser().resolve()
            if str(local).startswith(("\\\\", "//")):
                raise ValueError("Resolved network targets are unsupported")
            resolved[name] = local
        self.targets = resolved
        self.state_dir = Path(self.state_dir).expanduser().resolve()
        self.cache_dir = Path(self.cache_dir or self.state_dir / "cache").expanduser().resolve()
        if (
            not isinstance(self.trivy_path, str)
            or not self.trivy_path.strip()
            or "\x00" in self.trivy_path
        ):
            raise ValueError("Invalid Trivy executable")
        if Path(self.trivy_path).suffix.lower() in (".cmd", ".bat", ".ps1", ".sh"):
            raise ValueError("Configure a trusted executable, not a shell script")


def load_settings(path: Path | None = None) -> Settings:
    if path is None:
        candidate = Path("config.yaml")
        if not candidate.exists():
            return Settings()
        path = candidate
    path = Path(path).resolve()
    if path.stat().st_size > 65536:
        raise ValueError("Config exceeds 64 KiB")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeError) as exc:
        raise ValueError("Invalid YAML configuration") from exc
    if not isinstance(data, dict):
        raise ValueError("Config must be a mapping")
    allowed = {f.name for f in fields(Settings)}
    if set(data) - allowed:
        raise ValueError("Unknown configuration keys")
    values = dict(data)
    targets = values.get("targets", {})
    if not isinstance(targets, dict):
        raise ValueError("targets must be a mapping")

    def relative(value):
        if not isinstance(value, str) or not value:
            raise ValueError("Paths must be nonempty strings")
        if "://" in value or value.startswith(("\\\\", "//")) or "\x00" in value:
            raise ValueError("Only local paths are supported")
        p = Path(value).expanduser()
        return p if p.is_absolute() else path.parent / p

    values["targets"] = {name: relative(value) for name, value in targets.items()}
    for name in ("state_dir", "cache_dir"):
        if name in values:
            values[name] = relative(values[name])
    if "trivy_path" in values:
        if not isinstance(values["trivy_path"], str):
            raise ValueError("trivy_path must be a string")
        if "/" in values["trivy_path"] or "\\" in values["trivy_path"]:
            values["trivy_path"] = str(relative(values["trivy_path"]))
    return Settings(**values)
