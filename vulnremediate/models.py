from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    package: str
    installed_version: str | None
    fixed_version: str | None
    source: str
    severity: str | None = None

    @property
    def artifact_id(self) -> str:
        return self.package.rsplit(":", 1)[-1]


@dataclass(frozen=True)
class Change:
    path: Path
    description: str
    before: str
    after: str

    def audit(self) -> dict[str, str]:
        return {"path": str(self.path), "description": self.description, "before": self.before, "after": self.after}


@dataclass
class RunConfig:
    repo: Path
    apply: bool = False
    push: bool = False
    scan_report: Path | None = None
    config_file: Path | None = None
    docker_images: dict[str, str] = field(default_factory=dict)
    helm_chart_version: str | None = None
    spring_boot_version: str | None = None
    scan_command: str | None = None

    @classmethod
    def from_mapping(cls, repo: Path, mapping: dict[str, Any], **overrides: Any) -> "RunConfig":
        data = {key: value for key, value in mapping.items() if key in cls.__dataclass_fields__}
        data.update(overrides)
        return cls(repo=repo, **data)


def audit_value(value: Any) -> Any:
    if isinstance(value, Change):
        return value.audit()
    if isinstance(value, Finding):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    return value
