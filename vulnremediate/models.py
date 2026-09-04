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
    owner: str = "direct"

    def audit(self) -> dict[str, str]:
        return {"path": str(self.path), "description": self.description, "before": self.before, "after": self.after, "owner": self.owner}


@dataclass(frozen=True)
class RemediationPlan:
    finding: Finding
    change: Change | None
    rationale: str
    blocked_reason: str | None = None


@dataclass(frozen=True)
class AgentDecision:
    action: str
    rationale: str
    evidence_needed: list[str] = field(default_factory=list)
    manual_steps: list[str] = field(default_factory=list)


@dataclass
class RunConfig:
    repo: Path
    apply: bool = False
    push: bool = False
    scan_report: Path | None = None
    config_file: Path | None = None
    docker_images: dict[str, str] = field(default_factory=dict)
    helm_images: dict[str, str] = field(default_factory=dict)
    helm_dependencies: dict[str, str] = field(default_factory=dict)
    helm_chart_version: str | None = None
    spring_boot_version: str | None = None
    scan_command: str | None = None
    github_repository: str | None = None
    github_token_env: str = "GITHUB_TOKEN"
    branch: str | None = None
    fail_on_remaining: bool = True
    agent_model: str | None = None
    agent_api_key_env: str = "OPENAI_API_KEY"
    post_scan_report: Path | None = None
    container_image: str | None = None
    container_build_command: str | None = None
    create_pull_request: bool = False
    pull_request_base: str = "main"
    wait_for_ci: bool = False
    ci_timeout_seconds: int = 600
    run_id: str | None = None

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
    if isinstance(value, RemediationPlan):
        return {"finding": asdict(value.finding), "change": value.change.audit() if value.change else None, "rationale": value.rationale, "blocked_reason": value.blocked_reason}
    if isinstance(value, AgentDecision):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    return value
