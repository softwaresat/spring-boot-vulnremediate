from __future__ import annotations

from .models import Finding


def fingerprint(finding: Finding) -> tuple[str, str | None]:
    return finding.package, finding.installed_version


def remaining(before: list[Finding], after: list[Finding]) -> list[Finding]:
    """Return only vulnerabilities still present after a remediation pass."""
    before_keys = {fingerprint(item) for item in before}
    return [item for item in after if fingerprint(item) in before_keys]
