from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def _first_string(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, list):
        return next((item for item in value if isinstance(item, str) and item), None)
    return None


def parse_scan_report(path: Path) -> list[Finding]:
    """Read GitHub Dependabot alert exports and Trivy JSON reports."""
    payload = json.loads(path.read_text())
    findings: list[Finding] = []
    # GitHub REST: GET /repos/{owner}/{repo}/dependabot/alerts
    if isinstance(payload, list) and payload and "security_advisory" in payload[0]:
        for alert in payload:
            advisory = alert.get("security_advisory", {})
            vulnerabilities = advisory.get("vulnerabilities", [])
            patched = next(
                (item.get("first_patched_version", {}) or {}).get("identifier")
                for item in vulnerabilities
                if (item.get("first_patched_version") or {}).get("identifier")
            )
            dependency = alert.get("dependency", {})
            package = dependency.get("package", {}).get("name")
            if package:
                findings.append(Finding(package, dependency.get("manifest_path"), patched, path.name, advisory.get("severity")))
        return findings
    # Trivy JSON: Results[].Vulnerabilities[]
    if isinstance(payload, dict) and "Results" in payload:
        for result in payload.get("Results", []):
            for vulnerability in result.get("Vulnerabilities") or []:
                package = vulnerability.get("PkgName")
                if package:
                    findings.append(Finding(
                        package=package,
                        installed_version=vulnerability.get("InstalledVersion"),
                        fixed_version=vulnerability.get("FixedVersion") or None,
                        source=path.name,
                        severity=vulnerability.get("Severity"),
                    ))
        return findings
    if not isinstance(payload, dict):
        return findings
    # Compatibility path for an existing generic dependency-scanning artifact.
    for item in payload.get("vulnerabilities", payload.get("results", [])):
        location = item.get("location", {})
        details = item.get("details", {})
        package = (
            location.get("dependency", {}).get("package", {}).get("name")
            or location.get("package_name")
            or item.get("packageName")
            or item.get("package")
        )
        installed = (
            location.get("dependency", {}).get("version")
            or location.get("version")
            or item.get("installedVersion")
        )
        solution = item.get("solution") or details.get("solution", {}).get("value")
        fixed = (
            _first_string(item.get("fixed_versions"))
            or _first_string(item.get("fixedVersion"))
            or _first_string(item.get("fixed_version"))
        )
        if not fixed and isinstance(solution, str):
            # GitLab commonly reports: "Upgrade foo to version 1.2.3 or above."
            import re
            match = re.search(r"(?:version|to)\s+v?([0-9][\w.+-]*)", solution, re.I)
            fixed = match.group(1) if match else None
        if package:
            findings.append(Finding(
                package=package,
                installed_version=installed,
                fixed_version=fixed,
                source=path.name,
                severity=item.get("severity"),
            ))
    return findings
