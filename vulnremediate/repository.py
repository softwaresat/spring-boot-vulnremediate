from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .models import Change, Finding, RunConfig


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


def pom_files(repo: Path) -> list[Path]:
    return sorted(repo.rglob("pom.xml"))


def is_spring_boot_application(repo: Path) -> bool:
    """Detect the supported Spring Boot Maven application shapes."""
    markers = ("spring-boot-starter-parent", "spring-boot-dependencies", "spring-boot-starter-")
    return any(any(marker in pom.read_text() for marker in markers) for pom in pom_files(repo))


def parent_first_changes(repo: Path, findings: list[Finding]) -> list[Change]:
    """Plan only scanner-supported changes, preferring parent/BOM management entries."""
    changes: list[Change] = []
    for finding in findings:
        if not finding.fixed_version:
            continue
        needle = re.escape(finding.artifact_id)
        chosen: Change | None = None
        # Root pom first; an explicit dependency-management declaration is the owner.
        candidates = sorted(pom_files(repo), key=lambda p: (p != repo / "pom.xml", len(p.parts)))
        for pom in candidates:
            text = pom.read_text()
            # A Spring Boot CVE should first be remediated at the Boot parent.
            # This keeps the Boot-managed dependency set coherent.
            if finding.package.startswith("org.springframework.boot:"):
                boot_parent = re.search(
                    r"(<artifactId>spring-boot-starter-parent</artifactId>\s*<version>\s*)([^<]+)(\s*</version>)",
                    text,
                )
                if boot_parent and boot_parent.group(2).strip() != finding.fixed_version:
                    changes.append(Change(pom, "Update Spring Boot parent from scanner recommendation", boot_parent.group(2).strip(), finding.fixed_version))
                    break
            dependency = re.compile(
                rf"(<dependency>.*?<artifactId>\s*{needle}\s*</artifactId>.*?<version>\s*)([^<]+)(\s*</version>)",
                re.S,
            )
            match = dependency.search(text)
            if not match:
                continue
            before = match.group(2).strip()
            if before == finding.fixed_version:
                continue
            candidate = Change(pom, f"Parent-first Maven upgrade for {finding.package}", before, finding.fixed_version)
            # A dependencyManagement location is an explicit owner and wins immediately.
            management_start = text.rfind("<dependencyManagement>", 0, match.start())
            management_end = text.rfind("</dependencyManagement>", 0, match.start())
            if management_start > management_end:
                chosen = candidate
                break
            if chosen is None:
                chosen = candidate
        if chosen:
            changes.append(chosen)
    return changes


def apply_maven_change(change: Change) -> None:
    text = change.path.read_text()
    # Limit replacement to the artifact's declaration by matching old version once.
    escaped = re.escape(change.before)
    updated, count = re.subn(rf"(<version>\s*){escaped}(\s*</version>)", rf"\g<1>{change.after}\g<2>", text, count=1)
    if count != 1:
        raise RuntimeError(f"Could not safely apply planned change to {change.path}")
    change.path.write_text(updated)


def baseline_changes(config: RunConfig) -> list[Change]:
    changes: list[Change] = []
    for dockerfile in config.repo.rglob("Dockerfile*"):
        text = dockerfile.read_text()
        for image, new_tag in config.docker_images.items():
            match = re.search(rf"(?m)^FROM\s+({re.escape(image)}):([^\s@]+)", text)
            if match and match.group(2) != new_tag:
                changes.append(Change(dockerfile, f"Update Docker base image {image}", match.group(2), new_tag))
    if config.helm_chart_version:
        for chart in config.repo.rglob("Chart.yaml"):
            text = chart.read_text()
            match = re.search(r"(?m)^version:\s*([^\s#]+)", text)
            if match and match.group(1) != config.helm_chart_version:
                changes.append(Change(chart, "Update Helm chart version", match.group(1), config.helm_chart_version))
    if config.spring_boot_version:
        for pom in pom_files(config.repo):
            text = pom.read_text()
            match = re.search(r"(<artifactId>spring-boot-starter-parent</artifactId>\s*<version>\s*)([^<]+)", text)
            if match and match.group(2).strip() != config.spring_boot_version:
                changes.append(Change(pom, "Update Spring Boot parent", match.group(2).strip(), config.spring_boot_version))
    return changes


def apply_baseline_change(change: Change) -> None:
    text = change.path.read_text()
    updated = text.replace(change.before, change.after, 1)
    if updated == text:
        raise RuntimeError(f"Could not apply baseline change to {change.path}")
    change.path.write_text(updated)
