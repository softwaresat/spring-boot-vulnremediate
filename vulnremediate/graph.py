from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from .models import Change, RunConfig
from .repository import apply_baseline_change, apply_maven_change, baseline_changes, is_spring_boot_application, parent_first_changes, pom_files, run
from .scans import parse_scan_report


class RemediationState(TypedDict, total=False):
    config: RunConfig
    findings: list[Any]
    baseline_changes: list[Change]
    maven_changes: list[Change]
    commands: list[dict[str, Any]]
    verification_ok: bool
    errors: list[str]


def discover(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    if not pom_files(config.repo):
        return {"errors": ["No pom.xml found; this harness targets Spring Boot Maven applications."]}
    if not is_spring_boot_application(config.repo):
        return {"errors": ["No Spring Boot parent, BOM, or starter dependency found; refusing to remediate an unsupported application."]}
    return {"commands": []}


def harden_baselines(state: RemediationState) -> dict[str, Any]:
    changes = baseline_changes(state["config"])
    if state["config"].apply:
        for change in changes:
            apply_baseline_change(change)
    return {"baseline_changes": changes}


def ingest_scan(state: RemediationState) -> dict[str, Any]:
    report = state["config"].scan_report
    return {"findings": parse_scan_report(report) if report else []}


def plan_parent_first(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    # Effective POM provides evidence of inherited dependency management; errors are non-fatal.
    completed = run(["mvn", "-q", "help:effective-pom", "-Doutput=target/effective-pom.xml"], config.repo)
    command = {"command": "mvn -q help:effective-pom -Doutput=target/effective-pom.xml", "exit_code": completed.returncode}
    return {"maven_changes": parent_first_changes(config.repo, state.get("findings", [])), "commands": state.get("commands", []) + [command]}


def apply_plan(state: RemediationState) -> dict[str, Any]:
    if state["config"].apply:
        for change in state.get("maven_changes", []):
            apply_maven_change(change)
    return {}


def verify(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    if not config.apply:
        return {"verification_ok": True}
    completed = run(["mvn", "-B", "verify"], config.repo)
    commands = state.get("commands", []) + [{"command": "mvn -B verify", "exit_code": completed.returncode}]
    ok = completed.returncode == 0
    if ok and config.scan_command:
        command = config.scan_command.format(report=str(config.scan_report or "scan-report.json"))
        scanned = subprocess.run(command, cwd=config.repo, shell=True, text=True, capture_output=True, check=False)
        commands.append({"command": command, "exit_code": scanned.returncode})
        ok = scanned.returncode == 0
    return {"verification_ok": ok, "commands": commands}


def commit_and_push(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    if not (config.push and config.apply and state.get("verification_ok")):
        return {}
    dirty = run(["git", "status", "--porcelain"], config.repo)
    if not dirty.stdout.strip():
        return {}
    for command in (["git", "add", "-A"], ["git", "commit", "-m", "chore: remediate dependency vulnerabilities"], ["git", "push"]):
        completed = run(command, config.repo)
        if completed.returncode:
            return {"errors": state.get("errors", []) + [f"Git command failed: {' '.join(command)}"]}
    return {}


def build_graph():
    graph = StateGraph(RemediationState)
    graph.add_node("discover", discover)
    graph.add_node("harden_baselines", harden_baselines)
    graph.add_node("ingest_scan", ingest_scan)
    graph.add_node("plan_parent_first", plan_parent_first)
    graph.add_node("apply_plan", apply_plan)
    graph.add_node("verify", verify)
    graph.add_node("commit_and_push", commit_and_push)
    graph.add_edge(START, "discover")
    graph.add_conditional_edges("discover", lambda state: END if state.get("errors") else "harden_baselines")
    graph.add_edge("harden_baselines", "ingest_scan")
    graph.add_edge("ingest_scan", "plan_parent_first")
    graph.add_edge("plan_parent_first", "apply_plan")
    graph.add_edge("apply_plan", "verify")
    graph.add_edge("verify", "commit_and_push")
    graph.add_edge("commit_and_push", END)
    return graph.compile()
