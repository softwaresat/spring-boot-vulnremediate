from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from .github_api import export_dependabot_alerts
from .models import Change, RemediationPlan, RunConfig
from .repository import apply_baseline_change, apply_maven_change, baseline_changes, is_spring_boot_application, parent_first_plan, pom_files, run
from .scans import parse_scan_report


class RemediationState(TypedDict, total=False):
    config: RunConfig
    findings: list[Any]
    baseline_changes: list[Change]
    maven_changes: list[Change]
    plans: list[RemediationPlan]
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
    config = state["config"]
    report = config.scan_report
    if not report and config.github_repository:
        report = config.repo / "target" / "dependabot-alerts.json"
        report.parent.mkdir(exist_ok=True)
        export_dependabot_alerts(config.github_repository, report, config.github_token_env)
    return {"findings": parse_scan_report(report) if report else []}


def plan_parent_first(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    # Effective POM provides evidence of inherited dependency management; errors are non-fatal.
    completed = run(["mvn", "-q", "help:effective-pom", "-Doutput=target/effective-pom.xml"], config.repo)
    command = {"command": "mvn -q help:effective-pom -Doutput=target/effective-pom.xml", "exit_code": completed.returncode}
    plans = parent_first_plan(config.repo, state.get("findings", []))
    return {"plans": plans, "maven_changes": [plan.change for plan in plans if plan.change], "commands": state.get("commands", []) + [command]}


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
    blocked = [plan for plan in state.get("plans", []) if plan.blocked_reason]
    if config.fail_on_remaining and blocked:
        ok = False
    return {"verification_ok": ok, "commands": commands}


def commit_and_push(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    if not (config.push and config.apply and state.get("verification_ok")):
        return {}
    if config.branch:
        branch = run(["git", "switch", "-c", config.branch], config.repo)
        if branch.returncode:
            return {"errors": state.get("errors", []) + [f"Could not create branch {config.branch}"]}
    dirty = run(["git", "status", "--porcelain"], config.repo)
    if not dirty.stdout.strip():
        return {}
    push_command = ["git", "push", "--set-upstream", "origin", config.branch] if config.branch else ["git", "push"]
    for command in (["git", "add", "-A"], ["git", "commit", "-m", "chore: remediate Spring Boot vulnerabilities"], push_command):
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
