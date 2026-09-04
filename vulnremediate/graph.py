"""The end-to-end LangGraph lifecycle for Spring Boot vulnerability remediation."""
from __future__ import annotations

import subprocess
import json
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from .agent import review_blocked_plan
from .diffing import remaining
from .github_api import GitHubClient, export_dependabot_alerts
from .journal import RunJournal
from .models import AgentDecision, Change, Finding, RemediationPlan, RunConfig
from .repository import apply_baseline_change, apply_maven_change, baseline_changes, is_spring_boot_application, parent_first_plan, pom_files, run
from .scans import parse_scan_report
from .transaction import ChangeTransaction


class RemediationState(TypedDict, total=False):
    config: RunConfig
    findings_before: list[Finding]
    findings_after: list[Finding]
    remaining_findings: list[Finding]
    baseline_changes: list[Change]
    maven_changes: list[Change]
    plans: list[RemediationPlan]
    agent_decisions: list[AgentDecision]
    commands: list[dict[str, Any]]
    publication: dict[str, Any]
    ci: dict[str, Any]
    verification_ok: bool
    errors: list[str]
    journal_path: str
    transaction_path: str


def _journal(state: RemediationState, event: str, **payload: Any) -> None:
    journal = RunJournal(state["config"].repo, state["config"].run_id)
    journal.write(event, payload)


def discover(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    if not pom_files(config.repo):
        return {"errors": ["No pom.xml found; this harness targets Spring Boot Maven applications."]}
    if not is_spring_boot_application(config.repo):
        return {"errors": ["No Spring Boot parent, BOM, or starter dependency found; refusing an unsupported application."]}
    journal = RunJournal(config.repo, config.run_id)
    config.run_id = journal.run_id
    journal.write("discovered", {"repo": str(config.repo), "apply": config.apply})
    return {"commands": [], "journal_path": str(journal.path)}


def acquire_before(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    report = config.scan_report
    if not report and config.github_repository:
        report = config.repo / "target" / "vulnremediate" / "dependabot-before.json"
        export_dependabot_alerts(config.github_repository, report, config.github_token_env)
    findings = parse_scan_report(report) if report and report.exists() else []
    _journal(state, "scan_before", findings=len(findings), report=str(report) if report else None)
    return {"findings_before": findings}


def harden_baselines(state: RemediationState) -> dict[str, Any]:
    changes = baseline_changes(state["config"])
    _journal(state, "baseline_planned", changes=[item.audit() for item in changes])
    return {"baseline_changes": changes}


def plan_parent_first(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    completed = run(["mvn", "-q", "help:effective-pom", "-Doutput=target/effective-pom.xml"], config.repo)
    command = {"command": "mvn -q help:effective-pom -Doutput=target/effective-pom.xml", "exit_code": completed.returncode}
    plans = parent_first_plan(config.repo, state.get("findings_before", []))
    _journal(state, "planned", actionable=sum(plan.change is not None for plan in plans), blocked=sum(plan.blocked_reason is not None for plan in plans))
    return {"plans": plans, "maven_changes": [plan.change for plan in plans if plan.change], "commands": state.get("commands", []) + [command]}


def agent_review(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    if not config.agent_model:
        return {"agent_decisions": []}
    decisions = [review_blocked_plan(config, plan) for plan in state.get("plans", []) if plan.blocked_reason]
    _journal(state, "agent_review", decisions=[decision.__dict__ for decision in decisions])
    return {"agent_decisions": decisions}


def apply_plan(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    if config.apply:
        transaction = ChangeTransaction(config.repo, config.run_id or "unknown")
        changes = state.get("baseline_changes", []) + state.get("maven_changes", [])
        transaction.snapshot(changes)
        for change in state.get("baseline_changes", []):
            apply_baseline_change(change)
        for change in state.get("maven_changes", []):
            apply_maven_change(change)
        return {"transaction_path": str(transaction.path)}
    _journal(state, "changes_applied", count=len(state.get("baseline_changes", [])) + len(state.get("maven_changes", [])))
    return {}


def verify(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    if not config.apply:
        return {"verification_ok": True}
    commands = state.get("commands", [])
    if config.container_build_command:
        built = subprocess.run(config.container_build_command, cwd=config.repo, shell=True, text=True, capture_output=True, check=False)
        commands.append({"command": config.container_build_command, "exit_code": built.returncode})
        if built.returncode:
            ChangeTransaction(config.repo, config.run_id or "unknown").rollback()
            return {"verification_ok": False, "commands": commands}
    verified = run(["mvn", "-B", "verify"], config.repo)
    commands.append({"command": "mvn -B verify", "exit_code": verified.returncode})
    if verified.returncode:
        ChangeTransaction(config.repo, config.run_id or "unknown").rollback()
        return {"verification_ok": False, "commands": commands}
    if config.scan_command:
        post = config.post_scan_report or config.repo / "target" / "vulnremediate" / "post-scan.json"
        post.parent.mkdir(parents=True, exist_ok=True)
        command = config.scan_command.format(report=str(post), image=config.container_image or "")
        scanned = subprocess.run(command, cwd=config.repo, shell=True, text=True, capture_output=True, check=False)
        commands.append({"command": command, "exit_code": scanned.returncode})
        if scanned.returncode:
            ChangeTransaction(config.repo, config.run_id or "unknown").rollback()
            return {"verification_ok": False, "commands": commands}
    _journal(state, "verified", commands=commands)
    return {"verification_ok": True, "commands": commands}


def acquire_after(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    report = config.post_scan_report or config.repo / "target" / "vulnremediate" / "post-scan.json"
    if config.apply and config.github_repository and config.wait_for_ci:
        # GitHub artifact retrieval happens after publication; this node intentionally
        # preserves local scans as the immediate comparison source.
        pass
    findings = parse_scan_report(report) if report.exists() else []
    return {"findings_after": findings}


def compare_scans(state: RemediationState) -> dict[str, Any]:
    after = state.get("findings_after", [])
    before = state.get("findings_before", [])
    still_open = remaining(before, after) if after else []
    blocked = [plan for plan in state.get("plans", []) if plan.blocked_reason]
    ok = state.get("verification_ok", False) and (not state["config"].apply or not state["config"].fail_on_remaining or not still_open and not blocked)
    if state["config"].apply and not ok:
        ChangeTransaction(state["config"].repo, state["config"].run_id or "unknown").rollback()
    _journal(state, "compared", before=len(before), after=len(after), remaining=len(still_open), blocked=len(blocked))
    return {"remaining_findings": still_open, "verification_ok": ok}


def publish(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    if not (config.apply and config.push and state.get("verification_ok")):
        if config.apply and state.get("verification_ok"):
            ChangeTransaction(config.repo, config.run_id or "unknown").commit()
        return {"publication": {"status": "not_requested"}}
    if not config.branch:
        return {"errors": state.get("errors", []) + ["--branch is required with --push"]}
    branch = run(["git", "switch", "-c", config.branch], config.repo)
    if branch.returncode:
        return {"errors": state.get("errors", []) + [f"Could not create branch {config.branch}"]}
    for command in (["git", "add", "-A"], ["git", "commit", "-m", "chore: remediate Spring Boot vulnerabilities"], ["git", "push", "--set-upstream", "origin", config.branch]):
        completed = run(command, config.repo)
        if completed.returncode:
            return {"errors": state.get("errors", []) + [f"Git command failed: {' '.join(command)}"]}
    publication: dict[str, Any] = {"status": "pushed", "branch": config.branch}
    if config.github_repository and config.create_pull_request:
        client = GitHubClient(config.github_token_env)
        publication["pull_request"] = client.create_pull_request(config.github_repository, config.branch, config.pull_request_base, "chore: remediate Spring Boot vulnerabilities", "Automated parent-first remediation. Review the attached run audit and GitHub security results.")
    _journal(state, "published", **publication)
    ChangeTransaction(config.repo, config.run_id or "unknown").commit()
    return {"publication": publication}


def collect_github_ci(state: RemediationState) -> dict[str, Any]:
    config = state["config"]
    publication = state.get("publication", {})
    if not (config.wait_for_ci and publication.get("status") == "pushed" and config.github_repository and config.branch):
        return {"ci": {"status": "not_requested"}}
    client = GitHubClient(config.github_token_env)
    workflow = client.wait_for_ci(config.github_repository, config.branch, config.ci_timeout_seconds)
    ci = {"status": workflow.get("conclusion"), "run_id": workflow.get("id"), "url": workflow.get("html_url")}
    if workflow.get("conclusion") != "success":
        return {"ci": ci, "verification_ok": False}
    report = config.repo / "target" / "vulnremediate" / "github-trivy.json"
    try:
        client.download_artifact_json(config.github_repository, int(workflow["id"]), "trivy-results", report)
        after = parse_scan_report(report)
        # Re-fetch Dependabot after the branch workflow. This verifies both the
        # container/FS scan and GitHub's Maven advisory state.
        dependabot_report = config.repo / "target" / "vulnremediate" / "dependabot-after.json"
        dependabot_report.write_text(json.dumps(client.dependabot_alerts(config.github_repository)))
        after.extend(parse_scan_report(dependabot_report))
        still_open = remaining(state.get("findings_before", []), after)
        ci["artifact"] = str(report)
        return {"ci": ci, "findings_after": after, "remaining_findings": still_open, "verification_ok": not (config.fail_on_remaining and still_open)}
    except GitHubApiError as error:
        # A workflow without an artifact is a failed contract, not a silent pass.
        return {"ci": {**ci, "artifact_error": str(error)}, "verification_ok": False}


def build_graph():
    graph = StateGraph(RemediationState)
    graph.add_node("discover", discover)
    graph.add_node("acquire_before", acquire_before)
    graph.add_node("harden_baselines", harden_baselines)
    graph.add_node("plan_parent_first", plan_parent_first)
    graph.add_node("agent_review", agent_review)
    graph.add_node("apply_plan", apply_plan)
    graph.add_node("verify", verify)
    graph.add_node("acquire_after", acquire_after)
    graph.add_node("compare_scans", compare_scans)
    graph.add_node("publish", publish)
    graph.add_node("collect_github_ci", collect_github_ci)
    graph.add_edge(START, "discover")
    graph.add_conditional_edges("discover", lambda state: END if state.get("errors") else "acquire_before")
    graph.add_edge("acquire_before", "harden_baselines")
    graph.add_edge("harden_baselines", "plan_parent_first")
    graph.add_edge("plan_parent_first", "agent_review")
    graph.add_edge("agent_review", "apply_plan")
    graph.add_edge("apply_plan", "verify")
    graph.add_edge("verify", "acquire_after")
    graph.add_edge("acquire_after", "compare_scans")
    graph.add_edge("compare_scans", "publish")
    graph.add_edge("publish", "collect_github_ci")
    graph.add_edge("collect_github_ci", END)
    return graph.compile()
