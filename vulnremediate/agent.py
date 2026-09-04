"""Constrained LLM review layer for only the non-deterministic remediation cases."""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

from .models import AgentDecision, RemediationPlan, RunConfig
from .prompts import REVIEW_TEMPLATE, SYSTEM_PROMPT
from .repository import run

ALLOWED_ACTIONS = {"inspect_effective_pom", "inspect_dependency_tree", "manual_review", "no_action"}


def collect_evidence(repo: Path, package: str, actions: list[str]) -> dict[str, str]:
    """Run only fixed, read-only Maven diagnostics requested by the model."""
    evidence: dict[str, str] = {}
    artifact = package.rsplit(":", 1)[-1]
    for action in actions[:2]:
        if action == "inspect_effective_pom":
            result = run(["mvn", "-q", "help:effective-pom", "-Doutput=target/effective-pom.xml"], repo)
            text = (repo / "target" / "effective-pom.xml").read_text() if result.returncode == 0 and (repo / "target" / "effective-pom.xml").exists() else result.stderr
            evidence[action] = text[:12000]
        elif action == "inspect_dependency_tree":
            result = run(["mvn", "-q", "dependency:tree", f"-Dincludes=*:{artifact}"], repo)
            evidence[action] = (result.stdout + result.stderr)[:12000]
    return evidence


def _request_model(config: RunConfig, prompt: str) -> dict:
    key = os.environ.get(config.agent_api_key_env)
    if not key:
        raise RuntimeError(f"{config.agent_api_key_env} is required when --agent-model is set")
    body = {"model": config.agent_model, "input": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}], "text": {"format": {"type": "json_object"}}}
    request = Request("https://api.openai.com/v1/responses", data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=60) as response:
        payload = json.loads(response.read().decode())
    text = payload.get("output_text")
    if not text:
        raise RuntimeError("Model response did not contain output_text")
    return json.loads(text)


def review_blocked_plan(config: RunConfig, plan: RemediationPlan) -> AgentDecision:
    prompt = REVIEW_TEMPLATE.format(finding=json.dumps(plan.finding.__dict__), blocked_reason=plan.blocked_reason, evidence="none")
    raw = _request_model(config, prompt)
    action = raw.get("action", "manual_review")
    needed = [item for item in raw.get("evidence_needed", []) if item in ALLOWED_ACTIONS][:2]
    if action not in ALLOWED_ACTIONS:
        action = "manual_review"
    # The model can request diagnostics, but cannot run them or apply an edit.
    evidence = collect_evidence(config.repo, plan.finding.package, needed)
    if evidence:
        # One bounded follow-up lets the agent interpret deterministic evidence.
        raw = _request_model(config, REVIEW_TEMPLATE.format(
            finding=json.dumps(plan.finding.__dict__),
            blocked_reason=plan.blocked_reason,
            evidence=json.dumps(evidence),
        ))
        action = raw.get("action", "manual_review")
        if action not in ALLOWED_ACTIONS:
            action = "manual_review"
    rationale = str(raw.get("rationale", "No rationale returned"))
    if evidence:
        rationale += f"; deterministic evidence collected: {', '.join(evidence)}"
    return AgentDecision(action, rationale, needed, [str(step) for step in raw.get("manual_steps", [])][:5])
