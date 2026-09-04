"""Operator CLI for the Spring Boot remediation harness."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .github_api import GitHubApiError, export_dependabot_alerts
from .models import RunConfig, audit_value

EXAMPLE_CONFIG = {
    "docker_images": {"eclipse-temurin": "21-jre"},
    "helm_chart_version": "1.2.3",
    "spring_boot_version": "3.3.12",
    "scan_command": "trivy fs --format json --output trivy-results.json .",
}


def _load_config(repo: Path, explicit: str | None) -> tuple[Path | None, dict[str, Any]]:
    path = Path(explicit).resolve() if explicit else repo / ".vulnremediate.json"
    return (path, json.loads(path.read_text())) if path.exists() else (None, {})


def _add_execution_options(parser: argparse.ArgumentParser, allow_apply: bool) -> None:
    parser.add_argument("--repo", default=".", help="Spring Boot Maven repository")
    parser.add_argument("--config", help="Path to .vulnremediate.json")
    parser.add_argument("--scan-report", help="Dependabot or Trivy JSON report")
    parser.add_argument("--github-repository", help="owner/repository; exports open Dependabot alerts if no report is supplied")
    parser.add_argument("--github-token-env", default="GITHUB_TOKEN")
    parser.add_argument("--agent-model", help="Optional model ID for constrained review of blocked plans")
    parser.add_argument("--agent-api-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--allow-unresolved", action="store_true")
    if allow_apply:
        parser.add_argument("--apply", action="store_true", help="Write planned changes")
        parser.add_argument("--push", action="store_true", help="Commit and push after verification")
        parser.add_argument("--branch", help="Create this branch before committing; requires --push")
        parser.add_argument("--post-scan-report", help="Path written by the post-remediation scanner")
        parser.add_argument("--container-image", help="Image reference passed to scan_command as {image}")
        parser.add_argument("--container-build-command", help="Build command run before Maven verification")
        parser.add_argument("--create-pull-request", action="store_true")
        parser.add_argument("--pull-request-base", default="main")
        parser.add_argument("--wait-for-ci", action="store_true")
        parser.add_argument("--ci-timeout-seconds", type=int, default=600)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnremediate", description="LangGraph remediation harness for Spring Boot Maven applications")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create a reviewed configuration template")
    init.add_argument("--repo", default=".")
    init.add_argument("--force", action="store_true")
    alerts = sub.add_parser("export-dependabot", help="Export open GitHub Dependabot alerts to JSON")
    alerts.add_argument("--github-repository", required=True)
    alerts.add_argument("--output", default="dependabot-alerts.json")
    alerts.add_argument("--github-token-env", default="GITHUB_TOKEN")
    plan = sub.add_parser("plan", help="Print a non-mutating remediation plan")
    _add_execution_options(plan, False)
    remediate = sub.add_parser("remediate", help="Plan, apply, verify, and optionally publish")
    _add_execution_options(remediate, True)
    run = sub.add_parser("run", help="Compatibility alias for remediate")
    _add_execution_options(run, True)
    return parser


def _emit(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def _run_graph(args: argparse.Namespace, apply: bool) -> int:
    repo = Path(args.repo).resolve()
    config_path, data = _load_config(repo, args.config)
    config = RunConfig.from_mapping(repo, data, apply=apply, push=getattr(args, "push", False), branch=getattr(args, "branch", None), github_repository=args.github_repository, github_token_env=args.github_token_env, agent_model=args.agent_model, agent_api_key_env=args.agent_api_key_env, fail_on_remaining=not args.allow_unresolved, scan_report=Path(args.scan_report).resolve() if args.scan_report else None, post_scan_report=Path(args.post_scan_report).resolve() if getattr(args, "post_scan_report", None) else None, container_image=getattr(args, "container_image", None), container_build_command=getattr(args, "container_build_command", None), create_pull_request=getattr(args, "create_pull_request", False), pull_request_base=getattr(args, "pull_request_base", "main"), wait_for_ci=getattr(args, "wait_for_ci", False), ci_timeout_seconds=getattr(args, "ci_timeout_seconds", 600), config_file=config_path)
    try:
        from .graph import build_graph
        state = build_graph().invoke({"config": config, "errors": []})
    except (GitHubApiError, RuntimeError) as error:
        _emit({"errors": [str(error)]})
        return 2
    audit = {key: [audit_value(item) for item in value] if isinstance(value, list) else audit_value(value) for key, value in state.items() if key != "config"}
    _emit(audit)
    return 1 if state.get("errors") or not state.get("verification_ok", True) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init":
        path = Path(args.repo).resolve() / ".vulnremediate.json"
        if path.exists() and not args.force:
            _emit({"error": f"{path} already exists; use --force to replace it"})
            return 2
        path.write_text(json.dumps(EXAMPLE_CONFIG, indent=2) + "\n")
        _emit({"created": str(path)})
        return 0
    if args.command == "export-dependabot":
        try:
            count = export_dependabot_alerts(args.github_repository, Path(args.output).resolve(), args.github_token_env)
        except GitHubApiError as error:
            _emit({"errors": [str(error)]})
            return 2
        _emit({"repository": args.github_repository, "alerts": count, "output": str(Path(args.output).resolve())})
        return 0
    return _run_graph(args, apply=args.command in {"remediate", "run"} and args.apply)


if __name__ == "__main__":
    raise SystemExit(main())
