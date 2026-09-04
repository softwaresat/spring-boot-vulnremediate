from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .graph import build_graph
from .github_api import GitHubApiError
from .models import RunConfig, audit_value


def _load_config(repo: Path, explicit: str | None) -> tuple[Path | None, dict[str, Any]]:
    path = Path(explicit) if explicit else repo / ".vulnremediate.json"
    return (path, json.loads(path.read_text())) if path.exists() else (None, {})


def main() -> int:
    parser = argparse.ArgumentParser(description="LangGraph Maven vulnerability remediation harness")
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--repo", default=".")
    run_parser.add_argument("--scan-report")
    run_parser.add_argument("--config")
    run_parser.add_argument("--apply", action="store_true")
    run_parser.add_argument("--push", action="store_true")
    run_parser.add_argument("--branch", help="Create and push this remediation branch")
    run_parser.add_argument("--github-repository", help="owner/repository; downloads open Dependabot alerts when no report is supplied")
    run_parser.add_argument("--github-token-env", default="GITHUB_TOKEN")
    run_parser.add_argument("--allow-unresolved", action="store_true", help="Do not fail verification when a scanner finding has no safe explicit Maven owner")
    args = parser.parse_args()
    repo = Path(args.repo).resolve()
    config_path, data = _load_config(repo, args.config)
    config = RunConfig.from_mapping(repo, data, apply=args.apply, push=args.push, branch=args.branch, github_repository=args.github_repository, github_token_env=args.github_token_env, fail_on_remaining=not args.allow_unresolved, scan_report=Path(args.scan_report).resolve() if args.scan_report else None, config_file=config_path)
    try:
        state = build_graph().invoke({"config": config, "errors": []})
    except GitHubApiError as error:
        print(json.dumps({"errors": [str(error)]}, indent=2))
        return 2
    audit = {key: [audit_value(item) for item in value] if isinstance(value, list) else audit_value(value) for key, value in state.items() if key != "config"}
    print(json.dumps(audit, indent=2, default=str))
    return 1 if state.get("errors") or not state.get("verification_ok", True) else 0


if __name__ == "__main__":
    raise SystemExit(main())
