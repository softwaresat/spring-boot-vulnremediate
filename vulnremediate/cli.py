from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .graph import build_graph
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
    args = parser.parse_args()
    repo = Path(args.repo).resolve()
    config_path, data = _load_config(repo, args.config)
    config = RunConfig.from_mapping(repo, data, apply=args.apply, push=args.push, scan_report=Path(args.scan_report).resolve() if args.scan_report else None, config_file=config_path)
    state = build_graph().invoke({"config": config, "errors": []})
    audit = {key: [audit_value(item) for item in value] if isinstance(value, list) else audit_value(value) for key, value in state.items() if key != "config"}
    print(json.dumps(audit, indent=2, default=str))
    return 1 if state.get("errors") or not state.get("verification_ok", True) else 0


if __name__ == "__main__":
    raise SystemExit(main())
