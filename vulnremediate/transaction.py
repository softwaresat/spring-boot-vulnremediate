"""Recoverable file transaction for changes made before verification succeeds."""
from __future__ import annotations

import json
from pathlib import Path

from .models import Change


class ChangeTransaction:
    def __init__(self, repo: Path, run_id: str) -> None:
        self.path = repo / ".vulnremediate" / "transactions" / f"{run_id}.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def snapshot(self, changes: list[Change]) -> None:
        content = {str(path): path.read_text() for path in {change.path for change in changes}}
        self.path.write_text(json.dumps(content, indent=2))

    def rollback(self) -> None:
        if not self.path.exists():
            return
        for raw_path, content in json.loads(self.path.read_text()).items():
            Path(raw_path).write_text(content)

    def commit(self) -> None:
        self.path.unlink(missing_ok=True)
