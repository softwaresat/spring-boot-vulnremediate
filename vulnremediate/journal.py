"""Durable, local audit records make interrupted remediation runs resumable."""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class RunJournal:
    def __init__(self, repo: Path, run_id: str | None = None) -> None:
        self.run_id = run_id or uuid.uuid4().hex
        self.path = repo / ".vulnremediate" / "runs" / f"{self.run_id}.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, payload: dict[str, Any]) -> None:
        record = {"run_id": self.run_id, "updated_at": datetime.now(UTC).isoformat(), "event": event, **payload}
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(record, indent=2, default=str) + "\n")
        temporary.replace(self.path)
