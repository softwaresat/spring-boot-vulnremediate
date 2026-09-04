"""Small GitHub REST client used by the CLI; no GitHub SDK is required."""
from __future__ import annotations

import json
import os
import time
import zipfile
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class GitHubApiError(RuntimeError):
    pass


class GitHubClient:
    """Minimal authenticated REST client for alerts, PRs, CI, and artifacts."""
    def __init__(self, token_env: str = "GITHUB_TOKEN") -> None:
        token = os.environ.get(token_env)
        if not token:
            raise GitHubApiError(f"{token_env} is required for GitHub integration")
        self.token = token

    def request(self, method: str, path: str, payload: dict | None = None, binary: bool = False):
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(f"https://api.github.com{path}", data=data, headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"}, method=method)
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except (HTTPError, URLError) as error:
            reason = getattr(error, "reason", str(error))
            code = getattr(error, "code", "network")
            raise GitHubApiError(f"GitHub {method} {path} failed ({code}): {reason}") from error
        return raw if binary else json.loads(raw.decode()) if raw else {}

    def dependabot_alerts(self, repository: str) -> list[dict]:
        alerts: list[dict] = []
        page = 1
        while True:
            batch = self.request("GET", f"/repos/{repository}/dependabot/alerts?state=open&per_page=100&page={page}")
            alerts.extend(batch)
            if len(batch) < 100:
                return alerts
            page += 1

    def create_pull_request(self, repository: str, branch: str, base: str, title: str, body: str) -> str:
        response = self.request("POST", f"/repos/{repository}/pulls", {"title": title, "head": branch, "base": base, "body": body})
        return response["html_url"]

    def wait_for_ci(self, repository: str, branch: str, timeout_seconds: int) -> dict:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            runs = self.request("GET", f"/repos/{repository}/actions/runs?branch={branch}&per_page=1").get("workflow_runs", [])
            if runs:
                run = runs[0]
                if run.get("status") == "completed":
                    return run
            time.sleep(5)
        raise GitHubApiError(f"Timed out waiting for GitHub Actions on {branch}")

    def download_artifact_json(self, repository: str, run_id: int, artifact_name: str, output: Path) -> Path:
        artifacts = self.request("GET", f"/repos/{repository}/actions/runs/{run_id}/artifacts").get("artifacts", [])
        artifact = next((item for item in artifacts if item.get("name") == artifact_name and not item.get("expired")), None)
        if not artifact:
            raise GitHubApiError(f"Artifact {artifact_name!r} not found for workflow run {run_id}")
        raw = self.request("GET", f"/repos/{repository}/actions/artifacts/{artifact['id']}/zip", binary=True)
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            candidates = [name for name in archive.namelist() if name.endswith(".json")]
            if not candidates:
                raise GitHubApiError(f"Artifact {artifact_name!r} contains no JSON report")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(archive.read(candidates[0]))
        return output


def export_dependabot_alerts(repository: str, output: Path, token_env: str = "GITHUB_TOKEN") -> int:
    """Export all open Dependabot alerts to the JSON format consumed by the graph."""
    alerts = GitHubClient(token_env).dependabot_alerts(repository)
    output.write_text(json.dumps(alerts, indent=2))
    return len(alerts)
