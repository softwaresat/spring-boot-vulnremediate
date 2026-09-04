"""Small GitHub REST client used by the CLI; no GitHub SDK is required."""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class GitHubApiError(RuntimeError):
    pass


def export_dependabot_alerts(repository: str, output: Path, token_env: str = "GITHUB_TOKEN") -> int:
    """Export all open Dependabot alerts to the JSON format consumed by the graph."""
    token = os.environ.get(token_env)
    if not token:
        raise GitHubApiError(f"{token_env} is required to download Dependabot alerts")
    alerts: list[dict] = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repository}/dependabot/alerts?state=open&per_page=100&page={page}"
        request = Request(url, headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urlopen(request, timeout=30) as response:
                batch = json.loads(response.read().decode())
        except HTTPError as error:
            raise GitHubApiError(f"Unable to retrieve Dependabot alerts ({error.code}): {error.reason}") from error
        alerts.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    output.write_text(json.dumps(alerts, indent=2))
    return len(alerts)
