import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from vulnremediate.diffing import remaining
from vulnremediate.github_api import GitHubClient
from vulnremediate.models import Finding


class FakeGitHub(GitHubClient):
    def __init__(self):
        self.calls = []
    def request(self, method, path, payload=None, binary=False):
        self.calls.append((method, path, payload, binary))
        if "dependabot/alerts" in path:
            return [{"number": 1}] if "page=1" in path else []
        if path.endswith("/artifacts"):
            return {"artifacts": [{"id": 4, "name": "trivy-results", "expired": False}]}
        if path.endswith("/zip"):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("trivy-results.json", json.dumps({"Results": []}))
            return buffer.getvalue()
        return {}


class LifecycleTests(unittest.TestCase):
    def test_dependabot_pagination(self):
        client = FakeGitHub()
        self.assertEqual(client.dependabot_alerts("owner/repo"), [{"number": 1}])

    def test_downloads_json_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            FakeGitHub().download_artifact_json("owner/repo", 9, "trivy-results", output)
            self.assertEqual(json.loads(output.read_text()), {"Results": []})

    def test_compares_post_scan_with_pre_scan(self):
        before = [Finding("a:b", "1", "2", "pre"), Finding("x:y", "1", "2", "pre")]
        after = [Finding("a:b", "1", "2", "post")]
        self.assertEqual([item.package for item in remaining(before, after)], ["a:b"])
