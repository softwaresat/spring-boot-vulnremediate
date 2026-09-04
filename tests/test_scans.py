import json
import tempfile
import unittest
from pathlib import Path

from vulnremediate.scans import parse_scan_report


class ScanTests(unittest.TestCase):
    def test_parses_gitlab_solution(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"vulnerabilities": [{"severity": "High", "solution": "Upgrade jackson-databind to version 2.17.3 or above.", "location": {"dependency": {"package": {"name": "com.fasterxml.jackson.core:jackson-databind"}, "version": "2.17.0"}}}]}))
            finding = parse_scan_report(report)[0]
        self.assertEqual(finding.fixed_version, "2.17.3")
        self.assertEqual(finding.artifact_id, "jackson-databind")

    def test_parses_trivy_report(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "trivy.json"
            report.write_text(json.dumps({"Results": [{"Vulnerabilities": [{"PkgName": "org.springframework:spring-web", "InstalledVersion": "6.1.0", "FixedVersion": "6.1.14", "Severity": "HIGH"}]}]}))
            finding = parse_scan_report(report)[0]
        self.assertEqual(finding.fixed_version, "6.1.14")
        self.assertEqual(finding.package, "org.springframework:spring-web")

    def test_parses_dependabot_alert_export(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "dependabot.json"
            report.write_text(json.dumps([{"dependency": {"package": {"name": "org.springframework:spring-web"}}, "security_advisory": {"severity": "high", "vulnerabilities": [{"first_patched_version": {"identifier": "6.1.14"}}]}}]))
            finding = parse_scan_report(report)[0]
        self.assertEqual(finding.fixed_version, "6.1.14")
