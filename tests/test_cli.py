import tempfile
import unittest
from pathlib import Path

from vulnremediate.cli import build_parser, main


class CliTests(unittest.TestCase):
    def test_exposes_operational_subcommands(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["plan", "--repo", "."]).command, "plan")
        self.assertEqual(parser.parse_args(["remediate", "--repo", "."]).command, "remediate")
        self.assertEqual(parser.parse_args(["export-dependabot", "--github-repository", "owner/repo"]).command, "export-dependabot")

    def test_init_creates_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(main(["init", "--repo", directory]), 0)
            self.assertTrue((Path(directory) / ".vulnremediate.json").exists())
