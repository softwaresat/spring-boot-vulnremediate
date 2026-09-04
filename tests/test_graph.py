import importlib.util
import tempfile
import unittest
from pathlib import Path

from vulnremediate.models import RunConfig


@unittest.skipUnless(importlib.util.find_spec("langgraph"), "LangGraph is installed in GitHub CI")
class GraphTests(unittest.TestCase):
    def test_runs_complete_dry_plan(self):
        from vulnremediate.graph import build_graph
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pom.xml").write_text("<project><parent><artifactId>spring-boot-starter-parent</artifactId><version>3.3.0</version></parent></project>")
            state = build_graph().invoke({"config": RunConfig(root, fail_on_remaining=False), "errors": []})
            self.assertFalse(state.get("errors"))
            self.assertEqual(state["publication"]["status"], "not_requested")
