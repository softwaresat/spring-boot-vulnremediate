import tempfile
import unittest
from pathlib import Path

from vulnremediate.models import Finding
from vulnremediate.models import RunConfig
from vulnremediate.repository import apply_baseline_change, apply_maven_change, baseline_changes, is_spring_boot_application, parent_first_changes, parent_first_plan


class RepositoryTests(unittest.TestCase):
    def test_parent_first_prefers_root_dependency_management(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pom.xml").write_text("""<project><dependencyManagement><dependencies><dependency><artifactId>jackson-databind</artifactId><version>2.17.0</version></dependency></dependencies></dependencyManagement></project>""")
            child = root / "child"
            child.mkdir()
            (child / "pom.xml").write_text("""<project><dependencies><dependency><artifactId>jackson-databind</artifactId><version>2.17.0</version></dependency></dependencies></project>""")
            changes = parent_first_changes(root, [Finding("com.fasterxml.jackson.core:jackson-databind", "2.17.0", "2.17.3", "report")])
            self.assertEqual(changes[0].path, root / "pom.xml")

    def test_detects_spring_boot_application(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pom.xml").write_text("<project><parent><artifactId>spring-boot-starter-parent</artifactId></parent></project>")
            self.assertTrue(is_spring_boot_application(root))

    def test_property_owner_is_planned_and_safely_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pom = root / "pom.xml"
            pom.write_text("""<project><properties><jackson.version>2.17.0</jackson.version></properties><dependencies><dependency><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency></dependencies></project>""")
            plan = parent_first_plan(root, [Finding("com.fasterxml.jackson.core:jackson-databind", "2.17.0", "2.17.3", "report")])[0]
            self.assertEqual(plan.change.owner, "property")
            apply_maven_change(plan.change)
            self.assertIn("<jackson.version>2.17.3</jackson.version>", pom.read_text())

    def test_unowned_finding_is_retained_as_blocked_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pom.xml").write_text("<project><dependencies /></project>")
            plan = parent_first_plan(root, [Finding("a:b", "1", "2", "report")])[0]
            self.assertIsNotNone(plan.blocked_reason)

    def test_updates_helm_image_and_dependency_without_global_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "values.yaml").write_text("image:\n  repository: api\n  tag: old\n")
            (root / "Chart.yaml").write_text("dependencies:\n  - name: redis\n    version: 1.0.0\n")
            changes = baseline_changes(RunConfig(root, helm_images={"api": "new"}, helm_dependencies={"redis": "2.0.0"}))
            for change in changes:
                apply_baseline_change(change)
            self.assertIn("tag: new", (root / "values.yaml").read_text())
            self.assertIn("version: 2.0.0", (root / "Chart.yaml").read_text())
