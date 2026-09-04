import tempfile
import unittest
from pathlib import Path

from vulnremediate.models import Finding
from vulnremediate.repository import is_spring_boot_application, parent_first_changes


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
