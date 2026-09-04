import tempfile
import unittest
from pathlib import Path

from vulnremediate.models import Change
from vulnremediate.transaction import ChangeTransaction


class TransactionTests(unittest.TestCase):
    def test_rollback_restores_original_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "pom.xml"
            target.write_text("before")
            transaction = ChangeTransaction(root, "run")
            transaction.snapshot([Change(target, "test", "before", "after")])
            target.write_text("after")
            transaction.rollback()
            self.assertEqual(target.read_text(), "before")
