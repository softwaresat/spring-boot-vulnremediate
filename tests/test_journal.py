import json
import tempfile
import unittest
from pathlib import Path

from vulnremediate.journal import RunJournal


class JournalTests(unittest.TestCase):
    def test_updates_one_durable_run_record(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = RunJournal(Path(directory), "run-1")
            journal.write("started", {"count": 1})
            journal.write("finished", {"count": 2})
            record = json.loads(journal.path.read_text())
            self.assertEqual(record["run_id"], "run-1")
            self.assertEqual(record["event"], "finished")
