"""
Integration tests for ReconX TEST_MODE end-to-end scan.

Runs a full 4-phase scan against mock data using the --test flag codepath,
then asserts that the database contains non-zero results in every category.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconx import ReconX


TARGET = "example.com"


class TestIntegrationTestMode(unittest.TestCase):
    """Full scan in test mode using mock data — no external tools required."""

    def setUp(self):
        self.fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.fd)
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except FileNotFoundError:
            pass

    def test_scan_populates_database(self):
        reconx = ReconX(targets=[TARGET], db_path=self.db_path, output_dir=self.output_dir, test_mode=True)
        reconx.scan_target(TARGET)

        stats = reconx.db.get_stats(TARGET)

        # All mock data categories must be non-zero after a test scan
        self.assertGreater(stats["subdomains"], 0, "subdomains should be > 0")
        self.assertGreater(stats["alive_hosts"], 0, "alive_hosts should be > 0")
        self.assertGreater(stats["urls"], 0, "urls should be > 0")
        self.assertGreater(stats["open_ports"], 0, "open_ports should be > 0")
        self.assertGreater(stats["vulnerabilities"], 0, "vulnerabilities should be > 0")

        reconx.db.close()

    def test_scan_progress_marked_complete(self):
        reconx = ReconX(targets=[TARGET], db_path=self.db_path, output_dir=self.output_dir, test_mode=True)
        reconx.scan_target(TARGET)

        progress = reconx.db.get_progress(TARGET)
        self.assertIsNotNone(progress)
        self.assertTrue(progress["phase1_done"], "phase1 should be marked done")
        self.assertTrue(progress["phase2_done"], "phase2 should be marked done")
        self.assertTrue(progress["phase3_done"], "phase3 should be marked done")
        self.assertTrue(progress["phase4_done"], "phase4 should be marked done")

        reconx.db.close()

    def test_scan_only_selected_phases(self):
        reconx = ReconX(targets=[TARGET], db_path=self.db_path, output_dir=self.output_dir, test_mode=True)
        reconx.scan_target(TARGET, phases=[1, 2])

        progress = reconx.db.get_progress(TARGET)
        self.assertIsNotNone(progress)
        self.assertTrue(progress["phase1_done"])
        self.assertTrue(progress["phase2_done"])
        # Phases 3 & 4 were not requested
        self.assertFalse(progress["phase3_done"])
        self.assertFalse(progress["phase4_done"])

        reconx.db.close()


if __name__ == "__main__":
    unittest.main()
