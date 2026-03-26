"""
Unit tests for db/database.py

Tests are self-contained: each test creates a fresh in-memory (or temp-file)
SQLite database so no external infrastructure is needed.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import DatabaseManager
from tests.mock_data import MOCK_SUBDOMAINS, MOCK_VULNS


TARGET = "example.com"


def make_db():
    """Return a DatabaseManager backed by a fresh temporary file."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(path)
    db.init_target(TARGET)
    return db, path


class TestDatabaseInit(unittest.TestCase):
    def setUp(self):
        self.db, self.path = make_db()

    def tearDown(self):
        self.db.close()
        os.unlink(self.path)

    def test_init_creates_progress_row(self):
        progress = self.db.get_progress(TARGET)
        self.assertIsNotNone(progress)

    def test_stats_all_zero_on_fresh_db(self):
        stats = self.db.get_stats(TARGET)
        self.assertEqual(stats["subdomains"], 0)
        self.assertEqual(stats["alive_hosts"], 0)
        self.assertEqual(stats["urls"], 0)
        self.assertEqual(stats["open_ports"], 0)
        self.assertEqual(stats["leaks"], 0)
        self.assertEqual(stats["vulnerabilities"], 0)


class TestDifferentDbPaths(unittest.TestCase):
    """Regression for Bug 2 (Singleton ignoring db_path)."""

    def test_two_instances_use_separate_files(self):
        fd1, path1 = tempfile.mkstemp(suffix=".db")
        fd2, path2 = tempfile.mkstemp(suffix=".db")
        os.close(fd1)
        os.close(fd2)
        try:
            db1 = DatabaseManager(path1)
            db2 = DatabaseManager(path2)
            db1.init_target("alpha.com")
            db2.init_target("beta.com")

            # alpha.com must only be in db1
            rows1 = db1.fetchall("SELECT target FROM scan_progress WHERE target = ?", ("alpha.com",))
            rows2 = db2.fetchall("SELECT target FROM scan_progress WHERE target = ?", ("alpha.com",))
            self.assertEqual(len(rows1), 1)
            self.assertEqual(len(rows2), 0)
        finally:
            db1.close()
            db2.close()
            os.unlink(path1)
            os.unlink(path2)


class TestInsertSubdomainsBulk(unittest.TestCase):
    def setUp(self):
        self.db, self.path = make_db()

    def tearDown(self):
        self.db.close()
        os.unlink(self.path)

    def test_bulk_insert_stores_all_rows(self):
        self.db.insert_subdomains_bulk(TARGET, MOCK_SUBDOMAINS)
        stats = self.db.get_stats(TARGET)
        self.assertEqual(stats["subdomains"], len(MOCK_SUBDOMAINS))

    def test_bulk_insert_updates_alive_on_conflict(self):
        """Regression for Bug 3: INSERT OR IGNORE silently dropped updates."""
        # First insert: host is dead
        initial = [{"host": "www.example.com", "ip": None, "is_alive": False,
                    "status_code": None, "source_tool": "subfinder"}]
        self.db.insert_subdomains_bulk(TARGET, initial)

        # Second insert: same host, now alive
        updated = [{"host": "www.example.com", "ip": "93.184.216.34", "is_alive": True,
                    "status_code": 200, "source_tool": "httpx"}]
        self.db.insert_subdomains_bulk(TARGET, updated)

        # Should still be 1 row, and it should now be alive
        stats = self.db.get_stats(TARGET)
        self.assertEqual(stats["subdomains"], 1)
        self.assertEqual(stats["alive_hosts"], 1)

    def test_alive_count_reflects_reality(self):
        self.db.insert_subdomains_bulk(TARGET, MOCK_SUBDOMAINS)
        alive_expected = sum(1 for s in MOCK_SUBDOMAINS if s.get("is_alive"))
        stats = self.db.get_stats(TARGET)
        self.assertEqual(stats["alive_hosts"], alive_expected)


class TestGetStats(unittest.TestCase):
    def setUp(self):
        self.db, self.path = make_db()

    def tearDown(self):
        self.db.close()
        os.unlink(self.path)

    def test_get_stats_returns_dict(self):
        stats = self.db.get_stats(TARGET)
        self.assertIsInstance(stats, dict)

    def test_get_stats_has_all_keys(self):
        stats = self.db.get_stats(TARGET)
        expected_keys = {"subdomains", "alive_hosts", "urls", "open_ports",
                         "leaks", "vulnerabilities", "critical_vulns", "high_vulns"}
        self.assertTrue(expected_keys.issubset(stats.keys()))

    def test_vulnerability_counts_by_severity(self):
        for v in MOCK_VULNS:
            self.db.insert_vulnerability(
                target=TARGET,
                host=v["host"],
                tool=v["tool"],
                severity=v["severity"],
                name=v["name"],
                info=v.get("description", ""),
                cve=v.get("cve"),
            )
        stats = self.db.get_stats(TARGET)
        self.assertEqual(stats["vulnerabilities"], len(MOCK_VULNS))
        self.assertEqual(stats["critical_vulns"], sum(1 for v in MOCK_VULNS if v["severity"] == "critical"))
        self.assertEqual(stats["high_vulns"], sum(1 for v in MOCK_VULNS if v["severity"] == "high"))


if __name__ == "__main__":
    unittest.main()
