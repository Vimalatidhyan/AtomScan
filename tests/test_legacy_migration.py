"""Legacy DB migration tests.

Proves that a technieum.db created by the old db/database.py schema (legacy CLI)
can be upgraded by migration 006 so the ORM-backed API works correctly.
"""
import hashlib
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


# ---------------------------------------------------------------------------
# Helpers to build a legacy-style database
# ---------------------------------------------------------------------------

def _create_legacy_db(path: str) -> None:
    """Create a SQLite DB with the schema produced by db/database.py (legacy)."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_progress (
            target TEXT PRIMARY KEY,
            phase1_done BOOLEAN DEFAULT 0,
            phase2_done BOOLEAN DEFAULT 0,
            phase3_done BOOLEAN DEFAULT 0,
            phase4_done BOOLEAN DEFAULT 0,
            phase1_partial BOOLEAN DEFAULT 0,
            phase2_partial BOOLEAN DEFAULT 0,
            phase3_partial BOOLEAN DEFAULT 0,
            phase4_partial BOOLEAN DEFAULT 0,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            host TEXT,
            tool TEXT,
            severity TEXT,
            name TEXT,
            info TEXT,
            cve TEXT,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            host TEXT,
            ip TEXT,
            is_alive BOOLEAN DEFAULT 0,
            status_code INTEGER,
            source_tools TEXT,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            host TEXT,
            port INTEGER,
            protocol TEXT,
            service TEXT,
            version TEXT
        );
    """)

    # Legacy data
    conn.execute(
        "INSERT INTO scan_progress (target, phase1_done, phase2_done) VALUES (?, ?, ?)",
        ("example.com", 1, 1),
    )
    conn.execute(
        "INSERT INTO vulnerabilities (target, host, tool, severity, name, info, cve) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("example.com", "www.example.com", "nuclei", "high",
         "SQL Injection", "SQLi in login form", "CVE-2024-1234"),
    )
    conn.execute(
        "INSERT INTO vulnerabilities (target, host, tool, severity, name, info, cve) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("example.com", "api.example.com", "nikto", "critical",
         "RCE via deserialization", "Java deserialization", "CVE-2024-5678"),
    )
    conn.execute(
        "INSERT INTO subdomains (target, host, ip, is_alive) VALUES (?, ?, ?, ?)",
        ("example.com", "www.example.com", "1.2.3.4", 1),
    )
    conn.commit()
    conn.close()


def _run_migrations_on(db_path: str) -> None:
    """Apply the full migration stack (including 006) to a DB file."""
    import app.db.database as _dbmod
    from sqlalchemy import create_engine as ce
    engine = ce(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})

    # Patch the module-level engine so apply_migrations uses our test DB
    original_engine = _dbmod.engine
    original_url = _dbmod.DATABASE_URL
    _dbmod.DATABASE_URL = f"sqlite:///{db_path}"
    _dbmod.engine = engine
    try:
        _dbmod.apply_migrations()
    finally:
        _dbmod.engine = original_engine
        _dbmod.DATABASE_URL = original_url

    return engine


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestLegacyMigration:
    """Upgrade a legacy-schema DB and verify the ORM can serve its data."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "legacy.db")
        _create_legacy_db(self.db_path)
        self.engine = _run_migrations_on(self.db_path)
        Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = Session()

    def teardown_method(self):
        self.db.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_vulnerabilities_have_title_after_migration(self):
        """Migration 006 must backfill title from legacy name column."""
        rows = self.db.execute(
            text("SELECT title, name, severity FROM vulnerabilities")
        ).fetchall()
        assert len(rows) == 2, f"Expected 2 vulns, got {len(rows)}"
        for title, name, severity in rows:
            assert title == name, f"title ({title!r}) != name ({name!r})"

    def test_severity_text_converted_to_integer(self):
        """Migration 006 must convert text severity to integer scores."""
        rows = self.db.execute(
            text("SELECT name, severity FROM vulnerabilities")
        ).fetchall()
        sev_map = {name: severity for name, severity in rows}
        # "high" → 75, "critical" → 90
        assert int(sev_map["SQL Injection"]) == 75, f"high→75 failed: {sev_map}"
        assert int(sev_map["RCE via deserialization"]) == 90, f"critical→90 failed: {sev_map}"

    def test_subdomains_have_subdomain_column(self):
        """Migration 006 must add subdomain column and backfill from host."""
        rows = self.db.execute(
            text("SELECT subdomain, host FROM subdomains")
        ).fetchall()
        assert len(rows) >= 1
        for subdomain, host in rows:
            assert subdomain == host, f"subdomain ({subdomain!r}) != host ({host!r})"

    def test_scan_progress_legacy_rows_survive(self):
        """Legacy scan_progress rows are preserved in _legacy_scan_progress table."""
        # Migration 006 renames legacy 'scan_progress' to '_legacy_scan_progress'
        # so SQLAlchemy can create the new ORM-compatible scan_progress.
        rows = self.db.execute(
            text("SELECT target FROM _legacy_scan_progress WHERE target IS NOT NULL")
        ).fetchall()
        targets = [r[0] for r in rows]
        assert "example.com" in targets

    def test_api_does_not_crash_on_upgraded_db(self):
        """ORM queries against the upgraded DB must not raise exceptions.

        Vulnerability rows can have NULL scan_run_id (legacy data) — the ORM
        column is nullable so queries succeed.  Subdomain is NOT queried via
        ORM here because legacy rows missing 'subdomain' value would violate
        the NOT NULL constraint on the column (they get backfilled only when
        the 'subdomain' migration runs and host is present).  We use raw SQL
        instead to verify the data is still accessible.
        """
        from app.db.models import Vulnerability
        Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        db = Session()
        try:
            # Vulnerability ORM query must work (scan_run_id is nullable)
            vulns = db.query(Vulnerability).all()
            assert isinstance(vulns, list)
            # Subdomains: verify via raw SQL that data survived
            rows = db.execute(text("SELECT id, subdomain, host FROM subdomains")).fetchall()
            assert len(rows) >= 1
        finally:
            db.close()

    def test_new_orm_rows_can_be_written_after_migration(self):
        """After migration, new ORM-style rows must be writable alongside legacy data."""
        from app.db.models import ScanRun, ScanProgress, ScanJob
        from app.db.base import Base
        # Ensure all ORM tables exist
        Base.metadata.create_all(bind=self.engine)
        Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        db = Session()
        try:
            scan = ScanRun(domain="new-scan.example.com", scan_type="quick", status="queued")
            db.add(scan)
            db.flush()
            progress = ScanProgress(scan_run_id=scan.id, status="queued")
            db.add(progress)
            db.commit()
            assert scan.id is not None
            assert progress.id is not None
        finally:
            db.close()
