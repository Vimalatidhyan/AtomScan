"""Migration runner.

Applies versioned SQL migrations in order.  Each migration has:
  - version: string identifier (e.g. "001")
  - description: human-readable label
  - upgrade(): DDL to apply
  - downgrade(): DDL to reverse (optional)

The `schema_migrations` table tracks applied versions.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from sqlalchemy import Engine, text

logger = logging.getLogger(__name__)

_MIGRATIONS: list["Migration"] = []


@dataclass
class Migration:
    version: str
    description: str
    upgrade_sql: list[str]
    downgrade_sql: list[str] = field(default_factory=list)


def register(
    version: str,
    description: str,
    upgrade_sql: list[str] | None = None,
    downgrade_sql: list[str] | None = None,
    # Legacy aliases kept for backward compat
    upgrade: list[str] | None = None,
    downgrade: list[str] | None = None,
) -> None:
    """Register a migration.

    Accepts both ``upgrade_sql``/``downgrade_sql`` (canonical) and
    the older ``upgrade``/``downgrade`` parameter names.
    """
    up = upgrade_sql if upgrade_sql is not None else (upgrade or [])
    dn = downgrade_sql if downgrade_sql is not None else (downgrade or [])
    _MIGRATIONS.append(Migration(version, description, up, dn))


def _ensure_migrations_table(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version     TEXT    PRIMARY KEY,
                description TEXT    NOT NULL,
                applied_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))


def _applied_versions(engine: Engine) -> set[str]:
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version FROM schema_migrations")).fetchall()
    return {r[0] for r in rows}


def get_current_version(engine: Engine) -> Optional[str]:
    """Return the latest applied migration version, or None."""
    _ensure_migrations_table(engine)
    applied = _applied_versions(engine)
    if not applied:
        return None
    return max(applied)


def run_migrations(engine: Engine) -> None:
    """Apply all pending migrations in version order."""
    _ensure_migrations_table(engine)
    applied = _applied_versions(engine)
    pending = [m for m in sorted(_MIGRATIONS, key=lambda m: m.version) if m.version not in applied]

    if not pending:
        logger.debug("No pending migrations.")
        return

    for migration in pending:
        logger.info("Applying migration %s: %s", migration.version, migration.description)
        with engine.begin() as conn:
            for stmt in migration.upgrade_sql:
                try:
                    conn.execute(text(stmt))
                except Exception as exc:
                    # Tolerate "column already exists", "table already exists", and "no such column"
                    msg = str(exc).lower()
                    if (
                        "already exists" in msg
                        or "duplicate column" in msg
                        or "no such column" in msg
                    ):
                        logger.debug("Skipping idempotent or irrelevant DDL (%s)", stmt[:60])
                    else:
                        raise
            conn.execute(
                text("INSERT INTO schema_migrations (version, description) VALUES (:v, :d)"),
                {"v": migration.version, "d": migration.description},
            )
        logger.info("Migration %s applied.", migration.version)


def rollback_last(engine: Engine) -> None:
    """Roll back the most recently applied migration."""
    _ensure_migrations_table(engine)
    applied = _applied_versions(engine)
    if not applied:
        logger.warning("No migrations to roll back.")
        return
    latest_version = max(applied)
    migration = next((m for m in _MIGRATIONS if m.version == latest_version), None)
    if migration is None:
        logger.error("Migration %s not found in registry.", latest_version)
        return
    logger.info("Rolling back migration %s: %s", migration.version, migration.description)
    with engine.begin() as conn:
        for stmt in migration.downgrade_sql:
            conn.execute(text(stmt))
        conn.execute(
            text("DELETE FROM schema_migrations WHERE version = :v"),
            {"v": latest_version},
        )
    logger.info("Migration %s rolled back.", latest_version)
