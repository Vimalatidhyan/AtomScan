#!/usr/bin/env python3
"""Technieum API key management CLI.

Usage:
    python scripts/manage_keys.py create --name "My Key" [--expires-days 365]
    python scripts/manage_keys.py list
    python scripts/manage_keys.py revoke <key_id>

All operations require DATABASE_URL to be set (or default sqlite:///./technieum.db).
"""
import argparse
import hashlib
import os
import secrets
import sys
from datetime import datetime, timezone, timedelta

# Ensure repo root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./technieum.db")


def _get_session():
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    )
    # Ensure tables exist
    from app.db.base import Base
    from app.db import models  # register all models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return Session()


def cmd_create(args):
    from app.db.models import APIKey
    db = _get_session()
    raw_key = secrets.token_urlsafe(32)[:32]
    # Ensure alphanumeric only (required by auth middleware)
    raw_key = "".join(c for c in raw_key if c.isalnum())[:32].ljust(32, "0")
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=args.expires_days)
        if args.expires_days
        else None
    )
    api_key = APIKey(
        key_hash=key_hash,
        name=args.name,
        user_identifier=args.user or args.name,
        expires_at=expires_at,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    print(f"API Key created:")
    print(f"  ID:         {api_key.id}")
    print(f"  Name:       {api_key.name}")
    print(f"  Key:        {raw_key}")
    print(f"  Expires:    {expires_at or 'never'}")
    print()
    print("Store this key securely — it cannot be retrieved again.")
    print(f"Use as: X-API-Key: {raw_key}")
    db.close()


def cmd_list(args):
    from app.db.models import APIKey
    db = _get_session()
    keys = db.query(APIKey).all()
    if not keys:
        print("No API keys found.")
    else:
        print(f"{'ID':<5} {'Name':<25} {'Active':<8} {'Expires':<25} {'Last Used'}")
        print("-" * 80)
        for k in keys:
            active = "yes" if k.is_active else "no"
            expires = k.expires_at.isoformat()[:19] if k.expires_at else "never"
            last_used = k.last_used.isoformat()[:19] if k.last_used else "never"
            print(f"{k.id:<5} {(k.name or ''):<25} {active:<8} {expires:<25} {last_used}")
    db.close()


def cmd_revoke(args):
    from app.db.models import APIKey
    db = _get_session()
    key = db.query(APIKey).filter(APIKey.id == args.key_id).first()
    if not key:
        print(f"Key ID {args.key_id} not found.", file=sys.stderr)
        sys.exit(1)
    key.is_active = False
    db.commit()
    print(f"Key {args.key_id} ({key.name!r}) revoked.")
    db.close()


def main():
    parser = argparse.ArgumentParser(description="Technieum API key manager")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a new API key")
    p_create.add_argument("--name", required=True, help="Human-readable key name")
    p_create.add_argument("--user", help="User identifier (defaults to name)")
    p_create.add_argument("--expires-days", type=int, default=365,
                          help="Expiry in days (0 = never)")
    p_create.set_defaults(func=cmd_create)

    p_list = sub.add_parser("list", help="List all API keys")
    p_list.set_defaults(func=cmd_list)

    p_revoke = sub.add_parser("revoke", help="Revoke an API key")
    p_revoke.add_argument("key_id", type=int, help="Key ID to revoke")
    p_revoke.set_defaults(func=cmd_revoke)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
