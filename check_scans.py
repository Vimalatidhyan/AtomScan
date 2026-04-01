#!/usr/bin/env python3
from app.db import SessionLocal
from app.models import ScanRun

db = SessionLocal()
scans = db.query(ScanRun).all()
for s in scans:
    print(f"ID={s.id}, Domain={s.domain}, Status={s.status}")
db.close()
