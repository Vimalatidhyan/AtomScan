#!/usr/bin/env python3
"""
Phase 5 Threat Intelligence Aggregator.

Reads raw JSON/text outputs from 05_threat_intel.sh (data_leaks, malware,
ip_reputation, domain_reputation, blocklists, breach_monitoring) and produces
a single phase5_threat_intel_summary.json. Can be called from bash or Python.

Usage:
  python3 -m intelligence.threat_intel.aggregator --target example.com --phase-dir output/example_com/phase5_threat_intel --output summary.json
"""

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List


def _read_json(path: Path) -> Any:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _collect_dir(phase_dir: Path, subdir: str) -> List[Dict[str, Any]]:
    """Collect and normalize entries from a subdirectory of raw results."""
    entries = []
    d = phase_dir / subdir
    if not d.is_dir():
        return entries
    for f in d.iterdir():
        if f.suffix in (".json", ".txt"):
            data = _read_json(f) if f.suffix == ".json" else None
            if data is not None:
                if isinstance(data, list):
                    entries.extend(data)
                elif isinstance(data, dict):
                    entries.append(data)
                else:
                    entries.append({"raw": data})
    return entries


def _severity_from_entry(entry: Dict[str, Any], default: str = "medium") -> str:
    s = (entry.get("severity") or entry.get("threat") or default).lower()
    if s in ("critical", "high", "medium", "low", "info"):
        return s
    return default


def aggregate(phase_dir: Path, target: str) -> Dict[str, Any]:
    """Aggregate all phase5 subdirs into one summary."""
    phase_dir = Path(phase_dir)
    summary: Dict[str, Any] = {
        "target": target,
        "total_threats": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "by_type": {},
        "top_threats": [],
    }

    all_entries: List[Dict[str, Any]] = []
    type_counts: Dict[str, int] = {}

    for subdir, label in [
        ("data_leaks", "data_leaks"),
        ("malware", "malware"),
        ("ip_reputation", "ip_reputation"),
        ("domain_reputation", "domain_reputation"),
        ("blocklists", "blocklists"),
        ("breach_monitoring", "breach_monitoring"),
    ]:
        entries = _collect_dir(phase_dir, subdir)
        if entries:
            type_counts[label] = len(entries)
            for e in entries:
                e["_type"] = label
                all_entries.append(e)

    # Blocklists: often CSV or one file
    bl_dir = phase_dir / "blocklists"
    if bl_dir.is_dir():
        for f in bl_dir.iterdir():
            if f.suffix == ".csv" and f.stat().st_size > 0:
                with open(f) as fp:
                    lines = [l.strip() for l in fp if l.strip()]
                type_counts["blocklists"] = type_counts.get("blocklists", 0) + len(lines)
                for line in lines[:100]:  # cap for summary
                    parts = line.split(",", 2)
                    all_entries.append({
                        "_type": "blocklists",
                        "indicator": parts[0] if parts else "",
                        "source": parts[1] if len(parts) > 1 else "",
                        "listed": True,
                    })

    summary["by_type"] = type_counts
    summary["total_threats"] = len(all_entries)

    for e in all_entries:
        sev = _severity_from_entry(e)
        if sev == "critical":
            summary["critical"] += 1
        elif sev == "high":
            summary["high"] += 1
        elif sev == "medium":
            summary["medium"] += 1
        else:
            summary["low"] += 1

    # Top threats: first 20 by severity order
    def order_key(x: Dict[str, Any]) -> tuple:
        s = _severity_from_entry(x)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return (order.get(s, 2), x.get("_type", ""))

    all_entries.sort(key=order_key)
    summary["top_threats"] = [
        {k: v for k, v in e.items() if k != "_type"} for e in all_entries[:20]
    ]

    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="Aggregate Phase 5 threat intel outputs")
    ap.add_argument("--target", required=True, help="Target domain")
    ap.add_argument("--phase-dir", required=True, help="Phase 5 output directory (e.g. .../phase5_threat_intel)")
    ap.add_argument("--output", required=True, help="Output summary JSON path")
    ap.add_argument("--db", default="", help="Optional: insert into technieum DB (path to technieum.db)")
    args = ap.parse_args()

    phase_dir = Path(args.phase_dir)
    if not phase_dir.is_dir():
        os.makedirs(phase_dir, exist_ok=True)

    summary = aggregate(phase_dir, args.target)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Wrote {out_path}: total_threats={summary['total_threats']}")

    if args.db and Path(args.db).exists():
        try:
            import os
            os.environ.setdefault("DATABASE_URL", f"sqlite:///{args.db}")
            from app.db.database import SessionLocal
            from app.db.models import ThreatIntelData
            db_session = SessionLocal()
            try:
                record = ThreatIntelData(
                    source="aggregator",
                    indicator_type="summary",
                    indicator_value=args.target,
                    severity=None,
                    description=json.dumps(summary),
                )
                db_session.add(record)
                db_session.commit()
                print("Inserted summary into threat_intel_data table")
            finally:
                db_session.close()
        except Exception as e:
            print(f"DB insert skipped: {e}")


if __name__ == "__main__":
    main()
