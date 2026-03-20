#!/usr/bin/env python3
"""Report generation CLI for Technieum Enterprise."""
import argparse, sys, json, logging
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = ["pdf", "html", "json", "csv", "markdown"]

def cmd_generate(args):
    logger.info(f"Generating {args.format} report for scan {args.scan_id}")
    output_dir = Path("output/reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    fname = output_dir / f"report_{args.scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.format}"
    if args.format == "json":
        data = {"scan_id": args.scan_id, "generated_at": datetime.utcnow().isoformat(), "format": "json", "summary": "Report stub - implement reporting module"}
        fname.write_text(json.dumps(data, indent=2))
    else:
        fname.write_text(f"Technieum Enterprise Report\nScan ID: {args.scan_id}\nGenerated: {datetime.utcnow().isoformat()}\nFormat: {args.format}\n")
    print(f"[+] Report generated: {fname}")

def cmd_list(args):
    reports_dir = Path("output/reports")
    if not reports_dir.exists():
        print("[!] No reports found")
        return
    for f in reports_dir.glob("*"):
        print(f"  {f.name}")

def main():
    parser = argparse.ArgumentParser(description="Technieum report generator")
    sub = parser.add_subparsers(dest="command")

    gen = sub.add_parser("generate")
    gen.add_argument("--scan-id", required=True, type=int)
    gen.add_argument("--format", default="json", choices=SUPPORTED_FORMATS)
    gen.add_argument("--output", default=None)
    gen.set_defaults(func=cmd_generate)

    lst = sub.add_parser("list")
    lst.set_defaults(func=cmd_list)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
