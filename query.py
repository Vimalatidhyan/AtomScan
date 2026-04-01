#!/usr/bin/env python3
"""
Technieum Database Query Tool
Quick queries and reports from the Technieum database
"""

import argparse
import sys
from pathlib import Path
from tabulate import tabulate

sys.path.insert(0, str(Path(__file__).parent))
from db.database import DatabaseManager

# Whitelist of allowed table names for export (prevents SQL injection)
ALLOWED_TABLES = {'subdomains', 'vulnerabilities', 'leaks', 'ports', 'urls'}


class TechnieumQuery:
    """Database query interface"""

    def __init__(self, db_path: str = "technieum.db"):
        self.db = DatabaseManager(db_path)

    def list_targets(self):
        """List all targets in database"""
        rows = self.db.fetchall("SELECT DISTINCT target FROM scan_progress ORDER BY target")
        targets = [row['target'] for row in rows]
        print(f"\nTotal targets: {len(targets)}\n")
        for target in targets:
            print(f"  • {target}")
        print()

    def target_summary(self, target: str):
        """Show summary for a target"""
        stats = self.db.get_stats(target)
        progress = self.db.get_progress(target)

        print(f"\n{'='*70}")
        print(f"Summary for {target}")
        print(f"{'='*70}\n")

        # Progress
        if progress:
            print("Scan Progress:")
            phases = [
                ("Phase 1: Discovery", progress['phase1_done']),
                ("Phase 2: Intelligence", progress['phase2_done']),
                ("Phase 3: Content", progress['phase3_done']),
                ("Phase 4: Vulnerabilities", progress['phase4_done'])
            ]
            for phase, done in phases:
                status = "✓ Complete" if done else "✗ Incomplete"
                print(f"  {phase}: {status}")
            print()

        # Statistics
        print("Statistics:")
        data = [
            ["Subdomains", stats['subdomains']],
            ["Alive Hosts", stats['alive_hosts']],
            ["URLs", stats['urls']],
            ["Open Ports", stats['open_ports']],
            ["Leaks", stats['leaks']],
            ["Total Vulnerabilities", stats['vulnerabilities']],
            ["  └─ Critical", stats['critical_vulns']],
            ["  └─ High", stats['high_vulns']],
        ]
        print(tabulate(data, tablefmt="simple"))
        print()

    def show_subdomains(self, target: str, alive_only: bool = False):
        """Show subdomains for target"""
        query = "SELECT host, ip, is_alive, status_code, source_tools FROM subdomains WHERE target = ?"
        params = [target]

        if alive_only:
            query += " AND is_alive = 1"

        query += " ORDER BY is_alive DESC, host"

        rows = self.db.fetchall(query, tuple(params))

        if not rows:
            print(f"\nNo subdomains found for {target}\n")
            return

        print(f"\nSubdomains for {target} ({len(rows)} total):\n")

        data = []
        for row in rows:
            status = "✓" if row['is_alive'] else "✗"
            data.append([
                status,
                row['host'],
                row['ip'] or '-',
                row['status_code'] or '-',
                (row['source_tools'] or '-')[:30]
            ])

        print(tabulate(data, headers=['Alive', 'Host', 'IP', 'Status', 'Source'], tablefmt="grid"))
        print()

    def show_vulnerabilities(self, target: str, severity: str = None):
        """Show vulnerabilities for target"""
        query = "SELECT host, tool, severity, name, cve FROM vulnerabilities WHERE target = ?"
        params = [target]

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"

        rows = self.db.fetchall(query, tuple(params))

        if not rows:
            msg = f"\nNo vulnerabilities found for {target}"
            if severity:
                msg += f" with severity '{severity}'"
            print(msg + "\n")
            return

        print(f"\nVulnerabilities for {target} ({len(rows)} total):\n")

        data = []
        for row in rows:
            # Color code severity
            sev = row['severity']
            if sev == 'critical':
                sev = f"🔴 {sev}"
            elif sev == 'high':
                sev = f"🟠 {sev}"
            elif sev == 'medium':
                sev = f"🟡 {sev}"

            data.append([
                sev,
                row['tool'],
                row['host'][:40] if row['host'] else '-',
                row['name'][:50],
                row['cve'] or '-'
            ])

        print(tabulate(data, headers=['Severity', 'Tool', 'Host', 'Vulnerability', 'CVE'], tablefmt="grid"))
        print()

    def show_leaks(self, target: str):
        """Show leaks for target"""
        rows = self.db.fetchall(
            "SELECT leak_type, url, info, severity FROM leaks WHERE target = ? ORDER BY severity",
            (target,)
        )

        if not rows:
            print(f"\nNo leaks found for {target}\n")
            return

        print(f"\nLeaks for {target} ({len(rows)} total):\n")

        data = []
        for row in rows:
            data.append([
                row['leak_type'],
                row['url'][:50] if row['url'] else '-',
                row['info'][:60],
                row['severity']
            ])

        print(tabulate(data, headers=['Type', 'URL', 'Info', 'Severity'], tablefmt="grid"))
        print()

    def show_ports(self, target: str):
        """Show open ports for target"""
        rows = self.db.fetchall(
            "SELECT host, port, protocol, service, version FROM ports WHERE target = ? ORDER BY host, port",
            (target,)
        )

        if not rows:
            print(f"\nNo open ports found for {target}\n")
            return

        print(f"\nOpen Ports for {target} ({len(rows)} total):\n")

        data = []
        for row in rows:
            data.append([
                row['host'],
                row['port'],
                row['protocol'],
                row['service'] or '-',
                (row['version'] or '-')[:40]
            ])

        print(tabulate(data, headers=['Host', 'Port', 'Protocol', 'Service', 'Version'], tablefmt="grid"))
        print()

    def export_csv(self, target: str, table: str, output_file: str):
        """Export table to CSV"""
        import csv

        if table not in ALLOWED_TABLES:
            print(f"Error: Invalid table name '{table}'")
            return

        rows = self.db.fetchall(f"SELECT * FROM {table} WHERE target = ?", (target,))

        if not rows:
            print(f"No data found in {table} for {target}")
            return

        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(row))

        print(f"Exported {len(rows)} rows to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Technieum Database Query Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-d', '--database', default='technieum.db', help='Database file path')
    parser.add_argument('-t', '--target', help='Target domain')

    parser.add_argument('--list', action='store_true', help='List all targets')
    parser.add_argument('--summary', action='store_true', help='Show target summary')
    parser.add_argument('--subdomains', action='store_true', help='Show subdomains')
    parser.add_argument('--alive-only', action='store_true', help='Show only alive hosts')
    parser.add_argument('--vulns', action='store_true', help='Show vulnerabilities')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low', 'info'],
                        help='Filter vulnerabilities by severity')
    parser.add_argument('--leaks', action='store_true', help='Show leaks')
    parser.add_argument('--ports', action='store_true', help='Show open ports')
    parser.add_argument('--export', choices=sorted(ALLOWED_TABLES),
                        help='Export table to CSV')
    parser.add_argument('-o', '--output', help='Output file for export')

    args = parser.parse_args()

    query = TechnieumQuery(args.database)

    try:
        if args.list:
            query.list_targets()

        elif args.target:
            if args.summary or (not any([args.subdomains, args.vulns, args.leaks, args.ports, args.export])):
                query.target_summary(args.target)

            if args.subdomains:
                query.show_subdomains(args.target, args.alive_only)

            if args.vulns:
                query.show_vulnerabilities(args.target, args.severity)

            if args.leaks:
                query.show_leaks(args.target)

            if args.ports:
                query.show_ports(args.target)

            if args.export:
                if not args.output:
                    args.output = f"{args.target}_{args.export}.csv"
                query.export_csv(args.target, args.export, args.output)

        else:
            parser.print_help()

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        query.db.close()


if __name__ == "__main__":
    main()
