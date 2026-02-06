#!/usr/bin/env python3
"""
ReconX - Attack Surface Management Framework
Comprehensive reconnaissance and vulnerability assessment platform

Author: Security Research Team
License: MIT
"""

import argparse
import os
import sys
import subprocess
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from datetime import datetime

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from db.database import DatabaseManager
from parsers.parser import (
    SubdomainParser, HttpParser, DnsParser, PortParser,
    UrlParser, DirectoryParser, VulnerabilityParser,
    LeakParser, TakeoverParser
)


class Colors:
    """Terminal color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ReconX:
    """Main ReconX orchestrator"""

    def __init__(self, targets: List[str], output_dir: str = "output",
                 db_path: str = "reconx.db", threads: int = 5):
        self.targets = targets
        self.output_dir = Path(output_dir)
        self.db = DatabaseManager(db_path)
        self.threads = threads
        self.modules_dir = Path(__file__).parent / "modules"
        self.phase_timeout_default = int(os.getenv("RECONX_PHASE_TIMEOUT", "3600"))
        self.continue_on_fail = os.getenv("RECONX_CONTINUE_ON_FAIL", "1").lower() in ("1", "true", "yes")
        self.phase_timeouts = {
            1: int(os.getenv("RECONX_PHASE1_TIMEOUT", str(self.phase_timeout_default))),
            2: int(os.getenv("RECONX_PHASE2_TIMEOUT", str(max(self.phase_timeout_default, 7200)))),
            3: int(os.getenv("RECONX_PHASE3_TIMEOUT", str(max(self.phase_timeout_default, 10800)))),
            4: int(os.getenv("RECONX_PHASE4_TIMEOUT", str(max(self.phase_timeout_default, 14400)))),
        }

        # Initialize output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize parsers
        self.subdomain_parser = SubdomainParser()
        self.http_parser = HttpParser()
        self.dns_parser = DnsParser()
        self.port_parser = PortParser()
        self.url_parser = UrlParser()
        self.directory_parser = DirectoryParser()
        self.vuln_parser = VulnerabilityParser()
        self.leak_parser = LeakParser()
        self.takeover_parser = TakeoverParser()

    def banner(self):
        """Display ReconX banner"""
        banner = f"""
{Colors.CYAN}
╦═╗╔═╗╔═╗╔═╗╔╗╔╦ ╦
╠╦╝║╣ ║  ║ ║║║║╔╩╦╝
╩╚═╚═╝╚═╝╚═╝╝╚╝╩ ╚═
{Colors.END}{Colors.BOLD}
Attack Surface Management Framework
{Colors.END}{Colors.CYAN}Version 1.0 | Comprehensive Reconnaissance Platform{Colors.END}
"""
        print(banner)

    def log_info(self, message: str):
        """Log info message"""
        print(f"{Colors.GREEN}[+]{Colors.END} {message}")

    def log_error(self, message: str):
        """Log error message"""
        print(f"{Colors.RED}[-]{Colors.END} {message}")

    def log_warn(self, message: str):
        """Log warning message"""
        print(f"{Colors.YELLOW}[!]{Colors.END} {message}")

    def log_phase(self, phase: str):
        """Log phase header"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{phase}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")

    def phase1_outputs_ok(self, target_dir: Path) -> bool:
        """Check required Phase 1 outputs exist before skipping."""
        phase_dir = target_dir / "phase1_discovery"
        required_files = [
            "all_subdomains.txt",
            "resolved_subdomains.txt",
            "alive_hosts.txt",
        ]
        return all((phase_dir / filename).exists() for filename in required_files)

    def run_module(self, module_script: str, target: str, output_dir: Path, timeout: int | None = None) -> bool:
        """Execute a bash module script"""
        script_path = self.modules_dir / module_script

        if not script_path.exists():
            self.log_error(f"Module {module_script} not found at {script_path}")
            return False

        self.log_info(f"Executing {module_script} for {target}")

        if timeout is None:
            timeout = self.phase_timeout_default

        try:
            result = subprocess.run(
                [str(script_path), target, str(output_dir)],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Print module output
            if result.stdout:
                print(result.stdout)

            if result.returncode != 0:
                self.log_error(f"Module {module_script} failed with code {result.returncode}")
                if result.stderr:
                    print(f"Error output:\n{result.stderr}")
                return False

            return True

        except subprocess.TimeoutExpired:
            self.log_error(f"Module {module_script} timed out")
            return False
        except Exception as e:
            self.log_error(f"Error running {module_script}: {e}")
            return False

    def parse_phase1_output(self, target: str, output_dir: Path):
        """Parse Phase 1 (Discovery) outputs into database"""
        self.log_info(f"Parsing Phase 1 outputs for {target}")

        phase_dir = output_dir / "phase1_discovery"

        # Parse subdomains from various sources
        subdomain_files = {
            'all_subdomains.txt': 'mixed',
            'passive_subdomains.txt': 'passive',
            'active_subdomains.txt': 'active'
        }

        all_subs = []
        for filename, source in subdomain_files.items():
            file_path = phase_dir / filename
            if file_path.exists():
                subdomains = self.subdomain_parser.parse_generic_list(str(file_path), source)
                all_subs.extend(subdomains)

        # Insert subdomains
        if all_subs:
            self.db.insert_subdomains_bulk(target, all_subs)
            self.log_info(f"Inserted {len(all_subs)} subdomains")

        # Parse HTTPx results
        httpx_file = phase_dir / "httpx_alive.json"
        if httpx_file.exists():
            alive_hosts = self.http_parser.parse_httpx(str(httpx_file))
            if alive_hosts:
                self.db.insert_subdomains_bulk(target, alive_hosts)
                self.log_info(f"Updated {len(alive_hosts)} alive hosts")
        else:
            # Fallback to alive_hosts.txt when httpx output is missing
            alive_file = phase_dir / "alive_hosts.txt"
            if alive_file.exists():
                alive_hosts = self.subdomain_parser.parse_generic_list(str(alive_file), 'alive_hosts')
                for entry in alive_hosts:
                    entry['is_alive'] = True
                if alive_hosts:
                    self.db.insert_subdomains_bulk(target, alive_hosts)
                    self.log_info(f"Updated {len(alive_hosts)} alive hosts (fallback)")

        # Parse DNSx results
        dnsx_file = phase_dir / "dnsx_resolved.json"
        if dnsx_file.exists():
            resolved = self.dns_parser.parse_dnsx(str(dnsx_file))
            if resolved:
                self.db.insert_subdomains_bulk(target, resolved)
                self.log_info(f"Updated {len(resolved)} DNS records")

    def parse_phase2_output(self, target: str, output_dir: Path):
        """Parse Phase 2 (Intelligence) outputs into database"""
        self.log_info(f"Parsing Phase 2 outputs for {target}")

        phase_dir = output_dir / "phase2_intel"

        # Parse Nmap results
        nmap_file = phase_dir / "ports" / "nmap_all.xml"
        if nmap_file.exists():
            ports = self.port_parser.parse_nmap_xml(str(nmap_file))
            if ports:
                self.db.insert_ports_bulk(target, ports)
                self.log_info(f"Inserted {len(ports)} port records")

        # Parse RustScan results
        rustscan_file = phase_dir / "ports" / "rustscan_ports.txt"
        if rustscan_file.exists():
            ports = self.port_parser.parse_rustscan(str(rustscan_file))
            if ports:
                self.db.insert_ports_bulk(target, ports)
                self.log_info(f"Inserted {len(ports)} RustScan ports")

        # Parse Subjack (takeover) results
        subjack_file = phase_dir / "takeover" / "subjack_results.txt"
        if subjack_file.exists():
            takeovers = self.takeover_parser.parse_subjack(str(subjack_file))
            if takeovers:
                self.db.insert_vulnerabilities_bulk(target, takeovers)
                self.log_info(f"Found {len(takeovers)} potential subdomain takeovers")

        # Parse Gitleaks results
        gitleaks_files = list((phase_dir / "leaks").glob("gitleaks*.json"))
        for gitleaks_file in gitleaks_files:
            leaks = self.leak_parser.parse_gitleaks(str(gitleaks_file))
            if leaks:
                self.db.insert_leaks_bulk(target, leaks)
                self.log_info(f"Found {len(leaks)} git leaks in {gitleaks_file.name}")

    def parse_phase3_output(self, target: str, output_dir: Path):
        """Parse Phase 3 (Content) outputs into database"""
        self.log_info(f"Parsing Phase 3 outputs for {target}")

        phase_dir = output_dir / "phase3_content"

        # Parse URLs from various tools
        url_tools = {
            'gau.txt': 'gau',
            'waybackurls.txt': 'waybackurls',
            'hakrawler.txt': 'hakrawler',
            'katana.txt': 'katana',
            'spideyx.txt': 'spideyx'
        }

        urls_dir = phase_dir / "urls"
        all_urls = []

        for filename, tool in url_tools.items():
            file_path = urls_dir / filename
            if file_path.exists():
                parser_method = getattr(self.url_parser, f"parse_{tool}", None)
                if parser_method:
                    urls = parser_method(str(file_path))
                    all_urls.extend(urls)

        if all_urls:
            self.db.insert_urls_bulk(target, all_urls)
            self.log_info(f"Inserted {len(all_urls)} URLs")

        # Parse directory brute-force results
        brute_dir = phase_dir / "bruteforce"

        # Parse FFUF
        ffuf_file = brute_dir / "ffuf_all.json"
        if ffuf_file.exists():
            paths = self.directory_parser.parse_ffuf(str(ffuf_file))
            if paths:
                self.db.insert_urls_bulk(target, paths)
                self.log_info(f"Inserted {len(paths)} paths from FFUF")

        # Parse SecretFinder results
        js_dir = phase_dir / "javascript"
        secretfinder_file = js_dir / "secretfinder_secrets.txt"
        if secretfinder_file.exists():
            secrets = self.leak_parser.parse_secretfinder(str(secretfinder_file))
            if secrets:
                self.db.insert_leaks_bulk(target, secrets)
                self.log_info(f"Found {len(secrets)} JS secrets")

        # Parse LinkFinder results
        linkfinder_file = js_dir / "linkfinder_endpoints.txt"
        if linkfinder_file.exists():
            endpoints = self.leak_parser.parse_linkfinder(str(linkfinder_file))
            if endpoints:
                self.db.insert_leaks_bulk(target, endpoints)
                self.log_info(f"Found {len(endpoints)} JS endpoints")

    def parse_phase4_output(self, target: str, output_dir: Path):
        """Parse Phase 4 (Vulnerability) outputs into database"""
        self.log_info(f"Parsing Phase 4 outputs for {target}")

        phase_dir = output_dir / "phase4_vulnscan"

        # Parse Nuclei results
        nuclei_file = phase_dir / "nuclei" / "nuclei_all.json"
        if nuclei_file.exists():
            vulns = self.vuln_parser.parse_nuclei(str(nuclei_file))
            if vulns:
                self.db.insert_vulnerabilities_bulk(target, vulns)
                self.log_info(f"Inserted {len(vulns)} Nuclei vulnerabilities")

        # Parse Dalfox (XSS) results
        dalfox_file = phase_dir / "xss" / "dalfox_results.txt"
        if dalfox_file.exists():
            vulns = self.vuln_parser.parse_dalfox(str(dalfox_file))
            if vulns:
                self.db.insert_vulnerabilities_bulk(target, vulns)
                self.log_info(f"Found {len(vulns)} XSS vulnerabilities")

        # Parse SQLMap results
        sqlmap_file = phase_dir / "sqli" / "sqlmap_results.txt"
        if sqlmap_file.exists():
            vulns = self.vuln_parser.parse_sqlmap(str(sqlmap_file))
            if vulns:
                self.db.insert_vulnerabilities_bulk(target, vulns)
                self.log_info(f"Found {len(vulns)} SQL injection vulnerabilities")

        # Parse Corsy (CORS) results
        corsy_file = phase_dir / "cors" / "corsy_results.txt"
        if corsy_file.exists():
            vulns = self.vuln_parser.parse_corsy(str(corsy_file))
            if vulns:
                self.db.insert_vulnerabilities_bulk(target, vulns)
                self.log_info(f"Found {len(vulns)} CORS misconfigurations")

    def scan_target(self, target: str, phases: List[int]) -> bool:
        """Perform reconnaissance on a single target"""
        self.log_phase(f"Starting scan for {target}")

        # Create target-specific output directory
        target_dir = self.output_dir / target.replace('.', '_')
        target_dir.mkdir(parents=True, exist_ok=True)

        # Initialize target in database
        self.db.init_target(target)

        success = True

        try:
            # Phase 1: Discovery
            if 1 in phases:
                progress = self.db.get_progress(target)
                if progress and progress['phase1_done'] and not self.phase1_outputs_ok(target_dir):
                    self.log_warn("Phase 1 marked complete but outputs missing; rerunning...")
                    self.db.update_phase(target, 1, False)
                    progress = None

                if progress and progress['phase1_done']:
                    self.log_warn("Phase 1 already completed, skipping...")
                else:
                    self.log_phase(f"Phase 1: Discovery & Enumeration - {target}")
                    if self.run_module("01_discovery.sh", target, target_dir, timeout=self.phase_timeouts[1]):
                        self.parse_phase1_output(target, target_dir)
                        self.db.update_phase(target, 1, True)
                    else:
                        self.log_error("Phase 1 failed")
                        success = False
                        if self.continue_on_fail:
                            self.log_warn("Continuing to next phases despite Phase 1 failure")

            # Phase 2: Intelligence
            if 2 in phases and (success or self.continue_on_fail):
                progress = self.db.get_progress(target)
                if progress and progress['phase2_done']:
                    self.log_warn("Phase 2 already completed, skipping...")
                else:
                    self.log_phase(f"Phase 2: Intelligence & Infrastructure - {target}")
                    if self.run_module("02_intel.sh", target, target_dir, timeout=self.phase_timeouts[2]):
                        self.parse_phase2_output(target, target_dir)
                        self.db.update_phase(target, 2, True)
                    else:
                        self.log_error("Phase 2 failed")
                        success = False
                        if self.continue_on_fail:
                            self.log_warn("Continuing to next phases despite Phase 2 failure")

            # Phase 3: Content Discovery
            if 3 in phases and (success or self.continue_on_fail):
                progress = self.db.get_progress(target)
                if progress and progress['phase3_done']:
                    self.log_warn("Phase 3 already completed, skipping...")
                else:
                    self.log_phase(f"Phase 3: Deep Web & Content Discovery - {target}")
                    if self.run_module("03_content.sh", target, target_dir, timeout=self.phase_timeouts[3]):
                        self.parse_phase3_output(target, target_dir)
                        self.db.update_phase(target, 3, True)
                    else:
                        self.log_error("Phase 3 failed")
                        success = False
                        if self.continue_on_fail:
                            self.log_warn("Continuing to next phases despite Phase 3 failure")

            # Phase 4: Vulnerability Scanning
            if 4 in phases and (success or self.continue_on_fail):
                progress = self.db.get_progress(target)
                if progress and progress['phase4_done']:
                    self.log_warn("Phase 4 already completed, skipping...")
                else:
                    self.log_phase(f"Phase 4: Vulnerability Scanning - {target}")
                    if self.run_module("04_vuln.sh", target, target_dir, timeout=self.phase_timeouts[4]):
                        self.parse_phase4_output(target, target_dir)
                        self.db.update_phase(target, 4, True)
                    else:
                        self.log_error("Phase 4 failed")
                        success = False
                        if self.continue_on_fail:
                            self.log_warn("Continuing after Phase 4 failure")

        except Exception as e:
            self.log_error(f"Error scanning {target}: {e}")
            success = False

        return success

    def print_statistics(self, target: str):
        """Print scan statistics for target"""
        stats = self.db.get_stats(target)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}Statistics for {target}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")

        print(f"{Colors.GREEN}Subdomains:{Colors.END} {stats['subdomains']}")
        print(f"{Colors.GREEN}Alive Hosts:{Colors.END} {stats['alive_hosts']}")
        print(f"{Colors.GREEN}URLs:{Colors.END} {stats['urls']}")
        print(f"{Colors.GREEN}Open Ports:{Colors.END} {stats['open_ports']}")
        print(f"{Colors.GREEN}Leaks:{Colors.END} {stats['leaks']}")
        print(f"{Colors.GREEN}Total Vulnerabilities:{Colors.END} {stats['vulnerabilities']}")

        if stats['critical_vulns'] > 0:
            print(f"{Colors.RED}{Colors.BOLD}  ├─ Critical: {stats['critical_vulns']}{Colors.END}")
        if stats['high_vulns'] > 0:
            print(f"{Colors.YELLOW}  ├─ High: {stats['high_vulns']}{Colors.END}")

        print()

    def run(self, phases: List[int] = [1, 2, 3, 4]):
        """Main execution method"""
        start_time = time.time()

        self.banner()
        self.log_info(f"Starting ReconX for {len(self.targets)} target(s)")
        self.log_info(f"Output directory: {self.output_dir}")
        self.log_info(f"Database: {self.db.db_path}")
        self.log_info(f"Phases: {phases}")
        self.log_info(f"Thread pool size: {self.threads}")

        # Scan targets
        if len(self.targets) == 1:
            # Single target mode
            target = self.targets[0]
            success = self.scan_target(target, phases)
            if success:
                self.print_statistics(target)
        else:
            # Multi-target mode with threading
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self.scan_target, target, phases): target
                    for target in self.targets
                }

                for future in as_completed(futures):
                    target = futures[future]
                    try:
                        success = future.result()
                        if success:
                            self.print_statistics(target)
                    except Exception as e:
                        self.log_error(f"Target {target} generated exception: {e}")

        # Final summary
        elapsed = time.time() - start_time
        self.log_phase("Scan Complete")
        self.log_info(f"Total time: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
        self.log_info(f"Results saved to: {self.output_dir}")
        self.log_info(f"Database: {self.db.db_path}")

        # Print final statistics for all targets
        print(f"\n{Colors.BOLD}{Colors.GREEN}Final Statistics:{Colors.END}\n")
        for target in self.targets:
            self.print_statistics(target)


def main():
    parser = argparse.ArgumentParser(
        description="ReconX - Attack Surface Management Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan on single target
  %(prog)s -t example.com

  # Multiple targets
  %(prog)s -t example.com,example.org

  # From file
  %(prog)s -f targets.txt

  # Specific phases only
  %(prog)s -t example.com -p 1,2

  # Custom output and threads
  %(prog)s -t example.com -o results -T 10

Phases:
  1 - Discovery & Enumeration
  2 - Intelligence & Infrastructure
  3 - Deep Web & Content Discovery
  4 - Vulnerability Scanning
        """
    )

    parser.add_argument('-t', '--target', help='Target domain(s), comma-separated')
    parser.add_argument('-f', '--file', help='File containing target domains (one per line)')
    parser.add_argument('-o', '--output', default='output', help='Output directory (default: output)')
    parser.add_argument('-d', '--database', default='reconx.db', help='Database file path (default: reconx.db)')
    parser.add_argument('-p', '--phases', default='1,2,3,4', help='Phases to run (default: 1,2,3,4)')
    parser.add_argument('-T', '--threads', type=int, default=5, help='Number of concurrent target scans (default: 5)')
    parser.add_argument('--resume', action='store_true', help='Resume incomplete scans')

    args = parser.parse_args()

    # Get targets
    targets = []
    if args.target:
        targets = [t.strip() for t in args.target.split(',')]
    elif args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            sys.exit(1)
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    # Parse phases
    phases = [int(p.strip()) for p in args.phases.split(',')]

    # Validate phases
    if not all(p in [1, 2, 3, 4] for p in phases):
        print("Error: Phases must be 1, 2, 3, or 4")
        sys.exit(1)

    # Initialize and run ReconX
    reconx = ReconX(
        targets=targets,
        output_dir=args.output,
        db_path=args.database,
        threads=args.threads
    )

    try:
        reconx.run(phases=phases)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
