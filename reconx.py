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
import threading
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

# Load .env before anything else that reads env vars
from dotenv import load_dotenv
load_dotenv()

import yaml
from tqdm import tqdm

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from db.database import DatabaseManager
from parsers.parser import (
    SubdomainParser, HttpParser, DnsParser, PortParser,
    UrlParser, DirectoryParser, VulnerabilityParser,
    LeakParser, TakeoverParser, URL_TOOL_PARSERS
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


class ColorFormatter(logging.Formatter):
    """Logging formatter that adds ANSI color codes based on log level"""

    LEVEL_COLORS = {
        logging.DEBUG:    Colors.BLUE,
        logging.INFO:     Colors.GREEN,
        logging.WARNING:  Colors.YELLOW,
        logging.ERROR:    Colors.RED,
        logging.CRITICAL: Colors.RED + Colors.BOLD,
    }
    LEVEL_PREFIXES = {
        logging.DEBUG:    '[~]',
        logging.INFO:     '[+]',
        logging.WARNING:  '[!]',
        logging.ERROR:    '[-]',
        logging.CRITICAL: '[!]',
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, '')
        prefix = self.LEVEL_PREFIXES.get(record.levelno, '[?]')
        msg = super().format(record)
        return f"{color}{prefix}{Colors.END} {msg}"


class ReconX:
    """Main ReconX orchestrator"""

    def __init__(self, targets: List[str], output_dir: str = "output",
                 db_path: str = "reconx.db", threads: int = 5,
                 test_mode: bool = False):
        self.targets = targets
        self.output_dir = Path(output_dir)
        self.test_mode = test_mode

        # Load config.yaml first, then allow env vars to override
        self.config = self._load_config()
        general = self.config.get('general', {})

        self.threads = threads or general.get('threads', 5)
        self.db = DatabaseManager(db_path)
        self.modules_dir = Path(__file__).parent / "modules"
        self.phase_timeout_default = int(os.getenv(
            "RECONX_PHASE_TIMEOUT",
            str(general.get('timeout', 3600))
        ))
        self.continue_on_fail = os.getenv("RECONX_CONTINUE_ON_FAIL", "1").lower() in ("1", "true", "yes")
        self.phase_timeouts = {
            1: int(os.getenv("RECONX_PHASE1_TIMEOUT", str(self.phase_timeout_default))),
            2: int(os.getenv("RECONX_PHASE2_TIMEOUT", str(max(self.phase_timeout_default, 7200)))),
            3: int(os.getenv("RECONX_PHASE3_TIMEOUT", str(max(self.phase_timeout_default, 10800)))),
            4: int(os.getenv("RECONX_PHASE4_TIMEOUT", str(max(self.phase_timeout_default, 14400)))),
        }

        # Initialize output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up logging
        self.logger = self._setup_logging()

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

    def _load_config(self, config_path: str = None) -> Dict[str, Any]:
        """Load config.yaml, merge with env vars (env takes precedence)"""
        if config_path is None:
            config_path = Path(__file__).parent / "config.yaml"
        config = {}
        if Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f) or {}
            except Exception:
                pass
        return config

    def _setup_logging(self) -> logging.Logger:
        """Configure logging with file + console handlers"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        logger = logging.getLogger('reconx')
        logger.setLevel(logging.DEBUG)

        # Avoid adding duplicate handlers on repeated instantiation
        if logger.handlers:
            return logger

        # Console handler — INFO and above, colored
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(ColorFormatter('%(message)s'))
        logger.addHandler(console)

        # File handler — DEBUG and above, plain text
        file_handler = RotatingFileHandler(
            log_dir / 'reconx.log', maxBytes=10 * 1024 * 1024, backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(file_handler)

        return logger

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

    def run_module(self, module_script: str, target: str, output_dir: Path,
                   timeout: Optional[int] = None) -> bool:
        """Execute a bash module script with real-time streaming output"""
        script_path = self.modules_dir / module_script

        if not script_path.exists():
            self.logger.error(f"Module {module_script} not found at {script_path}")
            return False

        self.logger.info(f"Executing {module_script} for {target}")

        if timeout is None:
            timeout = self.phase_timeout_default

        try:
            process = subprocess.Popen(
                [str(script_path), target, str(output_dir)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            def drain_stderr(proc):
                for line in proc.stderr:
                    self.logger.warning(f"[{module_script}] {line.rstrip()}")

            stderr_thread = threading.Thread(target=drain_stderr, args=(process,), daemon=True)
            stderr_thread.start()

            for line in process.stdout:
                print(line, end='')

            process.wait(timeout=timeout)
            stderr_thread.join(timeout=5)

            if process.returncode != 0:
                self.logger.error(f"Module {module_script} failed with code {process.returncode}")
                return False
            return True

        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            self.logger.error(f"Module {module_script} timed out after {timeout}s")
            return False
        except Exception as e:
            self.logger.error(f"Error running {module_script}: {e}")
            return False

    def parse_phase1_output(self, target: str, output_dir: Path):
        """Parse Phase 1 (Discovery) outputs into database"""
        self.logger.info(f"Parsing Phase 1 outputs for {target}")

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
            self.logger.info(f"Inserted {len(all_subs)} subdomains")

        # Parse HTTPx results
        httpx_file = phase_dir / "httpx_alive.json"
        if httpx_file.exists():
            alive_hosts = self.http_parser.parse_httpx(str(httpx_file))
            if alive_hosts:
                self.db.insert_subdomains_bulk(target, alive_hosts)
                self.logger.info(f"Updated {len(alive_hosts)} alive hosts")
        else:
            # Fallback to alive_hosts.txt when httpx output is missing
            alive_file = phase_dir / "alive_hosts.txt"
            if alive_file.exists():
                alive_hosts = self.subdomain_parser.parse_generic_list(str(alive_file), 'alive_hosts')
                for entry in alive_hosts:
                    entry['is_alive'] = True
                if alive_hosts:
                    self.db.insert_subdomains_bulk(target, alive_hosts)
                    self.logger.info(f"Updated {len(alive_hosts)} alive hosts (fallback)")

        # Parse DNSx results
        dnsx_file = phase_dir / "dnsx_resolved.json"
        if dnsx_file.exists():
            resolved = self.dns_parser.parse_dnsx(str(dnsx_file))
            if resolved:
                self.db.insert_subdomains_bulk(target, resolved)
                self.logger.info(f"Updated {len(resolved)} DNS records")

    def parse_phase2_output(self, target: str, output_dir: Path):
        """Parse Phase 2 (Intelligence) outputs into database"""
        self.logger.info(f"Parsing Phase 2 outputs for {target}")

        phase_dir = output_dir / "phase2_intel"

        # Parse Nmap results
        nmap_file = phase_dir / "ports" / "nmap_all.xml"
        if nmap_file.exists():
            ports = self.port_parser.parse_nmap_xml(str(nmap_file))
            if ports:
                self.db.insert_ports_bulk(target, ports)
                self.logger.info(f"Inserted {len(ports)} port records")

        # Parse RustScan results
        rustscan_file = phase_dir / "ports" / "rustscan_ports.txt"
        if rustscan_file.exists():
            ports = self.port_parser.parse_rustscan(str(rustscan_file))
            if ports:
                self.db.insert_ports_bulk(target, ports)
                self.logger.info(f"Inserted {len(ports)} RustScan ports")

        # Parse Subjack (takeover) results
        subjack_file = phase_dir / "takeover" / "subjack_results.txt"
        if subjack_file.exists():
            takeovers = self.takeover_parser.parse_subjack(str(subjack_file))
            if takeovers:
                self.db.insert_vulnerabilities_bulk(target, takeovers)
                self.logger.info(f"Found {len(takeovers)} potential subdomain takeovers")

        # Parse Gitleaks results
        gitleaks_files = list((phase_dir / "leaks").glob("gitleaks*.json"))
        for gitleaks_file in gitleaks_files:
            leaks = self.leak_parser.parse_gitleaks(str(gitleaks_file))
            if leaks:
                self.db.insert_leaks_bulk(target, leaks)
                self.logger.info(f"Found {len(leaks)} git leaks in {gitleaks_file.name}")

    def parse_phase3_output(self, target: str, output_dir: Path):
        """Parse Phase 3 (Content) outputs into database"""
        self.logger.info(f"Parsing Phase 3 outputs for {target}")

        phase_dir = output_dir / "phase3_content"
        urls_dir = phase_dir / "urls"
        all_urls = []

        # Use consolidated URL_TOOL_PARSERS mapping
        for filename, tool in URL_TOOL_PARSERS.items():
            file_path = urls_dir / filename
            if file_path.exists():
                # spideyx and gospider use regex extraction; others use plain list
                if tool in ('spideyx', 'gospider'):
                    parser_method = getattr(self.url_parser, f"parse_{tool}", None)
                    if parser_method:
                        urls = parser_method(str(file_path))
                        all_urls.extend(urls)
                else:
                    urls = self.url_parser.parse_url_list(str(file_path), tool)
                    all_urls.extend(urls)

        if all_urls:
            self.db.insert_urls_bulk(target, all_urls)
            self.logger.info(f"Inserted {len(all_urls)} URLs")

        # Parse directory brute-force results
        brute_dir = phase_dir / "bruteforce"

        # Parse FFUF
        ffuf_file = brute_dir / "ffuf_all.json"
        if ffuf_file.exists():
            paths = self.directory_parser.parse_ffuf(str(ffuf_file))
            if paths:
                self.db.insert_urls_bulk(target, paths)
                self.logger.info(f"Inserted {len(paths)} paths from FFUF")

        # Parse SecretFinder results
        js_dir = phase_dir / "javascript"
        secretfinder_file = js_dir / "secretfinder_secrets.txt"
        if secretfinder_file.exists():
            secrets = self.leak_parser.parse_secretfinder(str(secretfinder_file))
            if secrets:
                self.db.insert_leaks_bulk(target, secrets)
                self.logger.info(f"Found {len(secrets)} JS secrets")

        # Parse LinkFinder results
        linkfinder_file = js_dir / "linkfinder_endpoints.txt"
        if linkfinder_file.exists():
            endpoints = self.leak_parser.parse_linkfinder(str(linkfinder_file))
            if endpoints:
                self.db.insert_leaks_bulk(target, endpoints)
                self.logger.info(f"Found {len(endpoints)} JS endpoints")

    def parse_phase4_output(self, target: str, output_dir: Path):
        """Parse Phase 4 (Vulnerability) outputs into database"""
        self.logger.info(f"Parsing Phase 4 outputs for {target}")

        phase_dir = output_dir / "phase4_vulnscan"

        # Parse Nuclei results
        nuclei_file = phase_dir / "nuclei" / "nuclei_all.json"
        if nuclei_file.exists():
            vulns = self.vuln_parser.parse_nuclei(str(nuclei_file))
            if vulns:
                self.db.insert_vulnerabilities_bulk(target, vulns)
                self.logger.info(f"Inserted {len(vulns)} Nuclei vulnerabilities")

        # Parse Dalfox (XSS) results
        dalfox_file = phase_dir / "xss" / "dalfox_results.txt"
        if dalfox_file.exists():
            vulns = self.vuln_parser.parse_dalfox(str(dalfox_file))
            if vulns:
                self.db.insert_vulnerabilities_bulk(target, vulns)
                self.logger.info(f"Found {len(vulns)} XSS vulnerabilities")

        # Parse SQLMap results
        sqlmap_file = phase_dir / "sqli" / "sqlmap_results.txt"
        if sqlmap_file.exists():
            vulns = self.vuln_parser.parse_sqlmap(str(sqlmap_file))
            if vulns:
                self.db.insert_vulnerabilities_bulk(target, vulns)
                self.logger.info(f"Found {len(vulns)} SQL injection vulnerabilities")

        # Parse Corsy (CORS) results
        corsy_file = phase_dir / "cors" / "corsy_results.txt"
        if corsy_file.exists():
            vulns = self.vuln_parser.parse_corsy(str(corsy_file))
            if vulns:
                self.db.insert_vulnerabilities_bulk(target, vulns)
                self.logger.info(f"Found {len(vulns)} CORS misconfigurations")

    def scan_target_test_mode(self, target: str, phases: List[int]) -> bool:
        """Run scan with mock data for testing — no live network access"""
        from tests.mock_data import MOCK_FILES

        self.logger.info(f"[TEST MODE] Simulating scan for {target}")
        target_dir = self.output_dir / target.replace('.', '_')

        # MOCK_FILES is a flat {filename: content} dict.
        # Map each mock filename → (subdirectory, filename-on-disk) so the files
        # land exactly where parse_phase*_output expects them.
        _file_mapping = {
            # source name          subdir                      dest filename
            "subfinder.txt":    ("phase1_discovery",           "all_subdomains.txt"),
            "httpx.jsonl":      ("phase1_discovery",           "httpx_alive.json"),
            "nmap_all.xml":     ("phase2_intel/ports",         "nmap_all.xml"),
            "ffuf_all.json":    ("phase3_content/bruteforce",  "ffuf_all.json"),
            "nuclei_all.json":  ("phase4_vulnscan/nuclei",     "nuclei_all.json"),
            "gau.txt":          ("phase3_content/urls",        "gau.txt"),
            "katana.txt":       ("phase3_content/urls",        "katana.txt"),
            "trufflehog.txt":   ("phase2_intel/leaks",         "trufflehog.txt"),
        }
        for src_filename, content in MOCK_FILES.items():
            subdir, dest_filename = _file_mapping.get(src_filename, ("phase1_discovery", src_filename))
            dest = target_dir / subdir / dest_filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)

        # Initialize target in database
        self.db.init_target(target)

        # Run parsers against mock files (same code path as production)
        if 1 in phases:
            self.parse_phase1_output(target, target_dir)
            self.db.update_phase(target, 1, True)
        if 2 in phases:
            self.parse_phase2_output(target, target_dir)
            self.db.update_phase(target, 2, True)
        if 3 in phases:
            self.parse_phase3_output(target, target_dir)
            self.db.update_phase(target, 3, True)
        if 4 in phases:
            self.parse_phase4_output(target, target_dir)
            self.db.update_phase(target, 4, True)

        self.logger.info(f"[TEST MODE] Scan complete for {target}")
        return True

    def scan_target(self, target: str, phases: List[int] = None) -> bool:
        """Perform reconnaissance on a single target"""
        if phases is None:
            phases = [1, 2, 3, 4]

        if self.test_mode:
            return self.scan_target_test_mode(target, phases)

        self.log_phase(f"Starting scan for {target}")

        # Create target-specific output directory
        target_dir = self.output_dir / target.replace('.', '_')
        target_dir.mkdir(parents=True, exist_ok=True)

        # Initialize target in database
        self.db.init_target(target)

        success = True

        phase_names = {1: "Discovery", 2: "Intelligence", 3: "Content", 4: "Vulnerability"}
        active_phases = [p for p in phases if p in phase_names]

        try:
            with tqdm(active_phases, desc=f"Scanning {target}", unit="phase") as pbar:
                for phase_num in pbar:
                    pbar.set_postfix_str(phase_names[phase_num])

                    # Phase 1: Discovery
                    if phase_num == 1:
                        progress = self.db.get_progress(target)
                        if progress and progress['phase1_done'] and not self.phase1_outputs_ok(target_dir):
                            self.logger.warning("Phase 1 marked complete but outputs missing; rerunning...")
                            self.db.update_phase(target, 1, False)
                            progress = None

                        if progress and progress['phase1_done']:
                            self.logger.warning("Phase 1 already completed, skipping...")
                        else:
                            self.log_phase(f"Phase 1: Discovery & Enumeration - {target}")
                            if self.run_module("01_discovery.sh", target, target_dir, timeout=self.phase_timeouts[1]):
                                self.parse_phase1_output(target, target_dir)
                                self.db.update_phase(target, 1, True)
                            else:
                                self.logger.error("Phase 1 failed")
                                success = False
                                if self.continue_on_fail:
                                    self.logger.warning("Continuing to next phases despite Phase 1 failure")

                    # Phase 2: Intelligence
                    elif phase_num == 2 and (success or self.continue_on_fail):
                        progress = self.db.get_progress(target)
                        if progress and progress['phase2_done']:
                            self.logger.warning("Phase 2 already completed, skipping...")
                        else:
                            self.log_phase(f"Phase 2: Intelligence & Infrastructure - {target}")
                            if self.run_module("02_intel.sh", target, target_dir, timeout=self.phase_timeouts[2]):
                                self.parse_phase2_output(target, target_dir)
                                self.db.update_phase(target, 2, True)
                            else:
                                self.logger.error("Phase 2 failed")
                                success = False
                                if self.continue_on_fail:
                                    self.logger.warning("Continuing to next phases despite Phase 2 failure")

                    # Phase 3: Content Discovery
                    elif phase_num == 3 and (success or self.continue_on_fail):
                        progress = self.db.get_progress(target)
                        if progress and progress['phase3_done']:
                            self.logger.warning("Phase 3 already completed, skipping...")
                        else:
                            self.log_phase(f"Phase 3: Deep Web & Content Discovery - {target}")
                            if self.run_module("03_content.sh", target, target_dir, timeout=self.phase_timeouts[3]):
                                self.parse_phase3_output(target, target_dir)
                                self.db.update_phase(target, 3, True)
                            else:
                                self.logger.error("Phase 3 failed")
                                success = False
                                if self.continue_on_fail:
                                    self.logger.warning("Continuing to next phases despite Phase 3 failure")

                    # Phase 4: Vulnerability Scanning
                    elif phase_num == 4 and (success or self.continue_on_fail):
                        progress = self.db.get_progress(target)
                        if progress and progress['phase4_done']:
                            self.logger.warning("Phase 4 already completed, skipping...")
                        else:
                            self.log_phase(f"Phase 4: Vulnerability Scanning - {target}")
                            if self.run_module("04_vuln.sh", target, target_dir, timeout=self.phase_timeouts[4]):
                                self.parse_phase4_output(target, target_dir)
                                self.db.update_phase(target, 4, True)
                            else:
                                self.logger.error("Phase 4 failed")
                                success = False
                                if self.continue_on_fail:
                                    self.logger.warning("Continuing after Phase 4 failure")

        except Exception as e:
            self.logger.error(f"Error scanning {target}: {e}")
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

    def run(self, phases: List[int] = None):
        """Main execution method"""
        if phases is None:
            phases = [1, 2, 3, 4]

        start_time = time.time()

        self.banner()
        self.logger.info(f"Starting ReconX for {len(self.targets)} target(s)")
        self.logger.info(f"Output directory: {self.output_dir}")
        self.logger.info(f"Database: {self.db.db_path}")
        self.logger.info(f"Phases: {phases}")
        self.logger.info(f"Thread pool size: {self.threads}")

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
                        self.logger.error(f"Target {target} generated exception: {e}")

        # Final summary
        elapsed = time.time() - start_time
        self.log_phase("Scan Complete")
        self.logger.info(f"Total time: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
        self.logger.info(f"Results saved to: {self.output_dir}")
        self.logger.info(f"Database: {self.db.db_path}")

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

  # Test mode (no live scanning)
  %(prog)s -t example.com --test

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
    parser.add_argument('-d', '--database', default=os.getenv('RECONX_DB_PATH', 'reconx.db'), help='Database file path (default: reconx.db or RECONX_DB_PATH)')
    parser.add_argument('-p', '--phases', default='1,2,3,4', help='Phases to run (default: 1,2,3,4)')
    parser.add_argument('-T', '--threads', type=int, default=5, help='Number of concurrent target scans (default: 5)')
    parser.add_argument('--resume', action='store_true', help='Resume incomplete scans')
    parser.add_argument('--test', action='store_true', help='Run in test mode with mock data (no live scanning)')

    args = parser.parse_args()

    def normalize_target(raw: str) -> str:
        """Convert URL or domain with trailing slash to bare domain (e.g. pcis.education)."""
        s = raw.strip()
        if not s:
            return s
        if "://" in s:
            parsed = urlparse(s if "://" in s else "//" + s)
            host = parsed.netloc or parsed.path
        else:
            host = s
        # Strip trailing slash and any path
        host = host.rstrip("/").split("/")[0].split(":")[0]
        return host.lower() if host else s

    # Get targets and normalize to bare domains (no https://, no trailing /)
    targets = []
    if args.target:
        targets = [normalize_target(t) for t in args.target.split(",") if t.strip()]
    elif args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            sys.exit(1)
        with open(args.file, 'r') as f:
            targets = [normalize_target(line) for line in f if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    if not targets:
        print("Error: No valid targets after normalization")
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
        threads=args.threads,
        test_mode=args.test
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
    finally:
        reconx.db.close()


if __name__ == "__main__":
    main()
