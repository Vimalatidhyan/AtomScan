#!/usr/bin/env python3
"""
ReconX Output Parsers
Parses output from various reconnaissance tools into structured data
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterator
import xml.etree.ElementTree as ET


class OutputParser:
    """Base parser class with common parsing utilities"""

    # Pre-compiled regexes — avoids recompilation on every call
    _DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')
    _SUBDOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    _URL_RE = re.compile(r'(https?://[^\s]+)')
    _PROTOCOL_RE = re.compile(r'^https?://')

    @staticmethod
    def read_lines(file_path: str) -> List[str]:
        """Read file and return non-empty lines"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return []

    @staticmethod
    def iter_lines(file_path: str) -> Iterator[str]:
        """Yield non-empty lines from file without loading all into memory"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        yield stripped
        except Exception as e:
            print(f"Error reading {file_path}: {e}")

    @staticmethod
    def iter_jsonl(file_path: str) -> Iterator[Dict]:
        """Yield parsed JSON objects from a JSONL file one at a time"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"Error reading JSONL {file_path}: {e}")

    @staticmethod
    def read_json(file_path: str) -> List[Dict[str, Any]]:
        """Read JSON file (supports JSONL format)"""
        results = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
                if not content:
                    return []

                # Try parsing as JSON array or object first
                try:
                    data = json.loads(content)
                    return data if isinstance(data, list) else [data]
                except json.JSONDecodeError:
                    # Try JSONL format (one JSON object per line)
                    for line in content.split('\n'):
                        if line.strip():
                            try:
                                results.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
        except Exception as e:
            print(f"Error reading JSON {file_path}: {e}")
        return results

    @staticmethod
    def extract_domain(text: str) -> Optional[str]:
        """Extract domain from various formats"""
        text = OutputParser._PROTOCOL_RE.sub('', text)
        match = OutputParser._DOMAIN_RE.match(text)
        return match.group(0) if match else None

    @staticmethod
    def is_valid_subdomain(subdomain: str) -> bool:
        """Validate subdomain format"""
        return bool(OutputParser._SUBDOMAIN_RE.match(subdomain))


class SubdomainParser(OutputParser):
    """Parse subdomain enumeration tool outputs"""

    def parse_generic_list(self, file_path: str, source_tool: str) -> List[Dict[str, str]]:
        """Parse generic subdomain list (one per line)"""
        results = []
        for line in self.iter_lines(file_path):
            domain = self.extract_domain(line)
            if domain and self.is_valid_subdomain(domain):
                results.append({
                    'host': domain.lower(),
                    'source_tool': source_tool
                })
        return results

    def parse_amass(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Amass output (supports text and JSON)"""
        if file_path.endswith('.json'):
            data = self.read_json(file_path)
            results = []
            for entry in data:
                if 'name' in entry:
                    result = {'host': entry['name'].lower(), 'source_tool': 'amass'}
                    if 'addresses' in entry and entry['addresses']:
                        result['ip'] = entry['addresses'][0].get('ip', '')
                    results.append(result)
            return results
        else:
            return self.parse_generic_list(file_path, 'amass')

    def parse_subfinder(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Subfinder output"""
        return self.parse_generic_list(file_path, 'subfinder')

    def parse_assetfinder(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Assetfinder output"""
        return self.parse_generic_list(file_path, 'assetfinder')

    def parse_sublist3r(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Sublist3r output"""
        return self.parse_generic_list(file_path, 'sublist3r')

    def parse_subdominator(self, file_path: str) -> List[Dict[str, str]]:
        """Parse SubDominator output"""
        return self.parse_generic_list(file_path, 'subdominator')


class HttpParser(OutputParser):
    """Parse HTTP probing tool outputs"""

    def parse_httpx(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse httpx output (JSON format)"""
        results = []
        for entry in self.iter_jsonl(file_path):
            if 'host' in entry or 'url' in entry:
                host = entry.get('host', '')
                if not host and 'url' in entry:
                    host = self.extract_domain(entry['url'])

                result = {
                    'host': host.lower() if host else '',
                    'is_alive': True,
                    'status_code': entry.get('status_code', entry.get('status-code')),
                    'source_tool': 'httpx'
                }

                if 'a' in entry and entry['a']:
                    result['ip'] = entry['a'][0] if isinstance(entry['a'], list) else entry['a']

                results.append(result)
        return results

    def parse_subprober(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse SubProber output"""
        results = []
        for line in self.iter_lines(file_path):
            # SubProber format: URL [STATUS_CODE]
            match = re.match(r'(https?://)?([^\s\[]+)(?:\s+\[(\d+)\])?', line)
            if match:
                host = self.extract_domain(match.group(2))
                if host:
                    result = {
                        'host': host.lower(),
                        'is_alive': True,
                        'source_tool': 'subprober'
                    }
                    if match.group(3):
                        result['status_code'] = int(match.group(3))
                    results.append(result)
        return results


class DnsParser(OutputParser):
    """Parse DNS tool outputs"""

    def parse_dnsx(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse dnsx output (JSON format)"""
        results = []
        for entry in self.iter_jsonl(file_path):
            if 'host' in entry:
                result = {
                    'host': entry['host'].lower(),
                    'source_tool': 'dnsx'
                }
                if 'a' in entry and entry['a']:
                    result['ip'] = entry['a'][0] if isinstance(entry['a'], list) else entry['a']
                results.append(result)
        return results


class PortParser(OutputParser):
    """Parse port scanning tool outputs"""

    def parse_nmap_xml(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output"""
        results = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            for host in root.findall('.//host'):
                # Get IP address
                addr = host.find('.//address[@addrtype="ipv4"]')
                ip = addr.get('addr') if addr is not None else ''

                # Get hostname
                hostname_elem = host.find('.//hostname')
                hostname = hostname_elem.get('name') if hostname_elem is not None else ip

                # Get ports
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        service = port.find('service')
                        results.append({
                            'host': hostname.lower(),
                            'ip': ip,
                            'port': int(port.get('portid')),
                            'protocol': port.get('protocol', 'tcp'),
                            'service': service.get('name') if service is not None else '',
                            'version': service.get('version', '') if service is not None else ''
                        })
        except Exception as e:
            print(f"Error parsing Nmap XML {file_path}: {e}")
        return results

    def parse_rustscan(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse RustScan output"""
        results = []
        current_host = None

        for line in self.iter_lines(file_path):
            # Match host line: "Open 1.2.3.4:80"
            if 'Open' in line:
                match = re.search(r'Open\s+([^\s:]+):(\d+)', line)
                if match:
                    results.append({
                        'host': match.group(1),
                        'port': int(match.group(2)),
                        'protocol': 'tcp'
                    })
            # Alternative format: host -> [ports]
            elif '->' in line:
                match = re.match(r'([^\s]+)\s+->\s+\[([^\]]+)\]', line)
                if match:
                    current_host = match.group(1)
                    ports = re.findall(r'\d+', match.group(2))
                    for port in ports:
                        results.append({
                            'host': current_host,
                            'port': int(port),
                            'protocol': 'tcp'
                        })
        return results


class UrlParser(OutputParser):
    """Parse URL discovery tool outputs"""

    def parse_url_list(self, file_path: str, source_tool: str) -> List[Dict[str, str]]:
        """Parse generic URL list (one URL per line)"""
        return [{'url': line, 'source_tool': source_tool}
                for line in self.iter_lines(file_path) if line.startswith('http')]

    def parse_gau(self, file_path: str) -> List[Dict[str, str]]:
        """Parse gau output"""
        return self.parse_url_list(file_path, 'gau')

    def parse_waybackurls(self, file_path: str) -> List[Dict[str, str]]:
        """Parse waybackurls output"""
        return self.parse_url_list(file_path, 'waybackurls')

    def parse_hakrawler(self, file_path: str) -> List[Dict[str, str]]:
        """Parse hakrawler output"""
        return self.parse_url_list(file_path, 'hakrawler')

    def parse_katana(self, file_path: str) -> List[Dict[str, str]]:
        """Parse katana output"""
        return self.parse_url_list(file_path, 'katana')

    def parse_spideyx(self, file_path: str) -> List[Dict[str, str]]:
        """Parse SpideyX output"""
        results = []
        for line in self.iter_lines(file_path):
            match = self._URL_RE.search(line)
            if match:
                results.append({'url': match.group(1), 'source_tool': 'spideyx'})
        return results

    def parse_gospider(self, file_path: str) -> List[Dict[str, str]]:
        """Parse gospider output"""
        results = []
        for line in self.iter_lines(file_path):
            # Gospider format: [SOURCE] - [CODE] - URL
            match = self._URL_RE.search(line)
            if match:
                results.append({'url': match.group(1), 'source_tool': 'gospider'})
        return results


# Mapping of filename -> source_tool for URL parsers
URL_TOOL_PARSERS = {
    'gau.txt': 'gau',
    'waybackurls.txt': 'waybackurls',
    'hakrawler.txt': 'hakrawler',
    'katana.txt': 'katana',
    'spideyx.txt': 'spideyx',
    'gospider.txt': 'gospider',
}


class DirectoryParser(OutputParser):
    """Parse directory brute-forcing tool outputs"""

    def parse_ffuf(self, file_path: str) -> List[Dict[str, str]]:
        """Parse ffuf JSON output"""
        data = self.read_json(file_path)
        results = []
        for item in data:
            # Handle both raw dict and wrapped formats
            entries = item.get('results', []) if isinstance(item, dict) else []
            for entry in entries:
                if 'url' in entry:
                    results.append({
                        'url': entry['url'],
                        'source_tool': 'ffuf',
                        'status': str(entry.get('status', ''))
                    })
        return results

    def parse_feroxbuster(self, file_path: str) -> List[Dict[str, str]]:
        """Parse feroxbuster output"""
        results = []
        for line in self.iter_lines(file_path):
            # Format: STATUS   SIZE   URL
            match = re.match(r'(\d{3})\s+\S+\s+(https?://\S+)', line)
            if match:
                results.append({
                    'url': match.group(2),
                    'source_tool': 'feroxbuster',
                    'status': match.group(1)
                })
        return results

    def parse_dirsearch(self, file_path: str) -> List[Dict[str, str]]:
        """Parse dirsearch output"""
        results = []
        for line in self.iter_lines(file_path):
            # Format: STATUS - SIZE - URL
            match = re.search(r'(\d{3})\s+.*?(https?://\S+)', line)
            if match:
                results.append({
                    'url': match.group(2),
                    'source_tool': 'dirsearch',
                    'status': match.group(1)
                })
        return results


class VulnerabilityParser(OutputParser):
    """Parse vulnerability scanner outputs"""

    def parse_nuclei(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Nuclei JSON output (JSONL format)"""
        results = []
        for entry in self.iter_jsonl(file_path):
            if 'info' in entry:
                results.append({
                    'tool': 'nuclei',
                    'host': entry.get('host', entry.get('matched-at', '')),
                    'name': entry['info'].get('name', 'Unknown'),
                    'severity': entry['info'].get('severity', 'info'),
                    'info': entry.get('description', entry['info'].get('description', '')),
                    'cve': ','.join(entry['info'].get('classification', {}).get('cve-id', []))
                })
        return results

    def parse_dalfox(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Dalfox output"""
        results = []
        for line in self.iter_lines(file_path):
            if '[V]' in line or 'VULN' in line.upper():
                match = self._URL_RE.search(line)
                if match:
                    results.append({
                        'tool': 'dalfox',
                        'host': self.extract_domain(match.group(1)),
                        'name': 'XSS Vulnerability',
                        'severity': 'high',
                        'info': line
                    })
        return results

    def parse_sqlmap(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse SQLMap output"""
        results = []
        current_url = None

        for line in self.iter_lines(file_path):
            if 'URL:' in line:
                match = re.search(r'URL:\s*(https?://[^\s]+)', line)
                if match:
                    current_url = match.group(1)
            elif 'vulnerable' in line.lower() and current_url:
                results.append({
                    'tool': 'sqlmap',
                    'host': self.extract_domain(current_url),
                    'name': 'SQL Injection',
                    'severity': 'critical',
                    'info': line
                })
        return results

    def parse_corsy(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Corsy output"""
        results = []
        for line in self.iter_lines(file_path):
            if 'vulnerable' in line.lower() or 'misconfigured' in line.lower():
                match = self._URL_RE.search(line)
                if match:
                    results.append({
                        'tool': 'corsy',
                        'host': self.extract_domain(match.group(1)),
                        'name': 'CORS Misconfiguration',
                        'severity': 'medium',
                        'info': line
                    })
        return results


class LeakParser(OutputParser):
    """Parse leak detection tool outputs"""

    def parse_gitleaks(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Gitleaks JSON output"""
        data = self.read_json(file_path)
        results = []
        for entry in data:
            results.append({
                'leak_type': 'Git',
                'url': entry.get('File', entry.get('file', '')),
                'info': f"{entry.get('RuleID', entry.get('Description', 'Secret found'))}: {entry.get('Secret', entry.get('Match', ''))}",
                'severity': 'high'
            })
        return results

    def parse_secretfinder(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse SecretFinder output"""
        results = []
        for line in self.iter_lines(file_path):
            match = self._URL_RE.search(line)
            if match:
                results.append({
                    'leak_type': 'JS_Secret',
                    'url': match.group(1),
                    'info': line,
                    'severity': 'medium'
                })
        return results

    def parse_linkfinder(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse LinkFinder output"""
        results = []
        for line in self.iter_lines(file_path):
            if 'api' in line.lower() or 'key' in line.lower() or 'secret' in line.lower():
                results.append({
                    'leak_type': 'JS_Secret',
                    'url': '',
                    'info': line,
                    'severity': 'info'
                })
        return results


class TakeoverParser(OutputParser):
    """Parse subdomain takeover tool outputs"""

    def parse_subjack(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Subjack output"""
        results = []
        for line in self.iter_lines(file_path):
            if 'vulnerable' in line.lower() or 'takeover' in line.lower():
                match = re.search(r'\[([^\]]+)\]', line)
                subdomain = match.group(1) if match else ''
                results.append({
                    'tool': 'subjack',
                    'host': subdomain,
                    'name': 'Subdomain Takeover',
                    'severity': 'high',
                    'info': line
                })
        return results


# Factory function to get appropriate parser
def get_parser(tool_name: str):
    """Get parser instance based on tool name"""
    parsers = {
        'subdomain': SubdomainParser(),
        'http': HttpParser(),
        'dns': DnsParser(),
        'port': PortParser(),
        'url': UrlParser(),
        'directory': DirectoryParser(),
        'vulnerability': VulnerabilityParser(),
        'leak': LeakParser(),
        'takeover': TakeoverParser()
    }
    return parsers.get(tool_name)
