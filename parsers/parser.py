#!/usr/bin/env python3
"""
ReconX Output Parsers
Parses output from various reconnaissance tools into structured data
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import xml.etree.ElementTree as ET


class OutputParser:
    """Base parser class with common parsing utilities"""

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
    def read_json(file_path: str) -> List[Dict[str, Any]]:
        """Read JSON file (supports JSONL format)"""
        results = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
                if not content:
                    return []

                # Try parsing as JSON array first
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
        # Remove protocol
        text = re.sub(r'^https?://', '', text)
        # Extract domain
        match = re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', text)
        return match.group(0) if match else None

    @staticmethod
    def is_valid_subdomain(subdomain: str) -> bool:
        """Validate subdomain format"""
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, subdomain))


class SubdomainParser(OutputParser):
    """Parse subdomain enumeration tool outputs"""

    def parse_generic_list(self, file_path: str, source_tool: str) -> List[Dict[str, str]]:
        """Parse generic subdomain list (one per line)"""
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
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
        data = self.read_json(file_path)
        results = []
        for entry in data:
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
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
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
        data = self.read_json(file_path)
        results = []
        for entry in data:
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
        lines = self.read_lines(file_path)
        results = []
        current_host = None

        for line in lines:
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

    def parse_gau(self, file_path: str) -> List[Dict[str, str]]:
        """Parse gau output"""
        lines = self.read_lines(file_path)
        return [{'url': line, 'source_tool': 'gau'} for line in lines if line.startswith('http')]

    def parse_waybackurls(self, file_path: str) -> List[Dict[str, str]]:
        """Parse waybackurls output"""
        lines = self.read_lines(file_path)
        return [{'url': line, 'source_tool': 'waybackurls'} for line in lines if line.startswith('http')]

    def parse_hakrawler(self, file_path: str) -> List[Dict[str, str]]:
        """Parse hakrawler output"""
        lines = self.read_lines(file_path)
        return [{'url': line, 'source_tool': 'hakrawler'} for line in lines if line.startswith('http')]

    def parse_katana(self, file_path: str) -> List[Dict[str, str]]:
        """Parse katana output"""
        lines = self.read_lines(file_path)
        return [{'url': line, 'source_tool': 'katana'} for line in lines if line.startswith('http')]

    def parse_spideyx(self, file_path: str) -> List[Dict[str, str]]:
        """Parse SpideyX output"""
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
            match = re.search(r'(https?://[^\s]+)', line)
            if match:
                results.append({'url': match.group(1), 'source_tool': 'spideyx'})
        return results

    def parse_gospider(self, file_path: str) -> List[Dict[str, str]]:
        """Parse gospider output"""
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
            # Gospider format: [SOURCE] - [CODE] - URL
            match = re.search(r'(https?://[^\s]+)', line)
            if match:
                results.append({'url': match.group(1), 'source_tool': 'gospider'})
        return results


class DirectoryParser(OutputParser):
    """Parse directory brute-forcing tool outputs"""

    def parse_ffuf(self, file_path: str) -> List[Dict[str, str]]:
        """Parse ffuf JSON output"""
        data = self.read_json(file_path)
        results = []
        if 'results' in data:
            for entry in data['results']:
                if 'url' in entry:
                    results.append({
                        'url': entry['url'],
                        'source_tool': 'ffuf',
                        'status': str(entry.get('status', ''))
                    })
        return results

    def parse_feroxbuster(self, file_path: str) -> List[Dict[str, str]]:
        """Parse feroxbuster output"""
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
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
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
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
        """Parse Nuclei JSON output"""
        data = self.read_json(file_path)
        results = []
        for entry in data:
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
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
            if '[V]' in line or 'VULN' in line.upper():
                match = re.search(r'(https?://[^\s]+)', line)
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
        lines = self.read_lines(file_path)
        results = []
        current_url = None

        for line in lines:
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
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
            if 'vulnerable' in line.lower() or 'misconfigured' in line.lower():
                match = re.search(r'(https?://[^\s]+)', line)
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
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
            match = re.search(r'(https?://[^\s]+)', line)
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
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
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
        lines = self.read_lines(file_path)
        results = []
        for line in lines:
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
