"""
Mock data for Technieum unit and integration tests.

Each constant mirrors the real output format produced by the corresponding
external tool so that parser tests can run without any tools installed.
"""

import json

# ---------------------------------------------------------------------------
# Subdomain / alive-host mock data
# ---------------------------------------------------------------------------

MOCK_SUBDOMAINS = [
    {"host": "www.example.com", "ip": "93.184.216.34", "is_alive": True, "status_code": 200, "source_tool": "httpx"},
    {"host": "api.example.com", "ip": "93.184.216.34", "is_alive": True, "status_code": 200, "source_tool": "subfinder"},
    {"host": "mail.example.com", "ip": "93.184.216.35", "is_alive": False, "status_code": None, "source_tool": "amass"},
    {"host": "dev.example.com", "ip": None, "is_alive": False, "status_code": None, "source_tool": "subfinder"},
]

MOCK_ALIVE_HOSTS = [s for s in MOCK_SUBDOMAINS if s["is_alive"]]

# ---------------------------------------------------------------------------
# Port / service mock data
# ---------------------------------------------------------------------------

MOCK_PORTS = [
    {"host": "www.example.com", "port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.24"},
    {"host": "www.example.com", "port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.24"},
    {"host": "api.example.com", "port": 443, "protocol": "tcp", "service": "https", "version": ""},
]

# ---------------------------------------------------------------------------
# URL mock data
# ---------------------------------------------------------------------------

MOCK_URLS = [
    {"url": "https://www.example.com/", "status": "200", "source_tool": "katana"},
    {"url": "https://www.example.com/login", "status": "200", "source_tool": "katana"},
    {"url": "https://api.example.com/v1/users", "status": "200", "source_tool": "gau"},
]

# ---------------------------------------------------------------------------
# Vulnerability mock data
# ---------------------------------------------------------------------------

MOCK_VULNS = [
    {"host": "www.example.com", "tool": "nuclei", "severity": "critical", "name": "Log4Shell RCE", "cve": "CVE-2021-44228", "description": "Remote code execution via Log4j"},
    {"host": "api.example.com", "tool": "nuclei", "severity": "high", "name": "SQL Injection", "cve": None, "description": "SQLi in /v1/search endpoint"},
    {"host": "www.example.com", "tool": "dalfox", "severity": "medium", "name": "Reflected XSS", "cve": None, "description": "XSS in search param"},
]

# ---------------------------------------------------------------------------
# Leak mock data
# ---------------------------------------------------------------------------

MOCK_LEAKS = [
    {"leak_type": "api_key", "url": "https://www.example.com/app.js", "info": "AWS_ACCESS_KEY_ID=AKIA...", "severity": "critical"},
    {"leak_type": "email", "url": "https://www.example.com/contact", "info": "admin@example.com", "severity": "info"},
]

# ---------------------------------------------------------------------------
# Raw file content strings (written to disk for parser tests)
# ---------------------------------------------------------------------------

# subfinder plain-text output
MOCK_SUBFINDER_OUTPUT = "\n".join([
    "www.example.com",
    "api.example.com",
    "mail.example.com",
    "dev.example.com",
])

# httpx JSONL output (one JSON object per line).
# The IP field in real httpx JSON output is "a" (A-record), not "ip".
MOCK_HTTPX_OUTPUT = "\n".join([
    json.dumps({"url": "https://www.example.com", "host": "www.example.com",
                "a": ["93.184.216.34"], "status_code": 200, "input": "www.example.com"}),
    json.dumps({"url": "https://api.example.com", "host": "api.example.com",
                "a": ["93.184.216.34"], "status_code": 200, "input": "api.example.com"}),
])

# nmap XML output (minimal)
MOCK_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames><hostname name="www.example.com" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# ffuf JSON output (single results wrapper)
MOCK_FFUF_OUTPUT = json.dumps([{
    "results": [
        {"url": "https://www.example.com/admin", "status": 200, "length": 1024},
        {"url": "https://www.example.com/api", "status": 301, "length": 0},
    ]
}])

# nuclei JSONL output
MOCK_NUCLEI_OUTPUT = "\n".join([
    json.dumps({
        "template-id": "log4shell-rce",
        "info": {"name": "Log4Shell RCE", "severity": "critical"},
        "matched-at": "https://www.example.com",
        "host": "www.example.com",
        "curl-command": "",
    }),
    json.dumps({
        "template-id": "sqli-generic",
        "info": {"name": "SQL Injection", "severity": "high"},
        "matched-at": "https://api.example.com/v1/search?q=test",
        "host": "api.example.com",
        "curl-command": "",
    }),
])

# gau plain-text URL output
MOCK_GAU_OUTPUT = "\n".join([row["url"] for row in MOCK_URLS])

# katana plain-text URL output
MOCK_KATANA_OUTPUT = MOCK_GAU_OUTPUT

# trufflehog / gitleaks-style secret output (plain text, one per line)
MOCK_TRUFFLEHOG_OUTPUT = "Found API key: AWS_ACCESS_KEY_ID=AKIA... in https://www.example.com/app.js"

MOCK_FILES = {
    "subfinder.txt": MOCK_SUBFINDER_OUTPUT,
    "httpx.jsonl": MOCK_HTTPX_OUTPUT,
    "nmap_all.xml": MOCK_NMAP_XML,
    "ffuf_all.json": MOCK_FFUF_OUTPUT,
    "nuclei_all.json": MOCK_NUCLEI_OUTPUT,
    "gau.txt": MOCK_GAU_OUTPUT,
    "katana.txt": MOCK_KATANA_OUTPUT,
    "trufflehog.txt": MOCK_TRUFFLEHOG_OUTPUT,
}
