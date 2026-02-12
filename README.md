# ReconX - Attack Surface Management Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux-red.svg" alt="Platform">
</p>

**ReconX** is a comprehensive, database-driven Attack Surface Management (ASM) framework designed for maximum coverage through tool redundancy. It orchestrates over **50+ reconnaissance and vulnerability assessment tools** across 4 distinct phases to provide complete visibility into your attack surface.

## 🎯 Features

- **Comprehensive Coverage**: Utilizes ALL major reconnaissance tools for maximum discovery
- **Database-Driven**: SQLite3 with WAL mode for efficient data storage and querying
- **Modular Architecture**: Bash modules for tool execution, Python for orchestration
- **Multi-Threading**: Concurrent scanning of multiple targets
- **Resume Capability**: Track progress and resume incomplete scans
- **Automated Parsing**: Intelligent parsing of diverse tool outputs
- **Phase-Based Execution**: Run specific phases or complete workflows

## 📋 Table of Contents

- [Architecture](#architecture)
- [Tool Coverage](#tool-coverage)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Phases](#phases)
- [Database Schema](#database-schema)
- [Examples](#examples)
- [API Keys](#api-keys)
- [Contributing](#contributing)
- [License](#license)

## 🏗️ Architecture

```
ReconX/
├── reconx.py              # Main orchestrator
├── db/
│   └── database.py        # Database manager (Singleton, WAL mode)
├── modules/
│   ├── 01_discovery.sh    # Phase 1: Discovery & Enumeration
│   ├── 02_intel.sh        # Phase 2: Intelligence & Infrastructure
│   ├── 03_content.sh      # Phase 3: Deep Web & Content Discovery
│   └── 04_vuln.sh         # Phase 4: Vulnerability Scanning
├── parsers/
│   └── parser.py          # Tool output parsers
├── output/                # Scan results (organized by target)
├── logs/                  # Application logs
├── config.yaml            # Configuration file
└── install.sh             # Installation script
```

**Controller**: Python 3.11+ (Orchestration, Database, Logic)
**Executors**: Modular Bash scripts (Tool execution and chaining)
**Database**: SQLite3 with WAL mode (State tracking and results)

## 🛠️ Tool Coverage

ReconX implements **ALL** of the following tools across 4 phases:

### Phase 1: Discovery & Enumeration

**Horizontal Discovery (Acquisitions)**:
- Whois
- Amass (Intel mode)
- getSubsidiaries

**Vertical Discovery (Subdomains)**:
- Sublist3r
- OWASP Amass (Enum mode)
- Assetfinder
- Subfinder
- SubDominator
- crt.sh
- SecurityTrails API
- Dnsbruter
- Dnsprober

**Validation**:
- DNSx (Resolution)
- HTTPx (Live checking)

### Phase 2: Intelligence & Infrastructure

**Validation**:
- SubProber

**Port Scanning**:
- RustScan (Fast scan)
- Nmap (Deep scan with service detection)

**OSINT & Infrastructure**:
- Shodan CLI
- ShodanX
- Censys CLI
- ASN lookup

**Takeover Detection**:
- Subjack
- SubOver

**Repository Leaks**:
- Gitleaks
- GitHunt
- TruffleHog
- git-secrets

### Phase 3: Deep Web & Content Discovery

**Archive Crawling**:
- gau (GetAllUrls)
- waybackurls
- SpideyX/gospider
- hakrawler
- Katana

**Directory Brute-forcing**:
- ffuf
- Feroxbuster
- Dirsearch

**JavaScript Analysis**:
- LinkFinder
- SecretFinder
- JSScanner

**Pastebin Monitoring**:
- PasteHunter
- Pastebin API

**API Testing**:
- Newman (Postman CLI)
- Kiterunner
- Arjun

### Phase 4: Vulnerability Scanning

**Core Scanners**:
- Nuclei (All templates, all severities)

**Specific Vulnerabilities**:
- Dalfox (XSS)
- XSStrike
- SQLMap (SQL Injection)
- Corsy (CORS Misconfiguration)

**Additional Scanners**:
- Nikto (Web server)
- WPScan (WordPress)
- Wapiti (Web application)
- CMSmap (CMS detection)
- Retire.js (JavaScript libraries)

**SSL/TLS**:
- testssl.sh
- SSLyze

## 📦 Installation

### Requirements

- Linux (Kali, Debian, Ubuntu, Arch)
- Root/sudo access
- 20GB+ disk space
- 4GB+ RAM recommended

### Automated Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/reconx.git
cd reconx

# Run installation script (as root)
sudo bash install.sh
```

The installation script will:
1. Install system packages (Python, Go, Rust, etc.)
2. Install all Go-based tools
3. Install Rust-based tools
4. Clone and setup Python-based tools
5. Install wordlists (SecLists)
6. Verify installation

### Manual Installation

See `install.sh` for the complete list of commands to install tools manually.

## ⚙️ Configuration

### 1. API Keys

Create a `.env` file in the ReconX directory:

```bash
# Shodan
export SHODAN_API_KEY="your_shodan_key"

# Censys
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"

# GitHub
export GITHUB_TOKEN="your_github_token"

# SecurityTrails
export SECURITYTRAILS_API_KEY="your_securitytrails_key"

# Pastebin
export PASTEBIN_API_KEY="your_pastebin_key"
```

Source the file before running:
```bash
source .env
```

### 2. Configuration File

Edit `config.yaml` to customize:
- Tool selection per phase
- Timeout values
- Thread counts
- Rate limits
- Wordlist paths
- Output preferences

## 🚀 Usage

### Basic Usage

```bash
# Full scan on single target
python3 reconx.py -t example.com

# Multiple targets
python3 reconx.py -t example.com,example.org

# From file
python3 reconx.py -f targets.txt

# Specific phases only
python3 reconx.py -t example.com -p 1,2

# Custom output directory
python3 reconx.py -t example.com -o results

# Multiple threads for concurrent targets
python3 reconx.py -f targets.txt -T 10
```

### Command-Line Options

```
usage: reconx.py [-h] [-t TARGET] [-f FILE] [-o OUTPUT] [-d DATABASE]
                 [-p PHASES] [-T THREADS] [--resume]

Options:
  -t, --target      Target domain(s), comma-separated
  -f, --file        File containing target domains (one per line)
  -o, --output      Output directory (default: output)
  -d, --database    Database file path (default: reconx.db)
  -p, --phases      Phases to run (default: 1,2,3,4)
  -T, --threads     Number of concurrent target scans (default: 5)
  --resume          Resume incomplete scans
```

## 📊 Phases

### Phase 1: Discovery & Enumeration

**Purpose**: Discover all subdomains and validate them

**Tools**: Sublist3r, Amass, Assetfinder, Subfinder, SubDominator, Dnsbruter, Dnsprober, DNSx, HTTPx

**Output**:
- `all_subdomains.txt` - All discovered subdomains
- `resolved_subdomains.txt` - DNS-resolved subdomains
- `alive_hosts.txt` - Live HTTP/HTTPS hosts
- `httpx_alive.json` - Detailed HTTPx results
- `dnsx_resolved.json` - Detailed DNSx results

**Duration**: 10-30 minutes (varies by target size)

### Phase 2: Intelligence & Infrastructure

**Purpose**: Port scanning, OSINT, takeover detection, leak scanning

**Tools**: RustScan, Nmap, Shodan, Censys, Subjack, Gitleaks, GitHunt

**Output**:
- Port scan results (XML, JSON)
- OSINT data (Shodan, Censys)
- Subdomain takeover results
- Git leak reports

**Duration**: 30-60 minutes

### Phase 3: Deep Web & Content Discovery

**Purpose**: URL discovery, directory brute-forcing, JS analysis

**Tools**: gau, waybackurls, gospider, hakrawler, Katana, ffuf, Feroxbuster, Dirsearch, LinkFinder, SecretFinder

**Output**:
- All discovered URLs
- Directory brute-force results
- JavaScript endpoints and secrets
- API endpoints

**Duration**: 45-90 minutes

### Phase 4: Vulnerability Scanning

**Purpose**: Comprehensive vulnerability assessment

**Tools**: Nuclei, Dalfox, SQLMap, Corsy, Nikto, WPScan, testssl.sh

**Output**:
- Nuclei vulnerabilities (JSON)
- XSS vulnerabilities
- SQL injection findings
- CORS misconfigurations
- SSL/TLS issues

**Duration**: 60-120 minutes

## 🗄️ Database Schema

ReconX uses SQLite3 with the following schema:

```sql
-- Scan Progress
scan_progress (target, phase1_done, phase2_done, phase3_done, phase4_done, started_at, updated_at)

-- Acquisitions
acquisitions (target, company, domain, discovered_at)

-- Subdomains
subdomains (target, host, ip, is_alive, status_code, source_tools, discovered_at)

-- Ports
ports (target, host, port, protocol, service, version, discovered_at)

-- URLs
urls (target, url, source_tool, discovered_at)

-- Leaks
leaks (target, leak_type, url, info, severity, discovered_at)

-- Vulnerabilities
vulnerabilities (target, host, tool, severity, name, info, cve, discovered_at)

-- Infrastructure
infrastructure (target, host, ip, asn, org, cloud_provider, cdn, technologies, discovered_at)
```

### Querying the Database

```bash
# Open database
sqlite3 reconx.db

# View all subdomains for a target
SELECT * FROM subdomains WHERE target = 'example.com';

# View critical vulnerabilities
SELECT * FROM vulnerabilities WHERE severity = 'critical';

# Get statistics
SELECT
    COUNT(*) as total_subdomains,
    SUM(is_alive) as alive_hosts
FROM subdomains
WHERE target = 'example.com';
```

## 📝 Examples

### Example 1: Quick Subdomain Discovery

```bash
# Run only Phase 1
python3 reconx.py -t example.com -p 1

# Check results
sqlite3 reconx.db "SELECT host FROM subdomains WHERE target='example.com' AND is_alive=1"
```

### Example 2: Full Security Assessment

```bash
# Run all phases
python3 reconx.py -t example.com

# Generate report
sqlite3 reconx.db << EOF
SELECT
    'Subdomains: ' || COUNT(DISTINCT host) FROM subdomains WHERE target='example.com'
UNION ALL
SELECT
    'Vulnerabilities: ' || COUNT(*) FROM vulnerabilities WHERE target='example.com'
UNION ALL
SELECT
    'Critical: ' || COUNT(*) FROM vulnerabilities WHERE target='example.com' AND severity='critical';
EOF
```

### Example 3: Multiple Targets

```bash
# Create targets file
cat > targets.txt << EOF
example.com
example.org
example.net
EOF

# Run with 3 concurrent threads
python3 reconx.py -f targets.txt -T 3
```

### Example 4: Resume Scan

```bash
# If scan was interrupted, resume it
python3 reconx.py -t example.com --resume
```

## 🔑 API Keys

Some tools require API keys for full functionality:

| Service | Required For | Get Key |
|---------|--------------|---------|
| Shodan | Infrastructure OSINT | https://account.shodan.io/ |
| Censys | Infrastructure OSINT | https://censys.io/register |
| GitHub | Repository scanning | https://github.com/settings/tokens |
| SecurityTrails | Enhanced subdomain enum | https://securitytrails.com/app/account/credentials |
| Pastebin | Pastebin monitoring | https://pastebin.com/doc_api |

## 📈 Output Structure

```
output/
└── example_com/
    ├── phase1_discovery/
    │   ├── all_subdomains.txt
    │   ├── alive_hosts.txt
    │   ├── httpx_alive.json
    │   └── dnsx_resolved.json
    ├── phase2_intel/
    │   ├── ports/
    │   │   ├── nmap_all.xml
    │   │   └── rustscan_ports.txt
    │   ├── osint/
    │   │   ├── shodan_all.txt
    │   │   └── censys_all.json
    │   ├── takeover/
    │   │   └── subjack_results.txt
    │   └── leaks/
    │       ├── gitleaks_report.json
    │       └── githunt_results.txt
    ├── phase3_content/
    │   ├── urls/
    │   │   ├── all_urls.txt
    │   │   └── javascript_files.txt
    │   ├── bruteforce/
    │   │   ├── ffuf_all.json
    │   │   └── feroxbuster_all.txt
    │   └── javascript/
    │       ├── linkfinder_endpoints.txt
    │       └── secretfinder_secrets.txt
    └── phase4_vulnscan/
        ├── nuclei/
        │   └── nuclei_all.json
        ├── xss/
        │   └── dalfox_results.txt
        └── sqli/
            └── sqlmap_results.txt
```

## 🐛 Troubleshooting

### Common Issues

**Issue**: Tools not found after installation
```bash
# Ensure PATH includes Go binaries
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin
source ~/.bashrc
```

**Issue**: Permission denied errors
```bash
# Make sure scripts are executable
chmod +x reconx.py modules/*.sh install.sh
```

**Issue**: Database locked
```bash
# WAL mode should prevent this, but if it occurs:
sqlite3 reconx.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

**Issue**: Rate limiting
```bash
# Edit config.yaml to reduce rate limits
# Or add delays between requests
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add your tool/feature
4. Update documentation
5. Submit a pull request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**IMPORTANT**: This tool is designed for **defensive security purposes only**.

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse or damage caused by this tool
- Always comply with applicable laws and regulations

## 🙏 Acknowledgments

ReconX integrates and orchestrates tools created by the security community:

- ProjectDiscovery team (Nuclei, Subfinder, HTTPx, Katana, etc.)
- OWASP (Amass)
- TomNomNom (waybackurls, assetfinder)
- And many other amazing security researchers

## 📞 Support

For issues, questions, or contributions:

- GitHub Issues: [Report a bug](https://github.com/yourusername/reconx/issues)
- Documentation: [Wiki](https://github.com/yourusername/reconx/wiki)

---

**Made with ❤️ by Security Researchers, for Security Researchers**

**Happy Hunting! 🎯**
