# Technieum: Complete Attack Surface Mapping Tool

**Version:** 1.0  
**Status:** Production Ready (CLI)  
**Last Updated:** February 2026

---

## What is Technieum?

Technieum is an automated attack surface mapping and reconnaissance platform designed for security professionals who need to understand everything about a target organization's digital footprint. Instead of manually running dozens of different security scanning tools and trying to piece together the results, Technieum does all the heavy lifting automatically.

Think of Technieum as your personal security intelligence agent. You give it a domain name, and it goes to work discovering everything about that target: all the subdomains, which ones are actually live, what services are running, what ports are open, what vulnerabilities exist, and where sensitive data might be exposed.

It's designed for:
- **Security Teams** conducting comprehensive assessments
- **Penetration Testers** who need fast reconnaissance
- **Security Researchers** studying attack surfaces
- **Organizations** monitoring their own digital footprint
- **Bug Bounty Hunters** finding vulnerabilities at scale

---

## How Technieum Works: The Four-Phase Approach

Technieum breaks down the reconnaissance process into four logical phases, each building on the previous one:

### Phase 1: Discovery
**What it does:** Finds all possible subdomains and hostnames belonging to a target.

When you ask Technieum to scan `example.com`, this phase discovers things like:
- `api.example.com`
- `admin.example.com`
- `staging.example.com`
- `cdn.example.com`
- And potentially hundreds more

The tool uses multiple methods to ensure nothing is missed:
- **Passive discovery** using Certificate Transparency logs (finds domains from historical SSL certificates)
- **Subdomain enumeration** that searches public databases
- **DNS brute-forcing** to guess possible subdomains
- **WHOIS lookups** for organization information
- **ASIC research** to understand the company's network infrastructure

**Current Status:** ✅ Fully working and automated

### Phase 2: Intelligence Gathering
**What it does:** Validates which discovered subdomains are actually active and running services.

From the thousands of possible subdomains found in Phase 1, many might be dead (pointing nowhere) or inactive. This phase separates the live targets from the dead ones, then probes them to understand:
- **Alive hosts:** Which servers are actually responding
- **Open ports:** What services are running on each host (HTTP, HTTPS, DNS, etc.)
- **IP addresses:** The actual servers behind domain names
- **Response analysis:** Whether a host redirects to another location, is blocked, or is fully accessible

This phase is crucial because it dramatically reduces the scope of actual targets while providing detailed insight into architecture.

**Current Status:** ✅ Fully working and automated

### Phase 3: Content Discovery
**What it does:** Maps the web applications, endpoints, and files available on discovered services.

Now that we know what's running, we need to find what's accessible:
- **Web crawling:** Automatically follows links to discover web pages and endpoints
- **Directory brute-forcing:** Tests common paths like `/admin`, `/api`, `/config`, `/backup`
- **JavaScript analysis:** Examines JavaScript code found in web pages for hidden API endpoints
- **Parameter discovery:** Finds input fields and API parameters
- **File discovery:** Locates backing up files, configuration files, and other potentially sensitive items
- **Web archive searching:** Finds historical versions of websites using the Wayback Machine

This reveals the actual "attack surface" – the specific things an attacker can interact with.

**Current Status:** ✅ Fully working and automated

### Phase 4: Vulnerability Scanning
**What it does:** Tests discovered content and endpoints for security vulnerabilities.

With a complete map of what's accessible, this phase looks for actual security problems:
- **Web vulnerabilities:** XSS, SQL injection, CSRF, insecure deserialization
- **Misconfigurations:** Default credentials, exposed configurations, insecure headers
- **Open source risks:** Known vulnerabilities in libraries and frameworks
- **API flaws:** Broken authentication, data exposure, rate limiting bypass
- **Infrastructure weaknesses:** Unpatched services, outdated software versions

**Current Status:** ✅ Fully working and automated

---

## What's Currently Working (Today)

### Complete Automation
You can run Technieum with a single command and it automatically executes all four phases, managing:
- Parallel execution of multiple tools to save time
- Intelligent sequencing of phases (you can't scan for vulnerabilities until you know what exists)
- Automatic retry and error recovery if a tool fails
- Continuation from the last successful phase if interrupted
- Proper cleanup and result aggregation

### 50+ Integrated Tools
Technieum orchestrates over 50 specialized security tools, including:

**Discovery Tools:**
- Subfinder (fast subdomain enumeration)
- Amass (intelligence-driven enumeration)
- assetfinder (comma-separated comma-separated discovery)
- Certificate Transparency logs (historical SSL data)
- crt.sh (public certificate database)
- WHOIS lookups
- DNS enumeration

**Validation Tools:**
- HTTPx (HTTP probing)
- DNSx (DNS validation)
- Nmap (port scanning)
- RustScan (faster port scanning)
- Masscan (ultra-fast scanning)

**Content Discovery Tools:**
- GAU (URI finder using Google, Wayback Machine, Common Crawl)
- Katana (powerful web crawler)
- FFUF (fast fuzzing tool)
- Dirsearch (directory brute-forcing)
- Feroxbuster (recursive content discovery)
- JavaScript Parser (API endpoint discovery)
- Waybackurls (historical endpoint discovery)

**Vulnerability Scanning Tools:**
- Nuclei (multi-purpose vulnerability scanner)
- Dalfox (XSS-focused scanner)
- SQLMap (SQL injection detection)
- Corsy (CORS misconfiguration finder)
- Gitleaks (exposed secrets detector)
- TruffleHog (secret scanning)

Plus many more specialized tools for specific vulnerability types.

### Intelligent Database
All results are stored in a local SQLite database rather than scattered logs. This means:
- **Persistent storage:** Results are saved permanently, not lost when you close the tool
- **Searchability:** Query specific results (`find all subdomains on port 443`)
- **Deduplication:** Same finding from multiple tools is recorded once
- **Relationships:** Subdomains linked to ports, which link to vulnerabilities
- **Analytics:** Understand patterns and trends across scans

### Command-Line Query Interface
Results are accessible through an intuitive CLI:
- **List all discovered subdomains:** `python3 query.py -t example.com --subdomains`
- **Find all open ports:** `python3 query.py -t example.com --ports`
- **Show all vulnerabilities:** `python3 query.py -t example.com --vulnerabilities`
- **Export to CSV:** `python3 query.py -t example.com --export`
- **Summary view:** `python3 query.py -t example.com --summary`

### Flexible Scanning Options
- **Individual phases:** Run just Phase 1 to find subdomains, or just Phase 4 to scan known targets
- **Multiple targets:** Scan dozens of domains in a single batch
- **Resume capability:** If interrupted, resume from where you left off
- **Custom configuration:** Control which tools run, timeouts, aggressiveness levels

### Transparent Results
All data is stored locally, accessible at any time:
- Raw output from each tool is preserved
- Parsed, structured data in the database
- No external service dependencies
- No cloud calls (completely offline after download)
- Your data stays on your machine

---

## What's Planned (Phase A - MVP Enhancement)

In the next phase of development (estimated 2-3 weeks of dedicated development), the tool will gain:

### REST API
A modern API will allow:
- **Programmatic access:** Integrate Technieum with other security tools
- **Scan automation:** Create, manage, and retrieve scans via API
- **Data access:** Query results in JSON format for custom dashboards
- **Cloud readiness:** Deploy in cloud environments with standard API patterns
- **Integration hooks:** Connect with ticketing systems and SOAR platforms

Example future usage: Instead of command-line only, you could run:
- Create a scan: `POST /api/scans` with target domain
- Get results: `GET /api/scans/{id}/subdomains`
- Export data: `GET /api/scans/{id}/export`

### Web Dashboard
A browser-based interface replacing the command-line:
- **Visual overview:** See all targets at a glance
- **Interactive maps:** Visualize the attack surface
- **Real-time progress:** Watch scans execute in real-time
- **Filtered views:** Focus on high-risk findings
- **Report generation:** Create custom PDF/HTML reports
- **Multi-report comparison:** Compare results across multiple scans

### Professional Reports
Automated report generation in multiple formats:
- **PDF Reports:** Management-friendly summaries with findings and recommendations
- **HTML Reports:** Interactive reports for sharing with stakeholders
- **CSV Export:** Data-scientist friendly formats for analysis
- **Executive Summary:** High-level overview for decision-makers
- **Technical Details:** In-depth findings with evidence

### Docker Containerization
Easy deployment anywhere:
- **Container image:** Deploy Technieum as a Docker container
- **Compose setup:** Run with supporting services easily
- **Cloud deployment:** Ready for Kubernetes, AWS, Azure, GCP
- **Isolated environment:** No dependencies conflicts with your system
- **Reproducible:** Same results everywhere

### Scheduled Scanning (Phase B)
Continuous monitoring capabilities:
- **Recurring scans:** Schedule daily, weekly, or monthly scans automatically
- **Change detection:** Get alerts when new vulnerabilities appear
- **Trend tracking:** Track vulnerability counts over time
- **Alert system:** Notifications via Slack, Discord, Email, Teams
- **Alert rules:** Custom rules like "alert only critical vulnerabilities"

---

## Why Technieum is Different

### Comprehensive by Default
Unlike most tools that focus on one aspect (just subdomain finding, or just port scanning), Technieum handles the entire reconnaissance workflow in one place with proper tool selection for each phase.

### Tool Redundancy
For critical tasks, Technieum uses multiple tools:
- **5 subdomain enumeration tools** ensure nothing is missed
- **3 port scanning approaches** for thorough validation
- **4 content discovery methods** to find all endpoints
- **Multiple vulnerability scanners** for different attack types

If one tool breaks or fails, others complete the task. You don't get stuck.

### Intelligent Orchestration
Tools are smartly sequenced:
- You can't scan for vulnerabilities until you know what exists
- You can't brute-force directories until you validate hosts are live
- Results feed forward, reducing redundant work and tool conflicts

### Local and Permanent
- All results stored in a database, not temporary logs
- No external service dependencies
- No phoning home or cloud uploads
- Your scan history is preserved permanently

### Actually Finds Things
Through bug bounty hunting and real-world testing, Technieum has been proven to:
- Discover hidden subdomains competitors miss
- Find live hosts with useful vulnerabilities
- Locate exposed credentials and secrets
- Identify security misconfigurations

---

## Getting Started

### Installation (Quick Version)
```
1. Install dependencies: bash setup.sh
2. Install Python packages: pip3 install -r requirements.txt
3. Set API keys: Edit config.yaml with your tool credentials
4. Run first scan: python3 technieum.py -t yourtarget.com
```

### Your First Scan
```
python3 technieum.py -t example.com
```

This automatically:
1. Discovers all subdomains
2. Validates which are live
3. Maps accessible web content
4. Scans for vulnerabilities
5. Stores everything in the database

Then query results:
```
python3 query.py -t example.com --summary
python3 query.py -t example.com --subdomains
python3 query.py -t example.com --vulnerabilities
```

### Configuration
The tool works out of the box, but you can customize:
- **Which tools to run** (if you don't need certain tools)
- **Scanning intensity** (fast vs. thorough)
- **API keys** for tools that require authentication
- **Output formats** (CSV, JSON, etc.)
- **Timeout values** for different phases

---

## Common Use Cases

### 1. Security Assessment
A security team wants to assess a company's external security posture before beginning a penetration test. Technieum provides the complete attack surface map without manual reconnaissance.

### 2. Startup Security Program
A startup with limited security staff uses Technieum monthly to monitor their growing infrastructure and catch new security issues as they come online.

### 3. Acquisition Due Diligence
During M&A, security teams need to quickly understand the target company's infrastructure. Technieum provides a complete picture.

### 4. Bug Bounty Hunting
A researcher scans targets on bug bounty platforms to find the attack surface others might miss.

### 5. Red Team Assessment
Simulating attackers requires understanding the full attack surface. Technieum provides that baseline in hours instead of weeks.

### 6. Compliance Verification
Organizations verify that their infrastructure changes haven't introduced unexpected exposure.

---

## Capability Summary

| Capability | Status | Details |
|-----------|--------|---------|
| **Multi-tool orchestration** | ✅ Working | 50+ tools coordinated automatically |
| **Phase-based execution** | ✅ Working | 4 phases executed in proper sequence |
| **Subdomain discovery** | ✅ Working | 5 enumeration tools, very comprehensive |
| **Live validation** | ✅ Working | Identifies which hosts are actually up |
| **Content discovery** | ✅ Working | Maps all accessible web endpoints |
| **Vulnerability scanning** | ✅ Working | Multiple vulnerability scanners |
| **Data persistence** | ✅ Working | Database storage, permanent results |
| **CLI querying** | ✅ Working | Command-line interface for results |
| **Resume capability** | ✅ Working | Pick up where you left off |
| **REST API** | 🔄 Planned | Phase A: Programmatic access to everything |
| **Web dashboard** | 🔄 Planned | Phase A: Browser-based UI |
| **Report generation** | 🔄 Planned | Phase A: PDF/HTML/CSV reports |
| **Docker support** | 🔄 Planned | Phase A: Container deployment |
| **Scheduled scanning** | 🔄 Planned | Phase B: Recurring scans with alerts |

---

## What You Get Today

Right now, you have a powerful command-line tool that:
- Automatically orchestrates 50+ security tools
- Finds your complete attack surface in hours
- Stores results in a searchable database
- Provides detailed insights into your security posture
- Runs completely locally on your machine
- Requires no complex setup or cloud dependencies

It's battle-tested, production-ready, and actively used for real security assessments.

---

## What's Coming Next

The planned Phase A enhancements will transform Technieum from a powerful command-line tool into a complete platform with:
- Web interface for easier use
- REST API for integration
- Professional report generation
- Docker containerization
- Scheduled scanning

This foundation then enables future phases (B, C, D) with:
- Advanced alerting and notifications
- Multi-user access and role-based permissions
- Enterprise integrations (Jira, ServiceNow, etc.)
- Distributed scanning architecture
- Custom plugin system

---

## Support and Resources

### Getting Help
- Check the troubleshooting section for common issues
- Review example commands in the quick reference
- Check the FAQ for frequently asked questions
- Examine the database schema if you want to query results directly

### Learning More
- Read the technical architecture documentation for deep dives
- Study the tools list to understand what each tool does
- Review the four-phase workflow documentation for details on each step

### Contributing
Technieum is designed to be extended:
- Add custom tools to any phase
- Write custom parsers for tool outputs
- Build custom queries against the database
- Create automation workflows

### License
Technieum is provided under the MIT License. Use freely in your security work.

---

## The Vision

Technieum exists because security teams spend too much time on manual reconnaissance. By automating this critical-but-repetitive task and providing a unified interface to 50+ tools, more time can be spent on actual analysis and remediation.

The planned enhancements (API, Dashboard, Reports, Scheduling) transform it from a personal tool into a team platform, enabling organizations of any size to maintain awareness of their complete attack surface.

Whether you're a lone penetration tester running reconnaissance on a target, a security team assessing multiple applications, or an organization monitoring your own infrastructure, Technieum provides the fastest path from "what do we need to assess?" to "here's what we need to fix."

---

## Quick Command Reference

```
# Scan a target
python3 technieum.py -t example.com

# Run specific phases only
python3 technieum.py -t example.com --phases 1,2

# Scan multiple targets
python3 technieum.py -t example.com,other.com,third.com

# Resume interrupted scan
python3 technieum.py -t example.com --resume

# Query: Get summary
python3 query.py -t example.com --summary

# Query: List subdomains
python3 query.py -t example.com --subdomains

# Query: List vulnerabilities
python3 query.py -t example.com --vulnerabilities

# Query: Export to CSV
python3 query.py -t example.com --export csv

# Query: Find by port
python3 query.py -t example.com --port 443
```

---

## Current System Requirements

- **Python:** 3.11 or higher
- **Operating System:** Linux or macOS (tested primarily on these; Windows requires bash)
- **Disk Space:** 2 GB minimum for results database, tool installations
- **Network:** Active internet connection (tools download data from public sources)
- **Tools:** 50+ security tools automatically installed during setup

---

## The Bottom Line

Technieum makes reconnaissance fast, comprehensive, and automated. What used to take weeks of manual work can now be done in hours. The four-phase approach ensures nothing is missed, while the comprehensive tool suite provides coverage across all major reconnaissance techniques.

You get all the power of enterprise security tools without the enterprise price tag or complexity. Deploy it locally, run your scans, and own your security assessment process.

Ready to map your attack surface? Start with a single scan and see what Technieum discovers.

---

**Questions?** Refer to the expanded documentation in the project for technical details, phase workflows, tool descriptions, and development roadmap.

**Want to contribute?** Check the contributing guide for how to extend Technieum with custom tools and parsers.

**Ready to upgrade?** Check Phase A planning documents for REST API, dashboard, and enterprise features coming soon.
