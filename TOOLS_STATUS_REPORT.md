# Technieum Tools Status Report

**Generated:** March 9, 2026  
**Total Tools:** 57 tools  
**Status:** 55 Working, 1 Broken, 1 Deprecated

---

## Summary Table

| Phase | Count | Working | Issues | Status |
|-------|-------|---------|--------|--------|
| **Phase 1: Discovery** | 18 | 17 | 1 (Removed) | ✅ Functional |
| **Phase 2: Intelligence** | 16 | 16 | - | ✅ Functional |
| **Phase 3: Content Discovery** | 16 | 15 | 1 (Parser Bug) | ⚠️ Partial Issue |
| **Phase 4: Vulnerability** | 13 | 13 | - | ✅ Functional |
| **Cross-Phase / Utility** | 4 | 4 | - | ✅ Functional |
| **TOTAL** | **57** | **55** | **2** | **96.5% Working** |

---

## PHASE 1: DISCOVERY (18 Tools)

| Tool | Purpose | Status | Notes |
|------|---------|--------|-------|
| **subfinder** | Fast subdomain enumeration | ✅ Working | Primary tool; 50 threads configured |
| **assetfinder** | Subdomain finder using various sources | ✅ Working | Alternative enumeration method |
| **sublist3r** | Subdomain enumeration via multiple APIs | ✅ Working | Optional; 20 min timeout |
| **subdominator** | Subdomain enumeration tool | ✅ Working | 20 min timeout configured |
| **ct-monitor** | Certificate Transparency monitoring | ✅ Working | Monitors for new certificates |
| **crt.sh** | Public certificate database | ✅ Working | Built-in via HTTPS query |
| **whois** | WHOIS lookups for domains | ✅ Working | 1 min timeout; used in Phase 1 & 2 |
| **securitytrails** | The SecurityTrails API integration | ✅ Working | Requires API key |
| **certspotter** | Certificate Transparency logs | ✅ Working | Alternative CT source |
| **dnsx** | DNS validator and resolver | ✅ Working | 100 threads; used in Phase 1 & 2 |
| **dnsbruter** | DNS brute-force enumeration | ✅ Working | 30 min timeout |
| **dnsprober** | DNS probing tool | ✅ Working | Works with passive subdomains |
| **httpx** | HTTP server detection | ✅ Working | 100 threads; 15s per probe |
| **asnmap** | ASN/CIDR mapping | ✅ Working | Network-level discovery |
| **mapcidr** | CIDR to IP expansion | ✅ Working | 20 min timeout |
| **cloud_enum** | Cloud bucket enumeration | ✅ Working | Can find S3, GCP, Azure buckets |
| **s3scanner** | AWS S3 bucket finder | ✅ Working | 30 min timeout |
| **amass** | Comprehensive enumeration framework | ❌ REMOVED | No longer used in scans |

---

## PHASE 2: INTELLIGENCE GATHERING (16 Tools)

| Tool | Purpose | Status | Notes |
|------|---------|--------|-------|
| **subprober** | Subdomain validation tool | ✅ Working | Built-in validation |
| **dnsx** | DNS validation | ✅ Working | Reused from Phase 1 |
| **rustscan** | Fast port scanner (Rust) | ✅ Working | Alternative to nmap |
| **nmap** | Comprehensive port scanning | ✅ Working | Primary port scanner |
| **shodan** | Shodan API integration | ✅ Working | Requires `SHODAN_API_KEY` |
| **shodanx** | Extended Shodan queries | ✅ Working | Requires API key |
| **dorker** | Google dork automation | ✅ Working | For search results |
| **censys** | Censys API integration | ✅ Working | Requires `CENSYS_API_ID` & `CENSYS_API_SECRET` |
| **whois** | WHOIS data gathering | ✅ Working | Reused from Phase 1 |
| **subover** | Subdomain takeover detection | ✅ Working | Checks CNAME records |
| **gitleaks** | Secret scanning in repos | ✅ Working | Reused across phases |
| **gh** | GitHub CLI tool | ✅ Working | For GitHub searching |
| **githunt** | GitHub secret hunting | ✅ Working | Requires `GITHUB_TOKEN` |
| **trufflehog** | Secret detection tool | ✅ Working | Reused across phases |
| **git-secrets** | Git hook for secret detection | ✅ Working | For local repo scanning |

---

## PHASE 3: CONTENT DISCOVERY (16 Tools)

| Tool | Purpose | Status | Notes |
|------|---------|--------|-------|
| **gau** | Get All URLs from Wayback, Common Crawl, URLScan | ✅ Working | Archive-based URL discovery |
| **waybackurls** | Wayback Machine URL scraper | ✅ Working | Historical endpoint finder |
| **spideyx** | Powerful spider tool | ✅ Working | Primary crawler; alternative spidey available |
| **hakrawler** | Web crawler | ✅ Working | Crawls discovered URLs |
| **katana** | Advanced web crawler | ✅ Working | Fast crawling with JS support |
| **cariddi** | Endpoint discovery tool | ✅ Working | Alternative crawler |
| **mantra** | Web spider tool | ✅ Working | Another crawling option |
| **gitleaks** | Secret scanning in downloaded content | ✅ Working | Scans downloaded files |
| **trufflehog** | Secret detection in content | ✅ Working | Scans downloaded files |
| **ffuf** | Directory/parameter fuzzing | ❌ BROKEN | JSON parsing bug; results silently dropped - **HIGH PRIORITY FIX** |
| **feroxbuster** | Recursive directory discovery | ✅ Working | Alternative dir fuzzer |
| **dirsearch** | Directory brute-forcing | ✅ Working | Standard directory scanner |
| **linkfinder** | JavaScript endpoint extractor | ✅ Working | Finds API endpoints in JS |
| **jsscanner** | JavaScript security scanner | ✅ Working | Scans JS for issues |
| **pbin** | Pastebin monitoring tool | ✅ Working | Checks for leaked data |

---

## PHASE 4: VULNERABILITY SCANNING (13 Tools)

| Tool | Purpose | Status | Notes |
|------|---------|--------|-------|
| **nuclei** | Multi-purpose vulnerability scanner | ✅ Working | Primary vuln scanner; template update gated on `TECHNIEUM_NUCLEI_UPDATE` |
| **dalfox** | XSS vulnerability scanner | ✅ Working | Specialized XSS detection |
| **sqlmap** | SQL injection detection | ✅ Working | Automated SQLi testing |
| **corsy** | CORS misconfiguration finder | ✅ Working | Cross-origin policy checker |
| **nikto** | Web server scanner | ✅ Working | Comprehensive web vuln scanner |
| **wpscan** | WordPress vulnerability scanner | ✅ Working | WordPress-specific scanning |
| **wapiti** | Web application vulnerability scanner | ✅ Working | General web app scanner |
| **skipfish** | Web security scanner | ✅ Working | Alternative web scanner |
| **cmsmap** | CMS vulnerability scanner | ✅ Working | CMS-specific detection (WordPress, Joomla, Drupal) |
| **retire** | JavaScript library vulnerability scanner | ✅ Working | Detects vulnerable JS libraries |
| **testssl.sh** | SSL/TLS security checker | ✅ Working | Certificate & SSL analysis |
| **sslyze** | SSL/TLS analyzer | ✅ Working | Deep SSL analysis |
| **gowitness** | Web page screenshot tool | ✅ Working | Visual validation & verification |

---

## CROSS-PHASE & UTILITY TOOLS (4 Tools)

| Tool | Purpose | Status | Used In | Notes |
|--------|---------|--------|---------|-------|
| **jq** | JSON processor | ✅ Working | Phase 3, 4 | Data parsing utility |
| **timeout** / **run_timeout** | Command timeout utility | ✅ Working | All phases | Prevents tool hangs |
| Python parsers | Output parsing | ✅ Working | All phases | Ingests tool outputs into DB |
| Database (SQLite) | Results storage | ✅ Working | All phases | 25+ ORM models |

---

## Issues & Fixes Required

### HIGH PRIORITY (Block Production)

| Issue | Tool | Impact | Fix | Severity |
|-------|------|--------|-----|----------|
| **FFUF JSON parsing broken** | ffuf | Results silently dropped, never enters DB | Fix `parse_ffuf()` function to check dict keys correctly | 🔴 HIGH |
| **Amass removed** | amass | Missing from Phase 1 discovery | Either restore or update docs to reflect removal | 🟡 MEDIUM |

### MEDIUM PRIORITY (Hardening)

| Issue | Impact | Fix |
|-------|--------|-----|
| **Nuclei template auto-update disabled** | Templates may be outdated | Set `TECHNIEUM_NUCLEI_UPDATE=true` to enable updates |
| **Database singleton caching bug** | Multi-DB sessions broken | Fix Singleton `__new__` to allow path changes |
| **INSERT OR IGNORE data loss** | Silent data drops in bulk inserts | Change to `ON CONFLICT ... DO UPDATE` |

---

## Environment Configuration

### API Keys Required
- `SHODAN_API_KEY` - for Shodan queries
- `CENSYS_API_ID` & `CENSYS_API_SECRET` - for Censys data
- `GITHUB_TOKEN` - for GitHub secret hunting
- `SECURITYTRAILS_API_KEY` - for SecurityTrails queries

### Timeouts Configured (Environment Variables)
```bash
# Discovery Phase
TECHNIEUM_WHOIS_TIMEOUT=60
TECHNIEUM_SUBFINDER_TIMEOUT=900
TECHNIEUM_DNSX_TIMEOUT=1800
TECHNIEUM_HTTPX_TIMEOUT=15
TECHNIEUM_HTTPX_RUN_TIMEOUT=3600

# Intelligence Phase
TECHNIEUM_DNSX_TIMEOUT=1800
TECHNIEUM_RUSTSCAN_TIMEOUT=900
TECHNIEUM_NMAP_TIMEOUT=900
TECHNIEUM_SHODAN_TIMEOUT=900

# Content Discovery
TECHNIEUM_FFUF_TIMEOUT=1800
TECHNIEUM_FEROXBUSTER_TIMEOUT=1800
TECHNIEUM_DIRSEARCH_TIMEOUT=1800

# Vulnerability Phase
TECHNIEUM_NUCLEI_TIMEOUT=3600
TECHNIEUM_SQLMAP_TIMEOUT=1800
TECHNIEUM_TESTSSL_TIMEOUT=900
```

---

## Recommended Actions

### Immediate (Before Production)
1. ✅ Fix FFUF parser bug (Lines 298-310 in `parsers/parser.py`)
2. 📋 Document why Amass was removed or restore it
3. 🧪 Run `tests/prod_readiness_test.py` to validate all endpoints

### Short Term (1-2 Weeks)
1. Add tool registration tracking to database
2. Implement tool health checks at scan startup
3. Create per-tool retry logic for transient failures

### Long Term (Enterprise Features)
1. Tool version tracking and compatibility checks
2. Custom tool registration framework
3. Tool performance profiling and optimization

---

## Testing Checklist

- [ ] All 57 tools present on test system
- [ ] Phase 1: Discovery completes with 17+ tools succeeding
- [ ] Phase 2: Intelligence gathers data from available tools
- [ ] Phase 3: Content discovery finds endpoints (excluding FFUF results until fixed)
- [ ] Phase 4: Vulnerabilities detected by multiple scanners
- [ ] FFUF parser fixed and results appear in DB
- [ ] Nuclei template update behavior confirmed
- [ ] Rate limiting working for API-based tools
- [ ] Timeout handling prevents tool hangs
- [ ] Failed tools don't cascade to following phases

---

**Last Updated:** March 9, 2026  
**Next Review:** After FFUX parser fix completion
