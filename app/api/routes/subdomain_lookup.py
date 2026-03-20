"""Subdomain discovery API routes — crt.sh + C99 + ip.thc.org (subdomains / CNAME / rDNS).

crt.sh         : Free — queries Certificate Transparency logs (no API key needed).
C99 SubFinder  : Requires C99_API_KEY env var (get one at https://subdomainfinder.c99.nl/).
ip.thc.org     : Free — world’s largest domain database (5.4B+ domains, no key needed).
  /sb/<domain>   -> subdomains of a domain
  /cn/<domain>   -> domains that CNAME-point to a domain
  /<ip>          -> all domains sharing an IP (reverse DNS)
"""
import asyncio
import logging
import os
import socket
from datetime import datetime, timezone
from typing import List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()

C99_API_KEY = os.getenv("C99_API_KEY", "")

# ── Response models ──────────────────────────────────────────────────────────

class SubdomainEntry(BaseModel):
    subdomain: str
    source: str  # "crt.sh" | "c99" | "ip.thc.org" | "ip.thc.org (cname)" | "ip.thc.org (rdns)"


class SubdomainLookupResponse(BaseModel):
    domain: str
    total: int
    crtsh_count: int
    c99_count: int
    iphthc_count: int = 0
    cname_count: int = 0
    rdns_count: int = 0
    subdomains: List[SubdomainEntry]
    messages: List[str] = []   # informational / warning messages for the UI


class SourceStatus(BaseModel):
    name: str
    available: bool
    message: str


class SourceStatusResponse(BaseModel):
    sources: List[SourceStatus]


class CertRecord(BaseModel):
    id: int
    logged_at: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]
    common_name: Optional[str]
    matching_identities: List[str]   # split name_value lines
    issuer_name: Optional[str]
    serial_number: Optional[str]
    status: str                      # "valid" | "expiring" | "expired"


class CertMonitorResponse(BaseModel):
    domain: str
    total: int
    valid: int
    expiring: int
    expired: int
    certs: List[CertRecord]
    messages: List[str] = []


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _query_crtsh(domain: str, timeout: float = 90.0) -> List[str]:
    """Query crt.sh Certificate Transparency logs for subdomains.

    crt.sh can be very slow (30-90s) for popular domains and is frequently
    overloaded (502/503/404).  We retry with back-off and try two URL
    strategies to maximise reliability.
    """
    _MAX_RETRIES = 3
    domain_lower = domain.lower()

    # Two URL strategies — crt.sh's CDN sometimes handles %-encoding
    # differently.  Strategy 1 uses httpx params (proper %25 encoding);
    # Strategy 2 builds the URL manually with a raw percent character.
    _url_strategies = [
        # Strategy 1: let httpx encode params (sends %25.domain)
        {"url": "https://crt.sh/", "params": {"q": f"%.{domain}", "output": "json"}},
        # Strategy 2: pre-encoded URL
        {"url": f"https://crt.sh/?q=%25.{domain}&output=json", "params": None},
    ]

    for attempt in range(_MAX_RETRIES + 1):
        strategy = _url_strategies[attempt % len(_url_strategies)]
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(timeout, connect=20.0),
                follow_redirects=True,
                http2=False,
                headers={"User-Agent": "Mozilla/5.0 (Technieum; crt.sh client)"},
            ) as client:
                if strategy["params"]:
                    resp = await client.get(strategy["url"], params=strategy["params"])
                else:
                    resp = await client.get(strategy["url"])

                # crt.sh returns 502/503/404 when overloaded — retry with backoff
                if resp.status_code in (404, 429, 500, 502, 503) and attempt < _MAX_RETRIES:
                    wait = 4 * (attempt + 1)
                    logger.info("crt.sh returned %s for %s — retrying in %ss (attempt %s/%s)",
                                resp.status_code, domain, wait, attempt + 1, _MAX_RETRIES)
                    await asyncio.sleep(wait)
                    continue

                resp.raise_for_status()

                # crt.sh sometimes sends text/html on error despite ?output=json
                raw_text = resp.text.strip()
                if not raw_text or raw_text.startswith("<!") or raw_text.startswith("<html"):
                    logger.warning("crt.sh returned HTML instead of JSON for %s", domain)
                    if attempt < _MAX_RETRIES:
                        await asyncio.sleep(4)
                        continue
                    return []

                data = resp.json()

            if not isinstance(data, list):
                logger.warning("crt.sh returned non-list JSON for %s: %s", domain, type(data))
                return []

            subdomains: set[str] = set()
            for entry in data:
                # Extract names from both name_value and common_name fields
                for field in ("name_value", "common_name"):
                    raw = entry.get(field, "")
                    if not raw:
                        continue
                    for name in raw.split("\n"):
                        name = name.strip().lower()
                        if not name:
                            continue
                        # Strip leading wildcard prefix (*.)
                        if name.startswith("*."):
                            name = name[2:]
                        # Must belong to the target domain
                        if name == domain_lower or name.endswith(f".{domain_lower}"):
                            subdomains.add(name)

            logger.info("crt.sh returned %d unique subdomains for %s", len(subdomains), domain)
            return sorted(subdomains)

        except httpx.TimeoutException:
            logger.warning("crt.sh request timed out for %s (attempt %s/%s, timeout=%ss)",
                           domain, attempt + 1, _MAX_RETRIES + 1, timeout)
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(3)
                continue
            return []
        except Exception as exc:
            logger.warning("crt.sh lookup failed for %s: %s", domain, exc)
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(3)
                continue
            return []

    return []  # all retries exhausted


async def _fetch_crtsh_json(url: str, params=None, timeout: float = 90.0) -> List[dict]:
    """Fetch a single crt.sh JSON query with retries.  Returns raw list or []."""
    _MAX_RETRIES = 2
    for attempt in range(_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(timeout, connect=20.0),
                follow_redirects=True,
                http2=False,
                headers={"User-Agent": "Mozilla/5.0 (Technieum; crt.sh client)"},
            ) as client:
                resp = await client.get(url, params=params)
                if resp.status_code in (502, 503, 404, 429, 500):
                    if attempt < _MAX_RETRIES:
                        await asyncio.sleep(5 * (attempt + 1))
                        continue
                    return []
                ct = resp.headers.get("content-type", "")
                raw_text = resp.text.strip()
                if "text/html" in ct or raw_text.startswith("<!") or raw_text.startswith("<html"):
                    if attempt < _MAX_RETRIES:
                        await asyncio.sleep(5)
                        continue
                    return []
                data = resp.json()
                return data if isinstance(data, list) else []
        except httpx.TimeoutException:
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(5)
                continue
            return []
        except Exception as exc:
            logger.warning("crt.sh fetch failed (%s): %s", url, exc)
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(5)
                continue
            return []
    return []


async def _query_crtsh_full(domain: str, timeout: float = 90.0) -> List[dict]:
    """Query crt.sh and return full raw certificate records (not just subdomain names).

    Runs TWO parallel queries to replicate the crt.sh identity-search behaviour:
      1. q=%.{domain}   — every cert whose SAN/CN ends with .{domain}  (subdomains + wildcards)
      2. q={domain}     — every cert whose SAN/CN is exactly {domain}  (apex certs)
    Both result-sets are merged and deduplicated by certificate id, then sorted
    newest-first so the caller sees the same ~200+ rows that the crt.sh web UI shows.
    """
    # Launch both searches concurrently
    results = await asyncio.gather(
        _fetch_crtsh_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=timeout),
        _fetch_crtsh_json("https://crt.sh/", params={"q": domain,          "output": "json"}, timeout=timeout),
        return_exceptions=False,
    )

    seen: set = set()
    records: List[dict] = []
    for batch in results:
        if not isinstance(batch, list):
            continue
        for rec in batch:
            rid = rec.get("id")
            if rid and rid not in seen:
                seen.add(rid)
                records.append(rec)

    logger.info("crt.sh returned %d unique cert records for %s", len(records), domain)
    return records


def _cert_status(not_after_str: Optional[str]) -> str:
    """Return 'valid', 'expiring' (within 30 days), or 'expired'."""
    if not not_after_str:
        return "valid"
    try:
        # crt.sh format: "2026-05-09T00:00:00" or "2026-05-09"
        s = not_after_str.replace("Z", "").split(".")[0]
        fmt = "%Y-%m-%dT%H:%M:%S" if "T" in s else "%Y-%m-%d"
        dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = (dt - now).days
        if delta < 0:
            return "expired"
        if delta <= 30:
            return "expiring"
        return "valid"
    except Exception:
        return "valid"


async def _query_iphthc(domain: str, timeout: float = 30.0) -> List[str]:
    """Query ip.thc.org subdomain database (world's largest, 5.4B+ domains).

    Uses the /sb/<domain> endpoint which returns plain-text subdomain lines.
    Lines starting with ';' are comments/headers and are skipped.
    Max 100 results per request (hard limit of the service).
    """
    domain_lower = domain.lower()
    results: set[str] = set()

    # Fetch up to 100 results; ip.thc.org public endpoint, no auth needed
    url = f"https://ip.thc.org/sb/{domain_lower}"
    params = {"l": "100", "noheader": "1", "nocolor": "1"}

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=15.0),
            follow_redirects=True,
            headers={"User-Agent": "curl/7.88.0"},  # ip.thc.org is curl-friendly
        ) as client:
            resp = await client.get(url, params=params)

            if resp.status_code == 429:
                logger.warning("ip.thc.org rate-limited for %s", domain)
                return []
            if resp.status_code >= 400:
                logger.warning("ip.thc.org returned %s for %s", resp.status_code, domain)
                return []

            # Response is plain text — one subdomain per line, ';' lines are comments
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                line = line.lower()
                if line == domain_lower or line.endswith(f".{domain_lower}"):
                    results.add(line)

        logger.info("ip.thc.org returned %d subdomains for %s", len(results), domain)
        return sorted(results)

    except httpx.TimeoutException:
        logger.warning("ip.thc.org request timed out for %s", domain)
        return []
    except Exception as exc:
        logger.warning("ip.thc.org lookup failed for %s: %s", domain, exc)
        return []


async def _query_iphthc_cname(domain: str, timeout: float = 30.0) -> List[str]:
    """Query ip.thc.org for domains that CNAME-point to the target domain (/cn/ endpoint)."""
    domain_lower = domain.lower()
    results: set[str] = set()
    url = f"https://ip.thc.org/cn/{domain_lower}"
    params = {"l": "100", "noheader": "1", "nocolor": "1"}
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=15.0),
            follow_redirects=True,
            headers={"User-Agent": "curl/7.88.0"},
        ) as client:
            resp = await client.get(url, params=params)
            if resp.status_code == 429:
                logger.warning("ip.thc.org CNAME rate-limited for %s", domain)
                return []
            if resp.status_code >= 400:
                logger.warning("ip.thc.org CNAME returned %s for %s", resp.status_code, domain)
                return []
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                results.add(line.lower())
        logger.info("ip.thc.org CNAME returned %d domains pointing to %s", len(results), domain)
        return sorted(results)
    except httpx.TimeoutException:
        logger.warning("ip.thc.org CNAME timed out for %s", domain)
        return []
    except Exception as exc:
        logger.warning("ip.thc.org CNAME failed for %s: %s", domain, exc)
        return []


async def _query_iphthc_rdns(domain: str, timeout: float = 30.0) -> List[str]:
    """Query ip.thc.org reverse DNS: resolve domain → IPs, then find all domains on those IPs."""
    domain_lower = domain.lower()

    # Step 1: resolve domain to IPs (blocking call, run in thread pool)
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(domain_lower, None)
        )
        ips = list({info[4][0] for info in infos})
    except Exception as exc:
        logger.warning("DNS resolution failed for %s: %s", domain, exc)
        return []

    if not ips:
        return []

    logger.info("ip.thc.org rDNS: resolved %s to IPs: %s", domain, ips)

    # Step 2: fetch rDNS for each IP (cap at 4 IPs to avoid hammering rate limits)
    results: set[str] = set()
    resolved_ips: list[str] = []

    async def _fetch_rdns(ip: str) -> None:
        url = f"https://ip.thc.org/{ip}"
        params = {"l": "100", "noheader": "1", "nocolor": "1"}
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(timeout, connect=15.0),
                follow_redirects=True,
                headers={"User-Agent": "curl/7.88.0"},
            ) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 429:
                    logger.warning("ip.thc.org rDNS rate-limited for %s", ip)
                    return
                if resp.status_code >= 400:
                    logger.warning("ip.thc.org rDNS returned %s for %s", resp.status_code, ip)
                    return
                resolved_ips.append(ip)
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";"):
                        continue
                    results.add(line.lower())
        except Exception as exc:
            logger.warning("ip.thc.org rDNS failed for %s: %s", ip, exc)

    await asyncio.gather(*[_fetch_rdns(ip) for ip in ips[:4]])
    logger.info("ip.thc.org rDNS returned %d domains for %s (IPs queried: %s)",
                len(results), domain, resolved_ips)
    return sorted(results)


async def _query_c99(domain: str, timeout: float = 30.0) -> List[str]:
    """Query C99 SubdomainFinder API."""
    if not C99_API_KEY:
        logger.debug("C99_API_KEY not set — skipping C99 lookup")
        return []

    url = "https://api.c99.nl/subdomainfinder"
    params = {
        "key": C99_API_KEY,
        "domain": domain,
        "json": "",  # request JSON output
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()

        if not data.get("success", False):
            logger.warning("C99 returned error for %s: %s", domain, data)
            return []

        subdomains: set[str] = set()
        for entry in data.get("subdomains", []):
            sub = (entry.get("subdomain") or "").strip().lower()
            if sub:
                subdomains.add(sub)

        return sorted(subdomains)

    except httpx.TimeoutException:
        logger.warning("C99 request timed out for %s", domain)
        return []
    except Exception as exc:
        logger.warning("C99 lookup failed for %s: %s", domain, exc)
        return []


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get(
    "/lookup",
    response_model=SubdomainLookupResponse,
    summary="Discover subdomains via crt.sh and C99",
)
async def subdomain_lookup(
    domain: str = Query(..., min_length=3, description="Target domain (e.g. example.com)"),
):
    """Query crt.sh (Certificate Transparency) and C99 SubdomainFinder in
    parallel and return a deduplicated, merged list of discovered subdomains."""

    # Basic domain validation
    domain = domain.strip().lower()
    if "/" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    # Run all five lookups in parallel, bounded by a hard overall timeout.
    # crt.sh alone can retry for minutes — without this cap the browser/proxy
    # drops the connection and the client sees "Failed to fetch".
    _TOTAL_TIMEOUT = 120.0  # seconds
    try:
        crtsh_results, c99_results, iphthc_results, cname_results, rdns_results = await asyncio.wait_for(
            asyncio.gather(
                _query_crtsh(domain),
                _query_c99(domain),
                _query_iphthc(domain),
                _query_iphthc_cname(domain),
                _query_iphthc_rdns(domain),
                return_exceptions=True,
            ),
            timeout=_TOTAL_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.warning("subdomain_lookup timed out after %ss for %s", _TOTAL_TIMEOUT, domain)
        raise HTTPException(
            status_code=504,
            detail=f"Lookup timed out after {int(_TOTAL_TIMEOUT)}s — external sources (crt.sh / ip.thc.org) are slow. Try individual sources instead.",
        )

    # Treat any per-source exception as an empty result
    if isinstance(crtsh_results, BaseException):
        logger.warning("crt.sh gather error for %s: %s", domain, crtsh_results)
        crtsh_results = []
    if isinstance(c99_results, BaseException):
        c99_results = []
    if isinstance(iphthc_results, BaseException):
        iphthc_results = []
    if isinstance(cname_results, BaseException):
        cname_results = []
    if isinstance(rdns_results, BaseException):
        rdns_results = []

    # Build deduplicated entries (prefer earlier source if duplicate)
    seen: set[str] = set()
    entries: List[SubdomainEntry] = []

    for sub in crtsh_results:
        if sub not in seen:
            seen.add(sub)
            entries.append(SubdomainEntry(subdomain=sub, source="crt.sh"))

    for sub in c99_results:
        if sub not in seen:
            seen.add(sub)
            entries.append(SubdomainEntry(subdomain=sub, source="c99"))

    for sub in iphthc_results:
        if sub not in seen:
            seen.add(sub)
            entries.append(SubdomainEntry(subdomain=sub, source="ip.thc.org"))

    for sub in cname_results:
        if sub not in seen:
            seen.add(sub)
            entries.append(SubdomainEntry(subdomain=sub, source="ip.thc.org (cname)"))

    for sub in rdns_results:
        if sub not in seen:
            seen.add(sub)
            entries.append(SubdomainEntry(subdomain=sub, source="ip.thc.org (rdns)"))

    # Sort alphabetically
    entries.sort(key=lambda e: e.subdomain)

    return SubdomainLookupResponse(
        domain=domain,
        total=len(entries),
        crtsh_count=len(crtsh_results),
        c99_count=len(c99_results),
        iphthc_count=len(iphthc_results),
        cname_count=len(cname_results),
        rdns_count=len(rdns_results),
        subdomains=entries,
        messages=_build_messages(crtsh_results, c99_results),
    )


def _build_messages(crtsh: list, c99: list) -> List[str]:
    msgs = []
    if len(crtsh) == 0:
        msgs.append("crt.sh returned 0 results — the service may be temporarily unavailable (502/503). Try again in a minute.")
    if len(c99) == 0 and not C99_API_KEY:
        msgs.append("C99 skipped — set C99_API_KEY to enable.")
    elif len(c99) == 0 and C99_API_KEY:
        msgs.append("C99 returned 0 results.")
    return msgs


@router.get(
    "/crtsh",
    response_model=SubdomainLookupResponse,
    summary="Discover subdomains via crt.sh only",
)
async def crtsh_lookup(
    domain: str = Query(..., min_length=3, description="Target domain"),
):
    """Query crt.sh Certificate Transparency logs only."""
    domain = domain.strip().lower()
    if "/" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    results = await _query_crtsh(domain)
    entries = [SubdomainEntry(subdomain=s, source="crt.sh") for s in results]
    messages = []
    if len(results) == 0:
        messages.append("crt.sh returned 0 results — the service may be temporarily unavailable. Try again in a minute.")

    return SubdomainLookupResponse(
        domain=domain,
        total=len(entries),
        crtsh_count=len(entries),
        c99_count=0,
        iphthc_count=0,
        cname_count=0,
        rdns_count=0,
        subdomains=entries,
        messages=messages,
    )


@router.get(
    "/c99",
    response_model=SubdomainLookupResponse,
    summary="Discover subdomains via C99 SubdomainFinder",
)
async def c99_lookup(
    domain: str = Query(..., min_length=3, description="Target domain"),
):
    """Query C99 SubdomainFinder API."""
    domain = domain.strip().lower()
    if "/" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    if not C99_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="C99_API_KEY not configured. Set the C99_API_KEY environment variable.",
        )

    results = await _query_c99(domain)
    entries = [SubdomainEntry(subdomain=s, source="c99") for s in results]

    return SubdomainLookupResponse(
        domain=domain,
        total=len(entries),
        crtsh_count=0,
        c99_count=len(entries),
        iphthc_count=0,
        cname_count=0,
        rdns_count=0,
        subdomains=entries,
        messages=[],
    )


@router.get(
    "/iphthc",
    response_model=SubdomainLookupResponse,
    summary="Discover subdomains via ip.thc.org",
)
async def iphthc_lookup(
    domain: str = Query(..., min_length=3, description="Target domain"),
):
    """Query ip.thc.org — the world's largest domain/CNAME database (5.4B+ domains)."""
    domain = domain.strip().lower()
    if "/" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    results = await _query_iphthc(domain)
    entries = [SubdomainEntry(subdomain=s, source="ip.thc.org") for s in results]
    messages = []
    if len(results) == 0:
        messages.append("ip.thc.org returned 0 results — the service may be rate-limited or temporarily unavailable.")

    return SubdomainLookupResponse(
        domain=domain,
        total=len(entries),
        crtsh_count=0,
        c99_count=0,
        iphthc_count=len(entries),
        cname_count=0,
        rdns_count=0,
        subdomains=entries,
        messages=messages,
    )


@router.get(
    "/iphthc-cname",
    response_model=SubdomainLookupResponse,
    summary="Find domains CNAME-pointing to target via ip.thc.org",
)
async def iphthc_cname_lookup(
    domain: str = Query(..., min_length=3, description="Target domain"),
):
    """Query ip.thc.org /cn/ endpoint to find all domains whose CNAME record points at this domain."""
    domain = domain.strip().lower()
    if "/" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    results = await _query_iphthc_cname(domain)
    entries = [SubdomainEntry(subdomain=s, source="ip.thc.org (cname)") for s in results]
    messages = []
    if len(results) == 0:
        messages.append("ip.thc.org CNAME returned 0 results — no domains appear to CNAME-point to this domain.")

    return SubdomainLookupResponse(
        domain=domain,
        total=len(entries),
        crtsh_count=0,
        c99_count=0,
        iphthc_count=0,
        cname_count=len(entries),
        rdns_count=0,
        subdomains=entries,
        messages=messages,
    )


@router.get(
    "/iphthc-rdns",
    response_model=SubdomainLookupResponse,
    summary="Find domains sharing IPs via ip.thc.org reverse DNS",
)
async def iphthc_rdns_lookup(
    domain: str = Query(..., min_length=3, description="Target domain"),
):
    """Resolve the domain to IPs, then query ip.thc.org rDNS to find all domains on those IPs."""
    domain = domain.strip().lower()
    if "/" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    results = await _query_iphthc_rdns(domain)
    entries = [SubdomainEntry(subdomain=s, source="ip.thc.org (rdns)") for s in results]
    messages = []
    if len(results) == 0:
        messages.append("ip.thc.org rDNS returned 0 results — could not resolve IPs or no domains found.")

    return SubdomainLookupResponse(
        domain=domain,
        total=len(entries),
        crtsh_count=0,
        c99_count=0,
        iphthc_count=0,
        cname_count=0,
        rdns_count=len(entries),
        subdomains=entries,
        messages=messages,
    )


@router.get(
    "/sources",
    response_model=SourceStatusResponse,
    summary="Check which subdomain lookup sources are available",
)
async def source_status():
    """Return availability status for each data source."""

    async def _check(url: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.head(url)
                return r.status_code < 500
        except Exception:
            return False

    crtsh_reachable, iphthc_reachable = await asyncio.gather(
        _check("https://crt.sh/"),
        _check("https://ip.thc.org/"),
    )

    sources = [
        SourceStatus(
            name="crt.sh",
            available=crtsh_reachable,
            message="Online — no API key required" if crtsh_reachable
                    else "crt.sh appears down (502/503) — queries will retry automatically",
        ),
        SourceStatus(
            name="C99 SubdomainFinder",
            available=bool(C99_API_KEY),
            message="Active" if C99_API_KEY else "C99_API_KEY not set — configure in .env or environment",
        ),
        SourceStatus(
            name="ip.thc.org",
            available=iphthc_reachable,
            message="Online — no API key required (5.4B+ domains)" if iphthc_reachable
                    else "ip.thc.org appears unreachable",
        ),
    ]
    return SourceStatusResponse(sources=sources)


# ── Certificate Transparency Monitor ─────────────────────────────────────────

@router.get(
    "/crtsh-certs",
    response_model=CertMonitorResponse,
    summary="Full certificate transparency records from crt.sh",
)
async def crtsh_cert_monitor(
    domain: str = Query(..., description="Domain to look up (e.g. example.com)"),
):
    """Return full certificate records from crt.sh for a domain.

    Each record includes: id, logged_at, not_before, not_after, common_name,
    matching_identities (name_value), issuer_name, serial_number, and a
    computed status field (valid / expiring / expired).
    """
    domain = domain.strip().lower().lstrip("*.")
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain")

    raw = await _query_crtsh_full(domain, timeout=90.0)

    if not raw:
        return CertMonitorResponse(
            domain=domain, total=0, valid=0, expiring=0, expired=0,
            certs=[], messages=["crt.sh returned no results — it may be overloaded. Try again in a moment."],
        )

    certs: List[CertRecord] = []
    for rec in raw:
        not_after = rec.get("not_after") or rec.get("not_after_ts")
        status = _cert_status(not_after)

        # name_value may contain multiple SANs separated by newlines
        raw_nv = rec.get("name_value", "") or ""
        identities = sorted(set(
            n.strip() for n in raw_nv.replace("\r", "\n").split("\n")
            if n.strip()
        ))

        certs.append(CertRecord(
            id=int(rec.get("id", 0)),
            logged_at=rec.get("entry_timestamp") or rec.get("logged_at"),
            not_before=rec.get("not_before"),
            not_after=not_after,
            common_name=rec.get("common_name"),
            matching_identities=identities,
            issuer_name=rec.get("issuer_name"),
            serial_number=rec.get("serial_number"),
            status=status,
        ))

    # Sort: newest logged first
    certs.sort(key=lambda c: c.logged_at or "", reverse=True)

    n_valid    = sum(1 for c in certs if c.status == "valid")
    n_expiring = sum(1 for c in certs if c.status == "expiring")
    n_expired  = sum(1 for c in certs if c.status == "expired")

    return CertMonitorResponse(
        domain=domain,
        total=len(certs),
        valid=n_valid,
        expiring=n_expiring,
        expired=n_expired,
        certs=certs,
    )
