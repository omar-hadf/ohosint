"""MCP tool implementations.

Every tool is a thin wrapper over ``osint_core`` / ``ohosint.pipelines``. The
wrappers exist for three reasons:

1. **Schema**: fastmcp generates the tool input schema from the type hints and
   the description from the docstring.
2. **stdout hygiene**: the engine prints progress/diagnostics to stdout, which
   would corrupt the MCP stdio transport. ``_run`` captures stdout and returns
   it as a ``logs`` list in the result dict.
3. **JSON-safety**: ``ScanResult`` objects are serialized to plain dicts.

Passivity is enforced by the engine; nothing here adds a new network primitive.
"""

from __future__ import annotations

import contextlib
import io
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import osint_core as oc
from ohosint.pipelines import (
    load_site_databases,
    run_breach_pipeline,
    run_email_pipeline,
    run_name_pipeline,
    run_phone_pipeline,
    run_username_pipeline_bounded,
)

from .planner import build_plan, detect_target_type
from .session import SESSION

# ---------------------------------------------------------------------------
# silent-account-finder constants (mirrors skills/silent-account-finder)
# ---------------------------------------------------------------------------

_PROFILE_SITES = ["xnxx", "xvideos"]

_PROFILE_DORKS = [
    '"{email}"',
    'site:xvideos.com "{fl}"',
    'site:xnxx.com "{fl}"',
    '"{fu}" "{lu}" profile',
    'site:xvideos.com OR site:xnxx.com "{f}{l}{n}"',
]

_ADULT_HOST_RE = re.compile(r"(xnxx|xvideos)\.")
_PROFILE_SLUG_RE = re.compile(r"(?:xnxx|xvideos)\.\w+/profiles?/([A-Za-z0-9_.-]+)")
_ADULT_LEAK_RE = re.compile(r"x(nxx|videos)", re.I)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _logs(buf: io.StringIO) -> List[str]:
    text = buf.getvalue().strip()
    return text.splitlines() if text else []


def _run(fn, *args, **kwargs) -> Dict[str, Any]:
    """Run ``fn`` capturing stdout; wrap failures as a structured error dict.

    ``osint_core`` (Fetcher, pipelines, search) prints progress and diagnostics
    to stdout. Over the MCP stdio transport stdout is reserved for JSON-RPC, so
    any stray print would break the session. Capturing redirects those lines
    into a ``logs`` field instead. Tools run in a worker thread and an MCP
    client invokes them sequentially, so process-global redirection is safe.
    """
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            result = fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — surface any failure to the client
        return {
            "error": str(exc),
            "error_type": type(exc).__name__,
            "logs": _logs(buf),
        }
    if isinstance(result, dict):
        captured = _logs(buf)
        if captured:
            result["logs"] = captured
    return result


def _scan_results(results) -> List[Dict[str, Any]]:
    return [r.to_dict() for r in results]


def _summary(results) -> Dict[str, int]:
    return {
        "total": len(results),
        "found": sum(1 for r in results if r.is_found()),
    }


def _fetcher() -> oc.Fetcher:
    return SESSION.fetcher()


# ---------------------------------------------------------------------------
# tool implementations
# ---------------------------------------------------------------------------

def _configure(proxy, delay_min, delay_max, timeout, nsfw, in_parallel, sites_db,
               insecure_tls) -> Dict[str, Any]:
    warnings = []
    if proxy and str(proxy).strip().lower() in ("none", "off", "null", ""):
        proxy = None
    if proxy:
        if not oc.valid_proxy(proxy):
            raise ValueError(f"invalid proxy URL {proxy!r}")
        leak = oc.warn_if_dns_leaking(proxy)
        if leak:
            warnings.append(leak)
    SESSION.set_proxy(proxy)
    SESSION.set_delay(delay_min, delay_max)
    SESSION.timeout = timeout
    SESSION.nsfw = bool(nsfw)
    SESSION.in_parallel = in_parallel
    SESSION.sites_db = sites_db
    SESSION.insecure_tls = bool(insecure_tls)
    return {"proxy": SESSION.proxy, "delay": list(SESSION.delay),
            "timeout": SESSION.timeout, "nsfw": SESSION.nsfw,
            "in_parallel": SESSION.in_parallel, "sites_db": SESSION.sites_db,
            "insecure_tls": SESSION.insecure_tls, "warnings": warnings}


def _status() -> Dict[str, Any]:
    keys = oc.get_api_keys()
    google_keyed = bool(oc.google_creds())
    github_keyed = bool(oc.github_key())
    hints = []
    if not github_keyed:
        hints.append("OHO_GITHUB_KEY — unlocks GitHub code search")
    if not google_keyed:
        hints.append("OHO_GOOGLE_KEY + OHO_GOOGLE_CX — adds the Google dork engine")
    if not keys.get("hibp"):
        hints.append("OHO_HIBP_KEY — HIBP per-account breach search")
    if not keys.get("intelx"):
        hints.append("OHO_INTELX_KEY — Intelligence X leak search")
    return {
        "proxy": SESSION.proxy,
        "delay": list(SESSION.delay),
        "timeout": SESSION.timeout,
        "nsfw": SESSION.nsfw,
        "in_parallel": SESSION.in_parallel,
        "sites_db": SESSION.sites_db,
        "insecure_tls": SESSION.insecure_tls,
        "identifiers": SESSION.identifiers,
        "candidates": SESSION.candidate_handles[:50],
        "results_collected": len(SESSION.results),
        "results_found": len(SESSION.found_results()),
        "breach_keys": {k: bool(v) for k, v in keys.items()},
        "google_keyed": google_keyed,
        "github_keyed": github_keyed,
        "recommended_next_keys": hints,
    }


def _tor_check() -> Dict[str, Any]:
    r = _fetcher().get("https://check.torproject.org/api/ip")
    if r is None or r.status_code != 200:
        return {"tor": None, "note": "unreachable — is tor running on the proxy?"}
    try:
        j = r.json()
    except Exception as e:
        return {"tor": None, "note": str(e)[:100]}
    return {"tor": bool(j.get("IsTor")), "ip": j.get("IP")}


def _rotate_tor_circuit() -> Dict[str, Any]:
    try:
        from stem.control import Controller
    except ImportError:
        return {"rotated": False,
                "note": "stem not installed — pip install stem to control Tor circuits"}
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal("NEWNYM")
        return {"rotated": True, "note": "Tor circuit rotated"}
    except Exception as e:
        if isinstance(e, ConnectionRefusedError) or "refused" in str(e).lower():
            note = ("Tor ControlPort 9051 not available. Enable CookieAuthentication "
                    "in torrc (ControlPort 9051), or wait 10-30 min for automatic "
                    "circuit rotation (or `sudo systemctl restart tor`).")
        else:
            note = f"failed: {e}"
        return {"rotated": False, "note": note}


def _plan(target: str, target_type: Optional[str]) -> Dict[str, Any]:
    return build_plan(target, target_type)


def _investigate_email(address: str, sweep_candidates: bool, max_candidates: int,
                       include_sources: bool) -> Dict[str, Any]:
    sites = load_site_databases(SESSION.sites_db) if sweep_candidates else None
    report = run_email_pipeline(
        address,
        sites=sites,
        proxy=SESSION.proxy,
        timeout=SESSION.timeout,
        in_parallel=SESSION.in_parallel,
        skip_nsfw=not SESSION.nsfw,
        verify_ssl=not SESSION.insecure_tls,
        apply_exclusions=True,
        delay=SESSION.delay,
    )
    out: Dict[str, Any] = {"email": report.get("email")}
    SESSION.add_identifier("email", report.get("email") or address)
    cands = report.get("candidates", [])[:max_candidates]
    out["candidates"] = cands
    SESSION.add_candidates(cands)
    if include_sources:
        out["sources"] = report.get("sources", {})
    results = _scan_results(report.get("results", []))
    SESSION.add_results(report.get("results", []))
    out["results"] = results
    out["summary"] = _summary(report.get("results", []))
    if report.get("sweep_error"):
        out["sweep_error"] = report["sweep_error"]
    return out


def _investigate_phone(number: str) -> Dict[str, Any]:
    report = run_phone_pipeline(number)
    SESSION.add_identifier("phone", number)
    return report


def _investigate_name(first: str, last: Optional[str], year: Optional[int]) -> Dict[str, Any]:
    report = run_name_pipeline(first, last, year, fetcher=_fetcher())
    SESSION.add_identifier("name", report.get("name", ""))
    SESSION.add_candidates(report.get("candidates", []))
    return report


def _generate_candidates(seed: str, year: Optional[int], style: str) -> Dict[str, Any]:
    style = (style or "broad").lower()
    if "@" in seed:
        local = oc.split_email(seed)[0]
    else:
        local = seed.strip().lower()
    if style == "simple":
        cands = oc.simple_candidates(local)
    elif style == "second_wave":
        cands = oc.second_wave_candidates([local])
    else:
        cands = oc.generate_candidates(local, year)
    SESSION.add_candidates(cands)
    return {"seed": seed, "style": style, "candidates": cands}


def _sweep_username(username: str, nsfw: Optional[bool], in_parallel: Optional[int],
                    max_sites: Optional[int], budget: Optional[float]) -> Dict[str, Any]:
    sites = load_site_databases(SESSION.sites_db)
    out = run_username_pipeline_bounded(
        username,
        sites,
        proxy=SESSION.proxy,
        timeout=SESSION.timeout,
        in_parallel=in_parallel or SESSION.in_parallel,
        skip_nsfw=not (nsfw if nsfw is not None else SESSION.nsfw),
        verify_ssl=not SESSION.insecure_tls,
        apply_exclusions=True,
        max_sites=max_sites,
        budget=budget,
    )
    results = out["results"]
    SESSION.add_results(results)
    SESSION.add_identifier("username", username)
    return {"username": username, "results": _scan_results(results),
            "summary": _summary(results), "truncated": out["truncated"],
            "total_sites": out["total_sites"], "checked": out["checked"]}


def _find_profiles(email: str, max_candidates: int, skip_breaches: bool) -> Dict[str, Any]:
    fetch = _fetcher()
    local, _domain, first, last, num = oc.split_email(email)
    subs = {"email": email, "fl": f"{first} {last}".strip(),
            "fu": first, "lu": last, "f": first, "l": last, "n": num}
    cands = oc.simple_candidates(local)[:max_candidates]
    SESSION.add_identifier("email", email)
    SESSION.add_candidates(cands)

    profiles = []
    for site in _PROFILE_SITES:
        for c in cands:
            hit, title = oc.probe(fetch, site, oc.PLATFORMS[site], c)
            profiles.append({**hit, "title": title})

    dorks = []
    seen = set()
    for q in _PROFILE_DORKS:
        query = q.format(**subs)
        if len(query) < 6:
            continue
        hits, _states, _flag = oc.dork(fetch, query)
        adult = [h for h in hits
                 if _ADULT_HOST_RE.search(h["url"]) and h["url"] not in seen]
        for h in adult:
            seen.add(h["url"])
        slug_hits = _PROFILE_SLUG_RE.findall(" ".join(h["url"] for h in adult))
        dorks.append({"query": query, "adult_hits": adult,
                      "profile_slugs": list(set(slug_hits))})

    slugs = sorted({s for d in dorks for s in d["profile_slugs"]})

    breaches = None
    if not skip_breaches:
        b = oc.leakcheck(fetch, email, limit=30)
        b["source"] = "leakcheck.io (public)"
        b["adult_sources"] = [s for s in (b.get("sources") or [])
                              if isinstance(s, str) and _ADULT_LEAK_RE.search(s)]
        breaches = b

    confirmed = [p["url"] for p in profiles if p["verdict"] == "confirmed"]
    return {"email": email, "candidates": cands, "profiles": profiles,
            "dorks": dorks, "profile_slugs": slugs, "confirmed": confirmed,
            "breaches": breaches}


def _breach(query: str, qtype: Optional[str], sources: Optional[str]) -> Dict[str, Any]:
    srcs = [s.strip() for s in sources.split(",") if s.strip()] if sources else None
    return run_breach_pipeline(
        query,
        qtype=qtype,
        proxy=SESSION.proxy,
        delay=SESSION.delay,
        sources=srcs,
    )


def _subdomains(domain: str) -> Dict[str, Any]:
    return oc.enum_subdomains(_fetcher(), domain)


def _docs(target: str) -> Dict[str, Any]:
    return oc.hunt_docs(_fetcher(), target)


def _onion(query: str) -> Dict[str, Any]:
    state, hits = oc.search_onion(_fetcher(), query)
    return {"query": query, "state": state, "hits": hits}


def _github(query: str) -> Dict[str, Any]:
    return oc.github_leaks(_fetcher(), query)


def _dork(query: str) -> Dict[str, Any]:
    hits, states, flag = oc.dork(_fetcher(), query)
    return {"query": query, "hits": hits, "states": states,
            "throttled": bool(flag)}


def _suggest(query: str) -> Dict[str, Any]:
    return oc.suggest(_fetcher(), query)


def _mentions(query: str) -> Dict[str, Any]:
    return {"query": query, "sources": oc.mentions_detailed(_fetcher(), query)}


_WALL_MARKERS = (
    "enable javascript", "checking your browser", "just a moment",
    "log in to continue", "sign in to continue", "login to continue",
    "content not available", "this page isn't available",
)


def _looks_walled(html: str) -> bool:
    low = html.lower()
    return len(html) < 4000 and any(m in low for m in _WALL_MARKERS)


def _autopsy(url: str) -> Dict[str, Any]:
    host = (urlsplit(url).hostname or "") if url else ""
    r = _fetcher().get(url)
    if r is None or r.status_code != 200:
        return {"url": url, "platform": host, "error": "unreachable"}
    html = r.text
    links = oc.cross_links(html)
    emails = oc.page_emails(html)
    handles = oc.at_handles(html)
    walled = oc.detect_waf(html) or (not links and _looks_walled(html))
    out = {"url": url, "platform": host, "wall": walled,
           "links": links, "emails": emails, "handles": handles}
    if walled:
        out["note"] = ("JS/login shell or WAF returned — no server-rendered "
                       "profile data. Corroborate via corroborate_handle or "
                       "search_dork instead of retrying this URL.")
    return out


def _autodork(url: str, anchors: Optional[List[str]]) -> Dict[str, Any]:
    r = _fetcher().get(url)
    if r is None or r.status_code != 200:
        return {"url": url, "error": "unreachable"}
    html = r.text
    og = oc.extract_og_tags(html)
    og_text = " ".join(v for v in og.values() if v)
    keywords = oc.extract_keywords(html + "\n" + og_text)
    base = list(anchors or []) + SESSION.candidate_handles[:5]
    base += [v for v in SESSION.identifiers.values() if isinstance(v, str)]
    queries = oc.auto_dorks(html, base)
    return {"url": url,
            "og_tags": og,
            "keywords": [kw for kw, _ in keywords],
            "dorks": queries}


def _corroborate(handle: str, sites: Optional[List[str]]) -> Dict[str, Any]:
    queries = [f'"{handle}"']
    for site in (sites or []):
        if site:
            queries.append(f'site:{site} "{handle}"')
    out = []
    for q in queries[:5]:
        hits, states, flag = oc.dork(_fetcher(), q)
        out.append({"query": q, "hits": hits, "states": states,
                    "throttled": bool(flag)})
    return {"handle": handle, "results": out}


def _pivot() -> Dict[str, Any]:
    if not SESSION.results:
        return {"usernames": [], "emails": [], "ranked_usernames": [],
                "note": "no results collected yet — run a sweep first"}
    pivots = oc.extract_pivots(SESSION.results)
    emails = oc.extract_email_pivots(SESSION.results)
    usernames = [
        {"username": p.username, "kind": p.kind.value,
         "source_site": p.source_site, "site": p.site, "url": p.url}
        for p in pivots
    ]
    SESSION.add_candidates([p.username for p in pivots])
    return {
        "usernames": usernames,
        "emails": [{"email": e.email, "kind": e.kind.value,
                    "source_site": e.source_site} for e in emails],
        "ranked_usernames": oc.rank_usernames(pivots),
    }


def _clear() -> Dict[str, Any]:
    SESSION.clear()
    return {"cleared": True}


def _run_investigation(target: str, target_type: Optional[str], depth: str) -> Dict[str, Any]:
    """Execute an automated investigation and return findings + a continuation plan."""
    ttype = (target_type or detect_target_type(target)).lower()
    depth = (depth or "fast").lower()
    findings: Dict[str, Any] = {}

    if ttype == "email":
        findings["email"] = _investigate_email(
            target, sweep_candidates=(depth == "full"), max_candidates=5,
            include_sources=True)
        findings["breach"] = _breach(target, "email", None)
        findings["github"] = _github(target)
    elif ttype == "phone":
        findings["phone"] = _investigate_phone(target)
    elif ttype == "name":
        parts = target.split(maxsplit=1)
        first = parts[0]
        last = parts[1] if len(parts) > 1 else None
        findings["name"] = _investigate_name(first, last, None)
        if depth == "full":
            for handle in findings["name"].get("candidates", [])[:5]:
                findings[f"sweep:{handle}"] = _sweep_username(handle, None, None, 100, 60.0)
    elif ttype == "username":
        findings["sweep"] = _sweep_username(target, None, None, 100, 60.0)
        findings["breach"] = _breach(target, "username", None)
        findings["github"] = _github(target)
    elif ttype == "domain":
        findings["subdomains"] = _subdomains(target)
        findings["docs"] = _docs(target)
        findings["breach"] = _breach(target, "domain", None)

    plan = build_plan(target, ttype)
    return {"target": target, "target_type": ttype, "depth": depth,
            "findings": findings, "next_steps": plan}


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------

def register_tools(mcp) -> None:
    """Register every tool on the FastMCP instance."""

    @mcp.tool()
    def configure(
        proxy: Optional[str] = None,
        delay_min: float = 1.5,
        delay_max: float = 3.5,
        timeout: float = 10.0,
        nsfw: bool = False,
        in_parallel: int = 20,
        sites_db: str = "all",
        insecure_tls: bool = False,
    ) -> Dict[str, Any]:
        """Set OPSEC configuration for subsequent tool calls.

        Call this first to route traffic through Tor (proxy=socks5h://127.0.0.1:9050),
        tune inter-request delays, and toggle NSFW sites / TLS verification.
        """
        return _run(_configure, proxy, delay_min, delay_max, timeout, nsfw,
                    in_parallel, sites_db, insecure_tls)

    @mcp.tool()
    def status() -> Dict[str, Any]:
        """Show current session state: proxy, delays, collected results, and which
        optional API keys are configured."""
        return _run(_status)

    @mcp.tool()
    def tor_check() -> Dict[str, Any]:
        """Verify the current exit IP is a Tor relay (queries check.torproject.org)."""
        return _run(_tor_check)

    @mcp.tool()
    def rotate_tor_circuit() -> Dict[str, Any]:
        """Rotate the Tor circuit for a fresh exit IP (needs ControlPort 9051).
        Use when search engines start throttling the current exit."""
        return _run(_rotate_tor_circuit)

    @mcp.tool()
    def osint_plan(target: str, target_type: Optional[str] = None) -> Dict[str, Any]:
        """Return a detailed, phase-by-phase passive OSINT investigation plan for a
        target. target_type is auto-detected (email/phone/name/username/domain) when
        omitted. Use this first to see the whole workflow, then execute it with the
        granular tools."""
        return _run(_plan, target, target_type)

    @mcp.tool()
    def run_investigation(target: str, target_type: Optional[str] = None,
                          depth: str = "fast") -> Dict[str, Any]:
        """Run a fully-automated investigation for a target and return the findings
        plus a continuation plan. depth='fast' runs the keyless lookups (breach,
        github, subdomains); depth='full' also runs username sweeps."""
        return _run(_run_investigation, target, target_type, depth)

    @mcp.tool()
    def investigate_email(address: str, sweep_candidates: bool = False,
                          max_candidates: int = 5,
                          include_sources: bool = True) -> Dict[str, Any]:
        """Investigate an email: breach metadata (LeakCheck/Hudson Rock), Gravatar
        profile, username candidates, and (optionally) a username sweep of the top
        candidates. Passively queries third-party databases only."""
        return _run(_investigate_email, address, sweep_candidates, max_candidates,
                    include_sources)

    @mcp.tool()
    def investigate_phone(number: str) -> Dict[str, Any]:
        """Normalize a phone number (E.164/national/international), report line type,
        carrier and region, and generate search-engine dorks for every format."""
        return _run(_investigate_phone, number)

    @mcp.tool()
    def investigate_name(first: str, last: Optional[str] = None,
                         year: Optional[int] = None) -> Dict[str, Any]:
        """Investigate a name: username candidates, identity dorks (LinkedIn/Facebook/
        socials), and Wikipedia public-figure disambiguation."""
        return _run(_investigate_name, first, last, year)

    @mcp.tool()
    def generate_candidates(seed: str, year: Optional[int] = None,
                            style: str = "broad") -> Dict[str, Any]:
        """Generate username candidates from an email local-part or a name fragment.
        style: 'broad' (full permutation sweep), 'simple' (compact), or 'second_wave'."""
        return _run(_generate_candidates, seed, year, style)

    @mcp.tool()
    def sweep_username(username: str, nsfw: Optional[bool] = None,
                       in_parallel: Optional[int] = None,
                       max_sites: Optional[int] = 100,
                       budget: Optional[float] = 60.0) -> Dict[str, Any]:
        """Sweep a username across the Maigret/Sherlock site databases (GET-only,
        async). Bounded to the top ~100 sites by default and capped by a wall-clock
        `budget` (seconds); returns partial results with `truncated=true` if the
        budget is hit. Pass max_sites=None for the full database. Requires
        `pip install maigret sherlock-project`."""
        return _run(_sweep_username, username, nsfw, in_parallel, max_sites, budget)

    @mcp.tool()
    def breach_search(query: str, qtype: Optional[str] = None,
                      sources: Optional[str] = None) -> Dict[str, Any]:
        """Multi-source breach/leak search. qtype is auto-detected (email/username/
        domain); declare 'password' explicitly. sources is an optional comma-separated
        provider whitelist."""
        return _run(_breach, query, qtype, sources)

    @mcp.tool()
    def find_profiles(email: str, max_candidates: int = 12,
                      skip_breaches: bool = False) -> Dict[str, Any]:
        """Passive (target-never-notified) locator for XNXX/XVideos profiles tied to an
        email. GET-only: probes public profile URLs for generated candidates, runs
        adult-scoped search dorks, and pulls LeakCheck breach metadata. Best run after
        configure(proxy=...Tor...) for privacy."""
        return _run(_find_profiles, email, max_candidates, skip_breaches)

    @mcp.tool()
    def enumerate_subdomains(domain: str) -> Dict[str, Any]:
        """Passively enumerate subdomains from crt.sh, HackerTarget and AlienVault OTX
        (no brute-forcing, no contact with the target's infrastructure)."""
        return _run(_subdomains, domain)

    @mcp.tool()
    def hunt_docs(target: str) -> Dict[str, Any]:
        """Hunt exposed documents for a domain or name via a filetype:/open-dir/
        cloud-bucket dork pack run through every configured search engine."""
        return _run(_docs, target)

    @mcp.tool()
    def search_onion(query: str) -> Dict[str, Any]:
        """Search Ahmia for dark-web (.onion) mentions of a query. Open results with
        Tor."""
        return _run(_onion, query)

    @mcp.tool()
    def github_leaks(query: str) -> Dict[str, Any]:
        """Search GitHub code/commits/users for an email or username (code search
        needs OHO_GITHUB_KEY)."""
        return _run(_github, query)

    @mcp.tool()
    def search_dork(query: str) -> Dict[str, Any]:
        """Run a free-form search-engine dork across DuckDuckGo + Bing (and Google
        when OHO_GOOGLE_KEY + OHO_GOOGLE_CX are set)."""
        return _run(_dork, query)

    @mcp.tool()
    def suggest(query: str) -> Dict[str, Any]:
        """Return search-engine autocomplete suggestions around a query (a cheap pivot
        generator)."""
        return _run(_suggest, query)

    @mcp.tool()
    def mentions(query: str) -> Dict[str, Any]:
        """Find posts/pages that mention an identifier (Reddit + StackExchange),
        with per-source state so an empty result is distinguishable from a
        blocked/failed source."""
        return _run(_mentions, query)

    @mcp.tool()
    def autopsy_url(url: str) -> Dict[str, Any]:
        """Harvest cross-platform links, email addresses and @handles out of a fetched
        profile page. Detects JS/login shells and WAF walls and reports them as
        `wall: true` instead of empty results."""
        return _run(_autopsy, url)

    @mcp.tool()
    def auto_dork_url(url: str, anchors: Optional[List[str]] = None) -> Dict[str, Any]:
        """Fetch a profile page, extract its distinctive keywords (seeded from
        og:title/og:description when present), and build anchor-aware dorks."""
        return _run(_autodork, url, anchors)

    @mcp.tool()
    def corroborate_handle(handle: str, sites: Optional[List[str]] = None) -> Dict[str, Any]:
        """Corroborate a handle via search-engine dorks: `"handle"` and, for each
        platform in `sites`, `site:platform "handle"`. The search-index pass that
        confirms (or refutes) a sweep hit without touching the walled platform."""
        return _run(_corroborate, handle, sites)

    @mcp.tool()
    def pivot_results() -> Dict[str, Any]:
        """Correlate collected sweep results into ranked new usernames and email
        addresses to feed back into the investigation."""
        return _run(_pivot)

    @mcp.tool()
    def clear_session() -> Dict[str, Any]:
        """Reset accumulated session state (identifiers, candidates, results)."""
        return _run(_clear)
