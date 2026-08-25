"""Profile-page probing and verdict classification.

This module provides synchronous probe() for the legacy skills/ scripts.
New code in ohosint/ uses osint_core.async_check (async probing) and
osint_core.scan_result (ScanResult model) instead. Both engines are live
and intentionally kept separate: skills/ uses probe.py for simplicity
(single-threaded, delay-polite, GET-only), while ohosint/ uses async_check
for scale and speed (concurrent aiohttp/curl_cffi backends).
"""

import asyncio
import re

from .constants import NOT_FOUND_MARKERS


def page_title(text):
    m = re.search(r"<title>(.*?)</title>", text, re.S | re.I)
    return m.group(1).strip() if m else ""


def classify(text, status, user):
    low = text.lower()
    nf = any(m in low for m in NOT_FOUND_MARKERS)
    present = user.lower() in low
    if status == 200 and not nf and present:
        return "confirmed"
    if status == 200 and not nf:
        return "probable"
    return "absent"


def probe(fetcher, site, template, user):
    """GET template.format(u=user); return (result_dict, page_title[:90])."""
    url = template.format(u=user)
    r = fetcher.get(url)
    if r is None:
        return {"site": site, "candidate": user, "url": url,
                "verdict": "unknown"}, ""
    verdict = classify(r.text, r.status_code, user)
    return ({"site": site, "candidate": user, "url": url,
             "status": r.status_code, "verdict": verdict},
            page_title(r.text)[:90])


# ---------------------------------------------------------------------------
# New async API (primary interface going forward)
# ---------------------------------------------------------------------------

async def probe_async(site, username, proxy=None, timeout=10):
    """Async probe using the new engine. Returns a ScanResult."""
    from .async_check import check_site
    return await check_site(site, username, proxy=proxy, timeout=timeout)


async def probe_sites_async(sites, username, proxy=None, timeout=10, in_parallel=20):
    """Probe many sites concurrently. Returns list of ScanResult."""
    from .async_check import check_username_on_sites
    return await check_username_on_sites(sites, username, proxy=proxy,
                                         timeout=timeout, in_parallel=in_parallel)


def probe_sites_sync(sites, username, proxy=None, timeout=10, in_parallel=20):
    """Synchronous wrapper for probe_sites_async."""
    return asyncio.run(probe_sites_async(sites, username, proxy, timeout, in_parallel))
