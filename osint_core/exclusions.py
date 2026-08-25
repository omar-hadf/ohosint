"""Remote false-positive exclusion list.

Fetches a list of sites known to produce false positives from the Sherlock
project's exclusions file, and provides filtering logic.
"""

import logging
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

SHERLOCK_EXCLUSIONS_URL = (
    "https://raw.githubusercontent.com/sherlock-project/sherlock/"
    "refs/heads/exclusions/false_positive_exclusions.txt"
)

# Cache for the fetched exclusions
_exclusions_cache: Optional[Set[str]] = None


def fetch_exclusions(
    url: str = SHERLOCK_EXCLUSIONS_URL,
    timeout: float = 10,
    proxy: Optional[str] = None,
) -> Set[str]:
    """Fetch the false-positive exclusion list from Sherlock's repo.

    Returns a set of lowercase site names that are known to produce false positives.
    Caches the result for the lifetime of the process.

    ``proxy`` MUST be threaded through from the caller's configuration. This
    request is made on every sweep, so without it an ``--tor`` run still emits
    one clearnet request from the operator's real IP before any Tor-routed
    traffic starts (see docs/audit/security.md).
    """
    global _exclusions_cache
    if _exclusions_cache is not None:
        return _exclusions_cache

    try:
        import requests
        proxies = {"http": proxy, "https": proxy} if proxy else None
        resp = requests.get(url, timeout=timeout, proxies=proxies)
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        exclusions = set()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                exclusions.add(line.lower())
        _exclusions_cache = exclusions
        logger.info("Fetched %d exclusions from %s", len(exclusions), url)
        return exclusions
    except Exception as e:
        logger.warning("Failed to fetch exclusions from %s: %s", url, e)
        _exclusions_cache = set()
        return _exclusions_cache


def filter_excluded_sites(
    sites: Dict[str, Any],
    exclusions: Optional[Set[str]] = None,
    ignore_exclusions: bool = False,
) -> Dict[str, Any]:
    """Remove sites on the exclusion list from the scan target dict.

    Args:
        sites: Dict of site_name -> site object.
        exclusions: Set of site names to exclude. If None, fetches from remote.
        ignore_exclusions: If True, skip the exclusion filter entirely.

    Returns:
        Filtered dict of sites.
    """
    if ignore_exclusions:
        return sites

    if exclusions is None:
        exclusions = fetch_exclusions()

    if not exclusions:
        return sites

    filtered = {}
    excluded_count = 0
    for name, site in sites.items():
        if name.lower() in exclusions:
            excluded_count += 1
            continue
        filtered[name] = site

    if excluded_count:
        logger.info("Excluded %d sites from scan", excluded_count)

    return filtered
