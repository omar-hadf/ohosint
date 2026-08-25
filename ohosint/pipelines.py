"""Investigation pipelines for OHOsint.

Reusable functions for email, phone, username, and name investigation.
Each pipeline returns a list of ScanResult objects.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

import osint_core as oc
from osint_core.async_check import check_username_on_sites
from osint_core.scan_result import ScanResult

logger = logging.getLogger(__name__)


def load_site_databases(db_choice: str = "all") -> Dict[str, oc.MaigretSite]:
    """Load and merge Maigret and/or Sherlock site databases.

    Args:
        db_choice: "maigret", "sherlock", or "all".

    Returns:
        Dict of site_name -> MaigretSite.

    Raises:
        ValueError: if no sites could be loaded (missing dependencies).
    """
    merged: Dict[str, oc.MaigretSite] = {}

    if db_choice in ("maigret", "all"):
        maigret_db = oc.load_default_db()
        if maigret_db:
            for name, site in maigret_db.get_enabled_sites().items():
                merged[name] = site
            logger.info("Loaded %d Maigret sites", len(maigret_db.get_enabled_sites()))
        else:
            logger.warning("Maigret database not found")

    if db_choice in ("sherlock", "all"):
        sherlock_db = oc.load_default_sherlock_db()
        if sherlock_db:
            for name, site in sherlock_db.get_enabled_sites().items():
                existing = next((s for s in merged.values() if s.url_main == site.url_main), None)
                if existing:
                    continue
                merged[name] = site
            logger.info("Loaded %d Sherlock sites", len(sherlock_db.get_enabled_sites()))
        else:
            logger.warning("Sherlock database not found")

    if not merged:
        raise ValueError(
            "0 sites loaded — install at least one site database: "
            "pip install maigret sherlock-project   (or: pip install -e .[sweep])"
        )

    return merged


def run_username_pipeline(
    username: str,
    sites: Dict[str, oc.MaigretSite],
    proxy: Optional[str] = None,
    timeout: float = 10.0,
    in_parallel: int = 20,
    skip_nsfw: bool = True,
    apply_exclusions: bool = True,
    verify_ssl: bool = True,
    on_done=None,
) -> List[ScanResult]:
    """Run an async username sweep across loaded site databases."""
    if apply_exclusions:
        try:
            exclusions = oc.fetch_exclusions(proxy=proxy)
            sites = oc.filter_excluded_sites(sites, exclusions=exclusions)
        except Exception as e:
            logger.warning("Failed to apply exclusions: %s", e)

    return oc.check_username_sync(
        sites,
        username,
        proxy=proxy,
        timeout=timeout,
        in_parallel=in_parallel,
        skip_nsfw=skip_nsfw,
        verify_ssl=verify_ssl,
        on_done=on_done,
    )


def run_email_pipeline(
    email: str,
    sites: Optional[Dict[str, oc.MaigretSite]] = None,
    proxy: Optional[str] = None,
    timeout: float = 10.0,
    in_parallel: int = 20,
    skip_nsfw: bool = True,
    verify_ssl: bool = True,
    apply_exclusions: bool = True,
    delay=(1.5, 3.5),
) -> Dict[str, Any]:
    """Run the full email investigation pipeline.

    Returns a dict with:
        - email: normalized email
        - candidates: generated username candidates
        - sources: passive source lookups
        - results: async username sweep results (if sites provided)
    """
    report = {"email": email, "candidates": [], "sources": {}, "results": []}

    # Generate candidates
    local, _, _, _, _ = oc.split_email(email)
    report["candidates"] = oc.simple_candidates(local)
    logger.info("Generated %d candidates from email", len(report["candidates"]))

    # Passive source lookups (all share a polite Fetcher)
    fetcher = oc.Fetcher(proxy=proxy, delay=delay)
    try:
        report["sources"]["gravatar"] = oc.gravatar(fetcher, email)
    except Exception as e:
        logger.debug("Gravatar lookup failed: %s", e)

    try:
        report["sources"]["leakcheck"] = oc.leakcheck(fetcher, email)
    except Exception as e:
        logger.debug("LeakCheck lookup failed: %s", e)

    try:
        report["sources"]["hudson_rock"] = oc.hudson_rock(fetcher, email)
    except Exception as e:
        logger.debug("Hudson Rock lookup failed: %s", e)

    # Username sweep across candidates — all concurrently
    if sites:
        # Apply exclusions once (not per-candidate)
        if apply_exclusions:
            try:
                exclusions = oc.fetch_exclusions(proxy=proxy)
                sites = oc.filter_excluded_sites(sites, exclusions=exclusions)
            except Exception as e:
                logger.warning("Failed to apply exclusions: %s", e)

        candidates = report["candidates"][:5]
        total = len(candidates)
        total_sites = len(sites)

        async def _sweep_all():
            tasks = [
                asyncio.ensure_future(
                    check_username_on_sites(
                        sites, candidate, proxy=proxy, timeout=timeout,
                        in_parallel=in_parallel, skip_nsfw=skip_nsfw,
                        verify_ssl=verify_ssl,
                    )
                )
                for candidate in candidates
            ]
            results = []
            done = 0
            for coro in asyncio.as_completed(tasks):
                batch = await coro
                done += 1
                found = sum(1 for r in batch if r.is_found())
                print(
                    f"  [{done}/{total}] sweep {done}/{total} done "
                    f"— {found} found on {len(batch)}/{total_sites} sites"
                )
                results.extend(batch)
            return results

        print(f"  Sweeping {total} candidates across {total_sites} sites...")
        report["results"] = asyncio.run(_sweep_all())

    return report


def run_phone_pipeline(phone: str) -> Dict[str, Any]:
    """Run phone normalization and format-based dorks.

    Returns a dict with:
        - input: original input
        - e164, international, national: formatted numbers
        - valid: bool
        - type: line type
        - carrier: carrier name (if available)
        - dorks: search queries
    """
    report = {"input": phone}

    try:
        import phonenumbers
        parsed = phonenumbers.parse(phone)
        report["valid"] = phonenumbers.is_valid_number(parsed)
        report["e164"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        report["international"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        report["national"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        report["type"] = phonenumbers.number_type(parsed).__name__
        try:
            from phonenumbers.geocoder import description_for_number
            report["region"] = description_for_number(parsed, "en")
        except Exception:
            pass
        try:
            from phonenumbers.carrier import name_for_number
            report["carrier"] = name_for_number(parsed, "en")
        except Exception:
            pass
    except Exception as e:
        report["valid"] = False
        report["error"] = str(e)
        return report

    # Generate dork queries
    raw = report["e164"].lstrip("+")
    report["dorks"] = [
        f'"{report["e164"]}"',
        f'"{report["national"]}"',
        f'"{raw}"',
    ]

    return report


def run_name_pipeline(first: str, last: Optional[str] = None, year: Optional[int] = None) -> Dict[str, Any]:
    """Run name-based dorking and candidate generation.

    Returns a dict with:
        - name: full name
        - slug: URL slug
        - candidates: username candidates
        - dorks: search queries
    """
    full = f"{first} {last}".strip() if last else first
    report = {"name": full, "candidates": [], "dorks": []}

    # Build slug
    slug = f"{first}-{last}".lower() if last else first.lower()
    slug = "".join(c if c.isalnum() else "-" for c in slug)
    report["slug"] = slug

    # Generate username candidates from name
    candidates = set()
    candidates.add(slug.replace("-", ""))
    candidates.add(slug.replace("-", "_"))
    candidates.add(slug.replace("-", "."))
    if last:
        candidates.add(first[0].lower() + last.lower())
        candidates.add(first.lower() + last[0].lower())
    if year:
        for base in list(candidates):
            candidates.add(f"{base}{year}")
            candidates.add(f"{base}{str(year)[-2:]}")
    report["candidates"] = sorted(c for c in candidates if c)

    # Dorks
    report["dorks"] = {
        "general": f'"{full}"',
        "linkedin": f'site:linkedin.com "{full}"',
        "facebook": f'site:facebook.com "{full}"',
        "adult": f'"{full}" "profile"',
    }

    return report


def run_breach_pipeline(
    query: str,
    qtype: Optional[str] = None,
    proxy: Optional[str] = None,
    delay=(1.5, 3.5),
    sources: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run the multi-source breach-search pipeline.

    Args:
        query: email, username, domain, or password.
        qtype: "email" | "username" | "domain" | "password";
            auto-detected when None (passwords must be declared explicitly).
        proxy: HTTP/SOCKS proxy URL.
        delay: inter-request (min, max) passed to the Fetcher.
        sources: optional provider whitelist.

    Returns the normalized breach report dict from osint_core.breach.
    """
    fetcher = oc.Fetcher(proxy=proxy, delay=delay)
    return oc.breach_search(fetcher, query, qtype=qtype, sources=sources)


def extract_pivots_from_results(results: List[ScanResult]) -> Dict[str, List]:
    """Extract handle and email pivots from collected results."""
    return {
        "usernames": oc.extract_pivots(results),
        "emails": oc.extract_email_pivots(results),
    }
