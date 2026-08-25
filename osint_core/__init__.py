"""osint_core: shared building blocks for the passive-OSINT skills.

The skill scripts (interactive shell and one-shot finders) are thin CLIs over
these modules so all network, search, probing and parsing logic lives in one
place instead of being copy-pasted per script.
"""

from .constants import (
    NOT_FOUND_MARKERS,
    PHONE_TYPE,
    PLATFORMS,
    QUICK_SITES,
    UAS,
    VERDICT_MARK,
)
from .net import (Fetcher, build_session, polite, strip_tags, valid_proxy,
                  warn_if_dns_leaking)
from .cli import add_common_args, fetcher_from_args, save_report
from .search import dork, search_bing, search_ddg
from .probe import classify, page_title, probe
from .sources import gravatar, hudson_rock, leakcheck, wayback_cdx
from .breach import (
    breach_search,
    detect_qtype,
    get_api_keys,
    breach_leakcheck,
    breach_hudson_rock_email,
    breach_hudson_rock_username,
    breach_hudson_rock_domain,
    breach_xposedornot,
    breach_hibp_catalogue,
    pwned_password,
    breach_xon_password,
    breach_proxynova,
    breach_emailrep,
    breach_hibp_account,
    breach_intelx,
    breach_breachdirectory,
)
from .harvest import at_handles, cross_links, page_emails
from .candidates import (
    generate_candidates,
    parse_local,
    second_wave_candidates,
    simple_candidates,
    split_email,
)

# --- New modules from Maigret / user-scanner integration ---
from .scan_result import ScanResult, ScanStatus
from .async_check import (
    check_site,
    check_username_on_sites,
    check_username_sync,
    detect_waf,
    AiohttpChecker,
    CurlCffiChecker,
    DnsResolver,
)
from .impersonate import (
    impersonate_request,
    impersonate_validate,
    impersonate_request_async,
    is_available as curl_cffi_available,
)
from .site_db import (
    MaigretSite, MaigretEngine, MaigretDatabase,
    load_db, load_default_db,
    load_sherlock_db, load_default_sherlock_db,
)
from .executors import AsyncQueueExecutor, AsyncGeneratorExecutor, run_checks_parallel
from .pivots import (
    Pivot,
    PivotKind,
    EmailPivot,
    EmailKind,
    extract_pivots,
    select_pivots,
    extract_email_pivots,
    select_email_pivots,
    rank_usernames,
    resolve_url,
)
from .confidence import (
    Confidence,
    Anchors,
    RankedEmail,
    build_anchors,
    score,
    rank_emails,
    ORDER as CONFIDENCE_ORDER,
)
from .patterns import (
    expand_patterns,
    expand_patterns_random,
    count_patterns,
    expand_wildcard,
    expand_wildcard_all,
)
from .exclusions import fetch_exclusions, filter_excluded_sites

__all__ = [
    # original
    "NOT_FOUND_MARKERS", "PHONE_TYPE", "PLATFORMS", "QUICK_SITES", "UAS",
    "VERDICT_MARK",
    "Fetcher", "build_session", "polite", "strip_tags", "valid_proxy",
    "warn_if_dns_leaking",
    "add_common_args", "fetcher_from_args", "save_report",
    "dork", "search_bing", "search_ddg",
    "classify", "page_title", "probe",
    "gravatar", "hudson_rock", "leakcheck", "wayback_cdx",
    "breach_search", "detect_qtype", "get_api_keys",
    "breach_leakcheck", "breach_hudson_rock_email",
    "breach_hudson_rock_username", "breach_hudson_rock_domain",
    "breach_xposedornot", "breach_hibp_catalogue",
    "pwned_password", "breach_xon_password", "breach_proxynova",
    "breach_emailrep", "breach_hibp_account", "breach_intelx",
    "breach_breachdirectory",
    "at_handles", "cross_links", "page_emails",
    "generate_candidates", "parse_local", "second_wave_candidates",
    "simple_candidates", "split_email",
    # scan_result
    "ScanResult", "ScanStatus",
    # async_check
    "check_site", "check_username_on_sites", "check_username_sync", "detect_waf",
    "AiohttpChecker", "CurlCffiChecker", "DnsResolver",
    # impersonate
    "impersonate_request", "impersonate_validate", "impersonate_request_async",
    "curl_cffi_available",
    # site_db
    "MaigretSite", "MaigretEngine", "MaigretDatabase",
    "load_db", "load_default_db",
    "load_sherlock_db", "load_default_sherlock_db",
    # executors
    "AsyncQueueExecutor", "AsyncGeneratorExecutor", "run_checks_parallel",
    # pivots
    "Pivot", "PivotKind", "EmailPivot", "EmailKind",
    "extract_pivots", "select_pivots",
    "extract_email_pivots", "select_email_pivots",
    "rank_usernames", "resolve_url",
    # confidence
    "Confidence", "Anchors", "RankedEmail",
    "build_anchors", "score", "rank_emails", "CONFIDENCE_ORDER",
    # patterns
    "expand_patterns", "expand_patterns_random", "count_patterns",
    "expand_wildcard", "expand_wildcard_all",
    # exclusions
    "fetch_exclusions", "filter_excluded_sites",
]
