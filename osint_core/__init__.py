"""osint_core: shared building blocks for the passive-OSINT skills.

The skill scripts (interactive shell and one-shot finders) are thin CLIs over
these modules so all network, search, probing and parsing logic lives in one
place instead of being copy-pasted per script.
"""

from .async_check import (
    AiohttpChecker,
    CurlCffiChecker,
    DnsResolver,
    check_site,
    check_username_on_sites,
    check_username_on_sites_budget,
    check_username_sync,
    detect_waf,
)
from .breach import (
    breach_breachdirectory,
    breach_emailrep,
    breach_hibp_account,
    breach_hibp_catalogue,
    breach_hudson_rock_domain,
    breach_hudson_rock_email,
    breach_hudson_rock_username,
    breach_intelx,
    breach_leakcheck,
    breach_proxynova,
    breach_search,
    breach_xon_password,
    breach_xposedornot,
    detect_qtype,
    get_api_keys,
    pwned_password,
)
from .candidates import (
    generate_candidates,
    parse_local,
    second_wave_candidates,
    simple_candidates,
    split_email,
)
from .cli import add_common_args, fetcher_from_args, save_report
from .confidence import (
    ORDER as CONFIDENCE_ORDER,
)
from .confidence import (
    Anchors,
    Confidence,
    RankedEmail,
    build_anchors,
    rank_emails,
    score,
)
from .constants import (
    NOT_FOUND_MARKERS,
    PHONE_TYPE,
    PLATFORMS,
    QUICK_SITES,
    UAS,
    VERDICT_MARK,
)
from .docs import doc_dorks, hunt_docs
from .exclusions import fetch_exclusions, filter_excluded_sites
from .executors import AsyncGeneratorExecutor, AsyncQueueExecutor, run_checks_parallel
from .github_leaks import (
    github_code_search,
    github_commit_search,
    github_key,
    github_leaks,
    github_user_search,
)
from .harvest import at_handles, cross_links, page_emails
from .impersonate import (
    impersonate_request,
    impersonate_request_async,
    impersonate_validate,
)
from .impersonate import (
    is_available as curl_cffi_available,
)
from .keywords import auto_dorks, extract_keywords, extract_og_tags
from .mentions import mentions, mentions_detailed, reddit_mentions, stackexchange_mentions
from .net import Fetcher, build_session, polite, strip_tags, valid_proxy, warn_if_dns_leaking
from .onion import search_onion
from .patterns import (
    count_patterns,
    expand_patterns,
    expand_patterns_random,
    expand_wildcard,
    expand_wildcard_all,
)
from .pivots import (
    EmailKind,
    EmailPivot,
    Pivot,
    PivotKind,
    extract_email_pivots,
    extract_pivots,
    rank_usernames,
    resolve_url,
    select_email_pivots,
    select_pivots,
)
from .probe import classify, page_title, probe

# --- New modules from Maigret / user-scanner integration ---
from .scan_result import ScanResult, ScanStatus
from .search import dork, google_creds, search_bing, search_ddg, search_google
from .site_db import (
    MaigretDatabase,
    MaigretEngine,
    MaigretSite,
    load_db,
    load_default_db,
    load_default_sherlock_db,
    load_sherlock_db,
)
from .sources import gravatar, hudson_rock, leakcheck, wayback_cdx
from .subdomains import enum_subdomains, valid_domain
from .suggest import famous_collision, suggest, wikipedia_lookup

__all__ = [
    # original
    "NOT_FOUND_MARKERS", "PHONE_TYPE", "PLATFORMS", "QUICK_SITES", "UAS",
    "VERDICT_MARK",
    "Fetcher", "build_session", "polite", "strip_tags", "valid_proxy",
    "warn_if_dns_leaking",
    "add_common_args", "fetcher_from_args", "save_report",
    "dork", "google_creds", "search_bing", "search_ddg", "search_google",
    "enum_subdomains", "valid_domain",
    "doc_dorks", "hunt_docs",
    "search_onion",
    "github_key", "github_code_search", "github_commit_search",
    "github_user_search", "github_leaks",
    "suggest", "wikipedia_lookup", "famous_collision",
    "mentions", "mentions_detailed", "reddit_mentions", "stackexchange_mentions",
    "extract_keywords", "extract_og_tags", "auto_dorks",
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
    "check_site", "check_username_on_sites", "check_username_on_sites_budget",
    "check_username_sync", "detect_waf",
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
