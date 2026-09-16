"""Async username checking engine.

Provides multiple checker backends (aiohttp, curl_cffi, DNS) for probing
usernames across sites in parallel. Replaces the synchronous probe.py as the
primary checking engine. Derived from Maigret's checking module with Sherlock
WAF detection, errorCode/errorUrl support, regexCheck, and POST payloads.
"""

import asyncio
import logging
import random
import re
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from .scan_result import ScanResult, ScanStatus

logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def _random_ua() -> str:
    return random.choice(USER_AGENTS)


# ---------------------------------------------------------------------------
# WAF/CDN fingerprints (from Sherlock)
# ---------------------------------------------------------------------------

WAF_FINGERPRINTS = [
    r'loading-spinner\{visibility:hidden\}body\.no-js',
    r'<span id="challenge-error-text">',
    r'AwsWafIntegration\.forceRefreshToken',
    r'perimeterxIdentifiers',
    r'<title>Just a moment\.\.\.</title>',
    r'Checking if the site connection is secure',
    r'Enable JavaScript and cookies to continue',
    r'<meta name="robots" content="noindex,nofollow">',
]


def detect_waf(html: str) -> bool:
    """Return True if the response matches a known WAF/CDN fingerprint."""
    if not html:
        return False
    return any(re.search(fp, html) for fp in WAF_FINGERPRINTS)


# ---------------------------------------------------------------------------
# Error detection
# ---------------------------------------------------------------------------

def _detect_error(html: str, status: int, site_errors: dict, ignore_403: bool = False):
    """Return an error string if the response indicates a problem, else None."""
    low = html.lower() if html else ""

    for flag, msg in site_errors.items():
        if flag in low:
            return msg

    if status == 403 and not ignore_403:
        return "403 access denied"
    if status == 999:
        return None  # LinkedIn anti-bot, treat as valid
    if status >= 500:
        return f"{status} server error"
    return None


# ---------------------------------------------------------------------------
# Checker backends
# ---------------------------------------------------------------------------

class BaseChecker:
    """Abstract checker interface."""

    def prepare(self, url, headers=None, allow_redirects=True, timeout=10, method="get", payload=None):
        raise NotImplementedError

    async def check(self) -> Tuple[Optional[str], int, Optional[str]]:
        raise NotImplementedError

    async def close(self):
        pass


class AiohttpChecker(BaseChecker):
    """Checker using aiohttp with optional SOCKS5 proxy support."""

    def __init__(self, proxy: Optional[str] = None, verify_ssl: bool = True, logger=None):
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.logger = logger or logging.getLogger(__name__)
        self.url = None
        self.headers = None
        self.allow_redirects = True
        self.timeout = 10
        self.method = "get"
        self.payload = None

    def prepare(self, url, headers=None, allow_redirects=True, timeout=10, method="get", payload=None):
        self.url = url
        self.headers = headers
        self.allow_redirects = allow_redirects
        self.timeout = timeout
        self.method = method
        self.payload = payload

    async def check(self) -> Tuple[Optional[str], int, Optional[str]]:
        try:
            from aiohttp import ClientSession, ClientTimeout, TCPConnector
            from aiohttp.client_exceptions import ClientConnectorError, ServerDisconnectedError
        except ImportError:
            return None, 0, "aiohttp not installed"

        if self.verify_ssl:
            ssl_ctx = None  # aiohttp default: verify certificates
        else:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            if self.proxy and self.proxy.startswith("socks"):
                from aiohttp_socks import ProxyConnector
                connector = ProxyConnector.from_url(self.proxy, ssl=ssl_ctx)
            else:
                connector = TCPConnector(ssl=ssl_ctx)
        except ImportError:
            return None, 0, "aiohttp-socks not installed for SOCKS proxy"

        ct = ClientTimeout(total=self.timeout)
        try:
            async with ClientSession(connector=connector, trust_env=True, timeout=ct) as session:
                req_method = getattr(session, self.method.lower(), session.get)
                kwargs: Dict[str, Any] = {
                    "url": self.url,
                    "headers": self.headers or {"User-Agent": _random_ua()},
                    "allow_redirects": self.allow_redirects,
                }
                if self.payload and self.method.lower() == "post":
                    kwargs["json"] = self.payload

                async with req_method(**kwargs) as resp:
                    text = await resp.text(errors="ignore")
                    return text, resp.status, None

        except asyncio.TimeoutError:
            return None, 0, "timeout"
        except ClientConnectorError as e:
            return None, 0, f"connection error: {e}"
        except ServerDisconnectedError:
            return None, 0, "server disconnected"
        except Exception as e:
            return None, 0, str(e)


class CurlCffiChecker(BaseChecker):
    """Checker using curl_cffi to emulate browser TLS fingerprint."""

    def __init__(self, impersonate: str = "chrome", proxy: Optional[str] = None, logger=None):
        self.impersonate = impersonate
        self.proxy = proxy
        self.logger = logger or logging.getLogger(__name__)
        self.url = None
        self.headers = None
        self.allow_redirects = True
        self.timeout = 10
        self.method = "get"
        self.payload = None

    def prepare(self, url, headers=None, allow_redirects=True, timeout=10, method="get", payload=None):
        self.url = url
        self.headers = headers
        self.allow_redirects = allow_redirects
        self.timeout = timeout
        self.method = method
        self.payload = payload

    async def check(self) -> Tuple[Optional[str], int, Optional[str]]:
        try:
            from curl_cffi.requests import AsyncSession
        except ImportError:
            return None, 0, "curl_cffi not installed"

        try:
            async with AsyncSession(proxy=self.proxy) as session:
                kwargs: Dict[str, Any] = {
                    "url": self.url,
                    "headers": self.headers or {"User-Agent": _random_ua()},
                    "allow_redirects": self.allow_redirects,
                    "timeout": self.timeout,
                    "impersonate": self.impersonate,
                }
                if self.payload and self.method.lower() == "post":
                    kwargs["json"] = self.payload

                method_fn = getattr(session, self.method.lower(), session.get)
                resp = await method_fn(**kwargs)
                return resp.text, resp.status_code, None

        except asyncio.TimeoutError:
            return None, 0, "timeout"
        except Exception as e:
            return None, 0, str(e)


class DnsResolver(BaseChecker):
    """Checker that resolves a domain via DNS (checks if it exists)."""

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.url = None

    def prepare(self, url, headers=None, allow_redirects=True, timeout=10, method="get", payload=None):
        self.url = url

    async def check(self) -> Tuple[Optional[str], int, Optional[str]]:
        try:
            import aiodns
        except ImportError:
            return None, 0, "aiodns not installed"

        try:
            resolver = aiodns.DNSResolver()
            res = await resolver.query(self.url, "A")
            return str(res[0].host), 200, None
        except Exception:
            return "", 404, None


# ---------------------------------------------------------------------------
# Result classification (with Sherlock's errorCode/errorUrl/WAF support)
# ---------------------------------------------------------------------------

def classify_result(
    html_text: Optional[str],
    status_code: int,
    check_error: Optional[str],
    site: Any,
    username: str,
) -> ScanResult:
    """Classify a raw HTTP response into a ScanResult.

    Supports Sherlock's errorType array, errorCode, errorUrl, and WAF detection.
    """
    site_name = getattr(site, "pretty_name", getattr(site, "name", ""))
    url = getattr(site, "_probed_url", "")

    if check_error:
        return ScanResult.error(check_error, site_name=site_name, url=url)

    if not html_text:
        return ScanResult.error("empty response", site_name=site_name, url=url)

    # WAF detection (from Sherlock)
    if detect_waf(html_text):
        return ScanResult.waf(site_name=site_name, url=url)

    # Get error types (Sherlock supports arrays)
    error_types = getattr(site, "error_types", None)
    if error_types is None:
        ct = getattr(site, "check_type", "message")
        error_types = [ct] if ct else ["message"]

    # Check for absence markers. Normalize to a list first: a bare string here
    # would be iterated character-by-character, matching almost any page.
    absence_strs = getattr(site, "absence_strs", []) or []
    if isinstance(absence_strs, str):
        absence_strs = [absence_strs]
    absence_detected = any(m in html_text for m in absence_strs)

    # Check for presence markers — strings that MUST appear on a real profile.
    presense_strs = getattr(site, "presense_strs", []) or []
    if isinstance(presense_strs, str):
        presense_strs = [presense_strs]
    # No markers declared => nothing to disprove, so treat as satisfied.
    presense_detected = any(m in html_text for m in presense_strs) if presense_strs else True

    # Evaluate each error type in order (Sherlock logic)
    result_status = None

    for et in error_types:
        if et == "message":
            # absence_detected was computed above from the same markers.
            if absence_detected:
                result_status = ScanStatus.AVAILABLE
                break
            elif result_status is None:
                result_status = ScanStatus.CLAIMED

        elif et == "status_code":
            # Check custom errorCode (Sherlock)
            error_codes = getattr(site, "error_code", None)
            if error_codes is not None:
                if isinstance(error_codes, int):
                    error_codes = [error_codes]
                if status_code in error_codes:
                    result_status = ScanStatus.AVAILABLE
                    break
            # Standard status code check
            if status_code < 200 or status_code >= 300:
                result_status = ScanStatus.AVAILABLE
                break
            elif result_status is None:
                result_status = ScanStatus.CLAIMED

        elif et == "response_url":
            # Redirect-based detection (redirects should be disabled)
            if 200 <= status_code < 300:
                if result_status is None:
                    result_status = ScanStatus.CLAIMED
            else:
                result_status = ScanStatus.AVAILABLE
                break

    # Presence markers are a veto, applied after the error-type checks: if the
    # site declares strings that must appear on a real profile and none of them
    # are on the page, the account does not exist, whatever the status code or
    # absence-marker checks concluded. Without this the ~539 Maigret sites that
    # rely on presenceStrs/presenseStrs report false hits.
    if result_status == ScanStatus.CLAIMED and not presense_detected:
        result_status = ScanStatus.AVAILABLE

    if result_status is None:
        result_status = ScanStatus.UNKNOWN

    result = ScanResult(status=result_status, site_name=site_name, url=url)
    if result_status == ScanStatus.CLAIMED and not presense_strs:
        # The site declared no presence markers, so "claimed" rests solely on a
        # 200 with no absence marker — the classic false-positive family
        # (Apple, Wikipedia, GitHub Gist, Discord). Flag it as unconfirmed so
        # callers can demand search-index corroboration before trusting it.
        result.confidence = "low"
    return result


# ---------------------------------------------------------------------------
# Core check function
# ---------------------------------------------------------------------------

def _pick_checker(site, proxy: Optional[str] = None, verify_ssl: bool = True) -> BaseChecker:
    """Select the appropriate checker backend for a site.

    ``socks5h://`` routes DNS through the proxy and is the OPSEC-recommended
    scheme, but ``aiohttp_socks`` only accepts ``socks5``/``socks4``/``http``.
    libcurl (via ``curl_cffi``) accepts ``socks5h``, so prefer it when the
    scheme is present; otherwise rewrite to ``socks5`` with an explicit warning
    that DNS will resolve locally.
    """
    protection = getattr(site, "protection", [])
    if proxy and proxy.startswith("socks5h"):
        from .impersonate import is_available
        if is_available():
            return CurlCffiChecker(proxy=proxy)
        logger.warning(
            "curl_cffi unavailable; rewriting %s -> socks5:// for aiohttp "
            "(DNS will resolve locally and leak outside the proxy)", proxy)
        proxy = proxy.replace("socks5h://", "socks5://", 1)
    if "tls_fingerprint" in protection:
        from .impersonate import is_available
        if is_available():
            return CurlCffiChecker(proxy=proxy)
    if proxy and proxy.startswith("socks"):
        return AiohttpChecker(proxy=proxy, verify_ssl=verify_ssl)
    return AiohttpChecker(proxy=proxy, verify_ssl=verify_ssl)


def _interpolate_template(template: str, username: str) -> str:
    """Replace {} or {username} in a URL template."""
    if "{}" in template:
        return template.replace("{}", quote(username))
    return template.format(
        urlMain=template.split("/")[0] + "//" + template.split("/")[2] if "/" in template else "",
        username=quote(username),
    )


async def check_site(site, username: str, proxy: Optional[str] = None, timeout: float = 10, verify_ssl: bool = True) -> ScanResult:
    """Probe a single site for a username using the appropriate checker.

    Supports Sherlock's regexCheck pre-validation, urlProbe, errorCode,
    errorUrl, and POST payloads.
    """
    site_name = getattr(site, "pretty_name", getattr(site, "name", ""))

    # regexCheck pre-validation (from Sherlock)
    if not site.check_regex(username):
        return ScanResult.illegal(site_name=site_name, url="", error="username fails regexCheck")

    checker = _pick_checker(site, proxy, verify_ssl=verify_ssl)

    # Use urlProbe if available, otherwise build from url
    url = site.build_probe_url(username)
    site._probed_url = url

    headers = {"User-Agent": _random_ua(), "Connection": "close"}
    headers.update(getattr(site, "headers", {}))

    # Determine method: Sherlock defaults to HEAD for status_code detection
    method = getattr(site, "request_method", None)
    if method is None:
        check_type = getattr(site, "check_type", "message")
        method = "head" if check_type == "status_code" else "get"
    method = method.lower()

    # Handle POST/PUT payloads (Sherlock supports templated payloads)
    payload = None
    raw_payload = getattr(site, "request_payload", None)
    if raw_payload:
        if isinstance(raw_payload, str):
            payload = raw_payload.replace("{}", quote(username))
        elif isinstance(raw_payload, dict):
            payload = {k: v.replace("{}", username) if isinstance(v, str) else v
                       for k, v in raw_payload.items()}

    # response_url detection needs allow_redirects=False (Sherlock logic)
    error_types = getattr(site, "error_types", None)
    if error_types is None:
        ct = getattr(site, "check_type", "message")
        error_types = [ct] if ct else ["message"]
    allow_redirects = "response_url" not in error_types

    checker.prepare(url, headers=headers, allow_redirects=allow_redirects,
                    timeout=timeout, method=method, payload=payload)

    try:
        html_text, status_code, error = await checker.check()
    finally:
        await checker.close()

    # Handle errorUrl redirect (Sherlock): if response redirected to errorUrl, user doesn't exist
    error_url = getattr(site, "error_url", None)
    if error_url and html_text:
        error_url_clean = error_url.replace("{}", username)
        if error_url_clean in (html_text or ""):
            return ScanResult.available(site_name=site_name, url=url)

    result = classify_result(html_text, status_code, error, site, username)
    result.username = username
    result.site_name = site_name
    return result


async def check_username_on_sites(
    sites: Dict[str, Any],
    username: str,
    proxy: Optional[str] = None,
    timeout: float = 10,
    in_parallel: int = 20,
    skip_nsfw: bool = False,
    verify_ssl: bool = True,
    on_done=None,
) -> List[ScanResult]:
    """Check a username across multiple sites concurrently.

    Args:
        on_done: optional callback(completed_count, total_count, result) called
                 after each site check completes, for progress reporting.
    """
    results, _ = await _run_sweep(sites, username, proxy, timeout, in_parallel,
                                  skip_nsfw, verify_ssl, on_done, budget=None)
    return results


async def check_username_on_sites_budget(
    sites: Dict[str, Any],
    username: str,
    proxy: Optional[str] = None,
    timeout: float = 10,
    in_parallel: int = 20,
    skip_nsfw: bool = False,
    verify_ssl: bool = True,
    budget: float = 60.0,
    on_done=None,
) -> Tuple[List[ScanResult], bool]:
    """Like `check_username_on_sites`, but returns ``(results, truncated)``.

    When `budget` (wall-clock seconds) is exceeded, pending checks are cancelled
    and the completed results are returned with ``truncated=True`` so the caller
    can report partial progress instead of dropping everything.
    """
    return await _run_sweep(sites, username, proxy, timeout, in_parallel,
                            skip_nsfw, verify_ssl, on_done, budget=budget)


async def _run_sweep(
    sites: Dict[str, Any],
    username: str,
    proxy: Optional[str],
    timeout: float,
    in_parallel: int,
    skip_nsfw: bool,
    verify_ssl: bool,
    on_done,
    budget: Optional[float],
) -> Tuple[List[ScanResult], bool]:
    """Shared sweep engine: per-site isolation + optional wall-clock budget."""
    sem = asyncio.Semaphore(in_parallel)
    total = len([s for s in sites.values()
                 if not getattr(s, "disabled", False)
                 and not (skip_nsfw and getattr(s, "is_nsfw", False))])
    completed = 0

    async def _limited_check(site):
        nonlocal completed
        async with sem:
            try:
                result = await check_site(site, username, proxy=proxy,
                                          timeout=timeout, verify_ssl=verify_ssl)
            except Exception as exc:
                # A connector-level failure (e.g. an unsupported proxy scheme)
                # must degrade to a per-site error rather than aborting the
                # whole sweep and discarding already-completed results.
                result = _isolated_error(site, username, exc)
            completed += 1
            if on_done:
                on_done(completed, total, result)
            return result

    tasks = []
    for site in sites.values():
        if getattr(site, "disabled", False):
            continue
        if skip_nsfw and getattr(site, "is_nsfw", False):
            continue
        tasks.append(asyncio.ensure_future(_limited_check(site)))

    if budget is not None:
        done, pending = await asyncio.wait(tasks, timeout=budget)
        truncated = bool(pending)
        for p in pending:
            p.cancel()
        results = [t.result() for t in done]
    else:
        results = await asyncio.gather(*tasks)
        truncated = False
    return results, truncated


def _isolated_error(site, username: str, exc: Exception) -> ScanResult:
    """Turn a per-site failure into an UNKNOWN ScanResult instead of raising."""
    site_name = getattr(site, "pretty_name", getattr(site, "name", ""))
    try:
        url = site.build_probe_url(username)
    except Exception:
        url = ""
    return ScanResult.error(
        f"{type(exc).__name__}: {exc}", site_name=site_name, url=url,
        username=username,
    )


def check_username_sync(
    sites: Dict[str, Any],
    username: str,
    proxy: Optional[str] = None,
    timeout: float = 10,
    in_parallel: int = 20,
    skip_nsfw: bool = False,
    verify_ssl: bool = True,
    on_done=None,
) -> List[ScanResult]:
    """Synchronous wrapper for check_username_on_sites."""
    return asyncio.run(check_username_on_sites(sites, username, proxy, timeout, in_parallel, skip_nsfw, verify_ssl=verify_ssl, on_done=on_done))
