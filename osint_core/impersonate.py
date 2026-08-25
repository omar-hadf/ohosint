"""Browser TLS fingerprint impersonation via curl_cffi.

Bypasses TLS-fingerprint bot walls (DataDome, Cloudflare, etc.) that reject
Python's default TLS stack. Extracted from user-scanner's impersonate module.
"""

import asyncio
import threading
from typing import Callable, Literal, Optional

try:
    from curl_cffi.requests import Session as CurlSession
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False

DEFAULT_IMPERSONATE = "chrome"
DEFAULT_TIMEOUT = 15.0

_sessions: dict = {}
_key_locks: dict = {}
_warmed: set = set()
_lock = threading.Lock()


def impersonate_request(
    url: str,
    method: Literal["GET", "POST"] = "GET",
    warmup_url: Optional[str] = None,
    impersonate: str = DEFAULT_IMPERSONATE,
    proxy: Optional[str] = None,
    timeout: Optional[float] = None,
    **kwargs,
):
    """Issue a single request through a warmed, browser-impersonating session.

    Returns the raw curl_cffi Response. Raises on network errors.
    """
    if not CURL_CFFI_AVAILABLE:
        raise ImportError("curl_cffi is required for TLS impersonation: pip install curl_cffi")

    session = _get_warm_session(impersonate, proxy, warmup_url)
    kwargs.setdefault("timeout", timeout or DEFAULT_TIMEOUT)
    kwargs.setdefault("allow_redirects", False)
    return session.request(method, url, **kwargs)


def impersonate_validate(
    url: str,
    func: Callable,
    warmup_url: Optional[str] = None,
    impersonate: str = DEFAULT_IMPERSONATE,
    proxy: Optional[str] = None,
    timeout: Optional[float] = None,
    show_url: Optional[str] = None,
    **kwargs,
):
    """Like impersonate_request but applies a validation function to the response."""
    display_url = show_url or url
    try:
        response = impersonate_request(
            url, warmup_url=warmup_url, impersonate=impersonate,
            proxy=proxy, timeout=timeout, **kwargs,
        )
        return func(response)
    except Exception as e:
        return {"error": str(e), "url": display_url}


async def impersonate_request_async(
    url: str,
    method: Literal["GET", "POST"] = "GET",
    warmup_url: Optional[str] = None,
    impersonate: str = DEFAULT_IMPERSONATE,
    proxy: Optional[str] = None,
    timeout: Optional[float] = None,
    **kwargs,
):
    """Async wrapper around impersonate_request for use in async engines."""
    return await asyncio.to_thread(
        impersonate_request, url, method,
        warmup_url=warmup_url, impersonate=impersonate,
        proxy=proxy, timeout=timeout, **kwargs,
    )


def _get_warm_session(impersonate: str, proxy: Optional[str], warmup_url: Optional[str]):
    key = (impersonate, proxy)
    with _lock:
        session = _sessions.get(key)
        if session is None:
            session = CurlSession(
                impersonate=impersonate,
                proxies={"http": proxy, "https": proxy} if proxy else None,
            )
            _sessions[key] = session
            _key_locks[key] = threading.Lock()

        key_lock = _key_locks.get(key)
        if key_lock is None:
            key_lock = threading.Lock()
            _key_locks[key] = key_lock

    if warmup_url and key not in _warmed:
        with key_lock:
            if key not in _warmed:
                try:
                    session.get(warmup_url, timeout=DEFAULT_TIMEOUT)
                except Exception:
                    pass
                _warmed.add(key)

    return session


def is_available() -> bool:
    """Check if curl_cffi is installed."""
    return CURL_CFFI_AVAILABLE
