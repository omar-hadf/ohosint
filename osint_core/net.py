"""HTTP plumbing shared by every skill.

`Fetcher` owns a `requests.Session`, rotates the User-Agent per request,
sleeps a randomized delay between calls, counts requests and prints proxy
hints on failure. Both the interactive shell and the one-shot scripts drive
their traffic through it so the network behavior is defined in exactly one place.
"""

import logging
import random
import re
import time

import requests

from .constants import UAS

logger = logging.getLogger(__name__)

_PROXY_RE = re.compile(r"^(socks5h?|https?)://[\w.\-:\[\]]+/?$")


def build_session(proxy=None):
    """A requests.Session seeded with a random UA and optional proxy."""
    s = requests.Session()
    s.headers.update({"User-Agent": random.choice(UAS),
                      "Accept-Language": "en-US,en;q=0.9"})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def polite(delay):
    """Sleep a uniform-random number of seconds within `delay` (min, max)."""
    time.sleep(random.uniform(*delay))


def strip_tags(text):
    return re.sub(r"<.*?>", "", text).strip()


def valid_proxy(url):
    """True if `url` looks like a socks5(h)/http(s) proxy URL."""
    return bool(_PROXY_RE.match(url))


def warn_if_dns_leaking(url):
    """Warn when a proxy URL resolves DNS locally instead of through the proxy.

    ``socks5://`` resolves hostnames on this machine and sends the IP to the
    proxy, so every lookup leaks to the local resolver even though the traffic
    itself is tunnelled. ``socks5h://`` hands the hostname to the proxy. For a
    tool whose point is not being seen, that distinction matters — so say so
    rather than accepting it silently.

    Returns the warning string (also logged), or None if the URL is fine.
    """
    if url and url.startswith("socks5://"):
        msg = (
            f"{url} uses socks5:// — DNS is resolved locally and leaks outside "
            "the proxy. Use socks5h:// to tunnel DNS as well."
        )
        logger.warning(msg)
        return msg
    return None


class Fetcher:
    """Rate-limited, UA-rotating GET client with a request counter."""

    def __init__(self, proxy=None, delay=(1.5, 3.5)):
        self.session = build_session(proxy)
        self.delay = delay
        self.n_req = 0

    def nap(self):
        polite(self.delay)

    def get(self, url, **kw):
        self.session.headers["User-Agent"] = random.choice(UAS)
        try:
            r = self.session.get(url, timeout=25, **kw)
            self.n_req += 1
            self.nap()
            return r
        except requests.RequestException as e:
            name = type(e).__name__
            print(f"  [!] request failed: {str(e)[:100]}")
            if "MissingSchema" in name or "InvalidSchema" in name:
                print("      hint: pip install 'requests[socks]' for socks5 proxies")
            elif "refused" in str(e) or "SOCKSHTTPS" in str(e):
                print("      hint: is your proxy up? (tor: sudo service tor start)")
            return None
