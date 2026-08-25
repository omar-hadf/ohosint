"""Scrape identifiers out of a fetched profile page.

Shared by every "autopsy" step: pull cross-platform links, e-mail addresses and
@handles out of raw HTML. Callers pass their own keep/exclude patterns when they
want a narrower link filter; the defaults are general-purpose.
"""

import re

DEFAULT_EXCLUDE = r"(cdn|static|google|apple|microsoft|cloudflare)"
DEFAULT_KEEP = (
    r"(t\.me|telegram|twitter|x\.com|instagram|facebook|kick|snap|reddit|"
    r"tiktok|youtube|mail|gmail|yahoo|hotmail|xnxx|xvideos|pornhub)"
)


def cross_links(html, keep=DEFAULT_KEEP, exclude=DEFAULT_EXCLUDE):
    """Outbound links matching `keep` and not matching `exclude`, sorted/unique."""
    ext = sorted({h for h in re.findall(r'href="(https?://[^"]+)"', html)
                  if not re.search(exclude, h)})
    return [h for h in ext if re.search(keep, h, re.I)]


def page_emails(html):
    return sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", html)))


def at_handles(html, limit=25):
    return sorted(set(re.findall(r"(?:^|[\"'\s>])@([A-Za-z0-9_.]{3,25})", html)))[:limit]
