"""Dark-web search via Ahmia.fi — the clearnet-indexed .onion search engine.

Ahmia crawls Tor hidden services and is reachable over plain HTTPS, so this
stays passive and GET-only (and can itself be routed through Tor). It filters
abuse content server-side. Results point at .onion services, which require
Tor to actually open.

Same `(state, hits)` contract as the engines in search.py, so results can be
merged with clearnet dork hits.
"""

import re
from urllib.parse import unquote

from .net import strip_tags

_AHMIA = "https://ahmia.fi/search/"


def _unwrap(href):
    """Ahmia outbound links wrap the target in ?redirect_url=..."""
    if "redirect_url=" in href:
        return unquote(href.split("redirect_url=")[1].split("&")[0])
    return href


def search_onion(fetcher, query):
    """Search Ahmia for `query`; return (state, hits)."""
    r = fetcher.get(_AHMIA, params={"q": query})
    if r is None or r.status_code != 200 or not r.text:
        return None, []
    hits = []
    for block in re.findall(r'<li class="result">(.*?)</li>', r.text, re.S):
        m = re.search(r'<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not m:
            continue
        url = _unwrap(m.group(1))
        if not url.startswith("http"):
            continue
        hits.append({"engine": "ahmia", "url": url,
                     "title": strip_tags(m.group(2))[:120]})
    return ("ok" if hits else "empty"), hits
