"""Search-engine dorking via DuckDuckGo and Bing.

Each engine returns `(state, hits)` where state is one of:
  "ok"    - real results parsed
  "empty" - engine responded but nothing usable
  "junk"  - suspiciously few/duplicated domains (likely throttled/interstitial)
  None    - request failed or was blocked (202/403)

`dork()` runs both engines, de-duplicates by URL, and appends a warning flag
when every engine looks throttled so the caller can suggest a Tor circuit change.
"""

import base64
import re
from urllib.parse import unquote

from .net import strip_tags


def _bing_decode(url):
    """Bing wraps outbound links as u=a1<base64>; recover the real target."""
    m = re.search(r"u=a1([A-Za-z0-9_-]+)", url)
    if not m:
        return url
    try:
        pad = "=" * (-len(m.group(1)) % 4)
        return base64.urlsafe_b64decode(
            m.group(1).replace("-", "+").replace("_", "/") + pad
        ).decode("utf-8", "ignore")
    except Exception:
        return url


def search_ddg(fetcher, query):
    r = fetcher.get("https://html.duckduckgo.com/html/", data={"q": query})
    if r is None or r.status_code in (202, 403) or "anomaly" in r.text.lower()[:800]:
        r = fetcher.get("https://lite.duckduckgo.com/lite/", params={"q": query})
    if r is None or r.status_code in (202, 403) or not r.text:
        return None, []
    hits = []
    for href, text in re.findall(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', r.text, re.S):
        if "uddg=" in href:
            href = unquote(href.split("uddg=")[1].split("&")[0])
        hits.append({"engine": "ddg", "url": href, "title": strip_tags(text)})
    if not hits:
        for href, text in re.findall(
                r'<a[^>]*href="([^"]+)"[^>]*class="result-link"[^>]*>(.*?)</a>',
                r.text, re.S):
            if "uddg=" in href:
                href = unquote(href.split("uddg=")[1].split("&")[0])
            hits.append({"engine": "ddg-lite", "url": href, "title": strip_tags(text)})
    return ("ok" if hits else "empty"), hits


def search_bing(fetcher, query):
    r = fetcher.get("https://www.bing.com/search",
                    params={"q": query, "setmkt": "en-US", "count": "15"})
    if r is None or r.status_code != 200:
        return None, []
    hits = []
    for block in re.findall(r'<li class="b_algo".*?</li>', r.text, re.S):
        m = re.search(r'<a[^>]+href="(http[^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if m:
            url = _bing_decode(m.group(1))
            title = strip_tags(m.group(2))[:120]
            if re.match(r"^https?://(?!www\.bing\.com/search)", url) \
                    and title and "http" not in title[:12]:
                hits.append({"engine": "bing", "url": url, "title": title})
    if len(hits) >= 5:
        domains = {re.sub(r"^https?://(www\.)?", "", h["url"]).split("/")[0].split(".")[0]
                   for h in hits}
        if len(domains) <= 3:
            return "junk", hits
    return ("ok" if len(hits) >= 2 else "junk"), hits


ENGINES = [("ddg", search_ddg), ("bing", search_bing)]


def dork(fetcher, query):
    """Run every engine for `query`; return (unique_hits, states, warn_flag)."""
    hits, states = [], {}
    for name, fn in ENGINES:
        state, res = fn(fetcher, query)
        states[name] = state
        hits += res
    seen, uniq = set(), []
    for h in hits:
        if h["url"] not in seen:
            seen.add(h["url"])
            uniq.append(h)
    flag = ""
    if all(states.get(n) in ("junk", None, "empty") for n, _ in ENGINES):
        flag = "   <-- engines throttled; run 'newnym' (tor circuit) or wait"
    return uniq, states, flag
