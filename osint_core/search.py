"""Search-engine dorking via DuckDuckGo, Bing, and (optionally) Google.

Each engine returns `(state, hits)` where state is one of:
  "ok"    - real results parsed
  "empty" - engine responded but nothing usable
  "junk"  - suspiciously few/duplicated domains (likely throttled/interstitial)
  None    - request failed or was blocked (202/403)

`dork()` runs every available engine, de-duplicates by URL, and appends a
warning flag when every engine looks throttled so the caller can suggest a
Tor circuit change.

Google is queried through the official Custom Search JSON API (not HTML
scraping, which Google CAPTCHAs aggressively). It only activates when both
`OHO_GOOGLE_KEY` and `OHO_GOOGLE_CX` are set — environment first, then a
`.env` file in the cwd, same convention as the breach API keys. Free tier is
100 queries/day: https://programmablesearchengine.google.com/
"""

import base64
import os
import re
from functools import partial
from urllib.parse import unquote

from .net import strip_tags

_GOOGLE_API = "https://www.googleapis.com/customsearch/v1"

# credential name -> env var; both must be set for the google engine to run
_GOOGLE_ENV = {"key": "OHO_GOOGLE_KEY", "cx": "OHO_GOOGLE_CX"}


def google_creds(environ=None):
    """Return {"key": ..., "cx": ...} for the Google Custom Search API, or {}.

    Real environment variables win; a `.env` file in the cwd is the fallback
    (only when the caller did NOT pass an explicit `environ`, so tests stay
    isolated). Both values are required — a half-configured engine is treated
    as absent.
    """
    if environ is not None:
        env = environ
    else:
        env = dict(os.environ)
        try:
            with open(".env", "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        except OSError:
            pass
    creds = {name: env.get(var, "") for name, var in _GOOGLE_ENV.items()}
    return creds if all(creds.values()) else {}


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


def search_google(fetcher, query, creds=None):
    """Google Custom Search JSON API — the sanctioned way to google-dork.

    Unlike the DDG/Bing scrapers above this is a real API: it returns JSON,
    supports every Google operator (site:, filetype:, intitle:, inurl:, ...),
    and is not CAPTCHA-throttled — but it needs OHO_GOOGLE_KEY + OHO_GOOGLE_CX
    and the free tier caps at 100 queries/day.
    """
    creds = google_creds() if creds is None else creds
    if not creds:
        return None, []
    r = fetcher.get(_GOOGLE_API, params={
        "key": creds["key"], "cx": creds["cx"], "q": query, "num": "10",
    })
    if r is None:
        return None, []
    if r.status_code != 200:
        try:
            msg = r.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            msg = f"HTTP {r.status_code}"
        print(f"  [!] google dork failed: {msg[:100]}")
        if r.status_code in (403, 429):
            print("      hint: bad key/cx, or the 100 queries/day free quota is exhausted")
        return None, []
    try:
        items = r.json().get("items", [])
    except ValueError:
        return None, []
    hits = [
        {"engine": "google", "url": item["link"],
         "title": strip_tags(item.get("title", ""))[:120]}
        for item in items if item.get("link")
    ]
    return ("ok" if hits else "empty"), hits


ENGINES = [("ddg", search_ddg), ("bing", search_bing)]


def dork(fetcher, query):
    """Run every available engine for `query`; return (unique_hits, states, warn_flag).

    The google engine is only included when OHO_GOOGLE_KEY + OHO_GOOGLE_CX
    are set (env or `.env`); the keyless engines always run.
    """
    engines = list(ENGINES)
    creds = google_creds()
    if creds:
        engines.append(("google", partial(search_google, creds=creds)))
    hits, states = [], {}
    for name, fn in engines:
        state, res = fn(fetcher, query)
        states[name] = state
        hits += res
    seen, uniq = set(), []
    for h in hits:
        if h["url"] not in seen:
            seen.add(h["url"])
            uniq.append(h)
    flag = ""
    if all(states.get(n) in ("junk", None, "empty") for n, _ in engines):
        flag = "   <-- engines throttled; run 'newnym' (tor circuit) or wait"
    return uniq, states, flag
