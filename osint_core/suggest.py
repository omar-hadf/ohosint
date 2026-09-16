"""Autocomplete suggestions + Wikipedia disambiguation (Maryam `suggest` /
`famous_person` ideas).

Search-engine autocomplete endpoints are keyless JSON GETs and reveal what
the world commonly searches around a name — a cheap pivot generator.

`wikipedia_lookup` powers public-figure disambiguation: if the exact name is
a Wikipedia article title, treat generic social hits with extra suspicion.
"""

import re

_HANDLE_RE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._-]*$")


def looks_like_handle(query):
    """True when `query` is a handle, not a full name.

    Autocomplete engines are useless for handles (they surface whole names and
    phrases), so `suggest` self-values and pivots to candidate generation
    instead of burning a request slot on a guaranteed-empty query.
    """
    q = (query or "").strip()
    if not q or " " in q:
        return False
    if not _HANDLE_RE.fullmatch(q):
        return False
    return bool(re.search(r"[0-9._-]", q)) or q.startswith("@")



def _json_list(r):
    try:
        return r.json()
    except ValueError:
        return None


def suggest_google(fetcher, query):
    r = fetcher.get("https://suggestqueries.google.com/complete/search",
                    params={"client": "firefox", "q": query})
    if r is None or r.status_code != 200:
        return None
    data = _json_list(r)
    if not isinstance(data, list) or len(data) < 2 or not isinstance(data[1], list):
        return None
    return [s for s in data[1] if isinstance(s, str)]


def suggest_ddg(fetcher, query):
    r = fetcher.get("https://duckduckgo.com/ac/", params={"q": query})
    if r is None or r.status_code != 200:
        return None
    data = _json_list(r)
    if not isinstance(data, list):
        return None
    return [d["phrase"] for d in data if isinstance(d, dict) and d.get("phrase")]


def suggest_bing(fetcher, query):
    r = fetcher.get("https://api.bing.com/osjson.aspx", params={"query": query})
    if r is None or r.status_code != 200:
        return None
    data = _json_list(r)
    if not isinstance(data, list) or len(data) < 2 or not isinstance(data[1], list):
        return None
    return [s for s in data[1] if isinstance(s, str)]


ENGINES = [("google", suggest_google), ("ddg", suggest_ddg), ("bing", suggest_bing)]


def suggest(fetcher, query):
    """Run every autocomplete engine; return {"engines": {name: [...]|None},
    "merged": [unique suggestions in first-seen order]}.

    Handles get no useful autocomplete, so for handle-like queries this
    short-circuits and generates username candidates locally instead (the same
    permutation logic `generate_candidates` uses) rather than wasting request
    slots on engines that return nothing relevant.
    """
    if looks_like_handle(query):
        from .candidates import generate_candidates
        seed = query.strip().lstrip("@")
        return {
            "engines": {},
            "merged": [],
            "note": ("suggest is optimized for full names, not handles — "
                     "generated username candidates instead"),
            "candidates": generate_candidates(seed),
        }
    engines, merged = {}, []
    for name, fn in ENGINES:
        try:
            res = fn(fetcher, query)
        except Exception:
            res = None
        engines[name] = res
        for s in res or []:
            if s not in merged:
                merged.append(s)
    return {"engines": engines, "merged": merged}


def wikipedia_lookup(fetcher, name, limit=5):
    """OpenSearch lookup; return [{"title", "url"}], or None on failure."""
    r = fetcher.get("https://en.wikipedia.org/w/api.php", params={
        "action": "opensearch", "search": name, "limit": str(limit),
        "namespace": "0", "format": "json",
    })
    if r is None or r.status_code != 200:
        return None
    data = _json_list(r)
    if not isinstance(data, list) or len(data) < 4:
        return None
    return [{"title": t, "url": u} for t, u in zip(data[1], data[3])]


def famous_collision(entries, name):
    """True when an exact-title Wikipedia hit suggests a public-figure name
    collision (so generic social hits deserve extra suspicion)."""
    wanted = name.strip().lower()
    return any(e["title"].strip().lower() == wanted for e in entries or [])
