"""Mention search: posts/pages that *mention* an identifier (not accounts).

The username sweep answers "does this handle exist on site X". This answers a
different question: "who is talking about this email/handle/name".

  reddit        — reddit search JSON endpoint (keyless; browser UA required,
                  which the Fetcher already rotates)
  stackexchange — official keyless API (stackoverflow + the network)

Each returns a list of hit dicts, or None when the source failed.
"""


def reddit_mentions(fetcher, query, limit=10):
    r = fetcher.get("https://www.reddit.com/search.json",
                    params={"q": query, "limit": str(limit), "sort": "relevance"})
    if r is None or r.status_code != 200:
        return None
    try:
        children = r.json().get("data", {}).get("children", [])
    except ValueError:
        return None
    hits = []
    for c in children:
        d = c.get("data", {})
        permalink = d.get("permalink", "")
        hits.append({
            "source": "reddit",
            "title": (d.get("title") or "")[:120],
            "subreddit": d.get("subreddit", ""),
            "author": d.get("author", ""),
            "url": f"https://www.reddit.com{permalink}" if permalink else "",
        })
    return hits


def stackexchange_mentions(fetcher, query, limit=10):
    r = fetcher.get("https://api.stackexchange.com/2.3/search", params={
        "site": "stackoverflow", "pagesize": str(limit), "q": query,
    })
    if r is None or r.status_code != 200:
        return None
    try:
        items = r.json().get("items", [])
    except ValueError:
        return None
    return [{
        "source": "stackexchange",
        "title": (it.get("title") or "")[:120],
        "url": it.get("link", ""),
        "score": it.get("score", 0),
    } for it in items]


SOURCES = [("reddit", reddit_mentions), ("stackexchange", stackexchange_mentions)]


def mentions(fetcher, query):
    """Run every mention source; return {name: hits | None}."""
    out = {}
    for name, fn in SOURCES:
        try:
            out[name] = fn(fetcher, query)
        except Exception:
            out[name] = None
    return out


def mentions_detailed(fetcher, query):
    """Run every mention source; return {name: {hits, state, note}}.

    Unlike `mentions`, an empty result is distinguishable from a failed one:
    state is "ok" (hits found), "no_hits" (source responded, nothing matched),
    or "unavailable"/"error" (request failed or was blocked).
    """
    out = {}
    for name, fn in SOURCES:
        try:
            hits = fn(fetcher, query)
        except Exception as e:
            out[name] = {"hits": [], "state": "error", "note": str(e)[:100]}
            continue
        if hits is None:
            out[name] = {"hits": [], "state": "unavailable",
                         "note": "request failed or was blocked"}
        elif not hits:
            out[name] = {"hits": [], "state": "no_hits",
                         "note": "source responded with no matches"}
        else:
            out[name] = {"hits": hits, "state": "ok", "note": ""}
    return out
