"""Third-party passive data sources.

Each helper performs one GET against a public API and returns a normalized
dict. Nothing here touches the target's own infrastructure.
"""

import hashlib
from urllib.parse import quote_plus


def leakcheck(fetcher, email, limit=40):
    """Public breach metadata (source names only) from leakcheck.io."""
    res = {"found": None, "sources": [], "note": ""}
    r = fetcher.get("https://leakcheck.io/api/public", params={"check": email})
    if r is None:
        res["note"] = "unavailable"
        return res
    try:
        j = r.json()
        if j.get("success"):
            res["found"] = bool(j.get("found"))
            res["sources"] = [s.get("name") if isinstance(s, dict) else str(s)
                              for s in (j.get("sources") or [])][:limit]
        else:
            res["note"] = str(j)[:100]
    except Exception as e:
        res["note"] = str(e)[:80]
    return res


def hudson_rock(fetcher, email):
    """Hudson Rock Cavalier: has this email appeared in infostealer logs?"""
    r = fetcher.get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
                    f"search-by-email?email={quote_plus(email)}")
    if r is None:
        return {"error": "unreachable"}
    try:
        j = r.json()
        st = j.get("stealers") or []
        tp = j.get("third_party_access") or {}
        return {"message": (j.get("message") or "")[:140],
                "stealer_count": len(st),
                "machines": [m.get("machine_name") for m in st][:5],
                "top_domains": (tp.get("total_third_party_domains")
                                if isinstance(tp, dict) else tp),
                "raw_keys": list(j.keys())}
    except Exception as e:
        return {"error": str(e)[:100]}


def gravatar(fetcher, email):
    """Public Gravatar profile (display name, bio, linked accounts) for an email."""
    h = hashlib.md5(email.encode()).hexdigest()
    grav = {"hash": h, "profile": None}
    r = fetcher.get(f"https://gravatar.com/{h}.json")
    if r is not None and r.text.strip() not in ("[]", ""):
        try:
            e = r.json()[0].get("entry", [{}])[0]
            grav["profile"] = {
                "display": e.get("displayName"),
                "about": (e.get("aboutMe") or "")[:200],
                "accounts": [{"shortname": a.get("shortname"), "url": a.get("url")}
                             for a in (e.get("accounts") or [])],
            }
        except Exception:
            pass
    return grav


def wayback_cdx(fetcher, pattern, limit=40):
    """Wayback CDX prefix enumeration; returns snapshot rows (header stripped)."""
    url = (f"http://web.archive.org/cdx/search/cdx?url={quote_plus(pattern)}"
           f"&matchType=prefix&output=json&collapse=urlkey"
           f"&fl=original,timestamp&limit={limit}")
    r = fetcher.get(url)
    if r is None:
        return []
    try:
        rows = r.json()
        return rows[1:] if rows else []
    except Exception:
        return []
