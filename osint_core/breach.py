"""Multi-source breach / leak lookup (single source of truth).

Each adapter performs passive requests against a public third-party API and
returns a normalized dict. Adapters never raise — failures are reported via
"note"/"error" keys so one dead source can't sink a whole lookup.

Query types: email, username, domain, password.

Keyless sources (always available): LeakCheck public API, Hudson Rock
Cavalier OSINT endpoints, XposedOrNot, HIBP breach catalogue, HIBP Pwned
Passwords (k-anonymity), XposedOrNot anonymous password check, ProxyNova
COMB, EmailRep.

Keyed sources (activated by env vars — see get_api_keys): HIBP account
search, Intelligence X, BreachDirectory (RapidAPI), EmailRep (higher quota).

See docs/BREACH-SEARCH-PLAN.md for the full source research.
"""

import hashlib
import os
import re
from datetime import datetime
from urllib.parse import quote_plus

try:
    import sha3  # safe-pysha3 (Keccak-512) for XposedOrNot password checks
except ImportError:  # pragma: no cover
    sha3 = None

QUERY_TYPES = ("email", "username", "domain", "password")

# provider name -> env var holding its API key
_ENV_KEYS = {
    "hibp": "OHO_HIBP_KEY",
    "intelx": "OHO_INTELX_KEY",
    "breachdirectory": "OHO_RAPIDAPI_KEY",
    "emailrep": "OHO_EMAILREP_KEY",
}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# process-lifetime cache for the HIBP breach catalogue (static metadata)
_CATALOGUE_CACHE: dict = {}

THROTTLE_HINT = "rate-limited/blocked — run 'newnym' (Tor) or wait before retrying"


def detect_qtype(query):
    """Best-effort query-type detection: email > domain > username.

    Passwords are never auto-detected — pass qtype="password" explicitly.
    """
    q = query.strip()
    if _EMAIL_RE.match(q):
        return "email"
    if _DOMAIN_RE.match(q):
        return "domain"
    return "username"


def get_api_keys(environ=None):
    """Return {provider: key} for every OHO_* breach API key set in the env.

    Also picks up keys from a local `.env` file (key=value per line, `#` comments)
    in the current working directory — only when the caller did NOT pass an
    explicit `environ` (so tests stay isolated). Real environment variables
    always win over `.env` so CI / shell exports take precedence.
    """
    if environ is not None:
        return {name: environ[var] for name, var in _ENV_KEYS.items() if environ.get(var)}
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
    return {name: env[var] for name, var in _ENV_KEYS.items() if env.get(var)}


# ---------------------------------------------------------------------------
# Keyless adapters
# ---------------------------------------------------------------------------

def breach_leakcheck(fetcher, query):
    """LeakCheck public API: breach sources + exposed data categories.

    Works for emails and usernames (type auto-detected server-side).
    """
    res = {"found": None, "breaches": [], "fields": [], "note": ""}
    r = fetcher.get("https://leakcheck.io/api/public", params={"check": query})
    if r is None:
        res["note"] = "unavailable"
        return res
    if r.status_code == 429:
        res["note"] = THROTTLE_HINT
        return res
    try:
        j = r.json()
        if j.get("success"):
            res["found"] = bool(j.get("found"))
            res["fields"] = j.get("fields") or []
            res["breaches"] = [
                {"name": s.get("name"), "date": s.get("date")}
                for s in (j.get("sources") or [])
                if isinstance(s, dict) and s.get("name")
            ]
        else:
            res["note"] = str(j.get("error") or j)[:120]
    except Exception as e:
        res["note"] = str(e)[:100]
    return res


def _hr_normalize(j):
    """Shared normalizer for Hudson Rock Cavalier responses."""
    res = {"found": None, "stealer_count": 0, "stealers": [], "message": "", "note": ""}
    if isinstance(j, dict):
        msg = j.get("message") or ""
        res["message"] = msg[:200]
        stealers = j.get("stealers") or []
        if not isinstance(stealers, list):
            stealers = []
        res["stealer_count"] = len(stealers)
        res["stealers"] = [
            {
                "stealer_family": s.get("stealer_family"),
                "date_compromised": s.get("date_compromised"),
                "operating_system": s.get("operating_system"),
                "computer_name": s.get("computer_name"),
            }
            for s in stealers[:10] if isinstance(s, dict)
        ]
        res["found"] = bool(stealers) or "is associated" in msg.lower()
        if "not associated" in msg.lower():
            res["found"] = False
        # extra context keys when present (domain endpoint)
        for k in ("employees", "users", "third_party_domains", "total_urls"):
            if k in j:
                res[k] = j[k]
    elif isinstance(j, list):
        res["stealer_count"] = len(j)
        res["stealers"] = j[:10]
        res["found"] = bool(j)
    return res


def breach_hudson_rock_email(fetcher, email):
    """Hudson Rock: has this email appeared on an infostealer-infected machine?"""
    r = fetcher.get(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={quote_plus(email)}"
    )
    if r is None:
        return {"found": None, "note": "unavailable"}
    try:
        return _hr_normalize(r.json())
    except Exception as e:
        return {"found": None, "note": str(e)[:100]}


def breach_hudson_rock_username(fetcher, username):
    """Hudson Rock: username occurrences in infostealer logs."""
    r = fetcher.get(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-username?username={quote_plus(username)}"
    )
    if r is None:
        return {"found": None, "note": "unavailable"}
    try:
        return _hr_normalize(r.json())
    except Exception as e:
        return {"found": None, "note": str(e)[:100]}


def breach_hudson_rock_domain(fetcher, domain):
    """Hudson Rock: infostealer impact on a whole domain."""
    r = fetcher.get(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-domain?domain={quote_plus(domain)}"
    )
    if r is None:
        return {"found": None, "note": "unavailable"}
    try:
        return _hr_normalize(r.json())
    except Exception as e:
        return {"found": None, "note": str(e)[:100]}


def breach_xposedornot(fetcher, email):
    """XposedOrNot: breach names + per-breach detail (data classes, dates)."""
    res = {"found": None, "breaches": [], "paste_count": 0, "note": ""}
    r = fetcher.get(f"https://api.xposedornot.com/v1/check-email/{quote_plus(email)}")
    if r is None:
        res["note"] = "unavailable"
        return res
    if r.status_code == 429:
        res["note"] = THROTTLE_HINT
        return res
    if r.status_code == 404:
        res["found"] = False
        return res
    try:
        j = r.json()
    except Exception as e:
        res["note"] = str(e)[:100]
        return res
    if "Error" in j:  # {"Error": "Not found", "email": null}
        res["found"] = False
        return res
    names = j.get("breaches") or []
    if names and isinstance(names[0], list):  # v1 nests the list one level
        names = names[0]
    names = [str(n) for n in names]
    res["found"] = bool(names)
    res["breaches"] = [{"name": n} for n in names]

    # detail pass (second free endpoint): dates, data classes, pastes
    r2 = fetcher.get("https://api.xposedornot.com/v1/breach-analytics",
                     params={"email": email})
    if r2 is not None and r2.status_code == 200:
        try:
            aj = r2.json()
            details = ((aj.get("ExposedBreaches") or {}).get("breaches_details")) or []
            detail_map = {}
            for d in details:
                if not isinstance(d, dict):
                    continue
                bname = d.get("breach")
                if not bname:
                    continue
                classes = d.get("xposed_data") or ""
                detail_map[bname.lower()] = {
                    "name": bname,
                    "date": d.get("xposed_date"),
                    "records": d.get("xposed_records"),
                    "data_classes": [c.strip() for c in str(classes).split(",") if c.strip()],
                    "password_risk": d.get("password_risk"),
                }
            merged = []
            for b in res["breaches"]:
                extra = detail_map.pop(b["name"].lower(), {})
                merged.append({**b, **{k: v for k, v in extra.items() if v}})
            merged.extend(detail_map.values())  # details not in the names list
            res["breaches"] = merged
            pastes = aj.get("PastesSummary") or {}
            if isinstance(pastes, dict):
                res["paste_count"] = pastes.get("cnt") or 0
        except Exception:
            pass  # names-only result is still useful
    return res


def breach_hibp_catalogue(fetcher, domain=None):
    """HIBP breach catalogue (metadata only, keyless). Cached per process.

    With domain: breaches that hit that domain. Without: the full catalogue,
    used to enrich breach names found by other sources.
    """
    cache_key = (domain or "").lower()
    if cache_key in _CATALOGUE_CACHE:
        return _CATALOGUE_CACHE[cache_key]
    res = {"ok": False, "count": 0, "breaches": [], "by_name": {}, "note": ""}
    params = {"domain": domain} if domain else None
    r = fetcher.get("https://haveibeenpwned.com/api/v3/breaches", params=params)
    if r is None:
        res["note"] = "unavailable"
        _CATALOGUE_CACHE[cache_key] = res
        return res
    if r.status_code in (401, 403, 429):
        res["note"] = THROTTLE_HINT
        return res  # don't cache throttle states
    try:
        items = r.json()
        for b in items:
            entry = {
                "name": b.get("Name"),
                "title": b.get("Title"),
                "domain": b.get("Domain"),
                "date": b.get("BreachDate"),
                "pwn_count": b.get("PwnCount"),
                "data_classes": b.get("DataClasses") or [],
            }
            res["breaches"].append(entry)
            if entry["name"]:
                res["by_name"][entry["name"].lower()] = entry
        res["count"] = len(res["breaches"])
        res["ok"] = True
    except Exception as e:
        res["note"] = str(e)[:100]
    _CATALOGUE_CACHE[cache_key] = res
    return res


def pwned_password(fetcher, password):
    """HIBP Pwned Passwords via k-anonymity: only the first 5 chars of the
    SHA-1 hash leave the machine; the password itself is never transmitted."""
    res = {"pwned": None, "count": 0, "note": ""}
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = fetcher.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if r is None:
        res["note"] = "unavailable"
        return res
    if r.status_code != 200:
        res["note"] = f"http {r.status_code}"
        return res
    try:
        for line in r.text.splitlines():
            suf, _, cnt = line.partition(":")
            if suf.strip().upper() == suffix:
                res["pwned"] = True
                res["count"] = int(cnt.strip() or 0)
                return res
        res["pwned"] = False
    except Exception as e:
        res["note"] = str(e)[:100]
    return res


def breach_xon_password(fetcher, password):
    """XposedOrNot anonymous password check (second k-anonymity opinion).

    Uses Keccak-512 (not SHA-1) and sends only the first 10 hex characters.
    """
    res = {"pwned": None, "count": 0, "note": ""}
    if sha3 is None:
        res["note"] = "install safe-pysha3 for XON password checks"
        return res
    prefix = sha3.keccak_512(password.encode("utf-8")).hexdigest().upper()[:10]
    r = fetcher.get(f"https://passwords.xposedornot.com/api/v1/pass/anon/{prefix}")
    if r is None:
        res["note"] = "unavailable"
        return res
    if r.status_code == 404:
        res["pwned"] = False
        return res
    try:
        j = r.json()
        if "Error" in j:
            res["pwned"] = False
            return res
        spa = j.get("SearchPassAnon") or {}
        if isinstance(spa, dict):
            if spa.get("anon", "").upper() == prefix:
                res["pwned"] = True
                res["count"] = int(spa.get("count") or 0)
                return res
            # 200 with a different prefix means no match for this password
            res["pwned"] = False
            return res
        res["note"] = "unparsed response"
    except Exception as e:
        res["note"] = str(e)[:100]
    return res


def breach_proxynova(fetcher, query, limit=100):
    """ProxyNova COMB: plaintext email:password lines (3.2B records, keyless)."""
    res = {"found": None, "count": 0, "lines": [], "note": ""}
    r = fetcher.get("https://api.proxynova.com/comb",
                    params={"query": query, "start": 0, "limit": limit})
    if r is None:
        res["note"] = "unavailable"
        return res
    if r.status_code == 429:
        res["note"] = THROTTLE_HINT
        return res
    try:
        j = r.json()
        lines = [str(x) for x in (j.get("lines") or [])]
        res["lines"] = lines[:limit]
        res["count"] = j.get("count") or len(lines)
        res["found"] = bool(lines)
    except Exception as e:
        res["note"] = str(e)[:100]
    return res


def breach_emailrep(fetcher, email, key=None):
    """EmailRep: reputation + breach/credential-leak signals (enrichment)."""
    res = {"found": None, "reputation": None, "credentials_leaked": None,
           "data_breach": None, "references": 0, "profiles": [], "note": ""}
    headers = {"Key": key} if key else None
    r = fetcher.get(f"https://emailrep.io/{quote_plus(email)}",
                    **({"headers": headers} if headers else {}))
    if r is None:
        res["note"] = "unavailable"
        return res
    if r.status_code == 429:
        res["note"] = THROTTLE_HINT
        return res
    try:
        j = r.json()
        details = j.get("details") or {}
        res["reputation"] = j.get("reputation")
        res["references"] = j.get("references") or 0
        res["credentials_leaked"] = details.get("credentials_leaked")
        res["data_breach"] = details.get("data_breach")
        res["profiles"] = details.get("profiles") or []
        res["found"] = bool(res["credentials_leaked"] or res["data_breach"])
    except Exception as e:
        res["note"] = str(e)[:100]
    return res


# ---------------------------------------------------------------------------
# Keyed adapters (only run when their env var is set)
# ---------------------------------------------------------------------------

def breach_hibp_account(fetcher, email, key):
    """HIBP breachedaccount (paid key): authoritative breach names."""
    res = {"found": None, "breaches": [], "note": ""}
    r = fetcher.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}",
        params={"truncateResponse": "true"},
        headers={"hibp-api-key": key},
    )
    if r is None:
        res["note"] = "unavailable"
        return res
    if r.status_code == 404:
        res["found"] = False
        return res
    if r.status_code in (401, 403):
        res["note"] = f"hibp key rejected (http {r.status_code})"
        return res
    if r.status_code == 429:
        res["note"] = THROTTLE_HINT
        return res
    try:
        items = r.json()
        res["breaches"] = [{"name": b.get("Name")} for b in items if b.get("Name")]
        res["found"] = bool(res["breaches"])
    except Exception as e:
        res["note"] = str(e)[:100]
    return res


def breach_intelx(fetcher, selector, key, maxresults=50):
    """Intelligence X (free key): search leaks/darknet.tor/pastes buckets.

    Note: the IntelX API initiates searches with one POST to *its own* API
    (third-party service, not the target) — allowed by the passive rules.
    """
    res = {"found": None, "records": [], "note": ""}
    base = "https://free.intelx.io"
    headers = {"x-key": key}
    body = {
        "term": selector,
        "lookuplevel": 0,
        "maxresults": maxresults,
        "timeout": 5,
        "datefrom": "",
        "dateto": "",
        "sort": 4,
        "media": 0,
        "terminate": [],
        "buckets": ["leaks.public", "darknet.tor", "pastes"],
    }
    try:
        r = fetcher.session.post(f"{base}/intelligent/search",
                                 json=body, headers=headers, timeout=30)
        fetcher.n_req += 1
        fetcher.nap()
        if r.status_code in (401, 403):
            res["note"] = f"intelx key rejected (http {r.status_code})"
            return res
        if r.status_code != 200:
            res["note"] = f"http {r.status_code}"
            return res
        search_id = r.json().get("id")
        if not search_id:
            res["note"] = "no search id returned"
            return res
        r2 = fetcher.get(f"{base}/intelligent/search/result",
                         params={"id": search_id, "limit": maxresults},
                         headers=headers)
        if r2 is None or r2.status_code != 200:
            res["note"] = "result fetch failed"
            return res
        records = (r2.json().get("records")) or []
        res["records"] = [
            {
                "bucket": x.get("bucket"),
                "name": x.get("name"),
                "added": x.get("added"),
                "media": x.get("mediah"),
                "systemid": x.get("systemid"),
            }
            for x in records[:maxresults] if isinstance(x, dict)
        ]
        res["found"] = bool(res["records"])
    except Exception as e:
        res["note"] = str(e)[:100]
    return res


def breach_breachdirectory(fetcher, term, key):
    """BreachDirectory via RapidAPI (free tier: 10 req/month)."""
    res = {"found": None, "records": [], "breaches": [], "note": ""}
    r = fetcher.get(
        "https://breachdirectory.p.rapidapi.com/",
        params={"func": "auto", "term": term},
        headers={
            "x-rapidapi-key": key,
            "x-rapidapi-host": "breachdirectory.p.rapidapi.com",
        },
    )
    if r is None:
        res["note"] = "unavailable"
        return res
    if r.status_code in (401, 403):
        res["note"] = f"rapidapi key rejected (http {r.status_code})"
        return res
    if r.status_code in (404, 500):
        res["found"] = False  # API returns 500 when there are no records
        return res
    if r.status_code == 429:
        res["note"] = THROTTLE_HINT
        return res
    try:
        j = r.json()
        res["found"] = bool(j.get("found"))
        records = j.get("result") or []
        names = set()
        for rec in records:
            if not isinstance(rec, dict):
                continue
            entry = {k: rec.get(k) for k in
                     ("email", "username", "password", "sha1", "hash") if rec.get(k)}
            # "sources" is a list for most records, but the API also returns a
            # bare string for some. Iterating a string yields one entry per
            # character, producing garbage breach names like "(", "0", "a".
            raw_sources = rec.get("sources") or []
            if isinstance(raw_sources, str):
                raw_sources = [raw_sources]
            entry["sources"] = list(raw_sources)
            for s in entry["sources"]:
                names.add(str(s))
            res["records"].append(entry)
        res["breaches"] = [{"name": n} for n in sorted(names)]
    except Exception as e:
        res["note"] = str(e)[:100]
    return res


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# qtype -> (keyless providers, keyed providers)
_ROUTES = {
    "email": (
        ["leakcheck", "hudson_rock", "xposedornot", "proxynova", "emailrep"],
        ["hibp", "breachdirectory", "intelx"],
    ),
    "username": (
        ["leakcheck", "hudson_rock", "proxynova"],
        ["intelx"],
    ),
    "domain": (
        ["hudson_rock", "hibp_catalogue", "xposedornot"],
        ["intelx"],
    ),
    "password": (
        ["pwned_passwords", "xon_password"],
        [],
    ),
}


def _dispatch(provider, fetcher, query, keys):
    """Run one provider adapter; returns the normalized dict."""
    if provider == "leakcheck":
        return breach_leakcheck(fetcher, query)
    if provider == "hudson_rock":
        qtype_fn = {
            "email": breach_hudson_rock_email,
            "username": breach_hudson_rock_username,
            "domain": breach_hudson_rock_domain,
        }
        return qtype_fn[_CURRENT_QTYPE[0]](fetcher, query)
    if provider == "xposedornot":
        # domain queries use the breach list endpoint instead
        if _CURRENT_QTYPE[0] == "domain":
            return breach_xposedornot_domain(fetcher, query)
        return breach_xposedornot(fetcher, query)
    if provider == "proxynova":
        return breach_proxynova(fetcher, query)
    if provider == "emailrep":
        return breach_emailrep(fetcher, query, key=keys.get("emailrep"))
    if provider == "hibp_catalogue":
        return breach_hibp_catalogue(fetcher, domain=query)
    if provider == "pwned_passwords":
        return pwned_password(fetcher, query)
    if provider == "xon_password":
        return breach_xon_password(fetcher, query)
    if provider == "hibp":
        return breach_hibp_account(fetcher, query, keys["hibp"])
    if provider == "intelx":
        return breach_intelx(fetcher, query, keys["intelx"])
    if provider == "breachdirectory":
        return breach_breachdirectory(fetcher, query, keys["breachdirectory"])
    raise ValueError(f"unknown provider: {provider}")


# _dispatch is single-threaded; stash the current qtype for adapters that
# branch on it (hudson_rock, xposedornot).
_CURRENT_QTYPE = ["email"]


def breach_xposedornot_domain(fetcher, domain):
    """XposedOrNot: list known breaches affecting a domain (keyless)."""
    res = {"found": None, "breaches": [], "note": ""}
    r = fetcher.get("https://api.xposedornot.com/v1/breaches",
                    params={"domain": domain})
    if r is None:
        res["note"] = "unavailable"
        return res
    if r.status_code == 429:
        res["note"] = THROTTLE_HINT
        return res
    try:
        j = r.json()
        items = j.get("breaches") or j.get("exposedBreaches") or []
        if isinstance(items, list) and items and isinstance(items[0], list):
            items = items[0]
        for b in items:
            if isinstance(b, dict):
                res["breaches"].append({
                    "name": b.get("breachID") or b.get("breach") or b.get("name"),
                    "date": b.get("xposedDate") or b.get("xposed_date"),
                    "records": b.get("xposedRecords") or b.get("xposed_records"),
                    "data_classes": [
                        c.strip()
                        for c in str(b.get("xposedData") or b.get("xposed_data") or "").split(",")
                        if c.strip()
                    ],
                })
            elif b:
                res["breaches"].append({"name": str(b)})
        res["breaches"] = [b for b in res["breaches"] if b.get("name")]
        res["found"] = bool(res["breaches"])
    except Exception as e:
        res["note"] = str(e)[:100]
    return res


def _merge_breach(merged, name, provider, date=None, data_classes=()):
    key = name.strip().lower()
    if not key:
        return
    entry = merged.setdefault(key, {
        "name": name.strip(), "date": None, "providers": [], "data_classes": [],
    })
    if provider not in entry["providers"]:
        entry["providers"].append(provider)
    if date and not entry["date"]:
        entry["date"] = date
    for c in data_classes or []:
        if c and c not in entry["data_classes"]:
            entry["data_classes"].append(c)


def breach_search(fetcher, query, qtype=None, sources=None, keys=None):
    """Run every applicable breach source for a query and merge the results.

    Args:
        fetcher: osint_core Fetcher (honours proxy + delay).
        query: email / username / domain / password.
        qtype: one of QUERY_TYPES; auto-detected when None ("password" is
            never auto-detected).
        sources: optional list of provider names to restrict to.
        keys: optional {provider: key}; defaults to get_api_keys().

    Returns the report dict described in docs/BREACH-SEARCH-PLAN.md. The
    plaintext password query is never stored in the report (sha1 only).
    """
    qtype = qtype or detect_qtype(query)
    if qtype not in QUERY_TYPES:
        raise ValueError(f"qtype must be one of {QUERY_TYPES}")
    keys = get_api_keys() if keys is None else keys
    _CURRENT_QTYPE[0] = qtype

    keyless, keyed = _ROUTES[qtype]
    wanted = set(sources) if sources else None

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "query": query if qtype != "password"
                 else f"sha1:{hashlib.sha1(query.encode('utf-8')).hexdigest()}",
        "type": qtype,
        "sources_used": [],
        "sources_skipped": [],
        "breaches": [],
        "credentials": [],
        "summary": {
            "unique_breaches": 0,
            "credential_lines": 0,
            "infostealer_hits": 0,
            "intelx_records": 0,
            "pwned_password_count": None,
        },
        "flags": [],
        "raw": {},
    }

    for provider in keyless:
        if wanted and provider not in wanted:
            report["sources_skipped"].append(
                {"name": provider, "reason": "not in --sources"})
            continue
        raw = _dispatch(provider, fetcher, query, keys)
        report["raw"][provider] = raw
        report["sources_used"].append(provider)

    for provider in keyed:
        if wanted and provider not in wanted:
            report["sources_skipped"].append(
                {"name": provider, "reason": "not in --sources"})
            continue
        if not keys.get(provider):
            report["sources_skipped"].append(
                {"name": provider, "reason": f"{_ENV_KEYS[provider]} not set"})
            continue
        raw = _dispatch(provider, fetcher, query, keys)
        report["raw"][provider] = raw
        report["sources_used"].append(provider)

    # ---- merge -----------------------------------------------------------
    merged = {}
    for provider, raw in report["raw"].items():
        note = raw.get("note") or ""
        if "rate-limited" in note or "http 429" in note:
            report["flags"].append(f"{provider}: {note}")
        for b in raw.get("breaches") or []:
            if isinstance(b, dict) and b.get("name"):
                _merge_breach(merged, b["name"], provider,
                              date=b.get("date"),
                              data_classes=b.get("data_classes"))
        if provider == "proxynova":
            for line in raw.get("lines") or []:
                report["credentials"].append({"source": "proxynova", "line": line})
        if provider == "breachdirectory":
            for rec in raw.get("records") or []:
                report["credentials"].append(
                    {"source": "breachdirectory", **rec})
        if provider == "hudson_rock":
            report["summary"]["infostealer_hits"] = raw.get("stealer_count") or 0
        if provider == "intelx":
            report["summary"]["intelx_records"] = len(raw.get("records") or [])
        if provider == "pwned_passwords" and raw.get("pwned"):
            report["summary"]["pwned_password_count"] = raw.get("count")
        if provider == "xon_password" and raw.get("pwned") and \
                report["summary"]["pwned_password_count"] is None:
            report["summary"]["pwned_password_count"] = raw.get("count")

    # ---- HIBP catalogue enrichment (email/username names) -----------------
    if qtype in ("email", "username") and merged:
        cat = breach_hibp_catalogue(fetcher)
        if cat.get("ok"):
            for key, entry in merged.items():
                meta = cat["by_name"].get(key)
                if meta:
                    if not entry["date"]:
                        entry["date"] = meta.get("date")
                    for c in meta.get("data_classes") or []:
                        if c not in entry["data_classes"]:
                            entry["data_classes"].append(c)
                    entry["pwn_count"] = meta.get("pwn_count")
        elif cat.get("note") and cat["note"] != "unavailable":
            report["flags"].append(f"hibp_catalogue: {cat['note']}")

    report["breaches"] = sorted(merged.values(), key=lambda b: b["name"].lower())
    report["summary"]["unique_breaches"] = len(report["breaches"])
    report["summary"]["credential_lines"] = len(report["credentials"])
    return report
