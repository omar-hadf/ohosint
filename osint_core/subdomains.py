"""Passive subdomain enumeration from free, keyless, GET-only sources.

Sources:
  crt.sh        — certificate-transparency logs (JSON)
  hackertarget  — hostsearch API (plain text)
  OTX           — AlienVault Open Threat Exchange passive DNS (JSON, keyless)

Every source is a single GET; no brute-forcing, no DNS zone tricks, nothing
that touches the target's infrastructure directly. Returns a report dict:

  {"domain": ..., "subdomains": [sorted unique],
   "sources": {name: count | None},   # None = source failed
   "errors": [str]}
"""

import re

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def valid_domain(domain):
    return bool(_DOMAIN_RE.match(domain.strip()))


def _normalize(names, domain):
    """Lowercase, strip wildcards, and keep only names under `domain`."""
    out = set()
    for n in names:
        n = n.strip().lower().lstrip("*.").rstrip(".")
        if n and (n == domain or n.endswith("." + domain)) and " " not in n:
            out.add(n)
    return out


def _crtsh(fetcher, domain):
    r = fetcher.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    if r is None or r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    names = set()
    for entry in data:
        names.update(entry.get("name_value", "").splitlines())
    return _normalize(names, domain)


def _hackertarget(fetcher, domain):
    r = fetcher.get("https://api.hackertarget.com/hostsearch/",
                    params={"q": domain})
    if r is None or r.status_code != 200:
        return None
    text = r.text or ""
    if text.lower().startswith(("error", "api count", "no records")):
        return set() if "no records" in text.lower() else None
    names = [line.split(",")[0] for line in text.splitlines() if "," in line]
    return _normalize(names, domain)


def _otx(fetcher, domain):
    r = fetcher.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    if r is None or r.status_code != 200:
        return None
    try:
        records = r.json().get("passive_dns", [])
    except ValueError:
        return None
    return _normalize((rec.get("hostname", "") for rec in records), domain)


SOURCES = [("crt.sh", _crtsh), ("hackertarget", _hackertarget), ("otx", _otx)]


def enum_subdomains(fetcher, domain, sources=None):
    """Enumerate subdomains of `domain` across all passive sources.

    `sources`: optional whitelist of source names (see SOURCES).
    """
    domain = domain.strip().lower()
    if not valid_domain(domain):
        raise ValueError(f"not a valid domain: {domain!r}")
    report = {"domain": domain, "subdomains": [], "sources": {}, "errors": []}
    found = set()
    for name, fn in SOURCES:
        if sources and name not in sources:
            continue
        try:
            names = fn(fetcher, domain)
        except Exception as e:  # a broken parser must not sink the whole enum
            report["errors"].append(f"{name}: {e}")
            names = None
        report["sources"][name] = len(names) if names is not None else None
        if names:
            found |= names
    report["subdomains"] = sorted(found)
    return report
