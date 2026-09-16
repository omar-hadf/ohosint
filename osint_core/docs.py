"""Exposed-docs hunter: fire a pack of filetype/exposure dorks at the engines.

Maryam's `docs_search` idea, rebuilt on this project's dork machinery: given a
domain or a name/keyword, generate the classic Google-dork pack (exposed
documents, backups, configs, open directories, cloud buckets) and run every
query through `search.dork()` — DuckDuckGo + Bing always, Google when the CSE
keys are set.

`doc_dorks(target)` returns [(label, query)] so the pack can also just be
printed and pasted into a browser. `hunt_docs(fetcher, target)` runs them.
"""

import re

from .search import dork

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# label -> query template; {scope} is either site:domain or a quoted name
_DOC_TEMPLATES = [
    ("pdf",        "{scope} filetype:pdf"),
    ("word",       "{scope} filetype:doc OR filetype:docx"),
    ("sheets",     "{scope} filetype:xls OR filetype:xlsx OR filetype:csv"),
    ("text/logs",  "{scope} filetype:txt OR filetype:log"),
    ("db/backups", "{scope} filetype:sql OR filetype:bak"),
    ("configs",    "{scope} filetype:env OR filetype:ini OR filetype:yml"),
    ("open-dirs",  '{scope} intitle:"index of"'),
]

# cloud buckets take the bare org name, not the site: scope
_BUCKET_TEMPLATES = [
    ("s3",    'site:s3.amazonaws.com "{name}"'),
    ("gcs",   'site:storage.googleapis.com "{name}"'),
    ("azure", 'site:blob.core.windows.net "{name}"'),
]


def doc_dorks(target, include_buckets=True):
    """Return [(label, query)] for a domain or a name/keyword target."""
    target = target.strip()
    if _DOMAIN_RE.match(target):
        scope = f"site:{target}"
        name = target.split(".")[0]  # org stem for bucket names
    else:
        scope = f'"{target}"'
        name = target
    pack = [(label, tpl.format(scope=scope)) for label, tpl in _DOC_TEMPLATES]
    if include_buckets:
        pack += [(label, tpl.format(name=name)) for label, tpl in _BUCKET_TEMPLATES]
    return pack


def hunt_docs(fetcher, target, pack=None):
    """Run the dork pack; return {"target":..., "results":[{label, query, hits}]}.

    Queries whose engines all look throttled are kept with empty hits and a
    `throttled` flag so the caller can suggest `newnym`.
    """
    target = (target or "").strip()
    if _EMAIL_RE.match(target):
        return {
            "target": target,
            "results": [],
            "error": "hunt_docs targets domains or names, not email addresses — "
                     "use breach_search or search_dork for an email",
        }
    results = []
    for label, query in (pack or doc_dorks(target)):
        hits, states, flag = dork(fetcher, query)
        results.append({
            "label": label,
            "query": query,
            "hits": hits,
            "states": states,
            "throttled": bool(flag),
        })
    return {"target": target, "results": results}
