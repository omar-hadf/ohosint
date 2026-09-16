"""GitHub leak search: find an email/username in public code, commits, users.

Maryam's `github_leaks` idea. Uses the official GitHub search REST API:

  /search/code    — file contents (REQUIRES a token; 401 otherwise)
  /search/commits — commit messages (keyless at low rate limits)
  /search/users   — account search (keyless at low rate limits)

Token comes from `OHO_GITHUB_KEY` (env or `.env`, same convention as the
breach keys). The token is sent to api.github.com only and is never stored
in reports.
"""

import os

_API = "https://api.github.com"


def github_key(environ=None):
    """Return the OHO_GITHUB_KEY token, or "" when unset (env wins over .env)."""
    env = environ if environ is not None else dict(os.environ)
    if environ is None:
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
    return env.get("OHO_GITHUB_KEY", "")


def _gh(fetcher, path, params, key):
    """One GET against the GitHub search API; return parsed JSON or None."""
    headers = {"Accept": "application/vnd.github+json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    r = fetcher.get(f"{_API}{path}", params=params, headers=headers)
    if r is None or r.status_code != 200:
        return None
    try:
        return r.json()
    except ValueError:
        return None


def github_code_search(fetcher, query, key, limit=10):
    """Search file contents for `query`. Returns list of hits, or None.

    GitHub requires authentication for code search — without a key this
    always 401s, so we refuse early instead of burning the delay budget.
    """
    if not key:
        return None
    data = _gh(fetcher, "/search/code", {"q": query, "per_page": str(limit)}, key)
    if data is None:
        return None
    return [{
        "kind": "code",
        "url": it.get("html_url", ""),
        "repo": (it.get("repository") or {}).get("full_name", ""),
        "path": it.get("path", ""),
    } for it in data.get("items", [])]


def github_commit_search(fetcher, query, key="", limit=10):
    """Search commit messages for `query` (emails land here constantly)."""
    data = _gh(fetcher, "/search/commits", {"q": query, "per_page": str(limit)}, key)
    if data is None:
        return None
    return [{
        "kind": "commit",
        "url": it.get("html_url", ""),
        "repo": (it.get("repository") or {}).get("full_name", ""),
        "message": ((it.get("commit") or {}).get("message") or "").splitlines()[0][:120],
    } for it in data.get("items", [])]


def github_user_search(fetcher, query, key="", limit=10):
    """Search accounts for `query` (username / display name)."""
    data = _gh(fetcher, "/search/users", {"q": query, "per_page": str(limit)}, key)
    if data is None:
        return None
    return [{
        "kind": "user",
        "url": it.get("html_url", ""),
        "login": it.get("login", ""),
    } for it in data.get("items", [])]


def github_leaks(fetcher, query, key=None):
    """Run all three searches; return a merged report dict.

    Per-section value is a list of hits, or None when that search failed /
    was unavailable (code search without a token, rate limit, ...).
    """
    key = github_key() if key is None else key
    report = {"query": query, "keyed": bool(key),
              "code": None, "commits": None, "users": None, "errors": []}
    if not key:
        report["errors"].append("code search skipped — OHO_GITHUB_KEY not set")
    report["code"] = github_code_search(fetcher, query, key)
    report["commits"] = github_commit_search(fetcher, query, key)
    report["users"] = github_user_search(fetcher, query, key)
    if report["code"] is None and key:
        report["errors"].append("code search failed (bad token or rate limit)")
    if report["commits"] is None:
        report["errors"].append("commit search failed (rate limit?)")
    if report["users"] is None:
        report["errors"].append("user search failed (rate limit?)")
    return report
