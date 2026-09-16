"""Tests for osint_core.github_leaks."""

from osint_core.github_leaks import github_key, github_leaks


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeFetcher:
    def __init__(self, routes):
        self.routes = routes
        self.headers_seen = []

    def get(self, url, **kw):
        self.headers_seen.append(kw.get("headers", {}))
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return None


CODE = FakeResponse(200, {"items": [
    {"html_url": "https://github.com/a/b/blob/main/.env",
     "path": ".env", "repository": {"full_name": "a/b"}},
]})
COMMITS = FakeResponse(200, {"items": [
    {"html_url": "https://github.com/a/b/commit/deadbeef",
     "repository": {"full_name": "a/b"},
     "commit": {"message": "remove leaked creds\nsecond line"}},
]})
USERS = FakeResponse(200, {"items": [
    {"html_url": "https://github.com/jdoe", "login": "jdoe"},
]})


def test_github_key_env_and_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("OHO_GITHUB_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    assert github_key() == ""
    (tmp_path / ".env").write_text("OHO_GITHUB_KEY='tok123'\n")
    assert github_key() == "tok123"
    monkeypatch.setenv("OHO_GITHUB_KEY", "real-tok")
    assert github_key() == "real-tok"  # env wins


def test_code_search_requires_key():
    fetcher = FakeFetcher({"search/code": CODE})
    report = github_leaks(fetcher, "q", key="")
    assert report["code"] is None
    assert any("OHO_GITHUB_KEY" in e for e in report["errors"])
    assert all("search/code" not in h.get("Authorization", "") for h in fetcher.headers_seen)


def test_full_report_with_key():
    fetcher = FakeFetcher({
        "search/code": CODE, "search/commits": COMMITS, "search/users": USERS})
    report = github_leaks(fetcher, "user@example.com", key="tok")
    assert report["keyed"] is True
    assert report["code"][0]["repo"] == "a/b"
    assert report["code"][0]["path"] == ".env"
    assert report["commits"][0]["message"] == "remove leaked creds"
    assert report["users"][0]["login"] == "jdoe"
    assert report["errors"] == []
    assert any(h.get("Authorization") == "Bearer tok" for h in fetcher.headers_seen)


def test_failed_sections_reported():
    fetcher = FakeFetcher({})  # everything 404s -> None
    report = github_leaks(fetcher, "q", key="tok")
    assert report["code"] is None and report["commits"] is None and report["users"] is None
    assert len(report["errors"]) == 3
