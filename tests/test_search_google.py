"""Tests for the Google Custom Search engine in osint_core.search."""

import osint_core.search as search
from osint_core.search import dork, google_creds, search_google


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = ""

    def json(self):
        return self._payload


class FakeFetcher:
    """Fetcher stand-in: answers the Google API, fails everything else."""

    def __init__(self, response):
        self.response = response
        self.urls = []

    def get(self, url, **kw):
        self.urls.append(url)
        if "googleapis.com" in url:
            return self.response
        return None  # ddg/bing look blocked — no network in tests


class TestGoogleCreds:
    def test_missing_env_returns_empty(self, monkeypatch):
        monkeypatch.delenv("OHO_GOOGLE_KEY", raising=False)
        monkeypatch.delenv("OHO_GOOGLE_CX", raising=False)
        assert google_creds() == {}

    def test_both_values_required(self):
        assert google_creds({"OHO_GOOGLE_KEY": "k"}) == {}
        assert google_creds({"OHO_GOOGLE_CX": "c"}) == {}

    def test_reads_from_environ(self):
        creds = google_creds({"OHO_GOOGLE_KEY": "k", "OHO_GOOGLE_CX": "c"})
        assert creds == {"key": "k", "cx": "c"}

    def test_dotenv_fallback(self, monkeypatch, tmp_path):
        monkeypatch.delenv("OHO_GOOGLE_KEY", raising=False)
        monkeypatch.delenv("OHO_GOOGLE_CX", raising=False)
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text(
            'OHO_GOOGLE_KEY="k-from-env"\nOHO_GOOGLE_CX=c-from-env\n'
        )
        assert google_creds() == {"key": "k-from-env", "cx": "c-from-env"}

    def test_real_env_wins_over_dotenv(self, monkeypatch, tmp_path):
        monkeypatch.setenv("OHO_GOOGLE_KEY", "k-real")
        monkeypatch.setenv("OHO_GOOGLE_CX", "c-real")
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("OHO_GOOGLE_KEY=k-file\n")
        assert google_creds() == {"key": "k-real", "cx": "c-real"}


class TestSearchGoogle:
    def test_skipped_without_creds(self):
        fetcher = FakeFetcher(FakeResponse())
        state, hits = search_google(fetcher, "test", creds={})
        assert state is None and hits == []
        assert fetcher.urls == []  # never even called the API

    def test_parses_items(self):
        payload = {"items": [
            {"link": "http://a.example", "title": "A <b>result</b>"},
            {"link": "http://b.example", "title": "B"},
            {"title": "no link — skipped"},
        ]}
        state, hits = search_google(
            FakeFetcher(FakeResponse(200, payload)), "test",
            creds={"key": "k", "cx": "c"})
        assert state == "ok"
        assert [h["url"] for h in hits] == ["http://a.example", "http://b.example"]
        assert hits[0]["engine"] == "google"
        assert hits[0]["title"] == "A result"  # tags stripped

    def test_empty_when_no_items(self):
        state, hits = search_google(
            FakeFetcher(FakeResponse(200, {})), "test",
            creds={"key": "k", "cx": "c"})
        assert state == "empty" and hits == []

    def test_http_error_returns_none_and_hints(self, capsys):
        payload = {"error": {"message": "Daily Limit Exceeded"}}
        state, hits = search_google(
            FakeFetcher(FakeResponse(429, payload)), "test",
            creds={"key": "k", "cx": "c"})
        assert state is None and hits == []
        out = capsys.readouterr().out
        assert "Daily Limit Exceeded" in out
        assert "quota" in out

    def test_failed_request_returns_none(self):
        state, hits = search_google(
            FakeFetcher(None), "test", creds={"key": "k", "cx": "c"})
        assert state is None and hits == []


class TestDorkWithGoogle:
    def test_google_included_when_configured(self, monkeypatch):
        monkeypatch.setenv("OHO_GOOGLE_KEY", "k")
        monkeypatch.setenv("OHO_GOOGLE_CX", "c")
        payload = {"items": [{"link": "http://g.example", "title": "G"}]}
        hits, states, flag = dork(FakeFetcher(FakeResponse(200, payload)), "q")
        assert states == {"ddg": None, "bing": None, "google": "ok"}
        assert [h["url"] for h in hits] == ["http://g.example"]
        assert flag == ""  # one healthy engine means no throttle warning

    def test_google_absent_without_creds(self, monkeypatch):
        monkeypatch.delenv("OHO_GOOGLE_KEY", raising=False)
        monkeypatch.delenv("OHO_GOOGLE_CX", raising=False)
        hits, states, flag = dork(FakeFetcher(FakeResponse()), "q")
        assert set(states) == {"ddg", "bing"}
        assert "throttled" in flag

    def test_throttle_flag_when_google_fails_too(self, monkeypatch):
        monkeypatch.setenv("OHO_GOOGLE_KEY", "k")
        monkeypatch.setenv("OHO_GOOGLE_CX", "c")
        payload = {"error": {"message": "keyInvalid"}}
        hits, states, flag = dork(FakeFetcher(FakeResponse(400, payload)), "q")
        assert states["google"] is None
        assert "throttled" in flag
