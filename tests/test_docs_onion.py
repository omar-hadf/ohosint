"""Tests for osint_core.docs (dork pack) and osint_core.onion (Ahmia)."""

from unittest.mock import patch

import osint_core.docs as docs_mod
from osint_core.docs import doc_dorks, hunt_docs
from osint_core.onion import search_onion


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class FakeFetcher:
    def __init__(self, response=None):
        self.response = response

    def get(self, url, **kw):
        return self.response


class TestDocDorks:
    def test_domain_target_uses_site_scope(self):
        pack = doc_dorks("example.com")
        labels = [label for label, _ in pack]
        assert "pdf" in labels and "configs" in labels and "s3" in labels
        assert any(q == "site:example.com filetype:pdf" for _, q in pack)
        assert any(q == 'site:s3.amazonaws.com "example"' for _, q in pack)

    def test_name_target_uses_quoted_scope(self):
        pack = doc_dorks("Jane Doe")
        assert any(q == '"Jane Doe" filetype:pdf' for _, q in pack)
        assert any('"Jane Doe"' in q for label, q in pack if label == "s3")

    def test_buckets_can_be_excluded(self):
        pack = doc_dorks("example.com", include_buckets=False)
        assert not any(label in ("s3", "gcs", "azure") for label, _ in pack)


class TestHuntDocs:
    def test_runs_pack_through_dork_and_flags_throttle(self):
        fake_hits = [{"engine": "ddg", "url": "http://x", "title": "X"}]

        def fake_dork(fetcher, query):
            if "pdf" in query:
                return fake_hits, {"ddg": "ok"}, ""
            return [], {"ddg": None}, "throttled"

        with patch.object(docs_mod, "dork", side_effect=fake_dork):
            report = hunt_docs(FakeFetcher(), "example.com",
                               pack=[("pdf", "site:example.com filetype:pdf"),
                                     ("sql", "site:example.com filetype:sql")])
        assert report["results"][0]["hits"] == fake_hits
        assert report["results"][0]["throttled"] is False
        assert report["results"][1]["hits"] == []
        assert report["results"][1]["throttled"] is True


AHMIA_HTML = """
<ul><li class="result">
  <h4><a href="/search/redirect?redirect_url=http%3A%2F%2Fabc123.onion%2Fpage">Leak <b>Forum</b></a></h4>
</li>
<li class="result">
  <h4><a href="http://def456.onion/">Direct onion link</a></h4>
</li>
<li class="result">
  <h4><span>no anchor here</span></h4>
</li></ul>
"""


class TestOnion:
    def test_parses_and_unwraps_redirects(self):
        state, hits = search_onion(FakeFetcher(FakeResponse(200, AHMIA_HTML)), "q")
        assert state == "ok"
        assert len(hits) == 2
        assert hits[0]["url"] == "http://abc123.onion/page"
        assert hits[0]["title"] == "Leak Forum"
        assert hits[0]["engine"] == "ahmia"
        assert hits[1]["url"] == "http://def456.onion/"

    def test_empty_results(self):
        state, hits = search_onion(FakeFetcher(FakeResponse(200, "<html></html>")), "q")
        assert state == "empty" and hits == []

    def test_failure_returns_none(self):
        assert search_onion(FakeFetcher(FakeResponse(502, "bad gateway")), "q") == (None, [])
        assert search_onion(FakeFetcher(None), "q") == (None, [])
