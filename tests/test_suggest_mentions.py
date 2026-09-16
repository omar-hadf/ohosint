"""Tests for osint_core.suggest and osint_core.mentions."""

from osint_core.mentions import mentions
from osint_core.suggest import famous_collision, suggest, wikipedia_lookup


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class Router:
    def __init__(self, routes):
        self.routes = routes

    def get(self, url, **kw):
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return None


GOOGLE = FakeResponse(200, ["jane doe", ["jane doe instagram", "jane doe obituary"]])
DDG = FakeResponse(200, [{"phrase": "jane doe instagram"}, {"phrase": "jane doe facebook"}])
BING = FakeResponse(200, ["jane doe", ["jane doe linkedin"]])
WIKI = FakeResponse(200, ["tom cruise", ["Tom Cruise"], ["actor"],
                          ["https://en.wikipedia.org/wiki/Tom_Cruise"]])


def test_suggest_merges_and_dedupes():
    fetcher = Router({"suggestqueries.google": GOOGLE,
                      "duckduckgo.com/ac": DDG, "bing": BING})
    out = suggest(fetcher, "jane doe")
    assert out["merged"] == [
        "jane doe instagram", "jane doe obituary",
        "jane doe facebook", "jane doe linkedin",
    ]
    assert all(out["engines"].values())


def test_suggest_engine_failure_isolated():
    fetcher = Router({"suggestqueries.google": FakeResponse(500),
                      "duckduckgo.com/ac": DDG, "bing": FakeResponse(502)})
    out = suggest(fetcher, "jane doe")
    assert out["engines"]["google"] is None
    assert out["engines"]["bing"] is None
    assert out["merged"] == ["jane doe instagram", "jane doe facebook"]


def test_wikipedia_lookup_and_collision():
    fetcher = Router({"wikipedia.org": WIKI})
    entries = wikipedia_lookup(fetcher, "tom cruise")
    assert entries == [{"title": "Tom Cruise",
                        "url": "https://en.wikipedia.org/wiki/Tom_Cruise"}]
    assert famous_collision(entries, "tom cruise")
    assert not famous_collision(entries, "tom cruises")
    assert wikipedia_lookup(Router({}), "x") is None


REDDIT = FakeResponse(200, {"data": {"children": [
    {"data": {"title": "found this email in a leak", "subreddit": "osint",
              "author": "anon", "permalink": "/r/osint/comments/abc/x/"}},
]}})
SE = FakeResponse(200, {"items": [
    {"title": "Why is my key on GitHub", "link": "https://stackoverflow.com/q/1",
     "score": 42},
]})


def test_mentions_parse():
    fetcher = Router({"reddit.com/search.json": REDDIT,
                      "api.stackexchange.com": SE})
    out = mentions(fetcher, "user@example.com")
    assert out["reddit"][0]["subreddit"] == "osint"
    assert out["reddit"][0]["url"] == "https://www.reddit.com/r/osint/comments/abc/x/"
    assert out["stackexchange"][0]["score"] == 42


def test_mentions_failure_is_none():
    fetcher = Router({"reddit.com/search.json": FakeResponse(403),
                      "api.stackexchange.com": FakeResponse(200, ValueError("x"))})
    out = mentions(fetcher, "q")
    assert out["reddit"] is None
    assert out["stackexchange"] is None
