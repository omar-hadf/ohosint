"""Tests for osint_core.subdomains (passive subdomain enumeration)."""

import pytest

from osint_core.subdomains import enum_subdomains, valid_domain


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class Router:
    """Fetcher stand-in: route by URL substring."""

    def __init__(self, routes):
        self.routes = routes

    def get(self, url, **kw):
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return None


CRTSH = FakeResponse(200, payload=[
    {"name_value": "www.example.com\nmail.example.com"},
    {"name_value": "*.wildcard.example.com"},
    {"name_value": "WWW.EXAMPLE.COM"},
    {"name_value": "other.com"},  # out of scope — must be dropped
])
HT = FakeResponse(200, text="blog.example.com,1.2.3.4\nwww.example.com,1.2.3.5\n")
OTX = FakeResponse(200, payload={"passive_dns": [
    {"hostname": "api.example.com"},
    {"hostname": "www.example.com"},
]})


def test_valid_domain():
    assert valid_domain("example.com")
    assert valid_domain("sub.example.co.uk")
    assert not valid_domain("not a domain")
    assert not valid_domain("example")


def test_merges_and_normalizes_all_sources():
    fetcher = Router({"crt.sh": CRTSH, "hackertarget": HT, "otx": OTX})
    report = enum_subdomains(fetcher, "example.com")
    assert report["subdomains"] == [
        "api.example.com", "blog.example.com", "mail.example.com",
        "wildcard.example.com", "www.example.com",
    ]
    assert report["sources"] == {"crt.sh": 3, "hackertarget": 2, "otx": 2}
    assert report["errors"] == []


def test_failed_source_marked_none_others_survive():
    fetcher = Router({"crt.sh": None, "hackertarget": HT, "otx": None})
    report = enum_subdomains(fetcher, "example.com")
    assert report["sources"]["crt.sh"] is None
    assert report["sources"]["otx"] is None
    assert report["subdomains"] == ["blog.example.com", "www.example.com"]


def test_bad_json_counts_as_failure():
    fetcher = Router({"crt.sh": FakeResponse(200, payload=ValueError("no json")),
                      "hackertarget": FakeResponse(500), "otx": FakeResponse(403)})
    report = enum_subdomains(fetcher, "example.com")
    assert report["subdomains"] == []
    assert all(v is None for v in report["sources"].values())


def test_hackertarget_error_text_is_failure():
    fetcher = Router({"hackertarget": FakeResponse(200, text="error check your query"),
                      "crt.sh": None, "otx": None})
    report = enum_subdomains(fetcher, "example.com")
    assert report["sources"]["hackertarget"] is None


def test_source_whitelist():
    fetcher = Router({"crt.sh": CRTSH})
    report = enum_subdomains(fetcher, "example.com", sources={"crt.sh"})
    assert list(report["sources"]) == ["crt.sh"]


def test_invalid_domain_raises():
    with pytest.raises(ValueError):
        enum_subdomains(Router({}), "not a domain")
