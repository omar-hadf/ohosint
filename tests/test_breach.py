"""Tests for osint_core.breach multi-source breach lookup."""

import hashlib
import json
from unittest.mock import MagicMock, patch

import osint_core as oc


class Resp:
    """Tiny fake requests.Response."""

    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


def fake_fetcher(responses=None, post_response=None):
    """Build a Fetcher whose .get returns sequential responses."""
    f = MagicMock()
    f.get = MagicMock(side_effect=responses or [])
    f.session = MagicMock()
    f.session.post = MagicMock(return_value=post_response)
    f.n_req = 0
    f.nap = MagicMock()
    return f


class TestDetectQtype:
    def test_email(self):
        assert oc.detect_qtype("user@example.com") == "email"

    def test_domain(self):
        assert oc.detect_qtype("example.com") == "domain"

    def test_username(self):
        assert oc.detect_qtype("jdoe") == "username"


class TestLeakCheck:
    def test_found(self):
        f = fake_fetcher([
            Resp(200, {
                "success": True, "found": 2,
                "fields": ["email", "username"],
                "sources": [{"name": "Adobe", "date": "2013-10"}, {"name": "Canva", "date": "2019-05"}],
            })
        ])
        r = oc.breach_leakcheck(f, "user@example.com")
        assert r["found"] is True
        assert [b["name"] for b in r["breaches"]] == ["Adobe", "Canva"]
        assert r["fields"] == ["email", "username"]

    def test_not_found(self):
        f = fake_fetcher([Resp(200, {"success": True, "found": 0, "sources": []})])
        r = oc.breach_leakcheck(f, "clean@example.com")
        assert r["found"] is False
        assert r["breaches"] == []

    def test_unavailable(self):
        f = fake_fetcher([None])
        r = oc.breach_leakcheck(f, "user@example.com")
        assert r["found"] is None
        assert r["note"] == "unavailable"

    def test_throttled(self):
        f = fake_fetcher([Resp(429, {"error": "slow down"})])
        r = oc.breach_leakcheck(f, "user@example.com")
        assert "rate-limited" in r["note"]


class TestXposedOrNot:
    def test_found_nested_breaches(self):
        # v1 wraps the list one extra level
        f = fake_fetcher([
            Resp(200, {"breaches": [["LinkedIn", "Adobe"]]}),
            Resp(200, {"ExposedBreaches": {"breaches_details": [
                {"breach": "LinkedIn", "xposed_date": "2012-05", "xposed_data": "email,password",
                 "xposed_records": 164000000, "password_risk": "medium"},
            ]}}),
        ])
        r = oc.breach_xposedornot(f, "user@example.com")
        assert r["found"] is True
        names = {b["name"] for b in r["breaches"]}
        assert names == {"LinkedIn", "Adobe"}
        linkedin = next(b for b in r["breaches"] if b["name"] == "LinkedIn")
        assert linkedin["date"] == "2012-05"
        assert "email" in linkedin["data_classes"]

    def test_not_found_404(self):
        f = fake_fetcher([Resp(404, {"Error": "Not found", "email": None})])
        r = oc.breach_xposedornot(f, "clean@example.com")
        assert r["found"] is False

    def test_not_found_error_body(self):
        f = fake_fetcher([Resp(200, {"Error": "Not found", "email": None})])
        r = oc.breach_xposedornot(f, "clean@example.com")
        assert r["found"] is False


class TestProxyNova:
    def test_parses_lines(self):
        f = fake_fetcher([Resp(200, {"count": 2, "lines": ["a@b.com:pass1", "a@b.com:pass2"]})])
        r = oc.breach_proxynova(f, "a@b.com")
        assert r["found"] is True
        assert len(r["lines"]) == 2

    def test_throttled(self):
        f = fake_fetcher([Resp(429, {})])
        r = oc.breach_proxynova(f, "a@b.com")
        assert "rate-limited" in r["note"]


class TestPwnedPasswords:
    def test_pwned(self):
        password = "password123"
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        range_resp = f"00000:1\n{suffix}:4829654\nFFFFF:0"
        f = fake_fetcher([Resp(200, text=range_resp)])
        r = oc.pwned_password(f, password)
        assert r["pwned"] is True
        assert r["count"] == 4829654
        called_url = f.get.call_args[0][0]
        assert called_url.endswith(f"/range/{prefix}")
        assert password not in called_url

    def test_clean(self):
        password = "very-unique-password-xyz"
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        suffix = sha1[5:]
        range_resp = "00000:1\nFFFFF:0"
        # ensure suffix not present
        assert suffix not in range_resp
        f = fake_fetcher([Resp(200, text=range_resp)])
        r = oc.pwned_password(f, password)
        assert r["pwned"] is False
        assert r["count"] == 0


class TestHudsonRock:
    def test_email_found(self):
        f = fake_fetcher([Resp(200, {
            "message": "This email is associated with...",
            "stealers": [{"stealer_family": "RedLine", "date_compromised": "2024-01",
                          "operating_system": "Windows", "computer_name": "DESKTOP-1"}],
        })])
        r = oc.breach_hudson_rock_email(f, "user@example.com")
        assert r["found"] is True
        assert r["stealer_count"] == 1
        assert r["stealers"][0]["stealer_family"] == "RedLine"

    def test_not_associated(self):
        f = fake_fetcher([Resp(200, {"message": "This email is not associated...", "stealers": []})])
        r = oc.breach_hudson_rock_email(f, "clean@example.com")
        assert r["found"] is False


class TestHIBPCatalogue:
    def test_enrichment_cache(self):
        # two calls with same domain should hit cache after first
        data = [{"Name": "Adobe", "BreachDate": "2013-10", "DataClasses": ["email", "password"],
                 "PwnCount": 152000000, "Title": "Adobe", "Domain": "adobe.com"}]
        f = fake_fetcher([Resp(200, data), Resp(200, data)])
        r1 = oc.breach_hibp_catalogue(f, "adobe.com")
        r2 = oc.breach_hibp_catalogue(f, "adobe.com")
        assert r1["ok"] is True
        assert r1["count"] == 1
        assert r2["ok"] is True
        assert f.get.call_count == 1  # second was cached


class TestEmailRep:
    def test_keyless(self):
        f = fake_fetcher([Resp(200, {
            "reputation": "high", "references": 12,
            "details": {"credentials_leaked": True, "data_breach": True, "profiles": ["twitter"]},
        })])
        r = oc.breach_emailrep(f, "user@example.com")
        assert r["found"] is True
        assert r["data_breach"] is True
        f.get.assert_called_once()

    def test_with_key_header(self):
        f = fake_fetcher([Resp(200, {"reputation": "none", "details": {"data_breach": False}})])
        oc.breach_emailrep(f, "user@example.com", key="secret")
        _, kwargs = f.get.call_args
        assert kwargs["headers"]["Key"] == "secret"


class TestKeyHandling:
    def test_get_api_keys(self):
        keys = oc.get_api_keys(environ={"OHO_HIBP_KEY": "a", "OHO_INTELX_KEY": "b"})
        assert keys == {"hibp": "a", "intelx": "b"}

    def test_hibp_account_skipped_without_key(self):
        f = fake_fetcher([])
        with patch("osint_core.breach.breach_leakcheck", return_value={"found": False, "breaches": [], "note": ""}), \
             patch("osint_core.breach.breach_hudson_rock_email", return_value={"found": False, "stealer_count": 0, "note": ""}), \
             patch("osint_core.breach.breach_xposedornot", return_value={"found": False, "breaches": [], "note": ""}), \
             patch("osint_core.breach.breach_proxynova", return_value={"found": False, "lines": [], "note": ""}), \
             patch("osint_core.breach.breach_emailrep", return_value={"found": False, "data_breach": False, "note": ""}):
            report = oc.breach_search(f, "user@example.com", qtype="email", keys={})
        skipped = {s["name"] for s in report["sources_skipped"]}
        assert "hibp" in skipped
        assert "intelx" in skipped
        assert "breachdirectory" in skipped

    def test_env_key_activates_hibp(self):
        f = fake_fetcher([])
        keys = {"hibp": "paid-key", "intelx": "", "breachdirectory": "", "emailrep": ""}
        with patch("osint_core.breach.breach_hibp_account") as mock_hibp, \
             patch("osint_core.breach.breach_hibp_catalogue") as mock_cat, \
             patch("osint_core.breach.breach_leakcheck", return_value={"found": False, "breaches": [], "note": ""}), \
             patch("osint_core.breach.breach_hudson_rock_email", return_value={"found": False, "stealer_count": 0, "note": ""}), \
             patch("osint_core.breach.breach_xposedornot", return_value={"found": False, "breaches": [], "note": ""}), \
             patch("osint_core.breach.breach_proxynova", return_value={"found": False, "lines": [], "note": ""}), \
             patch("osint_core.breach.breach_emailrep", return_value={"found": False, "data_breach": False, "note": ""}):
            mock_hibp.return_value = {"found": True, "breaches": [{"name": "Adobe"}]}
            mock_cat.return_value = {"ok": True, "count": 1, "by_name": {}}
            oc.breach_search(f, "user@example.com", qtype="email", keys=keys)
        mock_hibp.assert_called_once_with(f, "user@example.com", "paid-key")

    def test_keys_not_in_report(self):
        f = fake_fetcher([])
        keys = {"hibp": "super-secret-key"}
        with patch("osint_core.breach.breach_hibp_account") as mock_hibp, \
             patch("osint_core.breach.breach_hibp_catalogue") as mock_cat, \
             patch("osint_core.breach.breach_leakcheck", return_value={"found": False, "breaches": [], "note": ""}), \
             patch("osint_core.breach.breach_hudson_rock_email", return_value={"found": False, "stealer_count": 0, "note": ""}), \
             patch("osint_core.breach.breach_xposedornot", return_value={"found": False, "breaches": [], "note": ""}), \
             patch("osint_core.breach.breach_proxynova", return_value={"found": False, "lines": [], "note": ""}), \
             patch("osint_core.breach.breach_emailrep", return_value={"found": False, "data_breach": False, "note": ""}):
            mock_hibp.return_value = {"found": True, "breaches": [{"name": "Adobe"}]}
            mock_cat.return_value = {"ok": True, "count": 1, "by_name": {"adobe": {"Name": "Adobe"}}}
            report = oc.breach_search(f, "user@example.com", qtype="email", keys=keys)
        dumped = json.dumps(report)
        assert "super-secret-key" not in dumped


class TestOrchestrator:
    def test_merges_breach_names(self):
        f = fake_fetcher([])
        with patch("osint_core.breach.breach_leakcheck") as mock_lc, \
             patch("osint_core.breach.breach_xposedornot") as mock_xon, \
             patch("osint_core.breach.breach_hudson_rock_email") as mock_hr, \
             patch("osint_core.breach.breach_proxynova") as mock_pn, \
             patch("osint_core.breach.breach_emailrep") as mock_er, \
             patch("osint_core.breach.breach_hibp_catalogue") as mock_cat:
            mock_lc.return_value = {"found": True, "breaches": [{"name": "Adobe", "date": "2013-10"}], "note": ""}
            mock_xon.return_value = {"found": True, "breaches": [{"name": "Adobe", "data_classes": ["email", "password"]}], "note": ""}
            mock_hr.return_value = {"found": False, "stealer_count": 0, "note": ""}
            mock_pn.return_value = {"found": False, "lines": [], "note": ""}
            mock_er.return_value = {"found": False, "data_breach": False, "note": ""}
            mock_cat.return_value = {"ok": True, "count": 1, "by_name": {}}

            report = oc.breach_search(f, "user@example.com", qtype="email", keys={})

        assert len(report["breaches"]) == 1
        breach = report["breaches"][0]
        assert breach["name"] == "Adobe"
        assert "leakcheck" in breach["providers"]
        assert "xposedornot" in breach["providers"]
        assert "email" in breach["data_classes"]
        assert breach["date"] == "2013-10"

    def test_password_query_sha1_in_report_not_plaintext(self):
        password = "hunter2"
        f = fake_fetcher([
            Resp(200, text="\n".join(["00000:1", "FFFFF:0"])),
            Resp(200, {"SearchPassAnon": []}),
        ])
        report = oc.breach_search(f, password, qtype="password", keys={})
        assert password not in json.dumps(report)
        assert report["query"].startswith("sha1:")

    def test_sources_whitelist(self):
        f = fake_fetcher([])
        with patch("osint_core.breach.breach_leakcheck") as mock_lc, \
             patch("osint_core.breach.breach_xposedornot") as mock_xon:
            mock_lc.return_value = {"found": False, "breaches": [], "note": ""}
            mock_xon.return_value = {"found": False, "breaches": [], "note": ""}
            report = oc.breach_search(f, "user@example.com", qtype="email", sources=["leakcheck"], keys={})
        assert "leakcheck" in report["sources_used"]
        assert "xposedornot" in {s["name"] for s in report["sources_skipped"]}

    def test_throttle_flag(self):
        f = fake_fetcher([])
        with patch("osint_core.breach.breach_leakcheck") as mock_lc, \
             patch("osint_core.breach.breach_xposedornot") as mock_xon, \
             patch("osint_core.breach.breach_hudson_rock_email") as mock_hr, \
             patch("osint_core.breach.breach_proxynova") as mock_pn, \
             patch("osint_core.breach.breach_emailrep") as mock_er:
            mock_lc.return_value = {"found": False, "breaches": [], "note": "rate-limited/blocked"}
            mock_xon.return_value = {"found": False, "breaches": [], "note": ""}
            mock_hr.return_value = {"found": False, "stealer_count": 0, "note": ""}
            mock_pn.return_value = {"found": False, "lines": [], "note": ""}
            mock_er.return_value = {"found": False, "data_breach": False, "note": ""}
            report = oc.breach_search(f, "user@example.com", qtype="email", keys={})
        assert any("leakcheck" in flag for flag in report["flags"])


class TestXONPassword:
    def test_pwned(self):
        # Keccak-512("password123") first 10 hex chars = aa77c1b9b7
        f = fake_fetcher([Resp(200, {"SearchPassAnon": {"anon": "aa77c1b9b7", "char": "D:3;A:8;S:0;L:11", "count": 789}})])
        r = oc.breach_xon_password(f, "password123")
        assert r["pwned"] is True
        assert r["count"] == 789
        called_url = f.get.call_args[0][0]
        assert called_url.endswith("/AA77C1B9B7")
        assert "password123" not in called_url

    def test_clean_404(self):
        f = fake_fetcher([Resp(404, {})])
        r = oc.breach_xon_password(f, "some-unique-password")
        assert r["pwned"] is False


class TestIntelXAdapter:
    def test_basic_flow(self):
        search_resp = Resp(200, {"id": "abc123", "status": 0})
        result_resp = Resp(200, {"records": [
            {"bucket": "leaks.public", "name": "combo.txt", "added": 1234567890, "systemid": "x"}
        ]})
        f = fake_fetcher([result_resp], post_response=search_resp)
        r = oc.breach_intelx(f, "user@example.com", key="k")
        assert r["found"] is True
        assert r["records"][0]["bucket"] == "leaks.public"
        f.session.post.assert_called_once()

    def test_key_rejected(self):
        search_resp = Resp(403, {})
        f = fake_fetcher([], post_response=search_resp)
        r = oc.breach_intelx(f, "user@example.com", key="k")
        assert "rejected" in r["note"]
