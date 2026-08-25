"""Tests for proxy invalidation in ohosint shell (issue #1/#3)."""

from ohosint.shell import OHOsintShell
from ohosint.config import Config


class TestFetcherInvalidation:
    """Verify the cached Fetcher is invalidated when proxy/delay changes."""

    def test_initial_fetcher_has_no_proxy(self):
        sh = OHOsintShell(Config())
        f = sh._fetcher()
        assert f.session.proxies == {}

    def test_proxy_change_invalidates_fetcher(self):
        sh = OHOsintShell(Config())
        f1 = sh._fetcher()
        sh.onecmd("proxy socks5h://127.0.0.1:9050")
        f2 = sh._fetcher()
        assert f2 is not f1
        assert "socks5h" in f2.session.proxies.get("http", "")

    def test_proxy_clear_invalidates_fetcher(self):
        sh = OHOsintShell(Config())
        sh.onecmd("proxy socks5h://127.0.0.1:9050")
        sh.onecmd("proxy off")
        f = sh._fetcher()
        assert f.session.proxies == {}

    def test_delay_change_invalidates_fetcher(self):
        sh = OHOsintShell(Config())
        f1 = sh._fetcher()
        sh.onecmd("delay 2 4")
        f2 = sh._fetcher()
        assert f2 is not f1
