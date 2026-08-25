"""Tests for the dork command in ohosint shell."""

from unittest.mock import patch
from ohosint.shell import OHOsintShell
from ohosint.config import Config


class TestDoDork:
    """Verify do_dork calls oc.dork with (fetcher, query) and unpacks 3-tuple."""

    def test_dork_calls_with_fetcher_and_query(self):
        sh = OHOsintShell(Config())
        fake_hits = [{"engine": "ddg", "url": "http://x", "title": "X"}]
        fake_states = {"ddg": "ok", "bing": "ok"}
        fake_flag = ""
        with patch("osint_core.dork", return_value=(fake_hits, fake_states, fake_flag)) as mock_dork:
            sh.onecmd("dork sql injection")
            mock_dork.assert_called_once()
            args = mock_dork.call_args
            # First positional arg should be a Fetcher instance
            from osint_core.net import Fetcher
            assert isinstance(args[0][0], Fetcher)
            # Second positional arg should be the query
            assert args[0][1] == "sql injection"

    def test_dork_empty_query_shows_usage(self, capsys):
        sh = OHOsintShell(Config())
        sh.onecmd("dork  ")
        out = capsys.readouterr().out
        assert "Usage: dork <query>" in out

    def test_dork_unpacks_three_values(self, capsys):
        """Regression: shell used to unpack 2 values from a 3-tuple return."""
        sh = OHOsintShell(Config())
        hits = [{"engine": "ddg", "url": "http://a", "title": "A"}]
        states = {"ddg": "ok", "bing": "empty"}
        flag = "   <-- engines throttled"
        with patch("osint_core.dork", return_value=(hits, states, flag)):
            sh.onecmd("dork test")
        out = capsys.readouterr().out
        assert "ddg" in out
        assert "engines throttled" in out
