"""Tests for the autopsy command proxy behaviour."""

from unittest.mock import patch, MagicMock
from ohosint.shell import OHOsintShell
from ohosint.config import Config
from osint_core.net import Fetcher


class TestDoAutopsy:
    """Verify do_autopsy routes through the session Fetcher (proxy honoured)."""

    def test_autopsy_uses_fetcher_not_bare_requests(self):
        sh = OHOsintShell(Config())
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html></html>"

        with patch.object(sh, "_fetcher") as mock_fetcher_method:
            mock_fetcher = MagicMock(spec=Fetcher)
            mock_fetcher.get.return_value = mock_resp
            mock_fetcher_method.return_value = mock_fetcher

            sh.onecmd("autopsy https://example.com/profile/jdoe")
            mock_fetcher.get.assert_called_once_with("https://example.com/profile/jdoe")

    def test_autopsy_rejects_non_http_url(self, capsys):
        sh = OHOsintShell(Config())
        sh.onecmd("autopsy ftp://example.com/file")
        out = capsys.readouterr().out
        assert "full URL starting with http(s)://" in out

    def test_autopsy_unreachable(self, capsys):
        sh = OHOsintShell(Config())
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch.object(sh, "_fetcher") as mock_fetcher_method:
            mock_fetcher = MagicMock(spec=Fetcher)
            mock_fetcher.get.return_value = mock_resp
            mock_fetcher_method.return_value = mock_fetcher
            sh.onecmd("autopsy https://example.com/404")
            out = capsys.readouterr().out
            assert "unreachable" in out
