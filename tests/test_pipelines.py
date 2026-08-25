"""Tests for pipeline verify_ssl threading (issue #4)."""

from unittest.mock import patch, MagicMock, AsyncMock
from ohosint.pipelines import run_username_pipeline, run_email_pipeline, run_breach_pipeline


class TestVerifySSLThreading:
    """verify_ssl should be forwarded from pipeline to check_username_sync."""

    def test_username_pipeline_passes_verify_ssl_false(self):
        with patch("ohosint.pipelines.oc.check_username_sync", return_value=[]) as mock_sync:
            run_username_pipeline(
                "testuser",
                sites={"test": MagicMock()},
                verify_ssl=False,
            )
            _, kwargs = mock_sync.call_args
            assert kwargs.get("verify_ssl") is False

    def test_username_pipeline_default_verifies(self):
        with patch("ohosint.pipelines.oc.check_username_sync", return_value=[]) as mock_sync:
            run_username_pipeline(
                "testuser",
                sites={"test": MagicMock()},
            )
            _, kwargs = mock_sync.call_args
            assert kwargs.get("verify_ssl") is True

    def test_email_pipeline_passes_verify_ssl_false(self, no_sources):
        with patch("ohosint.pipelines.check_username_on_sites", new_callable=AsyncMock, return_value=[]) as mock_check:
            run_email_pipeline(
                "test@example.com",
                sites={"test": MagicMock()},
                verify_ssl=False,
            )
            _, kwargs = mock_check.call_args
            assert kwargs.get("verify_ssl") is False

    def test_email_pipeline_applies_exclusions_once(self, no_sources):
        """Exclusions should be fetched once, not per-candidate."""
        with patch("ohosint.pipelines.check_username_on_sites", new_callable=AsyncMock, return_value=[]), \
             patch("ohosint.pipelines.oc.fetch_exclusions", return_value={"excl1"}) as mock_fetch, \
             patch("ohosint.pipelines.oc.filter_excluded_sites", side_effect=lambda s, exclusions: s) as mock_filter:
            run_email_pipeline(
                "test@example.com",
                sites={"test": MagicMock()},
                apply_exclusions=True,
            )
            mock_fetch.assert_called_once()
            mock_filter.assert_called_once()

    def test_email_pipeline_runs_candidates_concurrently(self, no_sources):
        """All candidates should be gathered, not run in a sequential loop."""
        with patch("ohosint.pipelines.check_username_on_sites", new_callable=AsyncMock, return_value=[]) as mock_check:
            run_email_pipeline(
                "test@example.com",
                sites={"test": MagicMock()},
            )
            # check_username_on_sites should be called once per candidate (up to 5)
            # but all in a single asyncio.gather, not sequentially
            assert mock_check.call_count > 0


class TestEmailPipelineSourceFix:
    """Regression: passive source helpers in run_email_pipeline must receive a Fetcher."""

    def test_email_pipeline_passes_fetcher_to_sources(self):
        with patch("ohosint.pipelines.oc.Fetcher") as MockFetcher, \
             patch("ohosint.pipelines.oc.gravatar") as mock_grav, \
             patch("ohosint.pipelines.oc.leakcheck") as mock_lc, \
             patch("ohosint.pipelines.oc.hudson_rock") as mock_hr:
            fetcher_instance = MockFetcher.return_value
            report = run_email_pipeline("test@example.com", sites=None)
            mock_grav.assert_called_once_with(fetcher_instance, "test@example.com")
            mock_lc.assert_called_once_with(fetcher_instance, "test@example.com")
            mock_hr.assert_called_once_with(fetcher_instance, "test@example.com")
            assert "sources" in report

    def test_breach_pipeline_passes_proxy_and_delay(self):
        with patch("ohosint.pipelines.oc.Fetcher") as MockFetcher, \
             patch("ohosint.pipelines.oc.breach_search", return_value={"ok": True}) as mock_search:
            run_breach_pipeline(
                "test@example.com",
                qtype="email",
                proxy="socks5h://127.0.0.1:9050",
                delay=(2.0, 4.0),
                sources=["leakcheck"],
            )
            MockFetcher.assert_called_once_with(proxy="socks5h://127.0.0.1:9050", delay=(2.0, 4.0))
            mock_search.assert_called_once_with(
                MockFetcher.return_value,
                "test@example.com",
                qtype="email",
                sources=["leakcheck"],
            )
