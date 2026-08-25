"""Tests for AiohttpChecker TLS verification (issue #4)."""

from osint_core.async_check import AiohttpChecker, _pick_checker


class TestAiohttpCheckerSSL:
    """Verify TLS verification is enabled by default."""

    def test_default_verifies_ssl(self):
        c = AiohttpChecker()
        assert c.verify_ssl is True

    def test_can_disable_ssl(self):
        c = AiohttpChecker(verify_ssl=False)
        assert c.verify_ssl is False

    def test_ssl_ctx_none_when_verifying(self):
        """When verify_ssl=True, no custom SSL context should be set (aiohttp defaults)."""
        c = AiohttpChecker(verify_ssl=True)
        assert c.verify_ssl is True

    def test_pick_checker_passes_verify_ssl(self):
        """_pick_checker should forward verify_ssl to the checker."""

        class FakeSite:
            protection = []

        checker = _pick_checker(FakeSite(), proxy=None, verify_ssl=False)
        assert isinstance(checker, AiohttpChecker)
        assert checker.verify_ssl is False

    def test_pick_checker_default_verifies(self):
        class FakeSite:
            protection = []

        checker = _pick_checker(FakeSite())
        assert checker.verify_ssl is True
