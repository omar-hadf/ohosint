"""Tests for site database loading (issue #2 — silent empty results)."""

import osint_core as oc
from ohosint.pipelines import load_site_databases


class TestEmptySiteDB:
    """load_site_databases must raise ValueError when no DBs are found."""

    def _patch_no_dbs(self):
        """Return a context manager that monkey-patches both loaders to return None."""
        from unittest.mock import patch
        return patch.object(oc, "load_default_db", return_value=None), \
               patch.object(oc, "load_default_sherlock_db", return_value=None)

    def test_raises_when_no_databases_installed(self):
        p1, p2 = self._patch_no_dbs()
        with p1, p2:
            try:
                load_site_databases("all")
                assert False, "Should have raised ValueError"
            except ValueError as e:
                assert "0 sites loaded" in str(e)
                assert "maigret" in str(e).lower()
                assert "sherlock" in str(e).lower()

    def test_raises_for_maigret_only_when_missing(self):
        p1, p2 = self._patch_no_dbs()
        with p1, p2:
            try:
                load_site_databases("maigret")
                assert False, "Should have raised ValueError"
            except ValueError as e:
                assert "0 sites loaded" in str(e)

    def test_shell_load_sites_returns_empty_dict(self, capsys):
        """Shell _load_sites catches ValueError and returns {}."""
        from ohosint.shell import OHOsintShell
        from ohosint.config import Config

        sh = OHOsintShell(Config())
        p1, p2 = self._patch_no_dbs()
        with p1, p2:
            result = sh._load_sites()
            assert result == {}
            out = capsys.readouterr().out
            assert "0 sites loaded" in out

    def test_shell_email_aborts_on_empty_sites(self, capsys):
        """Shell do_email aborts early when no sites loaded."""
        from ohosint.shell import OHOsintShell
        from ohosint.config import Config

        sh = OHOsintShell(Config())
        p1, p2 = self._patch_no_dbs()
        with p1, p2:
            sh.onecmd("email test@example.com")
            out = capsys.readouterr().out
            assert "0 sites loaded" in out
            # Should NOT have proceeded to pipeline
            assert "Email:" not in out
