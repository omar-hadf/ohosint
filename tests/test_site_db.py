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
