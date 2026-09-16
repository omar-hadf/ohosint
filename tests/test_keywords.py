"""Tests for osint_core.keywords (auto-dorking)."""

from osint_core.keywords import auto_dorks, extract_keywords

BIO = ("Hiking enthusiast living in Portland. Hiking every weekend. "
       "Photography and hiking are my life. Check my hiking blog. "
       "Login to subscribe to my newsletter. Privacy policy and terms apply.")


def test_extract_keywords_ranks_and_filters():
    kws = dict(extract_keywords(BIO))
    assert "hiking" in kws and kws["hiking"] >= 4
    assert "portland" in kws
    # stopwords and web-chrome words are gone
    assert "login" not in kws and "privacy" not in kws and "the" not in kws


def test_extract_keywords_empty_text():
    assert extract_keywords("") == []
    assert extract_keywords("the and of") == []


def test_auto_dorks_combines_anchor_and_keywords():
    queries = auto_dorks(BIO, ["jdoe"])
    assert queries
    # strongest combo first: two keywords
    assert queries[0].startswith('"jdoe" "')
    assert queries[0].count('"') == 6  # anchor + two quoted keywords
    assert any(q.count('"') == 4 for q in queries)  # single-keyword variants


def test_auto_dorks_needs_both_sides():
    assert auto_dorks("", ["jdoe"]) == []
    assert auto_dorks(BIO, []) == []
    assert auto_dorks(BIO, ["", "  "]) == []


def test_auto_dorks_dedupes_and_respects_multiple_anchors():
    queries = auto_dorks(BIO, ["jdoe", "jdoe", "jane doe"])
    assert len(queries) == len(set(queries))
    assert any(q.startswith('"jane doe"') for q in queries)
