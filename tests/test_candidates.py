"""Tests for candidate generation (issue #8 — dead filter clause)."""

from osint_core.candidates import generate_candidates, simple_candidates


class TestGenerateCandidates:
    """Verify generate_candidates produces correct output."""

    def test_basic_permutations(self):
        result = generate_candidates("johndoe")
        assert isinstance(result, list)
        assert len(result) > 0
        # All candidates should be ASCII, lowercase, 3+ chars
        for c in result:
            assert c.isascii(), f"non-ASCII candidate: {c}"
            assert c.islower() or not c.isalpha(), f"non-lowercase: {c}"
            assert len(c) >= 3, f"too short: {c}"

    def test_no_leading_trailing_separators(self):
        result = generate_candidates("johndoe")
        for c in result:
            assert not c.startswith("."), f"leading dot: {c}"
            assert not c.startswith("_"), f"leading underscore: {c}"
            assert not c.startswith("-"), f"leading dash: {c}"
            assert not c.endswith("."), f"trailing dot: {c}"
            assert not c.endswith("_"), f"trailing underscore: {c}"
            assert not c.endswith("-"), f"trailing dash: {c}"

    def test_no_regex_patterns_in_candidates(self):
        """The dead clause '[a-zA-Z0-9]' != c is removed; verify no such literal appears."""
        result = generate_candidates("test123")
        assert "[a-zA-Z0-9]" not in result

    def test_capped_at_24(self):
        result = generate_candidates("longfirstnamelonglastname")
        assert len(result) <= 24


class TestSimpleCandidates:
    def test_basic(self):
        result = simple_candidates("johndoe")
        assert isinstance(result, list)
        assert len(result) > 0
        for c in result:
            assert len(c) >= 3

    def test_no_last_name(self):
        result = simple_candidates("john")
        assert isinstance(result, list)
        assert len(result) > 0
