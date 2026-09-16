"""Keyword extraction -> auto-dorking (a lightweight, dependency-free Iris).

Maryam's Iris uses ML/NLP to analyze harvested text. This is the pragmatic
version: pull a profile page, extract its distinctive keywords, and combine
them with the investigation's known anchors (username / name / email) into
context-aware dorks — "found `hiking` and `portland` in the bio" becomes
`"jdoe" "hiking" "portland"`.

No ML: word/bigram frequency with a stopword list is enough to surface the
terms that make a page distinctive.
"""

import re
from collections import Counter

_WORD_RE = re.compile(r"[a-z][a-z0-9'-]{2,}")

# OpenGraph meta tag -> text (og:title / og:description / og:site_name).
_OG_RE = re.compile(
    r'<meta[^>]+property=["\']og:(title|description|site_name)["\'][^>]+'
    r'content=["\']([^"\']+)["\']',
    re.I,
)


def extract_og_tags(html):
    """Return {tag: content} for og:title / og:description / og:site_name."""
    return {k: v for k, v in _OG_RE.findall(html or "")}


# common english + web-chrome words that carry no investigative signal
STOPWORDS = frozenset("""
a about after all also am an and are as at be been but by can could did do
does for from get got had has have her him his how i if in into is it its
just like me more my no not now of on or our out over own said same she so
some such than that the their them then there these they this to too under
up us very was we were what when where which who will with you your
account agree click contact content cookies copyright follow following home
javascript join log login menu page password policy privacy profile register
reserved rights search sign site subscribe terms username website welcome
""".split())


def _boilerplate_stopwords():
    """JS-shell / social-platform chrome words that dominate raw wall pages."""
    return frozenset("""
    amount symbol cdninstagram instagram cdnjs javascript js cookie cookies
    enable browser check moment secure security connection verify
    """.split())


def extract_keywords(text, top=10):
    """Return [(keyword, count)] — top unigrams and bigrams from `text`."""
    stop = STOPWORDS | _boilerplate_stopwords()
    words = [w for w in _WORD_RE.findall(text.lower()) if w not in stop]
    if not words:
        return []
    unigrams = Counter(w for w in words if len(w) >= 4)
    bigrams = Counter(
        f"{a} {b}" for a, b in zip(words, words[1:])
        if a not in STOPWORDS and b not in STOPWORDS
    )
    ranked = [kv for kv in bigrams.most_common(top) if kv[1] > 1]
    ranked += unigrams.most_common(top)
    seen, out = set(), []
    for kw, n in ranked:
        if kw not in seen:
            seen.add(kw)
            out.append((kw, n))
        if len(out) >= top:
            break
    return out


def auto_dorks(text, anchors, top=5):
    """Combine extracted keywords with known anchors into targeted dorks.

    `anchors`: usernames/names/emails already tied to the target. Returns a
    list of query strings, strongest (two-keyword) combinations first.
    """
    keywords = [kw for kw, _ in extract_keywords(text, top=top)]
    anchors = [a.strip() for a in anchors if a and a.strip()]
    if not keywords or not anchors:
        return []
    queries = []
    for anchor in anchors:
        if len(keywords) >= 2:
            queries.append(f'"{anchor}" "{keywords[0]}" "{keywords[1]}"')
        for kw in keywords[:3]:
            queries.append(f'"{anchor}" "{kw}"')
    # de-dupe, preserve order
    seen, out = set(), []
    for q in queries:
        if q not in seen:
            seen.add(q)
            out.append(q)
    return out
