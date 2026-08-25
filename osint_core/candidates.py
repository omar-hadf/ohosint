"""Identifier parsing and username-candidate generation.

Three generators are kept because the skills use deliberately different
strategies (a broad name/email permutation sweep, a compact email-only set,
and a hand-tuned second-wave list). They live together so all handle-guessing
logic is in one module.
"""

import re

LOCAL_RE = re.compile(r"^([a-zA-Z]+)[._-]?([a-zA-Z]+)?(\d+)?$")


def parse_local(local):
    """Split an email local-part into (first, last, num) lowercase parts."""
    m = LOCAL_RE.match(local)
    if not m:
        return local.lower(), "", ""
    return m.group(1).lower(), (m.group(2) or "").lower(), (m.group(3) or "")


def split_email(addr):
    """(local, domain, first, last, num), all lowercase."""
    local, _, domain = addr.partition("@")
    first, last, num = parse_local(local)
    return local.lower(), domain.lower(), first, last, num


def generate_candidates(local, year=None):
    """Broad permutation sweep from a local-part/name, with optional year hints.

    Recombines first/last with separators {none . _ -}, swaps order, and adds
    or strips year suffixes. Capped at 24 plausible handles.
    """
    out = {local.lower()}
    m = LOCAL_RE.match(local)
    if m:
        f, l, n = m.group(1).lower(), (m.group(2) or "").lower(), (m.group(3) or "")
        yrs = [n] if n else []
        if year:
            yrs += [str(year)[-2:], str(year)]
        for y in [None] + yrs:
            suf = y or ""
            for sp in ["", ".", "_", "-"]:
                if l:
                    out |= {f + sp + l + suf, l + sp + f + suf}
                out |= {f + suf, f[0] + sp + l + suf if l else f + sp + suf,
                        (f[:4] + suf), (l + suf) if l else ""}
    return sorted({c for c in out
                   if len(c) >= 3 and c.isascii()
                   and not re.search(r"^[._-]|[._-]$", c)
                   and re.fullmatch(r"[a-z0-9._-]+", c)})[:24]


def simple_candidates(local):
    """Compact email-only candidate set (first/last recombinations)."""
    m = LOCAL_RE.match(local)
    if not m:
        return sorted({local.lower()})
    first, last, num = m.group(1).lower(), (m.group(2) or "").lower(), (m.group(3) or "")
    cands = set()
    for sp in ["", ".", "_", "-"]:
        if last:
            cands |= {first + sp + last + num, first + sp + last,
                      last + sp + first + num, last + sp + first}
        cands.add(first + num)
        if num:
            cands.add(last + num)
            cands.add(first[0] + sp + last + num)
    return sorted(c for c in cands if len(c) >= 3)


def second_wave_candidates(seeds, years=("94", "1994")):
    """Follow-up handles built from name fragments, year suffixes and pairings.

    `seeds` is the caller's set of known fragments (e.g. first/last name, a
    de-numbered handle). Nothing here is hardcoded to a specific target.
    """
    seeds = [s.lower() for s in seeds if s]
    c = set()
    for w in seeds:
        c.add(w)
        for y in years:
            for sp in ("", "_", ".", "-"):
                c.add(f"{w}{sp}{y}")
    for a in seeds:
        for b in seeds:
            if a == b:
                continue
            c.add(a + b)
            c.add(f"{a[0]}_{b}")
            for y in years:
                c.add(f"{a}{b}{y}")
    return sorted(x for x in c if 3 <= len(x) <= 25)
