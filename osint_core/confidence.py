"""Confidence scoring for cross-scan hits.

Rates how strongly a cross-scan hit is tied to the scanned target, using
confirmed accounts as anchors. Extracted from user-scanner's confidence module.
"""

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from .pivots import EmailKind, EmailPivot, is_media_key, resolve_url
from .scan_result import ScanResult

NAME_KEYS = (
    "name", "fullname", "full_name", "display_name", "displayname",
    "real_name", "realname", "i_am",
)

_OWN_KEYS = frozenset({"confidence", "pivot_source"})

_GENERIC_HOSTS = frozenset({
    "amzn.to", "bit.ly", "buff.ly", "cutt.ly", "discord.gg",
    "docs.google.com", "drive.google.com", "gmail.com", "goo.gl",
    "google.com", "hotmail.com", "is.gd", "lnkd.in", "outlook.com",
    "ow.ly", "paypal.me", "rb.gy", "t.co", "tinyurl.com",
    "wa.me", "yahoo.com",
})

_TOKEN_RE = re.compile(r"[A-Za-z]{2,}")


class Confidence(Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    CANDIDATE = "candidate"
    CONFLICTING = "conflicting"

    @property
    def explanation(self) -> str:
        return {
            Confidence.CONFIRMED: "a pivot named this exact site and handle",
            Confidence.LIKELY: "metadata matches the confirmed profiles",
            Confidence.CANDIDATE: "handle is registered; nothing ties it to the target",
            Confidence.CONFLICTING: "metadata names someone else",
        }[self]


ORDER = (Confidence.CONFIRMED, Confidence.LIKELY, Confidence.CANDIDATE, Confidence.CONFLICTING)


@dataclass(frozen=True)
class Anchors:
    names: FrozenSet[str]
    domains: FrozenSet[str]
    emails: FrozenSet[str]
    urls: FrozenSet[str]
    accounts: FrozenSet[Tuple[str, str]]
    link_domains: FrozenSet[str]


@dataclass(frozen=True)
class RankedEmail:
    email: str
    confidence: Confidence
    sources: Tuple[str, ...]
    field: bool


def build_anchors(
    confirmed: Iterable[ScanResult],
    emails: Iterable[str] = (),
    urls: Iterable[str] = (),
) -> Anchors:
    names: Set[str] = set()
    domains: Set[str] = set()
    accounts: Set[Tuple[str, str]] = set()
    email_set = {e.lower().strip() for e in emails if e}
    url_set = {_normalize_url(u) for u in urls if u}
    url_set.discard("")

    for result in confirmed:
        account = _account_of(result)
        if account:
            accounts.add(account)
        for name in _informative_names(result):
            names.add(_normalize(name))
        for text in _texts(result):
            email_set.update(m.group(0).lower() for m in _EMAIL_RE.finditer(text))
            for u in _urls_in(text):
                url_set.add(_normalize_url(u))
                host = _personal_host(u)
                if host:
                    domains.add(host)
        if result.url:
            url_set.add(_normalize_url(result.url))

    email_set.discard("")
    link_domains = domains - _GENERIC_HOSTS
    domains.update(e.split("@", 1)[1] for e in email_set if "@" in e)
    domains -= _GENERIC_HOSTS
    names.discard("")

    return Anchors(
        names=frozenset(names),
        domains=frozenset(domains),
        emails=frozenset(email_set),
        urls=frozenset(url_set),
        accounts=frozenset(accounts),
        link_domains=frozenset(link_domains),
    )


def score(result: ScanResult, anchors: Anchors, confirmed: bool = False) -> Confidence:
    if confirmed:
        return Confidence.CONFIRMED
    names = _informative_names(result)
    if any(_normalize(name) in anchors.names for name in names):
        return Confidence.LIKELY
    if _links_a_confirmed_account(result, anchors):
        return Confidence.LIKELY
    if _echoes_anchor(result, anchors):
        return Confidence.LIKELY
    if anchors.names and any(_is_person_name(name) for name in names):
        return Confidence.CONFLICTING
    return Confidence.CANDIDATE


def rank_emails(pivots: Iterable[EmailPivot], anchors: Anchors) -> List[RankedEmail]:
    by_email: Dict[str, List[EmailPivot]] = {}
    for pivot in pivots:
        by_email.setdefault(pivot.email, []).append(pivot)

    ranked = [
        RankedEmail(
            email=email,
            confidence=_rate_email(email, group, anchors),
            sources=tuple(sorted({p.origin for p in group})),
            field=any(p.kind is EmailKind.FIELD for p in group),
        )
        for email, group in by_email.items()
    ]
    return sorted(ranked, key=lambda r: (ORDER.index(r.confidence), -len(r.sources), r.email))


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)


def _rate_email(email: str, group: List[EmailPivot], anchors: Anchors) -> Confidence:
    fields = {p.source_site for p in group if p.kind is EmailKind.FIELD}
    if len(fields) >= 2:
        return Confidence.CONFIRMED
    if fields:
        return Confidence.LIKELY
    if email.rpartition("@")[2] in anchors.link_domains:
        return Confidence.LIKELY
    return Confidence.CANDIDATE


def _links_a_confirmed_account(result: ScanResult, anchors: Anchors) -> bool:
    own = _account_of(result)
    for text in _texts(result):
        for u in _urls_in(text):
            site, handle = resolve_url(u)
            if not site or not handle:
                continue
            account = (site, handle.lower())
            if account != own and account in anchors.accounts:
                return True
    return False


def _echoes_anchor(result: ScanResult, anchors: Anchors) -> bool:
    haystack = " ".join(_texts(result)).lower()
    if not haystack:
        return False
    if any(e in haystack for e in anchors.emails):
        return True
    stripped = _strip_schemes(haystack)
    if any(u and u in stripped for u in anchors.urls):
        return True
    return any(d in stripped for d in anchors.domains)


def _account_of(result: ScanResult) -> Optional[Tuple[str, str]]:
    stem = _module_stem(result.site_name or "")
    username = (result.username or "").lower()
    return (stem, username) if stem and username else None


def _is_person_name(value: str) -> bool:
    return len(_TOKEN_RE.findall(value)) >= 2


def _informative_names(result: ScanResult) -> List[str]:
    own = _normalize(result.username or "")
    return [name for name in _names(result) if _normalize(name) and _normalize(name) != own]


def _names(result: ScanResult) -> List[str]:
    return [
        str(result.extra[key]).split(",", 1)[0].strip()
        for key in NAME_KEYS
        if result.extra.get(key)
    ]


def _texts(result: ScanResult) -> List[str]:
    texts = [
        str(value)
        for key, value in result.extra.items()
        if key not in _OWN_KEYS and not is_media_key(key) and isinstance(value, str)
    ]
    if result.url:
        texts.append(str(result.url))
    return texts


def _urls_in(text: str) -> List[str]:
    return re.findall(r"https?://[^\s,;\"'<>()\[\]]+", text)


def _personal_host(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    host = host.removeprefix("www.")
    if not host or host in _GENERIC_HOSTS:
        return ""
    return host


def _normalize_url(url: str) -> str:
    return _strip_schemes(url.strip().lower()).rstrip("/")


def _strip_schemes(value: str) -> str:
    return value.replace("https://", "").replace("http://", "").replace("www.", "")


def _normalize(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value or "")
    without_marks = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "", without_marks.lower())


def _module_stem(site_name: str) -> Optional[str]:
    name = re.sub(r"\s*\(.*\)\s*$", "", (site_name or "").strip().lower())
    stem = re.sub(r"[^a-z0-9]+", "_", name).strip("_")
    return stem or None
