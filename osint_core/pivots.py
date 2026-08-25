"""Cross-reference pivot extraction from scan results.

Turns finished scan metadata into new scan targets: handles, verified links,
and email addresses found in profile data. Extracted from user-scanner's
pivots module.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Iterator, List, Optional, Tuple
from urllib.parse import unquote, urlsplit

from .scan_result import ScanResult

# Keys whose value is the account's own handle on the reporting site.
HANDLE_KEYS = frozenset({
    "username", "user_name", "handle", "screen_name", "nickname",
    "login", "login_name", "preferred_username", "profile_name", "vanity",
})

# Keys whose links the platform itself verified.
VERIFIED_KEYS = frozenset({"verified_accounts", "verified_links", "connected_accounts"})

# Keys named after another platform, holding a bare handle rather than a URL.
PLATFORM_HANDLE_KEYS = {
    "bluesky": "bluesky", "facebook": "facebook", "github": "github",
    "instagram": "instagram", "linkedin": "linkedin", "mastodon": "mastodon",
    "pinterest": "pinterest", "reddit": "reddit", "soundcloud": "soundcloud",
    "spotify": "spotify", "tiktok": "tiktok", "tumblr": "tumblr",
    "twitch": "twitch", "twitter": "x", "x": "x", "youtube": "youtube",
}

_PLATFORM_KEY_SUFFIXES = ("_handle", "_username", "_user", "_name")

# Keys whose value is the account holder's own email address.
EMAIL_KEYS = frozenset({
    "email", "emails", "business_email", "contact_email",
    "public_email", "paypal_email", "verified_email",
})

# Role addresses that are not personal.
_ROLE_LOCAL_PARTS = frozenset({
    "abuse", "do-not-reply", "donotreply", "hostmaster",
    "mailer-daemon", "no-reply", "noreply", "postmaster", "webmaster",
})

# Domains that hold no mailbox.
_NON_MAILBOX_DOMAINS = frozenset({
    "domain.com", "email.com", "example.com", "example.net",
    "example.org", "users.noreply.github.com", "yourdomain.com",
})

_NON_MAILBOX_TLDS = (".example", ".invalid", ".localhost", ".test")

# Substrings marking a value as an image URL.
_MEDIA_KEY_PARTS = (
    "avatar", "image", "photo", "picture", "thumbnail", "icon",
    "banner", "background", "snapcode", "pfp", "logo",
)

_URL_RE = re.compile(r"https?://[^\s,;\"'<>()\[\]]+", re.I)
_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{1,63}$")
_EMAIL_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")

# Route table: host -> (module_name, path_patterns)
_BARE = r"^/(?P<user>[^/?#]+)/?$"
_AT = r"^/@(?P<user>[^/?#]+)/?$"

_HOST_ROUTES = (
    (("x.com", "twitter.com"), "x", (_BARE,)),
    (("linkedin.com",), "linkedin", (r"^/in/(?P<user>[^/?#]+)/?$",)),
    (("github.com",), "github", (_BARE,)),
    (("gitlab.com",), "gitlab", (_BARE,)),
    (("stackoverflow.com",), "stackoverflow", (r"^/users/\d+/(?P<user>[^/?#]+)/?$",)),
    (("youtube.com", "youtu.be"), "youtube", (_AT, r"^/c/(?P<user>[^/?#]+)/?$", r"^/user/(?P<user>[^/?#]+)/?$")),
    (("instagram.com",), "instagram", (_BARE,)),
    (("facebook.com", "fb.com"), "facebook", (_BARE,)),
    (("threads.net", "threads.com"), "threads", (_AT,)),
    (("tiktok.com",), "tiktok", (_AT,)),
    (("reddit.com",), "reddit", (r"^/u(?:ser)?/(?P<user>[^/?#]+)/?$",)),
    (("mastodon.social",), "mastodon", (_AT,)),
    (("bsky.app",), "bluesky", (r"^/profile/(?P<user>[^/?#]+)/?$",)),
    (("t.me", "telegram.me"), "telegram", (_BARE,)),
    (("twitch.tv",), "twitch", (_BARE,)),
    (("vk.com",), "vk", (_BARE,)),
    (("pinterest.com",), "pinterest", (_BARE,)),
    (("medium.com",), "medium", (_AT,)),
    (("dev.to",), "devto", (_BARE,)),
    (("github.io",), "github", (_BARE,)),
)

_SUBDOMAIN_ROUTES = (
    ("tumblr.com", "tumblr"),
    ("wordpress.com", "wordpress"),
    ("blogspot.com", "blogger"),
    ("medium.com", "medium"),
    ("substack.com", "substack"),
    ("bandcamp.com", "bandcamp"),
    ("github.io", "github"),
    ("hashnode.dev", "hashnode"),
)

_ROUTES = {
    host: (module, tuple(re.compile(p) for p in patterns))
    for hosts, module, patterns in _HOST_ROUTES
    for host in hosts
}


class PivotKind(Enum):
    HANDLE = "handle"
    VERIFIED = "verified"
    LINK = "link"

    @property
    def rank(self) -> int:
        return {PivotKind.HANDLE: 0, PivotKind.VERIFIED: 1, PivotKind.LINK: 2}[self]


@dataclass(frozen=True)
class Pivot:
    """A username worth scanning, and where it came from."""
    username: str
    kind: PivotKind
    source_site: str
    source_key: str
    site: Optional[str] = None
    url: str = ""

    @property
    def origin(self) -> str:
        return f"{self.source_site} ({self.source_key})"


class EmailKind(Enum):
    FIELD = "field"
    TEXT = "text"

    @property
    def rank(self) -> int:
        return 0 if self is EmailKind.FIELD else 1


@dataclass(frozen=True)
class EmailPivot:
    """An email address worth scanning, and where it came from."""
    email: str
    kind: EmailKind
    source_site: str
    source_key: str

    @property
    def origin(self) -> str:
        return f"{self.source_site} ({self.source_key})"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_pivots(results: Iterable[ScanResult]) -> List[Pivot]:
    """Collect every username a set of finished results implies."""
    pivots: List[Pivot] = []
    seen = set()
    for result in results:
        if not result.is_found():
            continue
        for pivot in _pivots_from_result(result):
            key = (pivot.username.lower(), pivot.site, pivot.kind)
            if key not in seen:
                seen.add(key)
                pivots.append(pivot)
    return sorted(pivots, key=lambda p: (p.kind.rank, p.source_site, p.username.lower()))


def select_pivots(pivots: Iterable[Pivot], links: str = "all") -> List[Pivot]:
    """Filter pivots by link class: 'all', 'verified', or 'none'."""
    if links == "verified":
        return [p for p in pivots if p.kind is not PivotKind.LINK]
    if links == "none":
        return [p for p in pivots if p.kind is PivotKind.HANDLE]
    return list(pivots)


def extract_email_pivots(results: Iterable[ScanResult]) -> List[EmailPivot]:
    """Collect every address a set of finished results exposes."""
    pivots: List[EmailPivot] = []
    seen = set()
    for result in results:
        if not result.is_found():
            continue
        for pivot in _email_pivots_from_result(result):
            key = (pivot.email, pivot.source_site, pivot.kind)
            if key not in seen:
                seen.add(key)
                pivots.append(pivot)
    return sorted(pivots, key=lambda p: (p.kind.rank, p.source_site, p.email))


def select_email_pivots(pivots: Iterable[EmailPivot], emails: str = "verified") -> List[EmailPivot]:
    """Filter address pivots: 'all', 'verified', or 'none'."""
    if emails == "none":
        return []
    if emails == "all":
        return list(pivots)
    return [p for p in pivots if p.kind is EmailKind.FIELD]


def rank_usernames(pivots: Iterable[Pivot]) -> List[str]:
    """Order distinct usernames by how well vouched they are."""
    best: dict = {}
    for pivot in pivots:
        key = pivot.username.lower()
        entry = best.get(key)
        if entry is None:
            best[key] = {"username": pivot.username, "rank": pivot.kind.rank, "count": 1}
            continue
        entry["count"] += 1
        if pivot.kind.rank < entry["rank"]:
            entry["rank"] = pivot.kind.rank
            entry["username"] = pivot.username
    return [e["username"] for e in sorted(best.values(), key=lambda e: (e["rank"], -e["count"], e["username"].lower()))]


def resolve_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Map a profile URL to (module_name, username)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None, None

    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None, None

    host = parts.hostname or ""
    path = unquote(parts.path or "")

    # subdomain check
    for suffix, module in _SUBDOMAIN_ROUTES:
        if host.endswith("." + suffix):
            label = host[: -len(suffix) - 1]
            if "." not in label:
                user = _clean_handle(label)
                if user:
                    return module, user

    # host routes
    labels = host.split(".")
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        route = _ROUTES.get(candidate)
        if route:
            module, patterns = route
            for pattern in patterns:
                match = pattern.match(path)
                if match:
                    user = _clean_handle(match.group("user"))
                    if user:
                        return module, user
            return None, None

    # domain handle fallback
    if path in ("", "/") and len(labels) >= 2:
        user = _clean_handle(labels[-2])
        if user:
            return None, user

    return None, None


def is_media_key(key: str) -> bool:
    return any(part in key for part in _MEDIA_KEY_PARTS)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _pivots_from_result(result: ScanResult) -> Iterator[Pivot]:
    source_site = result.site_name or "Unknown"
    for key, value in result.extra.items():
        if not isinstance(value, str) or is_media_key(key):
            continue
        if key in HANDLE_KEYS:
            handle = _clean_handle(value)
            if handle:
                yield Pivot(handle, PivotKind.HANDLE, source_site, key)
            continue
        name = key.lower()
        for suffix in _PLATFORM_KEY_SUFFIXES:
            name = name.removesuffix(suffix)
        module = PLATFORM_HANDLE_KEYS.get(name)
        if module and not _URL_RE.search(value):
            handle = _clean_handle(value)
            if handle:
                yield Pivot(handle, PivotKind.LINK, source_site, key, module)
            continue
        yield from _pivots_from_links(value, key, source_site)


def _email_pivots_from_result(result: ScanResult) -> Iterator[EmailPivot]:
    source_site = result.site_name or "Unknown"
    for key, value in result.extra.items():
        if not isinstance(value, str) or is_media_key(key):
            continue
        kind = EmailKind.FIELD if key in EMAIL_KEYS else EmailKind.TEXT
        masked = _URL_RE.sub(lambda m: " " * len(m.group(0)), value)
        for match in _EMAIL_RE.finditer(masked):
            if match.start() and masked[match.start() - 1] == "@":
                continue
            addr = _clean_email(match.group(0))
            if addr:
                yield EmailPivot(addr, kind, source_site, key)


def _pivots_from_links(value: str, key: str, source_site: str) -> Iterator[Pivot]:
    verified = key in VERIFIED_KEYS
    for match in _URL_RE.finditer(value):
        url = match.group(0).rstrip(".,;:")
        module, username = resolve_url(url)
        if not username:
            continue
        kind = PivotKind.VERIFIED if verified else PivotKind.LINK
        yield Pivot(username, kind, source_site, key, module, url)


def _clean_handle(value: str) -> Optional[str]:
    handle = unquote(value or "").strip().strip("@").rstrip("/")
    if not _HANDLE_RE.match(handle) or handle.isdigit():
        return None
    return handle


def _clean_email(value: str) -> Optional[str]:
    addr = value.strip().strip(".,;:").lower()
    if not _EMAIL_RE.fullmatch(addr):
        return None
    local, _, domain = addr.rpartition("@")
    if local in _ROLE_LOCAL_PARTS or domain in _NON_MAILBOX_DOMAINS:
        return None
    if domain.startswith("noreply.") or ".noreply." in domain:
        return None
    if domain.endswith(_NON_MAILBOX_TLDS):
        return None
    return addr
