"""Unified result model for async username/email probing.

Merges the best parts of Maigret's MaigretCheckResult and user-scanner's Result
into a single, richer data class used by the async checking engine.
"""

import csv
import io
import json
from enum import Enum
from typing import Any, Dict, List, Optional


class ScanStatus(Enum):
    """Probe outcome enumeration."""

    CLAIMED = "claimed"      # Username/email detected on the site
    AVAILABLE = "available"  # Username/email not detected
    UNKNOWN = "unknown"      # Error or request failure
    ILLEGAL = "illegal"      # Username not allowed on this site
    WAF = "waf"              # Blocked by WAF/CDN (Cloudflare, AWS WAF, PerimeterX)

    def __str__(self):
        return self.value

    def to_label(self, is_email: bool = False) -> str:
        if self == ScanStatus.WAF:
            return "WAF Blocked"
        if self == ScanStatus.UNKNOWN:
            return "Error"
        if self == ScanStatus.ILLEGAL:
            return "Illegal"
        if is_email:
            return "Registered" if self == ScanStatus.CLAIMED else "Not Registered"
        return "Found" if self == ScanStatus.CLAIMED else "Not Found"


class ScanResult:
    """Result of probing a username or email on a single site.

    Attributes:
        username:   The identifier that was probed.
        site_name:  Human-readable site label.
        url:        The URL that was actually fetched.
        status:     ScanStatus enum value.
        extra:      Arbitrary key/value metadata harvested from the page.
        media:      Image/avatar URLs.
        ids_data:   Extracted platform-specific IDs (gaia_id, vk_id, etc.).
        tags:       Category tags from the site database.
        error:      Error message when status is UNKNOWN.
        query_time: Request latency in seconds.
        confidence: Cross-scan confidence score (set by confidence module).
    """

    __slots__ = (
        "username", "site_name", "url", "status", "extra", "media",
        "ids_data", "tags", "error_msg", "query_time", "confidence",
    )

    def __init__(
        self,
        username: str = "",
        site_name: str = "",
        url: str = "",
        status: ScanStatus = ScanStatus.UNKNOWN,
        extra: Optional[Dict[str, Any]] = None,
        media: Optional[Dict[str, str]] = None,
        ids_data: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        error: Optional[str] = None,
        query_time: Optional[float] = None,
        confidence: Optional[str] = None,
    ):
        self.username = username
        self.site_name = site_name
        self.url = url
        self.status = status
        self.extra = extra or {}
        self.media = media or {}
        self.ids_data = ids_data or {}
        self.tags = tags or []
        self.error_msg = error
        self.query_time = query_time
        self.confidence = confidence

    # -- factory helpers --

    @classmethod
    def claimed(cls, **kw):
        return cls(status=ScanStatus.CLAIMED, **kw)

    @classmethod
    def available(cls, **kw):
        return cls(status=ScanStatus.AVAILABLE, **kw)

    @classmethod
    def unknown(cls, **kw):
        return cls(status=ScanStatus.UNKNOWN, **kw)

    @classmethod
    def illegal(cls, **kw):
        return cls(status=ScanStatus.ILLEGAL, **kw)

    @classmethod
    def waf(cls, **kw):
        return cls(status=ScanStatus.WAF, **kw)

    @classmethod
    def error(cls, reason: Any = None, **kw):
        msg = str(reason) if reason is not None else ""
        return cls(status=ScanStatus.UNKNOWN, error=msg, **kw)

    # -- predicates --

    def is_found(self) -> bool:
        return self.status == ScanStatus.CLAIMED

    def is_visible(self, show_all: bool = False) -> bool:
        if show_all:
            return True
        return self.status in (ScanStatus.CLAIMED, ScanStatus.ILLEGAL)

    # -- serialization --

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "site_name": self.site_name,
            "url": self.url,
            "status": self.status.to_label(),
            "extra": self.extra,
            "media": self.media,
            "ids": self.ids_data,
            "tags": self.tags,
            "error": self.error_msg,
            "confidence": self.confidence,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_csv_row(self) -> str:
        fields = ["username", "site_name", "status", "url", "extra", "media", "confidence"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fields, lineterminator="")
        row = {k: self.to_dict().get(k, "") for k in fields}
        row["extra"] = "; ".join(f"{k}: {v}" for k, v in (self.extra or {}).items())
        row["media"] = "; ".join(f"{k}: {v}" for k, v in (self.media or {}).items())
        writer.writerow(row)
        return buf.getvalue()

    def update(self, **kw) -> "ScanResult":
        for field in ("username", "site_name", "url", "confidence"):
            if field in kw and kw[field] is not None:
                setattr(self, field, kw[field])
        if "extra" in kw and isinstance(kw["extra"], dict):
            for k, v in kw["extra"].items():
                if v is None:
                    continue
                clean = k.strip().rstrip(":").replace(" ", "_").lower()
                if clean:
                    self.extra[clean] = v if isinstance(v, (bool, int)) else str(v)
        if "media" in kw and isinstance(kw["media"], dict):
            for k, v in kw["media"].items():
                if v is not None and str(v).strip():
                    self.media[k.strip().lower()] = str(v).strip()
        return self

    def __repr__(self):
        return f"<ScanResult {self.site_name}/{self.username} {self.status}>"

    def __str__(self):
        s = str(self.status)
        if self.error_msg:
            s += f" ({self.error_msg})"
        return s
