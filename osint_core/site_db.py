"""Site database loader and data classes.

Loads Maigret-format and Sherlock-format site databases (JSON) and provides
MaigretSite/MaigretEngine classes for URL templating, presence/absence
detection, and error classification.
"""

import json
import re
import site
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote


class MaigretEngine:
    """Represents a site engine (e.g. WordPress, GitHub Pages)."""

    def __init__(self, name: str, data: dict):
        self.name = name
        self.__dict__.update(data)

    @property
    def json(self):
        return self.__dict__


class MaigretSite:
    """Describes how to probe a username on a particular site.

    Supports both Maigret and Sherlock data formats via flexible __init__.
    """

    NOT_SERIALIZABLE_FIELDS = [
        "name", "engineData", "requestFuture", "detectedEngine",
        "engineObj", "stats", "urlRegexp",
    ]

    username_claimed = ""
    username_unclaimed = ""
    url_subpath = ""
    url_main = ""
    url = ""
    disabled = False
    similar_search = False
    ignore403 = False
    tags: List[str] = []
    type = "username"
    headers: Dict[str, str] = {}
    errors: Dict[str, str] = {}
    activation: Dict[str, Any] = {}
    regex_check = None
    url_probe = None
    check_type = ""
    request_method = ""
    request_payload: Dict[str, Any] = {}
    request_head_only = ""
    get_params: Dict[str, Any] = {}
    presense_strs: List[str] = []
    absence_strs: List[str] = []
    stats: Dict[str, Any] = {}
    engine = None
    engine_data: Dict[str, Any] = {}
    engine_obj: Optional[MaigretEngine] = None
    request_future = None
    alexa_rank = None
    source: Optional[str] = None
    protocol = ""
    protection: List[str] = []
    # Sherlock-specific fields
    error_code: Optional[Union[int, List[int]]] = None
    error_url: Optional[str] = None
    is_nsfw: bool = False
    username_claimed: str = ""

    def __init__(self, name: str, data: dict):
        self.name = name
        self.pretty_name = data.get("prettyName", name)
        self.stats = {}

        for k, v in data.items():
            if k in self.NOT_SERIALIZABLE_FIELDS:
                continue
            setattr(self, k, v)

        # Map camelCase JSON keys to snake_case attributes
        if "urlMain" in data:
            self.url_main = data["urlMain"]
        if "urlSubpath" in data:
            self.url_subpath = data["urlSubpath"]
        if "checkType" in data:
            self.check_type = data["checkType"]
        if "prettyName" in data:
            self.pretty_name = data["prettyName"]
        # Sherlock uses "errorType" -> map to check_type
        if "errorType" in data:
            et = data["errorType"]
            self.check_type = et if isinstance(et, str) else et[0] if et else "message"
            self.error_types = et if isinstance(et, list) else [et] if et else []
        # Sherlock uses "errorMsg" -> map to absence_strs
        if "errorMsg" in data:
            em = data["errorMsg"]
            self.absence_strs = [em] if isinstance(em, str) else list(em)
        # Maigret's absence/presence markers -> map to the snake_case attributes
        # classify_result() actually reads. Without this the markers are only
        # ever stored under their original camelCase names by the setattr loop
        # above, so detection silently no-ops (see docs/audit/code-quality.md).
        #
        # The upstream database is inconsistent about spelling and ships all
        # four variants, so accept every one. Counts in maigret 2,589-site DB:
        #   absenceStrs 909 | absenseStrs 1 | presenseStrs 526 | presenceStrs 13
        # NB: the consumer attribute is itself spelled "presense_strs"
        # (async_check.py); keep that name rather than silently renaming it.
        def _as_list(value):
            return [value] if isinstance(value, str) else list(value)

        for key in ("absenceStrs", "absenseStrs"):
            if data.get(key):
                self.absence_strs = _as_list(data[key])
                break
        for key in ("presenceStrs", "presenseStrs"):
            if data.get(key):
                self.presense_strs = _as_list(data[key])
                break
        # Sherlock uses "errorCode"
        if "errorCode" in data:
            self.error_code = data["errorCode"]
        # Sherlock uses "errorUrl"
        if "errorUrl" in data:
            self.error_url = data["errorUrl"]
        # Sherlock uses "isNSFW"
        if "isNSFW" in data:
            self.is_nsfw = data["isNSFW"]
            if self.is_nsfw and "adult" not in self.tags:
                self.tags = list(self.tags) + ["adult"]
        # Sherlock uses "regexCheck"
        if "regexCheck" in data:
            self.regex_check = data["regexCheck"]
        # Sherlock uses "urlProbe"
        if "urlProbe" in data:
            self.url_probe = data["urlProbe"]
        # Sherlock uses "username_claimed"
        if "username_claimed" in data:
            self.username_claimed = data["username_claimed"]

        if isinstance(self.tags, str):
            self.tags = [self.tags]

        self.errors_dict = self.errors if isinstance(self.errors, dict) else {}

    def build_url(self, username: str) -> str:
        """Format the URL template with the given username."""
        # Sherlock uses {} as placeholder, Maigret uses {username}
        if "{}" in self.url:
            url = self.url.replace("{}", quote(username))
        else:
            url = self.url.format(
                urlMain=self.url_main,
                urlSubpath=self.url_subpath,
                username=quote(username),
            )
        return re.sub(r"(?<!:)/+", "/", url)

    def build_probe_url(self, username: str) -> str:
        """Format the probe URL (urlProbe or url) with the given username."""
        probe = self.url_probe
        if probe is None:
            return self.build_url(username)
        if "{}" in probe:
            return probe.replace("{}", quote(username))
        return probe.format(
            urlMain=self.url_main,
            urlSubpath=self.url_subpath,
            username=quote(username),
        )

    def check_regex(self, username: str) -> bool:
        """Return True if username passes the site's regexCheck (or no check)."""
        if not self.regex_check:
            return True
        return re.search(self.regex_check, username) is not None

    def json_repr(self) -> dict:
        d = {}
        for k, v in self.__dict__.items():
            if k in self.NOT_SERIALIZABLE_FIELDS:
                continue
            d[k] = v
        return d


class MaigretDatabase:
    """Collection of MaigretSite objects loaded from a JSON database file.

    Supports both Maigret format ({sites: {...}}) and Sherlock format (flat {name: {...}}).
    """

    def __init__(self):
        self.sites: Dict[str, MaigretSite] = {}
        self.engines: Dict[str, MaigretEngine] = {}
        self.self_keywords: List[str] = []
        self.format: str = "maigret"  # "maigret" or "sherlock"

    def load_from_file(self, path: str) -> None:
        """Load a JSON database (auto-detects Maigret vs Sherlock format)."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.load_from_dict(data)

    def load_from_dict(self, data: dict) -> None:
        """Load from an already-parsed dict."""
        # Detect format: Maigret has "sites" key, Sherlock has "$schema" or flat site entries
        if "sites" in data:
            self._load_maigret(data)
        else:
            self._load_sherlock(data)

    def _load_maigret(self, data: dict) -> None:
        """Load Maigret-format data."""
        self.format = "maigret"
        engines_data = data.get("engines", {})
        for name, eng_data in engines_data.items():
            self.engines[name] = MaigretEngine(name, eng_data)

        sites_data = data.get("sites", {})
        for site_name, site_data in sites_data.items():
            try:
                site = MaigretSite(site_name, site_data)
                self.sites[site_name] = site
            except Exception:
                continue

        self.self_keywords = data.get("selfKeywords", [])

    def _load_sherlock(self, data: dict) -> None:
        """Load Sherlock-format data (flat JSON, sites at top level)."""
        self.format = "sherlock"
        for site_name, site_data in data.items():
            if site_name.startswith("$"):
                continue  # skip $schema key
            if not isinstance(site_data, dict):
                continue
            if "url" not in site_data:
                continue
            try:
                site = MaigretSite(site_name, site_data)
                self.sites[site_name] = site
            except Exception:
                continue

    def get_site(self, name: str) -> Optional[MaigretSite]:
        return self.sites.get(name)

    def get_enabled_sites(self) -> Dict[str, MaigretSite]:
        return {k: v for k, v in self.sites.items() if not v.disabled}

    def get_sites_by_tag(self, tag: str) -> Dict[str, MaigretSite]:
        return {
            k: v for k, v in self.sites.items()
            if tag in v.tags and not v.disabled
        }

    def get_nsfw_sites(self) -> Dict[str, MaigretSite]:
        return {k: v for k, v in self.sites.items() if v.is_nsfw}

    def get_sfw_sites(self) -> Dict[str, MaigretSite]:
        return {k: v for k, v in self.sites.items() if not v.is_nsfw and not v.disabled}

    def site_count(self) -> int:
        return len(self.sites)

    def enabled_count(self) -> int:
        return sum(1 for s in self.sites.values() if not s.disabled)


def load_db(path: str) -> MaigretDatabase:
    """Convenience function to load a database from a file path."""
    db = MaigretDatabase()
    db.load_from_file(path)
    return db


def load_sherlock_db(path: str) -> MaigretDatabase:
    """Load a Sherlock-format JSON database."""
    db = MaigretDatabase()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    db._load_sherlock(data)
    return db


def load_default_db() -> Optional[MaigretDatabase]:
    """Try to load the Maigret database from the installed package."""
    try:
        import maigret
        db_path = Path(maigret.__file__).parent / "resources" / "data.json"
        if db_path.exists():
            return load_db(str(db_path))
    except ImportError:
        pass
    return None


def load_default_sherlock_db() -> Optional[MaigretDatabase]:
    """Try to load the Sherlock database from the installed package."""
    try:
        import sherlock_project
        db_path = Path(sherlock_project.__file__).parent / "resources" / "data.json"
        if db_path.exists():
            return load_db(str(db_path))
    except ImportError:
        pass
    # Try common install locations. Derive the user site-packages path from the
    # running interpreter rather than hardcoding a version — a literal
    # "python3.10" silently finds nothing on 3.11+, which the project supports.
    rel = Path("sherlock_project/resources/data.json")
    candidates = [Path(p) / rel for p in site.getsitepackages()]
    user_site = site.getusersitepackages()
    if isinstance(user_site, str):
        user_site = [user_site]
    candidates += [Path(p) / rel for p in user_site]
    candidates.append(Path("/usr/lib/python3/dist-packages") / rel)

    for candidate in candidates:
        if candidate.exists():
            return load_db(str(candidate))
    return None
