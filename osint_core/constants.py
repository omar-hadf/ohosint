"""Shared lookup tables used across the OSINT skills.

Single source of truth for user-agents, not-found markers, profile-URL
templates and small display maps. Individual skills select the subset of
platforms they care about rather than redefining their own copies.
"""

# Rotated per request to blend in with ordinary browser traffic.
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

# Substrings that, in a 200 response body, mean "this profile does not exist".
NOT_FOUND_MARKERS = [
    "page not found", "user does not exist", "no user", "profile not found",
    "doesn't exist", "cannot be found", "404", "not exist", "unknown profile",
    "sorry, this page isn", "page you were looking for", "couldn't find",
    "utilisateur n'existe", "nicht gefunden", "no encontrado",
]

# {u} is substituted with a candidate handle. Superset; skills pick keys.
PLATFORMS = {
    "github":     "https://github.com/{u}",
    "gitlab":     "https://gitlab.com/{u}",
    "reddit":     "https://www.reddit.com/user/{u}",
    "telegram":   "https://t.me/{u}",
    "medium":     "https://medium.com/@{u}",
    "keybase":    "https://keybase.io/{u}",
    "soundcloud": "https://soundcloud.com/{u}",
    "pinterest":  "https://www.pinterest.com/{u}/",
    "flickr":     "https://www.flickr.com/people/{u}",
    "vk":         "https://vk.com/{u}",
    "steam":      "https://steamcommunity.com/id/{u}",
    "youtube":    "https://www.youtube.com/@{u}",
    "tiktok":     "https://www.tiktok.com/@{u}",
    "instagram":  "https://www.instagram.com/{u}/",
    "kofi":       "https://ko-fi.com/{u}",
    "bmc":        "https://www.buymeacoffee.com/{u}",
    "xvideos":    "https://www.xvideos.com/profiles/{u}",
    "xnxx":       "https://www.xnxx.com/profiles/{u}",
    "pornhub":    "https://www.pornhub.com/users/{u}",
    "xhamster":   "https://xhamster.com/users/{u}",
    "redtube":    "https://www.redtube.com/users/{u}",
}

# Small, fast subset for a first pass.
QUICK_SITES = ["telegram", "github", "reddit", "instagram", "tiktok",
               "xvideos", "xnxx", "xhamster"]

# phonenumbers.PhoneNumberType value -> human label.
PHONE_TYPE = {
    0: "unknown", 1: "fixed-line", 2: "mobile", 3: "fixed/mobile",
    4: "toll-free", 5: "premium-rate", 6: "shared-cost", 7: "voip",
    8: "personal", 9: "pager", 10: "uan", 11: "voicemail",
}

VERDICT_MARK = {"confirmed": "[+]", "probable": "[?]", "absent": "[-]",
                "unknown": "[!]"}
