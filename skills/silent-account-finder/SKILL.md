---
name: silent-account-finder
description: "Use to locate a person's account/profile on XNXX/XVideos from an email address WITHOUT notifying the target — 100% passive GET-based OSINT (username permutations, public profile probing, search-engine dorks, breach metadata). Explicitly excludes any password-reset / recovery flow that would send email to the owner."
---

# /silent-account-finder

Find which username belongs to a confirmed-registered email on xnxx/xvideos,
using only requests that are invisible to the target.

## Hard rules (enforced by design)

1. **GET only** on public pages. Never POST to login/recovery/forgot endpoints.
2. No account creation, no login attempts, no credential use from breaches.
3. Randomized delays + UA rotation; optional SOCKS5 proxy (tor) for origin IP.
4. Lawful purpose required (authorized assessment / own account / legal case).

## Method plan (why each step is silent)

| Phase | Technique | Why target never knows |
|---|---|---|
| 1 | Candidate generation | local math, zero network |
| 2 | Profile URL probing | reads public profile pages like any visitor |
| 3 | Search-engine dorking | queries hit Google/DDG/Bing caches, not the site's "security" systems; adult profiles are indexed |
| 4 | Breach metadata lookup | queries third-party leak databases, not the platform |

Loud alternatives deliberately excluded: forgot-password, forgot-username,
account-recovery, "report profile" probes — all of these email the owner.

## Phase details

### Phase 1 — candidates
From local part (`jane.doe94`): split first/last/number, recombine with
separators {none . _ -}, swap order, add/strip year → ~15-25 candidates.

### Phase 2 — probe
Templates tried per candidate:
- `https://www.xnxx.com/profiles/{u}`
- `https://www.xvideos.com/profiles/{u}`
Classification = status code + not-found phrase markers + candidate string
appearing in page body/title.

### Phase 3 — dorks (DDG html + Bing)
- `"email"` exact
- `site:xvideos.com "first last"`
- `site:xnxx.com "firstlast"`
- `"firstlast" profile`
Parses result links/titles, flags any xnxx/xvideos URL and extracts the
profile slug if present.

### Phase 4 — breach metadata
Best-effort free sources (no key): LeakCheck public endpoint returns breach
source names for the email — a source named xvideos/xnxx confirms which
platform leaked creds (and combo lists often contain the handle itself).
Optional: run through tor with `--proxy socks5h://127.0.0.1:9050`.

## Usage

```bash
python3 skills/silent-account-finder/find_profiles.py --email user@example.com
python3 skills/silent-account-finder/find_profiles.py --email user@example.com \
        --max-candidates 8 --proxy socks5h://127.0.0.1:9050 --out report.json -v
```

Output: console verdicts + JSON report with confidence levels
(confirmed / probable / absent / unknown).
