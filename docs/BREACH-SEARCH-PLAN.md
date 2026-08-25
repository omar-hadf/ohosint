# BREACH-SEARCH-PLAN.md — Multi-Source Breach Search for OHOsint

Status: approved 2026-08-24. Implementation tracking in repo.

## 1. Goal

Add a `breach` capability to OHOsint that checks **emails, usernames, domains,
and passwords** against multiple free breach/leak sources, fully routable over
Tor (`--tor` / `--proxy socks5h://...`), with results merged into the existing
JSON report flow. Zero required API keys; optional keyed sources activate via
environment variables.

Passive-only rules from `docs/AGENTS.md` apply: all queries go to third-party
public APIs, never to the target's own infrastructure. (Intelligence X's search
API uses one POST to *its own* API to initiate a search — acceptable, since the
"no POST" rule exists to avoid notifying the target, not third-party services.)

## 2. Research findings — source landscape (verified 2026-08)

### Tier 1 — free, keyless, confirmed live (built first)

| Source | Endpoint | Query types | Limits | Returns |
|---|---|---|---|---|
| **LeakCheck Public API** | `GET https://leakcheck.io/api/public?check={q}` | email, username, SHA256-hash (trunc 24) | 1 req/s | breach names + dates (YYYY-MM) + exposed data *categories* |
| **Hudson Rock Cavalier OSINT** | `GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-{email\|username\|domain\|ip}` (+ `urls-by-domain`) | email, username, domain | ~50 req/10s | infostealer hits: malware family, compromise date, machine context |
| **XposedOrNot** | `GET https://api.xposedornot.com/v1/check-email/{email}`, `/v1/breach-analytics?email=`, `/v1/breaches?domain=` | email, domain | 2/s, 25/h, 100/day | breach names; analytics adds risk/data classes. 404/Error JSON = clean |
| **HIBP breach catalogue** | `GET https://haveibeenpwned.com/api/v3/breaches?domain=` | domain (+ enrichment) | keyless, User-Agent header required | full breach metadata (BreachDate, PwnCount, DataClasses) — used to enrich names reported by other sources |
| **HIBP Pwned Passwords** | `GET https://api.pwnedpasswords.com/range/{first-5-of-SHA1}` | password | keyless, k-anonymity (password never leaves the machine) | pwn count |
| **XON password anon** | `GET https://passwords.xposedornot.com/api/v1/pass/anon/{hash-prefix}` | password | keyless, k-anonymity | second opinion on password exposure |
| **ProxyNova COMB** | `GET https://api.proxynova.com/comb?query={q}&start=0&limit=100` | email, username | ~100 req/min | plaintext `email:password` pairs (3.2B-record COMB dataset) |
| **EmailRep** | `GET https://emailrep.io/{email}` | email | keyless: a few/day; free key: 10/day, 250/month (`Key` header) | `credentials_leaked`, `data_breach` booleans + reputation/profiles (enrichment) |

### Tier 2 — optional, activated by env vars

| Source | Env var | Notes |
|---|---|---|
| **Intelligence X** | `OHO_INTELX_KEY` | Free key from https://intelx.io/account?tab=developer → instance `free.intelx.io`, ~50 selector searches/day. Searches `leaks.public`, `darknet.tor`, `pastes` buckets. Strong selectors only (email, domain, phone, IP, BTC...) |
| **HIBP account search** | `OHO_HIBP_KEY` | Paid key. `GET /api/v3/breachedaccount/{email}`, headers `hibp-api-key` + User-Agent |
| **BreachDirectory (RapidAPI)** | `OHO_RAPIDAPI_KEY` | Free tier: 10 req/month. `GET https://breachdirectory.p.rapidapi.com/?func=auto&term={q}` with `x-rapidapi-key` / `x-rapidapi-host` headers → sources + hashes/passwords |
| **EmailRep key** | `OHO_EMAILREP_KEY` | Raises the tiny keyless quota |

Keys are read from the environment only; they are never written into reports
(the report records which sources were *used* or *skipped*, and why).

### Rejected / dead (do not integrate)

- **pwndb onion** (`pwndb2am4tzkvold.onion`) — **dead**: v2 onion addresses were
  dropped by Tor in 2021 and no working v3 mirror exists. Today there is **no
  viable .onion breach-search endpoint** — Tor's role in this feature is
  anonymizing clearnet API calls via `socks5h://`, which the existing
  `Fetcher`/`requests[socks]` stack already does.
- **GhostProject** — web UI only, Cloudflare-walled, no public API.
- **Scylla** — community-run, chronically down/unstable.
- **Snusbase / DeHashed / LeakRadar / OathNet / HackNotice** — paid or
  account-walled, no usable free API tier.
- **ransomware.live** — free keyless v2 API for ransomware *victim* listings;
  stretch item for domain queries (endpoint shape must be re-verified before
  wiring in).

## 3. Pre-requisite bug fix (found during research)

`ohosint/pipelines.py` (`run_email_pipeline`) called
`oc.gravatar(email)` / `oc.leakcheck(email)` / `oc.hudson_rock(email)` **without
the required `fetcher` first argument** → `TypeError`, swallowed by a broad
`except` → the email pipeline's source lookups silently never ran
(`report["sources"]` was always `{}`). Fixed by building a `Fetcher` from the
pipeline args (new `delay` param) and passing it — the same pattern the breach
pipeline reuses.

## 4. Architecture

### New module: `osint_core/breach.py` (single source of truth)

Follows the existing `sources.py` style: each adapter is
`(fetcher, query, **kw) -> normalized dict` and **never raises** (returns
`note`/`error` keys on failure).

- Adapters: `breach_leakcheck`, `breach_hudson_rock_{email,username,domain}`,
  `breach_xposedornot`, `breach_hibp_catalogue` (in-process cache; enriches
  breach names with dates/data classes), `pwned_password` (SHA-1 k-anonymity —
  only the 5-char prefix leaves the machine), `breach_xon_password`,
  `breach_proxynova` (plaintext lines, opt-in via `--raw`… no: full plaintext
  per approved decision), `breach_emailrep`, and keyed: `breach_intelx`,
  `breach_hibp_account`, `breach_breachdirectory`.
- `get_api_keys()` — reads the four env vars.
- Orchestrator `breach_search(fetcher, query, qtype, sources=None) -> dict`:
  - Routes by type:
    - **email** → leakcheck, hudson_rock, xposedornot, proxynova, emailrep (+ keyed)
    - **username** → leakcheck, hudson_rock, proxynova (+ intelx)
    - **domain** → hudson_rock domain, HIBP catalogue filter, XON breaches (+ intelx)
    - **password** → HIBP Pwned Passwords + XON pass/anon
  - Sequential calls through the `Fetcher` → the existing 1.5–3.5s randomized
    delay keeps us under every rate limit.
  - Normalizes + dedupes breach names across providers with per-provider
    attribution; HIBP catalogue metadata merged in.
  - Per-source graceful degradation: 429/403/Tor-blocked → `note` + "run
    `newnym`" hint (consistent with existing dork behavior).

### Report shape

```json
{
  "generated_at": "...",
  "metadata": {
    "query": "...", "type": "email",
    "sources_used": ["leakcheck", ...],
    "sources_skipped": [{"name": "intelx", "reason": "OHO_INTELX_KEY not set"}]
  },
  "summary": {"unique_breaches": 0, "credential_lines": 0,
              "infostealer_hits": 0, "pwned_password_count": null},
  "breaches": [{"name": "Adobe", "date": "2013-10",
                "providers": ["xposedornot", "leakcheck"],
                "data_classes": ["..."]}],
  "credentials": [{"source": "proxynova", "line": "user@x.com:pass"}],
  "raw": {"<provider>": {"...": "normalized adapter dict"}}
}
```

### CLI / shell wiring

- `ohosint/cli.py`: `breach <query> [--type email|username|domain|password]
  [--sources a,b,c]`; type auto-detected when omitted; global flags (`--tor`,
  delays, `--format`, `--out`) come free.
- `ohosint/pipelines.py`: `run_breach_pipeline(query, qtype, proxy, delay, ...)`
  builds the `Fetcher` and calls `oc.breach_search`.
- `ohosint/output.py`: `print_breach_report()` + `save_breach_json()`.
- `ohosint/shell.py`: `do_breach` using cached `self._fetcher()`; added to
  `do_help`.

## 5. Tests

`tests/test_breach.py` + a regression test for the pipelines fetcher fix:

- Each adapter against a mocked `fetcher.get` with fixture JSON (incl.
  404/429/`None` paths → note, never raise).
- Orchestrator: dedupe/merge correctness; env-var activation; keys absent from
  serialized report.
- k-anonymity: requested URL contains only the 5-char SHA-1 prefix.
- CLI dispatch + proxy/delay threading into the Fetcher.

## 6. Manual verification

With Tor running:

```bash
ohosint --tor breach multiple-breaches@hibp-integration-tests.com  # must show breaches
ohosint breach --type password password123    # heavily pwned; only hash prefix sent
ohosint breach --type username testuser
ohosint breach --type domain adobe.com
ohosint breach clean-never-registered@example.invalid   # "not found" path
pytest
```
