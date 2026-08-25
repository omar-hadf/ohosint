# AGENTS.md

## Project overview

Passive OSINT tool for email/phone/username investigation. The target is never contacted or notified; requests go to public pages and third-party APIs only. Python 3.10+.

## Dependencies

**Runtime (always installed):**
`requests[socks]`, `phonenumbers`, `aiohttp`, `aiohttp-socks`, `aiodns`, `curl_cffi`, `rich`, `stem`, `safe-pysha3`

**Optional (site databases):**
`maigret` — installs the Maigret site database (2,500+ sites)
`sherlock-project` — installs the Sherlock site database
Install both via: `pip install -e .[sweep]`

**Optional (breach API keys — read from the environment, falling back to a `.env` file in the cwd; never stored in reports):**
- `OHO_HIBP_KEY` — Have I Been Pwned `breachedaccount` email search
- `OHO_INTELX_KEY` — Intelligence X free account API
- `OHO_RAPIDAPI_KEY` — BreachDirectory (RapidAPI)
- `OHO_EMAILREP_KEY` — EmailRep (higher quota than keyless)

**Optional (search engine API keys — same env/`.env` convention):**
- `OHO_GOOGLE_KEY` + `OHO_GOOGLE_CX` — both required; adds a `google` engine to `dork()` via the official Custom Search JSON API (no scraping, 100 free queries/day). Unset ⇒ engine list stays DuckDuckGo + Bing.

## Architecture

```
osint_core/          # shared library (single source of truth for all network/search/probe logic)
ohosint/             # unified CLI + interactive shell (console-script entry point: `ohosint`)
skills/
  silent-recon/      # legacy interactive OSINT shell (thin CLI over osint_core)
  silent-account-finder/  # email → adult-platform profile locator
  tor-proxy/         # docs-only skill (no code)
```

`ohosint/` is the primary user-facing interface. `skills/` scripts are still functional but `ohosint` supersedes them with async multi-site sweeps, rich output, and a cleaner config model. Both share `osint_core` as the single source of truth.

## Commands

```bash
# setup
pip install -r requirements.txt
# or install the full package (gives you the `ohosint` command):
pip install -e .

# install with site databases (maigret + sherlock):
pip install -e .[sweep]

# run the ohosint interactive shell
ohosint shell --proxy socks5h://127.0.0.1:9050

# one-shot commands
ohosint email user@example.com --proxy socks5h://127.0.0.1:9050
ohosint username jdoe --sites maigret
ohosint phone +14155550123
ohosint --tor breach user@example.com   # global flags go BEFORE the subcommand
ohosint breach --type password 'hunter2'

# legacy skill scripts (still functional)
python3 skills/silent-recon/silent_recon.py --proxy socks5h://127.0.0.1:9050
```

## Key conventions

- **Passive only**: GET requests to public pages and third-party APIs. Never POST to login/recovery/OTP/forgot-password endpoints — those notify the target. A POST to a third-party search API (e.g. Intelligence X) is allowed because it does not contact the target.
- **Tor integration**: Use `--proxy socks5h://127.0.0.1:9050`. Use `socks5h://` (not `socks5://`) to avoid DNS leaks. The `newnym` command rotates Tor circuits. There are no working .onion breach-search endpoints as of 2026; Tor is used to anonymize clearnet API calls.
- **Delays**: Randomized inter-request sleep (default 1.5–3.5s) via `Fetcher`. Adjustable with `--delay-min`/`--delay-max` or the `delay` shell command.
- **Verdicts**: `confirmed` (200 + handle in page), `probable` (200, no not-found markers), `absent` (404/not-found marker), `unknown` (request failed).
- **Reports**: Written only on explicit request (`save` command or `--out`); never written implicitly. Created `0600` because they contain personal data, and breach reports can contain real leaked credentials. Gitignored (`*_report_*.json`, `*_breach_*.json`, `report.json`, `out.json`).
- **TLS verification**: Enabled by default. Use `--insecure` or `insecure on` in shell to skip verification (not recommended over Tor).
- **Breach sources**: Keyless sources include LeakCheck, Hudson Rock Cavalier, XposedOrNot, HIBP breach catalogue, HIBP Pwned Passwords (k-anonymity), XposedOrNot password check, ProxyNova COMB, and EmailRep. Optional keyed sources (env vars) are HIBP account search, Intelligence X, BreachDirectory, and EmailRep keyed tier. API keys are never written into reports.

## Tests

A pytest suite lives under `tests/` (63 tests). Run it with `pytest`.

`tests/conftest.py` installs autouse fixtures that **block all outbound
sockets**, reset the `exclusions` module cache, and pin each test to a scratch
cwd so no real `.env` is read. Never write a test that hits a live third-party
API — mock at the `oc.*` / `ohosint.pipelines` seam, or use the `no_sources`
fixture. A `NetworkCallInTest` failure means the test leaked.

Lint with `ruff check .` (config in `pyproject.toml`). CI runs lint, a
3.10–3.13 test matrix, and a packaging check — `.github/workflows/ci.yml`.

## Common pitfalls

- Scripts import `osint_core` via `sys.path` manipulation, not as an installed package. Don't add absolute imports that assume a different layout.
- `phonenumbers` is optional at runtime (graceful fallback with raw normalization), but recommended for full phone analysis.
- Search engines aggressively rate-limit Tor/datacenter IPs. If dorks return `junk`/`empty`/`None` for all engines, the agent should suggest rotating the Tor circuit (`newnym`) or waiting. The keyed `google` engine is the exception — it's the official Custom Search JSON API, so it's quota-capped (100/day free) instead of CAPTCHA-throttled.
- `requests[socks]` (with PySocks) is required for SOCKS5 proxy support. A bare `requests` install will fail silently on proxy URLs.
- Site databases (`maigret`, `sherlock-project`) are optional. Without them, `ohosint username`/`email` commands fail with a clear error instead of silently returning 0 results.
