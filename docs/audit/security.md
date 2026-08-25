# Security & OPSEC Audit — OHOsint / osint_core

Date: 2026-08-25
Scope: `osint_core/`, `ohosint/`, `skills/`, `.env`/`.gitignore`, dependency manifests. Security & OPSEC only — packaging, docs quality, and general code style are out of scope (covered by other audits).
Method: full read of every network-call site in scope, static grep sweeps for secret/TLS-bypass/injection patterns, targeted reproduction via `unittest.mock` (no real third-party network calls made), one local file-permission reproduction, and a full `pytest` run (63/63 passed, read-only).

## Verdict

No hardcoded secrets exist anywhere in tracked source, docs, or tests — the one real credential in the tree (`OHO_RAPIDAPI_KEY` in `.env`) is correctly `.gitignore`'d and does not appear duplicated anywhere else. TLS verification and the two worst proxy-bypass bugs flagged in the prior audit (`docs/AUDIT.md`, 2026-08-24) are now fixed and covered by regression tests. However, this audit found a **new, unfixed proxy/Tor bypass** — the site-exclusion-list fetch (`osint_core/exclusions.py`) makes a bare, unproxied `requests.get()` call on every default `ohosint email`/`username` run, defeating the tool's core anonymity guarantee exactly like the already-fixed `autopsy` bug did — plus a **data-at-rest gap**: `ohosint breach` auto-saves reports containing real plaintext leaked credentials (by the tool's own design and warning text) under a filename pattern the repo's `.gitignore` does not cover, and all report files are written with default, typically world-readable permissions. These three items should be fixed before the repo goes public. The dual-use/authorized-use posture is already handled well (explicit "Lawful use only" language in `README.md` and all three `skills/*/SKILL.md` files) and needs no changes.

## Severity summary

| # | Severity | File:Line | Summary |
|---|----------|-----------|---------|
| 1 | High | `osint_core/exclusions.py:33` (called from `ohosint/pipelines.py:76,141`) | `fetch_exclusions()` uses bare `requests.get()` with no proxy — bypasses Tor/SOCKS on every default `ohosint email`/`username` run |
| 2 | High | `ohosint/output.py:199`, `ohosint/cli.py:279`, `.gitignore:12-14` | Default `ohosint breach` report filename (`ohosint_breach_*.json`, containing real plaintext leaked credentials) is not matched by any `.gitignore` pattern |
| 3 | Medium | `ohosint/output.py:90-96,193-196`, `osint_core/cli.py:25-28` | Report/breach-report JSON files are written with default OS permissions (no `chmod`) — typically world-readable, yet may contain plaintext leaked credentials and the investigation target's identifiers |
| 4 | Low | `osint_core/async_check.py:215-236`, `osint_core/__init__.py:57,124` | `DnsResolver` checker has no proxy parameter at all; unreachable from any current pipeline, but exported in the public API as a latent DNS-leak footgun |
| 5 | Low | `osint_core/net.py:17,39-41` | `valid_proxy()` silently accepts `socks5://` (DNS-leaking) alongside `socks5h://`, with no warning, despite the README explicitly telling users to prefer the latter |
| 6 | Info | `ohosint/config.py:13`, `osint_core/cli.py:14` | No proxy/Tor by default (opt-in via `--proxy`/`--tor`) — a legitimate, correctly-documented design choice, not a bug |
| 7 | Info | `ohosint/shell.py:219-259`, `osint_core/async_check.py:123-128`, `pyproject.toml:19` | Three findings from the prior audit (`docs/AUDIT.md`) are now fixed and regression-tested: `dork` crash, `autopsy` proxy bypass, unconditional `CERT_NONE` in `AiohttpChecker`; `stem` is now in `pyproject.toml` |
| 8 | Info | `README.md:16-19`, `skills/*/SKILL.md` | Authorized-use / lawful-purpose statement already present in the README and all three skill manifests — no action needed |
| 9 | Info | `requirements.txt:10`, `pyproject.toml:19` | `safe-pysha3` confirmed to be a normal, actively-versioned PyPI package (not a git/URL dependency) — minor single-maintainer supply-chain exposure, nothing abnormal |

No Critical findings — no hardcoded live secret in tracked source, no unconditional TLS bypass, no `eval`/`exec`/`pickle`/`shell=True` anywhere in the tree.

---

## 1. `fetch_exclusions()` bypasses the configured proxy — Tor/SOCKS leak (High, VERIFIED)

**File:** `osint_core/exclusions.py:21-47`, called from `ohosint/pipelines.py:74-77` and `:139-144`.

### Evidence

```python
# osint_core/exclusions.py
def fetch_exclusions(url: str = SHERLOCK_EXCLUSIONS_URL, timeout: float = 10) -> Set[str]:
    ...
    try:
        import requests
        resp = requests.get(url, timeout=timeout)   # <-- no proxies=, no Fetcher
```

```python
# ohosint/pipelines.py — run_username_pipeline() and run_email_pipeline()
apply_exclusions: bool = True,          # default ON
...
    if apply_exclusions:
        try:
            exclusions = oc.fetch_exclusions()      # <-- called with zero proxy context
            sites = oc.filter_excluded_sites(sites, exclusions=exclusions)
```

`fetch_exclusions()` has **no `proxy` parameter at all** — unlike every other network call in this codebase, it doesn't go through `osint_core.net.Fetcher` or thread a `proxy=` kwarg. `apply_exclusions` defaults to `True` in both `Config` (`ohosint/config.py:20`) and the pipeline function signatures, and `--no-exclusions` is the only opt-out. This means **every default `ohosint email`, `ohosint username`, and shell `email`/`username`/`sweep` invocation** makes a direct, unproxied HTTPS request to `raw.githubusercontent.com` — on the operator's real IP — regardless of `--proxy socks5h://...` or `--tor` being set for the rest of the run.

For a tool whose stated purpose is "your own origin is hidden too," this silently deanonymizes every session that uses the default site list, in exactly the same way the now-fixed `autopsy` bug did (see `docs/AUDIT.md` finding #3). Timing correlation is also a concern: a direct clearnet connection made in the same second as Tor-routed traffic is a classic deanonymization vector for this exact threat model.

**How verified:** Read the full function body (no `proxy`/`Fetcher` reference anywhere in `osint_core/exclusions.py`). Reproduced with `unittest.mock.patch("requests.get")` (no real network call made) and confirmed the call is invoked with `kwargs = {'timeout': 10}` — no `proxies=` key present:

```
requests.get called with args: ('https://raw.githubusercontent.com/...',) kwargs: {'timeout': 10}
CONFIRMED: requests.get() invoked with NO proxies= kwarg -> bypasses Tor/SOCKS proxy entirely.
```

### Recommended fix

Thread the fetcher/proxy through, matching every other call site in the codebase:

```python
def fetch_exclusions(fetcher, url: str = SHERLOCK_EXCLUSIONS_URL) -> Set[str]:
    resp = fetcher.get(url)   # osint_core.net.Fetcher — honors proxy + delay
    ...

# ohosint/pipelines.py
if apply_exclusions:
    exclusions = oc.fetch_exclusions(oc.Fetcher(proxy=proxy))
    sites = oc.filter_excluded_sites(sites, exclusions=exclusions)
```

At minimum, add a `proxy: Optional[str] = None` parameter and build a `requests.Session` with `proxies={"http": proxy, "https": proxy}` when set, so the call can never silently ride the operator's real IP when a proxy is configured.

---

## 2. Breach reports containing plaintext leaked credentials are not covered by `.gitignore` (High, VERIFIED)

**Files:** `ohosint/output.py:199-202`, `ohosint/cli.py:262-283`, `.gitignore:9-14`.

### Evidence

```python
# ohosint/output.py
def make_report_path(prefix: str = "ohosint_report") -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.json"
```

```python
# ohosint/cli.py — handle_breach()
if config.out or config.format == "table":     # "table" is the DEFAULT --format
    out_path = config.out or make_report_path(prefix="ohosint_breach")
    formatter.save_breach_json(report, out_path)
```

```
# .gitignore
*_report_*.json
report.json
out.json
```

`ohosint breach <query>` auto-saves a JSON report **by default** (no `--out` needed — the `config.format == "table"` branch triggers the save unconditionally, and `table` is the default format). The generated filename is `ohosint_breach_YYYYMMDD_HHMMSS.json`. That filename does not contain the substring `_report_`, so it matches **none** of the three patterns in `.gitignore`.

Per the report schema (`osint_core/breach.py:670-782`) and the README's own admission ("Plaintext credentials: ProxyNova and BreachDirectory can return real leaked `email:password` pairs. The CLI displays them as-is..."), `report["credentials"]` can contain **other people's real breached passwords in plaintext**, plus the investigation target's own leaked data if matched. Since this repository is about to be published on GitHub, any contributor who runs `ohosint breach ...` in their working copy and later does `git add -A` / `git add .` will have this file staged and is highly likely to push it, publicly leaking third-party breach data attributable to this project's repo history forever.

**How verified:** Traced `make_report_path`'s default prefix through `handle_breach`'s save-trigger condition, then confirmed with Python's `fnmatch` (the same glob semantics `.gitignore` uses for a plain top-level pattern) that `ohosint_breach_20260825_120000.json` is not matched by any of the three ignore patterns, while `ohosint_report_20260825_120000.json` (the email/username report's default name) correctly is:

```
'ohosint_report_20260825_120000.json'         matched_by_gitignore=True
'ohosint_breach_20260825_120000.json'         matched_by_gitignore=False
```

### Recommended fix

Add the missing pattern to `.gitignore` (and consider a catch-all rather than three narrow ones):

```
# Generated recon reports
*_report_*.json
ohosint_breach_*.json
report.json
out.json
```

or simply broaden to `ohosint_*_*.json` / `*.report.json` conventions so any future report prefix is covered by construction, rather than requiring a `.gitignore` update every time a new prefix is added.

---

## 3. Report files written with default (typically world-readable) permissions (Medium, VERIFIED)

**Files:** `ohosint/output.py:90-96` (`save_json`), `ohosint/output.py:193-196` (`save_breach_json`), `osint_core/cli.py:25-28` (`save_report`).

### Evidence

```python
def save_breach_json(self, report: Dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(self.breach_to_json(report))
```

No call site anywhere in the tree (`ohosint/output.py`, `osint_core/cli.py`) sets a restrictive file mode via `os.open(..., 0o600)` or `os.chmod()` after writing. The file is created with whatever the process umask allows.

**How verified — reproduced locally** (no third-party network call; wrote a synthetic report to the scratchpad dir):

```python
of.save_breach_json({"query": "test@example.com",
                      "credentials": [{"source": "proxynova",
                                        "line": "test@example.com:hunter2"}]}, path)
```

Result: file created with mode `0o664` under this environment's `umask 002`. Under the far more common default `umask 022` (stock Debian/Ubuntu/macOS), the same code produces `0o644` — **world-readable**. On any shared or multi-user machine, other local accounts can read a report file containing plaintext breach credentials and the full identity picture (emails, candidate usernames, confirmed-account URLs) built for the investigation target.

### Recommended fix

Open report files with an explicit restrictive mode instead of relying on umask:

```python
import os

def save_breach_json(self, report: Dict, path: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(self.breach_to_json(report))
```

Apply the same pattern to `save_json` (`ohosint/output.py`) and `save_report` (`osint_core/cli.py`).

---

## 4. `DnsResolver` checker has no proxy support — latent DNS-leak footgun (Low, VERIFIED — currently unreachable)

**File:** `osint_core/async_check.py:215-236`; exported at `osint_core/__init__.py:57,124`.

### Evidence

```python
class DnsResolver(BaseChecker):
    """Checker that resolves a domain via DNS (checks if it exists)."""

    def __init__(self, logger=None):        # <-- no `proxy` parameter
        self.logger = logger or logging.getLogger(__name__)
        self.url = None
    ...
    async def check(self):
        import aiodns
        resolver = aiodns.DNSResolver()      # <-- always resolves via the system's plain DNS
        res = await resolver.query(self.url, "A")
```

**How verified:** Confirmed `_pick_checker()` (`osint_core/async_check.py:340-349`) — the only function that selects a checker backend — returns only `CurlCffiChecker` or `AiohttpChecker`, never `DnsResolver`. Grepped the whole tree for `DnsResolver(` and found no instantiation anywhere outside its own class body. It is currently dead code on every reachable code path (`ohosint` CLI/shell, all three `skills/` scripts).

However, it **is** part of the public API surface (`osint_core.DnsResolver`, listed in `__all__`), so any future contributor — or a third-party skill authored against this library — reaching for "a lightweight way to check if a domain resolves" would get a checker that performs plain, un-tunneled DNS resolution with no way to route it through Tor/SOCKS, silently defeating the anonymity guarantee for that one check.

### Recommended fix

Either remove `DnsResolver` from the public API until it supports a proxy, or give it one (e.g., resolve via the same `aiohttp_socks`/SOCKS DNS path used by `AiohttpChecker`, or explicitly document/raise if used without a SOCKS5h proxy configured).

---

## 5. `socks5://` accepted silently alongside `socks5h://` (Low, VERIFIED)

**File:** `osint_core/net.py:17,39-41`.

### Evidence

```python
_PROXY_RE = re.compile(r"^(socks5h?|https?)://[\w.\-:\[\]]+/?$")

def valid_proxy(url):
    """True if `url` looks like a socks5(h)/http(s) proxy URL."""
    return bool(_PROXY_RE.match(url))
```

`socks5h?` matches both `socks5://` (DNS resolved **locally**, i.e. leaked outside the tunnel) and `socks5h://` (DNS resolved **through** the proxy). `valid_proxy()` is the only validation gate used by `skills/silent-recon/silent_recon.py`'s `do_proxy` command, and `ohosint/config.py`'s `set_proxy()` does no validation at all. The README explicitly warns: *"Use `socks5h://`, not `socks5://` — the trailing `h` routes DNS resolution through Tor too, avoiding leaks."* — but nothing in the code enforces or even warns about this when a user (or a copy-pasted command missing the `h`) sets a plain `socks5://` proxy.

**How verified:** Read `_PROXY_RE` and confirmed via the regex that `socks5://127.0.0.1:9050` matches (the `h?` makes the `h` optional). Confirmed `valid_proxy` is the sole gate in `silent_recon.py:79` and that `ohosint/config.py:44-49`'s `set_proxy()` has no equivalent check at all.

### Recommended fix

Warn (or refuse) on `socks5://` specifically:

```python
if url.startswith("socks5://"):
    print("[!] socks5:// resolves DNS locally (leak risk) — use socks5h:// instead")
```

---

## 6. No proxy/Tor by default — Info, working as designed

**Files:** `ohosint/config.py:13`, `osint_core/cli.py:14`.

`Config.proxy` defaults to `None`; Tor routing is opt-in via `--proxy socks5h://127.0.0.1:9050` or the `--tor` shortcut. This is a legitimate, correctly-documented design choice (not every investigation needs Tor), and where the tool does build a default Tor URL for the `--tor` shortcut, it correctly uses `socks5h://` (`ohosint/cli.py:123`: `proxy = "socks5h://127.0.0.1:9050" if args.tor else args.proxy`). No action needed beyond making sure users understand the opt-in nature (already stated in the README's "Optional: Tor" section).

---

## 7. Previously-reported issues confirmed fixed (Info)

`docs/AUDIT.md` (dated 2026-08-24, the day before this audit) reported several issues in this same area. Re-verified independently rather than trusting the prior report:

- **`dork` crash / missing fetcher argument** (prior finding #1): `ohosint/shell.py:219-229`'s `do_dork` now calls `oc.dork(self._fetcher(), line.strip())` — correctly passes the proxy-aware `Fetcher`. Regression test at `tests/test_dork.py` (`test_dork_calls_with_fetcher_and_query`, `test_dork_unpacks_three_values`) passes. **Fixed.**
- **`autopsy` proxy bypass** (prior finding #3, High/OPSEC): `ohosint/shell.py:231-259`'s `do_autopsy` now calls `self._fetcher().get(url)` instead of bare `requests.get()`. Regression test at `tests/test_autopsy.py` (`test_autopsy_uses_fetcher_not_bare_requests`) asserts the fetcher mock is invoked. **Fixed.**
- **Unconditional `CERT_NONE` in `AiohttpChecker`** (prior finding #4, Medium): `osint_core/async_check.py:123-128` now only builds a `CERT_NONE` context when `verify_ssl=False` is explicitly passed; default is `verify_ssl=True` (verification on). Threaded end-to-end from `ohosint/cli.py`'s `--insecure` flag (default off) through `Config.insecure_tls` → `verify_ssl=not config.insecure_tls`. Regression tests at `tests/test_tls.py` (5 tests) all pass, including `test_pick_checker_default_verifies`. **Fixed.**
- **`stem` missing from `pyproject.toml`** (prior finding #5, packaging): now present at `pyproject.toml:19` alongside `requirements.txt:9`. **Fixed** (packaging, not re-scored here — outside this audit's remit, noted only because the prior audit flagged it).

All four are confirmed via direct code reading plus the newly-added, passing regression tests (`python3 -m pytest -q` → 63 passed).

---

## 8. Dual-use / authorized-use posture — already adequate (Info)

Assessed per the audit brief: whether this legitimate OSINT tool needs an explicit authorized-use statement, and whether any default behavior is unusually aggressive.

- **Authorized-use statement:** Already present and prominent. `README.md:16-19`:
  > **Lawful use only.** Authorized security assessments, your own accounts, or an active legal case. This tool never logs in, creates accounts, or triggers password-reset / recovery / OTP flows...

  Repeated with near-identical wording in all three skill manifests: `skills/silent-recon/SKILL.md` ("Hard rules... 4. Lawful purpose required"), `skills/silent-account-finder/SKILL.md` (same), and reinforced by explicit "GET only, never POST to login/recovery/OTP" rules in both. No changes needed.
- **Rate limits / aggressiveness:** `Fetcher` (used by all `skills/` scripts and the sync breach path) applies a randomized 1.5–3.5s delay between requests by default (`ohosint/config.py:15-16`, `osint_core/net.py:30-32`). The async username-sweep engine (`osint_core/async_check.py`) has no inter-request delay, only an `in_parallel` concurrency cap (default 20), but since each concurrent request targets a *different* site (not repeated hits on one target), this matches the accepted norm for this class of tool (Sherlock/Maigret behave the same way) and isn't a meaningful abuse vector against any single target.
- **robots.txt / ToS:** Not consulted anywhere (`osint_core/probe.py`, `osint_core/async_check.py`) — also standard for this tool category (a single GET per site to check existence, not a crawler), and consistent with the passive/GET-only design already documented. No action recommended.

---

## 9. Dependency note: `safe-pysha3` (Info)

**Files:** `requirements.txt:10`, `pyproject.toml:19`; used at `osint_core/breach.py:27-30,331-365` for XposedOrNot's Keccak-512 password check (optional — code degrades gracefully with a `note` if not installed, per `osint_core/breach.py:29-30,337-339`).

Confirmed `safe-pysha3` is a normal PyPI package (not a git/URL dependency, no supply-chain red flag beyond being a small, single-maintainer project): installed locally at v1.0.5, `Home-page: https://github.com/5afe/pysha3`, actively versioned (1.0.3 → 1.0.4 → 1.0.5 on PyPI). It is a maintained fork of the older `pysha3` providing Keccak (not NIST SHA-3) for current Python versions. No dependency-confusion or typosquat risk identified — the name is distinct and the import (`import sha3`) matches the package's documented module name. Not a blocker for publishing; worth a one-line comment in `requirements.txt` noting it's optional (`breach --type password` degrades gracefully without it) so downstream users aren't surprised if they trim it.

---

## What's solid (confirmed independently, not just repeated from the prior audit)

- No hardcoded secrets in tracked source, tests, or docs anywhere in the tree — grepped for `rapidapi`/`api_key`/`token`/`secret`, for the actual `.env` key value's 12-character prefix, and for generic 32+-char hex / 40+-char base64 blobs; the only hit for the real key value was `.env` itself.
- `.env` is correctly listed in `.gitignore` (`.gitignore:14`); the repository is not yet a git repo (`git status` → "not a git repository"), so there is no historical leak to scrub either.
- API keys are proven (by code read + `tests/test_breach.py::TestKeyHandling::test_keys_not_in_report`) never to be written into breach reports — adapters (`breach_hibp_account`, `breach_intelx`, `breach_breachdirectory`) never place the `key` argument into their returned dict.
- No `eval`, `exec`, `pickle`, `subprocess`, `shell=True`, `os.system`, or `os.popen` anywhere in the tree.
- Every network call site outside of finding #1 (`osint_core/exclusions.py`) correctly routes through either `osint_core.net.Fetcher` (proxy-aware `requests.Session`) or the proxy-aware async checkers (`AiohttpChecker`/`CurlCffiChecker`) — verified by grepping the entire tree for `requests.`, `urllib`, `socket.`, `aiohttp`, `dns.resolver`/`aiodns`/`getaddrinfo` call sites and tracing each one.
- The one `socket.create_connection` call in the tree (`skills/silent-recon/silent_recon.py:340`) connects to the local Tor control port (`127.0.0.1:9051`) to issue a `NEWNYM` circuit-rotation signal — a loopback control-plane connection, not an outbound leak.
- Password checks correctly use k-anonymity (only a hash prefix leaves the machine): `pwned_password()` sends the first 5 hex chars of a SHA-1 hash; `breach_xon_password()` sends the first 10 hex chars of a Keccak-512 hash. The full plaintext password is never transmitted, and `breach_search()`'s report never stores the plaintext password query (`report["query"]` becomes `sha1:<hash>` for `qtype="password"`) — verified by `tests/test_breach.py::test_password_query_sha1_in_report_not_plaintext`.
- `ScanResult.to_dict()` stores only extracted metadata (site name, URL, status, small `extra`/`media`/`ids` dicts) — never raw fetched HTML — bounding what ends up at rest in reports for the username-sweep path.
