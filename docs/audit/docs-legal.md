# Documentation Accuracy & Legal/Ethical Readiness Audit

**Scope:** README.md, docs/AGENTS.md, docs/AUDIT.md, docs/PLAN.md, docs/BREACH-SEARCH-PLAN.md, SKILL.md files, and the CLI/shell surface they document. Code internals, packaging metadata, and the test suite are covered by companion audits (`docs/audit/security.md`, `docs/audit/packaging.md`).
**Method:** every command/flag claim was dry-checked against `ohosint/cli.py`'s live `argparse` parser and `ohosint/shell.py`'s `do_*` methods (via `parse_args()` and mocked handler calls — no real network calls were made). Every dependency/behavior claim was checked against the current source. ToS assessments are based on the endpoints found in source plus general knowledge of each platform's terms; none of the third-party ToS pages were fetched live, so every ToS conclusion is marked **UNVERIFIED** for exact current wording even where the underlying behavior is **VERIFIED**.
**Date of audit:** 2026-08-25.

---

## Verdict

The code has clearly moved faster than the docs: nearly every bug `docs/AUDIT.md` reported one day ago (2026-08-24) is already fixed in the current tree, yet the README still describes the *pre-fix* behavior in at least one place, and both `AUDIT.md`/`PLAN.md` read as if the bugs are still open — publishing them unannotated would misrepresent the project to the public. The README itself is a good first draft (it does document `ohosint`, has a real "lawful use" note, and already warns about plaintext-credential handling) but contains several factual errors severe enough to break copy-pasted commands and one overclaim in its core "we're passive" safety promise. The most urgent issues, however, are not documentation bugs at all: **there is no LICENSE file**, **a live-looking third-party API key sits in plaintext in `.env` in the working tree**, and **the `.gitignore` pattern that is supposed to protect generated reports does not actually match the filename the code produces for breach reports** — which can contain real plaintext leaked credentials. None of these block a "docs accuracy" pass, but all three should block a public launch, and the third is a genuine, reproduced (not theoretical) data-exposure risk. Fix those three, tighten the README's factual claims, retire or clearly re-label `AUDIT.md`/`PLAN.md` as historical, and add the intended-use/SECURITY.md content drafted at the end of this report, and the repo is in reasonable shape to publish.

---

## Findings table

| # | Severity | Area | Location | Status |
|---|----------|------|----------|--------|
| L1 | **Critical** | Legal | repo root — no `LICENSE` file, no `license` field in `pyproject.toml` | VERIFIED |
| L2 | **Critical** | Data exposure | `.env` (repo root) — live-looking RapidAPI key in plaintext | VERIFIED |
| L3 | **High** | Data protection | `.gitignore` vs `ohosint/output.py:199-202` — breach-report filenames not actually gitignored | VERIFIED |
| D1 | **High** | README accuracy | README.md:22-23 vs `osint_core/breach.py:471` — "GET only" claim contradicted by a real POST | VERIFIED |
| D2 | **High** | README/AGENTS accuracy | README.md:197, docs/AGENTS.md:54 — `--tor` placed after the subcommand; argparse rejects it (exit 2) | VERIFIED |
| D3 | **High** | README staleness | README.md:132-135 — describes pre-fix "silent 0 results" behavior; code now raises a hard error | VERIFIED |
| D4 | **Medium** | README accuracy | README.md:250-262 — "Reading verdicts" table conflates two disjoint verdict vocabularies | VERIFIED |
| D5 | **Medium** | README/AGENTS accuracy | README.md:140-141, docs/AGENTS.md:17 — "environment only" contradicted by `.env`-file fallback in `breach.py:69-87` | VERIFIED |
| D6 | **Medium** | Docs staleness | docs/AUDIT.md, docs/PLAN.md — 8 of 9 reported findings already fixed in current code | VERIFIED |
| D7 | Low | README accuracy | README.md:276 — broken relative link to `AGENTS.md` (actual path `docs/AGENTS.md`) | VERIFIED |
| D8 | Low | README accuracy | README.md:96-100 — project-layout tree omits `docs/PLAN.md` | VERIFIED |
| D9 | Low | README completeness | README.md:221-224 — shell command summary omits `insecure` | VERIFIED |
| D10 | Low | README completeness | README.md (whole file) — `--insecure`, `--no-exclusions`, `-v/--verbose`, `--timeout`, `--delay-min`/`--delay-max`, `--version` never documented | VERIFIED |
| D11 | Low | AGENTS.md staleness | docs/AGENTS.md:9-10 — dependency list omits `safe-pysha3` (10th dependency in `pyproject.toml`) | VERIFIED |
| D12 | Low | README quality | README.md:1 — title "pythonProject" vs. actual product branding "OHOsint" everywhere else | VERIFIED |
| E1 | Info | Ethics/UA | `osint_core/net.py:56` — browser-spoofing UA rotation applied to breach/reputation APIs (HIBP, EmailRep, etc.), not just site-probing | VERIFIED (code) / UNVERIFIED (ToS conflict) |
| S1 | High | ToS | `osint_core/search.py:34-75` — DuckDuckGo/Bing HTML scraping (not their sanctioned APIs) | VERIFIED (behavior) / UNVERIFIED (exact ToS text) |
| M1 | Medium | Missing docs | No `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `CHANGELOG.md` | VERIFIED |
| M2 | Medium | Ethics | `skills/silent-account-finder/` locates a person's account on adult platforms from just their email, without consent | VERIFIED |

---

## Complete environment-variable table

Grep evidence: `grep -rn "os\.environ\|getenv" --include=*.py` → exactly one hit, `osint_core/breach.py:76` (`env = dict(os.environ)`), which is the single choke point for all four `OHO_*` keys.

| Variable | Read by | What it does | Documented? |
|---|---|---|---|
| `OHO_HIBP_KEY` | `osint_core/breach.py` `_ENV_KEYS` / `get_api_keys()` (:36, :76-87), consumed by `breach_hibp_account()` (:420) | Activates the paid HIBP `breachedaccount` endpoint for authoritative breach names | Yes — README.md:144, docs/AGENTS.md:18 |
| `OHO_INTELX_KEY` | same (`breach.py:37`), consumed by `breach_intelx()` (:449) | Activates Intelligence X search (leaks/darknet.tor/pastes buckets); **this adapter issues a real HTTP POST** to `free.intelx.io/intelligent/search` (:471) | Yes — README.md:145, docs/AGENTS.md:19 |
| `OHO_RAPIDAPI_KEY` | same (`breach.py:38`), consumed by `breach_breachdirectory()` (:508) | Activates BreachDirectory via RapidAPI (free tier: 10 req/month); can return **plaintext email/password/hash records** | Yes — README.md:146, docs/AGENTS.md:20 |
| `OHO_EMAILREP_KEY` | same (`breach.py:39`), consumed by `breach_emailrep()` (:389) | Raises EmailRep's keyless quota | Yes — README.md:147, docs/AGENTS.md:21 |
| *(none — file, not env var)* `.env` in CWD | `osint_core/breach.py:77-86` — read directly with a hand-rolled parser (not `python-dotenv`), only when `get_api_keys()` is called with `environ=None` | Silent fallback source for all four keys above; real env vars still win | **No** — README/AGENTS.md both say keys come "from the environment only" (see finding D5) |
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` / `~/.netrc` *(ambient, not read via `os.environ`/`getenv` in this codebase)* | Implicitly honored by `requests.Session()` (`osint_core/net.py:22`, default `trust_env=True`, never overridden) and explicitly by `aiohttp.ClientSession(..., trust_env=True)` (`osint_core/async_check.py:141`) | Can silently redirect or bypass traffic that the user believes is going through the explicit `--proxy`/`--tor` setting, and can pull HTTP auth from `.netrc` | **No** — not mentioned anywhere, despite being directly relevant to the tool's core anonymity promise |

No other `os.environ`/`getenv` call sites exist anywhere in `osint_core/`, `ohosint/`, or `skills/`.

---

## Per-data-source Terms-of-Service table

All "risk" ratings are my own assessment from the endpoint shape plus general knowledge of how each platform treats automated querying; I did not fetch any of these ToS pages live, so treat every risk rating as **UNVERIFIED** for exact current wording even when marked VERIFIED for the underlying code behavior.

| Source | Endpoint(s) | Auth | Automated-query risk | README must say... |
|---|---|---|---|---|
| LeakCheck | `GET leakcheck.io/api/public` | keyless | **Low** — branded as a public check API; BREACH-SEARCH-PLAN.md notes a self-imposed 1 req/s pace | Respect the rate limit; keyed tier exists for heavier use |
| Hudson Rock Cavalier | `GET cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-{email,username,domain}` | keyless | **Low** — marketed as free OSINT tooling | none needed beyond general courtesy |
| XposedOrNot | `GET api.xposedornot.com/v1/{check-email,breach-analytics,breaches}`, `passwords.xposedornot.com/...` | keyless | **Low** — documented rate limits (2/s, 25/h, 100/day per BREACH-SEARCH-PLAN.md); designed as a public breach-check API | Respect documented limits |
| HIBP breach catalogue / Pwned Passwords | `GET haveibeenpwned.com/api/v3/breaches`, `GET api.pwnedpasswords.com/range/{prefix}` | keyless | **Low for intended use, but see E1** — Pwned Passwords was purpose-built for exactly this k-anonymity integration. HIBP's documented API guidance has historically asked integrators to send an identifying `User-Agent`; this codebase sends a randomized browser-spoofing UA (same pool used to evade site WAFs) on every request, including to HIBP (`net.py:56`). That's a code-behavior mismatch worth fixing regardless of the docs. | Recommend a real, identifying UA for API calls (separate from the browser-spoofing pool used for username-sweep site probing) |
| HIBP account search (keyed) | `GET .../breachedaccount/{email}` | `OHO_HIBP_KEY` | **Low** — paid, sanctioned use | Tell users to get their own key and respect HIBP's quota |
| ProxyNova COMB | `GET api.proxynova.com/comb` | keyless | **High** — unofficial community endpoint serving **literal plaintext stolen credentials** (3.2B-record dump); no discoverable formal ToS; ethically the most fraught source regardless of ToS status | Explicit warning already exists in README (plaintext-credentials note) — keep it, and add a data-protection note (see §5 below) |
| EmailRep | `GET emailrep.io/{email}` | keyless / `OHO_EMAILREP_KEY` | **Low** — built for this exact reputation-check use case | none beyond respecting quota |
| Intelligence X | `POST/GET free.intelx.io/...` | `OHO_INTELX_KEY` (registration required) | **Low** — key-gated, so use is by definition sanctioned by the provider | Tell users to register their own free account |
| BreachDirectory (RapidAPI) | `GET breachdirectory.p.rapidapi.com/` | `OHO_RAPIDAPI_KEY` | **Low-Medium** — RapidAPI marketplace subscription is the sanctioned path, but this specific listing has a mixed public reputation as a "breach lookup reseller"; worth a line telling users to review the listing themselves | Tell users to obtain their own RapidAPI key and review that listing's terms |
| Gravatar | `GET gravatar.com/{md5}.json` | keyless | **Low** — public developer API by design | none |
| Wayback CDX | `GET web.archive.org/cdx/search/cdx` | keyless | **Low** — Internet Archive publishes this API for exactly this kind of use, asks only for reasonable rate limiting | none beyond courtesy |
| **DuckDuckGo (HTML scrape)** | `POST html.duckduckgo.com/html/`, `GET lite.duckduckgo.com/lite/` | keyless | **High** — this is scraping the consumer search-results HTML page, not a sanctioned API product; most consumer search engines' terms prohibit automated/scripted retrieval of results outside a licensed API, and DDG has no general-purpose paid search API equivalent to fall back on | README should disclose that dorking scrapes search-result pages and may be throttled/blocked, and that heavy automated use can conflict with the engine's terms |
| **Bing (HTML scrape)** | `GET www.bing.com/search` | keyless | **High** — same pattern, and the code contains bespoke logic to decode Bing's `u=a1<base64>` link-wrapping (`search.py:20-31`), which only exists because this is unsanctioned scraping working around Bing's anti-scraping measures. Microsoft's Bing terms are understood to prohibit systematic/automated retrieval and "data mining, robots, or similar data gathering" outside the licensed Bing Search API. | Same disclosure as DDG, called out explicitly as the higher-risk of the two |

**Bottom line for §5 of the task:** the two search-engine dork sources are the clearest ToS-conflict risk in the project (flagged as requested). Every breach/reputation API is either explicitly free/public-by-design or key-gated (i.e., sanctioned by construction); the README should still tell users to get their own keys and respect published rate limits, which it already does reasonably well for the keyed sources.

---

## Detail per finding

### L1 — No LICENSE file (Critical)

**Evidence (VERIFIED):** `ls -la` at repo root and `grep -n license pyproject.toml README.md` both come back empty. `pyproject.toml`'s `[project]` table has no `license` key. Under default copyright law, code with no license is **not** open source no matter how public the GitHub repo is — nobody can legally fork, modify, or redistribute it, which defeats the point of publishing it.

**Recommended fix:** Pick a license (MIT/Apache-2.0 are the common defaults for a tool like this) *before* the first public commit, add the `LICENSE` file, and add `license = {text = "..."}` (or `license = {file = "LICENSE"}`) to `pyproject.toml`. Given the tool's dual-use nature (legitimate research + real potential for misuse), also consider whether the license should be paired with the intended-use statement drafted below — a license doesn't restrict *use*, only redistribution/modification, so the ethical scoping has to live in the README/CODE_OF_CONDUCT, not the LICENSE text.

### L2 — Live API key in plaintext `.env` (Critical)

**Evidence (VERIFIED):** `/home/omar/Documents/pythonProject/.env` contains:
```
OHO_RAPIDAPI_KEY=e2ccf...[REDACTED — live-looking RapidAPI key, 50 chars]
```
This is read automatically by `osint_core/breach.py:77-87` any time `get_api_keys()` runs without an explicit `environ` override — i.e., every real `ohosint breach` invocation from this directory. `.gitignore:19` does list `.env`, and this directory is not yet a git repository, so the key is *not* currently at risk of being committed by accident — but it has already been read by this audit and by anyone else with filesystem access, so it should be treated as compromised regardless of git status.

**Recommended fix:**
1. Rotate/revoke this RapidAPI key now, independent of the publishing timeline — a key that has sat in plaintext on disk and been read by tooling should not be trusted going forward.
2. Right before the first commit, run `git status` and confirm `.env` shows as ignored (not "??"), not just present in `.gitignore`.
3. Consider replacing `.env` with a checked-in `.env.example` (empty/placeholder values) so contributors know the expected variable names without a real file sitting in the tree.

### L3 — Breach-report filenames are not actually covered by `.gitignore` (High)

**Evidence (VERIFIED, reproduced with a real `git status --ignored` test):** `ohosint/output.py:199-202` defines
```python
def make_report_path(prefix: str = "ohosint_report") -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.json"
```
and `ohosint/cli.py:279` calls it with `prefix="ohosint_breach"` for breach reports, producing filenames like `ohosint_breach_20260825_120000.json`. `.gitignore` only has:
```
*_report_*.json
report.json
out.json
```
`fnmatch.fnmatch("ohosint_breach_20260825_120000.json", "*_report_*.json")` is `False` (no `_report_` substring), and a live `git init` + `git status --ignored` test confirms it: `ohosint_report_*.json` shows `!!` (ignored) but `ohosint_breach_*.json` shows `??` (untracked, **not** ignored). Per README.md:213-215, breach reports "can return real leaked `email:password` pairs" — so this is a concrete path by which a user following the documented workflow could `git add .` real stolen credentials into what may become a public repository.

**Recommended fix:** widen the `.gitignore` pattern, e.g. add `ohosint_breach_*.json` (or better, a single pattern covering both: `ohosint_*_*.json`, or simply `*.json` scoped to the CWD reports if that's not too broad for the project). Also update the README line that currently claims all report filenames are gitignored (see D-findings below) once the pattern is actually fixed.

### D1 — "GET only" claim contradicted by a real POST to Intelligence X (High)

**Evidence (VERIFIED):** README.md:22-23, the first bullet under "How it stays passive":
> 1. **GET only**, against public pages and public third-party APIs. Nothing here ever POSTs to a login, recovery, "forgot password," or OTP endpoint.

`osint_core/breach.py:471` (inside `breach_intelx()`):
```python
r = fetcher.session.post(f"{base}/intelligent/search", json=body, headers=headers, timeout=30)
```
This is a real `POST`, made whenever `OHO_INTELX_KEY` is set and a breach search runs. The *design intent* is fine and is stated correctly elsewhere — `docs/AGENTS.md:63` says "A POST to a third-party search API (e.g. Intelligence X) is allowed because it does not contact the target" — but the README's own headline claim, read literally, is false. This is the tool's core safety promise, stated at the top of a public README; it should be exactly right.

**Recommended fix:** Replace the README's "GET only" framing with AGENTS.md's more precise rule: *no POST to the target's own infrastructure or to any login/recovery/OTP endpoint; POSTs to third-party search APIs you've been keyed into (e.g. Intelligence X) are fine because they never reach the target.*

### D2 — `--tor` placed after the subcommand fails to parse (High)

**Evidence (VERIFIED, reproduced):**
- README.md:197: `ohosint breach --tor someone@example.com`
- docs/AGENTS.md:54: `ohosint breach user@example.com --tor`

Both commands were run against the live parser:
```
$ python3 -m ohosint.cli breach --tor someone@example.com
ohosint: error: unrecognized arguments: --tor
$ echo $?
2
$ python3 -m ohosint.cli breach user@example.com --tor
ohosint: error: unrecognized arguments: --tor
$ echo $?
2
```
`--tor` is defined on the top-level parser (`ohosint/cli.py:37`), not on the `breach` subparser (:101-109). Because `argparse` hands off all remaining tokens to the subparser once it sees the subcommand name, any global flag placed after `breach`/`email`/`username`/etc. is rejected. The correct form, `ohosint --tor breach someone@example.com`, does parse correctly (confirmed: `Namespace(..., tor=True, ..., command='breach', query='someone@example.com', ...)`, `cfg.proxy == 'socks5h://127.0.0.1:9050'`). This exact mistake appears twice — once in each doc — for the tool's flagship privacy feature (Tor routing), which is the worst possible place for a copy-paste-broken example.

**Recommended fix:** Fix both examples to put `--tor`/`--proxy` before the subcommand. Since this is a fairly non-obvious `argparse` gotcha, also add one line explaining it explicitly: *"Global flags like `--tor`/`--proxy`/`--format` must come before the subcommand name, e.g. `ohosint --tor breach ...`, not `ohosint breach --tor ...`."*

### D3 — README describes the pre-fix "silent 0 results" site-DB behavior (High)

**Evidence (VERIFIED, reproduced):** README.md:132-135:
> Without either installed, `ohosint username <handle>` runs but has zero sites to check against (you'll see a `Sherlock/Maigret database not found` warning and a report with `Total: 0`). See finding #2 in [docs/AUDIT.md](docs/AUDIT.md) for details.

Current `ohosint/pipelines.py:53-57`:
```python
if not merged:
    raise ValueError(
        "0 sites loaded — install at least one site database: "
        "pip install maigret sherlock-project   (or: pip install -e .[sweep])"
    )
```
Reproduced end-to-end with both site databases mocked absent:
```
WARNING: Maigret database not found
WARNING: Sherlock database not found
ERROR: Command failed: 0 sites loaded — install at least one site database: pip install maigret sherlock-project   (or: pip install -e .[sweep])
exit code: 1
```
This is the fix described in `docs/PLAN.md`'s "Phase 1, step 3" ("Fail loudly on empty site DBs") — it has already been implemented. The command now exits non-zero with an actionable message; it does **not** silently produce a `Total: 0` report. This is a direct, reproducible contradiction between the README and the current code, and it's actively pointing readers at `docs/AUDIT.md` finding #2 as if it were still live (see D6).

**Recommended fix:** Update README.md:132-135 to describe the actual current behavior (hard error, non-zero exit, actionable install hint) and drop the link to `docs/AUDIT.md` finding #2, or replace it with a note that the finding has been fixed.

### D4 — "Reading verdicts" table conflates two different, non-overlapping vocabularies (Medium)

**Evidence (VERIFIED):** README.md:250-262 presents one table with `confirmed`/`claimed`, `probable`, `absent`/`available`, `unknown`, `waf` as if it's one system. In reality:
- `osint_core/probe.py:21-30` (`classify()`, used only by the `skills/` scripts) returns exactly `"confirmed"`, `"probable"`, `"absent"`, or `"unknown"` — and has **no concept of `waf`** at all.
- `osint_core/scan_result.py:19-23` (`ScanStatus`, used only by `ohosint`) defines `CLAIMED`/`AVAILABLE`/`UNKNOWN`/`ILLEGAL`/`WAF`, and `to_label()` (:28-35) renders them as `"Found"`/`"Not Found"` (or `"Registered"`/`"Not Registered"` for email) / `"Error"` / `"Illegal"` / `"WAF Blocked"` — and **never** produces the strings `"confirmed"`, `"probable"`, or `"absent"`.

A user running `ohosint username X` (the tool the README spends most of its space documenting) will never see "confirmed"/"probable"/"absent" anywhere in the output; a user running `skills/silent-recon/silent_recon.py` will never see "waf" as a distinct verdict. The table is accurate for neither tool individually and misleading as presented.

**Recommended fix:** Split into two small tables (or clearly label which column belongs to which interface): one for `ohosint`'s `ScanStatus` labels, one for the `skills/` scripts' `confirmed`/`probable`/`absent`/`unknown` vocabulary.

### D5 — "Read from the environment only" is contradicted by the `.env`-file fallback (Medium)

**Evidence (VERIFIED):** README.md:140-141: *"Keys are read from the environment only and are never written into reports"*; docs/AGENTS.md:17: *"Optional (breach API keys — env vars only, never stored in reports)"*. But `osint_core/breach.py:66-87` (`get_api_keys()`), docstring: *"Also picks up keys from a local `.env` file (key=value per line, `#` comments) in the current working directory..."*, with the actual file-read implemented at :77-86. The "never written into reports" half of the claim checked out (no adapter returns its key in the report dict) — only the "environment only" half is false.

**Recommended fix:** Reword to: *"Keys are read from real environment variables, or from a `.env` file in the current directory as a fallback (real env vars always win); neither is ever written into reports."* This also connects naturally to the L2 finding above — the doc fix and the security fix should land together.

### D6 — `docs/AUDIT.md`/`docs/PLAN.md` describe bugs that are mostly already fixed (Medium — see also §4 recommendation below)

**Evidence (VERIFIED against current code, finding-by-finding):**

| AUDIT.md # | AUDIT.md claim | Current code state |
|---|---|---|
| 1 | `shell` → `dork` always crashes (missing `fetcher` arg, wrong unpack arity) | **Fixed.** `ohosint/shell.py:224`: `hits, states, flag = oc.dork(self._fetcher(), line.strip())` — correct arg and correct 3-tuple unpack. |
| 2 | Site sweeps silently return 0 results; maigret/sherlock undeclared | **Fixed.** `pyproject.toml` now declares `maigret`/`sherlock`/`sweep` extras; `pipelines.py:53-57` raises `ValueError` on empty DB (see D3). |
| 3 | `autopsy` bypasses the configured proxy | **Fixed.** `ohosint/shell.py:240`: `r = self._fetcher().get(url)` — routes through the configured `Fetcher`, not a bare `requests.get`. |
| 4 | `AiohttpChecker` disables TLS verification unconditionally | **Fixed.** `osint_core/async_check.py:97-128`: `verify_ssl: bool = True` by default; `CERT_NONE` only applied when explicitly disabled (i.e. now opt-in via `--insecure`). |
| 5 | `stem` missing from `pyproject.toml` | **Fixed.** `pyproject.toml:19` lists `stem>=1.8`. |
| 6 | README/AGENTS.md don't mention `ohosint/` | **Partially fixed.** README now documents `ohosint` extensively. AGENTS.md documents the `ohosint/` architecture too, but its dependency list is still stale (see D11). |
| 7 | `Dict[str, any]` (builtin, not `typing.Any`) in 5 places | **Fixed.** `grep -rn "Dict\[str, any\]"` across the whole tree returns nothing. |
| 8 | Dead filter clause in `generate_candidates()` | **Fixed.** The literal-string comparison is gone from `osint_core/candidates.py`. |
| 9 | `probe.py` mislabeled "DEPRECATED" | **Fixed.** Current docstring explains both engines are intentionally kept separate (simplicity vs. scale). |

8 of 9 findings are resolved. `docs/PLAN.md`'s own "Verification results" table (written the same day as `AUDIT.md`) already noted finding #6 was "partially stale" even at the time it was written. One day later, both documents are now substantially historical, but nothing in either file, or in the README's reference to `docs/AUDIT.md` finding #2 (D3 above), signals that to a reader.

**Recommended fix:** see the dedicated §4 assessment below — recommend re-labeling rather than deleting.

### D7 — Broken relative link to AGENTS.md (Low)

**Evidence (VERIFIED):** README.md:276: `See [AGENTS.md](AGENTS.md) for repo conventions...`. This link is relative to README.md's own location (repo root). `ls AGENTS.md` at repo root: *No such file or directory*. The real file is at `docs/AGENTS.md` (confirmed present). On GitHub this renders as a 404.

**Recommended fix:** change the link target to `docs/AGENTS.md`.

### D8 — Project-layout tree omits `docs/PLAN.md` (Low)

**Evidence (VERIFIED):** README.md:96-100 lists only `AGENTS.md`, `AUDIT.md`, `BREACH-SEARCH-PLAN.md` under `docs/`. `ls docs/` shows four files: `AGENTS.md`, `AUDIT.md`, `BREACH-SEARCH-PLAN.md`, `PLAN.md`. `PLAN.md` is real, substantial (112 lines, the remediation plan for `AUDIT.md`), and simply missing from the tree diagram.

**Recommended fix:** add it to the tree, or — if `PLAN.md` is retired per the §4 recommendation below — remove it from the repo and this becomes moot.

### D9 — Shell command summary omits `insecure` (Low)

**Evidence (VERIFIED):** README.md:221-224 lists the shell's commands: `email`, `phone`, `username`, `breach`, `name`, `sweep`, `dork`, `autopsy`, `pivot`, `proxy`, `newnym`, `delay`, `status`, `save`, `clear`, `exit`. `ohosint/shell.py:285-295` defines `do_insecure` (`insecure [on|off] — toggle TLS certificate verification`), and the shell's own `do_help` (:379) lists it. It's a security-relevant toggle (disables TLS verification) and is the one command missing from the README's summary.

**Recommended fix:** add `insecure` to the list.

### D10 — Several global CLI flags are never documented (Low)

**Evidence (VERIFIED via grep):** `--insecure`, `--no-exclusions`, `-v`/`--verbose`, `--timeout`, `--delay-min`/`--delay-max` (as flag names — the *concept* of delays is described in prose), and `--version` appear nowhere in README.md (`grep -n` for each term returns no flag-usage hits). `docs/AGENTS.md` documents `--insecure`/`insecure` and delay adjustment but not `--verbose`/`--timeout`/`--version`/`--no-exclusions`. All seven are real, working flags per `ohosint/cli.py:30-75`.

**Recommended fix:** add a compact flag-reference table to the README (see the structure outline below) covering every top-level flag, not just the five currently demonstrated inline.

### D11 — AGENTS.md dependency list omits `safe-pysha3` (Low)

**Evidence (VERIFIED):** docs/AGENTS.md:9-10 lists 9 runtime dependencies: `requests[socks]`, `phonenumbers`, `aiohttp`, `aiohttp-socks`, `aiodns`, `curl_cffi`, `alive-progress`, `rich`, `stem`. `pyproject.toml:10-21` lists 10, the extra one being `safe-pysha3>=1.0.4`. `osint_core/breach.py:28` imports it (`import sha3  # safe-pysha3 (Keccak-512) for XposedOrNot password checks`), and it backs the `breach_xon_password` keyless source that `docs/AGENTS.md:69`'s own "Breach sources" line documents by name two sections later in the same file — i.e., the file is internally inconsistent, not just out of sync with `pyproject.toml`.

**Recommended fix:** add `safe-pysha3` to the dependency list.

### D12 — README title doesn't match the product's own branding (Low)

**Evidence (VERIFIED):** README.md:1: `# pythonProject — passive OSINT toolkit`. But `ohosint/__init__.py:6-7`: `__shortname__ = "OHOsint"`, `__longname__ = "OHOsint Passive OSINT Tool"`; `pyproject.toml:29`: `ohosint = "ohosint.cli:main"` (the actual installed command name); the shell's own intro banner (`ohosint/shell.py:28-36`) prints an ASCII-art "OHOSINT" banner. Every user-facing surface of the tool calls itself "OHOsint"; only the README's H1 uses the generic directory name "pythonProject".

**Recommended fix:** retitle the README to lead with "OHOsint" (e.g. `# OHOsint — passive OSINT toolkit`), keeping "pythonProject"/`osint_core` as a parenthetical if the repo directory name itself won't change.

### E1 — Browser-spoofing User-Agent sent to breach/reputation APIs too (Info)

**Evidence (VERIFIED — code behavior):** `osint_core/net.py:56`, inside `Fetcher.get()`, unconditionally does `self.session.headers["User-Agent"] = random.choice(UAS)` before every request — including calls to `haveibeenpwned.com`, `emailrep.io`, `leakcheck.io`, etc. via `osint_core/breach.py`'s adapters, all of which route through the same `Fetcher`. `UAS` (in `osint_core/constants.py`) is a pool of real desktop/mobile browser strings, built to make username-sweep probes look like ordinary visitors to the sites being checked. HIBP's public API documentation has historically asked integrators to identify their application via `User-Agent` rather than impersonate a browser (**UNVERIFIED** — current exact wording not fetched live in this audit), so sending a randomized Chrome/Firefox/Safari string to `haveibeenpwned.com/api/v3/...` is the opposite of that guidance, whatever it currently says.

**Recommended fix:** give `breach.py`'s adapters (and any other calls to sanctioned third-party APIs, as opposed to username-sweep site probing) a fixed, identifying UA, e.g. `OHOsint/{version} (+https://github.com/<org>/<repo>)`, separate from the `UAS` rotation pool used for site probing.

### S1 — Search-engine scraping (flagged per task instructions)

Already detailed in the ToS table above. `osint_core/search.py` scrapes `html.duckduckgo.com/html/`, `lite.duckduckgo.com/lite/`, and `www.bing.com/search` directly — not through any officially licensed search API — and contains logic specifically built to decode Bing's outbound-link wrapping (`_bing_decode`, :20-31), which only has a reason to exist because this is working against a page not designed for programmatic consumption. This is the single most likely ToS-conflict in the project. **UNVERIFIED** for the exact current clause text of either engine's terms; **VERIFIED** for the code behavior (direct HTML scraping of live search-results pages, with retry/fallback and throttle-detection logic — `dork()`'s `"junk"`/`empty`/`None` state handling — that reads as scraper-hardening).

**Recommended fix:** add an explicit README note (see intended-use draft below) that dorking scrapes public search-result pages rather than using a licensed API, that this can be throttled or blocked, and that heavy automated use may not comply with the search engines' terms — so users should keep volume low and treat dork results as a convenience, not a guaranteed data source.

### M1 — No SECURITY.md / CODE_OF_CONDUCT.md / CONTRIBUTING.md / CHANGELOG.md (Medium)

**Evidence (VERIFIED):** `ls -la` at repo root and a case-insensitive grep for these filenames both come back empty; there is no `[tool.*]` license/security metadata in `pyproject.toml` either.

**Recommendation:**
- **SECURITY.md — warranted, should ship at launch.** This tool makes live outbound calls to multiple third-party APIs with real credentials (`.env`), supports a `--insecure` flag that disables TLS verification, and is exactly the kind of security-adjacent tool where a researcher finding a bug (e.g. the OPSEC proxy-bypass class of bug that `AUDIT.md` documented) needs a clear, fast channel to report it responsibly rather than opening a public issue. Draft below.
- **CODE_OF_CONDUCT.md — nice to have, not launch-blocking.** Not urgent for a single-maintainer repo with no contributor community yet, but worth adding a lightweight Contributor Covenant once the repo starts taking outside contributions/issues — especially useful here because the subject matter (breach data, adult-platform lookups) makes it worth setting explicit expectations that discussion stay abstract/technical and not turn into requests to "look someone up."
- **CONTRIBUTING.md — nice to have.** Low effort; even a short "how to run tests, coding conventions live in `docs/AGENTS.md`" pointer helps.
- **CHANGELOG.md — nice to have.** The project is pre-1.0 and moving fast (per D6, most of a full bug-fix pass landed in a day); a changelog would have made this specific audit-vs-code drift immediately visible to future readers.

### M2 — `silent-account-finder` raises a sharper ethical question than the rest of the toolkit (Medium)

**Evidence (VERIFIED):** `skills/silent-account-finder/find_profiles.py` and `deep_dive.py` locate a person's account on **XNXX/XVideos** (confirmed via `PROFILE_SITES = ["xnxx", "xvideos"]`, `ADULT_HOSTS`, and matching dork templates) from just their email address, entirely passively, without their knowledge (`skills/silent-account-finder/SKILL.md:3`: *"Use to locate a person's account/profile on XNXX/XVideos from an email address WITHOUT notifying the target"*). This is qualitatively different from the rest of the toolkit: successfully linking a real person's identity to an adult-content account is precisely the kind of finding that has, in real documented cases (celebrity/public-figure outings, breach-adjacent harassment campaigns), been used for blackmail, harassment, or non-consensual "outing" of someone's sexual activity or orientation — harms disclosure of that data is well known to cause, independent of how the data was obtained. Under GDPR this also lands squarely in **Article 9 "special category" data** ("data concerning a person's sex life or sexual orientation"), which requires a materially higher lawful-use bar than ordinary personal data (Article 6 alone isn't sufficient — see §5 below).

**Recommendation:** keep the tool (it has a legitimate niche — e.g. verifying whether *your own* accounts or a client's, in an authorized engagement, are exposed), but give it visibly stronger, skill-specific framing rather than relying on the generic repo-wide "lawful use only" note: name the specific harm (outing/blackmail), name the specific higher legal bar (special-category data), and consider whether it belongs in the initial public release at all versus a follow-up once the rest of the legal/README work lands. This is a judgment call for the maintainer, not something this audit can resolve — flagging it clearly is the deliverable.

---

## Undocumented surface — summary

**CLI subcommands** (`ohosint/cli.py:79-116`): `email`, `phone`, `username`, `name`, `shell`, `breach`, `sites` — **all 7 are documented** in README.md's Usage section. No gap here.

**Global CLI flags** (`ohosint/cli.py:30-75`, 13 flags total): `--proxy`, `--tor`, `--nsfw`, `--sites` documented with examples; `--format`/`--out` documented; `--in-parallel` documented. **Undocumented:** `--insecure`, `--no-exclusions`, `-v`/`--verbose`, `--timeout`, `--delay-min`, `--delay-max`, `--version` (7 of 13 flags never shown in README — see D10).

**Shell commands** (`ohosint/shell.py`, `do_*` methods): `email`, `phone`, `username`, `breach`, `name`, `sweep`, `dork`, `autopsy`, `pivot`, `proxy`, `newnym`, `delay`, `status`, `save`, `clear`, `exit`/`quit`/`EOF`, `help` — **`insecure` is the only one missing** from README's summary list (see D9); it does appear in the shell's own built-in `help` output.

**Environment variables:** see the complete table above — the four `OHO_*` keys are all documented; the `.env`-file fallback and the ambient `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`/`.netrc` behavior are not documented anywhere.

---

## §4 — Internal working docs: ship-readiness per file

| File | Contains anything embarrassing/stale/sensitive? | Recommendation |
|---|---|---|
| `docs/AUDIT.md` | Yes — reads as a live list of unfixed bugs (crash, TLS-verification bypass, OPSEC proxy leak) when 8 of 9 are already fixed (D6). Publishing it as-is would either (a) look like the project shipped with known holes it didn't disclose fixing, or (b) confuse contributors/users about current behavior. Contains **no** secrets, credentials, or personal data — the content itself is fine, just time-stamped and now inaccurate. | **Rewrite, don't ship as-is.** Add a one-line status banner at the top ("Historical — findings 1,2,3,4,5,7,8,9 fixed as of `PLAN.md`; only 6 partially remains, see `AGENTS.md`") or move it to a `docs/audit/` (or `docs/history/`) folder with a clear "point-in-time snapshot" framing, matching how this very audit is being filed. Either is fine; shipping it unlabeled in the main `docs/` tree next to still-current reference docs (`AGENTS.md`, `BREACH-SEARCH-PLAN.md`) is not. |
| `docs/PLAN.md` | Same issue as AUDIT.md, one layer worse: it's a step-by-step fix plan for bugs that are now fixed, so it's pure historical noise for a first-time public reader with no context. Nothing sensitive in it. | **Move or exclude.** This reads as an implementation-tracking artifact, not reference documentation — either fold its still-relevant content (none, it's all completed) into a CHANGELOG entry, or move it alongside AUDIT.md into a clearly historical location. Lowest priority to keep of the three internal docs. |
| `docs/BREACH-SEARCH-PLAN.md` | No — this one is different in kind: it's accurate, current (matches `breach.py` closely), and genuinely useful as *the* architecture reference for the breach-search feature (source list, rate limits, rejected sources with reasons, report shape). Nothing embarrassing or sensitive; the "Rejected / dead" section (pwndb onion, GhostProject, Scylla, Snusbase/DeHashed/etc.) is useful transparency, not a liability. | **Ship as-is**, but consider renaming/moving it to something like `docs/BREACH-SOURCES.md` or a `docs/architecture/` folder so it reads as permanent reference documentation rather than a dated "plan" (it's already marked "Status: approved 2026-08-24... Implementation tracking in repo," which is a little odd to leave in a public architecture doc once implementation is done — a light copy-edit removing the "plan"/tracking framing would help). |

No personal data, credentials, or genuinely embarrassing content (e.g. real target names, real found accounts, actual scan output) was found in any of the three documents — the risk with `AUDIT.md`/`PLAN.md` is staleness and misrepresentation of current security posture, not leaked sensitive data.

---

## §6 — Missing docs, beyond what's covered above

- **LICENSE** — see L1, critical, covered above.
- **CONTRIBUTING.md** — missing; see M1.
- **CHANGELOG.md** — missing; see M1. Especially valuable here given how fast the code has been diverging from the docs (D6).
- **Architecture overview** — partially covered by README's project-layout tree and `docs/BREACH-SEARCH-PLAN.md`, but there's no single doc explaining *why* two parallel engines exist (`probe.py` sync for `skills/` vs `async_check.py` async for `ohosint`) for a new contributor — `osint_core/probe.py`'s module docstring is the closest thing to this today and it's not linked from anywhere in the docs.
- **Per-source documentation** — `docs/BREACH-SEARCH-PLAN.md` covers the breach sources well (rate limits, endpoints, what's rejected and why); there's no equivalent doc for the username-sweep site-database format (Maigret/Sherlock JSON schema, how `MaigretSite`/`MaigretDatabase` normalize them) or for the search/dork engines' quirks (WAF/throttle detection heuristics).
- **Troubleshooting/FAQ** — README has scattered troubleshooting notes (search-engine throttling → `newnym`, missing site DBs → install hint) but no consolidated FAQ. Common first-run failures worth a dedicated section: "0 sites loaded" error, SOCKS5 proxy `MissingSchema`/`InvalidSchema` errors (already hinted at in `net.py:65-66` but not in docs), Tor not running (`ConnectionRefusedError` hint already exists in code at `net.py:67-68` but isn't mirrored in docs).
- **Tor setup guide** — this exists and is good: `skills/tor-proxy/SKILL.md` is a thorough, verified, no-sudo Tor setup guide, and README links to it. No gap here beyond noting it's filed under `skills/` rather than `docs/`, which is a slightly odd location for a setup guide that applies to the whole project, not just the `skills/` scripts.

---

## Drafted copy-paste blocks

### (a) README "Intended use & legal" section

```markdown
## Intended use & legal

OHOsint is built for **defensive and authorized** work: security research,
checking your own exposure (email/phone/username/breach status), and OSINT
tasks inside an engagement you're authorized to run (a scoped pentest, an
active legal case, a due-diligence check you have a legitimate basis for).
It is not built for, and must not be used for, monitoring, profiling, or
locating a specific person without their consent or a lawful basis to do so.

**What makes this tool passive, specifically:**
- Every request is a `GET` to a public page or a public/keyed third-party
  API — **except** third-party search APIs that require a `POST` to submit
  a query (currently: Intelligence X, when `OHO_INTELX_KEY` is set). Those
  POSTs go to the API provider, never to the target's own infrastructure.
- Nothing here ever contacts a login, account-recovery, "forgot password,"
  or OTP endpoint — those are exactly the actions that would notify the
  person you're investigating, and this tool is designed to never trigger
  them.
- No account creation, no authentication, no reuse of credentials found in
  breach data, ever.

**Search-engine dorking uses page scraping, not a licensed API.** The
`dork`/`sweep` search commands parse DuckDuckGo's and Bing's public
search-results HTML because neither offers a general-purpose free search
API. This can be throttled or blocked by either engine, and heavy automated
use may not comply with their terms of service — keep query volume low,
expect occasional `junk`/`empty` results, and don't rely on this as a
guaranteed data source. Rotating your Tor circuit (`newnym`) helps with
throttling; it does not change the underlying terms.

**Third-party breach/reputation APIs.** All keyless sources (LeakCheck,
Hudson Rock, XposedOrNot, HIBP breach catalogue & Pwned Passwords,
ProxyNova, EmailRep) are public APIs designed for exactly this kind of
lookup. Keyed sources (HIBP account search, Intelligence X, BreachDirectory,
EmailRep's higher tier) require **you** to register your own account and
API key with that provider — get your own key, read that provider's terms,
and stay within their published rate limits. This project does not ship,
proxy, or resell access to any of these services.

**Plaintext credentials.** ProxyNova and BreachDirectory can return real
`email:password` pairs recovered from past breaches. Treat any report
containing them as sensitive: don't commit them to version control, don't
share them outside the authorized scope of your work, and delete them once
you no longer need them. `ohosint_breach_*.json` report files are **not**
currently excluded by this repo's `.gitignore` — double-check before
running `git add` in a directory where you've generated reports.

**Data handling.** This tool writes what it finds to local JSON report
files and does not send anything you collect anywhere except the
third-party APIs being queried. You are the data controller for whatever
you collect with it: collect only what your authorized purpose requires,
don't retain reports longer than that purpose needs, and don't redistribute
breach data (plaintext credentials or otherwise) you didn't already have a
lawful basis to hold. If you are subject to GDPR/CCPA or similar
regimes, running lookups against another identifiable person's data is
processing their personal data and needs its own lawful basis — "I was
curious" is not one. Looking someone up on adult-content platforms
(`skills/silent-account-finder/`) in particular touches GDPR Article 9
"special category" data (sex life / sexual orientation) and needs a
correspondingly higher bar than routine OSINT.

**If you are the target of a lookup and have concerns** about how this
tool might be used against you, see `SECURITY.md` for a contact channel.
```

### (b) `SECURITY.md`

```markdown
# Security Policy

## Scope

OHOsint is a command-line OSINT tool, not a hosted service — most
"security" concerns here are about the tool's own behavior (credential
handling, TLS verification, proxy/anonymity guarantees, dependency
supply chain) rather than a live attack surface. Vulnerabilities in that
sense — anything that makes the tool behave less safely or less
anonymously than documented, leaks a user's own data or API keys, or
executes unintended code — are in scope. Findings about the third-party
services this tool queries (LeakCheck, HIBP, Hudson Rock, etc.) belong to
those providers, not this project, unless the finding is specifically
about how OHOsint calls them.

Examples of what belongs here (based on real historical findings):
- A code path that silently bypasses the configured proxy/Tor routing
  (an anonymity leak).
- TLS/certificate verification being skipped when it shouldn't be.
- API keys, `.env` contents, or breach-report data being written,
  logged, or transmitted somewhere they shouldn't be.
- A dependency with a known CVE that affects this project's usage of it.
- Anything that lets a malicious site/API response cause code execution,
  path traversal, or similar in this tool.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

Instead, email **[SECURITY_CONTACT_EMAIL]** with:
- A description of the issue and its impact.
- Steps to reproduce (a minimal repro is very helpful).
- The version/commit you tested against.

You should get an acknowledgment within **5 business days**. We'll aim to
confirm the issue, give you an expected timeline, and credit you in the
fix (unless you'd prefer to stay anonymous) once it ships. Please give us
a reasonable window to ship a fix before any public disclosure.

## Supported versions

This project is pre-1.0 (`0.1.x`) and does not yet maintain multiple
release branches. Security fixes land on `main`; please always test
against the latest commit before reporting.

## A note on responsible use of this tool itself

If your concern is about how OHOsint *could be used* against a person
(rather than a bug in the tool), see the "Intended use & legal" section
of the README. That's a product/policy question, not a vulnerability
report, but we still want to hear about it — email the same address
above.
```

### (c) Recommended README structure outline

```markdown
# OHOsint — passive OSINT toolkit
[one-line description]
[badges: license, Python version, build/test status if CI is added, PyPI if published]

## What this is (2-3 sentences + "lawful use only" callout, kept from current README)

## Features (keep current bullet list; tighten "GET only" language per D1)

## Quickstart
  - shortest possible path from clone to one real command running
  - show ACTUAL sample output (table + JSON) for at least one command

## Installation
  - Requirements (Python 3.10+, OS notes if any)
  - pip install -r requirements.txt / pip install -e .
  - Site databases (maigret/sherlock) — mention `pip install -e .[sweep]` explicitly, not just raw `pip install maigret`
  - Optional: breach API keys (env-var table, not just export lines — see below)
  - Optional: Tor setup (keep link to skills/tor-proxy/SKILL.md, or move that guide under docs/)

## Configuration reference
  | Flag | Default | Description |
  (all 13 global flags, not just the 6 currently shown)
  | Env var | Required? | Purpose |
  (4 OHO_* vars + note on .env fallback + note on ambient HTTP_PROXY/NO_PROXY)

## Usage
  ### ohosint CLI — one example block per subcommand, with sample output
  ### ohosint shell — full command list (including `insecure`)
  ### skills/ scripts — keep current examples

## Reading verdicts
  (split into two tables: ohosint's ScanStatus vocabulary vs. skills/'s probe.py vocabulary — see D4)

## Reports — what gets written, where, and the current gitignore gap (fix before merging this section)

## Intended use & legal
  (full block drafted above)

## Project layout (keep, but fix D7/D8: correct AGENTS.md link, add PLAN.md or remove per §4 recommendation)

## Development status
  (keep; consider adding a CHANGELOG link once one exists)

## Troubleshooting / FAQ (new)
  - "0 sites loaded" → install maigret/sherlock
  - SOCKS5 proxy MissingSchema/InvalidSchema → pip install 'requests[socks]'
  - Connection refused over Tor → is tor running?
  - All dork engines returning junk/empty/None → rotate circuit (newnym) or wait

## Contributing (new, can be one line pointing to docs/AGENTS.md + CONTRIBUTING.md)

## License (new — pick one, see L1)
```

---

## Summary of what I verified vs. could not verify

**VERIFIED** (reproduced against live code, real filesystem state, or exact grep evidence): L1, L2, L3, D1–D12, E1 (code behavior only), M1, M2 (behavior/content, not the ethical judgment call itself, which is inherently subjective).

**UNVERIFIED** (assessed from general knowledge of the platform, not fetched live in this audit — flagged explicitly wherever used): every specific ToS-conflict conclusion in the per-data-source table, including the DuckDuckGo/Bing scraping risk (S1) and the HIBP User-Agent guidance referenced in E1. These should be spot-checked against each provider's actual current terms before the README makes any firm claims about them (the drafted "Intended use & legal" section above is deliberately worded as risk disclosure — "may not comply," "can be throttled" — rather than asserting a definitive ToS verdict, precisely because I could not verify the exact current clauses.
