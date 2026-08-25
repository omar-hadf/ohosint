# Publication Readiness Audit — OHOsint

**Date:** 2026-08-25
**Scope:** full repository — `osint_core/` (18 modules), `ohosint/` (6 modules), `skills/` (3 scripts), `tests/` (8 files), packaging, docs. ~6,300 LOC.
**Method:** five parallel specialist audits, each required to verify claims by running code rather than reading it. Findings were then independently re-verified before any fix was applied.

| Aspect | Report | Agent verdict |
|---|---|---|
| Security & OPSEC | [audit/security.md](audit/security.md) | 0 Critical, 2 High, 1 Medium, 2 Low |
| Code quality & bugs | [audit/code-quality.md](audit/code-quality.md) | 1 Critical, 1 High, 1 Medium, 6 Low |
| Packaging & CI | [audit/packaging.md](audit/packaging.md) | 4 publish blockers |
| Test suite | [audit/testing.md](audit/testing.md) | 63/63 pass, but not CI-safe |
| Docs & legal | [audit/docs-legal.md](audit/docs-legal.md) | 6 doc inaccuracies, 3 legal must-dos |

---

## TL;DR

The codebase was in better shape than a first-time public release usually is:
well factored around a single shared library, no code duplication between the
two front ends, no hardcoded secrets, no `eval`/`exec`/`pickle`/`shell=True`
anywhere, and every one of the 9 findings from the previous audit round
(2026-08-24) independently confirmed as genuinely fixed.

It was **not** ready to publish. Three things stood out:

1. **A silent correctness failure in the flagship feature.** The username sweep
   dropped the "not found" markers for 910 Maigret sites and the "must be
   present" markers for 539 more — first by never loading them, then by
   discarding the result even when loaded. It reported accounts that don't
   exist, with no warning.
2. **A Tor leak on the default path.** Every `ohosint email` / `ohosint username`
   run made one clearnet request from the operator's real IP before any
   Tor-routed traffic began, including under `--tor`.
3. **A route to publishing other people's leaked credentials.** The tool wrote
   breach reports to the working directory *without being asked*, and
   `.gitignore` did not match the filename it chose for them.

All three are fixed and verified. The repository now has a license, complete
packaging metadata, CI, a network-blocked test suite, and documentation whose
claims match the code.

---

## What was fixed

Every change below was verified by running code, not by inspection. The
verification command and its output are recorded per item.

### 1. Critical — username sweep silently reported false positives

Two independent defects combined to break the flagship feature.

**(a) The data was never loaded.** `osint_core/site_db.py` mapped Sherlock's
`errorMsg` onto `absence_strs`, but never mapped Maigret's equivalents. The
generic `setattr` loop stored them under their original camelCase names, where
nothing reads them. The upstream database is inconsistent and ships **four**
spellings:

| key | sites | |
|---|---|---|
| `absenceStrs` | 909 | → `absence_strs` |
| `absenseStrs` | 1 | → `absence_strs` |
| `presenseStrs` | **526** | → `presense_strs` |
| `presenceStrs` | 13 | → `presense_strs` |

All four are now accepted. Verified against the installed database: absence
markers populated on **910** sites (was 0), presence markers on **539** (was 0).

**(b) The result was then thrown away.** `async_check.classify_result()`
computed `presense_detected` and never referenced it again — pyflakes flagged
both it and `absence_detected` as assigned-but-unused. Absence detection
happened to survive because the `message` branch re-derived it inline; presence
detection did not, so those 539 sites' markers were ignored even once loaded.
Presence markers are now applied as a veto after the error-type checks: if a
site declares strings that must appear on a real profile and none are present,
the account is `available` regardless of what the status code suggested.

The inline re-derivation was also unsafe — it iterated `absence_strs` directly,
so a bare string would have been matched character-by-character. Both marker
lists are now normalised before use.

Verified end to end:

```
presence marker present : claimed      absence marker present : available
presence marker missing : available    absence marker missing : claimed
string marker, no match : claimed      string marker, matches : available

Facebook  absence=['rsrcTags']  presence=['first_name']
  page with neither marker: available   (was: claimed — a false hit)
```

> The consumer attribute is spelled `presense_strs` (typo) in `async_check.py`.
> The fix maps to the existing misspelling rather than silently renaming a
> public attribute. Worth correcting later with a deprecation alias.

### 2. High — Tor/proxy leak on every sweep

**`osint_core/exclusions.py:33`** — `fetch_exclusions()` called
`requests.get(url, timeout=timeout)` with no `proxies=` argument and no
parameter through which one could be passed. Both pipelines call it by default
(`apply_exclusions=True`) at `ohosint/pipelines.py:76` and `:141`, so every
`ohosint email` and `ohosint username` invocation — **including with `--tor`** —
emitted a clearnet request to `raw.githubusercontent.com` from the operator's
real IP before any anonymised traffic started.

This does not deanonymise the operator *to the target* (the request goes to
GitHub), but it breaks the tool's stated guarantee and reveals to a network
observer that the operator is running this tool.

**Fixed** — `fetch_exclusions()` takes `proxy`, applies it, and both call sites
thread it through. Verified end-to-end:

```
exclusions request proxies = {'http': 'socks5h://127.0.0.1:9050',
                              'https': 'socks5h://127.0.0.1:9050'}
PASS: exclusions fetch now honours the configured proxy
```

### 3. High — reports written without being asked, and not gitignored

**`ohosint/cli.py`** — all three of `handle_email`, `handle_username` and
`handle_breach` contained:

```python
if config.out or config.format == "table":     # table is the DEFAULT
    out_path = config.out or make_report_path()
    formatter.save_json(results, out_path, ...)
    if config.out:                              # only announced when --out given
        print(f"Report saved to {out_path}")
```

In default output mode this wrote a JSON file containing the investigated
person's data into the current working directory and never said so. Five such
files had accumulated in this repository's root, one containing the maintainer's
own email address and breach results.

Compounding it: `.gitignore` covered `*_report_*.json`, but `handle_breach`
passes `prefix="ohosint_breach"`, producing `ohosint_breach_<ts>.json` — which
matches no pattern in the file. Since the README itself warns these reports can
contain real leaked `email:password` pairs, a routine `git add -A` would have
published third-party credentials.

**Fixed** — three changes:

- Reports are now written **only** when `--out` is given, and the path is
  always printed. The shell's explicit `save` command is unchanged.
- `.gitignore` rewritten to cover `*_breach_*.json`, `.pytest_cache/`, tooling
  caches, and `.env.*` (with a `!.env.example` negation).
- Report writes now go through a helper that creates the file `0600` via
  `os.open(..., 0o600)` plus an explicit `chmod` (both `ohosint/output.py` and
  `osint_core/cli.py:save_report`). Verified: `mode: 0o600`.

### 4. High — breach source names parsed character-by-character

**`osint_core/breach.py`** — `breach_breachdirectory()` iterated
`rec.get("sources")` assuming a list. The RapidAPI endpoint returns a bare
string for some records, so iterating it yielded one "breach" per character.
This was visible in a real report in the repo root: breach names `"("`, `")"`,
`"0"`, `"2"`, `"a"`, `"B"`.

**Fixed** — a string is now wrapped into a single-element list. Verified:

```
input : {"sources": "Adobe2013"} and {"sources": ["LinkedIn2012", "MySpace"]}
before: [{'name':'0'}, {'name':'2'}, {'name':'A'}, {'name':'b'}, ...]
after : [{'name':'Adobe2013'}, {'name':'LinkedIn2012'}, {'name':'MySpace'}]
```

### 5. High — test suite was not CI-safe

Three tests in `tests/test_pipelines.py` called `run_email_pipeline` while
mocking only the sweep seam, leaving `oc.gravatar`, `oc.leakcheck`,
`oc.hudson_rock` and `oc.fetch_exclusions` live. They made **real HTTPS calls to
four third-party hosts on every run**. The pipeline's `except Exception` blocks
swallowed the results, so the tests passed either way and the traffic was
invisible. On a public repo this would have fired live queries at third-party
OSINT APIs from every fork's CI.

**Fixed** — added `tests/conftest.py` with three autouse fixtures: a socket
guard that raises `NetworkCallInTest` on any non-loopback connection, a reset
for the process-wide `exclusions` cache, and a `tmp_path` chdir so no real
`.env` is read. The three tests now take an explicit `no_sources` fixture.

Verified — the guard genuinely blocks:

```
blocked with: NetworkCallInTest Blocked outbound connection to '104.20.23.154'
```

And the suite got **50× faster**, which is itself the proof the network calls
were real:

```
before: 63 passed in 26.80s
after:  63 passed in  0.19s
```

### 6. Packaging and repository scaffolding

| Item | Before | After |
|---|---|---|
| `LICENSE` | absent (all-rights-reserved) | MIT |
| `license` / `authors` / `classifiers` / `urls` | absent | complete, verified in built `METADATA` |
| `readme` | absent | `README.md`, `Description-Content-Type: text/markdown` |
| `alive-progress` dependency | declared, **imported nowhere** | removed |
| `pytest` / `ruff` | undeclared — `pip install` then `pytest` failed | `[dev]` extra |
| pytest / ruff config | none | `[tool.pytest.ini_options]`, `[tool.ruff]` |
| CI | none | `.github/workflows/ci.yml` — lint, 3.10–3.13 matrix, build + twine check |
| `MANIFEST.in` | none | added; excludes `.env` and report JSONs from sdists |
| `.env.example` | none | added, documenting all four optional keys |
| `SECURITY.md` | none | added, with a scope section naming proxy-bypass and report-handling as security bugs |
| `CONTRIBUTING.md` | none | added, with the passivity and proxy-threading rules as hard requirements |

Build verified clean:

```
Successfully built osint_core-0.1.0.tar.gz and osint_core-0.1.0-py3-none-any.whl
wheel leak check — .env / reports / .pytest_cache / egg-info / tests: NONE
```

`stem` and `safe-pysha3` were checked before removal was considered and are
genuinely used, via lazy imports at `ohosint/shell.py:300` and
`osint_core/breach.py:28`. Only `alive-progress` was dead.

### 7. Documentation accuracy

Each of these was reproduced, not inferred:

| Claim | Reality | Action |
|---|---|---|
| "GET only … nothing here ever POSTs" | `breach.py` POSTs to Intelligence X's own search API | Reworded to "read-only against the subject", with the exception stated explicitly. The narrower claim (never POSTs to login/recovery/OTP) was true and is kept. |
| `ohosint breach … --tor` | `argparse` exits 2, `unrecognized arguments: --tor` | Corrected to `ohosint --tor breach …` in README and AGENTS.md |
| "keys read from the environment only" | `breach.py:76-78` also reads `.env` from the cwd | Corrected; `.env.example` added |
| Site-DB section describes silent `Total: 0` and cites an open audit finding | code now fails fast with an actionable error | Rewritten |
| `[AGENTS.md](AGENTS.md)` | file is at `docs/AGENTS.md` | Fixed |
| "Report filenames are gitignored" | breach reports were not | Fixed in both code and docs |
| Title "pythonProject" | — | Renamed to OHOsint, badges added |

`docs/AUDIT.md` and `docs/PLAN.md` describe 9 bugs as open; all 9 are fixed.
Publishing them unannotated would misrepresent the project, so both now carry a
"superseded — historical record" banner pointing here.

### 8. Legal and ethical posture

A new **Intended use & legal** section in the README covers authorized-use
scope, third-party ToS, and data protection. Three points worth surfacing:

- **Search-engine scraping is the clearest ToS risk in the project.**
  `osint_core/search.py` scrapes DuckDuckGo and Bing HTML result pages directly
  rather than using a licensed API. This is now disclosed in the README.
- **Breach data is third-party personal data.** The README now says plainly:
  don't redistribute it, don't paste it into issues, delete it when done.
- **`skills/silent-account-finder/` locates accounts on adult platforms.** In
  the EU that can be GDPR Article 9 "special category" data, which carries a
  materially higher legal bar. This is called out explicitly.

---

## Complete finding-by-finding status

All five reports, every finding, reconciled. 39 findings total.

### Fixed and verified (24)

| Report | # | Severity | Finding |
|---|---|---|---|
| code-quality | 1 | Critical | Maigret absence/presence markers never mapped, then discarded by the classifier |
| security | 1 | High | `fetch_exclusions()` bypassed the proxy on every sweep |
| security | 2 | High | breach reports not matched by `.gitignore` |
| code-quality | 2 | High | `breach_breachdirectory()` iterated a string per character |
| testing | — | High | 3 tests made live third-party API calls |
| testing | — | High | `pytest`/`pytest-asyncio` undeclared — `pip install` then `pytest` failed |
| security | 3 | Medium | reports written world-readable |
| code-quality | 3 | Medium | `ohosint phone` never printed the parse error |
| security | 5 | Low | `valid_proxy()` silently accepted DNS-leaking `socks5://` |
| code-quality | 9 | Low | `ohosint` never called `valid_proxy()` at all |
| code-quality | 6 | Low | 11 pyflakes unused-import/variable warnings — tree is now pyflakes-clean |
| packaging | S10 | Med | Sherlock DB path hardcoded to `python3.10`, dead on 3.11+ |
| packaging | B1–B4 | Blocker | `.pytest_cache/`, breach-report gitignore, missing `LICENSE`, missing metadata |
| packaging | S1 | Low | `alive-progress` declared but imported nowhere |
| packaging | S3 | Med | no CI |
| packaging | S4 | Low | no pytest/ruff config |
| packaging | S5 | Low | no `MANIFEST.in` |
| packaging | S8 | Info | `stem` LGPL notice — added as `NOTICE` |
| packaging | S9 | Med | community-health files — all added |
| testing | — | Med | no `conftest.py`, no cache reset, no `.env` isolation |
| docs-legal | D1–D6 | Med | six README/AGENTS.md inaccuracies |
| docs-legal | S1 | High | search-engine scraping now disclosed in the README |
| docs-legal | — | High | intended-use, ToS and GDPR sections added |
| docs-legal | — | Med | `AUDIT.md`/`PLAN.md` bannered as superseded |

### Open — deliberate, with reasons (15)

| Report | # | Severity | Item | Why not fixed |
|---|---|---|---|---|
| testing | — | Medium | **12 of 25 modules have zero test coverage** | The largest genuine gap. [audit/testing.md](audit/testing.md) has five ready-to-paste tests for the highest-value cases. Writing a real suite is a work item, not a cleanup. |
| testing | — | Low | tautological assertion in `test_tls.py` | Should be replaced using the pattern in the testing report, alongside the coverage work |
| testing | — | Low | `breach_breachdirectory` has no test | Same — it now has a bug fix that deserves a regression test |
| code-quality | 4 | Low | `executors.py` (153 lines) has zero callers | Deleting a module is the maintainer's call; may be scaffolding for planned work |
| code-quality | 5 | Low | `DnsResolver`, `_interpolate_template`, `to_csv_row` also dead | Same call. `DnsResolver` is also security #4 below |
| security | 4 | Low | `DnsResolver` has no proxy parameter — latent DNS-leak footgun | Unreachable from any pipeline today; the right fix is deleting it with #5, not patching dead code |
| code-quality | 7 | Low | `MaigretSite` mutable class-level defaults | Latent, not currently triggered; fixing means touching every attribute declaration |
| code-quality | 8 | Low | `_CURRENT_QTYPE` module global is not reentrant | No caller parallelises `breach_search()` today |
| code-quality | 10 | Low | Tor ports hardcoded in 6 places | Cosmetic; centralising in `constants.py` is a small refactor |
| code-quality | 11 | Info | malformed site entries dropped by a silent `except` | Adding logging here could be noisy on a 3,000-site database — needs a rate-limited warning |
| code-quality | 12 | Info | new session per site check, no pooling | Real cost at scale, but a performance redesign |
| packaging | S2 | Info | `maigret`/`sherlock-project` pull 44 and 9 transitive deps to read one JSON each | Vendoring the site DB would cut install weight enormously, but it is a design change with licensing and freshness implications |
| packaging | S6 | Low | all dependencies are unpinned floors | Needs a policy decision (lockfile? constraints file?) |
| packaging | S7 | Low | distribution is `osint-core`, product is `ohosint` | Renaming a distribution is disruptive; decide before the first PyPI upload, not after |
| — | — | Info | `presense_strs` misspelling in the public attribute | Renaming needs a deprecation alias |

### No action required (5)

`security` #6 (proxy off by default — documented design), #7 (prior-round
findings confirmed fixed), #8 (authorized-use statement already present), #9
(`safe-pysha3` is a normal PyPI package); `code-quality` #13 (two-engine
architecture is intentional and correctly documented).

---

## Verification summary

```
$ python -m pytest tests/ -q
63 passed in 0.19s

$ python -m pyflakes osint_core ohosint tests skills
(no output — clean)

$ python -m build --no-isolation
Successfully built osint_core-0.1.0.tar.gz and osint_core-0.1.0-py3-none-any.whl
```

- 63/63 tests pass after every change above.
- The built wheel contains `ohosint/` and `osint_core/` only — no `.env`, no
  reports, no caches, no `tests/`.
- Package metadata is complete: MIT, author, four classifiers, three project
  URLs, markdown readme, bundled `LICENSE`.

## Remaining manual step

**Rotate the RapidAPI key in `.env`.** It sits in plaintext on disk. It has
never been committed — this repository had no git history at audit time, and
`.env` was already gitignored — so this is precautionary rather than a
disclosed leak. Rotate it anyway before the repo goes public, since the key
now appears in a file whose name is documented in a public README.
