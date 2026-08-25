# Test Suite Health & Coverage Audit — OHOsint / osint_core

Scope: test suite health and coverage only. Security review, packaging metadata, and docs prose are covered by separate audits.

## Verdict

The 63 tests that exist all pass, and the parts of the suite that *are* mocked (`tests/test_breach.py` in particular) are well-built — realistic fake responses, edge cases like 429/404, cache behavior, and secret-redaction all get real assertions. But the suite is **not CI-safe as published**: three tests in `tests/test_pipelines.py` make real, unmocked outbound HTTPS requests to four live third-party services (gravatar.com, leakcheck.io, cavalier.hudsonrock.com, raw.githubusercontent.com) every time they run, `pytest`/`pytest-asyncio` are not declared as project dependencies anywhere, there is no `conftest.py`, no network markers, and no CI workflow file at all. Coverage is lopsided: the breach-lookup layer is thoroughly tested, but roughly half the source tree by line count — `pivots.py`, `confidence.py`, `patterns.py`, `executors.py`, `impersonate.py`, `probe.py`, `search.py`, most of `async_check.py`'s actual checking logic, and the entire `ohosint/output.py` and `ohosint/cli.py` — has zero direct tests. Ship-blocking items: unmock the three leaky tests (or add a network-blocking `conftest.py`) before this goes on a public CI runner, since a runner with restricted egress will hang/timeout and a runner with open egress will silently send live traffic (and eventually flaky failures) from every contributor's fork.

## Real pytest run (verbatim)

Environment: Python 3.10.12, pytest 9.1.1, pytest-asyncio 1.4.0. Run from repo root, no flags beyond `-v`. All optional deps (`maigret`, `sherlock_project`, `aiodns`, `curl_cffi`, etc.) happened to be present in this environment already — see Finding T-06 for why that's not something CI can assume.

```
$ python -m pytest tests/ -v
============================= test session starts ==============================
platform linux -- Python 3.10.12, pytest-9.1.1, pluggy-1.6.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /home/omar/Documents/pythonProject
configfile: pyproject.toml
plugins: asyncio-1.4.0, anyio-4.11.0, langsmith-0.4.31
asyncio: mode=strict, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collecting ... collected 63 items

tests/test_autopsy.py::TestDoAutopsy::test_autopsy_uses_fetcher_not_bare_requests PASSED [  1%]
tests/test_autopsy.py::TestDoAutopsy::test_autopsy_rejects_non_http_url PASSED [  3%]
tests/test_autopsy.py::TestDoAutopsy::test_autopsy_unreachable PASSED    [  4%]
tests/test_breach.py::TestDetectQtype::test_email PASSED                 [  6%]
tests/test_breach.py::TestDetectQtype::test_domain PASSED                [  7%]
tests/test_breach.py::TestDetectQtype::test_username PASSED              [  9%]
tests/test_breach.py::TestLeakCheck::test_found PASSED                   [ 11%]
tests/test_breach.py::TestLeakCheck::test_not_found PASSED               [ 12%]
tests/test_breach.py::TestLeakCheck::test_unavailable PASSED             [ 14%]
tests/test_breach.py::TestLeakCheck::test_throttled PASSED               [ 15%]
tests/test_breach.py::TestXposedOrNot::test_found_nested_breaches PASSED [ 17%]
tests/test_breach.py::TestXposedOrNot::test_not_found_404 PASSED         [ 19%]
tests/test_breach.py::TestXposedOrNot::test_not_found_error_body PASSED  [ 20%]
tests/test_breach.py::TestProxyNova::test_parses_lines PASSED            [ 22%]
tests/test_breach.py::TestProxyNova::test_throttled PASSED               [ 23%]
tests/test_breach.py::TestPwnedPasswords::test_pwned PASSED              [ 25%]
tests/test_breach.py::TestPwnedPasswords::test_clean PASSED              [ 26%]
tests/test_breach.py::TestHudsonRock::test_email_found PASSED            [ 28%]
tests/test_breach.py::TestHudsonRock::test_not_associated PASSED         [ 30%]
tests/test_breach.py::TestHIBPCatalogue::test_enrichment_cache PASSED    [ 31%]
tests/test_breach.py::TestEmailRep::test_keyless PASSED                  [ 33%]
tests/test_breach.py::TestEmailRep::test_with_key_header PASSED          [ 34%]
tests/test_breach.py::TestKeyHandling::test_get_api_keys PASSED          [ 36%]
tests/test_breach.py::TestKeyHandling::test_hibp_account_skipped_without_key PASSED [ 38%]
tests/test_breach.py::TestKeyHandling::test_env_key_activates_hibp PASSED [ 39%]
tests/test_breach.py::TestKeyHandling::test_keys_not_in_report PASSED    [ 41%]
tests/test_breach.py::TestOrchestrator::test_merges_breach_names PASSED  [ 42%]
tests/test_breach.py::TestOrchestrator::test_password_query_sha1_in_report_not_plaintext PASSED [ 44%]
tests/test_breach.py::TestOrchestrator::test_sources_whitelist PASSED    [ 46%]
tests/test_breach.py::TestOrchestrator::test_throttle_flag PASSED        [ 47%]
tests/test_breach.py::TestXONPassword::test_pwned PASSED                 [ 49%]
tests/test_breach.py::TestXONPassword::test_clean_404 PASSED             [ 50%]
tests/test_breach.py::TestIntelXAdapter::test_basic_flow PASSED          [ 52%]
tests/test_breach.py::TestIntelXAdapter::test_key_rejected PASSED        [ 53%]
tests/test_candidates.py::TestGenerateCandidates::test_basic_permutations PASSED [ 55%]
tests/test_candidates.py::TestGenerateCandidates::test_no_leading_trailing_separators PASSED [ 57%]
tests/test_candidates.py::TestGenerateCandidates::test_no_regex_patterns_in_candidates PASSED [ 58%]
tests/test_candidates.py::TestGenerateCandidates::test_capped_at_24 PASSED [ 60%]
tests/test_candidates.py::TestSimpleCandidates::test_basic PASSED        [ 61%]
tests/test_candidates.py::TestSimpleCandidates::test_no_last_name PASSED [ 63%]
tests/test_dork.py::TestDoDork::test_dork_calls_with_fetcher_and_query PASSED [ 65%]
tests/test_dork.py::TestDoDork::test_dork_empty_query_shows_usage PASSED [ 66%]
tests/test_dork.py::TestDoDork::test_dork_unpacks_three_values PASSED    [ 68%]
tests/test_fetcher_cache.py::TestFetcherInvalidation::test_initial_fetcher_has_no_proxy PASSED [ 69%]
tests/test_fetcher_cache.py::TestFetcherInvalidation::test_proxy_change_invalidates_fetcher PASSED [ 71%]
tests/test_fetcher_cache.py::TestFetcherInvalidation::test_proxy_clear_invalidates_fetcher PASSED [ 73%]
tests/test_fetcher_cache.py::TestFetcherInvalidation::test_delay_change_invalidates_fetcher PASSED [ 74%]
tests/test_pipelines.py::TestVerifySSLThreading::test_username_pipeline_passes_verify_ssl_false PASSED [ 76%]
tests/test_pipelines.py::TestVerifySSLThreading::test_username_pipeline_default_verifies PASSED [ 77%]
tests/test_pipelines.py::TestVerifySSLThreading::test_email_pipeline_passes_verify_ssl_false PASSED [ 79%]
tests/test_pipelines.py::TestVerifySSLThreading::test_email_pipeline_applies_exclusions_once PASSED [ 80%]
tests/test_pipelines.py::TestVerifySSLThreading::test_email_pipeline_runs_candidates_concurrently PASSED [ 82%]
tests/test_pipelines.py::TestEmailPipelineSourceFix::test_email_pipeline_passes_fetcher_to_sources PASSED [ 84%]
tests/test_pipelines.py::TestEmailPipelineSourceFix::test_breach_pipeline_passes_proxy_and_delay PASSED [ 85%]
tests/test_site_db.py::TestEmptySiteDB::test_raises_when_no_databases_installed PASSED [ 87%]
tests/test_site_db.py::TestEmptySiteDB::test_raises_for_maigret_only_when_missing PASSED [ 88%]
tests/test_site_db.py::TestEmptySiteDB::test_shell_load_sites_returns_empty_dict PASSED [ 90%]
tests/test_site_db.py::TestEmptySiteDB::test_shell_email_aborts_on_empty_sites PASSED [ 92%]
tests/test_tls.py::TestAiohttpCheckerSSL::test_default_verifies_ssl PASSED [ 93%]
tests/test_tls.py::TestAiohttpCheckerSSL::test_can_disable_ssl PASSED    [ 95%]
tests/test_tls.py::TestAiohttpCheckerSSL::test_ssl_ctx_none_when_verifying PASSED [ 96%]
tests/test_tls.py::TestAiohttpCheckerSSL::test_pick_checker_passes_verify_ssl PASSED [ 98%]
tests/test_tls.py::TestAiohttpCheckerSSL::test_pick_checker_default_verifies PASSED [100%]

============================= 63 passed in 43.33s ==============================
```

**63/63 passed, 0 failed, 0 errors, 0 skipped.** No collection errors, no missing-dependency errors — every optional package (`maigret`, `sherlock_project`, `aiodns`, `curl_cffi`, `aiohttp_socks`, `stem`, `sha3`/`safe-pysha3`) happened to already be installed in this environment.

`.pytest_cache/v/cache/lastfailed` contains `{}` — an empty dict, meaning the last recorded run had zero failures. It carries no diagnostic information beyond that.

43.33s is unusually long for 63 mocked unit tests. `--durations=20` isolates the cause:

```
8.96s call     tests/test_pipelines.py::TestVerifySSLThreading::test_email_pipeline_runs_candidates_concurrently
8.29s call     tests/test_pipelines.py::TestVerifySSLThreading::test_email_pipeline_applies_exclusions_once
8.24s call     tests/test_pipelines.py::TestVerifySSLThreading::test_email_pipeline_passes_verify_ssl_false
0.20s call     tests/test_pipelines.py::TestVerifySSLThreading::test_username_pipeline_passes_verify_ssl_false
(16 durations < 0.005s hidden.)
```

Three tests each take ~8-9 seconds; everything else in the 63-test suite is sub-5ms. This is diagnosed in Finding T-01 below: those three tests are making real network calls.

## Per-module coverage table

Coverage was mapped manually (no `pytest-cov`/`coverage` package is installed, and per audit rules it was not installed) by cross-referencing every `import`/`patch(...)` target in `tests/*.py` against every function and class each source module exports. "Direct" means the module's own code executes during the test (mocks are one layer below it); "Indirect only" means the module is only ever replaced with a mock/patch, so its real implementation never runs under test.

### `osint_core/`

| Module | LOC | Test file(s) | Coverage |
|---|---:|---|---|
| `breach.py` | 781 | `test_breach.py` (32 tests) | **Good** — every keyless adapter, key handling, orchestrator merge logic, password sha1 hashing, throttle flags. `breach_hibp_account` and `breach_intelx` are exercised only via `patch(...)`, never their real bodies; `breach_breachdirectory` has **zero** references anywhere in `tests/`. |
| `candidates.py` | 94 | `test_candidates.py` | **Good** for `generate_candidates`/`simple_candidates`. `parse_local`, `second_wave_candidates`, `split_email` — zero direct tests (only exercised implicitly and unasserted inside pipeline tests). |
| `net.py` | 69 | `test_fetcher_cache.py` (indirect) | **Partial** — only `Fetcher().session.proxies` is inspected via the shell's cache wrapper. `Fetcher.get()`, `polite()` (the real `time.sleep` call), `valid_proxy()`, `build_session()`'s UA rotation: zero direct tests. |
| `async_check.py` | 481 | `test_tls.py` (5 tests) | **Partial** — only `AiohttpChecker.__init__` and `_pick_checker`'s `verify_ssl` forwarding. `check_site`, `check_username_on_sites`, `check_username_sync`, `classify_result` (the ~90-line Sherlock-style WAF/status/regex classification engine), `detect_waf`, `CurlCffiChecker`, `DnsResolver`, `_detect_error`, `_interpolate_template` — **zero** tests. |
| `sources.py` | 82 | none directly | **Zero as unit tests** — `gravatar`/`leakcheck`/`hudson_rock` only ever run for real over the live network inside the leaky pipeline tests (Finding T-01); there is no test that mocks a `Fetcher` and asserts on `sources.py`'s own parsing logic. `wayback_cdx` — zero coverage of any kind. |
| `site_db.py` | 298 | `test_site_db.py` (4 tests) | **Partial** — only the "0 sites loaded" error path via `patch.object(oc, "load_default_db", return_value=None)`. `MaigretSite`, `MaigretEngine`, `MaigretDatabase`, `_load_sherlock`, `get_enabled_sites`, real JSON parsing — **zero** tests. |
| `exclusions.py` | 85 | indirect only | **Zero direct** — `fetch_exclusions`/`filter_excluded_sites` are only ever `patch()`-ed away in pipeline tests; the actual filtering logic and the real network fetch are untested (and the real fetch is what leaks in Finding T-01). |
| `impersonate.py` | 118 | none | **Zero.** No test of `impersonate_request`, `impersonate_validate`, session warm-up/locking, or `is_available()`, despite this being the TLS-fingerprint bypass path used for WAF-protected sites. |
| `pivots.py` | 346 | none | **Zero.** `extract_pivots`, `select_pivots`, `extract_email_pivots`, `rank_usernames`, `resolve_url`, `_clean_handle`, `_clean_email` — the whole pivot/handle-extraction engine — untested. |
| `confidence.py` | 260 | none | **Zero.** `score`, `rank_emails`, `build_anchors`, and all `_rate_email`/`_echoes_anchor` heuristics — untested. |
| `patterns.py` | 225 | none | **Zero.** `expand_patterns`, `expand_wildcard`, the mini pattern-lexer — untested (only referenced by name in an unrelated docstring). |
| `probe.py` | 65 | none | **Zero.** Legacy sync probing engine — untested. |
| `executors.py` | 152 | none | **Zero.** `AsyncQueueExecutor`, `AsyncGeneratorExecutor`, `run_checks_parallel` — untested. |
| `harvest.py` | 29 | none | **Zero.** `at_handles`, `cross_links`, `page_emails` — untested. |
| `search.py` | 96 | indirect only | **Zero direct** — `test_dork.py` patches `osint_core.dork` itself away entirely; `search_bing`/`search_ddg`/real `dork()` logic never runs. |
| `scan_result.py` | 178 | none | **Zero direct** — `ScanResult`/`ScanStatus` factory methods and `to_dict`/`to_csv_row`/`update` are exercised transitively inside `async_check.py` production code but no test imports or asserts on them directly. |
| `cli.py` | 29 | none | **Zero.** `add_common_args`, `fetcher_from_args`, `save_report` — untested. |
| `constants.py` | 61 | none | **Zero**, but this is static data (UA list, marker strings) — low risk. |

### `ohosint/`

| Module | LOC | Test file(s) | Coverage |
|---|---:|---|---|
| `pipelines.py` | 297 | `test_pipelines.py`, `test_site_db.py` | **Good but network-leaky** (Finding T-01) — `run_username_pipeline`, `run_email_pipeline`, `run_breach_pipeline`, `load_site_databases` are tested. `run_phone_pipeline`, `run_name_pipeline`, `extract_pivots_from_results` — **zero** tests. |
| `shell.py` | 389 | `test_autopsy.py`, `test_dork.py`, `test_fetcher_cache.py`, `test_site_db.py` | **Partial** — `do_autopsy`, `do_dork`, proxy/delay cache invalidation, and `do_email`'s empty-sites abort path are covered. `do_phone`, `do_username`, `do_breach`, `do_name`, `do_sweep`, `do_pivot`, `do_insecure`, `do_newnym`, `do_status`, `do_save`, `do_clear`, `do_exit`/`do_quit`/`do_EOF`, `do_help` — **zero** tests (13 of 19 shell commands). |
| `config.py` | 49 | indirect only | **Partial** — `Config()` default construction is used as a fixture object everywhere, but `reset_session`, `add_results`, `get_found_results`, `set_proxy` have no dedicated assertions. |
| `output.py` | 202 | none | **Zero.** `OutputFormatter` (table/JSON/breach-report formatting, `save_json`, `save_breach_json`) — untested. This is also the layer a "no API keys in output" guarantee needs to hold at, and currently nothing checks it there (Finding T-11 / Top-5 test #4). |
| `cli.py` | 333 | none | **Zero.** The `ohosint` console-script entry point / argparse wiring — untested. |

**Modules with zero test coverage of any kind (not even indirect):** `confidence.py`, `constants.py`, `executors.py`, `harvest.py`, `impersonate.py`, `patterns.py`, `pivots.py`, `probe.py`, `osint_core/cli.py`, `scan_result.py` (direct), `ohosint/output.py`, `ohosint/cli.py` — **12 of 25 source modules**, roughly **1,900 of ~6,300 source lines (≈30%)** with no test touching them at all, and several more (`async_check.py`'s core checking/classification logic, `site_db.py`'s parsing, `sources.py`, `search.py`, `exclusions.py`) where only a thin edge is covered.

## Findings

| ID | Severity | File:line | Summary | Status |
|---|---|---|---|---|
| T-01 | **Critical** | `tests/test_pipelines.py:30-62`, `ohosint/pipelines.py:119-144` | 3 tests make real outbound HTTPS calls to 4 live third-party hosts | VERIFIED |
| T-02 | High | (repo-wide) | No `conftest.py`, no network markers, no CI workflow | VERIFIED |
| T-03 | High | (repo-wide) | `pytest`/`pytest-asyncio` not declared as dependencies anywhere | VERIFIED |
| T-04 | Medium | `tests/test_tls.py:19-22` | Tautological assertion — doesn't test what it claims | VERIFIED |
| T-05 | Medium | `osint_core/async_check.py:243-333` | `classify_result` (WAF/status-code/regex classification engine) has zero tests | VERIFIED |
| T-06 | Medium | `pyproject.toml` (whole file) | Suite silently depends on 7 optional packages actually being installed | VERIFIED |
| T-07 | Medium | `osint_core/exclusions.py:18,27-29` | Module-level mutable cache (`_exclusions_cache`) is shared/uncleared across tests | VERIFIED |
| T-08 | Low | `osint_core/breach.py:686` + `tests/test_breach.py` | `breach_search(keys=None)` reads the real `.env`/`os.environ`; every current test happens to pass `keys=` explicitly, but nothing enforces that for future tests | VERIFIED |
| T-09 | Medium | `osint_core/async_check.py:340-349` | `_pick_checker`'s `CurlCffiChecker(proxy=proxy)` branch never receives `verify_ssl`, and is never exercised by any test | VERIFIED |
| T-10 | High | `osint_core/breach.py:508-553` | `breach_breachdirectory` (RapidAPI adapter) has zero test references of any kind | VERIFIED |
| T-11 | High | (missing) | No test asserts API keys are absent from the final serialized/printed report (`ohosint/output.py`) — only from the intermediate `breach_search()` dict | VERIFIED |
| T-12 | Low | `tests/test_pipelines.py:53-62` | `test_email_pipeline_runs_candidates_concurrently`'s docstring claims to verify concurrency, but the assertion (`call_count > 0`) can't distinguish concurrent from sequential execution | VERIFIED |

---

### T-01 — Critical: three tests make real, unmocked outbound network calls

**Evidence.** `ohosint/pipelines.py:119-144` (`run_email_pipeline`) unconditionally constructs a real `oc.Fetcher(proxy=proxy, delay=delay)` and calls the real `oc.gravatar`, `oc.leakcheck`, `oc.hudson_rock`, and (when `apply_exclusions=True`, the default) the real `oc.fetch_exclusions()`:

```python
# ohosint/pipelines.py:119-134
fetcher = oc.Fetcher(proxy=proxy, delay=delay)
try:
    report["sources"]["gravatar"] = oc.gravatar(fetcher, email)
except Exception as e:
    logger.debug("Gravatar lookup failed: %s", e)
try:
    report["sources"]["leakcheck"] = oc.leakcheck(fetcher, email)
...
try:
    report["sources"]["hudson_rock"] = oc.hudson_rock(fetcher, email)
```

Three tests in `tests/test_pipelines.py` call `run_email_pipeline(...)` and mock only `check_username_on_sites`, leaving `oc.Fetcher`/`oc.gravatar`/`oc.leakcheck`/`oc.hudson_rock`/`oc.fetch_exclusions` untouched:

- `tests/test_pipelines.py:30-38` `test_email_pipeline_passes_verify_ssl_false`
- `tests/test_pipelines.py:40-51` `test_email_pipeline_applies_exclusions_once`
- `tests/test_pipelines.py:53-62` `test_email_pipeline_runs_candidates_concurrently`

Compare with the correctly-written sibling test two classes down that already demonstrates the fix pattern:
```python
# tests/test_pipelines.py:68-78 — this one mocks everything correctly
with patch("ohosint.pipelines.oc.Fetcher") as MockFetcher, \
     patch("ohosint.pipelines.oc.gravatar") as mock_grav, \
     patch("ohosint.pipelines.oc.leakcheck") as mock_lc, \
     patch("ohosint.pipelines.oc.hudson_rock") as mock_hr:
```

**Independent confirmation performed during this audit** (no repo files touched):
1. `curl` directly against the two endpoints confirmed both are live and return 200:
   `gravatar: 200 time=0.82s`, `leakcheck: 200 time=1.51s` for the literal query used in the tests.
2. `pytest --durations=20` shows exactly the 3 offending tests take 8.2–9.0s each; every other test (including the properly-mocked sibling above) is sub-5ms.
3. Running one of the offending tests with `-s` prints `Sweeping 1 candidates across 1 sites...` and completes in **11.13s** for a single test.
4. A socket-level guard fixture (`socket.socket.connect` raises `AssertionError`) inserted around an unmocked call to `run_email_pipeline` triggers immediately — `fetch_exclusions`'s own `except Exception` handler surfaces it as `logger.warning("Failed to fetch exclusions from https://raw.githubusercontent.com/... : REAL NETWORK CALL DETECTED")`, proving `fetch_exclusions()` (4th endpoint, `raw.githubusercontent.com`) is also attempted, real, and only silent because of a broad `except Exception` in `run_email_pipeline`. The same guard exception is thrown for gravatar/leakcheck/hudson_rock but swallowed by `run_email_pipeline`'s own `except Exception as e: logger.debug(...)` (debug level, invisible by default) — which is precisely why these tests neither fail nor warn today when the network *is* unreachable; they simply record empty/degraded `sources` data and still pass, because nothing asserts on `report["sources"]` contents.

**Impact.** On a GitHub Actions runner with restricted/no egress, each of these 3 tests will hang until the 25s `requests` timeout (`osint_core/net.py:58`) is hit on each of up to 4 calls — potentially 60-100s of dead time per CI run, or an outright job timeout. On a runner with open egress, every CI run (including from public forks/PRs) sends real traffic with a fixed test payload (`test@example.com`) to gravatar.com, leakcheck.io, cavalier.hudsonrock.com, and GitHub's raw content CDN — this is flaky (subject to those services' uptime/rate-limiting), slow, and is arguably abusive/ToS-questionable traffic to send from a shared CI IP pool on every commit of an open-source repo.

**Recommended fix.** Mock `oc.Fetcher`, `oc.gravatar`, `oc.leakcheck`, `oc.hudson_rock`, and `oc.fetch_exclusions` in all three tests, following the exact pattern already used in `test_email_pipeline_passes_fetcher_to_sources` (`tests/test_pipelines.py:68-78`). See Top-5 test #1 below for a copy-pasteable version plus a `conftest.py` network guard that would have caught this automatically.

---

### T-02 — High: no `conftest.py`, no network markers, no CI workflow

**Evidence.** `find . -iname conftest.py` returns nothing. `grep -n "\[tool.pytest" pyproject.toml` returns nothing — there is no `[tool.pytest.ini_options]` section at all (pytest reports `configfile: pyproject.toml` only because the file exists and is valid TOML, not because it configures pytest). No `pytest.ini`, no `setup.cfg`. `find . -path '*/.github/*'` and `find . -iname '*.yml' -o -iname '*.yaml'` both return nothing — there is no CI workflow in this repository at all.

**Impact.** There's no `@pytest.mark.network` (or similar) infrastructure to let a CI job run `pytest -m "not network"` and skip the leaky tests (T-01) while still running them locally/nightly. There's no shared fixture location, so every test file re-implements its own fake-response helpers (`tests/test_breach.py`'s `Resp`/`fake_fetcher` vs. ad-hoc `MagicMock()` elsewhere) instead of sharing one. And with no workflow file, none of this has been exercised in CI even once — the "tests pass" claim has only ever been verified locally.

**Recommended fix.** See "Fixtures & structure" section below for a concrete `conftest.py` and marker proposal, plus a minimal GitHub Actions workflow.

---

### T-03 — High: `pytest` and `pytest-asyncio` are not declared as project dependencies

**Evidence.**
```
$ grep -in pytest requirements.txt pyproject.toml
(no output — grep exit code 1)
```
`pyproject.toml`'s `[project.optional-dependencies]` only defines `maigret`, `sherlock`, `sweep` — there is no `test`/`dev` extra. `requirements.txt` lists only the 9 runtime deps (`requests[socks]`, `phonenumbers`, `aiohttp`, etc.). `pytest` (9.1.1) and `pytest-asyncio` (1.4.0) are present in this sandbox only because they happen to be installed system/user-wide already (`pip show` confirms `Name: pytest` / `Name: pytest-asyncio` with no version pin anywhere in the repo).

**Impact.** A clean `pip install -e .` (or `pip install -r requirements.txt`) followed by `python -m pytest tests/` on a fresh CI runner or a contributor's fresh venv will fail immediately with `ModuleNotFoundError: No module named 'pytest'` (or, once pytest is manually installed, tests using `AsyncMock`/async fixtures will behave unpredictably without `pytest-asyncio` — though this suite currently avoids native `async def test_...` functions, using `asyncio.run()` internally instead, so the immediate breakage is just "pytest itself isn't there").

**Recommended fix.** Add a `test` extra to `pyproject.toml`:
```toml
[project.optional-dependencies]
test = ["pytest>=8.0", "pytest-asyncio>=0.24"]
```
and have CI install with `pip install -e .[test]`.

---

### T-04 — Medium: tautological assertion in `tests/test_tls.py`

**Evidence.**
```python
# tests/test_tls.py:19-22
def test_ssl_ctx_none_when_verifying(self):
    """When verify_ssl=True, no custom SSL context should be set (aiohttp defaults)."""
    c = AiohttpChecker(verify_ssl=True)
    assert c.verify_ssl is True
```
This is byte-for-byte the same assertion as `test_default_verifies_ssl` two methods above it. The docstring promises to verify that "no custom SSL context should be set," but `ssl_ctx` is a **local variable** inside `AiohttpChecker.check()` (`osint_core/async_check.py:123-128`) — it is never stored on `self`, so there is nothing on the instance this test *could* inspect to honor its own docstring. The test cannot fail no matter what `check()`'s SSL-context logic does, short of `__init__` itself being broken (which the adjacent test already covers).

**Recommended fix.** Either delete this test as a pure duplicate of `test_default_verifies_ssl`, or replace it with a test that actually exercises `check()` and inspects the `ssl=` kwarg passed into `aiohttp.TCPConnector`/`aiohttp_socks.ProxyConnector.from_url` — see Top-5 test #3 below (verified to pass against the real code).

---

### T-05 — Medium: `classify_result` (the core WAF/claimed/available classification engine) has zero tests

**Evidence.** `osint_core/async_check.py:243-333` is a ~90-line function that decides, from raw HTML/status/error, whether a site result is `CLAIMED`, `AVAILABLE`, `WAF`, or `UNKNOWN` — supporting Sherlock-style `errorType` arrays (`message` / `status_code` / `response_url`), WAF fingerprint matching (`WAF_FINGERPRINTS`, `async_check.py:37-46`), and `absence_strs`/`presense_strs` markers. `grep -rn "classify_result" tests/` returns nothing. `grep -rn "detect_waf" tests/` also returns nothing. This is the single most consequential piece of decision logic in the whole checking engine (it's what turns "we got some bytes back" into "this username exists") and it is completely unverified — a regression here silently turns every "claimed" into "available" or vice versa across the entire sweep, with no test to catch it.

**Recommended fix.** Table-driven tests feeding `classify_result()` fixture `(html, status, site_stub)` tuples covering: plain absence-string match, plain presence-string match, `status_code`-type site with custom `error_code`, `response_url`-type redirect detection, and at least 2 real WAF fingerprints from `WAF_FINGERPRINTS` (e.g. the Cloudflare `<title>Just a moment...</title>` and the AWS WAF token) to prove `detect_waf` short-circuits classification correctly.

---

### T-06 — Medium: suite silently depends on 7 optional packages being pre-installed

**Evidence.** `pyproject.toml` declares `maigret` and `sherlock-project` as *optional* extras (`[project.optional-dependencies]`), not core dependencies. Yet `osint_core/site_db.py:270-297` (`load_default_db`, `load_default_sherlock_db`) and the `impersonate.py`/`async_check.py` TLS-fingerprint path depend on `maigret`, `sherlock_project`, `curl_cffi`, `aiodns`, `aiohttp_socks`, `stem`, `sha3` being importable. This audit's own dependency probe confirms all 7 happen to be installed in this specific sandbox — but a fresh `pip install -e .` (without `.[sweep]`) followed by `pytest` would not have them. `tests/test_site_db.py` only tests the "packages missing" fallback branch via mocking, so it wouldn't catch this — but any future test that calls `load_default_db()` for real, or any manual verification run by a contributor who installed the base package only, would silently get different behavior (or import errors deep in `async_check.py`'s lazy imports) depending on what happens to already be on their machine.

**Impact.** Test *outcomes* for this specific run are not reproducible from a clean environment matching the declared dependency set. This doesn't currently cause a failure (because the only site-db test mocks the loaders away), but it's a latent trap: "tests pass on my machine" may not mean "tests pass from `pip install -e .`".

**Recommended fix.** Document in `tests/README` or the top of `test_site_db.py` which tests require the `sweep` extra, or (better) make the `test` extra from T-03 also pull in `.[sweep]` so CI always has a consistent, complete environment.

---

### T-07 — Medium: module-level mutable cache not reset between tests

**Evidence.** `osint_core/exclusions.py:18,27-29`:
```python
_exclusions_cache: Optional[Set[str]] = None

def fetch_exclusions(url=..., timeout=10) -> Set[str]:
    global _exclusions_cache
    if _exclusions_cache is not None:
        return _exclusions_cache
    ...
```
This is process-lifetime, global, mutable state. No test file resets it (no `monkeypatch.setattr(osint_core.exclusions, "_exclusions_cache", None)` anywhere, confirmed by `grep -rn monkeypatch tests/` returning nothing at all — the suite never uses `monkeypatch` as a fixture). `osint_core/breach.py:104` has an analogous `_CATALOGUE_CACHE: dict = {}` (exercised deliberately by `TestHIBPCatalogue::test_enrichment_cache`, which is fine since that test's whole point is the cache — but it too never resets the cache afterward, so cache state leaks into whichever test runs next in the same process).

**Impact.** Test order dependence: whichever test happens to run first "wins" the cache population, and later tests that assume a fresh fetch (or a fresh throttle state) could get stale cached data instead. Currently masked because the only test that touches `fetch_exclusions` for real is one of the T-01 leaky ones (which doesn't assert on the exclusion set's contents), but this will bite as soon as someone adds a real assertion on `filter_excluded_sites` output.

**Recommended fix.** Add an autouse `conftest.py` fixture that resets both module caches before each test (shown in the Fixtures section below).

---

### T-08 — Low: `get_api_keys()`'s real-`.env` fallback is untested-but-unguarded

**Evidence.** `osint_core/breach.py:686`: `keys = get_api_keys() if keys is None else keys` inside `breach_search`. `get_api_keys(environ=None)` (`osint_core/breach.py:60-87`) reads `os.environ` **and** opens `.env` in the current working directory when `environ` is not explicitly passed. Every current call to `oc.breach_search(...)` in `tests/test_breach.py` passes `keys={}` or an explicit `keys=keys` dict (confirmed by inspecting all 7 call sites), and `TestKeyHandling::test_get_api_keys` itself deliberately passes `environ={...}` — its own docstring says this is "so tests stay isolated," showing the author was already aware of the risk. So **no test currently reads the real `.env`** (which exists at `/home/omar/Documents/pythonProject/.env` and contains a real `OHO_RAPIDAPI_KEY`).

**Impact.** This is a landmine for future contributors, not a live bug: the first test that calls `oc.breach_search(f, query, qtype=...)` without an explicit `keys=` argument will silently pick up whatever `OHO_*` environment variables and `.env` file happen to be present on the machine (or CI secret store) running the suite, non-deterministically activating keyed sources (real authenticated API calls) based on ambient state that has nothing to do with the test.

**Recommended fix.** Add an autouse `conftest.py` fixture that `monkeypatch.chdir()`s to a tmp directory with no `.env`, or `monkeypatch.delenv()`s all `OHO_*` variables, for every test by default (shown below).

---

### T-09 — Medium: `verify_ssl` is silently dropped on the `CurlCffiChecker` proxy path, and that path is untested

**Evidence.** `osint_core/async_check.py:340-349`:
```python
def _pick_checker(site, proxy=None, verify_ssl=True) -> BaseChecker:
    protection = getattr(site, "protection", [])
    if "tls_fingerprint" in protection:
        from .impersonate import is_available
        if is_available():
            return CurlCffiChecker(proxy=proxy)   # <-- no verify_ssl passed
    if proxy and proxy.startswith("socks"):
        return AiohttpChecker(proxy=proxy, verify_ssl=verify_ssl)
    return AiohttpChecker(proxy=proxy, verify_ssl=verify_ssl)
```
`CurlCffiChecker.__init__` (`osint_core/async_check.py:168-177`) has no `verify_ssl` parameter at all. Every existing test in `test_tls.py` uses `FakeSite(); protection = []`, so this branch is never taken by any test. (Note: because curl_cffi's default behavior is to verify certificates, silently dropping `verify_ssl=False` here fails *safe* rather than *open* — TLS verification can't be accidentally disabled through this path — but the "insecure" shell flag would also silently not apply to TLS-fingerprint-protected sites, which could surprise a user who explicitly asked for `verify_ssl=False`.)

**Recommended fix.** Either thread `verify_ssl` through to `CurlCffiChecker` (curl_cffi's `Session`/`AsyncSession` accept a `verify=` kwarg), or explicitly document/test that TLS-fingerprint sites always verify regardless of the flag. Add a test asserting `_pick_checker(FakeSite(protection=["tls_fingerprint"]), verify_ssl=False)` returns a checker and documenting current behavior either way.

---

### T-10 — High: `breach_breachdirectory` has zero test references

**Evidence.** `grep -rn "breach_breachdirectory\|breachdirectory" tests/` — the only hits are the string `"breachdirectory"` used as a *provider name* to check it appears in `sources_skipped` (`tests/test_breach.py:213`, `TestKeyHandling::test_hibp_account_skipped_without_key`) — the function `oc.breach_breachdirectory` itself (`osint_core/breach.py:508-553`, RapidAPI adapter) is never called, mocked, or asserted on anywhere. It has several non-obvious branches worth locking down: a 500 status code is treated as "no records" rather than an error (`breach.py:525-527`, a documented RapidAPI quirk), 401/403 means "key rejected," and successful responses need `result` list normalization.

**Recommended fix.** See Top-5 test #5 below — realistic fixture tests for this adapter (verified passing against the real implementation).

---

### T-11 — High: nothing verifies API keys stay out of the *serialized/printed* report

**Evidence.** `tests/test_breach.py::TestKeyHandling::test_keys_not_in_report` (`tests/test_breach.py:230-244`) only checks `json.dumps(report)` on the raw dict returned by `oc.breach_search(...)`. It never touches `ohosint/output.py`'s `OutputFormatter.breach_to_json()` / `save_breach_json()` / `_print_breach_rich()` / `_print_breach_plain()` — the actual code paths a user hits when they run `ohosint` and get a report printed to their terminal or saved to disk. `ohosint/output.py` has zero tests of any kind (confirmed in the coverage table above), so there is no guarantee that some future formatting change (e.g. adding a debug field, or echoing `metadata`) doesn't reintroduce a key into what the user actually sees or saves. For a tool whose explicit purpose is generating shareable JSON reports, this is the layer that matters most.

**Recommended fix.** See Top-5 test #4 below.

---

### T-12 — Low: concurrency claim is not actually verified

**Evidence.**
```python
# tests/test_pipelines.py:53-62
def test_email_pipeline_runs_candidates_concurrently(self):
    """All candidates should be gathered, not run in a sequential loop."""
    with patch("ohosint.pipelines.check_username_on_sites", new_callable=AsyncMock, return_value=[]) as mock_check:
        run_email_pipeline("test@example.com", sites={"test": MagicMock()})
        assert mock_check.call_count > 0
```
`mock_check.call_count > 0` is true whether `check_username_on_sites` is awaited one-at-a-time in a `for` loop or gathered concurrently via `asyncio.gather`/`asyncio.as_completed` (as `run_email_pipeline` actually does, `ohosint/pipelines.py:150-172`) — the assertion can't distinguish the two, so it wouldn't catch a regression back to sequential execution despite the docstring's claim. (This test is also one of the three T-01 network leaks, so today its 8s+ runtime is masking the fact that the concurrency claim itself isn't checked.)

**Recommended fix.** Use a side effect that records call *timestamps* or overlapping in-flight counts (e.g. an `AsyncMock` side effect that increments a counter on entry, sleeps briefly, decrements on exit, and asserts the counter reached >1 concurrently), or simplest: assert `mock_check.call_count == len(report["candidates"][:5])` (currently this passes trivially with only 1 candidate in the fixture — sites/candidates should be parametrized with ≥2 to make the count assertion meaningful at all).

---

## Flaky-pattern scan

Checked for: real `time.sleep`, wall-clock/`datetime.now()` dependence without freezing, and `assert True`/self-asserting-a-mock patterns.

- `grep -rn "time.sleep\|datetime.now\|random.seed\|freeze_time" tests/` — **no matches**. No test directly sleeps or depends on wall clock.
- However, `osint_core/net.py:52` (`Fetcher.nap()`) calls the real `time.sleep(random.uniform(*delay))`, and this real sleep executes inside the T-01 tests because their `Fetcher` isn't mocked — so the suite does contain real sleeps today, just indirectly (see T-01; this resolves itself once T-01 is fixed).
- `grep -rn "assert True\|assert 1 =="` — **no matches**. No unconditionally-true assertions found.
- No test in this suite asserts on the state of a mock it just configured (e.g. `mock.return_value = X; assert mock() == X`) — the closest thing is T-04's tautology, which is a duplicate-assertion problem rather than a mock-testing-itself problem.
- No `datetime.now()`/timestamp assertions found in the suite that would be sensitive to execution time (report generation timestamps like `ohosint/output.py:77` `make_report_path` are unused by tests).

## Missing negative/edge-case tests worth calling out (beyond the Top 5)

- **Unicode/non-ASCII usernames or emails**: `generate_candidates`/`simple_candidates` tests only use ASCII names (`"johndoe"`). No test exercises an email local-part or name with non-ASCII characters (e.g. accented names), which `candidates.py`'s ASCII-only assertions (`test_basic_permutations` explicitly asserts `c.isascii()`) suggest was a deliberate design constraint — but nothing tests what happens when a non-ASCII *input* is given (does it degrade gracefully or raise?).
- **Malformed/truncated API JSON**: `test_breach.py` covers "no JSON" (`Resp(json_data=None)` → raises `ValueError` inside `.json()`) for a few adapters, but not partially-malformed JSON (e.g. `{"success": true}` missing the expected `sources` key entirely, or `sources` being a list of raw strings instead of dicts) for every adapter — several adapters (`breach_hibp_account`, `breach_breachdirectory`, `breach_intelx`) have no malformed-JSON test at all.
- **Timeouts**: no test simulates `requests.Timeout`/`aiohttp.ClientTimeout` at the `Fetcher`/`AiohttpChecker` boundary to confirm the caller degrades correctly (returns `None`/`ScanResult.error` rather than raising).
- **Rate-limit propagation through the full CLI path**: `breach.py` handles 429 per-adapter, but there's no end-to-end test that a 429 anywhere produces the right user-visible flag in `OutputFormatter._print_breach_plain`/`_print_breach_rich`.
- **Empty input**: no test calls `run_email_pipeline("")`, `generate_candidates("")`, or `oc.detect_qtype("")` with empty strings.

## Fixtures & structure

There is no `conftest.py` in this repository (`find . -iname conftest.py` → empty), and each test file hand-rolls its own fake HTTP objects (`test_breach.py`'s `Resp`/`fake_fetcher`, ad-hoc `MagicMock()` elsewhere) instead of sharing one. Given a networked security tool, a `conftest.py` should own three things: a hard network guard, cache resets, and shared fixtures.

Recommended `tests/conftest.py` (not created — for the maintainer to add):

```python
"""Shared fixtures for the OHOsint / osint_core test suite."""
import socket
import pytest


@pytest.fixture(autouse=True)
def block_real_network(monkeypatch, request):
    """Fail any test that reaches the real network, unless explicitly marked.

    Use @pytest.mark.network on the rare test that legitimately needs it
    (and skip those in CI with `pytest -m "not network"`).
    """
    if "network" in request.keywords:
        yield
        return

    def guard(*args, **kwargs):
        raise AssertionError(
            "Real network access attempted in a test not marked @pytest.mark.network. "
            "Mock the Fetcher / requests call instead."
        )
    monkeypatch.setattr(socket.socket, "connect", guard)
    yield


@pytest.fixture(autouse=True)
def reset_module_caches():
    """osint_core keeps a couple of process-lifetime caches; without this,
    whichever test runs first silently seeds state for every test after it.
    """
    import osint_core.exclusions as excl
    import osint_core.breach as breach
    excl._exclusions_cache = None
    breach._CATALOGUE_CACHE = {}
    yield
    excl._exclusions_cache = None
    breach._CATALOGUE_CACHE = {}


@pytest.fixture(autouse=True)
def isolate_env_and_dotenv(monkeypatch, tmp_path):
    """Prevent osint_core.breach.get_api_keys() from ever reading a real
    .env or real OHO_* environment variables when a test forgets to pass
    keys= explicitly (see audit finding T-08).
    """
    for var in ("OHO_HIBP_KEY", "OHO_INTELX_KEY", "OHO_RAPIDAPI_KEY", "OHO_EMAILREP_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)  # no .env here


class FakeResponse:
    """Shared fake requests.Response — promote test_breach.py's local `Resp`
    class here so every test file uses the same fake instead of each
    reinventing it."""
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


@pytest.fixture
def fake_fetcher():
    """Factory: build a MagicMock Fetcher whose .get() returns a fixed
    sequence of FakeResponse objects (mirrors test_breach.py's helper)."""
    from unittest.mock import MagicMock

    def _make(responses=None, post_response=None):
        f = MagicMock()
        f.get = MagicMock(side_effect=responses or [])
        f.session = MagicMock()
        f.session.post = MagicMock(return_value=post_response)
        f.n_req = 0
        f.nap = MagicMock()
        return f
    return _make
```

And register the marker in `pyproject.toml` so `-m network` doesn't warn:
```toml
[tool.pytest.ini_options]
markers = [
    "network: test performs real outbound network I/O; excluded from CI by default",
]
```

CI (`.github/workflows/tests.yml`, does not currently exist):
```yaml
name: tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -e ".[test,sweep]"
      - run: pytest tests/ -v -m "not network"
```

## Top 5 missing tests (highest value, copy-pasteable)

All 5 snippets below were written to a scratch file and run standalone against the actual, unmodified source tree (`sys.path` pointed at the real repo) to confirm they pass as written — no repo file was created or modified to do this. Result: **11/11 passed in 0.14s** (versus 43s+ for the existing suite), confirming both that the code is correct today and that removing the network dependency is what makes the suite fast.

They assume the `conftest.py` fixtures above are *not* yet installed (each snippet is self-contained), so they can be dropped into the existing test files as-is.

### 1. Prove `run_email_pipeline` never touches the network when properly mocked (fixes T-01)

```python
# tests/test_pipelines.py — replaces the 3 leaky tests' missing mocks
import socket
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from ohosint.pipelines import run_email_pipeline


@pytest.fixture(autouse=True)
def block_real_network(monkeypatch):
    def guard(*args, **kwargs):
        raise AssertionError(
            "Real network access attempted — mock the Fetcher/HTTP call instead."
        )
    monkeypatch.setattr(socket.socket, "connect", guard)


def test_run_email_pipeline_never_touches_real_network():
    """Regression guard for the CI-breaking leak: run_email_pipeline() must
    not perform any real I/O once its collaborators are mocked. Unpatched,
    this call reaches gravatar.com, leakcheck.io, cavalier.hudsonrock.com
    and raw.githubusercontent.com (see audit finding T-01)."""
    with patch("ohosint.pipelines.oc.Fetcher") as MockFetcher, \
         patch("ohosint.pipelines.oc.gravatar", return_value={"hash": "x", "profile": None}), \
         patch("ohosint.pipelines.oc.leakcheck", return_value={"found": None, "sources": [], "note": ""}), \
         patch("ohosint.pipelines.oc.hudson_rock", return_value={"error": "unreachable"}), \
         patch("ohosint.pipelines.oc.fetch_exclusions", return_value=set()), \
         patch("ohosint.pipelines.check_username_on_sites", new_callable=AsyncMock, return_value=[]):
        report = run_email_pipeline(
            "test@example.com",
            sites={"test": MagicMock()},
            verify_ssl=False,
        )
    assert report["sources"]["gravatar"]["hash"]
    MockFetcher.assert_called_once()
```

### 2. Prove SOCKS/Tor proxy actually reaches the aiohttp connector (highest security priority per the audit brief)

```python
# tests/test_tls.py (or a new tests/test_proxy_routing.py)
import asyncio
from unittest.mock import patch
from osint_core.async_check import AiohttpChecker, _pick_checker


def test_socks_proxy_is_threaded_into_aiohttp_connector():
    """_pick_checker + AiohttpChecker.check() must hand the socks5h:// proxy
    to aiohttp_socks.ProxyConnector.from_url — proving Tor routing is wired
    on the actual request path, not just stored as an unused attribute."""

    class FakeSite:
        protection = []

    proxy = "socks5h://127.0.0.1:9050"
    checker = _pick_checker(FakeSite(), proxy=proxy, verify_ssl=True)
    assert isinstance(checker, AiohttpChecker)
    checker.prepare("https://example.com/u", timeout=5)

    captured = {}

    class FakeConnector:
        def __init__(self, *a, **kw):
            pass

    def fake_from_url(url, **kw):
        captured["url"] = url
        captured["ssl"] = kw.get("ssl")
        return FakeConnector()

    class FakeResp:
        status = 200
        async def text(self, errors="ignore"):
            return "<html>ok</html>"
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False

    class FakeSession:
        def __init__(self, *a, **kw):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        def get(self, **kw):
            return FakeResp()

    with patch("aiohttp_socks.ProxyConnector.from_url", side_effect=fake_from_url), \
         patch("aiohttp.ClientSession", FakeSession):
        text, status, err = asyncio.run(checker.check())

    assert captured["url"] == proxy
    assert status == 200
```

### 3. Prove `verify_ssl=False` actually disables certificate checking on the wire (fixes T-04's tautology)

```python
# tests/test_tls.py
import asyncio
import ssl
from unittest.mock import MagicMock, patch
from osint_core.async_check import AiohttpChecker


def test_verify_ssl_false_builds_cert_none_context():
    """AiohttpChecker(verify_ssl=False) must pass an ssl.CERT_NONE context to
    TCPConnector — not merely set an attribute nobody reads. Closes the gap
    left by the existing test_ssl_ctx_none_when_verifying, which only
    re-asserts checker.verify_ssl and never inspects the SSL context
    actually built inside check()."""
    checker = AiohttpChecker(verify_ssl=False)
    checker.prepare("https://example.com/u", timeout=5)

    captured = {}

    def fake_tcp_connector(*a, **kw):
        captured["ssl"] = kw.get("ssl")
        return MagicMock()

    class FakeResp:
        status = 200
        async def text(self, errors="ignore"):
            return "ok"
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False

    class FakeSession:
        def __init__(self, *a, **kw):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        def get(self, **kw):
            return FakeResp()

    with patch("aiohttp.TCPConnector", side_effect=fake_tcp_connector), \
         patch("aiohttp.ClientSession", FakeSession):
        asyncio.run(checker.check())

    ctx = captured["ssl"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False
```

### 4. Prove API keys never reach the *serialized* report a user actually sees/saves (fixes T-11)

```python
# tests/test_breach.py (or a new tests/test_output.py)
from unittest.mock import MagicMock, patch
import osint_core as oc
from ohosint.output import OutputFormatter


def test_api_key_never_reaches_serialized_breach_output():
    """breach_search() already strips keys from its dict (see
    test_keys_not_in_report), but nothing checks the layer users actually
    see: OutputFormatter.breach_to_json() / save_breach_json(). This guards
    the full path from a keyed lookup to the JSON a user might paste into a
    bug report or commit by accident."""
    f = MagicMock()
    f.get = MagicMock(return_value=None)  # every keyless source: unavailable
    f.session.post = MagicMock(return_value=None)

    secret = "sk-super-secret-rapidapi-key-do-not-leak"
    with patch("osint_core.breach.breach_hibp_account") as mock_hibp:
        mock_hibp.return_value = {"found": True, "breaches": [{"name": "Adobe"}]}
        report = oc.breach_search(
            f, "user@example.com", qtype="email",
            keys={"hibp": secret},
        )

    out = OutputFormatter(use_rich=False).breach_to_json(report)
    assert secret not in out
    assert "Adobe" in out  # sanity: the non-secret finding does survive
```

### 5. Realistic-fixture parsing tests for two never-directly-tested breach adapters (fixes T-10)

```python
# tests/test_breach.py — add alongside the existing TestHudsonRock etc. classes
from unittest.mock import MagicMock
import osint_core as oc


class _Resp:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class TestHIBPAccountFixtures:
    def test_found_truncated_response(self):
        f = MagicMock()
        f.get = MagicMock(return_value=_Resp(200, [
            {"Name": "Adobe"}, {"Name": "LinkedIn"},
        ]))
        r = oc.breach_hibp_account(f, "user@example.com", "paid-key")
        assert r["found"] is True
        assert {b["name"] for b in r["breaches"]} == {"Adobe", "LinkedIn"}

    def test_404_is_clean_not_error(self):
        f = MagicMock()
        f.get = MagicMock(return_value=_Resp(404))
        r = oc.breach_hibp_account(f, "clean@example.com", "paid-key")
        assert r["found"] is False
        assert r["breaches"] == []

    def test_key_rejected_401(self):
        f = MagicMock()
        f.get = MagicMock(return_value=_Resp(401))
        r = oc.breach_hibp_account(f, "user@example.com", "bad-key")
        assert "rejected" in r["note"]
        assert r["found"] is None

    def test_malformed_json_does_not_raise(self):
        f = MagicMock()
        bad = _Resp(200, json_data=None)  # .json() raises ValueError
        f.get = MagicMock(return_value=bad)
        r = oc.breach_hibp_account(f, "user@example.com", "paid-key")
        assert r["note"]  # error captured, not propagated


class TestBreachDirectoryFixtures:
    def test_found_with_records(self):
        f = MagicMock()
        f.get = MagicMock(return_value=_Resp(200, {
            "found": 1,
            "result": [
                {"email": "user@example.com", "password": "hunter2",
                 "sources": ["ExampleCorp2019"]},
            ],
        }))
        r = oc.breach_breachdirectory(f, "user@example.com", "rapidapi-key")
        assert r["found"] is True
        assert r["records"][0]["password"] == "hunter2"

    def test_500_treated_as_no_records(self):
        """BreachDirectory's RapidAPI quirk: HTTP 500 == 'nothing found', not
        a server error. Guards against a future refactor 'fixing' this into
        a raised exception."""
        f = MagicMock()
        f.get = MagicMock(return_value=_Resp(500))
        r = oc.breach_breachdirectory(f, "clean@example.com", "rapidapi-key")
        assert r["found"] is False

    def test_rate_limited_429(self):
        f = MagicMock()
        f.get = MagicMock(return_value=_Resp(429))
        r = oc.breach_breachdirectory(f, "user@example.com", "rapidapi-key")
        assert "rate-limited" in r["note"]
```

## Summary of what to do before going public

1. **Blocking**: fix the 3 leaky tests in `tests/test_pipelines.py` (T-01) — either mock properly (test #1 above) or the suite will hang/leak traffic in CI.
2. **Blocking**: add `pytest`/`pytest-asyncio` to a `test` extra (T-03) and add a minimal CI workflow (T-02) — right now this has never actually run in CI.
3. **Strongly recommended**: add `tests/conftest.py` with the network guard, cache reset, and env isolation fixtures shown above — this converts T-01, T-07, and T-08 from "currently fine by luck" into "structurally can't regress."
4. **Recommended**: the 5 tests above, plus `classify_result` coverage (T-05) and `breach_breachdirectory` coverage (T-10), close the highest-risk gaps in a security-sensitive tool's test suite.
