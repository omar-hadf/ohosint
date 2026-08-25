# Remediation Plan — AUDIT.md findings

> **Superseded — historical record.** This is the remediation plan for the
> 2026-08-24 audit round ([AUDIT.md](AUDIT.md)). That work is complete; all 9
> findings were re-verified as fixed on 2026-08-25. Kept for provenance only.
> Current state: [PUBLICATION-AUDIT.md](PUBLICATION-AUDIT.md).

Date: 2026-08-24
Status: all 9 findings **verified against the live code** before planning (see "Verification results" below). No fixes applied yet.

## Verification results

| # | Verdict | Evidence |
|---|---------|----------|
| 1 | **Real — and worse than reported** | Reproduced: `TypeError: dork() missing 1 required positional argument: 'query'`. Additionally: even after adding the missing fetcher arg, `state, hits = oc.dork(...)` unpacks 2 variables from a **3-tuple** `(uniq, states, flag)` — it would then crash with `ValueError: too many values to unpack`. The audit missed this second half. Working reference: `skills/silent-recon/silent_recon.py:319` (`hits, states, flag = dork(self.fetch, q)`). |
| 2 | **Real** | Reproduced: `sherlock_project` not installed here; output only appears because `maigret` happens to be installed (2,589 sites). Neither package is in `requirements.txt` or `pyproject.toml`. Missing DBs trigger only a `logger.warning`; an empty merge returns `{}` and commands "succeed" with 0 sites. |
| 3 | **Real** | `ohosint/shell.py:178`: bare `requests.get(url, headers=…, timeout=…)` — no `proxies=`, ignores `config.proxy`. Correct reference impl: `silent_recon.py` `do_autopsy` via `self.fetch.get(url)`. |
| 4 | **Real** | `osint_core/async_check.py:122-124`: `check_hostname = False` + `CERT_NONE`, unconditional, applies over Tor too. |
| 5 | **Real** | `stem>=1.8` is `requirements.txt:9` but absent from `pyproject.toml` dependencies (lines 10–19). `ohosint shell → newnym` needs it. |
| 6 | **Partially stale** | README.md **already documents ohosint** (rewritten alongside the audit). But `AGENTS.md` is still stale: claims "two dependencies: requests[socks], phonenumbers" and never mentions `ohosint/`. |
| 7 | **Real** | 5 occurrences grep-verified: `ohosint/config.py:26`, `ohosint/pipelines.py:86,136,183`, `osint_core/exclusions.py:51,54`. |
| 8 | **Real** | `osint_core/candidates.py:52`: `"[a-zA-Z0-9]" != c` compares against the literal 12-char string — always True, filters nothing. |
| 9 | **Real (labeling)** | `osint_core/probe.py:2` says DEPRECATED, yet all three `skills/` scripts call `probe()`. |

---

## Fix plan

### Phase 1 — High severity

**1. Fix `dork` crash (`ohosint/shell.py:159-167`)**

- Add a lazily-built, cached sync `Fetcher` to `OHOsintShell`:
  ```python
  def _fetcher(self):
      if self._fetcher_cached is None:
          self._fetcher_cached = oc.Fetcher(
              proxy=self.config.proxy,
              delay=(self.config.delay_min, self.config.delay_max))
      return self._fetcher_cached
  ```
  Invalidate the cache in `do_proxy` (and `do_delay`) so session config changes take effect.
- Fix the call **and** the unpacking (3-tuple, hits-first order):
  `hits, states, flag = oc.dork(self._fetcher(), line.strip())`, then print per-engine states and the throttle flag.
- Verify: `OHOsintShell(Config()).onecmd('dork test query')` no longer raises.

**2. Fix `autopsy` proxy bypass (`ohosint/shell.py:169-193`)**

- Replace the bare `requests.get` with `self._fetcher().get(url)` (same helper as fix 1 — one code path, proxy always honored). Keep the URL scheme guard from `silent_recon.py`'s version.
- Verify: set `proxy socks5h://127.0.0.1:9050`, run autopsy, confirm the session `proxies` dict is populated (unit-style check or proxy-side observation).

**3. Fail loudly on empty site DBs (`ohosint/pipelines.py:16-49`, `ohosint/shell.py:54-57`, `ohosint/cli.py`)**

- Keep maigret/sherlock **optional** (they're heavy), but make the empty case explicit:
  - In `load_site_databases()`: when the merged dict is empty, raise/log a clear actionable error: `0 sites loaded — install site data: pip install maigret sherlock-project`.
  - In the shell `_load_sites()` and the CLI `email`/`username`/`sites` paths: surface that message to the user and abort the sweep (non-zero exit in CLI) instead of printing an empty table.
- Declare extras in `pyproject.toml` so the fix is discoverable:
  ```toml
  [project.optional-dependencies]
  maigret = ["maigret"]
  sherlock = ["sherlock-project"]
  sweep = ["maigret", "sherlock-project"]
  ```
- Document `pip install -e .[sweep]` in README (site-data section already exists — extend it).
- Verify: in a venv without maigret/sherlock, `ohosint username foo` exits non-zero with the actionable message; with maigret installed, behavior unchanged.

### Phase 2 — Medium severity

**4. Re-enable TLS verification by default (`osint_core/async_check.py:115-133`)**

- Remove the unconditional `CERT_NONE` context; default to a normal verifying context (`ssl.create_default_context()` untouched, or simply let aiohttp use its defaults).
- Add an **opt-in** escape hatch for broken-cert sites: `AiohttpChecker(proxy=…, verify_ssl=True)` param, threaded `check_username_on_sites(…, verify_ssl=True)` ← pipelines ← `Config.insecure_tls` / `--insecure` CLI flag (default: verify).
- Apply the same context handling to the `ProxyConnector.from_url(..., ssl=…)` branch.
- Verify: request to a valid-HTTPS site succeeds; request to a bad-cert host fails with a cert error by default and succeeds with `--insecure`.

**5. Sync dependency manifests (`pyproject.toml`)**

- Add `stem>=1.8` to `[project] dependencies` (it's a hard requirement of `ohosint shell → newnym`).
- Optionally add a `[project.optional-dependencies] tor = ["stem>=1.8"]` — but since `newnym` is a built-in command, the main dependency list is the honest place.
- Verify: `pip install -e .` in a fresh venv, then `python -c "from stem.control import Controller"`.

### Phase 3 — Low severity / docs

**6. Update `AGENTS.md`** — add `ohosint/` to the architecture section, correct the dependency list (8 runtime deps, not 2), add `ohosint` CLI examples, note the optional maigret/sherlock site-data packages. README is already done.

**7. `any` → `typing.Any`** — 5 edits (`ohosint/config.py:26`, `ohosint/pipelines.py:86,136,183`, `osint_core/exclusions.py:51,54`), adding `Any` to each file's typing import.

**8. Remove dead clause in `osint_core/candidates.py:52`** — delete `"[a-zA-Z0-9]" != c and ` (the trailing `re.fullmatch(r"[a-z0-9._-]+", c)` already does the real filtering). Confirm candidate output for a few sample emails is unchanged before/after.

**9. Correct `osint_core/probe.py` docstring** — replace "DEPRECATED" with the actual decision: `probe.py` remains the synchronous engine for `skills/` (simplicity, GET-only, delay-politeness); `async_check.py` is the engine for `ohosint` (scale/speed). No consolidation planned.

### Phase 4 — Minimal test suite (audit recommendation #6)

New `tests/` with pytest, covering exactly the failure classes that shipped:

- `test_shell_dork.py` — `do_dork` calls `dork(fetcher, query)` with correct arity and unpacks 3 values (mock `oc.dork`).
- `test_shell_autopsy_proxy.py` — `do_autopsy` routes through the session whose `proxies` match `config.proxy`.
- `test_site_db.py` — parse tiny Maigret-format and Sherlock-format JSON fixtures; empty/missing DBs produce the loud error path.
- `test_candidates.py`, `test_pivots.py`, `test_confidence.py` — pure-function golden tests.
- `test_manifests_sync.py` — every package imported anywhere under `ohosint/`+`osint_core/` (requests, stem, aiohttp, …) appears in `pyproject.toml` dependencies or declared extras.

No CI wiring needed yet (repo is intentionally minimal); just make `python -m pytest` pass locally.

---

## Execution order & effort

| Step | Fixes | Effort | Risk |
|------|-------|--------|------|
| 1 | #1 + #3 (share the `_fetcher()` helper) | ~30 min | Low — mirrors proven `silent_recon.py` pattern |
| 2 | #2 loud-failure + extras | ~45 min | Low — no behavior change when DBs present |
| 3 | #4 TLS default-verify + opt-in flag | ~45 min | Medium — a few broken-cert sites may newly fail; mitigated by `--insecure` |
| 4 | #5 stem dep | 5 min | None |
| 5 | #6, #7, #8, #9 cleanup | ~30 min | None |
| 6 | Test suite | ~2 h | None |

Total: ~4–5 hours. Steps 1–2 are the user-facing wins (crash + anonymity leak + silent no-op); do those first.
