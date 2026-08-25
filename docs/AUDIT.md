# Code Audit — pythonProject (OHOsint / osint_core)

> **Superseded — historical record.** This report is from the audit round of
> 2026-08-24. All 9 findings below were independently re-verified on
> 2026-08-25 and **all are fixed** in the current code. It is kept for
> provenance only; do not read it as a list of open issues.
> For the current state of the codebase see
> [PUBLICATION-AUDIT.md](PUBLICATION-AUDIT.md) and [audit/](audit/).

Date: 2026-08-24
Scope: full repository (`osint_core/`, `ohosint/`, `skills/`), 27 Python files, ~4,400 LOC.
Method: full read of every source file, static parse check (no syntax errors),
targeted reproduction of suspected bugs by actually running the code.

## TL;DR

The codebase is two systems sharing one library:

1. **`skills/`** — three older, hand-written CLI scripts (`silent_recon.py`,
   `find_profiles.py`, `deep_dive.py`) built on the synchronous `Fetcher` +
   `probe()` path in `osint_core`. This is what the current README documents.
2. **`ohosint/`** — a newer, more capable unified CLI (`email/phone/username/name/shell/sites`
   subcommands, async multi-site sweeps, Maigret/Sherlock site-database
   integration, rich table/JSON output) registered as the actual
   `ohosint` console-script entry point in `pyproject.toml`. **The README never
   mentions it.**

Both are reasonably well-factored (one shared library, no code duplication
between skill scripts), but there are three real bugs (one a guaranteed
crash, one a silent-failure dependency trap, one an OPSEC leak for a tool
whose entire purpose is staying passive/anonymous), a security-relevant
regression in the async HTTP path, and a packaging gap. None are exotic —
all were confirmed by direct reproduction, not just reading.

## Findings

| # | Severity | Area | Summary |
|---|----------|------|---------|
| 1 | High | Reliability | `ohosint shell` → `dork` command always crashes (`TypeError`) |
| 2 | High | Packaging / UX | `ohosint`'s site-sweep commands silently return **zero** results on a stock `pip install -r requirements.txt` — the packages that actually supply site data (`maigret`, `sherlock_project`) aren't declared anywhere |
| 3 | High | Security / OPSEC | `ohosint shell` → `autopsy` bypasses the configured proxy entirely, defeating the Tor routing that is this tool's core anonymity guarantee |
| 4 | Medium | Security | The async HTTP checker (`AiohttpChecker`) disables TLS certificate verification unconditionally, on every request, including over Tor |
| 5 | Medium | Packaging | `stem` (required for `ohosint`'s Tor `newnym` command) is in `requirements.txt` but missing from `pyproject.toml`'s dependency list |
| 6 | Low | Docs | README/AGENTS.md describe only `skills/` + `osint_core`; the `ohosint/` package (the registered console-script entry point) is undocumented |
| 7 | Low | Code quality | `Dict[str, any]` (builtin `any`, not `typing.Any`) used as a type hint in 5 places |
| 8 | Low | Code quality | Dead filter condition in `generate_candidates()` |
| 9 | Info | Architecture | Two parallel, differently-labeled probing engines (`probe.py` marked "DEPRECATED" yet still the primary engine for `skills/`, vs. `async_check.py` used by `ohosint`) with no stated migration plan |

---

### 1. `ohosint shell` → `dork` crashes every time (High)

**File:** [ohosint/shell.py:164](ohosint/shell.py#L164)

```python
def do_dork(self, line):
    """dork <query> — run a search-engine dork."""
    if not line.strip():
        print("Usage: dork <query>")
        return
    state, hits = oc.dork(line.strip())   # <-- missing the fetcher argument
```

`osint_core.search.dork` is defined as `dork(fetcher, query)`
([osint_core/search.py:81](osint_core/search.py#L81)). The shell calls it
with only the query string, which Python binds to the first parameter
(`fetcher`), leaving `query` unfilled.

Reproduced directly:

```
$ python3 -c "
from ohosint.shell import OHOsintShell
from ohosint.config import Config
OHOsintShell(Config()).onecmd('dork test query')"
...
TypeError: dork() missing 1 required positional argument: 'query'
```

Every other call site (`silent_recon.py`, `find_profiles.py`, `deep_dive.py`)
passes a `Fetcher` correctly — this is the one place it was missed, and
because `ohosint` has no `Fetcher` of its own (its HTTP path is async), the
fix isn't a one-line argument swap; `dork()` itself is synchronous
`requests`-based and doesn't fit `ohosint`'s async model as-is.

### 2. `ohosint`'s username/email sweeps silently return 0 results out of the box (High)

**Files:** [osint_core/site_db.py:270-298](osint_core/site_db.py#L270),
[ohosint/pipelines.py:16-49](ohosint/pipelines.py#L16)

`ohosint email|username|sites` all go through `load_site_databases()`, which
populates the site list exclusively via:

```python
def load_default_db():        # tries `import maigret`
def load_default_sherlock_db():  # tries `import sherlock_project`
```

Neither `maigret` nor `sherlock_project` appears in `requirements.txt` or
`pyproject.toml`. On a machine that only installed this project's declared
dependencies, both imports fail, `load_site_databases("all")` returns an
**empty dict**, and every downstream command "succeeds" with an empty
table (`Total: 0 sites checked`) instead of an error telling the user what's
missing.

Confirmed on this machine: `sherlock_project` is not installed, and the only
reason `ohosint username <handle>` produces any output at all is that
`maigret` happens to be installed globally (2,589 sites) — a coincidence of
this dev environment, not something a fresh clone gets from the documented
setup steps.

```
$ pip show sherlock_project
WARNING: Package(s) not found: sherlock_project
$ python3 -c "from ohosint.pipelines import load_site_databases as l; print(len(l('all')))"
Sherlock database not found
2589        # <- only non-zero because maigret happens to be installed already
```

This is the single biggest gap between "the code as documented" and "the
code as it actually behaves" — the tool's headline feature (multi-site
username sweep) does nothing useful unless the user independently
discovers and installs one of two undeclared third-party packages.

### 3. `autopsy` in the `ohosint` shell ignores the configured proxy (High — OPSEC)

**File:** [ohosint/shell.py:169-193](ohosint/shell.py#L169)

```python
def do_autopsy(self, line):
    ...
    import requests
    headers = {"User-Agent": oc.UAS[0]}
    resp = requests.get(url, headers=headers, timeout=self.config.timeout)
```

Every other network path in this project (the `Fetcher` class, the async
checkers, `silent_recon.py`'s equivalent `autopsy` command) honors
`--proxy`/`--tor`. This one builds a bare `requests` call with no `proxies=`
argument, so it always goes out on the operator's real IP — regardless of
whether `proxy socks5h://127.0.0.1:9050` is set in the session. For a tool
whose stated design goal is "target never notified" and "your origin is
hidden too," silently making a direct connection to a target-controlled or
adult-platform URL the operator just confirmed is a real profile page is the
exact failure mode this project is built to avoid. (`silent_recon.py`'s
`do_autopsy` at [skills/silent-recon/silent_recon.py:291](skills/silent-recon/silent_recon.py#L291)
does this correctly via `self.fetch.get(url)`.)

### 4. Async HTTP checker disables TLS verification unconditionally (Medium — Security)

**File:** [osint_core/async_check.py:122-124](osint_core/async_check.py#L122)

```python
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE
```

This runs for **every** `AiohttpChecker` request — the primary backend used
by `ohosint`'s async sweeps — not just as a fallback for a specific broken
site. Certificate validation is fully disabled, over both direct connections
and SOCKS/Tor proxies. Practically, this means:

- A malicious or monitoring Tor exit node (a real, documented risk for this
  exact threat model) can MITM the response and flip a verdict from
  `available` to `claimed` or inject fabricated profile data, with no error
  or warning surfaced.
- It's inconsistent with the rest of the codebase: `net.Fetcher` (used by
  all `skills/` scripts) verifies certificates normally via `requests`
  defaults, and `CurlCffiChecker` doesn't override `curl_cffi`'s default
  verification either. Only this one backend opts out, silently.

If this was added to work around a specific WAF/site with a broken cert
chain, it should be scoped to that case (or at least be an opt-in flag),
not the default for every request the tool makes.

### 5. `stem` missing from `pyproject.toml` dependencies (Medium — Packaging)

**Files:** [requirements.txt:9](requirements.txt#L9), [pyproject.toml:10-19](pyproject.toml#L10)

`requirements.txt` lists `stem>=1.8` (used by `ohosint/shell.py`'s `newnym`
command via `stem.control.Controller`), but `pyproject.toml`'s
`[project] dependencies` array doesn't include it. Anyone who installs via
`pip install -e .` (the path the README itself recommends as an alternative
to `requirements.txt`) will not get `stem`, and `newnym` inside `ohosint
shell` will fail with `ImportError` at call time. The two dependency
manifests need to be kept in sync (or one should just `include` the other).

### 6. `ohosint/` is completely undocumented (Low — Docs)

**Files:** `README.md`, `AGENTS.md`

Both files describe the project as: `osint_core` (shared library) +
`skills/` (three thin CLI scripts). That was accurate for the original
project, but `ohosint/` — a 1,200+ line package with its own config model,
async pipelines, rich-table/JSON output, and interactive shell, registered
as the actual `ohosint` console-script — isn't mentioned anywhere. A new
contributor reading the README would not discover that `pip install -e .`
gives them an `ohosint` command at all. **Addressed in the README rewrite
delivered alongside this report.**

### 7. `Dict[str, any]` — builtin `any` used where `typing.Any` was meant (Low — Code quality)

**Files:** [ohosint/config.py:26](ohosint/config.py#L26),
[ohosint/pipelines.py:86,136,183](ohosint/pipelines.py#L86),
[osint_core/exclusions.py:51,54](osint_core/exclusions.py#L51)

```python
identifiers: Dict[str, any] = field(default_factory=dict)   # should be typing.Any
```

Harmless at runtime (Python doesn't enforce annotations), but it's the
wrong symbol — `any` is the builtin boolean-reduction function, not a type.
Any type checker (mypy/pyright) run over this code will flag or misinterpret
these five signatures. Cheap fix: `from typing import Any` and s/any/Any/ at
those five sites.

### 8. Dead filter condition in `generate_candidates()` (Low — Code quality)

**File:** [osint_core/candidates.py:52](osint_core/candidates.py#L52)

```python
return sorted({c for c in out
               if len(c) >= 3 and c.isascii()
               and not re.search(r"^[._-]|[._-]$", c)
               and "[a-zA-Z0-9]" != c and re.fullmatch(r"[a-z0-9._-]+", c)})[:24]
```

`"[a-zA-Z0-9]" != c` compares each candidate to the *literal 12-character
string* `"[a-zA-Z0-9]"`. Since no generated candidate will ever equal that
exact literal, this clause is always `True` and filters nothing — it looks
like a leftover from an attempt to write a regex-based check that was never
finished (the following `re.fullmatch(...)` already does the real
character-class filtering). Not causing incorrect output today, but it's
confusing dead code worth removing or fixing to say what was intended.

### 9. Two parallel probing engines, one mislabeled "deprecated" (Info — Architecture)

**Files:** [osint_core/probe.py:1-9](osint_core/probe.py#L1),
[osint_core/async_check.py](osint_core/async_check.py)

`probe.py`'s module docstring says:

> DEPRECATED: This module is a backward-compatibility shim. New code should
> import directly from `osint_core.async_check`...

But `probe()` is not a legacy shim in practice — it's the only probing
engine `silent_recon.py`, `find_profiles.py`, and `deep_dive.py` (i.e. every
script the current README documents) actually call. Meanwhile
`async_check.py`'s `check_site()`/`check_username_on_sites()` — the "primary
interface going forward" — is what `ohosint` actually uses. Both are live,
both are necessary, and nothing in the repo states an intent to ever
consolidate them or explains why `skills/` wasn't ported to the async
engine. Worth an explicit decision (keep both intentionally, e.g. because
`skills/` is optimized for simplicity and `ohosint` for scale/speed) so the
"DEPRECATED" label doesn't mislead the next contributor into ripping out
code three scripts depend on.

---

## What's solid

- No code duplication between the three `skills/` scripts — genuinely
  factored into `osint_core`, matching the README's stated design goal.
- No hardcoded secrets/credentials anywhere in the tree.
- The passive/GET-only design is followed consistently: no POST to
  login/recovery/OTP endpoints anywhere in the checked paths.
- `MaigretDatabase`/`MaigretSite` cleanly normalize two different upstream
  JSON schemas (Maigret's and Sherlock's) behind one interface.
- The confidence-scoring and pivot-extraction modules
  (`confidence.py`, `pivots.py`) are well-isolated, pure functions with no
  hidden state — easy to unit test if tests get added.
- No syntax errors anywhere; all 27 files parse cleanly.

## Recommendations, in priority order

1. Fix #1 (`dork` crash) and #3 (`autopsy` proxy bypass) — both are
   one-line-scope fixes with outsized user impact (a guaranteed crash, and
   a silent anonymity failure).
2. Fix #2 by either vendoring a small default site list `ohosint` can use
   with zero optional deps, or — at minimum — making `sites`/`email`/`username`
   fail loudly ("0 sites loaded — install `maigret` and/or
   `sherlock_project`") instead of silently returning empty results.
3. Scope or remove the blanket `CERT_NONE` in `AiohttpChecker` (#4).
4. Sync `requirements.txt` and `pyproject.toml` (#5).
5. Low-priority cleanup: #7, #8, and a decision + doc comment on #9.
6. This project has no test suite at all (confirmed in `AGENTS.md` and by
   inspection). Given issue #1 and #2 are exactly the kind of thing even a
   handful of smoke tests (`assert dork signature`, `assert load_site_databases
   raises/warns loudly when empty`) would have caught before they shipped,
   a minimal pytest suite covering the pure-logic modules (`candidates.py`,
   `pivots.py`, `confidence.py`, `patterns.py`, `site_db.py` parsing) would
   be high-value for relatively low effort.

None of the above were fixed as part of this audit — this is a read-only
report. Say the word if you'd like any of these patched.
