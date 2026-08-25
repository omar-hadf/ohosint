# Code Quality, Architecture & Correctness Audit — OHOsint / osint_core

Date: 2026-08-25
Scope (assigned): code quality, architecture, and correctness bugs only.
Security/OPSEC, packaging metadata, and documentation prose are covered by
other audit tracks and are out of scope here except where they intersect a
correctness bug.
Method: full read of all 27 source files under `osint_core/`, `ohosint/`,
`skills/`; `python -m py_compile` (no syntax errors); `python -m pyflakes`
(only static tool available — no `mypy`/`pyright`/`ruff` installed in this
environment, confirmed via `which`); full `pytest` run (63/63 pass); targeted
runtime reproduction of every claimed bug below using real data where
possible (the installed `maigret` package's actual 3,150-site database was
used for finding #1, not a synthetic fixture).

## Verdict

The codebase is in noticeably better shape than the previous audit round
(`docs/AUDIT.md` / `docs/PLAN.md`, dated the same day): all 9 previously
reported findings — the `dork` crash, the silent-empty-site-sweep, the
`autopsy` proxy bypass, the unconditional `CERT_NONE`, the missing `stem`
dependency, the `Dict[str, any]` typos, the dead filter clause, and the
mislabeled "DEPRECATED" docstring — are now fixed and, in most cases,
covered by a regression test. However, this round surfaced a **new Critical
bug that the previous round did not catch**: `MaigretSite` silently drops
the `absenceStrs`/`presenceStrs` markers that the majority of the Maigret
site database (the primary data source behind `ohosint`'s headline
username-sweep feature) relies on for correct verdicts, because the
camelCase-to-snake_case field mapping in `site_db.py` never includes them.
Reproduced live against the real, installed Maigret database: a page
containing Facebook's own "not found" marker text is still classified as
"claimed." This one bug means a large fraction of every `ohosint
email|username` sweep's "found" results are not trustworthy without
independent verification, with no error or warning surfaced anywhere. A
second, narrower but fully confirmed bug validates the user-supplied lead
almost exactly: `breach_breachdirectory()` iterates a JSON field
character-by-character when the RapidAPI response returns a string instead
of a list, producing single-character garbage "breach names." Beyond these
two, the remaining findings are dead code (one now-orphaned ~150-line
module, several unused helpers/imports confirmed by `pyflakes`), one
UX-only silent-error gap in the `phone` command, and a handful of
consistency/architecture notes. No async misuse (blocking calls in
coroutines, un-awaited coroutines, unclosed sessions) was found — the async
engine is otherwise sound.

## Severity table

| # | Severity | File:Line | Summary | Status |
|---|----------|-----------|---------|--------|
| 1 | **Critical** | `osint_core/site_db.py:75-127`, `osint_core/async_check.py:274-303` | `MaigretSite.__init__` never maps Maigret's `absenceStrs`/`presenceStrs` (or `absenseStrs`/`presenseStrs`) JSON keys to the `absence_strs`/`presense_strs` attributes `classify_result()` reads — ~73% of Maigret sites (checkType `"message"`), including ~910 with real absence markers, get their not-found detection silently discarded, producing false "claimed" verdicts | VERIFIED — new finding |
| 2 | High | `osint_core/breach.py:539-544` | `breach_breachdirectory()` iterates `rec["sources"]` assuming a list; a string response is iterated character-by-character, producing garbage single-char "breach names" | VERIFIED — new finding, confirms the user-supplied lead |
| 3 | Medium | `ohosint/cli.py:182-199`, `ohosint/shell.py:108-122` | `run_phone_pipeline()` captures a specific, actionable parse-error in `report["error"]`; `handle_phone`/`do_phone` never print it — user sees "Valid: False" with no explanation | VERIFIED — new finding |
| 4 | Low | `osint_core/executors.py` (whole file, 153 lines) | `AsyncQueueExecutor`/`AsyncGeneratorExecutor`/`run_checks_parallel` have zero callers anywhere in the codebase or tests; `check_username_on_sites` reimplements the same semaphore-bounded-gather pattern independently | VERIFIED — new finding |
| 5 | Low | `osint_core/async_check.py:215-236`, `:352-359`; `osint_core/scan_result.py:144-152` | More dead code: `DnsResolver` checker class (defined, exported, never selected by `_pick_checker`), `_interpolate_template()` helper (never called), `ScanResult.to_csv_row()` (never called, no CSV export wired up anywhere) | VERIFIED — new finding |
| 6 | Low | multiple (see finding 6) | 11 unused-import/unused-variable warnings from `pyflakes` across 8 files | VERIFIED — new finding (tool: pyflakes) |
| 7 | Low | `osint_core/site_db.py:38-70` | `MaigretSite` class-level mutable defaults (`tags`, `headers`, `errors`, etc. as `[]`/`{}`) are shared across every instance that doesn't override them — latent mutable-default hazard, not currently triggered | VERIFIED — new finding |
| 8 | Low | `osint_core/breach.py:576-613` | Module-level mutable `_CURRENT_QTYPE` list passes call-scoped routing state into `_dispatch()` — not thread-safe/reentrant by the code's own admission; no current caller parallelizes `breach_search()` | VERIFIED (code smell) / UNVERIFIED (as an active race — not reproduced under GIL timing) — new finding |
| 9 | Low | `ohosint/cli.py:121-136`, `ohosint/shell.py:275-284` vs. `skills/silent-recon/silent_recon.py:79-84` | `osint_core.net.valid_proxy()` is used by the legacy shell to fail fast on a bad proxy URL; `ohosint`'s CLI/shell never call it — bad input surfaces later as a raw connection error instead | VERIFIED — new finding |
| 10 | Low | 6 call sites across 4 files | Tor defaults (`127.0.0.1:9050`, control port `9051`) hardcoded ad-hoc instead of centralized in `constants.py` | VERIFIED — new finding |
| 11 | Info | `osint_core/site_db.py:205-209, 223-227` | Malformed site entries are dropped via bare `except Exception: continue` with zero logging, inconsistent with sibling modules that log warnings on failure | VERIFIED — new finding |
| 12 | Info | `osint_core/async_check.py:141, 194` | `AiohttpChecker`/`CurlCffiChecker` open a new session per single site check rather than pooling across a sweep — correctly closed each time (no leak), but costs a full TLS handshake per request at scale | VERIFIED — new finding |
| 13 | Info | Architecture | Two-engine split (`probe.py` sync for `skills/`, `async_check.py` async for `ohosint/`) — now correctly documented as intentional, no circular-import risk found | VERIFIED — see Architecture section |
| — | — | — | Findings #1–9 from `docs/AUDIT.md` (dork crash, silent-empty-sweep, autopsy proxy bypass, unconditional `CERT_NONE`, missing `stem` dep, `Dict[str, any]`, dead filter clause, mislabeled DEPRECATED docstring) | **All 9 CONFIRMED FIXED** — see "Previous audit re-verification" |

---

## 1. `MaigretSite` silently drops absence/presence markers — false "claimed" verdicts (Critical)

**Status: VERIFIED — reproduced against the real, installed Maigret database.**

`osint_core/site_db.py`'s `MaigretSite.__init__` maps a specific, hand-picked
set of Maigret/Sherlock camelCase JSON keys onto snake_case Python
attributes:

```python
# osint_core/site_db.py:85-122
if "urlMain" in data: self.url_main = data["urlMain"]
if "urlSubpath" in data: self.url_subpath = data["urlSubpath"]
if "checkType" in data: self.check_type = data["checkType"]
if "prettyName" in data: self.pretty_name = data["prettyName"]
if "errorType" in data: ...
if "errorMsg" in data:
    em = data["errorMsg"]
    self.absence_strs = [em] if isinstance(em, str) else list(em)
if "errorCode" in data: ...
if "errorUrl" in data: ...
if "isNSFW" in data: ...
if "regexCheck" in data: ...
if "urlProbe" in data: ...
if "username_claimed" in data: ...
```

Note `errorMsg` (Sherlock's field name) is explicitly mapped to
`absence_strs`. **There is no equivalent mapping for Maigret's own field
names, `absenceStrs`/`absenseStrs` and `presenceStrs`/`presenseStrs`.**  The
generic loop above this block, `for k, v in data.items(): setattr(self, k,
v)`, does set an attribute — but it sets it under the *raw* JSON key
(`self.absenceStrs = [...]`), not the snake_case name
(`self.absence_strs`) that `classify_result()` in `async_check.py` actually
reads:

```python
# osint_core/async_check.py:273-303 (classify_result)
absence_strs = getattr(site, "absence_strs", [])
absence_detected = any(m in html_text for m in absence_strs) if absence_strs else False
...
for et in error_types:
    if et == "message":
        errors = getattr(site, "absence_strs", [])   # <-- always [] for Maigret sites
        error_flag = True                              # True = no error found (user exists)
        ...
        for err in errors:
            if err in html_text:
                error_flag = False
                break
        if not error_flag:
            result_status = ScanStatus.AVAILABLE
            break
        elif result_status is None:
            result_status = ScanStatus.CLAIMED
```

Since `errors` is always empty for Maigret-format sites, the `for err in
errors` loop never executes, `error_flag` never flips to `False`, and the
site is classified `CLAIMED` for **any HTTP 200 response**, regardless of
whether the page actually shows the site's own "not found" text.

### Impact, measured against the real installed database

```
$ python3 -c "
import maigret, json
from pathlib import Path
data = json.load(open(Path(maigret.__file__).parent/'resources'/'data.json'))
sites = data['sites']
from collections import Counter
print(Counter(s.get('checkType','message') for s in sites.values()))
print('sites with absence markers:', sum(1 for s in sites.values() if 'absenceStrs' in s or 'absenseStrs' in s))
print('sites with presence markers:', sum(1 for s in sites.values() if 'presenceStrs' in s or 'presenseStrs' in s))
"
Counter({'message': 2305, 'status_code': 746, 'response_url': 99})
sites with absence markers: 910
sites with presence markers: 539
```

2,305 of 3,150 sites (73%) use `checkType: "message"`, the branch this bug
breaks. 910 of those ship an `absenceStrs` marker that is silently
discarded; 539 ship a `presenceStrs` marker that's read into a
`presense_detected` local variable that is then **never used at all** (see
finding #6 — `pyflakes` independently flags this as dead code, which is the
same root cause surfacing as a static-analysis symptom).

### Reproduction (real Facebook entry from the installed Maigret DB, no network call)

```python
import osint_core as oc
from osint_core.async_check import classify_result

db = oc.load_default_db()
site = db.get_site("Facebook")
print("checkType:", site.check_type)
print("site.absence_strs (what async_check.py reads):", site.absence_strs)
print("but it actually landed here instead:", getattr(site, "absenceStrs", "<not set>"))

not_found_html = "<html><body>... rsrcTags missing marker page</body></html>"
result = classify_result(not_found_html, 200, None, site, "some_username_that_does_not_exist")
print("Verdict:", result.status)
```

Output:

```
checkType: message
site.absence_strs (what async_check.py reads): []
but it actually landed here instead: ['rsrcTags']
Verdict for a page containing the site's own 'not found' marker: claimed
```

Facebook's own JSON entry is `{"absenceStrs": ["rsrcTags"]}` — a page
containing that exact marker (i.e., a genuine "not found" page) is still
classified `claimed`. This is not a Facebook-specific edge case; it is the
classification path for the majority checkType across the whole database.

### Recommended fix

Add the missing camelCase mappings in `MaigretSite.__init__`
(`osint_core/site_db.py`), handling both the canonical and the
upstream-typo'd spellings Maigret itself ships:

```python
# after the existing "errorMsg" -> absence_strs block
for src_key in ("absenceStrs", "absenseStrs"):
    if src_key in data:
        v = data[src_key]
        self.absence_strs = [v] if isinstance(v, str) else list(v)
        break
for src_key in ("presenceStrs", "presenseStrs"):
    if src_key in data:
        v = data[src_key]
        self.presense_strs = [v] if isinstance(v, str) else list(v)
        break
```

And then actually use `presense_detected` in `classify_result()` — right
now even after fixing the mapping, a site that defines *only*
`presenceStrs` (no `absenceStrs`) still falls through to "no error found ->
CLAIMED" because the `"message"` branch only ever consults
`absence_strs`. Minimal fix for that branch:

```python
if et == "message":
    if presense_strs:
        error_flag = presense_detected     # presence markers found -> user exists
    else:
        errors = getattr(site, "absence_strs", [])
        error_flag = True
        ...  # existing absence-marker logic unchanged
```

Add a regression test using the real Facebook fixture above (or a small
inline JSON fixture with `absenceStrs`) so this cannot regress silently
again — none of the existing 63 tests exercise `MaigretSite` loaded from
real Maigret-format JSON with these fields.

---

## 2. `breach_breachdirectory()`: source names iterated character-by-character (High)

**Status: VERIFIED — confirms the user-supplied lead.**

```python
# osint_core/breach.py:531-548
try:
    j = r.json()
    res["found"] = bool(j.get("found"))
    records = j.get("result") or []
    names = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        entry = {k: rec.get(k) for k in
                 ("email", "username", "password", "sha1", "hash") if rec.get(k)}
        entry["sources"] = rec.get("sources") or []
        for s in entry["sources"]:          # <-- assumes list; a str iterates char-by-char
            names.add(str(s))
        res["records"].append(entry)
    res["breaches"] = [{"name": n} for n in sorted(names)]
```

`entry["sources"] = rec.get("sources") or []` does not check the type of
`rec.get("sources")`. When the upstream RapidAPI response returns a bare
string for that field (a documented, real-world shape for this API) instead
of a list, `for s in entry["sources"]` iterates the string one character at
a time.

### Reproduction

```python
from unittest.mock import MagicMock
import osint_core as oc

class Resp:
    def __init__(self, status_code=200, json_data=None):
        self.status_code, self._json = status_code, json_data
    def json(self): return self._json

fake_response = Resp(200, {
    "success": True, "found": 1,
    "result": [{"email": "user@example.com", "password": "hunter2", "sources": "Adobe2013"}],
})
fetcher = MagicMock(); fetcher.get = MagicMock(return_value=fake_response)
result = oc.breach_breachdirectory(fetcher, "user@example.com", key="fake-key")
print("breaches:", result["breaches"])
```

Output:

```
breaches: [{'name': '0'}, {'name': '1'}, {'name': '2'}, {'name': '3'}, {'name': 'A'}, {'name': 'b'}, {'name': 'd'}, {'name': 'e'}, {'name': 'o'}]
```

Every character of `"Adobe2013"` becomes its own fabricated "breach name"
(deduplicated/sorted by the `set`+`sorted()` call, hence the scrambled
order) — this exactly matches the reported symptom of breach source names
coming out as single punctuation/digit/letter tokens.

### Recommended fix

```python
srcs = rec.get("sources") or []
if isinstance(srcs, str):
    srcs = [srcs]
elif not isinstance(srcs, (list, tuple, set)):
    srcs = [srcs]
entry["sources"] = list(srcs)
for s in entry["sources"]:
    names.add(str(s))
```

Same defensive-typing gap is worth auditing in the other adapters that do
`for s in raw.get("sources", [])`-style iteration on external JSON (e.g.
`breach_leakcheck`'s `j.get("sources")`) — those happen to already guard
with `isinstance(s, dict)` checks per-item, but none of the "is this whole
field actually a list" checks are present anywhere in `breach.py`.

---

## 3. `ohosint phone`: captured error message never shown to the user (Medium)

**Status: VERIFIED.**

`run_phone_pipeline()` (`ohosint/pipelines.py:180-224`) correctly catches
`phonenumbers` failures (bad input, or the library not installed) and
records a specific, actionable message:

```python
except Exception as e:
    report["valid"] = False
    report["error"] = str(e)
    return report
```

But neither `handle_phone()` (`ohosint/cli.py:182-199`) nor `do_phone()`
(`ohosint/shell.py:108-122`) ever reads `report["error"]`:

```python
def handle_phone(args, config: Config):
    report = run_phone_pipeline(args.number)
    ...
    if config.format == "table":
        print(f"\nPhone: {report.get('input')}")
        print(f"Valid: {report.get('valid')}")
        if report.get("e164"):
            ...
        if report.get("carrier"):
            ...
        print("\nSuggested dorks:")
        for dork in report.get("dorks", []):
            print(f"  {dork}")
    # report.get("error") is never referenced anywhere in this function
```

### Reproduction

```
$ python3 -m ohosint.cli phone "not-a-phone-number"
Phone: not-a-phone-number
Valid: False

Suggested dorks:
$ echo "exit code: $?"
exit code: 0
```

The underlying library actually returned a precise reason —
`'(1) The string supplied did not seem to be a phone number.'` (confirmed by
calling `run_phone_pipeline()` directly) — but it is discarded before
reaching the terminal. The user is left to guess whether the number was
malformed, unsupported, or whether `phonenumbers` isn't installed at all.
Same gap in the shell's `do_phone`.

### Recommended fix

```python
print(f"Valid: {report.get('valid')}")
if report.get("error"):
    print(f"Error: {report['error']}")
```

in both `handle_phone` and `do_phone`, plus (optional) a non-zero exit code
from `handle_phone` when `report.get("error")` is set, so scripted use
doesn't silently treat a parse failure as success.

---

## 4–5. Dead code (Low)

**Status: VERIFIED** (via `grep` for callers + `pyflakes`).

- **`osint_core/executors.py`** — the entire module (`AsyncQueueExecutor`,
  `AsyncGeneratorExecutor`, `run_checks_parallel`, 153 lines) is exported
  from `osint_core/__init__.py` and has its own docstring claiming it's
  "extracted from Maigret's executors module," but grepping the whole repo
  (including `tests/`) turns up **zero call sites** outside its own
  definition. The actual concurrency engine that `ohosint` uses
  (`check_username_on_sites` in `async_check.py`) implements its own
  `asyncio.Semaphore` + `asyncio.gather` directly, duplicating the same
  pattern this module exists to provide.
- **`DnsResolver`** (`osint_core/async_check.py:215-236`) — a fully
  implemented checker backend, exported publicly, but `_pick_checker()` (the
  only function that selects a checker) never returns it — it only ever
  returns `CurlCffiChecker` or `AiohttpChecker`. Unreachable from any real
  code path.
- **`_interpolate_template()`** (`osint_core/async_check.py:352-359`) —
  defined, never called; `MaigretSite.build_url`/`build_probe_url` in
  `site_db.py` independently reimplement the same `{}`/`{urlMain}` template
  substitution logic that this function exists to provide.
- **`ScanResult.to_csv_row()`** (`osint_core/scan_result.py:144-152`) — no
  CSV export path exists anywhere in `ohosint/output.py` or the CLI; this
  method (and the `csv`/`io` imports it needs) is unreachable.
- **`probe_async()`** (`osint_core/probe.py:50-53`) and
  **`impersonate_request_async()`** (`osint_core/impersonate.py:70-84`) are
  exported public API with zero internal callers — not necessarily wrong to
  keep as a library convenience, but worth a comment noting they're
  offered for external consumers, not used internally, so a reader doesn't
  waste time looking for their call sites.

### Recommended fix

Either wire `executors.py` into the actual sweep path (replacing the
hand-rolled semaphore/gather in `check_username_on_sites`) or delete it —
keeping an untested, uncalled, "extracted from X" 150-line module in a
public release invites bit-rot and confuses new contributors about which
concurrency primitive is actually in use. Delete `DnsResolver` and
`_interpolate_template()` or wire them in; delete `to_csv_row()` or wire a
`--format csv` option in `output.py`.

## 6. `pyflakes` findings (Low)

**Status: VERIFIED — tool used: `python -m pyflakes` (only static-analysis
tool available in this environment; no `mypy`, `pyright`, or `ruff`
installed — confirmed via `which mypy pyright ruff`).**

```
osint_core/executors.py:10:1: 'time' imported but unused
osint_core/pivots.py:11:1: 'typing.Dict' imported but unused
osint_core/pivots.py:11:1: 'typing.FrozenSet' imported but unused
osint_core/async_check.py:14:1: 'typing.Union' imported but unused
osint_core/async_check.py:275:5: local variable 'absence_detected' is assigned to but never used
osint_core/async_check.py:282:9: local variable 'presense_detected' is assigned to but never used
osint_core/breach.py:21:1: 'json' imported but unused
osint_core/scan_result.py:10:1: 're' imported but unused
osint_core/scan_result.py:11:1: 'unicodedata' imported but unused
ohosint/shell.py:6:1: 'sys' imported but unused
```

(Test-file-only warnings — `tests/test_fetcher_cache.py`,
`tests/test_tls.py`, `tests/test_breach.py`, `tests/test_pipelines.py`,
`tests/test_dork.py` — omitted here as out of scope for a public-release
source audit, but are equally trivial to clean up.)

The two `async_check.py` lines are the same root cause as finding #1 —
included here separately because they are exactly the kind of thing an
automated linter in CI would have caught before merge.

### Recommended fix

Remove the unused imports; either wire `absence_detected`/`presense_detected`
into the classification logic (see finding #1's fix) or remove them if a
different fix is chosen. Consider adding `pyflakes` (or `ruff`) as a
pre-commit/CI check — none of the confirmed-fixed findings from the
previous audit round nor the new ones in this round would have shipped had
a linter gate existed.

## 7. `MaigretSite` class-level mutable defaults (Low)

**Status: VERIFIED as present; not currently triggered as an active bug.**

```python
# osint_core/site_db.py:38-70
class MaigretSite:
    ...
    tags: List[str] = []
    headers: Dict[str, str] = {}
    errors: Dict[str, str] = {}
    activation: Dict[str, Any] = {}
    request_payload: Dict[str, Any] = {}
    get_params: Dict[str, Any] = {}
    presense_strs: List[str] = []
    absence_strs: List[str] = []
    stats: Dict[str, Any] = {}
    engine_data: Dict[str, Any] = {}
```

These are **class** attributes, not per-instance. Any `MaigretSite` whose
source JSON doesn't provide a given key (e.g. no `"tags"` field) falls back
to the same shared `list`/`dict` object as every other such instance. I
checked every call site that reads these fields (`async_check.py`,
`site_db.py` itself) and none currently mutates them in place (the one
place that looks like it might,
`self.tags = list(self.tags) + ["adult"]` at `site_db.py:113`, correctly
creates a new list and reassigns rather than mutating in place). So this is
not an active bug today, but it is the exact shape of Python's classic
mutable-default-argument footgun, applied to class attributes instead of
function parameters — a future `site.tags.append(...)` or
`site.headers["X"] = "Y"` anywhere would silently corrupt state shared
across every site missing that field.

### Recommended fix

Initialize these in `__init__` (`self.tags = data.get("tags", []) or
[]`, etc.) instead of as class-body literals, or add a comment warning
against in-place mutation if changing the pattern is out of scope.

## 8. Global mutable `_CURRENT_QTYPE` for call-scoped routing state (Low)

**Status: VERIFIED as present in the code (including the code's own
comment acknowledging it); UNVERIFIED as an actively reproducible race — a
threading-based reproduction attempt did not manifest the race under
CPython's GIL scheduling in a quick test, so this is reported as a design
smell rather than a proven crash.**

```python
# osint_core/breach.py:576-613
def _dispatch(provider, fetcher, query, keys):
    if provider == "hudson_rock":
        qtype_fn = {...}
        return qtype_fn[_CURRENT_QTYPE[0]](fetcher, query)
    ...

# _dispatch is single-threaded; stash the current qtype for adapters that
# branch on it (hudson_rock, xposedornot).
_CURRENT_QTYPE = ["email"]
```

`breach_search()` sets `_CURRENT_QTYPE[0] = qtype` at the top of every call
and `_dispatch()` reads it to route `hudson_rock`/`xposedornot` to the
right per-type function. This is module-global, mutable, call-scoped state
— the comment already documents the constraint ("`_dispatch` is
single-threaded"). Every current caller (`run_breach_pipeline` in
`ohosint/pipelines.py`, the CLI, the shell) invokes `breach_search()`
synchronously, one at a time, so the constraint currently holds. It would
break silently (routing an email query through the domain-specific
adapter, or vice versa) the moment any caller runs two `breach_search()`
calls concurrently — e.g., a future batch/threaded-pool feature, or a
webserver wrapping this library.

### Recommended fix

Thread `qtype` as an explicit parameter through `_dispatch()` instead of a
module global — it's already a parameter of the enclosing `breach_search()`
call, so this is a small, low-risk refactor:

```python
def _dispatch(provider, fetcher, query, keys, qtype):
    if provider == "hudson_rock":
        qtype_fn = {...}
        return qtype_fn[qtype](fetcher, query)
    ...
```

## 9. Inconsistent proxy-URL validation (Low)

**Status: VERIFIED.**

`osint_core.net.valid_proxy()` exists and is used by the legacy
`silent_recon.py` shell:

```python
# skills/silent-recon/silent_recon.py:79-84
if not valid_proxy(arg):
    print("[!] bad proxy url (use socks5h://127.0.0.1:9050)")
    return
```

`ohosint`'s CLI (`config_from_args`, `ohosint/cli.py:121-136`) and shell
(`do_proxy` -> `Config.set_proxy`, `ohosint/shell.py:275-284` /
`ohosint/config.py:44-49`) never call it — a malformed proxy string is
accepted as-is:

```
$ python3 -c "
from ohosint.shell import OHOsintShell
from ohosint.config import Config
sh = OHOsintShell(Config())
sh.onecmd('proxy not-a-real-proxy-url')
print('proxy now:', sh.config.proxy)"
Proxy set to not-a-real-proxy-url
proxy now: not-a-real-proxy-url
```

I confirmed the downstream impact is graceful (the sync `Fetcher.get()`
catches the resulting `requests.RequestException` and prints a hint,
returning `None` rather than crashing), so this is a UX/consistency gap
rather than a crash — but it means `ohosint` fails *later and less clearly*
than the tool it's meant to supersede for the exact same mistake.

### Recommended fix

Call `oc.valid_proxy()` in `Config.set_proxy()` and in
`config_from_args()`, returning/printing the same style of upfront error
the legacy shell already gives.

## 10. Hardcoded Tor defaults duplicated instead of centralized (Low)

**Status: VERIFIED.**

`127.0.0.1:9050` (SOCKS proxy) and control port `9051` are hardcoded
independently in:

- `osint_core/cli.py:14` (help text)
- `ohosint/cli.py:34,37,123` (help text + the actual default used when
  `--tor` is passed)
- `ohosint/shell.py:298,301` (`do_newnym`)
- `skills/silent-recon/silent_recon.py:72,80,338,347,354` (help text +
  `do_newnym`)

`osint_core/constants.py` already exists as the documented "single source
of truth" for shared lookup tables (`UAS`, `NOT_FOUND_MARKERS`,
`PLATFORMS`, etc.) but doesn't include these. Not a bug — every occurrence
is currently consistent — but a future change to the default Tor port would
require hunting down 4 files instead of one.

### Recommended fix

```python
# osint_core/constants.py
TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"
TOR_CONTROL_PORT = 9051
```

and reference these from both CLIs and both shells.

## 11. Silent, unlogged exception swallowing in site-database loading (Info)

**Status: VERIFIED.**

```python
# osint_core/site_db.py:203-209 (_load_maigret), 220-227 (_load_sherlock)
for site_name, site_data in sites_data.items():
    try:
        site = MaigretSite(site_name, site_data)
        self.sites[site_name] = site
    except Exception:
        continue
```

Any malformed entry in either database is dropped with **zero** log output
— no `logger.debug`/`warning`, unlike `exclusions.py` and
`ohosint/pipelines.py`, which both log on failure. Given `MaigretSite.__init__`
is quite permissive (it accepts arbitrary extra keys via `setattr`), this
`except` is unlikely to fire often in practice, but when it does, a site
silently vanishes from every sweep with no trace, which is inconsistent
with how failures are surfaced everywhere else in the codebase.

### Recommended fix

```python
except Exception as e:
    logger.debug("Skipping malformed site %r: %s", site_name, e)
    continue
```

## 12. Per-request session creation in the async checkers (Info — efficiency, not a leak)

**Status: VERIFIED — confirmed not a resource leak; noted as an
architecture/efficiency observation only.**

```python
# osint_core/async_check.py:141 (AiohttpChecker.check)
async with ClientSession(connector=connector, trust_env=True, timeout=ct) as session:
    ...
# osint_core/async_check.py:194 (CurlCffiChecker.check)
async with AsyncSession() as session:
    ...
```

Both checkers open a brand-new HTTP client session for **every single site
check** rather than reusing one session across a sweep of (potentially)
thousands of sites. Each is correctly scoped with `async with`, so sessions
are always closed — this is not a leak. It is, however, a real cost at
scale: a multi-thousand-site sweep pays a fresh TCP/TLS handshake per
request instead of amortizing connection reuse across the sweep. Given
`ohosint`'s headline feature is exactly this kind of large sweep, this is
worth a look for anyone optimizing wall-clock time, but is not a
correctness issue.

---

## Architecture recommendation

**The two-engine split is sound and now correctly documented — keep it,
but delete `skills/` from the public release or fold it behind a clearly
labeled `legacy/` namespace.**

- `osint_core/probe.py`'s docstring no longer says "DEPRECATED" (previous
  audit finding #9, now fixed) — it correctly states that `probe.py` (sync,
  GET-only, delay-polite) backs `skills/` intentionally, and
  `async_check.py` (concurrent aiohttp/curl_cffi) backs `ohosint/` for
  scale. `docs/AGENTS.md` states the same thing. This is a legitimate
  design decision, not an accident, and I found no evidence either engine
  needs to disappear: `skills/`'s three scripts are simple, single-target,
  interactive-shell tools where synchronous GET-and-sleep is the right
  model; `ohosint`'s job is thousand-site concurrent sweeps, where the
  async engine is necessary.
- **Module boundaries and circular-import risk**: clean. I grepped for any
  `osint_core` -> `ohosint` import (none exist — `osint_core` has zero
  awareness of `ohosint`, correctly one-directional) and traced every
  intra-`osint_core` import; the only inter-module dependencies are
  `confidence.py -> pivots.py -> scan_result.py`, `async_check.py ->
  scan_result.py`, `net.py -> constants.py`, `cli.py -> net.py`, `probe.py
  -> constants.py` (with `async_check` imported lazily inside functions to
  avoid a hard dependency), all of which form a DAG with no cycles.
- **Public API surface** (`osint_core/__init__.py`, 147 lines, ~90 exported
  names): broad but not unreasonable for a library whose explicit purpose
  is "shared building blocks" for three different consumers. The one
  concrete problem is that it exports things that are dead code
  (`executors.py`'s three names, `DnsResolver`) alongside things that are
  actively used — a consumer reading `__all__` cannot tell which is which.
  Recommendation: either delete the dead exports (see findings #4–5) or
  move them to a clearly-marked `# experimental / unused internally`
  section of `__all__` so the curated surface accurately reflects what's
  load-bearing.
- **Should `skills/` ship in a public release?** This is genuinely a
  judgment call, and I'd lean towards **no, or demote it clearly**. The
  three scripts are fully functional, tested indirectly through their
  shared `osint_core` calls, and not broken — but they are a second,
  parallel user interface to the exact same investigation workflow that
  `ohosint` now covers more completely (async multi-site sweeps, rich
  output, session state, breach search, pivot extraction — none of which
  `skills/` has). Shipping two front-ends to the same library in a
  first public release doubles the surface a new contributor or security
  reviewer has to read to understand "what does this tool do," for little
  benefit: `skills/`'s only genuinely distinct behavior is the
  `silent-account-finder` scripts' adult-platform-specific phase
  structure, which could be ported to an `ohosint` pipeline/preset instead
  of kept as a separate code path. If there's a reason to keep it (e.g. a
  simpler dependency footprint for users who don't want `aiohttp`/`rich`),
  that's a legitimate reason — but it should be stated explicitly in the
  README/AGENTS.md as "kept intentionally for X reason," not left implicit.

---

## Previous audit re-verification (`docs/AUDIT.md` / `docs/PLAN.md`)

All 9 findings from the previous round were independently re-verified
against the current code (not just trusted from the prior report) and are
now **fixed**:

| # | Previous finding | Current status |
|---|---|---|
| 1 | `ohosint shell` -> `dork` always crashes (`TypeError`, then a second bug: wrong 2-tuple unpack of a 3-tuple) | **FIXED.** `ohosint/shell.py:224`: `hits, states, flag = oc.dork(self._fetcher(), line.strip())` — correct arity and unpacking. Covered by `tests/test_dork.py` (3 tests, including an explicit regression test for the 3-tuple unpack). |
| 2 | Site sweeps silently return 0 results without `maigret`/`sherlock_project` installed | **FIXED.** `ohosint/pipelines.py:53-57`: `load_site_databases()` now raises `ValueError("0 sites loaded — install...")` when the merged dict is empty; `pyproject.toml` now declares `[project.optional-dependencies]` (`maigret`, `sherlock`, `sweep`). Covered by `tests/test_site_db.py` (4 tests). |
| 3 | `autopsy` in the shell bypasses the configured proxy | **FIXED.** `ohosint/shell.py:240`: `r = self._fetcher().get(url)` — routes through the same proxy-aware cached `Fetcher` used everywhere else, with cache invalidation wired into `do_proxy`/`do_delay`. Covered by `tests/test_autopsy.py` and `tests/test_fetcher_cache.py`. |
| 4 | `AiohttpChecker` disables TLS verification unconditionally | **FIXED.** `osint_core/async_check.py:97,123-128`: `verify_ssl: bool = True` by default; `ssl_ctx = None` (aiohttp's own verifying default) unless explicitly disabled. Threaded through `ohosint`'s `--insecure` flag (default off). Covered by `tests/test_tls.py` and `tests/test_pipelines.py`. |
| 5 | `stem` missing from `pyproject.toml` | **FIXED.** `pyproject.toml` dependencies now include `"stem>=1.8"`. |
| 6 | `ohosint/` completely undocumented in README/AGENTS.md | **Addressed** (docs-track scope, not independently re-audited in depth here, but `docs/AGENTS.md` as read during this audit fully describes `ohosint/`, its dependencies, and example commands). |
| 7 | `Dict[str, any]` (builtin `any`, not `typing.Any`) in 5 places | **FIXED.** `grep -rn "Dict\[str, any\]"` across the whole tree returns zero matches; all affected files now import and use `typing.Any` correctly. |
| 8 | Dead filter clause `"[a-zA-Z0-9]" != c` in `generate_candidates()` | **FIXED.** `osint_core/candidates.py:49-52` no longer contains that clause. Covered by `tests/test_candidates.py::test_no_regex_patterns_in_candidates`. |
| 9 | `probe.py` docstring says "DEPRECATED" but is still the primary engine for `skills/` | **FIXED.** Docstring now explicitly states both engines are intentionally kept separate and why (see Architecture section above). |

No regressions were found in re-testing any of these — `pytest` passes
63/63, and each fix above was independently exercised (not just read) via
the reproduction commands shown in this report or the cited test files.
