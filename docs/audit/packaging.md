# Packaging, Dependencies, Build & CI/Release Readiness Audit

**Project:** OHOsint (distribution name `osint-core`)
**Scope:** `pyproject.toml`, `requirements.txt`, dependency reconciliation, optional
extras, build output, entry point, reproducibility posture, GitHub scaffolding,
test/lint config. Source-code security, code style, and documentation prose are
explicitly out of scope (covered by other audits — see `docs/AUDIT.md` for the
existing code-level findings, several of which are cross-referenced below where
they intersect with packaging).
**Method:** static reconciliation of every `import`/`from` statement against
declared dependencies; a real isolated `python -m build --no-isolation` into the
scratch directory with inspection of the resulting sdist/wheel; `pip download
--no-deps` of both optional extras into the scratch directory to confirm they
resolve on PyPI; `importlib.metadata` inspection of installed license metadata;
a full `pytest` run. No file in the project was modified; no `git` command was
run; nothing was installed into the ambient environment (the extras that appear
already installed — `maigret`, `sherlock-project` — pre-existed in this
environment before the audit started).

## Verdict

The package is fundamentally soundly built — `python -m build` succeeds cleanly,
the wheel contains exactly the two intended packages with no secrets or caches
inside it, the console-script entry point resolves and is callable, and the two
manifests (`pyproject.toml` / `requirements.txt`) are now in sync — but the
project is **not yet safe to `git init && git add . && git push`**: `.gitignore`
has two real gaps (`.pytest_cache/`, and the breach-report filename pattern the
tool itself generates, which the README says can contain real leaked
credentials) that would put junk or sensitive runtime output into the first
commit and its permanent history, there is no `LICENSE` file or license/author/
classifier/URL metadata anywhere (undefined legal status for a public repo),
and there is no CI, lint config, pytest config, or any of the standard GitHub
community-health scaffolding. None of this requires re-architecting anything —
it's all additive, mechanical fixes — but it should happen before, not after,
the first push.

---

## Publish blockers (must-fix before first push)

| # | Finding | Why it blocks | Verified |
|---|---|---|---|
| B1 | `.gitignore` does not exclude `.pytest_cache/` | Currently exists in the tree; `git add .` today would commit it | VERIFIED |
| B2 | `.gitignore` does not exclude the `ohosint_breach_*.json` filename pattern the tool itself writes by default | The tool's own README warns these reports "can return real leaked `email:password` pairs" — first `ohosint breach ... && git add .` with no `--out` would permanently commit real credential material into public git history | VERIFIED |
| B3 | No `LICENSE` file anywhere in the repo | Public GitHub repo with no license file is, by default copyright law, "all rights reserved" — nobody may legally fork, reuse, or contribute to it despite the stated intent to publish it | VERIFIED |
| B4 | `pyproject.toml` has no `license`, `readme`, `authors`, `classifiers`, or `[project.urls]` | PyPI/GitHub metadata is currently empty (confirmed via built `PKG-INFO`: no long description, no license, no author, no links) | VERIFIED |

## Should fix (not blocking, but do before or shortly after first push)

| # | Finding | Verified |
|---|---|---|
| S1 | `alive-progress` is declared in both `requirements.txt` and `pyproject.toml` but never imported anywhere in the source tree | VERIFIED |
| S2 | `maigret`/`sherlock-project` extras are each imported **only** to read one bundled JSON resource file, but pull 44 and 9 direct transitive dependencies respectively (pandas, reportlab, lxml, flask, cloudscraper, xhtml2pdf, pyvis, networkx, …) | VERIFIED |
| S3 | No `.github/workflows/` CI at all | VERIFIED |
| S4 | No `[tool.pytest.ini_options]`, no ruff/black/mypy config anywhere | VERIFIED |
| S5 | No `MANIFEST.in` — sdist ships stray `setup.cfg` (auto-generated, empty) and a duplicate `osint_core.egg-info/` directory | VERIFIED |
| S6 | All dependencies are unpinned floors (`>=`); no lockfile | VERIFIED |
| S7 | Distribution name `osint-core` vs. the actual product/CLI name `ohosint`/`OHOsint` — confusing for anyone trying to find the package | VERIFIED |
| S8 | `stem` (LGPLv3) is the one copyleft dependency among an otherwise MIT/Apache/BSD stack — fine as a normal pip dependency, but worth a one-line NOTICE | VERIFIED |
| S9 | Missing GitHub community-health files: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `.github/ISSUE_TEMPLATE/`, `.editorconfig`, `.pre-commit-config.yaml`, `.github/dependabot.yml` | VERIFIED |
| S10 | `osint_core/site_db.py`'s Sherlock fallback path is hardcoded to `python3.10` (`~/.local/lib/python3.10/site-packages/...`), silently useless on any other interpreter version even though `requires-python = ">=3.10"` allows 3.11/3.12/3.13 | VERIFIED |

---

## 1. `pyproject.toml` correctness

### 1a. Dependency reconciliation (`pyproject.toml` vs `requirements.txt` vs actual imports)

**Evidence.** Full third-party import inventory via:

```
$ grep -rnE '^\s*(import|from)\s+[a-zA-Z_]' ohosint osint_core skills --include='*.py' | grep -v __pycache__
```

Third-party (non-stdlib) names actually imported anywhere in `ohosint/`,
`osint_core/`, or `skills/`: `requests` (net.py, exclusions.py),
`phonenumbers` (pipelines.py, silent_recon.py), `aiohttp` +
`aiohttp.client_exceptions` (async_check.py), `aiohttp_socks` (async_check.py),
`curl_cffi.requests` (async_check.py, impersonate.py), `aiodns`
(async_check.py), `sha3` — provided by `safe-pysha3` (breach.py), `stem.control`
(shell.py), `rich.console`/`rich.table` (output.py), `maigret` (site_db.py, extra),
`sherlock_project` (site_db.py, extra).

`pyproject.toml` `dependencies` and `requirements.txt` are **currently
identical** (diffed byte-for-byte below) — the mismatch a previous audit
(`docs/AUDIT.md` finding #5, dated 2026-08-24) flagged, `stem` missing from
`pyproject.toml`, has already been fixed:

```
$ diff <(grep -oE '"[^"]+>=[^"]+"' pyproject.toml | tr -d '"') requirements.txt
(no output — identical)
```

| Package (declared) | In `requirements.txt` | In `pyproject.toml` | Actually imported | Verdict |
|---|---|---|---|---|
| `requests[socks]` | yes | yes | yes (`net.py`) | OK |
| `phonenumbers` | yes | yes | yes | OK |
| `aiohttp` | yes | yes | yes | OK |
| `aiohttp-socks` | yes | yes | yes | OK |
| `aiodns` | yes | yes | yes | OK |
| `curl_cffi` | yes | yes | yes | OK |
| `alive-progress` | yes | yes | **no** — zero hits anywhere, including `skills/` and docs | **declared-but-unused (S1)** |
| `rich` | yes | yes | yes | OK |
| `stem` | yes | yes | yes | OK |
| `safe-pysha3` | yes | yes | yes (as `sha3`) | OK |
| `maigret` (extra) | — | yes (extra) | yes, extra-gated | OK, but see S2 |
| `sherlock-project` (extra) | — | yes (extra) | yes, extra-gated | OK, but see S2 |

**No used-but-undeclared dependencies were found.** No version-floor mismatches
between the two manifests were found (they are identical).

**S1 — `alive-progress` is dead weight. Evidence:**

```
$ grep -rniI "alive" . --include='*.py' --include='*.md' --include='*.toml' --include='*.txt'
pyproject.toml:17:    "alive-progress>=3.0",
requirements.txt:7:alive-progress>=3.0
docs/AGENTS.md:10:...`alive-progress`, `rich`, `stem`
```

No `.py` file imports it. `osint_core/executors.py`'s own docstring says its
progress machinery was "*Extracted from Maigret's* [async queue runner]" —
`alive_progress` is almost certainly a leftover from that extraction (Maigret's
own `pyproject.toml` genuinely depends on `alive_progress>=3.2.0,<4.0.0` — see
§2). This project's actual progress reporting is a plain `print()` callback
(`ohosint/cli.py:205`, `ohosint/shell.py:133,200`), not `alive_progress`.

**Recommended fix:** remove `"alive-progress>=3.0"` from both `pyproject.toml`
and `requirements.txt`, or wire it up if a progress bar is genuinely wanted.

### 1b. `requires-python` vs. syntax actually used

**Evidence:**

```
$ grep -rnE '(->|\:)\s*[A-Za-z_][A-Za-z0-9_.\[\], ]*\s*\|\s*[A-Za-z_]' ohosint osint_core skills --include='*.py'
osint_core/patterns.py:42:    def parse_number(self) -> int | None:

$ grep -rnE '^\s*(match|case)\s' ohosint osint_core skills --include='*.py'
(no true match-statements found; one false positive is a local variable named
`match` at osint_core/pivots.py:256, not a match-statement)

$ grep -rn "tomllib" ohosint osint_core skills --include='*.py'
(no output)

$ grep -rn "except\*" ohosint osint_core skills --include='*.py'
(no output)
```

`osint_core/patterns.py:42` uses the PEP 604 `int | None` union syntax, which
requires Python **3.10+** — this is real, load-bearing evidence for the
declared `requires-python = ">=3.10"` floor. No `match`/`case` statements, no
`tomllib` (3.11+), no `except*` (3.11+), and no PEP 585 builtin-generic
annotations that would need a higher floor were found. **`requires-python =
">=3.10"` is correctly set — neither too loose nor unnecessarily strict.**
VERIFIED.

### 1c. Missing metadata for a public release

**Evidence** — the entire current `[project]` table:

```toml
[project]
name = "osint-core"
version = "0.1.0"
description = "Shared building blocks for the passive-OSINT skills (net, search, probe, sources, candidates)."
requires-python = ">=3.10"
dependencies = [ ... ]
```

No `license`, `readme`, `authors`, `keywords`, `classifiers`, or
`[project.urls]`. Confirmed by inspecting the actual built metadata:

```
$ python -m build --no-isolation --outdir <scratch> .
$ cat osint_core.egg-info/PKG-INFO
Metadata-Version: 2.4
Name: osint-core
Version: 0.1.0
Summary: Shared building blocks for the passive-OSINT skills ...
Requires-Python: >=3.10
Requires-Dist: requests[socks]>=2.28
...
Provides-Extra: sweep
Requires-Dist: sherlock-project; extra == "sweep"
```

No `License:`, no `Author:`, no `Home-page:`/`Project-URL:`, no `Description:`
(the 12.7KB `README.md` is never embedded — `readme` isn't set) — a `pip
install osint-core` or a PyPI listing today would show a one-line summary and
nothing else. VERIFIED.

**Recommended fix** — add to `pyproject.toml`:

```toml
[project]
name = "osint-core"
version = "0.1.0"
description = "Shared building blocks for the passive-OSINT skills (net, search, probe, sources, candidates)."
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
authors = [
    { name = "<your name or handle>", email = "<a public-facing contact address>" },
]
keywords = ["osint", "recon", "cli", "security", "privacy", "tor", "username-search", "breach-search"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Environment :: Console",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
    "Topic :: Internet",
]
dependencies = [
    "requests[socks]>=2.28",
    "phonenumbers>=8.13",
    "aiohttp>=3.9",
    "aiohttp-socks>=0.8",
    "aiodns>=3.2",
    "curl_cffi>=0.5",
    "rich>=13.0",
    "stem>=1.8",
    "safe-pysha3>=1.0.4",
]

[project.urls]
Homepage = "https://github.com/<owner>/<repo>"
Repository = "https://github.com/<owner>/<repo>"
Issues = "https://github.com/<owner>/<repo>/issues"
```

Note: `authors[].email` is intentionally left as a placeholder above — a
personal email address baked into public PyPI metadata gets scraped
aggressively; for a security/OSINT-adjacent project many maintainers prefer a
GitHub no-reply address (`<id>+<user>@users.noreply.github.com`) or omit the
email entirely. The `license = { text = "MIT" }` classic form is used rather
than PEP 639's `license = "MIT"` SPDX-expression form because the latter
requires a newer `setuptools` than the `>=64` floor currently pinned in
`[build-system]`; if you bump that floor to `setuptools>=70`, switch to the
SPDX form and drop the redundant `License ::` classifier (mixing both is
deprecated).

### 1d. `[tool.setuptools] packages` coverage

**Evidence:**

```toml
[tool.setuptools]
packages = ["osint_core", "ohosint"]
```

```
$ python -m zipfile -l osint_core-0.1.0-py3-none-any.whl
ohosint/__init__.py ... ohosint/shell.py (6 files)
osint_core/__init__.py ... osint_core/sources.py (18 files)
osint_core-0.1.0.dist-info/...
```

All 6 `ohosint/*.py` files and all 18 `osint_core/*.py` files are present in
the built wheel — every importable module is covered. VERIFIED — no gap.

`skills/` is correctly **not** a package (no `__init__.py`, and its scripts are
designed to be run directly from a repo checkout — the two `SKILL.md` files
describe them as [Claude Code
Skills](https://docs.claude.com/), which are consumed from a filesystem path,
not `pip install`ed) and is correctly omitted from both `packages` and the
built artifacts (confirmed absent from both sdist and wheel — see §3). This is
sensible as-is; the only action item is to say so explicitly, since a
newcomer inspecting `pyproject.toml` alone has no way to tell "skills/ was
deliberately left out" from "skills/ was forgotten." Add a one-line comment:

```toml
[tool.setuptools]
# skills/ is intentionally NOT packaged: its scripts (silent_recon.py,
# find_profiles.py, deep_dive.py) are Claude Code Skills, run from a repo
# checkout by path, not imported as a library. See skills/*/SKILL.md.
packages = ["osint_core", "ohosint"]
```

---

## 2. Optional extras (`maigret`, `sherlock`, `sweep`)

**Evidence — both extras resolve on PyPI**, downloaded (not installed) into the
scratch directory with `--no-deps`:

```
$ pip download --no-deps -d <scratch>/extras_download maigret sherlock-project
Collecting maigret
  Downloading maigret-0.6.4-py3-none-any.whl (312 kB)
Collecting sherlock-project
  Using cached sherlock_project-0.16.0-py3-none-any.whl (36 kB)
Successfully downloaded maigret sherlock-project
```

Both extras resolve cleanly. VERIFIED.

**Transitive weight** (`importlib.metadata` `Requires-Dist` on the versions
already present in this dev environment — `maigret==0.6.0`,
`sherlock-project==0.16.0`; the freshly downloaded `maigret==0.6.4` will be
similar):

- `maigret`: **44 direct dependencies**, including `pandas`-adjacent-weight
  packages: `reportlab`, `lxml`, `flask[async]`, `cloudscraper`, `xhtml2pdf`,
  `pyvis`, `networkx`, `PyPDF2`, `XMind`, `arabic-reshaper`, `python-bidi`.
- `sherlock-project`: **9 direct dependencies**, including `pandas>=2.2` and
  `openpyxl` (Excel export support sherlock-project doesn't need for this
  project's use case).

**Critical finding — both extras are installed for a single `.__file__` lookup.**
Evidence, the complete set of usages of either module anywhere in the codebase:

```
$ grep -rn "^import maigret\|^import sherlock_project\|maigret\.\|sherlock_project\." osint_core ohosint --include='*.py'
osint_core/site_db.py:274:        db_path = Path(maigret.__file__).parent / "resources" / "data.json"
osint_core/site_db.py:286:        db_path = Path(sherlock_project.__file__).parent / "resources" / "data.json"
```

That is the entire interaction with both packages: `import maigret` /
`import sherlock_project` purely to locate where pip put them on disk, then
read one static `resources/data.json` file out of each. None of maigret's or
sherlock-project's actual code — their HTTP checking engines, their CLI, their
PDF/XMind/graph export, `pandas`, `flask`, `reportlab`, etc. — is ever called.
Installing the `sweep` extra pulls in on the order of 50+ transitive packages
(several with compiled/binary wheels) to obtain two JSON files that together
are a few megabytes. VERIFIED.

**Recommended fix (should-fix, not blocking):** vendor a periodically-refreshed
snapshot of each site database as a static JSON file inside `osint_core/data/`
(both source projects are MIT-licensed — see below — so redistributing their
data file with attribution is permitted), and drop `maigret`/`sherlock-project`
as runtime dependencies entirely, or keep them only as an *optional* "get the
freshest possible site list" extra rather than the only path to a non-empty
site database. This also sidesteps S10 (the hardcoded `python3.10` fallback
path) and removes the entire dependency-confusion issue below.

**Core functionality silently degrades to zero results when both extras are
absent — corroborated independently.** This was already identified in
`docs/AUDIT.md` (finding #2, High severity) as a source-code/UX issue; from
the packaging side, the mechanism is exactly the extras split described above:
`osint_core/site_db.py`'s `load_default_db()` / `load_default_sherlock_db()`
each wrap the import in a bare `try/except ImportError: return None`, so a
`pip install osint-core` (core deps only, no extra) makes `ohosint
username`/`ohosint sites`/`ohosint email`'s username-sweep step run to
completion and report `Total: 0 sites checked` with no error, warning, or exit
code indicating anything is missing. Re-confirmed by reading the current code
path (unchanged since that audit):

```python
def load_default_db() -> Optional[MaigretDatabase]:
    try:
        import maigret
        ...
    except ImportError:
        pass
    return None
```

**Recommended fix (packaging angle):** at minimum, have `load_site_databases()`
in `ohosint/pipelines.py` emit a `logging.warning(...)` (or a printed banner)
when it returns an empty combined database, telling the user to `pip install
osint-core[sweep]`. This is a one-function code change but belongs in the
packaging story: right now nothing in the *packaging* surface (no extras_require
default, no post-install message, no runtime check) tells a fresh installer
that the flagship feature needs an extra.

**License compatibility of the extras:** both are MIT-licensed —

```
$ python3 -c "import importlib.metadata as m; print(m.metadata('maigret')['License'])"
MIT
$ python3 -c "import importlib.metadata as m; print(m.metadata('sherlock-project')['License'])"
MIT
```

No conflict with an MIT (or Apache-2.0) license for this project. VERIFIED.

---

## 3. Build check

**Evidence — a real isolated build, run with `--no-isolation` (system
`setuptools==84.0.0` / `wheel==0.48.0`, both already present, so no network
installs occurred) into the scratch directory, not the project tree:**

```
$ python -m build --no-isolation --outdir <scratch>/build_out .
...
Successfully built osint_core-0.1.0.tar.gz and osint_core-0.1.0-py3-none-any.whl
```

Build **succeeded**. No `build/` directory or other artifact was left behind in
the project tree (`setuptools`' build_meta backend builds in a temp dir and
cleans up); the only side effect on the checked-out tree was a mtime refresh of
the pre-existing, already-gitignored `osint_core.egg-info/*` files (regenerated
with identical content).

**Wheel contents** — exactly the two intended packages, nothing else:

```
$ python -m zipfile -l osint_core-0.1.0-py3-none-any.whl
ohosint/__init__.py
ohosint/cli.py
ohosint/config.py
ohosint/output.py
ohosint/pipelines.py
ohosint/shell.py
osint_core/__init__.py
osint_core/async_check.py
... (16 more osint_core/*.py files)
osint_core-0.1.0.dist-info/METADATA
osint_core-0.1.0.dist-info/WHEEL
osint_core-0.1.0.dist-info/entry_points.txt
osint_core-0.1.0.dist-info/top_level.txt
osint_core-0.1.0.dist-info/RECORD
```

**No `.env`, no report JSONs, no `.pytest_cache`, no `osint_core.egg-info/`, no
`tests/`, no `skills/` in the wheel.** VERIFIED clean.

**Sdist contents** — mostly clean, but with build cruft that a `MANIFEST.in`
would remove:

```
$ tar -tzf osint_core-0.1.0.tar.gz
osint_core-0.1.0/PKG-INFO
osint_core-0.1.0/README.md
osint_core-0.1.0/ohosint/...            (6 files)
osint_core-0.1.0/osint_core/...         (18 files)
osint_core-0.1.0/osint_core.egg-info/   (6 files: PKG-INFO, SOURCES.txt, ...)
osint_core-0.1.0/pyproject.toml
osint_core-0.1.0/setup.cfg              <- auto-generated, empty egg_info shim
osint_core-0.1.0/tests/...              (7 test files)
```

No `.env`, no `.gitignore`, no `skills/`, no `LICENSE` (none exists to
include), no `.pytest_cache`. `tests/` being included in the sdist is normal
and fine (it lets downstream packagers, e.g. a Linux distro, run the test
suite against the built package) — **not** a leak. The two things worth
cleaning up are `osint_core.egg-info/` (a duplicate of `PKG-INFO` plus derived
files that shouldn't be redistributed as source) and the empty auto-generated
`setup.cfg`. VERIFIED.

**Recommended fix — add `MANIFEST.in`:**

```
include LICENSE
include README.md
include requirements.txt
graft tests
prune osint_core.egg-info
global-exclude __pycache__
global-exclude *.py[cod]
global-exclude .DS_Store
```

(The `include LICENSE` line also becomes load-bearing once B3 is fixed.)

---

## 4. Entry point

**Evidence:**

```toml
[project.scripts]
ohosint = "ohosint.cli:main"
```

```
$ python -c "from ohosint.cli import main; print(main, callable(main))"
<function main at 0x7a9a6efa9d80> True
```

```python
# ohosint/cli.py:291
def main(argv: Optional[list] = None) -> int:
    """Main entry point for the ohosint CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    ...
```

`main` exists, is callable, takes an optional `argv` and returns `int` (correct
shape for a console-script). Confirmed registered correctly in the built
artifact too:

```
$ cat osint_core.egg-info/entry_points.txt
[console_scripts]
ohosint = ohosint.cli:main
```

VERIFIED — entry point is correct and functional.

---

## 5. Reproducibility & lockfile posture

**Evidence:** every entry in both `requirements.txt` and `pyproject.toml`
`dependencies` is an unpinned floor (`>=`), e.g. `aiohttp>=3.9`,
`curl_cffi>=0.5`. There is no lockfile (no `requirements.lock`, no
`poetry.lock`, no `pdm.lock`, no `uv.lock`) anywhere in the tree.

**Why this matters more than usual for this project:** this is a
security/OSINT tool whose core value proposition is *correctness of network
behavior* — proxy routing, TLS behavior, WAF/verdict detection all live in
fast-moving async HTTP libraries (`aiohttp`, `curl_cffi`, `aiohttp-socks`).
An unpinned `curl_cffi>=0.5` today resolves to `0.15.0`+ installed in this
environment — three-digit-minor-version drift from the declared floor, with
no CI running against either end of that range to know if both still work.

**Recommended policy:**

1. Keep `pyproject.toml` `dependencies` as loose, sensible floors (`>=`) —
   correct for a *library* (`osint_core`) that other projects might depend on;
   do not over-constrain it with upper bounds that cause resolver conflicts
   downstream.
2. For the **application** surface (the `ohosint` CLI as something end users
   `pip install` and run), add a generated, committed lockfile used only by CI
   and in local dev instructions — e.g. `pip-compile` (from `pip-tools`)
   producing a `requirements-lock.txt` pinned to exact versions + hashes
   (`--generate-hashes`), regenerated weekly by Dependabot/Renovate and
   verified by CI. This gets you both worlds: flexible floors for library
   consumers, a fully reproducible, hash-pinned install for anyone running the
   actual security tool.
3. Pin the **extras** especially tightly if you keep them as real dependencies
   (§2) — `maigret`/`sherlock-project` each pull 9–44 fast-moving direct
   dependencies; an unpinned resolve six months from now is a different
   dependency graph than the one tested today.
4. Add a `dependabot.yml` (below) so floor bumps are proposed as reviewable
   PRs rather than silently drifting.

---

## 6. Missing repo scaffolding for GitHub

### 6a. `.gitignore` completeness — every currently-existing path it fails to exclude

**Evidence — current `.gitignore`:**

```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
build/
dist/

# Virtual envs
.venv/
venv/
env/

# Generated recon reports
*_report_*.json
report.json
out.json

# Local API keys
.env
```

Cross-referenced against every file currently in the tree
(`find . -type f`):

| Path in tree today | Covered by current `.gitignore`? |
|---|---|
| `.env` (contains `OHO_RAPIDAPI_KEY`) | **Yes** — `.env` pattern matches |
| `osint_core.egg-info/*` | **Yes** — `*.egg-info/` matches |
| `**/__pycache__/*.pyc` | **Yes** — `__pycache__/` matches at any depth |
| **`.pytest_cache/`** (`CACHEDIR.TAG`, `README.md`, `v/cache/lastfailed`, `v/cache/nodeids`) | **No pattern matches this** |

Only one currently-existing directory leaks through: `.pytest_cache/`.
Confirmed by direct listing:

```
$ find . -maxdepth 4 -name '.pytest_cache'
./.pytest_cache
```

**Additionally (forward-looking, not "currently in the tree" but high-severity
and trivially fixable now):** the tool's own default report-filename
generator, `make_report_path()` in `ohosint/output.py`, is called from three
places in `ohosint/cli.py`:

```
$ grep -n "make_report_path" ohosint/cli.py
176:        out_path = config.out or make_report_path()
231:        out_path = config.out or make_report_path()
279:        out_path = config.out or make_report_path(prefix="ohosint_breach")
```

The first two use the default prefix `"ohosint_report"` →
`ohosint_report_<timestamp>.json`, which **is** covered by the existing
`*_report_*.json` pattern. The third — used specifically for `ohosint breach`
— passes `prefix="ohosint_breach"`, producing `ohosint_breach_<timestamp>.json`.
That filename contains **no** `_report_` substring and doesn't match
`report.json`/`out.json` either, so **it is not covered by any current
pattern**. This is the one the tool's own README flags as potentially
containing "real leaked `email:password` pairs" (README.md, "Reports"
section). `skills/silent-recon/silent_recon.py`'s default save path
(`silent_recon_report_<timestamp>.json`) is fine — it does contain
`_report_`.

**Recommended fix — add to `.gitignore`:**

```gitignore
# Test / lint / type-checker caches
.pytest_cache/
.ruff_cache/
.mypy_cache/
.coverage
htmlcov/

# Generated recon / breach reports (may contain PII or real leaked credentials
# — see README.md "Reports" and "Plaintext credentials" warnings)
*_report_*.json
*_breach_*.json
report.json
out.json

# Local API keys
.env
.env.*
!.env.example

# Build artifacts
osint_core-*.egg-info/
```

### 6b. LICENSE — recommendation and justification

**Dependency license survey** (evidence: `importlib.metadata` on installed
packages, cross-checked against PyPI for the two entries with empty local
metadata):

| Package | License | Source |
|---|---|---|
| `requests` | Apache-2.0 | local metadata |
| `PySocks` (via `requests[socks]`) | BSD | local metadata |
| `phonenumbers` | Apache-2.0 | PyPI (local metadata field empty) |
| `aiohttp` | Apache-2.0 AND MIT | local metadata |
| `aiohttp-socks` | Apache-2.0 | local metadata |
| `aiodns` | MIT | local metadata |
| `curl_cffi` | MIT | PyPI (local metadata field empty) |
| `rich` | MIT | local metadata |
| `stem` | **LGPLv3** | local metadata |
| `safe-pysha3` | PSFL (Keccak reference code: CC0 1.0) | local metadata |
| `maigret` (extra) | MIT | local metadata |
| `sherlock-project` (extra) | MIT | local metadata |
| ~~`alive-progress`~~ | MIT (moot — recommend removing, S1) | local metadata |

**Recommendation: MIT License.** Justification:

- The dependency stack is overwhelmingly permissive (MIT/Apache-2.0/BSD/CC0);
  MIT imposes no obligations that conflict with any of them.
- `stem` is LGPLv3, the one copyleft entry — but it is consumed as an ordinary
  installed pip dependency (imported, never vendored/copied into this repo's
  source), which does not extend LGPL's copyleft to this project's own code.
  Standard compliance is simply: don't vendor stem's source, and don't strip
  users' ability to swap in a different `stem` version (trivially true for a
  normal pip dependency). Worth one line in a `NOTICE` file, not a blocker.
- Both optional-but-load-bearing extras (`maigret`, `sherlock-project`) are
  themselves MIT — matching license with the ecosystem this tool sits in
  (virtually every other OSINT CLI tool of this shape — Sherlock, Maigret,
  Holehe, etc. — is MIT) reduces friction for anyone comparing/forking within
  that ecosystem.
- Apache-2.0 is a reasonable alternative (explicit patent grant — arguably
  attractive for a security tool; and it's what the two heaviest core deps,
  `requests` and `aiohttp`, already use) but adds NOTICE-file bookkeeping
  obligations MIT doesn't have, for marginal benefit at this project's size.

**Recommended fix — add `LICENSE` at repo root** (standard OSI MIT text):

```
MIT License

Copyright (c) 2026 <your name or org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 6c. CI workflow — proposed `.github/workflows/ci.yml`

No `.github/` directory exists at all today. Proposed lint + test-matrix +
build workflow:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install lint tools
        run: pip install ruff
      - name: ruff check
        run: ruff check .
      - name: ruff format --check
        run: ruff format --check .

  test:
    needs: lint
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install package (core + sweep extras) and test deps
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[sweep]"
          pip install pytest pytest-cov
      - name: Run tests
        run: pytest -q --cov=osint_core --cov=ohosint --cov-report=term-missing

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install build frontend
        run: pip install build
      - name: Build sdist + wheel
        run: python -m build
      - name: Check metadata with twine
        run: |
          pip install twine
          twine check dist/*
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
```

Notes on the matrix: `3.10` is the declared floor (§1b), `3.13` is current
stable at time of writing; drop the floor version from the matrix the day it's
past upstream EOL. The `test` job intentionally installs `[sweep]` so CI
actually exercises the maigret/sherlock-backed site-database path (§2),
catching the "silently 0 results" failure mode instead of masking it the way
a bare `pip install .` would.

### 6d. `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

### 6e. `.pre-commit-config.yaml`

Particularly valuable here given the `.env`-with-API-keys pattern already in
this repo (currently gitignored correctly, but a pre-commit secret scanner is
cheap insurance against a future `git add -f`):

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-toml
      - id: check-added-large-files
      - id: detect-private-key
```

### 6f. `.editorconfig`

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{yml,yaml,json,md}]
indent_size = 2
```

### 6g. Community-health files — enumerate, minimal content

| File | Status | Note |
|---|---|---|
| `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/ISSUE_TEMPLATE/config.yml` | missing | Standard GitHub issue-form templates; for an OSINT tool, include a checkbox re-affirming lawful-use intent |
| `CONTRIBUTING.md` | missing | Point at `docs/AGENTS.md` (already exists, has good repo conventions) plus how to run `pytest`/`ruff` locally |
| `SECURITY.md` | missing | Highest-value doc to add given the project's nature — needs a private vulnerability-reporting channel (GitHub Security Advisories or an email) and should restate the "lawful use only" framing already in `README.md` |
| `CODE_OF_CONDUCT.md` | missing | Adopt Contributor Covenant v2.1 verbatim |
| `CHANGELOG.md` | missing | Start in Keep a Changelog format at `## [0.1.0] - 2026-08-25` |

These are content/prose deliverables more than packaging ones; enumerated here
for completeness per the audit brief, kept intentionally brief since
documentation prose is another agent's remit.

---

## 7. Test runner & lint/format config

**Evidence:**

```
$ grep -n "pytest\|ruff\|black\|isort\|flake8\|mypy" pyproject.toml
(no output)
$ find . -maxdepth 1 -iname "pytest.ini" -o -iname "setup.cfg" -o -iname "tox.ini" -o -iname ".flake8"
(no output)
$ python -m pytest -q
...............................................................          [100%]
63 passed in 31.97s
```

Zero configuration exists for pytest or any linter/formatter — confirmed also
by the README's own "Development status" section: *"No linter config,
formatter, or CI yet — v0.1.0, intentionally minimal."* The suite itself is
healthy: 63/63 passing, no config needed to run it today because `tests/` has
an `__init__.py` and pytest's rootdir auto-discovery happens to find it.
VERIFIED.

**Recommended fix — add to `pyproject.toml`:**

```toml
[tool.pytest.ini_options]
minversion = "7.0"
testpaths = ["tests"]
addopts = "-ra --strict-markers --strict-config"
filterwarnings = [
    "error",
    "ignore::DeprecationWarning:aiohttp.*",
]

[tool.ruff]
target-version = "py310"
line-length = 100
src = ["ohosint", "osint_core", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "C4"]
ignore = []

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101"]
```

(`ruff format` replaces black — one tool, one config block, matches the CI
workflow in §6c. If black is preferred instead, swap the `[tool.ruff]` blocks
for `[tool.black] line-length = 100 target-version = ["py310"]` and add
`black`/`isort` to the lint job.)

---

## Summary of every command run (for reproducibility of this audit)

```bash
find . -maxdepth 3 -not -path '*/.*'
cat pyproject.toml requirements.txt .gitignore .env README.md docs/AUDIT.md docs/AGENTS.md
cat osint_core.egg-info/{requires.txt,SOURCES.txt,top_level.txt,entry_points.txt,PKG-INFO}
grep -rnE '^\s*(import|from)\s+[a-zA-Z_]' ohosint osint_core skills tests --include='*.py'
grep -rn "alive_progress\|alive-progress" .
grep -rnE 'PEP604 union / match-case / tomllib / except*' patterns across ohosint osint_core skills
python3 -m pip list | grep -iE "requests|phonenumbers|aiohttp|..."
python3 -c "from ohosint.cli import main; print(main, callable(main))"
python3 -m pytest -q
python3 -m build --no-isolation --outdir <scratch>/build_out .
python3 -m zipfile -l <scratch>/build_out/osint_core-0.1.0-py3-none-any.whl
tar -tzf <scratch>/build_out/osint_core-0.1.0.tar.gz
tar -xzf <scratch>/build_out/osint_core-0.1.0.tar.gz -C <scratch>/extracted
python3 -m pip download --no-deps -d <scratch>/extras_download maigret sherlock-project
python3 -c "import importlib.metadata as m; ... m.metadata(pkg)['License'] ..."
```

No file inside `/home/omar/Documents/pythonProject` was modified by this audit
other than the creation of this report at `docs/audit/packaging.md`; no `git`
command was run; all builds/downloads were written to the scratch directory
only.
