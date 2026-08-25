# OHOsint — passive OSINT toolkit

[![CI](https://github.com/omar-hadf/ohosint/actions/workflows/ci.yml/badge.svg)](https://github.com/omar-hadf/ohosint/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A collection of **passive, target-never-notified** OSINT tools for
investigating an email, phone number, name, or username. Everything shares
one core library (`osint_core/`), and it's exposed two ways:

- **`ohosint`** — a unified CLI and interactive shell: one command,
  subcommands per identifier type, async multi-site username sweeps against
  Maigret/Sherlock-format site databases, table or JSON output.
- **`skills/`** — three standalone scripts (an interactive recon shell and
  two adult-platform account finders), written as
  [Claude Code skills](https://docs.claude.com/) with their own `SKILL.md`
  manifests.

> **Lawful use only.** Authorized security assessments, your own accounts,
> or an active legal case. This tool never logs in, creates accounts, or
> triggers password-reset / recovery / OTP flows — those are exactly the
> actions that would notify the person you're investigating.

## How it stays passive

1. **Read-only against the subject.** Nothing here ever POSTs to a login,
   recovery, "forgot password," or OTP endpoint, and nothing ever touches
   infrastructure the subject controls. Requests go to public pages and
   third-party APIs. (One exception to "GET only" as a literal statement:
   the optional Intelligence X source issues a `POST` to *its own* search
   API to start a query — `osint_core/breach.py`. That is a third-party
   service, not the target, so the passivity guarantee holds.)
2. No account creation, no login attempts, no use of credentials found in
   breach data.
3. Randomized inter-request delays and User-Agent rotation on every request.
4. Optional routing through Tor (SOCKS5) so your own origin IP is hidden
   from the sites and services being queried too.

## Features

- **Email**: breach-source lookup (LeakCheck), infostealer-log check
  (Hudson Rock), Gravatar profile lookup, username-candidate generation.
- **Phone**: E.164/national/international normalization, line-type and
  carrier lookup (via `phonenumbers`), ready-made search-engine dorks.
- **Name**: username-candidate generation, identity dorks (LinkedIn,
  Facebook, socials).
- **Username**: async sweep across a merged Maigret + Sherlock site
  database (thousands of sites when both are installed — see
  [Site databases](#site-databases-for-username-sweeps) below), with WAF
  detection, per-site error/regex rules, and confidence scoring against
  confirmed accounts.
- **Breach search**: multi-source lookup for emails, usernames, domains,
  and passwords. Sources include LeakCheck, Hudson Rock Cavalier,
  XposedOrNot, HIBP breach catalogue / Pwned Passwords (k-anonymity),
  ProxyNova COMB, and EmailRep. Optional keyed sources (env vars): HIBP
  account search, Intelligence X, BreachDirectory, EmailRep keyed tier.
- **Profile autopsy**: pull cross-platform links, email addresses, and
  `@handles` out of any fetched page.
- **Pivoting**: turn a confirmed hit's page metadata into new username/email
  candidates automatically (`pivot` command / `extract_pivots`).
- **Tor integration**: `--proxy socks5h://...` / `--tor`, plus a `newnym`
  command to rotate circuits when a search engine starts throttling you.

## Project layout

```
ohosint/
├── osint_core/                 # shared library (single source of truth)
│   ├── constants.py            #   user-agents, not-found markers, platform URL templates
│   ├── net.py                  #   Fetcher: session, UA rotation, delays, proxy
│   ├── search.py                #   DuckDuckGo + Bing dorking, optional Google CSE engine
│   ├── probe.py                #   sync profile probing (used by skills/)
│   ├── async_check.py          #   async site-checking engine (used by ohosint)
│   ├── site_db.py              #   Maigret/Sherlock site-database loader
│   ├── scan_result.py          #   unified ScanResult/ScanStatus model
│   ├── executors.py            #   bounded-concurrency async task runners
│   ├── pivots.py               #   turn scan results into new usernames/emails to check
│   ├── confidence.py           #   confidence scoring for cross-scan hits
│   ├── patterns.py             #   username pattern/wildcard expansion ([a-z]{1-3} syntax)
│   ├── exclusions.py           #   Sherlock false-positive site exclusion list
│   ├── impersonate.py          #   curl_cffi TLS-fingerprint impersonation
│   ├── sources.py              #   leakcheck / hudson rock / gravatar / wayback
│   ├── breach.py               #   multi-source breach/leak lookup
│   ├── candidates.py           #   email parsing + username-candidate generation
│   ├── harvest.py              #   scrape links/emails/@handles out of a fetched page
│   └── cli.py                  #   shared argparse plumbing for the skills/ scripts
├── ohosint/                    # unified CLI (console-script entry point: `ohosint`)
│   ├── cli.py                  #   argparse: email/phone/username/name/shell/sites
│   ├── shell.py                #   interactive shell (cmd.Cmd)
│   ├── pipelines.py            #   email/phone/name/username investigation pipelines
│   ├── config.py                #   runtime config + session state
│   └── output.py               #   rich table / JSON formatting
├── skills/
│   ├── silent-recon/           #   interactive multi-identifier OSINT shell
│   │   ├── silent_recon.py
│   │   └── SKILL.md
│   ├── silent-account-finder/  #   email -> adult-platform profile locator
│   │   ├── find_profiles.py
│   │   ├── deep_dive.py        #   second-pass pivots from a known profile
│   │   └── SKILL.md
│   └── tor-proxy/               #   how-to: route traffic through Tor (docs only)
│       └── SKILL.md
├── requirements.txt
├── pyproject.toml               # makes osint_core + ohosint pip-installable
├── docs/
│   ├── AGENTS.md                # repo conventions for AI coding agents
│   ├── PUBLICATION-AUDIT.md     # consolidated pre-release audit + remediation log
│   ├── audit/                   # per-aspect audit reports (security, code, packaging, tests, docs)
│   ├── AUDIT.md                 # earlier audit round (superseded — see PUBLICATION-AUDIT.md)
│   ├── PLAN.md                  # remediation plan for that earlier round
│   └── BREACH-SEARCH-PLAN.md    # breach-search architecture plan
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
└── .github/workflows/ci.yml
```

### Two front ends, one library

`ohosint` is the primary interface and supersedes `skills/`. The `skills/`
scripts are kept because they run standalone from a path with a lighter
dependency footprint (no async stack, no site databases) and each carries a
`SKILL.md` documenting its method — useful as a reference, and as Claude Code
skills. New work should target `ohosint`.

## Installation

Requires **Python 3.10+**.

```bash
pip install -r requirements.txt
# or, to also get the `ohosint` console command on your PATH:
pip install -e .
```

The `skills/` scripts add the repo root to `sys.path` at startup, so they
also run directly by path without any install:

```bash
python3 skills/silent-recon/silent_recon.py --proxy socks5h://127.0.0.1:9050
```

### Site databases (for username sweeps)

`ohosint`'s `email`/`username`/`sites` commands source their site list from
the [Maigret](https://pypi.org/project/maigret/) and/or
[Sherlock](https://pypi.org/project/sherlock-project/) packages' bundled
site-definition JSON — **neither is a hard dependency of this project**, so
install at least one to get real sweep results:

```bash
pip install maigret            # ~2,500 sites
pip install sherlock_project   # Sherlock's site list, merged in alongside Maigret's
```

If neither is installed, the sweep commands now fail fast with an
actionable error rather than silently reporting zero hits.

### Optional: breach API keys

The breach search works fully without keys, but you can unlock extra sources
by setting environment variables. Keys are read from the environment, falling
back to a `.env` file in the current directory (copy `.env.example` to `.env`).
Shell variables take precedence. Keys are never written into reports:

```bash
export OHO_HIBP_KEY=...          # Have I Been Pwned account search
export OHO_INTELX_KEY=...        # Intelligence X free account API
export OHO_RAPIDAPI_KEY=...      # BreachDirectory (RapidAPI)
export OHO_EMAILREP_KEY=...      # EmailRep higher-quota tier
```

### Optional: Google dorking (env vars only)

The `dork` shell command scrapes DuckDuckGo + Bing by default. Set both of
these to add a real **Google** engine via the official
[Custom Search JSON API](https://programmablesearchengine.google.com/) —
every Google operator (`site:`, `filetype:`, `intitle:`, `inurl:`, …) works,
and it's a sanctioned API rather than scraping, so no CAPTCHAs. Free tier is
100 queries/day:

```bash
export OHO_GOOGLE_KEY=...        # Google Cloud API key (Custom Search enabled)
export OHO_GOOGLE_CX=...         # Programmable Search Engine ID (cx)
```

Without both set, the engine list stays DuckDuckGo + Bing and nothing changes.

### Optional: Tor

```bash
sudo apt install tor && sudo service tor start   # listens on 127.0.0.1:9050
```

Then pass `--proxy socks5h://127.0.0.1:9050` (or `--tor` as a shortcut in
`ohosint`) to any command. Use `socks5h://`, not `socks5://` — the trailing
`h` routes DNS resolution through Tor too, avoiding leaks. See
[skills/tor-proxy/SKILL.md](skills/tor-proxy/SKILL.md) for a from-scratch,
no-sudo Tor setup.

## Usage

### `ohosint` — unified CLI

```bash
ohosint email user@example.com
ohosint phone +14155550123
ohosint username someuser
ohosint breach user@example.com     # multi-source breach search
ohosint breach --type password 'hunter2'
ohosint breach --type domain adobe.com
ohosint name Jane Doe --year 1990
ohosint sites --db all              # see how many sites are loaded
ohosint shell                       # interactive mode
```

Common flags (work on every subcommand):

```bash
ohosint --proxy socks5h://127.0.0.1:9050 username someuser
ohosint --tor username someuser              # shortcut for the line above
ohosint --format json --out report.json username someuser
ohosint --nsfw username someuser             # include NSFW-tagged sites
ohosint --sites sherlock username someuser   # maigret | sherlock | all (default)
ohosint --in-parallel 40 username someuser   # concurrent request cap (default 20)
```

#### Breach search

`ohosint breach` queries multiple free breach/leak sources and merges the
results. It supports emails, usernames, domains, and passwords. Passwords are
hashed locally (k-anonymity) before any request is sent.

```bash
ohosint breach user@example.com
ohosint --tor breach someone@example.com
ohosint breach --type username jdoe
ohosint breach --type domain adobe.com
ohosint breach --type password 'hunter2'

# restrict to specific sources
ohosint breach --sources leakcheck,emailrep user@example.com
```

Keyless sources: **LeakCheck**, **Hudson Rock Cavalier**, **XposedOrNot**,
**HIBP breach catalogue**, **HIBP Pwned Passwords**, **XposedOrNot password
check**, **ProxyNova COMB**, and **EmailRep**.

Optional keyed sources: **HIBP account search**, **Intelligence X**,
**BreachDirectory**, and **EmailRep** (set the env vars above).

> **Plaintext credentials:** ProxyNova and BreachDirectory can return real
> leaked `email:password` pairs. The CLI displays them as-is; handle them
> responsibly and do not share reports that contain them.

> **Tor:** No working `.onion` breach-search endpoint exists as of 2026, but
> all clearnet APIs can be routed through Tor via `--tor` / `--proxy
> socks5h://...` to hide your origin IP.

Interactive shell commands: `email`, `phone`, `username`, `breach`, `name`,
`sweep` (probe every candidate generated so far), `dork`, `autopsy`, `pivot`,
`proxy`, `newnym`, `delay`, `status`, `save`, `clear`, `exit`. Run `help`
inside the shell for the full list.

### `skills/` — standalone scripts

```bash
# interactive multi-identifier shell (email / name / phone / username)
python3 skills/silent-recon/silent_recon.py --proxy socks5h://127.0.0.1:9050

# non-interactive, scripted:
python3 skills/silent-recon/silent_recon.py \
  -c "email user@example.com" -c "phone +14155550123" -c "save"

# email -> adult-platform (XNXX/XVideos) profile locator
python3 skills/silent-account-finder/find_profiles.py --email user@example.com

# second-pass pivots from an already-confirmed profile
python3 skills/silent-account-finder/deep_dive.py \
  --email user@example.com --known-handle jdoe \
  --profile-url https://example.com/profile/jdoe
```

Each `SKILL.md` documents its own method plan, phase-by-phase, and why each
step stays passive — see
[skills/silent-recon/SKILL.md](skills/silent-recon/SKILL.md) and
[skills/silent-account-finder/SKILL.md](skills/silent-account-finder/SKILL.md).

## Reading verdicts

| Verdict | Meaning |
|---|---|
| `confirmed` / `claimed` | 200 response, no not-found markers, handle appears in the page |
| `probable` | 200 response, no explicit not-found markers (common on login-walled sites) |
| `absent` / `available` | 404-class response or an explicit not-found marker |
| `unknown` | request failed (timeout, connection error, etc.) |
| `waf` | blocked by a WAF/CDN challenge page (Cloudflare, PerimeterX, AWS WAF) |

Dork results also report per-engine state: `ok` (real results), `empty` /
`junk` / `None` mean that engine looks throttled — rotate your Tor circuit
(`newnym`) or wait before treating the result as a true negative.

## Reports

A report is written **only when you ask for one** — `--out path.json`, or the
shell's `save` command. Nothing is written to disk otherwise.

Reports contain identifiers, generated candidates, per-site results, and — for
`ohosint` — a summary (`total` / `found` / `waf` / `illegal` / `errors`). They
are created with `0600` (owner-read/write only) permissions, because they
contain the personal data of the person being investigated.

**Breach reports are more sensitive still.** ProxyNova and BreachDirectory can
return real plaintext `email:password` pairs belonging to third parties. Treat
a breach report as you would a credential dump: don't share it, don't paste it
into an issue, and delete it when the investigation is over.

Report filenames are gitignored (`*_report_*.json`, `*_breach_*.json`,
`report.json`, `out.json`) — but check `git status` before committing anyway.

## Intended use & legal

This tool is built for **lawful, authorized** work:

- checking your own exposure (your email, your usernames, your leaked passwords),
- authorized security assessments and red-team engagements where you have
  written permission covering OSINT collection,
- security research, threat intelligence, and journalism,
- an active legal case or a due-diligence process with a lawful basis.

**Do not** use it to stalk, harass, dox, or surveil anyone, to build profiles
of people without a lawful basis, or in any way that breaks the law where you
or the subject live. You are responsible for what you run and for what you do
with the output.

### Third-party terms and rate limits

The tool queries third-party services. You are bound by their terms, not this
project's:

- **Breach sources** (LeakCheck, Hudson Rock, XposedOrNot, HIBP, ProxyNova,
  EmailRep, Intelligence X, BreachDirectory) — use your own API keys, stay
  inside the documented rate limits, and don't redistribute the data you get
  back. The default inter-request delays exist for this reason; don't set them
  to zero to hammer a free endpoint.
- **Search engines** — `osint_core/search.py` scrapes DuckDuckGo and Bing HTML
  result pages directly rather than using a licensed search API. This is likely
  contrary to those services' terms of use. It is provided for research; use it
  at your own risk, and prefer an official API for anything production or
  commercial.

### Personal data

Investigation reports are personal data. Under GDPR/CCPA-style regimes you
generally need a lawful basis to collect and keep them. In practice:

- collect only what the investigation actually needs,
- keep reports only as long as you need them, then delete them,
- store them somewhere access-controlled (they are written `0600` for this
  reason),
- never republish breach data or leaked credentials belonging to third parties.

The `skills/silent-account-finder/` scripts locate accounts on adult platforms.
In the EU that can constitute "special category" data under GDPR Article 9,
which carries a materially higher legal bar. Be sure you have one before using it.

## License

[MIT](LICENSE).

## Development status

v0.1.0 — pre-1.0, expect breaking changes.

```bash
pip install -e ".[dev]"     # runtime + pytest + ruff
python -m pytest tests/ -q  # 63 tests, no network access (see tests/conftest.py)
ruff check .
```

GitHub Actions runs lint, the test matrix (Python 3.10–3.13), and a packaging
check on every push — see [.github/workflows/ci.yml](.github/workflows/ci.yml).

See [docs/AGENTS.md](docs/AGENTS.md) for repo conventions if you're extending
this with an AI coding agent, [CONTRIBUTING.md](CONTRIBUTING.md) before opening
a PR, and [docs/audit/](docs/audit/) for the full code-audit reports.
