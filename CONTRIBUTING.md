# Contributing

Thanks for considering a contribution.

## Ground rules

This project has one hard rule that overrides convenience: **it stays
passive.** A contribution must never add code that notifies, contacts, or
authenticates against the person being investigated. Concretely, no pull
request may add:

- account creation, login attempts, or credential use (including credentials
  found in breach data),
- password-reset, account-recovery, or OTP flows,
- any request to infrastructure the subject controls that could show up in
  their logs or notifications.

Queries go to public pages and third-party APIs only.

Second hard rule: **every outbound request must honour the configured
proxy.** If you add a network call, thread `proxy` through to it and add a
test asserting it is applied. Bare `requests.get(...)` with no `proxies=`
argument is a Tor leak and will be rejected — see `SECURITY.md`.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # runtime + pytest + ruff
pip install -e ".[dev,sweep]"    # ...also the maigret + sherlock site databases
```

## Tests

```bash
python -m pytest tests/ -q
```

`tests/conftest.py` installs an autouse fixture that **blocks all outbound
sockets**. This is deliberate: tests must never fire live queries at
third-party breach APIs. If your test needs network data, mock at the
`osint_core` / `ohosint.pipelines` seam (`oc.gravatar`, `oc.leakcheck`,
`oc.fetch_exclusions`, `check_username_on_sites`, …) or use the `no_sources`
fixture. A test that fails with `NetworkCallInTest` is telling you it leaked.

The same fixture pins each test to a scratch working directory so no real
`.env` is read.

## Style

```bash
ruff check .
```

Line length 100, target Python 3.10.

## Reports and personal data

Never commit a generated report. `.gitignore` covers `*_report_*.json` and
`*_breach_*.json`, but check `git status` before committing anyway — breach
reports can contain real leaked credentials belonging to third parties.
Don't paste report output into issues; redact it first.

## Pull requests

Keep them focused. Include a test for behaviour changes, and say in the
description whether the change touches a network path (and if so, how proxy
routing is preserved).
