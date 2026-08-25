# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **Username sweeps no longer report false positives.** The Maigret site
  database ships absence/presence markers under four inconsistent spellings
  (`absenceStrs`, `absenseStrs`, `presenceStrs`, `presenseStrs`); none were
  being mapped to the attributes the classifier reads, and the classifier
  discarded the presence result even when it had one. 910 sites' absence
  markers and 539 sites' presence markers were silently ignored, so pages
  that say "user not found" were reported as hits.
- **Proxy/Tor leak on every sweep.** `fetch_exclusions()` issued a bare
  `requests.get()` with no proxy support, so every `ohosint email` and
  `ohosint username` run — including under `--tor` — made one clearnet
  request from the operator's real IP.
- **Reports are no longer written unless requested.** `email`, `username` and
  `breach` silently wrote a JSON report containing the target's data into the
  working directory in default output mode. Reports now require `--out`, and
  the path is always printed.
- **Report files are created `0600`** instead of inheriting the umask. They
  contain personal data, and breach reports can contain leaked credentials.
- **Breach source names parsed per character.** `breach_breachdirectory()`
  iterated a `sources` value that is sometimes a bare string, yielding breach
  names like `"("`, `"0"`, `"a"`.
- **Sherlock database not found on Python 3.11+.** The fallback search path
  was hardcoded to `python3.10`; it is now derived from the running
  interpreter via `site`.
- `ohosint phone` now prints *why* a number failed to parse instead of only
  `Valid: False`.
- `ohosint` now validates `--proxy` up front and warns that `socks5://` leaks
  DNS (use `socks5h://`).

### Added

- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
- CI: lint, a Python 3.10–3.13 test matrix, and a packaging check.
- `tests/conftest.py` — blocks all outbound sockets during tests, resets the
  exclusions cache, and isolates `.env`. The suite went from 26.8s to 0.2s,
  because three tests had been making live third-party API calls on every run.
- Full package metadata, `MANIFEST.in`, `.env.example`, `.editorconfig`,
  Dependabot config.
- README sections on intended use, third-party terms, and data protection.

### Removed

- `alive-progress` dependency — declared but imported nowhere.

### Security

- See [`docs/PUBLICATION-AUDIT.md`](docs/PUBLICATION-AUDIT.md) for the full
  pre-release audit and remediation log.

## [0.1.0]

- Initial development version.
