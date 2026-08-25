# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for a security vulnerability.

Report it privately through
[GitHub Security Advisories](https://github.com/omar-hadf/ohosint/security/advisories/new),
or by email to the address on the maintainer's GitHub profile.

Please include: what the issue is, how to reproduce it, and what an attacker
could achieve. You can expect an acknowledgement within 7 days and an
assessment within 30.

## What counts as a vulnerability here

This is a passive OSINT tool whose security properties are mostly about
protecting **its operator** and the **subjects of an investigation**. The
following are in scope and treated as security bugs, not feature requests:

- **Proxy / Tor bypass** — any code path that issues a network request
  ignoring the configured `--proxy` / `--tor` setting, leaking the operator's
  real IP address. (A bug of exactly this class was fixed in `fetch_exclusions()`;
  see `docs/audit/security.md`.)
- **DNS leaks** — resolving a hostname outside the SOCKS tunnel. Always use
  `socks5h://`, never `socks5://`.
- **TLS downgrade** — certificate verification being disabled anywhere other
  than by the operator explicitly passing `--insecure`.
- **Credential or API-key disclosure** — a key from the environment or `.env`
  appearing in a saved report, log line, or terminal output.
- **Unsafe report handling** — investigation reports (which contain personal
  data, and for breach searches can contain real leaked `email:password`
  pairs) being written world-readable, to an unexpected path, or without the
  operator asking.
- **Injection** — unvalidated input reaching a shell, a file path, or an
  outbound URL.

## Out of scope

- The existence of the tool, or the fact that it can look up public data
  about a person. Use the issue tracker for design discussion.
- Rate limits, availability, or data accuracy of the third-party APIs this
  tool queries. Report those to the provider.
- Findings that require the operator to run the tool against themselves with
  deliberately unsafe flags.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.
