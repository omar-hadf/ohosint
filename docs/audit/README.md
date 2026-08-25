# Audit reports

Five parallel specialist audits of the codebase, run 2026-08-25 ahead of the
first public release. Each agent was restricted to one aspect and required to
verify its claims by running code.

Start with the consolidated report: **[../PUBLICATION-AUDIT.md](../PUBLICATION-AUDIT.md)**
— it says what was found, what was fixed, and what was deliberately left open.

| Report | Covers |
|---|---|
| [security.md](security.md) | Secret handling, proxy/Tor leaks, TLS verification, PII at rest, injection, dependency risk, dual-use posture |
| [code-quality.md](code-quality.md) | Correctness bugs, type hints, dead code, architecture, error handling |
| [packaging.md](packaging.md) | `pyproject.toml`, dependency reconciliation, build output, entry point, CI and repo scaffolding |
| [testing.md](testing.md) | Suite health, hermeticity, per-module coverage, test quality, highest-value missing tests |
| [docs-legal.md](docs-legal.md) | README accuracy, undocumented surface, third-party ToS, GDPR posture |

Findings are marked VERIFIED (reproduced) or UNVERIFIED (read-only inference).
Severity is per-report; the consolidated report reconciles them.

These describe the codebase **as it was at the start of 2026-08-25**. Several
findings have since been fixed — the consolidated report tracks which.
