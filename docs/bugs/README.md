# Bug Tickets

All tickets raised in the 2026-09-15 MCP operations retro
(`docs/MCP-OPERATIONS-REPORT.md`) are **resolved**. The individual ticket files
were deleted on resolution.

## Resolution summary

| ID | Title | Resolution |
|---|---|---|
| BUG-001 | `socks5h://` scheme crash in username sweep | `_pick_checker` prefers `CurlCffiChecker` for `socks5h`; rewrites to `socks5` (with a DNS-leak warning) when curl_cffi is missing |
| BUG-002 | Connector ValueError aborts entire sweep | Per-site `try/except` in `_run_sweep` degrades failures to a site error |
| BUG-003 | `configure(proxy="None")` raises ValueError | `_configure` maps `"None"/"off"/"null"/""` to a cleared proxy |
| BUG-004 | Unbounded sweep causes MCP timeout | Default sweep bounded to ~100 sites + 60s budget; `run_investigation` sweeps bounded too |
| BUG-005 | Timeout drops all partial results | `check_username_on_sites_budget` returns partial results with `truncated=true` |
| BUG-006 | Sweep false-positive families | Claimed hits without presence markers are flagged `confidence="low"` |
| BUG-007 | `autopsy_url` returns empty for walled platforms | Wall/WAF detection returns `{wall: true, note: ...}` instead of empty links |
| BUG-008 | Missing search-index corroboration pass | `corroborate_handle` tool + relevance-guarded dorks |
| BUG-009 | `auto_dork_url` keyword boilerplate | Boilerplate stoplist (`amount symbol cdninstagram`, …) + `og:title`/`og:description` seeding |
| BUG-010 | No relevance guard in `search_bing`/`dork` | `_relevant` drops zero-token-overlap hits, applied across all engines |
| BUG-011 | `hunt_docs` accepts email targets | `hunt_docs` refuses email targets with a clear message |
| BUG-012 | Key readiness not surfaced to user | `status()` returns `recommended_next_keys` hints |
| BUG-013 | ProxyNova returns 10K unfiltered lines | ProxyNova adapter filters to the query token and caps at 100 lines |
| BUG-014 | EmailRep non-JSON response surfaces raw error | Adapters return a `note` instead of raw `json.JSONDecodeError` text |
| BUG-015 | `mentions` returns null with no diagnostic | `mentions_detailed` returns per-source `{state, note}` |
| BUG-016 | `suggest` empty for handles | Handle-like queries self-value and pivot to `generate_candidates` |
| BUG-017 | `investigate_email` discards breach data on sweep crash | Email pipeline isolates the sweep; breach/source data survives with a `sweep_error` field |
| BUG-018 | `search_dork` email queries return zero-relevance junk | Exact-match dorks filtered by the global relevance guard |
| BUG-019 | `rotate_tor_circuit` fails silently | Returns an actionable ControlPort 9051 hint instead of a raw traceback |

## Acceptance gates

```bash
ruff check .               # lint
pytest                     # 152 tests pass
```
