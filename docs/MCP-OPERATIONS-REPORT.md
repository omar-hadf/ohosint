# MCP-OPERATIONS-REPORT.md — OHOsint MCP retro on a sample e-mail target

Status: reviewed 2026-09-15. Target: e-mail → name → social handle
(Instagram) → TikTok handles. Synthetic/sample identifiers are used throughout;
no real test subject e-mail or username appears in this document. All
operations passive (GET-only via public pages / third-party APIs), routed
through Tor for the OPSEC phases. **The e-mail owner was never contacted or
notified.**

Identifier legend (generic stand-ins for the real test subject):

| Real value | Placeholder used here |
|---|---|
| tested e-mail | `test.user@example.com` |
| associated name | `Test User` |
| Instagram handle | `@test_user` |
| Instagram display name | `Jane` |
| TikTok handles | `@testuser`, `@testuser23` |
| generated handle candidates | `test.user`, `testuser`, `user_test94`, … |
| Instagram post/reel shortcodes | `<post-shortcode>` |
| infected-machine context from stealer logs | `<computer-name>` |
| leaked credential hashes | `<hash-redacted>` |

This report logs every MCP operation, scores success/failure, attributes root
causes to code (`file:line`), rates each tool's efficacy, assesses the model's
behavior, and ends with a prioritized improvement backlog. Goal: raise tool
efficacy, not to revisit the target.

---

## 1. Executive summary

| Metric | Value |
|---|---|
| MCP tools exercised | 18 of 25 registered |
| Operations that returned a usable result | ~14 / ~50 (28 %) |
| Crashes (tool raised / returned error) | 6 (all one root cause: `socks5h` scheme) |
| Client-side timeouts (`-32001`) | 7 (all one root cause: unbounded sweep) |
| High-value intelligence wins | **2** (breach profile; Instagram link) |
| Wall-blocked platforms (JS/WAF) | Instagram, TikTok, Facebook, X, linkedin, Bing |
| Code bugs identified | 8 (see §4) |

Two findings moved the case forward:
1. **breach_search** produced a rich, actionable exposure profile (6 breaches,
   infostealer machine context, leaked-password hashes).
2. **search_dork on the handle text** (`"test_user"`) surfaced the decisive
   link — Instagram `@test_user` titled "Jane".

Everything else was partial, junk, or blocked.

---

## 2. Operation log

Chronological, grouped by phase. Status: ✅ ok · ⚠ partial · ❌ failed/timeout.

### Phase 0 — OPSEC
| # | Tool + args | Result | Notes |
|---|---|---|---|
| 1 | `osint_plan(email)` | ✅ | Phase plan incl. hard rules generated. |
| 2 | `status()` | ✅ | Baseline: no proxy, 1 key configured. |
| 3 | `configure(proxy=socks5h://127.0.0.1:9050)` | ✅ | Tor routed. |
| 4 | `tor_check()` | ✅ | Exit IP confirmed as Tor relay. |

### Phase 1–2 — E-mail + breach (batch)
| # | Tool + args | Result | Notes |
|---|---|---|---|
| 5 | `investigate_email(sweep_candidates=true)` | ❌ | Raise `ValueError: Invalid scheme component: socks5h`. |
| 6 | `generate_candidates(seed=email, broad)` | ✅ | 19 candidates. |
| 7 | `breach_search(email)` | ✅ | **Primary win.** 6 breaches; ProxyNova noise; EmailRep parse fail. |
| 8 | `github_leaks(email)` | ⚠ | Keyless → code search skipped; no user/commit hits. |

### Phase 3 — Handle sweep (socks5h → timeouts)
| # | Tool + args | Result | Notes |
|---|---|---|---|
| 9–12 | `sweep_username` ×4 (handle variants) | ❌ | Same socks5h `ValueError`. |
| 13 | `mentions(email)` | ⚠ | `reddit: null, stackexchange: null`. |
| 14 | `configure(proxy=socks5://...)` | ⚠ | Worked; DNS-leak warning (see root cause A2). |
| 15–17 | `sweep_username` ×3 (socks5) | ❌ | MCP `-32001` — full site db exceeds client timeout. |
| 18 | `configure(proxy=None)` (**string**) | ❌ | `ValueError: invalid proxy URL 'None'` (bug E). |
| 19 | `configure()` (no proxy) | ✅ | Proxy cleared. |
| 20–23 | `sweep_username` ×4 (no proxy, full db) | ❌ | Still `-32001` — duration, not proxy, is the problem. |
| 24 | `pivot_results()` | ⚠ | "no results collected yet — run a sweep first" (correct, chain blocked). |
| 25 | `suggest(name query)` | ⚠ | All engines empty. |
| 26–28 | `search_dork` ×3 (name/e-mail dorks) | ❌ | bing junk, ddg empty, `throttled`. |
| 29 | `enumerate_subdomains(example.com)` | ⚠ | Only `www` — **off-plan guess** (see model assessment M5). |
| 30 | `hunt_docs(email)` | ❌ | All dork packs junk — wrong target type for this tool. |
| 31 | `autopsy_url` ×4 (ig/x/tt/fb) | ❌ | Empty or unreachable (JS-walled). |
| 32 | `websearch` exact email | ⚠ | No exact match; only unrelated same-name people. |
| 33–34 | `sweep_username(..., max_sites=50)` ×2 | ✅ | **The fix.** 48 sites, ~5 "found" — all dubious (see root cause D3). |
| 35–36 | `autopsy_url(wikipedia/apple)` | ⚠ | Empty → confirms the sweep "found"s are false positives. |

### Phase 4 — Name + handle corroboration
| # | Tool + args | Result | Notes |
|---|---|---|---|
| 37 | `investigate_name(Test, User)` | ✅ | Candidates + dorks; no Wikipedia collision. |
| 38 | `sweep_username(test_user, max=50)` | ✅ | 5 "found" — same dubious families. |
| 39 | `search_dork("test_user")` | ✅ | **Decisive link**: Instagram "Jane (@test_user)". |
| 40 | `autopsy_url(ig)` | ❌ | Empty (login shell). |
| 41 | `auto_dork_url(ig)` | ❌ | Keywords = IG boilerplate ("amount symbol"); dorks useless. |
| 42 | `mentions(handle)` | ⚠ | null/null. |
| 43–47 | mirrors (imginn, picnob, picuki), instagram oEmbed, Googlebot UA | ❌ | All 302/403/WAF. |

### Phase 5 — TikTok + reaction dig
| # | Tool + args | Result | Notes |
|---|---|---|---|
| 48–49 | `autopsy_url(@testuser / @testuser23)` | ⚠ | Empty (WAF shell). |
| 50–51 | `search_dork` (tiktok handles) | ❌ | No profile indexed; only a lookalike handle. |
| 52–53 | `curl` tiktok profiles / `user/detail` API | ❌ | Slardar WAF wall (1.4 KB), empty API. |
| 54–56 | urlebird (404), tikwm (Cloudflare "Just a moment"), m.tiktok API (empty) | ❌ | All blocked. |
| 57–60 | Wayback availability (429 ×2) / CDX (handles, ig = empty) | ❌ | No archives for any of the three accounts. |
| 61–63 | IG posts via curl + oEmbed | ❌ | 629 KB Meta-AI shell; oEmbed 302 (deprecated). |
| 64–66 | reaction dorks ("likes/comments/views") | ❌ | junk (unrelated sites). |

**Net:** Instagram account confirmed + a small number of posts/reels
enumerated; **reaction counts not retrievable** (login-walled). TikTok handles
**unverifiable** — no index entry, no archive, no mirror evidence; likely
nonexistent/private/new.

---

## 3. Efficacy ratings

Scored 1–10 for *result value delivered per operation*, not effort.

| Tool | Calls | Win rate | Rating | Verdict |
|---|---|---|---|---|
| `configure` | 4 | 75 % | 7 | ✅ main path; **bug with `"None"` string** |
| `status` | 1 | 100 % | 9 | ✅ |
| `tor_check` | 1 | 100 % | 9 | ✅ |
| `osint_plan` | 1 | 100 % | 8 | ✅ |
| `generate_candidates` | 2 | 100 % | 8 | ✅ (rich for e-mails, tautological for handles) |
| `breach_search` | 1 | 100 % | **9** | ✅ crown jewel; ProxyNova/EmailRep noise |
| `investigate_name` | 1 | 100 % | 7 | ✅ |
| `search_dork` | 8 | ~30 % | 5 | ⚠ junk-heavy, but **the decisive pivot** when it works |
| `sweep_username` (default) | 11 | 0 % | 2 | ❌ crashes (socks5h) / MCP timeouts |
| `sweep_username` (`max_sites=50`) | 4 | 100 % | 8 | ✅ the working configuration |
| `github_leaks` | 2 | 0 % (keyless) | 3 | ⚠ needs `OHO_GITHUB_KEY` |
| `mentions` | 3 | 0 % | 2 | ❌ both sources null |
| `suggest` | 2 | 0 % | 2 | ❌ empty for identifiers |
| `autopsy_url` | 10 | ~10 % | 3 | ❌ only server-rendered pages |
| `auto_dork_url` | 1 | 0 % | 2 | ❌ keyword boilerplate |
| `pivot_results` | 1 | n/a | n/a | blocked by upstream failures |
| `hunt_docs` | 1 | 0 % (email) | 2 | ❌ wrong target type |
| `enumerate_subdomains` | 1 | 100 % | 5 | ✅ but off-plan usage |

---

## 4. Root-cause analysis (code references)

### A. The sweep stack — the two dominant failures

**A1 — `socks5h://` crash.** `Pipelines.run_username_pipeline` →
`check_username_on_sites` → `_pick_checker` (`osint_core/async_check.py:342`)
chooses `AiohttpChecker` for any `socks` proxy, which calls
`ProxyConnector.from_url(self.proxy)` (`async_check.py:133`).
`aiohttp_socks 0.11.0` only accepts `socks5`/`socks4`/`http` — **`socks5h` raises
`ValueError: Invalid scheme component: socks5h`**. The tool's own recommended
OPSEC config (`socks5h://127.0.0.1:9050`, per `docs/AGENTS.md:82`) therefore
cannot sweep. The exception propagates out of `asyncio.run` and the *entire*
`investigate_email` call fails, discarding its completed source lookups too.

**A2 — DNS-leak contradiction.** `socks5://` (the only scheme the sweep
accepts) triggers `warn_if_dns_leaking` (`osint_core/net.py:47`), and the OPSEC
docs forbid it. The tool family is internally inconsistent: no proxy value can
satisfy both the sweep and the DNS policy.

**A3 — unbounded sweep = MCP timeout.** Full merged site db is over 2 500
sites; at `in_parallel=20, timeout=10 s` worst case is ~20+ min. Every default
sweep exceeded the client request timeout (`MCP -32001`). `_sweep_username`
(`ohosint_mcp/tools.py:214`) only bounds work when the client happens to pass
`max_sites`. The single change that unblocked the case (`max_sites=50`) came
from model improvisation, not a tool guarantee.

### B. Platform lockout (IG / TikTok / FB / X)

`autopsy_url` (`ohosint_mcp/tools.py:277`) returns whatever raw HTML a GET
gives. IG/TikTok return login/WAF shells, so `cross_links` / `page_emails` /
`at_handles` (`osint_core/harvest.py:17-29`) return empty. There is no
wall-detection, no oEmbed/mirror fallback chain, and no search-index
corroboration pass — the exact mechanism that found the account is manual
dorking, not a tool.

### C. Dork/search quality

`search_bing` (`osint_core/search.py:96-115`) marks near-zero domains as
"junk" but has **no relevance guard**: `junk` and even `ok` pages can share
zero tokens with the query (observed: unrelated results dominating). The keyed
Google engine (`search.py:118`, acts on `OHO_GOOGLE_KEY`+
`OHO_GOOGLE_CX`) was not configured, so dorking lived on throttled scrape
endpoints. `hunt_docs` reused the same engines in a 9-dork pack — pure noise
for an e-mail target.

### D. Sweep classifier noise

Every sweep reported ~5 `found`, dominated by the same families —
AppleDeveloper/AppleDiscussions, Wikipedia CentralAuth, GitHub Gist, Discord.
These endpoints reply `200` for any username; the presence-marker veto
(`async_check.py:329`, site `presense_strs`) is either not declared for those
sites or too weak. Sweep results therefore cannot be trusted without per-site
confirmation → model precision drops, and only the search-index pass salvages
the real hit.

### E. `configure(proxy="None")` bug

`_configure` treats any truthy string as a URL and calls
`valid_proxy("None")` → `ValueError` (`ohosint_mcp/tools.py:92`), even though
`Session.set_proxy` already understands `"off"/"none"/""`
(`ohosint_mcp/session.py:43`). The wrapper and the session disagree.

### F. Breach polish

- **ProxyNova noise**: adapter returned up to 10 000 `credential_lines`, only a
  handful relevant to the query, bloating output and dumping unrelated personal
  data into a report stream.
- **EmailRep**: returned non-JSON → `"Expecting value: line 1 column 1"`
  surfaced raw, no graceful fallback.

### G. Misc signal loss

- `mentions` (`osint_core/mentions.py`) returned null for both sources under
  the session's conditions — no diagnostics to tell "blocked" from "no hits".
- `suggest` is empty for handles (only useful for whole names) but consumed a
  request slot each time; no self-valuation.
- `auto_dork_url` keyword extraction (`extract_keywords`) has no boilerplate
  stoplist; IG's `amount symbol`/`cdninstagram` tokens dominate.

---

## 5. Model-behavior assessment

| # | What the model did | Verdict |
|---|---|---|
| M1 | Followed the planner's phases; retried with config variants after failures | ✅ methodical |
| M2 | Discovered `max_sites=50` bounding after several timeouts | ⚠ effective but arrived too late — wasted ~10 calls first |
| M3 | Used `search_dork` on the raw handle text → found the IG account | ✅ **the case-defining move** |
| M4 | Repeated identical failing ops (timeout sweeps ×7, wayback 429 ×2) instead of changing strategy after 1–2 failures | ❌ |
| M5 | Invented a domain (`example.com`) to `enumerate_subdomains` — off-plan, low value | ❌ |
| M6 | Ran `hunt_docs` against an e-mail (wrong target type) | ❌ |
| M7 | Harassed hard-walled platforms (Googlebot UA, mirrors, oEmbed, CDX) to exhaustion before concluding "not passive-extractable" | ⚠ thorough, but 15+ calls yielded zero |
| M8 | Never contacted/notified the target; kept OPSEC rules intact throughout | ✅ |
| M9 | Used `auto_dork_url` output blindly despite obvious boilerplate keywords | ❌ |
| M10 | Fed found-handle claims straight to conclusions without confirming them (Apple/wiki/gist/discord false positives) | ❌ |

Net: sound instincts, but the environment rewarded the model for making up
work rather than for declaring "not extractable" — there was no tool that says
"this platform is walled, here is the recommended alternative" quickly.

---

## 6. Improvement backlog (prioritized)

Priority P0 = crash, P1 = usability/scale, P2 = platform lockout,
P3 = result quality, P4 = polish. Each item lists file touch points and a test
hook.

### P0 — crashes (must fix)

1. **Normalize `socks5h` for the sweep.**
   Prefer `CurlCffiChecker` (libcurl supports `socks5h://`) when the proxy
   starts with `socks5h`, else rewrite to `socks5://` with an explicit
   DNS-leak warning. Files: `osint_core/async_check.py:131-151, 342-351`.
   Test: sweep under `socks5h://` doesn't raise; regression test pins
   `"Invalid scheme component"` out.
2. **Per-site failure isolation.** Wrap each `check_site` so a connector-level
   `ValueError` degrades to a site error instead of aborting the whole sweep /
   `investigate_email`. Files: `osint_core/async_check.py:452-469`.
3. **`configure` proxy-clear semantics.** Accept `"None"/"off"/""/null` as
   clear (mirror `Session.set_proxy`). Files: `ohosint_mcp/tools.py:92`.

### P1 — sweep scale (timeout-proof)

4. **Tiered site profiles.** Add `sites_db="socials|top100|full"` presets;
   default `sweep_username` to a bounded ~100-site set so it returns in
   <1 min. Full db becomes explicit opt-in. Files: `ohosint/pipelines.py:18-59`,
   `ohosint_mcp/tools.py:214`.
5. **Partial-result reporting.** On `asyncio.TimeoutError`/client timeout,
   return the completed results + `"truncated": true` instead of dropping
   everything (observed need: `.run_investigation` also drives full sweeps at
   depth=full, `ohosint_mcp/tools.py:350`).
6. **Kill false-positive families.** Declare `presense_strs` for Apple/
   Wikipedia/Gist/Discord or add a post-filter: a `found` now requires ≥1
   presence marker when the site declares none. Files: `osint_core/site_db.py`
   data + `osint_core/async_check.py:280-330`.

### P2 — walled platforms

7. **Wall-aware `autopsy_url`.** Detect IG/TikTok/FB login shells and WAF
   fingerprints (reuse `detect_waf`, `async_check.py:49`) and return a
   structured `{platform, wall, hints}` verdict instead of empty `links`.
   Files: `ohosint_mcp/tools.py:277-287`, `osint_core/harvest.py`.
8. **Search-index corroboration pass.** When a platform is walled, fall back
   to a dork `username + site:platform` and report evidence snippets — this is
   literally the move that cracked the case and belongs in the tool, not in
   the model's improvisation. Files: `osint_core/search.py`, `ohosint_mcp/tools.py`.
9. **Boilerplate stoplist + og-tags in `auto_dork_url`.** Filter IG/JS
   boilerplate tokens; when present, seed keywords from `og:title`
   /`og:description`. Files: `osint_core/keywords.py`.

### P3 — search/dork quality

10. **Relevance guard in `search_bing`/`dork`.** Drop hits with zero token
    overlap with the query; downgrade to `junk` when nothing overlaps. This
    removes the unrelated-noise class. Files: `osint_core/search.py:96-115`.
11. **`hunt_docs` target-type validation.** Refuse e-mail targets (or no-op
    with a clear message). Files: `osint_core/docs.py`.
12. **Key readiness surfacing.** `status()` already exposes `google_keyed`/
    `github_keyed`; add a one-line "recommended next key to configure" hint so
    the model stops burning scrape engines while keyed APIs sit idle. Files:
    `ohosint_mcp/tools.py:111-127`.

### P4 — breach polish & signals

13. **ProxyNova relevance filter** — keep only lines containing the query
    token; cap at e.g. 100 lines in the report. Files: `osint_core/breach.py`.
14. **Tolerant JSON in all adapters** — strip control chars / handle HTML
    error pages with a `note`, never surface `json.JSONDecodeError` text raw.
    Files: `osint_core/breach.py`.
15. **`mentions` diagnostics** — return per-source `{state, note}` ("blocked",
    "rate-limited", "no hits") so an empty result is distinguishable from a
    broken one. Files: `osint_core/mentions.py`.
16. **Veracity/confidence on sweep results** and a "confirm via search-index"
    flag so the model ranks pivots instead of feeding false positives to
    `pivot_results`. Files: `osint_core/scan_result.py`.

### Suggested acceptance gates

- `pytest` stays green (104 tests; no new network calls — mock at the `oc.*`
  seam per `docs/AGENTS.md:97`).
- New regression tests: (1) sweep under `socks5h://` proxy; (2)
  `configure(proxy=None)` clears; (3) capped sweep returns with
  `"truncated"` under a mock timeout; (4) bing relevance guard.
- Semi-manual smoke: re-run the sample e-mail case with Tor on —
  `sweep_username` must return in <60 s, `@test_user` must surface via the
  corroboration pass, reaction counts still declared "login-required" honestly.

---

## 7. Operational summary for the target (genericized)

Maintained for continuity, not part of the improvement plan.

- **Exposure:** e-mail present in 6 breach datasets (social app 2018,
  classifieds 2022-09, credentials combo 2023, stealer logs 2025 and 2022→);
  infostealer infection context from a Windows machine compromise
  (2022-03-07); hashed/partial passwords leaked.
- **Identity:** first + last name pair, region implied by the classifieds
  breach; Instagram `@test_user` (display name "Jane", ~5 posts/reels) is the
  only confirmed social hub. TikTok `@testuser` / `@testuser23` — no verifiable
  presence.