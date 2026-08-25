---
name: silent-recon
description: "Generalized passive OSINT process for pivoting on NAME + EMAIL + PHONE + USERNAME without ever notifying the target. Interactive Python shell with Tor SOCKS5 support: breach metadata, gravatar, stealer logs, handle permutation sweeps across 21 platforms, search-engine dorks, profile autopsy, correlation/pivot suggestions. GET-only public sources; explicitly excludes password-reset/recovery/OTP flows that would alert the owner."
---

# /silent-recon

One process, any identifier. Feed it a name, an email, a phone number or a
handle — it normalizes, permutes, probes passively, and suggests the next pivot.
All traffic can ride Tor so *your* origin is hidden too (and adult/leak sites
don't see your home IP).

## Hard rules (enforced by design)

1. **GET only** on public pages/endpoints. Never POST to login / recovery /
   forgot-password / OTP-send endpoints — those are the flows that notify the owner.
2. No account creation, no logins, no credential testing from breaches.
3. Randomized delays + UA rotation by default; route through Tor when possible.
4. Lawful purpose required (authorized assessment / own accounts / legal case).

## The general process (any identifier → identity cluster)

| Phase | Step | Silent because |
|---|---|---|
| 0 | OPSEC setup: start tor, `proxy socks5h://127.0.0.1:9050`, `torcheck` | your IP never touches target infra |
| 1 | Normalize identifier (email local-part parse / E.164 phone / name split) | pure local math |
| 2 | Passive lookups: breach metadata, stealer logs, gravatar | queries 3rd-party DBs, not the platform |
| 3 | Candidate generation: username permutations from name/email (+year hints) | local |
| 4 | Handle sweep: GET-probe candidates across 21 platforms (`sweep`, `username`) | reads public pages like any visitor |
| 5 | Dorks: quoted email/name/phone formats via DDG+Bing; extract profile slugs | hits search engines' caches, not security systems |
| 6 | Autopsy confirmed profiles: harvest cross-links, emails, @handles | ordinary page view |
| 7 | Correlate & pivot: loop harvested handles back to phase 3; `pivot` command | nothing sent anywhere |

Loop phases 3→7 until new identifiers stop appearing, then conclude.

## Setup

```bash
pip install "requests[socks]" phonenumbers   # phonenumbers optional but recommended
sudo apt install tor && sudo service tor start   # listens on 127.0.0.1:9050
```

## Run

```bash
python3 skills/silent-recon/silent_recon.py --proxy socks5h://127.0.0.1:9050

# non-interactive one-shots:
python3 skills/silent-recon/silent_recon.py -c "torcheck" \
        -c "email user@example.com" -c "phone +14155550123" \
        -c "name jane doe --year 1990" -c "save"
```

## Shell commands

| Command | What it does |
|---|---|
| `proxy <url\|off>` | set/remove SOCKS5/HTTP proxy |
| `torcheck` | show exit IP + whether circuit is Tor |
| `newnym` | rotate Tor circuit for fresh exit IP (needs ControlPort 9051 + CookieAuthentication in torrc); use when engines throttle |
| `delay <min> <max>` | randomized inter-request sleep |
| `status` | session state: proxy, counters, stored identifiers |
| `email <addr>` | leakcheck.io + Hudson Rock stealer logs + Gravatar + dorks + candidate gen |
| `phone <num>` | normalize (E.164/national/intl), validity, line type, carrier hint, dork every format |
| `name <f> [l] [--year YYYY]` | identity dorks (linkedin/facebook/socials/adult) + slug extraction + candidate gen |
| `username <h> [quick\|all] [-v]` | GET-probe one handle across platforms |
| `sweep [quick\|all]` | probe all generated candidates across platforms |
| `autopsy <url>` | pull cross-links / emails / @handles from any profile page |
| `dork "<query>"` | free-form query via DDG + Bing |
| `pivot` | correlation engine → suggested next silent moves |
| `save [path]` | JSON report of everything collected |

## Reading verdicts

- `[+] confirmed` — status 200, no not-found markers, handle appears in page/title
- `[?] probable` — 200 without explicit markers (login-walled sites like instagram/x)
- `[-] absent` / `[!] unknown` — 404-class or network failure

Dork lines show per-engine state `(ddg/bing)`: `ok` = real results,
`empty`/`junk`/`None` = engine throttled this exit IP → run `newnym`, wait ~10s,
retry. Search engines aggressively rate-limit datacenter/Tor IPs; treat a
throttled dork pass as inconclusive, not negative.

## Interpretation notes

- Breach source names containing xvideos/xnxx ⇒ combo lists likely contain the
  handle itself; prioritize `sweep all`.
- Gravatar linked accounts are high-value pivots (people reuse handles).
- Phone: only passive signals here (format dorks, carrier/country). Never trigger
  WhatsApp/Telegram/Truecaller verification SMS — that notifies the owner.
- Adult-platform handles rarely match email local-parts; treat `probable` as a
  lead, confirm via bio/avatar/timestamp correlation before concluding.
