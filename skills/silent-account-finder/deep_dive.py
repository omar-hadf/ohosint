#!/usr/bin/env python3
"""deep_dive.py - second-pass passive pivots: profile autopsy, sibling-platform
handle sweep, global handle dorks, Wayback CDX enumeration, Hudson Rock lookup.

Everything is derived from the CLI arguments; no target is hardcoded. Thin CLI
over the shared `osint_core` package.
"""

import argparse
import json
import os
import re
import sys
from urllib.parse import urlparse

# Make the repo root importable when this script is launched by path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from osint_core import (  # noqa: E402
    PLATFORMS,
    add_common_args, fetcher_from_args, save_report,
    search_ddg, probe, hudson_rock, wayback_cdx, second_wave_candidates,
    split_email, page_title, cross_links, page_emails, at_handles,
)

SIBLING_SITES = ["xnxx", "pornhub", "xhamster", "redtube"]
ADULT_HOSTS = ["xvideos.com", "xnxx.com"]

# Adult-focused link filter for the autopsy step.
AUTOPSY_EXCLUDE = r"(xvideos|xnxcdn|static-|google|apple|microsoft|cloudflare)"
AUTOPSY_KEEP = (
    r"(xnxx|pornhub|xhamster|redtube|youporn|t\.me|telegram|twitter|x\.com|"
    r"instagram|facebook|kick|snap|reddit|tiktok|youtube|mail|gmail|yahoo|hotmail)"
)


def autopsy(fetch, url):
    print(f"\n=== P1: AUTOPSY {url} ===")
    r = fetch.get(url)
    if r is None or r.status_code != 200:
        print("  unreachable")
        return {}
    html = r.text
    title = page_title(html)
    print(f"  title: {title[:90] or '-'}")
    interesting = cross_links(html, keep=AUTOPSY_KEEP, exclude=AUTOPSY_EXCLUDE)
    print("  cross-links found:" if interesting else "  no cross-platform links in page")
    for h in interesting[:20]:
        print(f"    -> {h}")
    mail = page_emails(html)
    if mail:
        print(f"  emails on page: {mail}")
    return {"title": title, "cross_links": interesting,
            "emails_on_page": mail, "at_handles": at_handles(html, limit=30)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--known-handle", required=True,
                    help="a confirmed handle for the target, e.g. from a found profile")
    ap.add_argument("--profile-url", required=True,
                    help="a confirmed profile URL to autopsy")
    add_common_args(ap)
    ap.add_argument("--skip-platforms", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    fetch = fetcher_from_args(args)
    _local, _domain, first, last, _num = split_email(args.email)
    handle = args.known_handle
    host = urlparse(args.profile_url).netloc or ADULT_HOSTS[0]
    name = f"{first} {last}".strip()
    seeds = [s for s in dict.fromkeys([first, last, re.sub(r"\d+", "", handle)]) if s]
    terms = [t for t in dict.fromkeys([handle, first, last]) if t]

    R = {"email": args.email, "autopsy": {}, "platform_hits": [], "cdx_slugs": {},
         "hudson_rock": {}}

    R["autopsy"] = autopsy(fetch, args.profile_url)

    if not args.skip_platforms:
        print("\n=== P2: SIBLING PLATFORM SWEEP (2nd-wave handles) ===")
        cands = second_wave_candidates(seeds)
        print(f"  {len(cands)} candidates x {len(SIBLING_SITES)} platforms")
        for site in SIBLING_SITES:
            for u in cands:
                hit, title = probe(fetch, site, PLATFORMS[site], u)
                if hit["verdict"] in ("confirmed", "probable"):
                    mark = "+" if hit["verdict"] == "confirmed" else "?"
                    print(f"  [{mark}] {site:<9} {u:<18} {title}")
                    R["platform_hits"].append({"site": site, "user": u,
                                               "verdict": hit["verdict"], "title": title})

    print("\n=== P3: GLOBAL HANDLE DORKS ===")
    dorks = [f'"{handle}"', f'"{handle}" -site:{host}']
    if name:
        dorks.append(f'"{name}"')
    dorks.append(f'"{handle}" (forum OR profile OR user)')
    for q in dorks:
        _state, hits = search_ddg(fetch, q)
        top = [h["title"][:60] for h in hits[:3]]
        print(f'  [{len(hits):>2} hits] {q}')
        for t in top:
            print(f"      - {t}")

    print("\n=== P4: WAYBACK CDX ENUMERATION ===")
    for pat in [f"{h}/profiles/{t}" for h in ADULT_HOSTS for t in terms]:
        rows = wayback_cdx(fetch, pat)
        slugs = sorted({re.sub(r"^https?://(www\.)?", "", o).split("?")[0]
                        for o, _ in rows})[:15]
        print(f"  [{len(rows):>2} snapshots] {pat}")
        for s in slugs:
            print(f"      {s}")
        R["cdx_slugs"][pat] = slugs

    print("\n=== P5: HUDSON ROCK STEALER LOOKUP ===")
    R["hudson_rock"] = hudson_rock(fetch, args.email)
    print(json.dumps(R["hudson_rock"], indent=2)[:800])

    print("\n============ DEEP-DIVE SUMMARY ============")
    print(f"  autopsy cross-links : {R['autopsy'].get('cross_links', []) or 'none'}")
    hits = [f"{h['site']}:{h['user']}" for h in R["platform_hits"]]
    print(f"  new platform hits   : {hits or 'none'}")
    flat_slugs = sorted({s.split('/')[-1] for sl in R["cdx_slugs"].values()
                         for s in sl if "/profiles/" in s})
    print(f"  cdx archived slugs  : {flat_slugs or 'none'}")

    if args.out:
        save_report(args.out, R)
        print(f"\n[i] saved {args.out}")


if __name__ == "__main__":
    main()
