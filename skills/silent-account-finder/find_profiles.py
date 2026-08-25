#!/usr/bin/env python3
"""silent-account-finder: passive (target-never-notified) locator for XNXX/XVideos
profiles tied to an email address. GET requests to public pages only.

Thin CLI over the shared `osint_core` package.
"""

import argparse
import os
import re
import sys

# Make the repo root importable when this script is launched by path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from osint_core import (  # noqa: E402
    PLATFORMS, VERDICT_MARK,
    add_common_args, fetcher_from_args, save_report,
    dork, probe, leakcheck, simple_candidates, split_email,
)

PROFILE_SITES = ["xnxx", "xvideos"]

DORK_QUERIES = [
    '"{email}"',
    'site:xvideos.com "{fl}"',
    'site:xnxx.com "{fl}"',
    '"{fu}" "{lu}" profile',
    'site:xvideos.com OR site:xnxx.com "{f}{l}{n}"',
]


def main():
    ap = argparse.ArgumentParser(description="Passive xnxx/xvideos account finder")
    ap.add_argument("--email", required=True)
    add_common_args(ap)
    ap.add_argument("--max-candidates", type=int, default=12)
    ap.add_argument("--skip-breaches", action="store_true")
    ap.add_argument("--out", default=None, help="JSON report path")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    fetch = fetcher_from_args(args)
    local, _, first, last, num = split_email(args.email)
    subs = {"email": args.email, "fl": f"{first} {last}".strip(),
            "fu": first, "lu": last, "f": first, "l": last, "n": num}

    cands = simple_candidates(local)[: args.max_candidates]
    print(f"[*] target: {args.email}  candidates({len(cands)}): {', '.join(cands)}")

    results = {"email": args.email, "candidates": cands, "profiles": [],
               "dorks": [], "breaches": None}

    print("\n=== PHASE 2: public profile probing ===")
    for site in PROFILE_SITES:
        for c in cands:
            hit, title = probe(fetch, site, PLATFORMS[site], c)
            mark = VERDICT_MARK.get(hit["verdict"], "[!]")
            print(f'  {mark} {site:<8} {c:<24} {title}')
            results["profiles"].append({**hit, "title": title})

    print("\n=== PHASE 3: search-engine dorks ===")
    seen = set()
    for q in DORK_QUERIES:
        query = q.format(**subs)
        if len(query) < 6:
            continue
        hits, _states, _flag = dork(fetch, query)
        adult = [h for h in hits
                 if re.search(r"(xnxx|xvideos)\.", h["url"]) and h["url"] not in seen]
        for h in adult:
            seen.add(h["url"])
        print(f'  [{len(hits):>2} results] {query}   -> adult hits: {len(adult)}')
        if args.verbose:
            for h in adult:
                print(f"      {h['title'][:70]}  {h['url']}")
        slug_hits = re.findall(r"(?:xnxx|xvideos)\.\w+/profiles?/([A-Za-z0-9_.-]+)",
                               " ".join(h["url"] for h in adult))
        results["dorks"].append({"query": query, "adult_hits": adult,
                                 "profile_slugs": list(set(slug_hits))})

    slugs = sorted({s for d in results["dorks"] for s in d["profile_slugs"]})
    if slugs:
        print(f"\n[*] profile slugs found via search engines: {', '.join(slugs)}")

    if not args.skip_breaches:
        print("\n=== PHASE 4: breach metadata ===")
        b = leakcheck(fetch, args.email, limit=30)
        b["source"] = "leakcheck.io (public)"
        src_adult = [s for s in (b.get("sources") or [])
                     if isinstance(s, str) and re.search(r"x(nxx|videos)", s, re.I)]
        print(f"  breaches found: {b['found']}  sources: {', '.join(map(str, b['sources'][:10])) or '-'}"
              f"  {b['note']}")
        if src_adult:
            print(f"  !! adult-platform leak sources: {src_adult} -> combo lists may contain the handle")
        results["breaches"] = b

    confirmed = [p for p in results["profiles"] if p["verdict"] == "confirmed"]
    print("\n================ SUMMARY ================")
    print(f"  confirmed profiles : {[p['url'] for p in confirmed] or 'none'}")
    print(f"  search-engine slugs: {slugs or 'none'}")
    print("  next step if empty : widen candidates (--max-candidates 20), add Yandex manual check,"
          " or accept that the handle is unrelated to the email (common on adult platforms)")

    if args.out:
        save_report(args.out, results)
        print(f"\n[i] report saved: {args.out}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
