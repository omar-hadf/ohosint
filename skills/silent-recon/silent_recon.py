#!/usr/bin/env python3
"""silent-recon: passive multi-identifier OSINT shell (email / name / phone /
username) over Tor SOCKS5. GET-only public sources; the target is never
notified. Lawful use only.

All network/search/probe/lookup logic lives in the shared `osint_core` package;
this file is just the interactive command surface over it.
"""

import argparse
import cmd
import json
import os
import re
import socket
import sys
from datetime import datetime, timezone

# Make the repo root importable when this script is launched by path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from osint_core import (  # noqa: E402
    PHONE_TYPE, PLATFORMS, QUICK_SITES, VERDICT_MARK,
    Fetcher, valid_proxy, dork, probe, gravatar, hudson_rock, leakcheck,
    generate_candidates, split_email, add_common_args, save_report,
    page_title, cross_links, page_emails, at_handles,
)


class ReconShell(cmd.Cmd):
    intro = ("silent-recon v1.0 - passive OSINT shell (GET-only, target never notified)\n"
             "type 'help' for commands. lawful purpose required.\n")
    prompt = "recon> "

    def __init__(self, proxy=None, delay=(1.5, 3.5)):
        super().__init__()
        self.fetch = Fetcher(proxy=proxy, delay=delay)
        self.data = {"meta": {"started": self._now(), "proxy": proxy or "direct"},
                     "emails": {}, "phones": {}, "names": [],
                     "usernames": [], "findings": []}
        self._last_candidates = []

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _dork_block(self, queries, top=5, minlen=1):
        """Run a list of dork queries, print each result block, return all hits."""
        allhits = []
        for q in queries:
            if len(q) < minlen:
                continue
            hits, states, flag = dork(self.fetch, q)
            print(f'  [{len(hits):>2}] {q}  ({states.get("ddg")}/{states.get("bing")}){flag}')
            for h in hits[:top]:
                print(f"      {h['title'][:65]}  {h['url'][:72]}")
            allhits += hits
        return allhits

    def do_status(self, arg):
        """show session state: proxy, delays, counters, stored identifiers"""
        print(f"  proxy        : {self.data['meta'].get('proxy', 'direct')}"
              f"  (current: {'set' if self.fetch.session.proxies else 'direct'})")
        print(f"  delay range  : {self.fetch.delay}")
        print(f"  requests sent: {self.fetch.n_req}")
        print(f"  identifiers  : emails={list(self.data['emails']) or '-'} "
              f"phones={list(self.data['phones']) or '-'} "
              f"names={self.data['names'] or '-'} "
              f"usernames={self.data['usernames'] or '-'}")

    def do_proxy(self, arg):
        """proxy <url|off>  e.g. proxy socks5h://127.0.0.1:9050"""
        arg = arg.strip()
        if not arg or arg == "off":
            self.fetch.session.proxies = {}
            self.data["meta"]["proxy"] = "direct"
            print("[*] direct connection")
            return
        if not valid_proxy(arg):
            print("[!] bad proxy url (use socks5h://127.0.0.1:9050)")
            return
        self.fetch.session.proxies = {"http": arg, "https": arg}
        self.data["meta"]["proxy"] = arg
        print(f"[*] proxy set -> {arg}  (run 'torcheck' to verify)")

    def do_torcheck(self, arg):
        """verify circuit via tor project check endpoint"""
        r = self.fetch.get("https://check.torproject.org/api/ip")
        if r is None:
            return
        try:
            j = r.json()
            state = "TOR" if j.get("IsTor") else "NOT tor"
            print(f"  exit ip: {j.get('IP')}  [{state}]")
        except Exception:
            print("  [!] unexpected response:", r.text[:120])

    def do_delay(self, arg):
        """delay <min> <max>  random sleep between requests (seconds)"""
        p = arg.split()
        if len(p) != 2:
            print("[!] usage: delay 2 6"); return
        try:
            a, b = float(p[0]), float(p[1])
            assert 0 <= a <= b <= 60
        except Exception:
            print("[!] invalid range"); return
        self.fetch.delay = (a, b)
        print(f"[*] delay -> uniform({a}, {b})s")

    def do_email(self, arg):
        """email <address>  breach metadata + gravatar + dorks"""
        addr = arg.strip().lower()
        if not re.match(r"^[\w.+-]+@[\w-]+\.[\w.-]+$", addr):
            print("[!] not an email"); return
        rec = self.data["emails"].setdefault(addr, {})
        local, domain, first, last, num = split_email(addr)
        rec.setdefault("identifiers", {"local": local, "domain": domain,
                                       "first": first, "last": last, "num": num})
        print(f"\n=== EMAIL {addr} ===")
        print(f"  parsed: first='{first}' last='{last}' num='{num}' domain={domain}")

        print("\n-- leakcheck.io (public breach metadata)")
        breaches = leakcheck(self.fetch, addr)
        if breaches["found"] is not None:
            print(f"  found={breaches['found']} sources={breaches['sources'][:12]}")
        elif breaches["note"]:
            print("  no data / error:", breaches["note"])
        rec["breaches"] = breaches

        print("\n-- hudson rock stealer log check")
        hr = hudson_rock(self.fetch, addr)
        if "error" in hr:
            print("  [!]", hr["error"])
        else:
            print(f"  {hr['message']}")
            if hr["stealer_count"]:
                print(f"  infected machines: {hr['machines']}")
        rec["stealer_logs"] = hr

        print("\n-- gravatar public profile")
        grav = gravatar(self.fetch, addr)
        if grav["profile"]:
            print(json.dumps(grav["profile"], indent=2)[:600])
        else:
            print("  no public gravatar profile")
        rec["gravatar"] = grav

        print("\n-- dorks")
        queries = [f'"{addr}"',
                   f'"{local}" "{domain}"',
                   f'site:xvideos.com OR site:xnxx.com "{first} {last}"'.strip()]
        rec["dorks"] = self._dork_block(queries, top=5, minlen=8)

        cands = generate_candidates(local)
        self._last_candidates = cands
        print(f"\n[*] username candidates from local part ({len(cands)}): "
              f"{', '.join(cands)}")
        print("[*] next: run 'username <handle>' or 'sweep' to test them")

    def do_phone(self, arg):
        """phone <number>  normalize + line-type + dorks"""
        raw = arg.strip()
        if not raw:
            print("[!] usage: phone +14155550123"); return
        rec = self.data["phones"].setdefault(raw, {})
        info = {"raw": raw}
        try:
            import phonenumbers as pn
            num = pn.parse(raw, None)
            info.update({
                "valid": pn.is_valid_number(num),
                "possible": pn.is_possible_number(num),
                "country": pn.region_code_for_number(num),
                "e164": pn.format_number(num, pn.PhoneNumberFormat.E164),
                "intl": pn.format_number(num, pn.PhoneNumberFormat.INTERNATIONAL),
                "national": pn.format_number(num, pn.PhoneNumberFormat.NATIONAL),
                "type": PHONE_TYPE.get(pn.number_type(num), "unknown"),
                "carrier_hint": None,
            })
            try:
                from phonenumbers import carrier
                info["carrier_hint"] = carrier.name_for_number(num, "en") or None
            except Exception:
                pass
        except ImportError:
            digits = re.sub(r"\D", "", raw)
            info.update({"e164": "+" + digits, "note":
                         "phonenumbers lib missing (pip install phonenumbers); raw normalization only"})
        except Exception as e:
            print("[!] parse error:", str(e)[:100]); return

        rec["info"] = info
        print(f"\n=== PHONE {raw} ===")
        for k, v in info.items():
            print(f"  {k:<11}: {v}")

        print("\n-- dorks")
        variants = {info.get("e164"), info.get("national"),
                    info.get("intl"), raw, re.sub(r"\D", "", raw)} - {None, ""}
        rec["dorks"] = self._dork_block([f'"{v}"' for v in sorted(variants)], top=4)
        print("\n[*] manual-passive next: truecaller/sync.me web preview only; "
              "never trigger OTP/SMS verification flows (that alerts the owner)")

    def do_name(self, arg):
        """name <first> [last] [--year YYYY]  candidate gen + identity dorks"""
        toks = [t for t in arg.split() if not t.startswith("--")]
        year = None
        myear = re.search(r"--year\s+(\d{4})", arg)
        if myear:
            year = myear.group(1)
        if not toks:
            print("[!] usage: name jane doe --year 1990"); return
        first = toks[0].lower()
        last = toks[1].lower() if len(toks) > 1 else ""
        full = f"{first} {last}".strip()
        self.data["names"].append(full)
        print(f"\n=== NAME '{full}' (year hint: {year or '-'}) ===")

        print("-- dorks")
        qs = [f'"{full}"']
        if last:
            qs += [
                f'site:linkedin.com/in "{full}"',
                f'site:facebook.com "{full}"',
                f'("{full}") (instagram OR tiktok OR telegram)',
                f'site:xvideos.com OR site:xnxx.com "{full}"',
            ]
        if year:
            qs.append(f'"{full}" "{year}"')
        hits_all = self._dork_block(qs, top=5, minlen=9)

        slugs = sorted({m for h in hits_all
                        for m in re.findall(
                            r"(?:xnxx|xvideos)\.\w+/profiles?/([A-Za-z0-9_.-]+)",
                            h["url"])})
        if slugs:
            print(f"[+] adult-platform slugs surfaced: {', '.join(slugs)}")
            self.data["findings"].append({"kind": "slug", "value": slugs})

        cands = generate_candidates(first + last, year=year) if last \
            else generate_candidates(first, year=year)
        self._last_candidates = cands
        print(f"[*] handle candidates ({len(cands)}): {', '.join(cands)}")
        print("[*] next: 'username <handle>' or 'sweep quick'")
        self.data.setdefault("name_dorks", {})[full] = hits_all

    def do_username(self, arg):
        """username <handle> [quick|all] [-v]  GET-probe one handle across platforms"""
        p = [t for t in arg.split() if t != "-v"]
        verbose = "-v" in arg.split()
        if not p:
            print("[!] usage: username janedoe all"); return
        handle = p[0].lstrip("@").lower()
        sites = QUICK_SITES if (len(p) > 1 and p[1].startswith("q")) else list(PLATFORMS)
        self.data["usernames"].append(handle)
        print(f"\n=== HANDLE '{handle}' across {len(sites)} sites ===")
        results = []
        for site in sites:
            hit, title = probe(self.fetch, site, PLATFORMS[site], handle)
            results.append(hit)
            mark = VERDICT_MARK.get(hit["verdict"], "[!]")
            if hit["verdict"] in ("confirmed", "probable") or verbose:
                print(f'  {mark} {site:<10} {str(hit.get("status", "-")):<4} '
                      f'{hit["verdict"]:<9} {title}')
        confirmed = [r for r in results if r["verdict"] == "confirmed"]
        probable = [r for r in results if r["verdict"] == "probable"]
        print(f"\n[*] confirmed: {[r['site'] for r in confirmed] or 'none'}  "
              f"probable: {[r['site'] for r in probable] or 'none'}")
        self.data.setdefault("handles", {}).setdefault(handle, {})["probes"] = results

    def do_sweep(self, arg):
        """sweep [quick|all]  run last generated candidates across sites"""
        mode = arg.strip() or "quick"
        if not self._last_candidates:
            print("[!] generate candidates first: email/name/local-part"); return
        sites = QUICK_SITES if mode.startswith("q") else list(PLATFORMS)
        print(f"\n=== SWEEP {mode}: {len(self._last_candidates)} candidates x {len(sites)} sites ===")
        found = []
        for c in self._last_candidates:
            self.data["usernames"].append(c)
            for site in sites:
                hit, title = probe(self.fetch, site, PLATFORMS[site], c)
                if hit["verdict"] in ("confirmed", "probable"):
                    mark = VERDICT_MARK[hit["verdict"]]
                    print(f'  {mark} {site:<10} {c:<20} {title}')
                    found.append(hit)
        print(f"\n[*] hits: {[(f['site'], f['candidate']) for f in found] or 'none'}")
        self.data.setdefault("sweeps", []).extend(found)

    def do_autopsy(self, arg):
        """autopsy <profile-url>  extract cross-links, emails, @handles from page"""
        url = arg.strip()
        if not url.startswith("http"):
            print("[!] need full URL"); return
        r = self.fetch.get(url)
        if r is None or r.status_code != 200:
            print("  unreachable"); return
        html = r.text
        print(f"  title: {page_title(html)[:90] or '-'}")
        interesting = cross_links(html)
        print("  cross-links:" if interesting else "  no cross-platform links")
        for h in interesting[:20]:
            print(f"    -> {h}")
        mails = page_emails(html)
        handles = at_handles(html)
        if mails:
            print(f"  emails on page: {mails}")
        if handles:
            print(f"  @handles on page: {handles}")
        self.data.setdefault("autopsies", {})[url] = {
            "cross_links": interesting, "emails": mails, "at_handles": handles}

    def do_dork(self, arg):
        """dork <free-form query>"""
        q = arg.strip()
        if not q:
            print("[!] empty query"); return
        hits, states, flag = dork(self.fetch, q)
        print(f'[{len(hits)} results] {q}  ({states.get("ddg")}/{states.get("bing")}){flag}')
        for h in hits[:15]:
            print(f"  {h['title'][:70]}  {h['url']}")
        self.data.setdefault("custom_dorks", []).append({"q": q, "hits": hits})

    def do_newnym(self, arg):
        """signal tor control port for a fresh circuit (new exit IP)"""
        cookie_paths = ["/var/run/tor/control.authcookie",
                        "/run/tor/control.authcookie",
                        "/var/lib/tor/control_auth_cookie"]
        token = None
        for p in cookie_paths:
            try:
                with open(p, "rb") as f:
                    token = f.read().strip().hex()
                break
            except OSError:
                continue
        host, port = "127.0.0.1", 9051
        try:
            with socket.create_connection((host, port), timeout=10) as sk:
                f = sk.makefile("rw", encoding="utf-8", newline="\r\n")
                auth = f"AUTHENTICATE {token}\r\n" if token else 'AUTHENTICATE ""\r\n'
                f.write(auth); f.flush()
                resp = f.readline().strip()
                if "250" not in resp:
                    print(f"[!] auth failed: {resp} "
                          f"(enable CookieAuthentication + ControlPort 9051 in torrc)"); return
                f.write("SIGNAL NEWNYM\r\n"); f.flush()
                print("[*]", f.readline().strip())
                f.write("QUIT\r\n"); f.flush()
            print("[*] new circuit requested - wait ~5-10s then run 'torcheck'")
        except OSError as e:
            print(f"[!] cannot reach control port {host}:{port}: {str(e)[:80]}")
            print("    add to /etc/tor/torrc:  ControlPort 9051  CookieAuthentication 1")

    def do_pivot(self, arg):
        """suggest next silent moves based on collected data"""
        print("\n=== PIVOT SUGGESTIONS ===")
        if self.data["emails"]:
            for e, d in self.data["emails"].items():
                srcs = (d.get("breaches") or {}).get("sources") or []
                adult = [s for s in srcs if isinstance(s, str)
                         and re.search(r"x(nxx|videos)|porn|adult", s, re.I)]
                if adult:
                    print(f"  [!] {e}: leaked from {adult} - combo lists likely hold the handle; sweep harder")
                if d.get("gravatar", {}).get("profile"):
                    print(f"  [+] {e}: gravatar profile exists -> cross-link accounts listed there")
                local = (d.get("identifiers") or {}).get("local")
                if local:
                    print(f"  -> email {e}: 'email {local}@x' done; try 'sweep all' with more candidates")
        if self.data["phones"]:
            print("  -> phone: compare carrier/country vs platform account regions; "
                  "dork each format variant; truecaller name-preview manually (no login)")
        if self.data["names"]:
            print("  -> names: add '--year' hints (birth year boosts handle permutations)")
        if self.data["usernames"]:
            print("  -> usernames: 'autopsy' any confirmed profile URL to harvest "
                  "cross-links, then loop new handles back into 'username'")
        print("  general: correlate timestamps/bios/avatars across confirmed profiles "
              "to cluster identities before concluding")

    def do_save(self, arg):
        """save [path.json]  dump full session findings"""
        path = arg.strip() or f"silent_recon_report_{datetime.now():%Y%m%d_%H%M%S}.json"
        self.data["meta"]["ended"] = self._now()
        self.data["meta"]["requests_sent"] = self.fetch.n_req
        save_report(path, self.data)
        print(f"[i] report saved: {path}")

    def do_quit(self, arg):
        """exit"""
        print("[*] bye")
        return True

    do_exit = do_EOF = do_q = do_quit


def main():
    ap = argparse.ArgumentParser(description="silent-recon passive OSINT shell")
    add_common_args(ap)
    ap.add_argument("-c", "--command", action="append", default=[],
                    help="run shell command(s) non-interactively (repeatable)")
    args = ap.parse_args()

    sh = ReconShell(proxy=args.proxy, delay=(args.delay_min, args.delay_max))
    if args.command:
        for c in args.command:
            sh.onecmd(c)
            if c.strip() in ("quit", "exit", "q"):
                return
        return
    try:
        sh.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] interrupted - use 'save' first next time")


if __name__ == "__main__":
    main()
