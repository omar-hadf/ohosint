"""Interactive shell for OHOsint."""

import cmd
import logging
import shlex
from typing import List

import osint_core as oc
from . import __version__
from .config import Config
from .output import OutputFormatter, make_report_path
from .pipelines import (
    load_site_databases,
    run_breach_pipeline,
    run_email_pipeline,
    run_name_pipeline,
    run_phone_pipeline,
    run_username_pipeline,
)

logger = logging.getLogger(__name__)


class OHOsintShell(cmd.Cmd):
    """Interactive OHOsint shell."""

    intro = f"""
    ____  __  ____ _____  ____
   / __ \\/ / / /  _/ |  /  _/
  / /_/ / /_/ // / | | / // /
 / ____/ __  // /  | |/ // /
/_/   /_/ /_/___/  |___/___/

OHOsint v{__version__} — type help or ? to list commands.
"""
    prompt = "ohosint> "

    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.formatter = OutputFormatter(use_rich=True)
        self._fetcher_obj = None
        self._last_breach_report = None

    def _fetcher(self):
        """Return a cached sync Fetcher that honours the current proxy/delay config."""
        if self._fetcher_obj is None:
            self._fetcher_obj = oc.Fetcher(
                proxy=self.config.proxy,
                delay=(self.config.delay_min, self.config.delay_max),
            )
        return self._fetcher_obj

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_args(self, line: str, expected: int = 1) -> List[str]:
        parts = shlex.split(line.strip())
        if len(parts) < expected:
            print(f"Error: expected at least {expected} argument(s)")
            return []
        return parts

    def _load_sites(self) -> dict:
        try:
            sites = load_site_databases(self.config.sites_db)
        except ValueError as e:
            print(f"Error: {e}")
            return {}
        print(f"Loaded {len(sites)} sites")
        return sites

    def _add_results(self, results):
        self.config.add_results(results)

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def do_email(self, line):
        """email <address> — investigate an email address."""
        args = self._parse_args(line, 1)
        if not args:
            return
        sites = self._load_sites()
        if not sites:
            return
        report = run_email_pipeline(
            args[0],
            sites=sites,
            proxy=self.config.proxy,
            timeout=self.config.timeout,
            in_parallel=self.config.in_parallel,
            skip_nsfw=not self.config.nsfw,
            verify_ssl=not self.config.insecure_tls,
            apply_exclusions=self.config.exclusions,
            delay=(self.config.delay_min, self.config.delay_max),
        )
        results = report.get("results", [])
        self._add_results(results)
        print(f"\nEmail: {report['email']}")
        print(f"Candidates: {', '.join(report['candidates'])}")
        if results:
            self.formatter.print_table(results, title=f"Results for {args[0]}")

    def do_phone(self, line):
        """phone <number> — investigate a phone number."""
        args = self._parse_args(line, 1)
        if not args:
            return
        report = run_phone_pipeline(args[0])
        print(f"\nPhone: {report.get('input')}")
        print(f"Valid: {report.get('valid')}")
        if report.get("error"):
            print(f"Reason: {report['error']}")
        if report.get("e164"):
            print(f"E.164: {report['e164']}")
            print(f"National: {report['national']}")
            print(f"Type: {report.get('type')}")
        print("Dorks:")
        for dork in report.get("dorks", []):
            print(f"  {dork}")

    def do_username(self, line):
        """username <handle> — sweep a username across sites."""
        args = self._parse_args(line, 1)
        if not args:
            return
        sites = self._load_sites()
        if not sites:
            return

        def _progress(done, total, result):
            pct = int(done / total * 100)
            print(f"\r  [{done}/{total}] {pct}% checked", end="", flush=True)

        print(f"  Sweeping {len(sites)} sites for {args[0]}...")
        results = run_username_pipeline(
            args[0],
            sites,
            proxy=self.config.proxy,
            timeout=self.config.timeout,
            in_parallel=self.config.in_parallel,
            skip_nsfw=not self.config.nsfw,
            apply_exclusions=self.config.exclusions,
            verify_ssl=not self.config.insecure_tls,
            on_done=_progress,
        )
        print()  # newline after progress
        self._add_results(results)
        self.formatter.print_table(results, title=f"Username Sweep: {args[0]}")

    def do_breach(self, line):
        """breach <query> [email|username|domain|password] — multi-source breach lookup."""
        args = self._parse_args(line, 1)
        if not args:
            return
        query = args[0]
        qtype = args[1] if len(args) > 1 else None
        report = run_breach_pipeline(
            query,
            qtype=qtype,
            proxy=self.config.proxy,
            delay=(self.config.delay_min, self.config.delay_max),
        )
        self._last_breach_report = report
        self.formatter.print_breach_report(report)

    def do_name(self, line):
        """name <first> [last] [--year YYYY] — investigate a name."""
        args = self._parse_args(line, 1)
        if not args:
            return
        first = args[0]
        last = args[1] if len(args) > 1 else None
        year = None
        if "--year" in args:
            idx = args.index("--year")
            if idx + 1 < len(args):
                year = int(args[idx + 1])
        report = run_name_pipeline(first, last, year)
        print(f"\nName: {report['name']}")
        print(f"Slug: {report['slug']}")
        print(f"Candidates: {', '.join(report['candidates'])}")
        self.config.candidate_handles.extend(report["candidates"])

    def do_sweep(self, line):
        """sweep — probe all generated candidates across sites."""
        if not self.config.candidate_handles:
            print("No candidates. Run 'email' or 'name' first.")
            return
        sites = self._load_sites()
        if not sites:
            return
        handles = self.config.candidate_handles[:10]
        total_handles = len(handles)
        for i, handle in enumerate(handles, 1):
            print(f"\n  [{i}/{total_handles}] Sweeping: {handle}")

            def _progress(done, total, result):
                pct = int(done / total * 100)
                print(f"\r    [{done}/{total}] {pct}% checked", end="", flush=True)

            results = run_username_pipeline(
                handle,
                sites,
                proxy=self.config.proxy,
                timeout=self.config.timeout,
                in_parallel=self.config.in_parallel,
                skip_nsfw=not self.config.nsfw,
                apply_exclusions=self.config.exclusions,
                verify_ssl=not self.config.insecure_tls,
                on_done=_progress,
            )
            print()  # newline after progress
            self._add_results(results)
            self.formatter.print_table(results, title=f"Sweep: {handle}")

    def do_dork(self, line):
        """dork <query> — run a search-engine dork."""
        if not line.strip():
            print("Usage: dork <query>")
            return
        hits, states, flag = oc.dork(self._fetcher(), line.strip())
        print(f"\nDork states: {states}")
        for h in hits[:10]:
            print(f"  {h}")
        if flag:
            print(flag)

    def do_autopsy(self, line):
        """autopsy <url> — harvest links, emails, and handles from a profile page."""
        args = self._parse_args(line, 1)
        if not args:
            return
        url = args[0]
        if not url.startswith("http"):
            print("Error: need a full URL starting with http(s)://")
            return
        r = self._fetcher().get(url)
        if r is None or r.status_code != 200:
            print("  unreachable")
            return
        try:
            text = r.text
            links = oc.cross_links(text)
            emails = oc.page_emails(text)
            handles = oc.at_handles(text)
            print(f"\nLinks: {len(links)}")
            for link in links[:10]:
                print(f"  {link}")
            print(f"\nEmails: {len(emails)}")
            for email in emails[:10]:
                print(f"  {email}")
            print(f"\n@handles: {len(handles)}")
            for handle in handles[:10]:
                print(f"  {handle}")
        except Exception as e:
            print(f"Autopsy failed: {e}")

    def do_pivot(self, line):
        """pivot — extract usernames and emails from collected results."""
        if not self.config.results:
            print("No results yet. Run 'username' or 'sweep' first.")
            return
        pivots = oc.extract_pivots(self.config.results)
        emails = oc.extract_email_pivots(self.config.results)
        print(f"\nUsername pivots: {len(pivots)}")
        for p in pivots[:20]:
            print(f"  [{p.kind.value}] {p.username} -> {p.site or '(any)'}")
        print(f"\nEmail pivots: {len(emails)}")
        for e in emails[:20]:
            print(f"  {e.email} ({e.kind.value})")

    def do_proxy(self, line):
        """proxy <url|off> — set or clear proxy."""
        value = line.strip()
        self.config.set_proxy(value)
        self._fetcher_obj = None  # invalidate cached Fetcher
        if self.config.proxy:
            print(f"Proxy set to {self.config.proxy}")
        else:
            print("Proxy cleared")

    def do_insecure(self, line):
        """insecure [on|off] — toggle TLS certificate verification."""
        value = line.strip().lower()
        if value in ("on", "true", "1"):
            self.config.insecure_tls = True
        elif value in ("off", "false", "0"):
            self.config.insecure_tls = False
        else:
            self.config.insecure_tls = not self.config.insecure_tls
        state = "DISABLED" if self.config.insecure_tls else "enabled"
        print(f"TLS verification: {state}")

    def do_newnym(self, line):
        """newnym — rotate Tor circuit via control port 9051."""
        try:
            from stem.control import Controller
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal("NEWNYM")
            print("Tor circuit rotated")
        except Exception as e:
            print(f"Failed to rotate Tor circuit: {e}")

    def do_delay(self, line):
        """delay <min> <max> — set inter-request delay range."""
        args = self._parse_args(line, 2)
        if not args:
            return
        try:
            self.config.delay_min = float(args[0])
            self.config.delay_max = float(args[1])
            self._fetcher_obj = None  # invalidate cached Fetcher
            print(f"Delay set to {self.config.delay_min}s - {self.config.delay_max}s")
        except ValueError:
            print("Error: min and max must be numbers")

    def do_status(self, line):
        """status — show current session state."""
        print("\nSession status:")
        print(f"  Proxy: {self.config.proxy or '(none)'}")
        print(f"  Timeout: {self.config.timeout}s")
        print(f"  Delay: {self.config.delay_min}s - {self.config.delay_max}s")
        print(f"  Sites DB: {self.config.sites_db}")
        print(f"  NSFW: {self.config.nsfw}")
        print(f"  Exclusions: {self.config.exclusions}")
        print(f"  Results collected: {len(self.config.results)}")
        print(f"  Found: {len(self.config.get_found_results())}")
        print(f"  Candidates: {len(self.config.candidate_handles)}")

    def do_save(self, line):
        """save [path] — save session results to JSON."""
        path = line.strip() or make_report_path()
        metadata = {"identifiers": self.config.identifiers}
        if self._last_breach_report:
            metadata["breach"] = self._last_breach_report
        self.formatter.save_json(
            self.config.results,
            path,
            metadata=metadata,
        )
        print(f"Saved {len(self.config.results)} results to {path}")

    def do_clear(self, line):
        """clear — reset the session."""
        self.config.reset_session()
        print("Session cleared")

    def do_exit(self, line):
        """exit or quit — leave the shell."""
        print("Goodbye.")
        return True

    def do_quit(self, line):
        """quit — leave the shell."""
        return self.do_exit(line)

    def do_EOF(self, line):
        """Handle Ctrl-D."""
        print()
        return self.do_exit(line)

    def do_help(self, line):
        """Show available commands."""
        print("\nAvailable commands:")
        print("  email <address>              investigate an email")
        print("  phone <number>               investigate a phone number")
        print("  username <handle>            sweep a username")
        print("  breach <query> [type]        multi-source breach/leak search")
        print("  name <first> [last]          generate candidates from a name")
        print("  sweep                        probe all generated candidates")
        print("  dork <query>                 search-engine dork")
        print("  autopsy <url>                harvest profile page")
        print("  pivot                        extract pivots from results")
        print("  proxy <url|off>              set/clear proxy")
        print("  insecure [on|off]            toggle TLS verification")
        print("  newnym                       rotate Tor circuit")
        print("  delay <min> <max>            set request delays")
        print("  status                       show session state")
        print("  save [path]                  save results to JSON")
        print("  clear                        reset session")
        print("  exit / quit                  leave shell")
        print()

    def emptyline(self):
        pass
