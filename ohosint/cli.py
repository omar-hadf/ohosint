"""OHOsint command-line interface.

Entry point for one-shot subcommands and the interactive shell.
"""

import argparse
import logging
import sys
from typing import Optional

import osint_core as oc

from . import __version__, __longname__
from .config import Config
from .output import OutputFormatter
from .pipelines import (
    load_site_databases,
    run_breach_pipeline,
    run_email_pipeline,
    run_name_pipeline,
    run_phone_pipeline,
    run_username_pipeline,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse CLI."""
    parser = argparse.ArgumentParser(
        prog="ohosint",
        description=f"{__longname__} v{__version__}",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--proxy", help="HTTP/SOCKS5 proxy URL (e.g. socks5h://127.0.0.1:9050)"
    )
    parser.add_argument(
        "--tor", action="store_true", help="Use Tor proxy at socks5h://127.0.0.1:9050"
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--delay-min", type=float, default=1.5, help="Minimum inter-request delay"
    )
    parser.add_argument(
        "--delay-max", type=float, default=3.5, help="Maximum inter-request delay"
    )
    parser.add_argument(
        "--format", choices=["table", "json"], default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "--out", help="Save JSON report to path"
    )
    parser.add_argument(
        "--nsfw", action="store_true", help="Include NSFW sites"
    )
    parser.add_argument(
        "--no-exclusions", action="store_true",
        help="Skip remote false-positive exclusion list"
    )
    parser.add_argument(
        "--sites", choices=["maigret", "sherlock", "all"], default="all",
        help="Site database to use (default: all)"
    )
    parser.add_argument(
        "--in-parallel", type=int, default=20, help="Max concurrent requests (default: 20)"
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="Skip TLS certificate verification (not recommended over Tor)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # email
    email_parser = subparsers.add_parser("email", help="Investigate an email address")
    email_parser.add_argument("address", help="Email address to investigate")

    # phone
    phone_parser = subparsers.add_parser("phone", help="Investigate a phone number")
    phone_parser.add_argument("number", help="Phone number (E.164 recommended)")

    # username
    username_parser = subparsers.add_parser("username", help="Sweep a username across sites")
    username_parser.add_argument("handle", help="Username to check")

    # name
    name_parser = subparsers.add_parser("name", help="Investigate a person's name")
    name_parser.add_argument("first", help="First name")
    name_parser.add_argument("last", nargs="?", help="Last name (optional)")
    name_parser.add_argument("--year", type=int, help="Birth/registration year")

    # shell
    subparsers.add_parser("shell", help="Launch interactive shell")

    # breach
    breach_parser = subparsers.add_parser("breach", help="Multi-source breach/leak search")
    breach_parser.add_argument("query", help="Email, username, domain, or password")
    breach_parser.add_argument(
        "--type", choices=["email", "username", "domain", "password"],
        help="Query type (auto-detected if omitted; passwords must be declared)"
    )
    breach_parser.add_argument(
        "--sources", help="Comma-separated provider whitelist"
    )

    # sites
    sites_parser = subparsers.add_parser("sites", help="List loaded site databases")
    sites_parser.add_argument(
        "--db", choices=["maigret", "sherlock", "all"], default="all",
        help="Which database to inspect"
    )

    return parser


def config_from_args(args) -> Config:
    """Build a Config from parsed argparse args."""
    proxy = "socks5h://127.0.0.1:9050" if args.tor else args.proxy
    if proxy:
        # Fail fast on a malformed proxy rather than surfacing it later as an
        # opaque connection error, and warn about DNS-leaking socks5://.
        if not oc.valid_proxy(proxy):
            raise SystemExit(
                f"ohosint: invalid proxy URL {proxy!r} — expected e.g. "
                "socks5h://127.0.0.1:9050 or http://host:port"
            )
        oc.warn_if_dns_leaking(proxy)
    return Config(
        proxy=proxy,
        timeout=args.timeout,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        format=args.format,
        out=args.out,
        nsfw=args.nsfw,
        exclusions=not args.no_exclusions,
        in_parallel=args.in_parallel,
        sites_db=args.sites,
        insecure_tls=args.insecure,
    )


def handle_email(args, config: Config):
    sites = load_site_databases(config.sites_db)
    report = run_email_pipeline(
        args.address,
        sites=sites,
        proxy=config.proxy,
        timeout=config.timeout,
        in_parallel=config.in_parallel,
        skip_nsfw=not config.nsfw,
        verify_ssl=not config.insecure_tls,
        apply_exclusions=config.exclusions,
        delay=(config.delay_min, config.delay_max),
    )

    results = report.get("results", [])
    formatter = OutputFormatter(use_rich=(config.format == "table"))

    if config.format == "table":
        print(f"\nEmail: {report['email']}")
        print(f"Candidates: {', '.join(report['candidates'])}")
        src = report.get("sources") or {}
        if src.get("leakcheck"):
            lc = src["leakcheck"]
            if lc.get("found") is not None:
                print(f"LeakCheck:  {'found' if lc['found'] else 'not found'} "
                      f"({', '.join(b.get('name', '?') for b in lc.get('breaches', []))})")
        if src.get("hudson_rock"):
            hr = src["hudson_rock"]
            print(f"Hudson Rock: {hr.get('stealer_count', 0)} infostealer hit(s)")
        if results:
            formatter.print_table(results, title=f"Username Sweep Results for {args.address}")
        else:
            print("No username sweep performed.")
    else:
        print(formatter.to_json(results, metadata={"email": args.address, "sources": report.get("sources")}))

    if config.out:
        formatter.save_json(results, config.out, metadata={"email": args.address, "sources": report.get("sources")})
        print(f"Report saved to {config.out}")


def handle_phone(args, config: Config):
    report = run_phone_pipeline(args.number)
    formatter = OutputFormatter(use_rich=False)

    if config.format == "table":
        print(f"\nPhone: {report.get('input')}")
        print(f"Valid: {report.get('valid')}")
        if report.get("error"):
            # The pipeline captures a specific parse failure here; without this
            # the user just sees "Valid: False" and no reason why.
            print(f"Reason: {report['error']}")
        if report.get("e164"):
            print(f"E.164: {report['e164']}")
            print(f"National: {report['national']}")
            print(f"Type: {report.get('type')}")
        if report.get("carrier"):
            print(f"Carrier: {report['carrier']}")
        print("\nSuggested dorks:")
        for dork in report.get("dorks", []):
            print(f"  {dork}")
    else:
        print(formatter.to_json([], metadata=report))


def handle_username(args, config: Config):
    sites = load_site_databases(config.sites_db)

    def _progress(done, total, result):
        pct = int(done / total * 100)
        print(f"\r  [{done}/{total}] {pct}% checked", end="", flush=True)

    print(f"  Sweeping {len(sites)} sites for {args.handle}...")
    results = run_username_pipeline(
        args.handle,
        sites,
        proxy=config.proxy,
        timeout=config.timeout,
        in_parallel=config.in_parallel,
        skip_nsfw=not config.nsfw,
        apply_exclusions=config.exclusions,
        verify_ssl=not config.insecure_tls,
        on_done=_progress,
    )
    print()  # newline after progress

    formatter = OutputFormatter(use_rich=(config.format == "table"))

    if config.format == "table":
        formatter.print_table(results, title=f"Username Sweep: {args.handle}")
    else:
        print(formatter.to_json(results, metadata={"username": args.handle}))

    if config.out:
        formatter.save_json(results, config.out, metadata={"username": args.handle})
        print(f"Report saved to {config.out}")


def handle_name(args, config: Config):
    report = run_name_pipeline(args.first, args.last, args.year)
    formatter = OutputFormatter(use_rich=False)

    if config.format == "table":
        print(f"\nName: {report['name']}")
        print(f"Slug: {report['slug']}")
        print(f"\nCandidates: {', '.join(report['candidates'])}")
        print("\nSuggested dorks:")
        for label, dork in report["dorks"].items():
            print(f"  [{label}] {dork}")
    else:
        print(formatter.to_json([], metadata=report))


def handle_sites(args, config: Config):
    sites = load_site_databases(args.db)
    print(f"\nLoaded {len(sites)} sites from {args.db} database")
    nsfw = sum(1 for s in sites.values() if getattr(s, "is_nsfw", False))
    print(f"NSFW sites: {nsfw}")
    print("\nTop 20 sites:")
    for name in list(sites.keys())[:20]:
        print(f"  {name}")


def handle_breach(args, config: Config):
    sources = [s.strip() for s in args.sources.split(",") if s.strip()] if args.sources else None
    report = run_breach_pipeline(
        args.query,
        qtype=args.type,
        proxy=config.proxy,
        delay=(config.delay_min, config.delay_max),
        sources=sources,
    )

    formatter = OutputFormatter(use_rich=(config.format == "table"))
    if config.format == "table":
        formatter.print_breach_report(report)
    else:
        print(formatter.breach_to_json(report))

    if config.out:
        formatter.save_breach_json(report, config.out)
        print(f"Report saved to {config.out}")


def handle_shell(args, config: Config):
    from .shell import OHOsintShell
    shell = OHOsintShell(config)
    shell.cmdloop()


def main(argv: Optional[list] = None) -> int:
    """Main entry point for the ohosint CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    if not args.command:
        parser.print_help()
        return 1

    config = config_from_args(args)

    handlers = {
        "email": handle_email,
        "phone": handle_phone,
        "username": handle_username,
        "name": handle_name,
        "breach": handle_breach,
        "sites": handle_sites,
        "shell": handle_shell,
    }

    try:
        handler = handlers[args.command]
        handler(args, config)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        logging.error("Command failed: %s", e)
        if args.verbose:
            logging.exception("Full traceback:")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
