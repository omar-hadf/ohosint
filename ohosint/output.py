"""Output formatting for OHOsint.

Supports terminal tables (rich) and JSON serialization.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from osint_core.scan_result import ScanResult

def _write_private(path: str, text: str) -> None:
    """Write ``text`` to ``path`` with owner-only (0600) permissions.

    Reports contain the investigation target's personal data, and breach
    reports can contain real leaked ``email:password`` pairs, so they must not
    be world-readable on a shared host (see docs/audit/security.md).
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    # os.open only applies the mode when creating; enforce it on reuse too.
    os.chmod(path, 0o600)


class OutputFormatter:
    """Format OHOsint results for terminal or JSON output."""

    STATUS_COLORS = {
        "claimed": "green",
        "available": "red",
        "unknown": "yellow",
        "illegal": "magenta",
        "waf": "bright_yellow",
    }

    def __init__(self, use_rich: bool = True):
        self.use_rich = use_rich and RICH_AVAILABLE

    def print_table(self, results: List[ScanResult], title: str = "Results"):
        """Print results as a terminal table."""
        if self.use_rich:
            self._print_rich_table(results, title)
        else:
            self._print_simple_table(results, title)

    def _print_rich_table(self, results: List[ScanResult], title: str):
        table = Table(title=title, show_lines=True)
        table.add_column("Site", style="cyan", no_wrap=True)
        table.add_column("Status", style="bold")
        table.add_column("URL")
        table.add_column("Confidence", style="dim")
        table.add_column("Error/Note", style="dim")

        for r in results:
            color = self.STATUS_COLORS.get(r.status.value, "white")
            status_text = f"[{color}]{r.status.to_label()}[/{color}]"
            url = r.url or ""
            conf = r.confidence or ""
            note = r.error_msg or ""
            table.add_row(r.site_name, status_text, url, conf, note)

        console = Console()
        console.print(table)
        console.print(f"\nTotal: {len(results)} sites checked")
        found = sum(1 for r in results if r.is_found())
        console.print(f"Found: {found}")

    def _print_simple_table(self, results: List[ScanResult], title: str):
        print(f"\n{title}")
        print("-" * 80)
        print(f"{'Site':<25} {'Status':<12} {'URL':<30} {'Confidence':<12}")
        print("-" * 80)
        for r in results:
            print(f"{r.site_name:<25} {r.status.to_label():<12} {(r.url or ''):<30} {(r.confidence or ''):<12}")
        print("-" * 80)
        found = sum(1 for r in results if r.is_found())
        print(f"Total: {len(results)} | Found: {found}")

    def to_json(self, results: List[ScanResult], metadata: Optional[Dict] = None) -> str:
        """Serialize results and optional metadata to JSON."""
        data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "metadata": metadata or {},
            "results": [r.to_dict() for r in results],
            "summary": {
                "total": len(results),
                "found": sum(1 for r in results if r.is_found()),
                "waf": sum(1 for r in results if r.status.value == "waf"),
                "illegal": sum(1 for r in results if r.status.value == "illegal"),
                "errors": sum(1 for r in results if r.status.value == "unknown"),
            },
        }
        return json.dumps(data, indent=2)

    def save_json(self, results: List[ScanResult], path: str, metadata: Optional[Dict] = None):
        """Save results as JSON to the given path (owner-readable only)."""
        _write_private(path, self.to_json(results, metadata))

    # ------------------------------------------------------------------
    # Breach reports (dict-based, not ScanResult-based)
    # ------------------------------------------------------------------

    def print_breach_report(self, report: Dict):
        """Print a breach-search report (rich table or plain text)."""
        if self.use_rich:
            self._print_breach_rich(report)
        else:
            self._print_breach_plain(report)

    def _print_breach_rich(self, report: Dict):
        from rich.console import Console
        from rich.table import Table

        query = report.get("query", "")
        qtype = report.get("type", "?")
        print(f"\nBreach search: {query} ({qtype})")

        breaches = report.get("breaches") or []
        if breaches:
            table = Table(title=f"{len(breaches)} unique breach(es)", show_lines=True)
            table.add_column("Breach", style="cyan", no_wrap=True)
            table.add_column("Date")
            table.add_column("Providers")
            table.add_column("Data classes")
            for b in breaches:
                table.add_row(
                    b.get("name") or "",
                    b.get("date") or "n/a",
                    ", ".join(b.get("providers") or []),
                    ", ".join(b.get("data_classes") or []),
                )
            Console().print(table)

        creds = report.get("credentials") or []
        if creds:
            print("\n[!] Plaintext credentials below are leaked data — handle responsibly")
            table = Table(title=f"{len(creds)} credential line(s)", show_lines=True)
            table.add_column("Source")
            table.add_column("Credential")
            for c in creds[:20]:
                table.add_row(c.get("source") or "", c.get("line") or str(c))
            Console().print(table)
            if len(creds) > 20:
                print(f"  ... and {len(creds) - 20} more")

        summary = report.get("summary") or {}
        print("\nSummary:")
        print(f"  Unique breaches:      {summary.get('unique_breaches', 0)}")
        print(f"  Credential lines:     {summary.get('credential_lines', 0)}")
        print(f"  Infostealer hits:     {summary.get('infostealer_hits', 0)}")
        print(f"  IntelX records:       {summary.get('intelx_records', 0)}")
        if summary.get("pwned_password_count") is not None:
            print(f"  Pwned password count: {summary['pwned_password_count']}")

        for f in report.get("flags") or []:
            print(f"  [flag] {f}")

    def _print_breach_plain(self, report: Dict):
        query = report.get("query", "")
        qtype = report.get("type", "?")
        print(f"\nBreach search: {query} ({qtype})")
        breaches = report.get("breaches") or []
        if breaches:
            print(f"\n{len(breaches)} unique breach(es):")
            print(f"{'Breach':<30} {'Date':<12} {'Providers':<25} {'Data classes'}")
            print("-" * 100)
            for b in breaches:
                print(f"{(b.get('name') or ''):<30} {(b.get('date') or 'n/a'):<12} "
                      f"{', '.join(b.get('providers') or []):<25} "
                      f"{', '.join(b.get('data_classes') or [])}")

        creds = report.get("credentials") or []
        if creds:
            print("\n[!] Plaintext credentials below are leaked data — handle responsibly")
            print(f"{len(creds)} credential line(s):")
            for c in creds[:20]:
                print(f"  [{c.get('source')}] {c.get('line') or c}")
            if len(creds) > 20:
                print(f"  ... and {len(creds) - 20} more")

        summary = report.get("summary") or {}
        print("\nSummary:")
        print(f"  Unique breaches:      {summary.get('unique_breaches', 0)}")
        print(f"  Credential lines:     {summary.get('credential_lines', 0)}")
        print(f"  Infostealer hits:     {summary.get('infostealer_hits', 0)}")
        print(f"  IntelX records:       {summary.get('intelx_records', 0)}")
        if summary.get("pwned_password_count") is not None:
            print(f"  Pwned password count: {summary['pwned_password_count']}")

        for f in report.get("flags") or []:
            print(f"  [flag] {f}")

    def breach_to_json(self, report: Dict) -> str:
        """Serialize a breach report dict to JSON."""
        return json.dumps(report, indent=2, ensure_ascii=False)

    def save_breach_json(self, report: Dict, path: str):
        """Save a breach report dict as JSON (owner-readable only)."""
        _write_private(path, self.breach_to_json(report))


def make_report_path(prefix: str = "ohosint_report") -> str:
    """Generate a timestamped report filename."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.json"
