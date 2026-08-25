"""Runtime configuration for OHOsint."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from osint_core.scan_result import ScanResult


@dataclass
class Config:
    """Runtime configuration shared across one-shot and shell modes."""

    proxy: Optional[str] = None
    timeout: float = 10.0
    delay_min: float = 1.5
    delay_max: float = 3.5
    format: str = "table"
    out: Optional[str] = None
    nsfw: bool = False
    exclusions: bool = True
    in_parallel: int = 20
    sites_db: str = "all"  # "maigret", "sherlock", or "all"
    insecure_tls: bool = False

    # Mutable session state
    results: List[ScanResult] = field(default_factory=list)
    identifiers: Dict[str, Any] = field(default_factory=dict)
    candidate_handles: List[str] = field(default_factory=list)

    def reset_session(self):
        """Clear collected results and identifiers."""
        self.results.clear()
        self.identifiers.clear()
        self.candidate_handles.clear()

    def add_results(self, results: List[ScanResult]):
        """Append new results to the session."""
        self.results.extend(results)

    def get_found_results(self) -> List[ScanResult]:
        """Return only claimed/found results."""
        return [r for r in self.results if r.is_found()]

    def set_proxy(self, proxy: Optional[str]):
        """Set or clear proxy. Use 'off' or None to disable."""
        if proxy is None or proxy.lower() in ("off", "none", ""):
            self.proxy = None
        else:
            self.proxy = proxy
