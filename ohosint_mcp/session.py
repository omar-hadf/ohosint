"""Shared runtime session for the MCP server.

Holds mutable OPSEC configuration (proxy, delays, TLS, concurrency) and the
accumulated investigation state (identifiers, candidates, results) so an LLM
client can run a multi-step investigation across several tool calls. The MCP
stdio transport is one process per session, so a single module-level session
is the natural fit.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import osint_core as oc


class Session:
    """Mutable configuration + accumulated investigation state."""

    def __init__(self) -> None:
        self.proxy: Optional[str] = None
        self.timeout: float = 10.0
        self.delay: Tuple[float, float] = (1.5, 3.5)
        self.nsfw: bool = False
        self.in_parallel: int = 20
        self.sites_db: str = "all"
        self.insecure_tls: bool = False
        self._fetcher: Optional[oc.Fetcher] = None

        self.identifiers: Dict[str, str] = {}
        self.candidate_handles: List[str] = []
        self.results: List[oc.ScanResult] = []

    def fetcher(self) -> oc.Fetcher:
        if self._fetcher is None:
            self._fetcher = oc.Fetcher(proxy=self.proxy, delay=self.delay)
        return self._fetcher

    def reset_fetcher(self) -> None:
        self._fetcher = None

    def set_proxy(self, value: Optional[str]) -> None:
        if value is None or value.lower() in ("off", "none", ""):
            self.proxy = None
        else:
            self.proxy = value
        self.reset_fetcher()

    def set_delay(self, delay_min: float, delay_max: float) -> None:
        self.delay = (delay_min, delay_max)
        self.reset_fetcher()

    def add_identifier(self, kind: str, value: str) -> None:
        if value:
            self.identifiers[kind] = value

    def add_candidates(self, candidates) -> None:
        for c in candidates:
            if c and c not in self.candidate_handles:
                self.candidate_handles.append(c)

    def add_results(self, results) -> None:
        self.results.extend(results)

    def found_results(self) -> List[oc.ScanResult]:
        return [r for r in self.results if r.is_found()]

    def clear(self) -> None:
        self.identifiers.clear()
        self.candidate_handles.clear()
        self.results.clear()


SESSION = Session()
