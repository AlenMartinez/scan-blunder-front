"""Scan-wide configuration and shared state."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from scanner.core.models import ScanResults


@dataclass
class ScanContext:
    """Everything a detector may need to know about the scan it belongs to."""

    base_url: str
    domain: str
    results: ScanResults

    # behaviour switches, wired to the CLI flags
    max_threads: int = 10
    timeout: int = 15
    max_asset_bytes: int = 5 * 1024 * 1024
    crawl_depth: int = 0
    max_assets: int = 300
    follow_sourcemaps: bool = True
    probe_paths: bool = True
    delay: float = 0.0
    verify_tls: bool = True
    proxy: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    include_subdomains: bool = False
    #: True when the user gave a bare host and we defaulted to https://
    scheme_inferred: bool = False

    def switch_to_http(self) -> None:
        """Fall back to http:// after an https:// attempt failed to connect."""
        self.base_url = "http://" + self.base_url.split("://", 1)[1]
        self.scheme_inferred = False
        self.results.target = self.base_url

    @classmethod
    def for_url(cls, url: str, **kwargs) -> "ScanContext":
        domain = urlparse(url).hostname or ""
        results = ScanResults(target=url, domain=domain)
        return cls(base_url=url, domain=domain, results=results, **kwargs)
