"""Detector orchestration.

`Detector` owns the registry of individual detectors and runs them against a
single asset. It is intentionally thin: all of the knowledge lives in the
detector classes, so adding a check means adding a class, not editing a
thousand-line function.
"""
from __future__ import annotations

import threading
from typing import Iterable, List, Optional

from scanner.core.detector.access import AccessControlDetector
from scanner.core.detector.base import BaseDetector
from scanner.core.detector.endpoints import EndpointDetector, summarize_backends
from scanner.core.detector.headers import HeaderDetector
from scanner.core.detector.secrets import SecretDetector
from scanner.core.detector.technologies import TechnologyDetector
from scanner.core.detector.vulnerabilities import (
    MiscVulnDetector,
    SQLDetector,
    XSSDetector,
)
from scanner.core.models import Asset, Finding, ScanResults

#: Every detector, in the order their findings read best.
DETECTOR_CLASSES = [
    TechnologyDetector,
    SecretDetector,
    SQLDetector,
    XSSDetector,
    MiscVulnDetector,
    AccessControlDetector,
    EndpointDetector,
    HeaderDetector,
]

#: Names accepted by `--only` / `--skip`.
DETECTOR_NAMES = [cls.name for cls in DETECTOR_CLASSES]


class Detector:
    """Runs the enabled detectors over assets and collects their findings.

    Instances are shared across worker threads, so every mutation of the shared
    `ScanResults` goes through a lock. The detectors themselves are stateless
    with respect to the asset they are given.
    """

    def __init__(self, context: "ScanContext", enabled: Optional[Iterable[str]] = None):
        self.context = context
        self.results: ScanResults = context.results
        self._lock = threading.Lock()

        allowed = set(enabled) if enabled is not None else None
        self.detectors: List[BaseDetector] = [
            cls(context)
            for cls in DETECTOR_CLASSES
            if allowed is None or cls.name in allowed
        ]
        self._tech_detector: Optional[TechnologyDetector] = next(
            (d for d in self.detectors if isinstance(d, TechnologyDetector)), None
        )

    # -- scanning ------------------------------------------------------------- #
    def scan(self, asset: Asset) -> None:
        """Run every detector against one asset and merge the results."""
        collected: List[Finding] = []
        for detector in self.detectors:
            try:
                collected.extend(detector.detect(asset) or [])
            except Exception as exc:  # a bad regex must not kill the scan
                with self._lock:
                    self.results.errors.append(
                        "{} failed on {}: {}".format(detector.name, asset.url, exc)
                    )

        with self._lock:
            self.results.add_findings(collected)
            self.results.stats["assets_scanned"] = (
                self.results.stats.get("assets_scanned", 0) + 1
            )
            self.results.stats["bytes_scanned"] = (
                self.results.stats.get("bytes_scanned", 0) + asset.size
            )

    def finalize(self, main_asset: Optional[Asset]) -> ScanResults:
        """Cross-asset checks that only make sense once everything is collected."""
        with self._lock:
            if self._tech_detector is not None and main_asset is not None:
                self.results.add_findings(self._tech_detector.check_outdated(main_asset))

            self.results.collapse_inferred_endpoints()

            backend_summary = summarize_backends(self.results, self.context.base_url)
            if backend_summary is not None:
                self.results.add_finding(backend_summary)

            self.results.stats["findings"] = len(self.results.findings)
            self.results.stats["endpoints"] = len(self.results.endpoints)
            self.results.stats["urls"] = len(self.results.urls)
            self.results.stats["technologies"] = len(self.results.technologies)
            self.results.stats["services"] = len(self.results.services)
        return self.results
