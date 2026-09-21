"""Shared plumbing for detectors."""
from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from scanner.core.models import (
    Asset,
    Confidence,
    Finding,
    Location,
    Severity,
    line_column,
    make_snippet,
)


class BaseDetector:
    """A detector turns one asset into zero or more findings.

    Subclasses implement `detect`. Everything else here exists so that the
    subclasses stay short and consistent: location maths, snippet extraction and
    the `is_enabled` switch that the CLI flags flip.
    """

    name = "detector"
    #: set to False for detectors that should not run on vendor bundles
    runs_on_vendor = True

    def __init__(self, context: "ScanContext"):
        self.context = context

    # -- API ---------------------------------------------------------------- #
    def detect(self, asset: Asset) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError

    # -- helpers ------------------------------------------------------------ #
    def locate(self, asset: Asset, start: int, end: int) -> Location:
        line, column = line_column(asset.content, start)
        return Location(
            url=asset.url,
            line=line,
            column=column,
            snippet=make_snippet(asset.content, start, end),
        )

    def finding(
        self,
        asset: Asset,
        category: str,
        title: str,
        severity: str,
        confidence: str,
        start: int,
        end: int,
        value: str = "",
        detail: str = "",
        remediation: str = "",
        evidence: Optional[dict] = None,
        tags: Optional[List[str]] = None,
    ) -> Finding:
        return Finding(
            category=category,
            title=title,
            severity=severity,
            confidence=confidence,
            location=self.locate(asset, start, end),
            value=value,
            detail=detail,
            remediation=remediation,
            evidence=evidence or {},
            tags=list(tags or []),
        )


def redact(value: str, keep: int = 6) -> str:
    """Shorten a credential for display without losing its identity."""
    if not value:
        return ""
    value = value.strip()
    if len(value) <= keep * 2 + 3:
        return value
    return "{}…{}".format(value[:keep], value[-4:])
