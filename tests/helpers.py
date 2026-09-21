"""Shared test scaffolding."""
from __future__ import annotations

from typing import List, Optional

from scanner.core.context import ScanContext
from scanner.core.detector.detector_services import Detector
from scanner.core.models import Asset, Finding


def scan_text(
    content: str,
    url: str = "https://example.com/app.js",
    kind: str = "js",
    headers: Optional[dict] = None,
    detectors: Optional[List[str]] = None,
) -> List[Finding]:
    """Run the detectors over a snippet and return the findings."""
    context = ScanContext.for_url("https://example.com/")
    detector = Detector(context, enabled=detectors)
    asset = Asset(
        url=url,
        content=content,
        content_type="application/javascript" if kind == "js" else "text/html",
        status=200,
        headers=headers or {},
        kind=kind,
    )
    detector.scan(asset)
    detector.finalize(asset)
    return context.results.findings


def scan_html(content: str, **kwargs) -> List[Finding]:
    kwargs.setdefault("url", "https://example.com/")
    return scan_text(content, kind="html", **kwargs)


def titles(findings: List[Finding]) -> List[str]:
    return [f.title for f in findings]


def has_title(findings: List[Finding], fragment: str) -> bool:
    return any(fragment.lower() in f.title.lower() for f in findings)
