"""Persisting results to disk in the formats a report actually gets read in."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List

from scanner.core.models import (
    Confidence,
    Finding,
    ScanResults,
    Severity,
)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def finding_basename(domain: str, timestamp: str = "") -> str:
    safe = _SAFE_NAME.sub("_", domain or "target").strip("_") or "target"
    stamp = timestamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    return "{}_{}".format(safe, stamp)


def create_finding_file(domain: str, directory: str = "findings", suffix: str = ".json") -> Path:
    """Backwards-compatible helper: build the path for a new report file."""
    findings_dir = Path(directory)
    findings_dir.mkdir(parents=True, exist_ok=True)
    return findings_dir / (finding_basename(domain) + suffix)


def write_reports(
    results: ScanResults,
    directory: str = "findings",
    formats: Iterable[str] = ("json", "md"),
    min_confidence: str = Confidence.TENTATIVE,
) -> List[str]:
    """Write every requested format and return the paths that were created."""
    findings_dir = Path(directory)
    findings_dir.mkdir(parents=True, exist_ok=True)
    base = findings_dir / finding_basename(results.domain)

    written: List[str] = []
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt == "json":
            path = _with_extension(base, ".json")
            path.write_text(
                json.dumps(results.to_dict(min_confidence), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            written.append(str(path))
        elif fmt in ("md", "markdown"):
            path = _with_extension(base, ".md")
            path.write_text(_markdown(results, min_confidence), encoding="utf-8")
            written.append(str(path))
        elif fmt in ("txt", "text"):
            path = _with_extension(base, ".txt")
            path.write_text(_plain_text(results, min_confidence), encoding="utf-8")
            written.append(str(path))
    return written


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #


def _markdown(results: ScanResults, min_confidence: str) -> str:
    findings = results.sorted_findings(min_confidence)
    counts = results.severity_counts(min_confidence)
    lines: List[str] = []

    lines.append("# Front-end security scan — {}".format(results.domain or results.target))
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append("| Target | {} |".format(results.target))
    lines.append("| Started | {} |".format(results.started_at))
    lines.append("| Duration | {:.1f}s |".format(results.duration))
    lines.append("| Requests | {} |".format(results.stats.get("requests", 0)))
    lines.append("| Assets scanned | {} |".format(results.stats.get("assets_scanned", 0)))
    lines.append("| Bytes scanned | {} |".format(results.stats.get("bytes_scanned", 0)))
    lines.append("")

    lines.append("## Findings by severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for severity in Severity.ALL:
        lines.append("| {} | {} |".format(severity, counts.get(severity, 0)))
    lines.append("")

    if results.technologies:
        lines.append("## Technologies and versions")
        lines.append("")
        lines.append("| Name | Version | Category | Evidence |")
        lines.append("|---|---|---|---|")
        for tech in sorted(results.technologies.values(), key=lambda t: (t.category, t.name)):
            lines.append("| {} | {} | {} | {} |".format(
                _esc(tech.name), _esc(tech.version or "unknown"),
                _esc(tech.category), _esc(tech.evidence)
            ))
        lines.append("")

    if results.services:
        lines.append("## Third-party services")
        lines.append("")
        lines.append("| Service | Category | Host |")
        lines.append("|---|---|---|")
        for service in sorted(results.services.values(), key=lambda s: (s.category, s.name)):
            lines.append("| {} | {} | {} |".format(
                _esc(service.name), _esc(service.category), _esc(service.host)
            ))
        lines.append("")

    if findings:
        lines.append("## Findings")
        lines.append("")
        current_category = None
        for index, finding in enumerate(findings, start=1):
            if finding.category != current_category:
                current_category = finding.category
                lines.append("### {}".format(current_category))
                lines.append("")
            lines.append("#### {}. [{}] {}".format(index, finding.severity, _esc(finding.title)))
            lines.append("")
            lines.append("- **Confidence:** {}".format(finding.confidence))
            if finding.value:
                lines.append("- **Value:** `{}`".format(_esc_code(finding.value)))
            lines.append("- **Location:** {}{}".format(
                finding.location.url,
                ":{}".format(finding.location.line) if finding.location.line else "",
            ))
            if finding.occurrences > 1:
                lines.append("- **Also seen in:** {} other location(s)".format(finding.occurrences - 1))
                for extra in finding.also_seen[:8]:
                    lines.append("  - {}{}".format(
                        extra.url, ":{}".format(extra.line) if extra.line else ""
                    ))
            if finding.detail:
                lines.append("- **Detail:** {}".format(_esc(finding.detail)))
            if finding.remediation:
                lines.append("- **Remediation:** {}".format(_esc(finding.remediation)))
            if finding.tags:
                lines.append("- **Tags:** {}".format(", ".join(finding.tags)))
            if finding.location.snippet:
                lines.append("")
                lines.append("```")
                lines.append(finding.location.snippet[:400])
                lines.append("```")
            for key, value in sorted(finding.evidence.items()):
                if value:
                    lines.append("- _{}_: `{}`".format(key, _esc_code(str(value)[:300])))
            lines.append("")

    api_endpoints = [e for e in results.endpoints if e.kind in ("api", "graphql", "websocket")]
    if api_endpoints:
        lines.append("## API endpoints")
        lines.append("")
        lines.append("| Method | Endpoint | Kind | Scope |")
        lines.append("|---|---|---|---|")
        for endpoint in sorted(api_endpoints, key=lambda e: (e.scope, e.url)):
            lines.append("| {} | {} | {} | {} |".format(
                endpoint.method, _esc(endpoint.url), endpoint.kind, endpoint.scope
            ))
        lines.append("")

    pages = [e for e in results.endpoints if e.kind == "page"]
    if pages:
        lines.append("## Routes / pages discovered")
        lines.append("")
        for endpoint in sorted(pages, key=lambda e: e.url)[:200]:
            lines.append("- {}".format(endpoint.url))
        lines.append("")

    if results.urls:
        lines.append("## All URLs ({})".format(len(results.urls)))
        lines.append("")
        for url in sorted(results.urls)[:500]:
            lines.append("- {}".format(url))
        lines.append("")

    if results.emails:
        lines.append("## Email addresses")
        lines.append("")
        for email in sorted(set(results.emails)):
            lines.append("- {}".format(email))
        lines.append("")

    if results.errors:
        lines.append("## Request errors")
        lines.append("")
        for err in results.errors[:100]:
            lines.append("- {}".format(_esc(err)))
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Plain text
# --------------------------------------------------------------------------- #


def _plain_text(results: ScanResults, min_confidence: str) -> str:
    lines: List[str] = []
    rule = "=" * 78
    lines.append(rule)
    lines.append("SCAN BLUNDER FRONT — {}".format(results.target))
    lines.append("{}  ·  {:.1f}s  ·  {} requests".format(
        results.started_at, results.duration, results.stats.get("requests", 0)
    ))
    lines.append(rule)

    counts = results.severity_counts(min_confidence)
    lines.append("")
    lines.append("SEVERITY: " + "  ".join(
        "{}={}".format(s, counts.get(s, 0)) for s in Severity.ALL
    ))

    if results.technologies:
        lines.append("")
        lines.append("-- TECHNOLOGIES " + "-" * 62)
        for tech in sorted(results.technologies.values(), key=lambda t: t.name.lower()):
            lines.append("  {:<34} {:<14} {}".format(
                tech.name[:34], (tech.version or "unknown")[:14], tech.category
            ))

    if results.services:
        lines.append("")
        lines.append("-- THIRD-PARTY SERVICES " + "-" * 54)
        for service in sorted(results.services.values(), key=lambda s: s.name):
            lines.append("  {:<34} {}".format(service.name[:34], service.category))

    findings = results.sorted_findings(min_confidence)
    if findings:
        lines.append("")
        lines.append("-- FINDINGS " + "-" * 66)
        for index, finding in enumerate(findings, start=1):
            lines.append("")
            lines.append("[{}] {} — {} ({})".format(
                index, finding.severity, finding.title, finding.confidence
            ))
            if finding.value:
                lines.append("    value : {}".format(finding.value[:200]))
            lines.append("    where : {}{}".format(
                finding.location.url,
                ":{}".format(finding.location.line) if finding.location.line else "",
            ))
            if finding.occurrences > 1:
                lines.append("    seen  : {} location(s)".format(finding.occurrences))
            if finding.detail:
                lines.append("    detail: {}".format(finding.detail))
            if finding.remediation:
                lines.append("    fix   : {}".format(finding.remediation))
            if finding.location.snippet:
                lines.append("    code  : {}".format(finding.location.snippet[:200]))

    api_endpoints = [e for e in results.endpoints if e.kind in ("api", "graphql", "websocket")]
    if api_endpoints:
        lines.append("")
        lines.append("-- API ENDPOINTS " + "-" * 61)
        for endpoint in sorted(api_endpoints, key=lambda e: e.url):
            lines.append("  {:<7} {}".format(endpoint.method, endpoint.url))

    if results.urls:
        lines.append("")
        lines.append("-- URLS ({}) ".format(len(results.urls)) + "-" * 55)
        for url in sorted(results.urls):
            lines.append("  {}".format(url))

    lines.append("")
    lines.append(rule)
    return "\n".join(lines)


def _with_extension(base: Path, extension: str) -> Path:
    """Append an extension.

    `Path.with_suffix` replaces whatever follows the last dot, which mangles
    hostnames and IP addresses: `127.0.0.1_stamp` would become `127.0.0.json`.
    """
    return base.with_name(base.name + extension)


def _esc(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _esc_code(text: str) -> str:
    return str(text).replace("`", "'").replace("\n", " ")
