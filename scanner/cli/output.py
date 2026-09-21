"""Terminal presentation."""
from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional

from rich.box import ROUNDED, SIMPLE_HEAD
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scanner.core.models import (
    Confidence,
    Finding,
    ScanResults,
    SEVERITY_COLOR,
    Severity,
)

console = Console(highlight=False)

_state = {"verbose": False, "quiet": False}


def configure(verbose_mode: bool = False, quiet: bool = False) -> None:
    _state["verbose"] = verbose_mode
    _state["quiet"] = quiet


def success(msg: str) -> None:
    if not _state["quiet"]:
        console.print("[bold green][+][/bold green] {}".format(msg))


def error(msg: str) -> None:
    console.print("[bold red][-][/bold red] {}".format(msg))


def info(msg: str) -> None:
    if not _state["quiet"]:
        console.print("[bold blue][*][/bold blue] {}".format(msg))


def warning(msg: str) -> None:
    if not _state["quiet"]:
        console.print("[bold yellow][!][/bold yellow] {}".format(msg))


def verbose(msg: str) -> None:
    if _state["verbose"] and not _state["quiet"]:
        console.print("[dim]    {}[/dim]".format(msg))


def show_banner() -> None:
    if _state["quiet"]:
        return
    console.print(
        """
 _____                   _____  _              _              _____                 _   
|   __| ___  ___  ___   | __  || | _ _  ___  _| | ___  ___   |   __| ___  ___  ___ | |_ 
|__   ||  _|| .'||   |  | __ -|| || | ||   || . || -_||  _|  |   __||  _|| . ||   ||  _|
|_____||___||__,||_|_|  |_____||_||___||_|_||___||___||_|    |__|   |_|  |___||_|_||_|  
""",
        style="bold cyan",
        crop=False,
        overflow="ignore",
    )
    console.print(
        "  front-end security scanner  ·  use only on targets you are authorised to test\n",
        style="dim",
    )


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


def _severity_text(severity: str) -> Text:
    return Text(severity, style=SEVERITY_COLOR.get(severity, "white"))


def show_results(results: ScanResults, min_confidence: str = Confidence.FIRM,
                 max_rows: int = 40) -> None:
    if _state["quiet"]:
        return

    console.rule("[bold cyan]SCAN SUMMARY[/bold cyan]")
    _summary_panel(results, min_confidence)

    _technologies(results)
    _services(results)
    _findings_by_category(results, min_confidence, max_rows)
    _endpoints(results, max_rows)
    _urls(results)

    if results.errors and _state["verbose"]:
        console.print("\n[bold yellow]Request errors[/bold yellow]")
        for err in results.errors[:20]:
            console.print("  [dim]{}[/dim]".format(err))


def _summary_panel(results: ScanResults, min_confidence: str) -> None:
    counts = results.severity_counts(min_confidence)
    parts = []
    for severity in Severity.ALL:
        count = counts.get(severity, 0)
        if count:
            parts.append("[{}]{} {}[/]".format(SEVERITY_COLOR[severity], count, severity))
    headline = "  ".join(parts) if parts else "[green]no findings above the confidence threshold[/green]"

    hidden = len(results.findings) - len(results.sorted_findings(min_confidence))
    body = (
        "Target      {target}\n"
        "Duration    {duration:.1f}s   ·   {requests} request(s)   ·   {bytes} KB scanned\n"
        "Findings    {headline}"
    ).format(
        target=results.target,
        duration=results.duration,
        requests=results.stats.get("requests", 0),
        bytes=results.stats.get("bytes_scanned", 0) // 1024,
        headline=headline,
    )
    if hidden > 0:
        body += "\n[dim]{} low-confidence finding(s) hidden — rerun with --include-tentative[/dim]".format(hidden)

    console.print(Panel(body, border_style="cyan", box=ROUNDED))


def _technologies(results: ScanResults) -> None:
    if not results.technologies:
        return
    console.print("\n[bold blue][+] TECHNOLOGIES & VERSIONS[/bold blue]")
    table = Table(box=SIMPLE_HEAD, header_style="bold magenta", show_edge=False)
    table.add_column("Name", style="green", no_wrap=True)
    table.add_column("Version")
    table.add_column("Category", style="dim")
    table.add_column("Evidence", style="dim", overflow="ellipsis", max_width=40)

    ordered = sorted(
        results.technologies.values(),
        key=lambda t: (t.category, t.name.lower()),
    )
    for tech in ordered:
        table.add_row(
            tech.name,
            tech.version or "[dim]unknown[/dim]",
            tech.category,
            tech.evidence,
        )
    console.print(table)


def _services(results: ScanResults) -> None:
    if not results.services:
        return
    console.print("\n[bold blue][+] THIRD-PARTY SERVICES[/bold blue]")
    table = Table(box=SIMPLE_HEAD, header_style="bold magenta", show_edge=False)
    table.add_column("Service", style="green")
    table.add_column("Category", style="dim")
    table.add_column("Host", style="dim")
    for service in sorted(results.services.values(), key=lambda s: (s.category, s.name)):
        table.add_row(service.name, service.category, service.host)
    console.print(table)


_CATEGORY_STYLE = {
    "Secret": ("bold red", "[!] SECRETS & CREDENTIALS"),
    "Vulnerability": ("bold red", "[!] VULNERABILITIES & BAD PRACTICES"),
    "Access Control": ("bold yellow", "[!] ROLES, PERMISSIONS & ACCESS CONTROL"),
    "Information Exposure": ("bold yellow", "[!] INFORMATION EXPOSURE"),
    "Security Header": ("bold cyan", "[+] SECURITY HEADERS"),
}


def _findings_by_category(results: ScanResults, min_confidence: str, max_rows: int) -> None:
    findings = results.sorted_findings(min_confidence)
    if not findings:
        return

    grouped: Dict[str, List[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.category, []).append(finding)

    for category in ("Secret", "Vulnerability", "Access Control",
                     "Information Exposure", "Security Header"):
        items = grouped.get(category)
        if not items:
            continue
        style, heading = _CATEGORY_STYLE.get(category, ("bold", category.upper()))
        console.print("\n[{}]{}[/{}]".format(style, heading, style))

        table = Table(box=SIMPLE_HEAD, header_style="bold magenta", show_edge=False)
        table.add_column("Sev", no_wrap=True)
        table.add_column("Conf", style="dim", no_wrap=True)
        table.add_column("Issue", overflow="fold", max_width=38)
        table.add_column("Value / evidence", overflow="fold", max_width=42)
        table.add_column("Where", style="dim", overflow="fold", max_width=32)

        for finding in items[:max_rows]:
            location = finding.location
            where = _short_location(location.url)
            if location.line:
                where += ":{}".format(location.line)
            if finding.occurrences > 1:
                where += " [dim](+{} more)[/dim]".format(finding.occurrences - 1)
            table.add_row(
                _severity_text(finding.severity),
                finding.confidence[:4].title(),
                finding.title,
                finding.value or finding.location.snippet[:80],
                where,
            )
        console.print(table)
        if len(items) > max_rows:
            console.print("  [dim]… and {} more in the report file[/dim]".format(len(items) - max_rows))

        # Details for the things that really matter.
        for finding in items:
            if Severity.weight(finding.severity) < Severity.weight(Severity.HIGH):
                continue
            if not finding.detail:
                continue
            console.print(
                "  [{}]▸ {}[/] {}".format(
                    SEVERITY_COLOR.get(finding.severity, "white"),
                    finding.title,
                    finding.detail,
                )
            )
            if finding.remediation:
                console.print("    [dim]fix: {}[/dim]".format(finding.remediation))


def _endpoints(results: ScanResults, max_rows: int) -> None:
    if not results.endpoints:
        return
    api = [e for e in results.endpoints if e.kind in ("api", "graphql", "websocket")]
    if not api:
        return
    console.print("\n[bold cyan][+] API ENDPOINTS ({})[/bold cyan]".format(len(api)))
    table = Table(box=SIMPLE_HEAD, header_style="bold cyan", show_edge=False)
    table.add_column("Method", no_wrap=True)
    table.add_column("Endpoint", overflow="fold")
    table.add_column("Kind", style="dim", no_wrap=True)
    table.add_column("Scope", style="dim", no_wrap=True)

    ordered = sorted(api, key=lambda e: (e.scope != "same-origin", e.url))
    for endpoint in ordered[:max_rows]:
        table.add_row(endpoint.method, endpoint.url, endpoint.kind, endpoint.scope)
    console.print(table)
    if len(ordered) > max_rows:
        console.print("  [dim]… and {} more in the report file[/dim]".format(len(ordered) - max_rows))


def _urls(results: ScanResults) -> None:
    if not results.urls:
        return
    scopes: Dict[str, int] = {}
    for scope in results.urls.values():
        scopes[scope] = scopes.get(scope, 0) + 1
    breakdown = ", ".join("{} {}".format(count, scope) for scope, count in sorted(scopes.items()))
    console.print(
        "\n[bold blue][+] {} URL(s) collected[/bold blue] [dim]({})[/dim]".format(
            len(results.urls), breakdown
        )
    )


def show_report_paths(paths: Iterable[str]) -> None:
    paths = list(paths)
    if not paths or _state["quiet"]:
        return
    console.print("\n[bold green][+] Reports written:[/bold green]")
    for path in paths:
        console.print("  [green]{}[/green]".format(path))


def _short_location(url: str) -> str:
    if len(url) <= 46:
        return url
    tail = url.split("/")[-1]
    return "…/" + tail if tail else url[-46:]
