"""Command-line entry point."""
from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional

from scanner.cli.output import (
    configure,
    error,
    info,
    show_banner,
    show_report_paths,
    show_results,
    warning,
)
from scanner.cli.validators import (
    header_validator,
    positive_int,
    scheme_was_inferred,
    url_validator,
)
from scanner.core.context import ScanContext
from scanner.core.detector.detector_services import DETECTOR_NAMES
from scanner.core.engine import ScannerEngine
from scanner.core.findings.writer import write_reports
from scanner.core.models import Confidence, Severity

DESCRIPTION = """\
Scan Blunder Front — front-end security scanner.

Fingerprints the stack, inventories the backends a page talks to, and reports
exposed secrets, raw SQL, client-side authorization logic and other front-end
weaknesses. Works against React, Next.js, Vue, Nuxt, Angular, Svelte, WordPress
and plain server-rendered sites.
"""

EPILOG = """\
examples:
  python3 main.py example.com
  python3 main.py https://example.com --threads 20 --depth 1
  python3 main.py https://example.com --include-tentative --format json,md,txt
  python3 main.py https://example.com --only secrets,sql --no-probe
  python3 main.py https://example.com -H "Cookie: session=..." --fail-on HIGH

Only scan systems you own or are explicitly authorised to test.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan-blunder-front",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", type=url_validator, help="target URL (scheme optional)")

    scan = parser.add_argument_group("scan scope")
    scan.add_argument("--threads", type=positive_int, default=10,
                      help="concurrent requests (default: 10)")
    scan.add_argument("--depth", type=int, default=0, metavar="N",
                      help="also crawl N levels of same-site pages (default: 0)")
    scan.add_argument("--max-assets", type=positive_int, default=300,
                      help="hard cap on files fetched (default: 300)")
    scan.add_argument("--max-size", type=positive_int, default=5, metavar="MB",
                      help="per-file download cap in MB (default: 5)")
    scan.add_argument("--no-sourcemaps", action="store_true",
                      help="do not download .map files")
    scan.add_argument("--no-probe", action="store_true",
                      help="do not request well-known sensitive paths")

    detectors = parser.add_argument_group("detectors")
    detectors.add_argument("--only", metavar="LIST",
                           help="run only these detectors ({})".format(",".join(DETECTOR_NAMES)))
    detectors.add_argument("--skip", metavar="LIST",
                           help="run everything except these detectors")

    network = parser.add_argument_group("network")
    network.add_argument("--timeout", type=positive_int, default=15,
                         help="per-request timeout in seconds (default: 15)")
    network.add_argument("--delay", type=float, default=0.0, metavar="SECONDS",
                         help="minimum delay between requests (default: 0)")
    network.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    network.add_argument("--insecure", action="store_true",
                         help="do not verify TLS certificates")
    network.add_argument("-H", "--header", type=header_validator, action="append",
                         default=[], metavar="'Name: value'",
                         help="extra request header (repeatable)")
    network.add_argument("--user-agent", default="", help="override the User-Agent")

    report = parser.add_argument_group("reporting")
    report.add_argument("--output", default="findings", metavar="DIR",
                        help="report directory (default: findings)")
    report.add_argument("--format", default="json,md", metavar="LIST",
                        help="report formats: json, md, txt (default: json,md)")
    report.add_argument("--no-report", action="store_true", help="do not write report files")
    report.add_argument("--include-tentative", action="store_true",
                        help="show low-confidence findings too")
    report.add_argument("--min-severity", default="INFO",
                        choices=[s for s in Severity.ALL] + [s.lower() for s in Severity.ALL],
                        help="hide findings below this severity (default: INFO)")
    report.add_argument("--fail-on", default="", metavar="SEVERITY",
                        choices=[""] + list(Severity.ALL) + [s.lower() for s in Severity.ALL],
                        help="exit with code 2 if a finding at or above this severity is found")
    report.add_argument("-v", "--verbose", action="store_true", help="log every request")
    report.add_argument("-q", "--quiet", action="store_true", help="suppress terminal output")

    return parser


def _resolve_detectors(only: Optional[str], skip: Optional[str]) -> Optional[List[str]]:
    if only:
        requested = [n.strip().lower() for n in only.split(",") if n.strip()]
        unknown = [n for n in requested if n not in DETECTOR_NAMES]
        if unknown:
            raise SystemExit(
                "Unknown detector(s): {}. Available: {}".format(
                    ", ".join(unknown), ", ".join(DETECTOR_NAMES)
                )
            )
        return requested
    if skip:
        excluded = {n.strip().lower() for n in skip.split(",") if n.strip()}
        unknown = [n for n in excluded if n not in DETECTOR_NAMES]
        if unknown:
            raise SystemExit(
                "Unknown detector(s): {}. Available: {}".format(
                    ", ".join(unknown), ", ".join(DETECTOR_NAMES)
                )
            )
        return [n for n in DETECTOR_NAMES if n not in excluded]
    return None


def run(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    configure(verbose_mode=args.verbose, quiet=args.quiet)
    show_banner()

    extra_headers: Dict[str, str] = dict(args.header or [])
    enabled = _resolve_detectors(args.only, args.skip)

    context = ScanContext.for_url(
        args.url,
        max_threads=args.threads,
        timeout=args.timeout,
        max_asset_bytes=args.max_size * 1024 * 1024,
        crawl_depth=max(0, args.depth),
        max_assets=args.max_assets,
        follow_sourcemaps=not args.no_sourcemaps,
        probe_paths=not args.no_probe,
        delay=max(0.0, args.delay),
        verify_tls=not args.insecure,
        proxy=args.proxy,
        extra_headers=extra_headers,
        user_agent=args.user_agent,
        scheme_inferred=scheme_was_inferred(args.url),
    )

    if args.insecure:
        warning("TLS verification is disabled for this scan.")

    engine = ScannerEngine(context, enabled_detectors=enabled)
    try:
        results = engine.run()
    except KeyboardInterrupt:
        warning("Interrupted — reporting what was collected so far.")
        results = context.results

    min_confidence = Confidence.TENTATIVE if args.include_tentative else Confidence.FIRM
    _apply_min_severity(results, args.min_severity.upper())

    show_results(results, min_confidence=min_confidence)

    if not args.no_report:
        try:
            paths = write_reports(
                results,
                directory=args.output,
                formats=[f for f in args.format.split(",") if f.strip()],
                min_confidence=Confidence.TENTATIVE,
            )
            show_report_paths(paths)
        except OSError as exc:
            error("Could not write the report: {}".format(exc))

    if args.fail_on:
        threshold = Severity.weight(args.fail_on.upper())
        worst = results.max_severity(min_confidence)
        if worst and Severity.weight(worst) >= threshold:
            return 2
    return 0


def _apply_min_severity(results, minimum: str) -> None:
    """Drop findings below the requested severity floor, in place."""
    if minimum == Severity.INFO:
        return
    threshold = Severity.weight(minimum)
    kept = [f for f in results.findings if Severity.weight(f.severity) >= threshold]
    results.findings[:] = kept


def main() -> None:
    sys.exit(run())
