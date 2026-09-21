"""Scan orchestration.

The flow is a breadth-first pipeline rather than the previous "fetch page, then
guess a few Next.js paths" approach:

    target page
      -> response headers      (server/CDN/cookie fingerprints, header checks)
      -> HTML                  (inline scripts, meta, __NEXT_DATA__)
      -> every referenced script, stylesheet and JSON chunk
      -> chunk manifests those scripts reference (webpack/Next/Vite/Nuxt)
      -> source maps, when published
      -> a short list of sensitive paths
      -> optional same-site page crawl, depth limited

Each stage feeds the next through a work queue, so a Next.js build that splits
into 300 chunks is walked properly instead of being sampled.
"""
from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from scanner.cli.output import error, info, success, verbose, warning
from scanner.core.context import ScanContext
from scanner.core.detector.detector_services import Detector
from scanner.core.models import (
    Asset,
    Category,
    Confidence,
    Finding,
    Location,
    ScanResults,
    Severity,
)
from scanner.core.patterns.technologies import SENSITIVE_PATHS
from scanner.services.http_client import HttpClient, extract_links

#: Framework-specific manifests worth requesting explicitly. They enumerate the
#: rest of the bundle, which is where the interesting code usually hides.
_MANIFEST_PATHS = {
    "Next.js": (
        "/_next/static/chunks/webpack.js",
        "/_next/static/chunks/main.js",
        "/_next/static/chunks/pages/_app.js",
        "/_next/static/chunks/pages/index.js",
    ),
    "Nuxt": ("/_nuxt/manifest.json",),
    "WordPress": ("/wp-json/", "/wp-json/wp/v2/types"),
}

_BUILD_MANIFEST_RE = re.compile(r"""["'](/_next/static/[^"']+\.js)["']""")


class ScannerEngine:
    """Drives the scan and hands the finished `ScanResults` back to the CLI."""

    def __init__(self, context: ScanContext, enabled_detectors: Optional[Iterable[str]] = None):
        self.context = context
        self.results: ScanResults = context.results
        self.detector = Detector(context, enabled=enabled_detectors)
        self.http = HttpClient(
            timeout=context.timeout,
            max_bytes=context.max_asset_bytes,
            verify_tls=context.verify_tls,
            proxy=context.proxy,
            user_agent=context.user_agent,
            extra_headers=context.extra_headers,
            delay=context.delay,
        )

        self._seen: Set[str] = set()
        self._seen_lock = threading.Lock()
        self._main_asset: Optional[Asset] = None

    # -- public API ------------------------------------------------------------ #
    def run(self) -> ScanResults:
        started = time.time()
        self.results.started_at = datetime.now().isoformat(timespec="seconds")

        info("Target: [bold]{}[/bold]".format(self.context.base_url))

        main_asset = self._fetch_and_scan(self.context.base_url)
        if main_asset is None and self.context.scheme_inferred:
            warning("https:// did not respond; retrying over http://")
            self.context.switch_to_http()
            self._seen.clear()
            main_asset = self._fetch_and_scan(self.context.base_url)

        if main_asset is None:
            error("The target did not return a usable response. Nothing to scan.")
            self._finish(started)
            return self.results
        self._main_asset = main_asset

        success(
            "Main document fetched ({} bytes, HTTP {})".format(
                main_asset.size, main_asset.status
            )
        )

        queue: Set[str] = set()
        pages: Set[str] = set()

        links = extract_links(main_asset, self.context.base_url)
        queue |= links["scripts"]
        pages |= links["pages"]
        sourcemaps: Set[str] = set(links["sourcemaps"])

        queue |= self._framework_manifests(main_asset)

        info("{} script/asset reference(s) queued from the main document".format(len(queue)))

        # --- breadth-first asset walk ----------------------------------------
        discovered_pages: Set[str] = set()
        depth_remaining = self.context.crawl_depth
        while queue:
            batch = self._take_batch(queue)
            if not batch:
                break
            for asset in self._fetch_batch(batch):
                if asset is None:
                    continue
                child = extract_links(asset, self.context.base_url)
                sourcemaps |= child["sourcemaps"]
                discovered_pages |= child["pages"]
                new_scripts = {u for u in child["scripts"] if not self._already_seen(u)}
                queue |= new_scripts
                queue |= self._next_build_chunks(asset)

        # --- source maps -------------------------------------------------------
        if self.context.follow_sourcemaps and sourcemaps:
            info("Checking {} source map(s)".format(len(sourcemaps)))
            self._scan_sourcemaps(sourcemaps)

        # --- optional same-site crawl -----------------------------------------
        if depth_remaining > 0:
            self._crawl_pages(pages | discovered_pages, depth_remaining)

        # --- sensitive paths ---------------------------------------------------
        if self.context.probe_paths:
            self._probe_sensitive_paths()

        self._finish(started)
        return self.results

    # -- stages ----------------------------------------------------------------- #
    def _fetch_and_scan(self, url: str) -> Optional[Asset]:
        if self._already_seen(url, mark=True):
            return None
        if len(self._seen) > self.context.max_assets:
            return None

        asset, err = self.http.fetch(url)
        if err is not None:
            verbose("skip {} ({})".format(url, err))
            self.results.errors.append("{}: {}".format(url, err))
            return None
        if asset is None or asset.kind == "binary" or not asset.content:
            return None
        if asset.status >= 400:
            verbose("skip {} (HTTP {})".format(url, asset.status))
            return None

        verbose("scan {} [{}] {} bytes".format(url, asset.kind, asset.size))
        self.detector.scan(asset)
        return asset

    def _fetch_batch(self, urls: List[str]) -> List[Optional[Asset]]:
        assets: List[Optional[Asset]] = []
        workers = max(1, min(self.context.max_threads, len(urls)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._fetch_and_scan, url): url for url in urls}
            for future in as_completed(futures):
                try:
                    assets.append(future.result())
                except Exception as exc:  # pragma: no cover - defensive
                    self.results.errors.append("{}: {}".format(futures[future], exc))
        return assets

    def _framework_manifests(self, asset: Asset) -> Set[str]:
        """Ask for the manifests of whichever framework we just fingerprinted."""
        candidates: Set[str] = set()
        detected = set(self.results.technologies.keys())
        for framework, paths in _MANIFEST_PATHS.items():
            if framework not in detected:
                continue
            for path in paths:
                candidates.add(urljoin(self.context.base_url, path))

        # Next.js publishes an explicit list of every chunk it ships.
        build_id = self._next_build_id(asset)
        if build_id:
            for path in ("_buildManifest.js", "_ssgManifest.js", "_middlewareManifest.js"):
                candidates.add(
                    urljoin(self.context.base_url, "/_next/static/{}/{}".format(build_id, path))
                )
        return {u for u in candidates if not self._already_seen(u)}

    @staticmethod
    def _next_build_id(asset: Asset) -> str:
        match = re.search(r'"buildId"\s*:\s*"([^"]{1,64})"', asset.content)
        return match.group(1) if match else ""

    def _next_build_chunks(self, asset: Asset) -> Set[str]:
        """`_buildManifest.js` lists every route chunk; follow them all."""
        if "_buildManifest" not in asset.url and "webpack" not in asset.url:
            return set()
        chunks = {
            urljoin(self.context.base_url, path)
            for path in _BUILD_MANIFEST_RE.findall(asset.content)
        }
        return {u for u in chunks if not self._already_seen(u)}

    def _scan_sourcemaps(self, sourcemaps: Set[str]) -> None:
        for url in list(sourcemaps)[:40]:
            asset, err = self.http.fetch(url)
            if err or asset is None or not asset.content:
                continue
            if asset.status >= 400:
                continue
            try:
                data = json.loads(asset.content)
            except ValueError:
                continue

            sources = data.get("sources") or []
            contents = data.get("sourcesContent") or []
            self.results.add_finding(
                Finding(
                    category=Category.EXPOSURE,
                    title="Source map published",
                    severity=Severity.MEDIUM if contents else Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    location=Location(url=url, line=0, column=0, snippet=""),
                    value=url,
                    detail=(
                        "The source map is publicly readable and embeds the original source of "
                        "{} file(s). The unminified code, including comments and internal paths, "
                        "is available to anyone.".format(len(sources))
                        if contents
                        else "The source map is publicly readable and reveals {} original file "
                             "path(s).".format(len(sources))
                    ),
                    remediation=(
                        "Stop deploying .map files, or serve them only to authenticated users."
                    ),
                    evidence={"sources": ", ".join(str(s) for s in sources[:15])},
                    tags=["exposure", "sourcemap"],
                )
            )

            # The original source is far more informative than the minified
            # bundle, so run the detectors over it as a synthetic asset.
            if contents:
                joined = "\n".join(c for c in contents if isinstance(c, str))[
                    : self.context.max_asset_bytes
                ]
                synthetic = Asset(
                    url=url + " (original sources)",
                    content=joined,
                    content_type="application/javascript",
                    status=200,
                    kind="js",
                )
                self.detector.scan(synthetic)

    def _crawl_pages(self, pages: Set[str], depth: int) -> None:
        frontier = {p for p in pages if not self._already_seen(p)}
        for level in range(depth):
            if not frontier:
                break
            batch = self._take_batch(frontier, limit=30)
            info("Crawling {} page(s) at depth {}".format(len(batch), level + 1))
            next_frontier: Set[str] = set()
            for asset in self._fetch_batch(batch):
                if asset is None:
                    continue
                child = extract_links(asset, self.context.base_url)
                for script in child["scripts"]:
                    if not self._already_seen(script):
                        self._fetch_and_scan(script)
                next_frontier |= {p for p in child["pages"] if not self._already_seen(p)}
            frontier = next_frontier

    def _probe_sensitive_paths(self) -> None:
        info("Probing {} well-known sensitive path(s)".format(len(SENSITIVE_PATHS)))
        base = self.context.base_url

        def probe(entry: Tuple[str, str, str]) -> Optional[Finding]:
            path, label, severity = entry
            url = urljoin(base, path)
            exists, status, preview = self.http.head_exists(url)
            if not exists:
                return None
            if not _looks_like_real_file(path, preview):
                return None
            return Finding(
                category=Category.EXPOSURE,
                title=label,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                location=Location(url=url, line=0, column=0, snippet=preview[:160].strip()),
                value=url,
                detail="`{}` is publicly reachable (HTTP {}).".format(path, status),
                remediation="Block the path at the web server or remove the file from the deployment.",
                evidence={"preview": preview[:300]},
                tags=["exposure", "probe"],
            )

        workers = max(1, min(self.context.max_threads, 8))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for finding in pool.map(probe, SENSITIVE_PATHS):
                if finding is not None:
                    self.results.add_finding(finding)

    # -- bookkeeping -------------------------------------------------------------- #
    def _take_batch(self, queue: Set[str], limit: int = 60) -> List[str]:
        batch: List[str] = []
        while queue and len(batch) < limit:
            url = queue.pop()
            if self._already_seen(url):
                continue
            batch.append(url)
        return batch

    def _already_seen(self, url: str, mark: bool = False) -> bool:
        normalized = url.split("#")[0]
        with self._seen_lock:
            if normalized in self._seen:
                return True
            if mark:
                self._seen.add(normalized)
            return False

    def _finish(self, started: float) -> None:
        self.detector.finalize(self._main_asset)
        self.results.finished_at = datetime.now().isoformat(timespec="seconds")
        self.results.duration = time.time() - started
        self.results.stats["requests"] = len(self._seen)
        if self.results.errors:
            warning("{} request(s) failed; see the report for details".format(
                len(self.results.errors)
            ))


def _looks_like_real_file(path: str, preview: str) -> bool:
    """Guard against SPA catch-all routes answering 200 for everything."""
    if not preview:
        return True
    head = preview.lstrip()[:400].lower()
    # A React/Vue index.html served for /.env is not an exposed .env file.
    if path not in ("/robots.txt", "/sitemap.xml") and head.startswith(("<!doctype html", "<html")):
        return False
    if path.endswith(".json") and not head.startswith(("{", "[")):
        return False
    if path == "/.git/config" and "[core]" not in preview.lower():
        return False
    if path == "/.git/HEAD" and not preview.lower().startswith("ref:"):
        return False
    if path.startswith("/.env") and "=" not in preview:
        return False
    return True
