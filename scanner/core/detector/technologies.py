"""Technology, version and third-party service fingerprinting."""
from __future__ import annotations

import json
import re
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from scanner.core.detector.base import BaseDetector
from scanner.core.models import (
    Asset,
    Category,
    Confidence,
    Finding,
    Service,
    Severity,
    Technology,
)
from scanner.core.patterns.technologies import (
    ASSET_VERSION_RE,
    BANNER_VERSION_RE,
    CONTENT_RULES,
    COOKIE_RULES,
    HEADER_RULES,
    SERVICE_HOSTS,
    WP_PLUGIN_RE,
    WP_THEME_RE,
)

_VERSION_IN_NAME = re.compile(r"[/@\-.]v?(\d+\.\d+(?:\.\d+)?(?:[-.\w]+)?)(?:\.min)?\.(?:js|css)")
#: "WordPress 6.2.1", "Drupal 10", "WordPress 7.2-alpha-63632" -> (name, version)
#: Not anchored at the end: real generator strings trail a URL or a note,
#: e.g. "Drupal 10 (https://www.drupal.org)".
_GENERATOR_SPLIT = re.compile(r"^(?P<name>[A-Za-z][\w .]*?)[\s\-]+v?(?P<version>\d[\w.\-]*)\b")

#: Libraries whose known-vulnerable ranges are worth calling out. Kept short and
#: conservative: a version check that fires constantly gets ignored.
_OUTDATED_RULES: List[Tuple[str, Tuple[int, ...], str, str]] = [
    ("jQuery", (3, 5, 0), "HIGH", "jQuery below 3.5.0 is affected by XSS via htmlPrefilter (CVE-2020-11022/11023)."),
    ("AngularJS", (1, 8, 0), "HIGH", "AngularJS is end-of-life and carries known template-injection issues."),
    ("Bootstrap", (4, 0, 0), "MEDIUM", "Bootstrap 3.x is unmaintained and has known XSS issues in data-* attributes."),
    ("Moment.js", (2, 29, 4), "MEDIUM", "moment below 2.29.4 is affected by a path traversal (CVE-2022-24785)."),
    ("Lodash", (4, 17, 21), "MEDIUM", "lodash below 4.17.21 is affected by command injection / prototype pollution."),
    ("Next.js", (14, 2, 25), "MEDIUM", "Next.js below 14.2.25 is affected by the middleware authorization bypass (CVE-2025-29927)."),
    ("Vue.js", (2, 7, 0), "LOW", "Vue 2 reached end-of-life; security fixes are no longer published."),
]


def _parse_version(version: str) -> Optional[Tuple[int, ...]]:
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", version.strip())
    if not match:
        return None
    return tuple(int(part) if part else 0 for part in match.groups())


class TechnologyDetector(BaseDetector):
    """Populates results.technologies / results.services and flags stale versions."""

    name = "technology"

    def detect(self, asset: Asset) -> Iterable[Finding]:
        findings: List[Finding] = []
        results = self.context.results

        self._from_headers(asset, results, findings)
        self._from_content(asset, results)
        self._from_asset_name(asset, results)
        self._from_banners(asset, results)
        self._wordpress(asset, results, findings)
        self._next_data(asset, results, findings)
        self._services(asset, results)

        return findings

    # -- sources -------------------------------------------------------------- #
    def _from_headers(self, asset: Asset, results, findings: List[Finding]) -> None:
        if not asset.headers:
            return
        lowered = {k.lower(): v for k, v in asset.headers.items()}

        for header, fixed_name, category in HEADER_RULES:
            value = lowered.get(header)
            if not value:
                continue
            if fixed_name:
                results.add_technology(
                    Technology(fixed_name, "", category, "{}: {}".format(header, value[:60]), asset.url)
                )
                continue
            # Server / X-Powered-By carry "nginx/1.18.0", "PHP/8.1.2"
            for part in re.split(r"[,;]", value):
                part = part.strip()
                if not part:
                    continue
                name, _, version = part.partition("/")
                results.add_technology(
                    Technology(name.strip(), version.strip(), category,
                               "{} header".format(header), asset.url)
                )
                if version.strip():
                    findings.append(
                        self.finding(
                            asset=asset,
                            category=Category.EXPOSURE,
                            title="Server software version disclosed",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            start=0,
                            end=0,
                            value="{}: {}".format(header, part),
                            detail=(
                                "The `{}` response header reveals the exact software version, "
                                "which lets an attacker look up matching CVEs directly.".format(header)
                            ),
                            remediation="Suppress or genericise version banners in the web server config.",
                            tags=["recon", "headers"],
                        )
                    )

        cookies = lowered.get("set-cookie", "")
        for pattern, name, category in COOKIE_RULES:
            if pattern.search(cookies):
                results.add_technology(
                    Technology(name, "", category, "cookie fingerprint", asset.url)
                )

    def _from_content(self, asset: Asset, results) -> None:
        # Cap the scanned window: fingerprints live near the top of a bundle and
        # scanning 10 MB of minified code for 60 regexes is wasted time.
        haystack = asset.content if asset.size <= 400_000 else asset.content[:400_000]

        for rule in CONTENT_RULES:
            match = rule.pattern.search(haystack)
            if not match:
                continue
            version = ""
            if rule.version_group:
                try:
                    version = (match.group(rule.version_group) or "").strip()
                except IndexError:
                    version = ""

            name = rule.name
            if name == "Generator":
                raw = version.strip()
                parsed = _GENERATOR_SPLIT.match(raw)
                if parsed:
                    name = parsed.group("name").strip()
                    version = parsed.group("version").strip()
                else:
                    name, version = raw.split(" ")[0], ""
                if not name:
                    continue

            results.add_technology(
                Technology(name, version, rule.category, rule.evidence, asset.url)
            )

    def _from_asset_name(self, asset: Asset, results) -> None:
        """`/js/jquery-3.4.1.min.js?ver=1.2.3` is a free version disclosure."""
        url = asset.url
        match = _VERSION_IN_NAME.search(url)
        if match:
            stem = url.split("?")[0].split("/")[-1]
            name = re.split(r"[-.@]\d", stem)[0].replace(".min", "").strip("-_.")
            if name and len(name) > 2:
                results.add_technology(
                    Technology(name.title(), match.group(1), "library", "filename version", url)
                )

    def _from_banners(self, asset: Asset, results) -> None:
        if asset.kind not in ("js", "css", "html"):
            return
        for match in BANNER_VERSION_RE.finditer(asset.content[:20000]):
            name, version = match.group(1), match.group(2)
            if name.lower() in ("copyright", "license", "licensed", "the", "this", "see"):
                continue
            results.add_technology(
                Technology(name, version, "library", "bundle banner", asset.url)
            )

    def _wordpress(self, asset: Asset, results, findings: List[Finding]) -> None:
        if "/wp-content/" not in asset.content and "/wp-includes/" not in asset.content:
            return

        for regex, kind in ((WP_PLUGIN_RE, "plugin"), (WP_THEME_RE, "theme")):
            seen: Dict[str, str] = {}
            for match in regex.finditer(asset.content):
                slug = match.group(1)
                if slug in seen:
                    continue
                tail = asset.content[match.end(): match.end() + 60]
                version_match = ASSET_VERSION_RE.search(match.group(0) + tail)
                version = version_match.group(1) if version_match else ""
                seen[slug] = version
                results.add_technology(
                    Technology(
                        "WordPress {}: {}".format(kind, slug),
                        version,
                        "wordpress-{}".format(kind),
                        "asset path",
                        asset.url,
                    )
                )

            if seen:
                versioned = {k: v for k, v in seen.items() if v}
                findings.append(
                    self.finding(
                        asset=asset,
                        category=Category.EXPOSURE,
                        title="WordPress {}s enumerated".format(kind),
                        severity=Severity.LOW if not versioned else Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        start=0,
                        end=0,
                        value=", ".join(
                            "{}{}".format(k, " " + v if v else "") for k, v in list(seen.items())[:15]
                        ),
                        detail=(
                            "{} {}(s) are identifiable from asset paths{}. Plugin versions are "
                            "the usual way a WordPress site gets compromised.".format(
                                len(seen), kind,
                                ", {} of them with an exact version".format(len(versioned))
                                if versioned else "",
                            )
                        ),
                        remediation=(
                            "Remove `?ver=` query strings from enqueued assets and keep every "
                            "plugin updated."
                        ),
                        tags=["wordpress", "recon"],
                    )
                )

    def _next_data(self, asset: Asset, results, findings: List[Finding]) -> None:
        """__NEXT_DATA__ regularly carries server-side props that leak config."""
        match = re.search(
            r'<script[^>]+id="__NEXT_DATA__"[^>]*>([\s\S]{0,2000000}?)</script>', asset.content
        )
        if not match:
            return
        try:
            data = json.loads(match.group(1))
        except ValueError:
            return

        build_id = data.get("buildId")
        if build_id:
            results.add_technology(
                Technology("Next.js", "", "framework", "buildId {}".format(build_id), asset.url)
            )

        runtime_config = data.get("runtimeConfig") or {}
        server_config = runtime_config.get("serverRuntimeConfig") if isinstance(runtime_config, dict) else None
        if server_config:
            findings.append(
                self.finding(
                    asset=asset,
                    category=Category.EXPOSURE,
                    title="Next.js serverRuntimeConfig exposed to the browser",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    start=match.start(1),
                    end=match.start(1) + 200,
                    value=str(server_config)[:200],
                    detail="Server-only runtime configuration is present in __NEXT_DATA__.",
                    remediation="Move server-only values out of runtimeConfig; use env vars read at request time.",
                    tags=["nextjs", "config"],
                )
            )

        env_keys = _collect_env_keys(data)
        if env_keys:
            findings.append(
                self.finding(
                    asset=asset,
                    category=Category.EXPOSURE,
                    title="Environment variables embedded in __NEXT_DATA__",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    start=match.start(1),
                    end=match.start(1) + 200,
                    value=", ".join(sorted(env_keys)[:20]),
                    detail=(
                        "{} environment variable name(s) are serialised into the page payload. "
                        "Anything named here is readable by any visitor.".format(len(env_keys))
                    ),
                    remediation="Only expose values that are genuinely public (NEXT_PUBLIC_*) and audit each one.",
                    tags=["nextjs", "config"],
                )
            )

    def _services(self, asset: Asset, results) -> None:
        haystack = asset.content if asset.size <= 600_000 else asset.content[:600_000]
        for host_fragment, (name, category) in SERVICE_HOSTS.items():
            if host_fragment in haystack:
                results.add_service(Service(name, host_fragment, category))

    # -- post-processing ------------------------------------------------------ #
    def check_outdated(self, asset: Asset) -> List[Finding]:
        """Run once at the end, over the aggregated technology list."""
        findings: List[Finding] = []
        for name, minimum, severity, detail in _OUTDATED_RULES:
            tech = self.context.results.technologies.get(name)
            if tech is None or not tech.version:
                continue
            parsed = _parse_version(tech.version)
            if parsed is None:
                continue
            if parsed >= minimum:
                continue
            findings.append(
                self.finding(
                    asset=asset,
                    category=Category.VULNERABILITY,
                    title="Outdated component: {} {}".format(name, tech.version),
                    severity=severity,
                    confidence=Confidence.FIRM,
                    start=0,
                    end=0,
                    value="{} {}".format(name, tech.version),
                    detail=detail,
                    remediation="Upgrade to {} or later.".format(".".join(str(p) for p in minimum)),
                    evidence={"detected": tech.version, "evidence": tech.evidence},
                    tags=["outdated", "dependency"],
                )
            )
        return findings


def _collect_env_keys(node, depth: int = 0) -> List[str]:
    """Walk a JSON blob looking for env-looking keys."""
    found: List[str] = []
    if depth > 6:
        return found
    if isinstance(node, dict):
        for key, value in node.items():
            if re.match(r"^(?:NEXT_PUBLIC_|REACT_APP_|VUE_APP_|VITE_|NUXT_|GATSBY_)\w+$", str(key)):
                found.append(str(key))
            elif str(key).lower() in ("env", "publicruntimeconfig", "environment"):
                if isinstance(value, dict):
                    found.extend(str(k) for k in value.keys())
            found.extend(_collect_env_keys(value, depth + 1))
    elif isinstance(node, list):
        for item in node[:200]:
            found.extend(_collect_env_keys(item, depth + 1))
    return found
