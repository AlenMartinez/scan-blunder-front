"""Response-header security checks (run once, on the main document)."""
from __future__ import annotations

import re
from typing import Iterable, List

from scanner.core.detector.base import BaseDetector
from scanner.core.models import Asset, Category, Confidence, Finding, Severity
from scanner.core.patterns.technologies import SECURITY_HEADERS


class HeaderDetector(BaseDetector):
    name = "headers"

    def detect(self, asset: Asset) -> Iterable[Finding]:
        findings: List[Finding] = []
        if asset.url != self.context.base_url or not asset.headers:
            return findings

        lowered = {k.lower(): v for k, v in asset.headers.items()}
        csp = lowered.get("content-security-policy", "")

        for header, severity, detail, remediation in SECURITY_HEADERS:
            if header in lowered:
                continue
            # frame-ancestors in a CSP replaces X-Frame-Options.
            if header == "x-frame-options" and "frame-ancestors" in csp:
                continue
            findings.append(
                self._header_finding(
                    asset,
                    "Missing security header: {}".format(header),
                    severity,
                    header,
                    detail,
                    remediation,
                )
            )

        findings.extend(self._csp_quality(asset, csp))
        findings.extend(self._cors(asset, lowered))
        findings.extend(self._cookies(asset, lowered))
        return findings

    # -- individual checks ------------------------------------------------------ #
    def _csp_quality(self, asset: Asset, csp: str) -> List[Finding]:
        if not csp:
            return []
        problems = []
        if "'unsafe-inline'" in csp:
            problems.append("`'unsafe-inline'` allows inline scripts, defeating most of the XSS protection")
        if "'unsafe-eval'" in csp:
            problems.append("`'unsafe-eval'` permits eval()")
        if re.search(r"(?:script-src|default-src)[^;]*\*(?!\.)", csp):
            problems.append("a wildcard source is allowed for scripts")
        if "data:" in csp and "script-src" in csp:
            problems.append("`data:` URIs are allowed as a script source")
        if not problems:
            return []
        return [
            self._header_finding(
                asset,
                "Weak Content-Security-Policy",
                Severity.MEDIUM,
                "content-security-policy",
                "The CSP is present but permissive: " + "; ".join(problems) + ".",
                "Remove unsafe-inline/unsafe-eval and use nonces or hashes for inline scripts.",
                value=csp[:300],
            )
        ]

    def _cors(self, asset: Asset, headers) -> List[Finding]:
        origin = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "").lower()
        if not origin:
            return []
        if origin.strip() == "*" and credentials == "true":
            return [
                self._header_finding(
                    asset,
                    "Dangerous CORS configuration",
                    Severity.HIGH,
                    "access-control-allow-origin",
                    "The server sends a wildcard origin together with "
                    "`Access-Control-Allow-Credentials: true`.",
                    "Echo a validated origin from an allow-list instead of `*` when credentials are used.",
                    value="{} / credentials: {}".format(origin, credentials),
                )
            ]
        if origin.strip() == "*":
            return [
                self._header_finding(
                    asset,
                    "Wildcard CORS origin",
                    Severity.LOW,
                    "access-control-allow-origin",
                    "Any origin may read responses from this endpoint.",
                    "Restrict the allowed origins if the responses are not fully public.",
                    value=origin[:120],
                )
            ]
        return []

    def _cookies(self, asset: Asset, headers) -> List[Finding]:
        raw = headers.get("set-cookie", "")
        if not raw:
            return []
        findings: List[Finding] = []
        for cookie in re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", raw):
            name = cookie.split("=", 1)[0].strip()
            lowered = cookie.lower()
            missing = []
            session_like = bool(
                re.search(r"(?i)sess|auth|token|jwt|login|remember|sid", name)
            )
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "secure" not in lowered:
                missing.append("Secure")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if not missing:
                continue
            findings.append(
                self._header_finding(
                    asset,
                    "Cookie `{}` missing {}".format(name, "/".join(missing)),
                    Severity.MEDIUM if session_like else Severity.LOW,
                    "set-cookie",
                    "The cookie is set without {}.{}".format(
                        ", ".join(missing),
                        " It looks like a session cookie, so JavaScript can steal it via XSS."
                        if session_like and "HttpOnly" in missing else "",
                    ),
                    "Set HttpOnly, Secure and SameSite on every authentication cookie.",
                    value=cookie[:120],
                )
            )
        return findings

    def _header_finding(self, asset, title, severity, header, detail, remediation, value="") -> Finding:
        return self.finding(
            asset=asset,
            category=Category.HEADER,
            title=title,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            start=0,
            end=0,
            value=value or header,
            detail=detail,
            remediation=remediation,
            tags=["headers", "hardening"],
        )
