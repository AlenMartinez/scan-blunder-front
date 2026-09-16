"""Endpoint, backend and URL inventory."""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from scanner.core.detector.base import BaseDetector
from scanner.core.lexer import iter_string_literals
from scanner.core.models import (
    Asset,
    Category,
    Confidence,
    Endpoint,
    Finding,
    Severity,
)
from scanner.core.patterns.endpoints import (
    ABSOLUTE_URL_RE,
    API_PATH_RE,
    EMAIL_RE,
    FETCH_CALL_RE,
    GENERIC_API_PATH_RE,
    METHOD_OPTION_RE,
    METHOD_URL_RE,
    NON_BACKEND_HOST_HINTS,
    PROTOCOL_RELATIVE_RE,
    ROUTE_DECLARATION_RE,
    STATIC_EXTENSIONS,
    WEBSOCKET_RE,
)

_TRAILING_JUNK = re.compile(r"[),;:.'\"\\]+$")

#: A URL lifted out of a template literal carries an interpolation, whether it
#: was cut short (`/v2/vitals?dsn=${a`) or complete (`?dsn=${a}`). Neither is a
#: real address, so the URL is truncated at the first `${`.
_INTERPOLATION = re.compile(r"\$\{[\s\S]*$")


class EndpointDetector(BaseDetector):
    """Builds the map of every URL, API route and backend the front-end talks to."""

    name = "endpoints"

    def detect(self, asset: Asset) -> Iterable[Finding]:
        findings: List[Finding] = []
        results = self.context.results

        self._absolute_urls(asset, results)
        self._api_calls(asset, results)
        self._routes(asset, results)
        self._emails(asset, results)

        return findings

    # -- URL harvesting -------------------------------------------------------- #
    def _absolute_urls(self, asset: Asset, results) -> None:
        for match in ABSOLUTE_URL_RE.finditer(asset.content):
            url = _TRAILING_JUNK.sub("", match.group(0))
            self._record_url(asset, results, url)

        for match in PROTOCOL_RELATIVE_RE.finditer(asset.content):
            self._record_url(asset, results, "https://" + _TRAILING_JUNK.sub("", match.group(1)))

        for match in WEBSOCKET_RE.finditer(asset.content):
            url = _TRAILING_JUNK.sub("", match.group(0))
            results.add_endpoint(
                Endpoint(url=url, method="WS", kind="websocket", source=asset.url,
                         scope=self._scope(url))
            )

    def _record_url(self, asset: Asset, results, url: str) -> None:
        url = _clean_url(url)
        if not url or len(url) > 500:
            return
        scope = self._scope(url)
        results.urls.setdefault(url, scope)

        path = urlparse(url).path.lower()
        if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
            return
        if self._is_api_like(url):
            results.add_endpoint(
                Endpoint(url=url, method="GET", kind=self._kind(url), source=asset.url,
                         scope=scope, inferred=True)
            )

    # -- call sites ------------------------------------------------------------ #
    def _api_calls(self, asset: Asset, results) -> None:
        """Pull (method, url) pairs out of real call sites, not prose."""
        for offset, source in asset.code_regions():
            for match in FETCH_CALL_RE.finditer(source):
                raw_url = match.group("url").strip()
                verb = (match.group("verb") or "").upper()
                inferred = False
                if not verb:
                    # look ahead for `{ method: "POST" }` in the same call
                    window = source[match.end(): match.end() + 240]
                    option = METHOD_OPTION_RE.search(window)
                    if option:
                        verb = option.group("verb").upper()
                    else:
                        verb, inferred = "GET", True
                self._record_call(asset, results, raw_url, verb, inferred=inferred)

            for match in METHOD_URL_RE.finditer(source):
                self._record_call(asset, results, match.group(2), match.group(1).upper())

            # Bare API-looking paths inside string literals.
            for literal in iter_string_literals(source, base_offset=offset):
                value = literal.value.strip()
                if not value.startswith("/") or len(value) > 200:
                    continue
                if API_PATH_RE.match(value) or GENERIC_API_PATH_RE.match(value):
                    self._record_call(asset, results, value, "GET", inferred=True)

    def _record_call(self, asset: Asset, results, raw_url: str, verb: str,
                     inferred: bool = False) -> None:
        if not raw_url or len(raw_url) > 400:
            return
        if raw_url.startswith(("data:", "blob:", "mailto:", "tel:", "javascript:", "#")):
            return

        if raw_url.startswith(("http://", "https://")):
            url = raw_url
        elif raw_url.startswith("//"):
            url = "https:" + raw_url
        elif raw_url.startswith("/"):
            url = urljoin(self.context.base_url, raw_url)
        else:
            return  # relative fragments without context are too noisy to resolve

        url = _clean_url(url)
        if not url:
            return
        path = urlparse(url).path.lower()
        if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
            return

        results.add_endpoint(
            Endpoint(url=url, method=verb or "GET", kind=self._kind(url),
                     source=asset.url, scope=self._scope(url), inferred=inferred)
        )
        results.urls.setdefault(url, self._scope(url))

    def _routes(self, asset: Asset, results) -> None:
        """Client-side router tables describe the whole page map of an SPA."""
        for offset, source in asset.code_regions():
            for match in ROUTE_DECLARATION_RE.finditer(source):
                path = match.group("path")
                if not path or len(path) > 160:
                    continue
                url = urljoin(self.context.base_url, path)
                results.add_endpoint(
                    Endpoint(url=url, method="GET", kind="page", source=asset.url,
                             scope=self._scope(url), inferred=True)
                )

    def _emails(self, asset: Asset, results) -> None:
        for match in EMAIL_RE.finditer(asset.content):
            email = match.group(0)
            if email.lower().endswith((".png", ".jpg", ".gif", ".js", ".css")):
                continue
            if len(results.emails) < 200:
                results.emails.append(email)

    # -- helpers ---------------------------------------------------------------- #
    def _scope(self, url: str) -> str:
        host = (urlparse(url).hostname or "").lower()
        base = self.context.domain.lower()
        if not host:
            return "same-origin"
        if host == base:
            return "same-origin"
        registrable = ".".join(base.split(".")[-2:]) if base.count(".") >= 1 else base
        if host.endswith("." + registrable) or host == registrable:
            return "subdomain"
        return "external"

    @staticmethod
    def _kind(url: str) -> str:
        path = urlparse(url).path.lower()
        if "graphql" in path or path.endswith("/gql"):
            return "graphql"
        if API_PATH_RE.match(path) or GENERIC_API_PATH_RE.match(path):
            return "api"
        return "page"

    def _is_api_like(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if any(hint in host for hint in NON_BACKEND_HOST_HINTS):
            return False
        path = parsed.path
        if not path or path == "/":
            return False
        return bool(API_PATH_RE.match(path) or GENERIC_API_PATH_RE.match(path))


def summarize_backends(results, base_url: str) -> Optional[Finding]:
    """Aggregate finding: which hosts actually serve this application's data."""
    from collections import Counter

    counter: Counter = Counter()
    for endpoint in results.endpoints:
        if endpoint.kind not in ("api", "graphql", "websocket"):
            continue
        host = urlparse(endpoint.url).hostname
        if not host:
            continue
        if any(hint in host.lower() for hint in NON_BACKEND_HOST_HINTS):
            continue
        counter[host] += 1

    if not counter:
        return None

    listing = ", ".join(
        "{} ({} endpoints)".format(host, count) for host, count in counter.most_common(15)
    )
    external = [h for h in counter if EndpointDetectorScope(results).is_external(h)]

    return Finding(
        category=Category.EXPOSURE,
        title="Backend hosts discovered",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        location=_summary_location(base_url),
        value=listing[:400],
        detail=(
            "The front-end calls {} distinct backend host(s){}. Each one is part of the "
            "attack surface and should be tested independently.".format(
                len(counter),
                "; {} of them are third-party".format(len(external)) if external else "",
            )
        ),
        remediation="Review authentication and CORS policy on every host listed here.",
        evidence={"hosts": listing[:1000]},
        tags=["recon", "backend"],
    )


class EndpointDetectorScope:
    """Tiny helper so `summarize_backends` can classify hosts without a context."""

    def __init__(self, results):
        self.domain = results.domain.lower()

    def is_external(self, host: str) -> bool:
        host = host.lower()
        if host == self.domain:
            return False
        registrable = ".".join(self.domain.split(".")[-2:])
        return not (host.endswith("." + registrable) or host == registrable)


def _clean_url(url: str) -> str:
    """Trim a URL that was cut off inside a template interpolation."""
    cleaned = _INTERPOLATION.sub("", url).rstrip("?&=/")
    return cleaned if cleaned.count("/") >= 2 else ""


def _summary_location(base_url: str):
    from scanner.core.models import Location

    return Location(url=base_url, line=0, column=0, snippet="")
