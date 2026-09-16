"""Core data structures shared by the whole scanner."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Severity / confidence
# --------------------------------------------------------------------------- #

SEVERITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
CONFIDENCE_WEIGHT = {"CONFIRMED": 3, "FIRM": 2, "TENTATIVE": 1}

SEVERITY_COLOR = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    ALL = (CRITICAL, HIGH, MEDIUM, LOW, INFO)

    @staticmethod
    def weight(value: str) -> int:
        return SEVERITY_WEIGHT.get(str(value).upper(), 0)


class Confidence:
    """How sure we are that a finding is real.

    CONFIRMED  structurally validated (a JWT that actually decodes, a key whose
               checksum/charset matches, a file we fetched and read).
    FIRM       strong pattern plus supporting context, survived every filter.
    TENTATIVE  worth a human look but statistically noisy; hidden by default.
    """

    CONFIRMED = "CONFIRMED"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"

    ALL = (CONFIRMED, FIRM, TENTATIVE)

    @staticmethod
    def weight(value: str) -> int:
        return CONFIDENCE_WEIGHT.get(str(value).upper(), 0)


class Category:
    SECRET = "Secret"
    VULNERABILITY = "Vulnerability"
    ACCESS_CONTROL = "Access Control"
    EXPOSURE = "Information Exposure"
    HEADER = "Security Header"
    TECHNOLOGY = "Technology"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


@dataclass
class Location:
    url: str
    line: int = 0
    column: int = 0
    snippet: str = ""

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
        }


@dataclass
class Finding:
    category: str
    title: str
    severity: str
    confidence: str
    location: Location
    value: str = ""
    detail: str = ""
    remediation: str = ""
    evidence: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    also_seen: List[Location] = field(default_factory=list)

    # -- dedupe ------------------------------------------------------------- #
    @property
    def dedupe_key(self) -> Tuple[str, str, str]:
        if self.value:
            return (self.category, self.title, self.value.strip())
        return (self.category, self.title, self.location.snippet.strip()[:120])

    @property
    def occurrences(self) -> int:
        return 1 + len(self.also_seen)

    def merge(self, other: "Finding") -> None:
        """Fold a duplicate hit into this finding as an extra location."""
        if len(self.also_seen) < 50:
            self.also_seen.append(other.location)
        # keep the strongest severity/confidence seen for this value
        if Severity.weight(other.severity) > Severity.weight(self.severity):
            self.severity = other.severity
        if Confidence.weight(other.confidence) > Confidence.weight(self.confidence):
            self.confidence = other.confidence

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "value": self.value,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "tags": self.tags,
            "occurrences": self.occurrences,
            "location": self.location.to_dict(),
            "also_seen": [loc.to_dict() for loc in self.also_seen],
        }


@dataclass
class Technology:
    name: str
    version: str = ""
    category: str = "framework"
    evidence: str = ""
    source: str = ""

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version or "unknown",
            "category": self.category,
            "evidence": self.evidence,
            "source": self.source,
        }


@dataclass
class Service:
    name: str
    host: str
    category: str = "third-party"

    def to_dict(self) -> Dict:
        return {"name": self.name, "host": self.host, "category": self.category}


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    kind: str = "api"          # api | graphql | websocket | page | external
    source: str = ""
    scope: str = "same-origin"  # same-origin | subdomain | external
    #: True when the method was assumed rather than read from a call site
    inferred: bool = False

    @property
    def dedupe_key(self) -> Tuple[str, str]:
        return (self.method.upper(), self.url)

    def to_dict(self) -> Dict:
        return {
            "method": self.method,
            "url": self.url,
            "kind": self.kind,
            "scope": self.scope,
            "source": self.source,
        }


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #

_SCRIPT_BLOCK = re.compile(r"<script\b([^>]*)>([\s\S]*?)</script\s*>", re.I)
_EVENT_HANDLER = re.compile(r"""\son[a-z]{2,20}\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.I)
_JS_URI = re.compile(
    r"""(?:href|src|action|formaction)\s*=\s*(?:"javascript:([^"]*)"|'javascript:([^']*)')""",
    re.I,
)
_HTML_DOC = re.compile(r"<(?:!doctype\s+html|html|head|body|div|span|p|meta|title)\b", re.I)


@dataclass
class Asset:
    """A single fetched resource plus everything we know about it."""

    url: str
    content: str = ""
    content_type: str = ""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    kind: str = "other"  # html | js | json | map | css | other
    referer: str = ""

    _code_regions: Optional[List[Tuple[int, str]]] = field(
        default=None, repr=False, compare=False
    )

    @property
    def is_html(self) -> bool:
        return self.kind == "html"

    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def filename(self) -> str:
        tail = self.url.split("?")[0].rstrip("/").split("/")[-1]
        return tail or self.url

    def code_regions(self) -> List[Tuple[int, str]]:
        """Return (absolute_offset, source_text) chunks that are *actual code*.

        This is the single most important false-positive control in the scanner:
        for an HTML document we only hand detectors the contents of <script>
        blocks, inline event handlers and `javascript:` URIs. Body copy such as
        "Select a plan from our catalog" never reaches the SQL detector, because
        prose is simply not part of any code region.
        """
        if self._code_regions is not None:
            return self._code_regions

        regions: List[Tuple[int, str]] = []
        if self.kind in ("js", "json", "map"):
            regions.append((0, self.content))
        elif self.kind == "html":
            for match in _SCRIPT_BLOCK.finditer(self.content):
                attrs = match.group(1) or ""
                body = match.group(2)
                if not body.strip():
                    continue
                # Ignore templating blocks that are not executable JS/JSON.
                if re.search(r"""type\s*=\s*["']?text/(?:template|html|x-\w+)""", attrs, re.I):
                    continue
                regions.append((match.start(2), body))
            for match in _EVENT_HANDLER.finditer(self.content):
                body = match.group(1) if match.group(1) is not None else match.group(2)
                if body and body.strip():
                    idx = 1 if match.group(1) is not None else 2
                    regions.append((match.start(idx), body))
            for match in _JS_URI.finditer(self.content):
                body = match.group(1) if match.group(1) is not None else match.group(2)
                if body and body.strip():
                    idx = 1 if match.group(1) is not None else 2
                    regions.append((match.start(idx), body))
        else:
            regions.append((0, self.content))

        self._code_regions = regions
        return regions

    def looks_like_html(self) -> bool:
        return bool(_HTML_DOC.search(self.content[:4000]))


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #


@dataclass
class ScanResults:
    target: str
    domain: str
    started_at: str = ""
    finished_at: str = ""
    duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    technologies: Dict[str, Technology] = field(default_factory=dict)
    services: Dict[str, Service] = field(default_factory=dict)
    endpoints: List[Endpoint] = field(default_factory=list)
    urls: Dict[str, str] = field(default_factory=dict)  # url -> scope
    emails: List[str] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    _finding_index: Dict[Tuple[str, str, str], Finding] = field(
        default_factory=dict, repr=False
    )
    _endpoint_index: Dict[Tuple[str, str], Endpoint] = field(
        default_factory=dict, repr=False
    )

    # -- mutation ----------------------------------------------------------- #
    def add_finding(self, finding: Optional[Finding]) -> None:
        if finding is None:
            return
        existing = self._finding_index.get(finding.dedupe_key)
        if existing is not None:
            existing.merge(finding)
            return
        self._finding_index[finding.dedupe_key] = finding
        self.findings.append(finding)

    def add_findings(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            self.add_finding(finding)

    def add_technology(self, tech: Optional[Technology]) -> None:
        if tech is None:
            return
        current = self.technologies.get(tech.name)
        if current is None:
            self.technologies[tech.name] = tech
            return
        # Prefer the entry that actually carries a version.
        if not current.version and tech.version:
            current.version = tech.version
            current.evidence = tech.evidence
            current.source = tech.source

    def add_service(self, service: Optional[Service]) -> None:
        if service is None:
            return
        self.services.setdefault(service.name, service)

    def add_endpoint(self, endpoint: Optional[Endpoint]) -> None:
        if endpoint is None:
            return
        if endpoint.dedupe_key in self._endpoint_index:
            return
        self._endpoint_index[endpoint.dedupe_key] = endpoint
        self.endpoints.append(endpoint)

    def collapse_inferred_endpoints(self) -> None:
        """Drop assumed-GET entries for URLs where a real verb was observed.

        `axios.delete("/api/users/42")` also leaves the bare path "/api/users/42"
        in the bundle, which the literal sweep would otherwise report a second
        time as a GET. Only the observed method is real.
        """
        explicit = {
            endpoint.url
            for endpoint in self.endpoints
            if not endpoint.inferred and endpoint.method.upper() != "GET"
        }
        if not explicit:
            return
        kept = [
            endpoint
            for endpoint in self.endpoints
            if not (endpoint.inferred and endpoint.method.upper() == "GET"
                    and endpoint.url in explicit)
        ]
        self.endpoints[:] = kept
        self._endpoint_index = {e.dedupe_key: e for e in self.endpoints}

    # -- queries ------------------------------------------------------------ #
    def sorted_findings(self, min_confidence: str = Confidence.FIRM) -> List[Finding]:
        threshold = Confidence.weight(min_confidence)
        visible = [
            f for f in self.findings if Confidence.weight(f.confidence) >= threshold
        ]
        return sorted(
            visible,
            key=lambda f: (
                -Severity.weight(f.severity),
                -Confidence.weight(f.confidence),
                f.category,
                f.title,
            ),
        )

    def severity_counts(self, min_confidence: str = Confidence.FIRM) -> Dict[str, int]:
        counts = {s: 0 for s in Severity.ALL}
        for finding in self.sorted_findings(min_confidence):
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def max_severity(self, min_confidence: str = Confidence.FIRM) -> Optional[str]:
        visible = self.sorted_findings(min_confidence)
        return visible[0].severity if visible else None

    def to_dict(self, min_confidence: str = Confidence.TENTATIVE) -> Dict:
        return {
            "target": self.target,
            "domain": self.domain,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration, 2),
            "stats": self.stats,
            "severity_counts": self.severity_counts(min_confidence),
            "technologies": [t.to_dict() for t in self.technologies.values()],
            "services": [s.to_dict() for s in self.services.values()],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "findings": [f.to_dict() for f in self.sorted_findings(min_confidence)],
            "urls": sorted(self.urls.keys()),
            "emails": sorted(set(self.emails)),
            "errors": self.errors,
        }


# --------------------------------------------------------------------------- #
# Small text helpers used by every detector
# --------------------------------------------------------------------------- #


def line_column(content: str, offset: int) -> Tuple[int, int]:
    """1-indexed line and column for an absolute offset."""
    if offset <= 0:
        return 1, 1
    prefix = content[:offset]
    line = prefix.count("\n") + 1
    column = offset - (prefix.rfind("\n") + 1) + 1
    return line, column


def make_snippet(content: str, start: int, end: int, width: int = 110) -> str:
    """A single-line, whitespace-collapsed excerpt centred on the match."""
    pad = max(0, (width - (end - start)) // 2)
    left = max(0, start - pad)
    right = min(len(content), end + pad)
    excerpt = content[left:right]
    excerpt = re.sub(r"\s+", " ", excerpt).strip()
    if left > 0:
        excerpt = "…" + excerpt
    if right < len(content):
        excerpt = excerpt + "…"
    return excerpt[: width + 40]
