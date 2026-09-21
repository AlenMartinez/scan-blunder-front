"""Vulnerability and bad-practice detection."""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

from scanner.core.detector.base import BaseDetector
from scanner.core.filters import (
    contains_html,
    is_vendor_bundle,
    looks_like_prose,
)
from scanner.core.lexer import StringLiteral, iter_string_literals, strip_comments
from scanner.core.models import Asset, Category, Confidence, Finding, Severity
from scanner.core.patterns.vulns import (
    MISC_VULN_RULES,
    ORM_PATTERNS,
    SQL_CORROBORATION,
    SQL_INTERPOLATION,
    SQL_STATEMENTS,
    SQL_STOPWORD_TARGETS,
    XSS_SINKS,
    XSS_TAINT_SOURCES,
)

_IDENT_CLEAN = re.compile(r"[`\"'\[\]\s]")
_VALID_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)?$")


class SQLDetector(BaseDetector):
    """Finds real SQL shipped to the browser, and nothing else.

    A candidate has to clear five gates before it is reported. Each gate exists
    because of a specific class of false positive seen in the wild:

    1. it must live in a string literal inside a code region  (kills body copy)
    2. the table target must be a syntactically valid identifier (kills `FROM our`)
    3. that identifier must not be a common word            (kills marketing copy)
    4. the statement needs a second SQL token or terminator (kills "update X set" prose)
    5. the excerpt must not contain HTML markup             (kills templates)
    """

    name = "sql"

    def detect(self, asset: Asset) -> Iterable[Finding]:
        findings: List[Finding] = []
        if is_vendor_bundle(asset.url):
            return findings

        for offset, source in asset.code_regions():
            for literal in iter_string_literals(source, base_offset=offset):
                finding = self._inspect_literal(asset, literal)
                if finding is not None:
                    findings.append(finding)

            findings.extend(self._orm_usage(asset, source, offset))
        return findings

    def _inspect_literal(self, asset: Asset, literal: StringLiteral) -> Optional[Finding]:
        text = literal.value
        if len(text) < 14 or len(text) > 4000:
            return None

        upper = text.upper()
        if not any(verb in upper for verb in ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "UNION")):
            return None

        for verb, pattern in SQL_STATEMENTS:
            match = pattern.search(text)
            if match is None:
                continue

            # Gate 2 + 3: the statement's target must be a real identifier.
            target = _IDENT_CLEAN.sub("", match.groupdict().get("target") or "")
            if verb not in ("UNION",):
                if not target or not _VALID_TABLE.match(target):
                    continue
                if target.split(".")[0].lower() in SQL_STOPWORD_TARGETS:
                    continue

            # Gate 4: a lone "SELECT x FROM y" is not enough; real queries carry
            # a clause, a bind parameter or a terminator.
            if not SQL_CORROBORATION.search(text):
                continue

            # Gate 5: markup means this is a template, not a query.
            if contains_html(text) or looks_like_prose(text):
                continue

            interpolation = SQL_INTERPOLATION.search(text)
            # A template literal with ${...} inside the SQL, or string
            # concatenation, means user input is being pasted into the query.
            if interpolation or literal.interpolated:
                severity = Severity.CRITICAL
                title = "SQL injection: query built by concatenation in the front-end"
                detail = (
                    "A SQL statement is assembled from interpolated values in client-side "
                    "code. Whatever produces those values is attacker controlled, so the "
                    "query is injectable and the database is reachable from the browser."
                )
                tags = ["sqli", "injection", "database"]
            else:
                severity = Severity.HIGH
                title = "Raw SQL statement in front-end code"
                detail = (
                    "A complete SQL statement is shipped to the browser. This exposes the "
                    "schema and usually means the database is queried from the client."
                )
                tags = ["sql", "database"]

            evidence = {
                "statement": verb,
                "target": target or "-",
                "query": text[:300],
            }
            if interpolation:
                evidence["interpolation"] = interpolation.group(0)[:80]

            return self.finding(
                asset=asset,
                category=Category.VULNERABILITY,
                title=title,
                severity=severity,
                confidence=Confidence.FIRM,
                start=literal.start,
                end=literal.end,
                value=re.sub(r"\s+", " ", text).strip()[:160],
                detail=detail,
                remediation=(
                    "Move the query behind an API endpoint and use parameterised "
                    "statements. The browser must never hold SQL or database credentials."
                ),
                evidence=evidence,
                tags=tags,
            )
        return None

    def _orm_usage(self, asset: Asset, source: str, offset: int) -> List[Finding]:
        findings: List[Finding] = []
        code = strip_comments(source)
        for name, pattern in ORM_PATTERNS:
            for match in pattern.finditer(code):
                findings.append(
                    self.finding(
                        asset=asset,
                        category=Category.VULNERABILITY,
                        title=name,
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        start=offset + match.start(),
                        end=offset + match.end(),
                        value=match.group(0)[:120],
                        detail=(
                            "Database-layer code appears in a client-side bundle. Either the "
                            "server bundle leaked into the browser build, or the database is "
                            "being queried directly from the client."
                        ),
                        remediation=(
                            "Keep data-access code in server-only modules and verify the "
                            "bundler is not including them in the client chunk."
                        ),
                        tags=["orm", "database"],
                    )
                )
        return findings


class XSSDetector(BaseDetector):
    """DOM XSS sinks, scored by whether tainted input reaches them."""

    name = "xss"

    def detect(self, asset: Asset) -> Iterable[Finding]:
        findings: List[Finding] = []
        if is_vendor_bundle(asset.url):
            return findings

        for offset, source in asset.code_regions():
            code = strip_comments(source)
            for name, pattern, base_severity in XSS_SINKS:
                for match in pattern.finditer(code):
                    window = code[match.start(): min(len(code), match.end() + 200)]
                    tainted = XSS_TAINT_SOURCES.search(window)

                    severity = base_severity
                    confidence = Confidence.TENTATIVE
                    detail = "An unsafe DOM sink is used."
                    if tainted:
                        severity = _escalate(base_severity)
                        confidence = Confidence.FIRM
                        detail = (
                            "An unsafe DOM sink is fed from a source the user controls "
                            "(`{}`), which is the standard DOM-XSS shape.".format(
                                tainted.group(0)[:60]
                            )
                        )

                    findings.append(
                        self.finding(
                            asset=asset,
                            category=Category.VULNERABILITY,
                            title="DOM XSS sink: {}".format(name),
                            severity=severity,
                            confidence=confidence,
                            start=offset + match.start(),
                            end=offset + match.end(),
                            value=match.group(0)[:100],
                            detail=detail,
                            remediation=(
                                "Render untrusted values as text, or sanitise with DOMPurify "
                                "before inserting markup."
                            ),
                            evidence={"taint_source": tainted.group(0)[:60] if tainted else ""},
                            tags=["xss", "dom"],
                        )
                    )
        return findings


class MiscVulnDetector(BaseDetector):
    """The remaining rule-driven checks."""

    name = "misc"

    def detect(self, asset: Asset) -> Iterable[Finding]:
        findings: List[Finding] = []
        vendor = is_vendor_bundle(asset.url)

        for rule in MISC_VULN_RULES:
            if vendor and rule.severity in (Severity.LOW, Severity.INFO):
                continue

            if rule.whole_document:
                targets: List[Tuple[int, str]] = [(0, asset.content)]
            else:
                targets = asset.code_regions()

            for offset, source in targets:
                for match in rule.pattern.finditer(source):
                    # Rules built from alternates leave the unused groups empty,
                    # so take the first one that actually captured something.
                    captured = next((g for g in match.groups() if g), None)
                    value = (captured or match.group(0))[:160]
                    if rule.name == "Internal / private host reference" and _is_benign_ip(value):
                        continue
                    if rule.name == "GraphQL query in client" and contains_html(match.group(0)):
                        continue
                    findings.append(
                        self.finding(
                            asset=asset,
                            category=Category.VULNERABILITY,
                            title=rule.name,
                            severity=rule.severity,
                            confidence=Confidence.FIRM,
                            start=offset + match.start(),
                            end=offset + match.end(),
                            value=value,
                            detail=rule.detail,
                            remediation=rule.remediation,
                            tags=list(rule.tags),
                        )
                    )
        return findings


_SEVERITY_LADDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

#: Version-number strings that the private-host regex picks up out of context.
_BENIGN_IP = re.compile(r"^(?:0\.0\.0\.0|10\.0\.0\.0|192\.168\.0\.0|172\.16\.0\.0)$")


def _escalate(severity: str) -> str:
    try:
        index = _SEVERITY_LADDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_LADDER[min(index + 1, len(_SEVERITY_LADDER) - 1)]


def _is_benign_ip(value: str) -> bool:
    return bool(_BENIGN_IP.match(value.strip()))
