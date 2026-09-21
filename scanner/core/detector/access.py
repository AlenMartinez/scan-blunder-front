"""Roles, permissions and access-control exposure."""
from __future__ import annotations

import re
from typing import Iterable, List, Set

from scanner.core.detector.base import BaseDetector
from scanner.core.filters import is_vendor_bundle
from scanner.core.lexer import strip_comments
from scanner.core.models import Asset, Category, Confidence, Finding, Severity
from scanner.core.patterns.access import (
    AUTH_BYPASS_RE,
    IDOR_HINT_RE,
    PERMISSION_CHECK_RE,
    PERMISSION_STRING_RE,
    PERMISSION_VALUE_DENYLIST_RE,
    PRIVILEGED_ROLE_NAMES,
    ROLE_ARRAY_RE,
    ROLE_ASSIGNMENT_RE,
    ROLE_CONSTANT_RE,
    ROLE_VALUE_DENYLIST,
)

_ARRAY_ITEM = re.compile(r"""["']([^"']{2,64})["']""")


class AccessControlDetector(BaseDetector):
    """Extracts the application's role/permission vocabulary from the bundle.

    Knowing that `SUPER_ADMIN`, `billing.export` and `canDeleteUser` exist is
    often more useful than any single finding: it is the privilege map an
    attacker would otherwise have to guess.
    """

    name = "access"

    def detect(self, asset: Asset) -> Iterable[Finding]:
        findings: List[Finding] = []
        if is_vendor_bundle(asset.url):
            return findings

        seen_roles: Set[str] = set()

        for offset, source in asset.code_regions():
            code = strip_comments(source)
            findings.extend(self._roles(asset, code, offset, seen_roles))
            findings.extend(self._role_arrays(asset, code, offset, seen_roles))
            findings.extend(self._constants(asset, code, offset, seen_roles))
            findings.extend(self._permissions(asset, code, offset, seen_roles))
            findings.extend(self._checks(asset, code, offset))
            findings.extend(self._bypasses(asset, code, offset))
            findings.extend(self._idor(asset, code, offset))

        return findings

    # -- roles --------------------------------------------------------------- #
    def _roles(self, asset, code, offset, seen) -> List[Finding]:
        out: List[Finding] = []
        for match in ROLE_ASSIGNMENT_RE.finditer(code):
            key = match.group("key")
            value = match.group("value").strip()
            if not self._is_real_role(key, value):
                continue
            if value.lower() in seen:
                continue
            seen.add(value.lower())
            out.append(self._role_finding(asset, match.start("value") + offset,
                                          match.end("value") + offset, key, value))
        return out

    def _role_arrays(self, asset, code, offset, seen) -> List[Finding]:
        out: List[Finding] = []
        for match in ROLE_ARRAY_RE.finditer(code):
            key = match.group("key")
            items = [i.strip() for i in _ARRAY_ITEM.findall(match.group("value"))]
            items = [i for i in items if self._is_real_role(key, i)]
            if not items:
                continue
            signature = "|".join(sorted(set(i.lower() for i in items)))
            if signature in seen:
                continue
            seen.add(signature)

            privileged = [i for i in items if i.lower().replace("-", "_") in PRIVILEGED_ROLE_NAMES]
            severity = Severity.MEDIUM if privileged else Severity.LOW
            out.append(
                self.finding(
                    asset=asset,
                    category=Category.ACCESS_CONTROL,
                    title="Role/permission catalogue exposed (`{}`)".format(key),
                    severity=severity,
                    confidence=Confidence.FIRM,
                    start=offset + match.start(),
                    end=offset + match.end(),
                    value=", ".join(items[:12]),
                    detail=(
                        "The client bundle enumerates {} value(s) for `{}`{}. This is the "
                        "application's privilege vocabulary.".format(
                            len(items),
                            key,
                            ", including privileged entries ({})".format(", ".join(privileged))
                            if privileged else "",
                        )
                    ),
                    remediation=(
                        "Shipping the catalogue is not a vulnerability by itself, but every "
                        "value listed here must be enforced server-side, not just in the UI."
                    ),
                    evidence={"key": key, "values": ", ".join(items[:40])},
                    tags=["authz", "roles", "recon"],
                )
            )
        return out

    def _constants(self, asset, code, offset, seen) -> List[Finding]:
        out: List[Finding] = []
        for match in ROLE_CONSTANT_RE.finditer(code):
            value = match.group("value")
            if value.lower() in seen:
                continue
            seen.add(value.lower())
            out.append(self._role_finding(asset, offset + match.start("value"),
                                          offset + match.end("value"), "constant", value))
        return out

    def _permissions(self, asset, code, offset, seen) -> List[Finding]:
        out: List[Finding] = []
        for match in PERMISSION_STRING_RE.finditer(code):
            value = match.group("value")
            if PERMISSION_VALUE_DENYLIST_RE.search(value):
                continue
            if value.lower() in seen:
                continue
            seen.add(value.lower())
            out.append(
                self.finding(
                    asset=asset,
                    category=Category.ACCESS_CONTROL,
                    title="Permission identifier exposed",
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    start=offset + match.start("value"),
                    end=offset + match.end("value"),
                    value=value,
                    detail="A granular permission string is present in client code.",
                    remediation="Verify the permission is enforced by the API, not only in the UI.",
                    tags=["authz", "permissions", "recon"],
                )
            )
        return out

    def _checks(self, asset, code, offset) -> List[Finding]:
        out: List[Finding] = []
        seen_calls: Set[str] = set()
        for match in PERMISSION_CHECK_RE.finditer(code):
            fn = match.group("fn")
            args = (match.group("value") or "").strip()
            key = "{}({})".format(fn, args)
            if key in seen_calls:
                continue
            seen_calls.add(key)
            if not args:
                continue  # a bare `can(` with no literal tells us nothing
            out.append(
                self.finding(
                    asset=asset,
                    category=Category.ACCESS_CONTROL,
                    title="Client-side permission check",
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    start=offset + match.start(),
                    end=offset + match.end(),
                    value=key[:120],
                    detail=(
                        "An authorization check runs in the browser. It can be bypassed by "
                        "editing the JavaScript, so the same rule must exist on the server."
                    ),
                    remediation="Mirror every client-side check with server-side enforcement.",
                    tags=["authz", "broken-access-control"],
                )
            )
        return out

    def _bypasses(self, asset, code, offset) -> List[Finding]:
        out: List[Finding] = []
        for name, pattern in AUTH_BYPASS_RE:
            for match in pattern.finditer(code):
                out.append(
                    self.finding(
                        asset=asset,
                        category=Category.ACCESS_CONTROL,
                        title=name,
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        start=offset + match.start(),
                        end=offset + match.end(),
                        value=match.group(0)[:120],
                        detail="Code that weakens or skips authentication is present in the bundle.",
                        remediation="Remove the bypass and make sure it cannot be reached in production.",
                        tags=["authz", "auth-bypass"],
                    )
                )
        return out

    def _idor(self, asset, code, offset) -> List[Finding]:
        out: List[Finding] = []
        seen: Set[str] = set()
        for match in IDOR_HINT_RE.finditer(code):
            value = re.sub(r"\s+", " ", match.group(0))[:140]
            if value in seen:
                continue
            seen.add(value)
            out.append(
                self.finding(
                    asset=asset,
                    category=Category.ACCESS_CONTROL,
                    title="Object id taken from the client in an API call",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    start=offset + match.start(),
                    end=offset + match.end(),
                    value=value,
                    detail=(
                        "A request addresses an object by an id supplied by the browser. If the "
                        "API does not check ownership, this is an IDOR."
                    ),
                    remediation="Authorize every object access against the authenticated user.",
                    tags=["idor", "authz"],
                )
            )
        return out

    # -- helpers -------------------------------------------------------------- #
    @staticmethod
    def _is_real_role(key: str, value: str) -> bool:
        lowered = value.strip().lower()
        if not lowered or len(lowered) > 48:
            return False
        if lowered in ROLE_VALUE_DENYLIST:
            return False
        # `role="button"` in HTML is ARIA, never an application role.
        if key.lower() == "role" and lowered in ROLE_VALUE_DENYLIST:
            return False
        if PERMISSION_VALUE_DENYLIST_RE.search(value):
            return False
        if re.match(r"^[\d.]+$", lowered):
            return False
        if re.search(r"[<>{}()\[\]/\\]", value):
            return False
        return True

    def _role_finding(self, asset, start, end, key, value) -> Finding:
        privileged = value.lower().replace("-", "_").lstrip("role_") in PRIVILEGED_ROLE_NAMES \
            or value.lower().replace("-", "_") in PRIVILEGED_ROLE_NAMES
        return self.finding(
            asset=asset,
            category=Category.ACCESS_CONTROL,
            title="Privileged role name exposed" if privileged else "Role name exposed",
            severity=Severity.MEDIUM if privileged else Severity.LOW,
            confidence=Confidence.FIRM,
            start=start,
            end=end,
            value=value,
            detail=(
                "The bundle references the role `{}`{}.".format(
                    value,
                    " which grants elevated privileges" if privileged else "",
                )
            ),
            remediation="Confirm the API enforces this role; the UI check alone is not protection.",
            evidence={"key": key},
            tags=["authz", "roles", "recon"],
        )
