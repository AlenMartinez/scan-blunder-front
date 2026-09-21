"""Secret detection with an explicit false-positive budget."""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

from scanner.core.detector.base import BaseDetector, redact
from scanner.core.filters import (
    decode_jwt,
    is_hash_like,
    is_human_text,
    is_placeholder,
    is_route_like,
    is_vendor_bundle,
    looks_random,
    shannon_entropy,
)
from scanner.core.lexer import iter_string_literals, preceding_identifier
from scanner.core.models import Asset, Category, Confidence, Finding, Severity
from scanner.core.patterns.secrets import (
    GENERIC_MIN_ENTROPY,
    GENERIC_MIN_LENGTH,
    HIGH_SIGNAL_RULES,
    NON_SECRET_KEYS,
    SENSITIVE_KEY_RE,
    SecretRule,
)

#: JWT payload keys that tell us the token is a real, issued credential.
_JWT_SIGNALS = ("exp", "iat", "sub", "iss", "aud", "nbf", "jti", "role", "scope")


class SecretDetector(BaseDetector):
    name = "secrets"

    def detect(self, asset: Asset) -> Iterable[Finding]:
        findings: List[Finding] = []
        vendor = is_vendor_bundle(asset.url)

        # High-signal vendor formats are scanned over the whole document: an AWS
        # key is an AWS key whether it sits in JS, in a meta tag or in JSON.
        for rule in HIGH_SIGNAL_RULES:
            findings.extend(self._apply_rule(asset, rule, vendor))

        # Generic `key = "value"` assignments only make sense inside code.
        for offset, source in asset.code_regions():
            findings.extend(self._generic_assignments(asset, source, offset, vendor))

        return findings

    # -- high signal rules --------------------------------------------------- #
    def _apply_rule(self, asset: Asset, rule: SecretRule, vendor: bool) -> List[Finding]:
        findings: List[Finding] = []
        for match in rule.pattern.finditer(asset.content):
            try:
                value = match.group(rule.group)
            except IndexError:
                continue
            if not value:
                continue
            value = value.strip()

            if is_placeholder(value):
                continue
            if rule.min_length and len(value) < rule.min_length:
                continue
            if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                continue
            if rule.validator and not rule.validator(value):
                continue

            severity = rule.severity
            confidence = Confidence.FIRM
            detail = rule.detail
            evidence = {}
            tags = list(rule.tags)

            if rule.name == "JSON Web Token (JWT)":
                decoded = self._inspect_jwt(value)
                if decoded is None:
                    continue  # base64 that is not actually a token
                confidence, detail_extra, evidence, severity_override = decoded
                detail = (detail + " " + detail_extra).strip()
                if severity_override:
                    severity = severity_override

            elif rule.name == "Supabase Service Role Key":
                # Only meaningful next to a JWT or a key assignment.
                window = asset.content[max(0, match.start() - 200): match.end() + 200]
                if "eyJ" not in window and not re.search(r"(?i)key|token|secret", window):
                    continue
                confidence = Confidence.FIRM

            elif rule.name in ("AWS Access Key ID", "GitHub Token", "Slack Token",
                               "Stripe Secret Key", "SendGrid API Key",
                               "Google OAuth Client Secret", "npm Access Token"):
                # These formats are self-identifying; the shape is the proof.
                confidence = Confidence.CONFIRMED

            elif rule.name == "Private Key (PEM)":
                confidence = Confidence.CONFIRMED

            if vendor and severity in (Severity.LOW, Severity.INFO):
                continue  # library noise not worth a line in the report

            if rule.public_by_design and "public" not in tags:
                tags.append("public-by-design")

            findings.append(
                self.finding(
                    asset=asset,
                    category=Category.SECRET,
                    title=rule.name,
                    severity=severity,
                    confidence=confidence,
                    start=match.start(rule.group) if rule.group else match.start(),
                    end=match.end(rule.group) if rule.group else match.end(),
                    value=redact(value) if len(value) > 24 else value,
                    detail=detail,
                    remediation=rule.remediation,
                    evidence=evidence,
                    tags=tags,
                )
            )
        return findings

    def _inspect_jwt(self, token: str):
        """Validate and characterise a JWT. Returns None when it is not one."""
        decoded = decode_jwt(token)
        if decoded is None:
            return None
        header, payload = decoded
        if not any(signal in payload for signal in _JWT_SIGNALS):
            return None

        evidence = {
            "alg": str(header.get("alg", "?")),
            "issuer": str(payload.get("iss", ""))[:120],
            "subject": str(payload.get("sub", ""))[:120],
        }
        notes: List[str] = []
        severity_override = None

        role_claims = {
            k: payload[k]
            for k in ("role", "roles", "scope", "scopes", "permissions", "groups")
            if k in payload
        }
        if role_claims:
            evidence["claims"] = str(role_claims)[:200]
            notes.append("Token carries authorization claims: {}.".format(
                ", ".join(sorted(role_claims))
            ))

        if str(payload.get("role", "")).lower() in ("service_role", "admin", "superuser"):
            severity_override = Severity.CRITICAL
            notes.append("The token holds a privileged role.")

        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            import time

            if exp < time.time():
                notes.append("The token is expired.")
                severity_override = severity_override or Severity.LOW
            else:
                notes.append("The token is still valid.")
        else:
            notes.append("The token has no expiry claim.")

        if header.get("alg") in ("none", "None", "NONE"):
            severity_override = Severity.CRITICAL
            notes.append("Algorithm is `none`: the signature is not verified.")

        return Confidence.CONFIRMED, " ".join(notes), evidence, severity_override

    # -- generic assignments -------------------------------------------------- #
    def _generic_assignments(
        self, asset: Asset, source: str, offset: int, vendor: bool
    ) -> List[Finding]:
        """`apiKey: "…"` style hits, filtered hard.

        The candidate value comes from the JS tokenizer, never from a raw regex.
        A regex that starts matching at an arbitrary offset can pair an opening
        quote with the closing quote of a *different* string, which is how a
        minified parser`s `token=` once yielded a 400-character slab of code as
        "high entropy key material". The tokenizer reads from the start of the
        file, so its quote pairing is correct by construction.

        Order matters below: the cheap, decisive checks run before the entropy
        maths, and each one drops the finding outright rather than downgrading it.
        """
        findings: List[Finding] = []
        if vendor:
            return findings

        for literal in iter_string_literals(source, base_offset=offset):
            value = literal.value
            if len(value) < GENERIC_MIN_LENGTH or len(value) > 512:
                continue
            if "\n" in value or "\r" in value:
                continue

            key = preceding_identifier(source, literal.start - offset)
            if not key:
                continue
            leaf_key = key.split(".")[-1]
            if leaf_key.lower() in NON_SECRET_KEYS:
                continue
            if not SENSITIVE_KEY_RE.match(leaf_key):
                continue
            if is_placeholder(value, key=leaf_key):
                continue

            # A UI string is never a credential: `required_password` holding
            # "La contraseña es obligatoria" is an i18n message, not a secret.
            if is_human_text(value):
                continue
            # `user/change_password` is an API route constant, not a password.
            if is_route_like(value):
                continue
            if is_hash_like(value):
                continue

            # A URL as the value of `database_url` matters; as the value of
            # `token` it is a config endpoint, not a credential.
            if re.match(r"(?i)^(?:https?|wss?|ftp)://", value) and "url" not in leaf_key.lower():
                continue
            if value.startswith(("/", "./", "../")):
                continue
            # Anything carrying JS syntax came from a malformed capture.
            if _CODE_FRAGMENT.search(value):
                continue

            entropy = shannon_entropy(value)
            if looks_random(value, GENERIC_MIN_LENGTH, GENERIC_MIN_ENTROPY):
                confidence, severity = Confidence.FIRM, Severity.HIGH
            elif entropy >= 2.8 and len(value) >= 16:
                confidence, severity = Confidence.TENTATIVE, Severity.MEDIUM
            else:
                continue

            findings.append(
                self.finding(
                    asset=asset,
                    category=Category.SECRET,
                    title="Hardcoded credential ({})".format(leaf_key),
                    severity=severity,
                    confidence=confidence,
                    start=literal.start,
                    end=literal.end,
                    value=redact(value),
                    detail=(
                        "A value assigned to `{}` has {:.1f} bits/char of entropy, "
                        "which is consistent with real key material.".format(key, entropy)
                    ),
                    remediation=(
                        "Move the value to a server-side environment variable and proxy "
                        "the calls that need it."
                    ),
                    evidence={"key": key, "entropy": "{:.2f}".format(entropy)},
                    tags=["generic"],
                )
            )
        return findings


#: Syntax that only appears when a "value" is really a slice of source code.
_CODE_FRAGMENT = re.compile(r"[{};]\s*(?:case|return|function|var|let|const)\b|\)\s*[;{]|=>\s*[{(]")
