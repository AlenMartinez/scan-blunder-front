"""Secret detection rules.

Each rule carries its own severity, minimum entropy and optional structural
validator, because "an AWS key id" and "a variable called token" deserve very
different treatment. Rules are grouped in two families:

* HIGH_SIGNAL: vendor-specific formats. The shape alone is strong evidence.
* GENERIC:     keyword-driven `name = "value"` assignments. These are the ones
               that historically produced the noise, so they only survive when
               the value passes the entropy and placeholder filters.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from scanner.core.models import Severity


@dataclass
class SecretRule:
    name: str
    pattern: "re.Pattern"
    severity: str = Severity.HIGH
    group: int = 0
    #: minimum entropy for the captured value (0 disables the check)
    min_entropy: float = 0.0
    min_length: int = 0
    #: extra callable(value) -> bool that must pass for the finding to be kept
    validator: Optional[Callable[[str], bool]] = None
    detail: str = ""
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    #: True when the credential is designed to be public (still worth listing)
    public_by_design: bool = False


def _rx(pattern: str, flags: int = 0) -> "re.Pattern":
    return re.compile(pattern, flags)


_ROTATE = "Revoke and rotate this credential, then serve it from a backend proxy instead of the bundle."

# --------------------------------------------------------------------------- #
# Vendor-specific formats
# --------------------------------------------------------------------------- #

HIGH_SIGNAL_RULES: List[SecretRule] = [
    SecretRule(
        name="AWS Access Key ID",
        pattern=_rx(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        group=1,
        severity=Severity.CRITICAL,
        detail="An AWS access key id shipped to the browser.",
        remediation=_ROTATE,
        tags=["aws", "cloud"],
    ),
    SecretRule(
        name="AWS Secret Access Key",
        pattern=_rx(
            r"(?i)aws[_\-.]?(?:secret|private)[_\-.]?(?:access[_\-.]?)?key\s*[:=]\s*"
            r"[\"']([A-Za-z0-9/+=]{40})[\"']"
        ),
        group=1,
        severity=Severity.CRITICAL,
        min_entropy=4.0,
        remediation=_ROTATE,
        tags=["aws", "cloud"],
    ),
    SecretRule(
        name="Google API Key",
        pattern=_rx(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        group=1,
        severity=Severity.MEDIUM,
        detail=(
            "Google API keys are meant to reach the browser, but an unrestricted "
            "key can be reused by anyone and billed to you."
        ),
        remediation=(
            "Restrict the key by HTTP referrer and by API in the Google Cloud console, "
            "and set a quota cap."
        ),
        tags=["google"],
        public_by_design=True,
    ),
    SecretRule(
        name="Google OAuth Client Secret",
        pattern=_rx(r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["google", "oauth"],
    ),
    SecretRule(
        name="Google Service Account Key",
        pattern=_rx(r"\"type\"\s*:\s*\"(service_account)\""),
        group=1,
        severity=Severity.CRITICAL,
        detail="A Google service-account JSON key appears to be embedded.",
        remediation=_ROTATE,
        tags=["google", "cloud"],
    ),
    SecretRule(
        name="Firebase Cloud Messaging Server Key",
        pattern=_rx(r"\b(AAAA[A-Za-z0-9_\-]{7}:APA91b[A-Za-z0-9_\-]{100,})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["firebase", "google"],
    ),
    SecretRule(
        name="Stripe Secret Key",
        pattern=_rx(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{10,99})\b"),
        group=1,
        severity=Severity.CRITICAL,
        detail="A Stripe *secret* key grants full API access to the account.",
        remediation=_ROTATE,
        tags=["stripe", "payments"],
    ),
    SecretRule(
        name="Stripe Publishable Key",
        pattern=_rx(r"\b(pk_(?:live|test)_[0-9a-zA-Z]{10,99})\b"),
        group=1,
        severity=Severity.INFO,
        detail="Publishable Stripe key. Expected in the front-end; listed for inventory.",
        tags=["stripe", "payments"],
        public_by_design=True,
    ),
    SecretRule(
        name="GitHub Token",
        pattern=_rx(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,255})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["github", "vcs"],
    ),
    SecretRule(
        name="GitLab Token",
        pattern=_rx(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["gitlab", "vcs"],
    ),
    SecretRule(
        name="Slack Token",
        pattern=_rx(r"\b(xox[baprse]-[0-9A-Za-z\-]{10,72})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["slack"],
    ),
    SecretRule(
        name="Slack Webhook",
        pattern=_rx(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_\-/]{20,})"),
        group=1,
        severity=Severity.HIGH,
        remediation="Delete the webhook in Slack; anyone can post to the channel with it.",
        tags=["slack"],
    ),
    SecretRule(
        name="Discord Webhook",
        pattern=_rx(r"(https://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+)"),
        group=1,
        severity=Severity.HIGH,
        tags=["discord"],
    ),
    SecretRule(
        name="Telegram Bot Token",
        pattern=_rx(r"\b(\d{8,12}:AA[A-Za-z0-9_\-]{30,})\b"),
        group=1,
        severity=Severity.HIGH,
        remediation=_ROTATE,
        tags=["telegram"],
    ),
    SecretRule(
        name="SendGrid API Key",
        pattern=_rx(r"\b(SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["email"],
    ),
    SecretRule(
        name="Mailgun API Key",
        pattern=_rx(r"\b(key-[0-9a-f]{32})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["email"],
    ),
    SecretRule(
        name="Mailchimp API Key",
        pattern=_rx(r"\b([0-9a-f]{32}-us[0-9]{1,2})\b"),
        group=1,
        severity=Severity.HIGH,
        remediation=_ROTATE,
        tags=["email"],
    ),
    SecretRule(
        name="Twilio Account SID",
        pattern=_rx(r"\b(AC[0-9a-fA-F]{32})\b"),
        group=1,
        severity=Severity.MEDIUM,
        tags=["twilio"],
    ),
    SecretRule(
        name="Twilio API Key",
        pattern=_rx(r"\b(SK[0-9a-fA-F]{32})\b"),
        group=1,
        severity=Severity.HIGH,
        remediation=_ROTATE,
        tags=["twilio"],
    ),
    SecretRule(
        name="OpenAI API Key",
        pattern=_rx(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,200})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["ai"],
    ),
    SecretRule(
        name="Anthropic API Key",
        pattern=_rx(r"\b(sk-ant-[A-Za-z0-9_\-]{20,200})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["ai"],
    ),
    SecretRule(
        name="npm Access Token",
        pattern=_rx(r"\b(npm_[A-Za-z0-9]{36})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["npm", "supply-chain"],
    ),
    SecretRule(
        name="Square Access Token",
        pattern=_rx(r"\b((?:EAAA|sq0atp-)[A-Za-z0-9_\-]{20,60})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["payments"],
    ),
    SecretRule(
        name="PayPal / Braintree Token",
        pattern=_rx(r"\b(access_token\$(?:production|sandbox)\$[A-Za-z0-9]{16,}\$[0-9a-f]{32})\b"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["payments"],
    ),
    SecretRule(
        name="Algolia Admin API Key",
        pattern=_rx(r"(?i)algolia[_\-.]?(?:admin|api)?[_\-.]?key\s*[:=]\s*[\"']([0-9a-f]{32})[\"']"),
        group=1,
        severity=Severity.HIGH,
        min_entropy=3.2,
        detail="Algolia admin keys allow index writes and deletion.",
        remediation="Use a search-only key in the browser and keep the admin key server-side.",
        tags=["algolia", "search"],
    ),
    SecretRule(
        name="Cloudinary Credentials URL",
        pattern=_rx(r"(cloudinary://[0-9]{10,}:[A-Za-z0-9_\-]{10,}@[a-z0-9_\-]+)"),
        group=1,
        severity=Severity.CRITICAL,
        remediation=_ROTATE,
        tags=["media"],
    ),
    SecretRule(
        name="Database Connection String",
        pattern=_rx(
            r"\b((?:postgres(?:ql)?|mysql|mysqlx|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|clickhouse)"
            r"://[^\s\"'<>`]{0,64}:[^\s\"'<>`@]{1,128}@[^\s\"'<>`/]{3,})"
        ),
        group=1,
        severity=Severity.CRITICAL,
        detail="A database URI including credentials is present in client-side code.",
        remediation="Remove it from the bundle, rotate the password and firewall the database.",
        tags=["database"],
    ),
    SecretRule(
        name="Private Key (PEM)",
        pattern=_rx(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"),
        group=1,
        severity=Severity.CRITICAL,
        detail="A private key block is embedded in a client-side file.",
        remediation="Rotate the key pair immediately and remove the key from the build.",
        tags=["crypto"],
    ),
    SecretRule(
        name="Basic Auth in URL",
        pattern=_rx(r"\b(https?://[^\s:@\"'/]{1,64}:[^\s:@\"'/]{1,64}@[\w.\-]+)"),
        group=1,
        severity=Severity.CRITICAL,
        detail="Credentials embedded in a URL.",
        remediation=_ROTATE,
        tags=["credentials"],
    ),
    SecretRule(
        name="Authorization Header (Basic)",
        pattern=_rx(r"(?i)\b(?:authorization|auth)\s*[:=]\s*[\"']Basic\s+([A-Za-z0-9+/=]{16,})[\"']"),
        group=1,
        severity=Severity.CRITICAL,
        min_entropy=3.0,
        remediation=_ROTATE,
        tags=["credentials"],
    ),
    SecretRule(
        name="Authorization Header (Bearer)",
        pattern=_rx(r"(?i)\b(?:authorization|auth)\s*[:=]\s*[\"']Bearer\s+([A-Za-z0-9._\-+/=]{20,})[\"']"),
        group=1,
        severity=Severity.HIGH,
        min_entropy=3.2,
        remediation=_ROTATE,
        tags=["credentials"],
    ),
    SecretRule(
        name="JSON Web Token (JWT)",
        pattern=_rx(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-+/=]{0,512})?)"),
        group=1,
        severity=Severity.HIGH,
        detail="A JSON Web Token is hardcoded in the delivered source.",
        remediation="Never ship tokens in the bundle; obtain them at runtime and keep them out of source control.",
        tags=["jwt", "auth"],
    ),
    SecretRule(
        name="Supabase Service Role Key",
        pattern=_rx(r"(?i)(service[_\-]?role)"),
        group=1,
        severity=Severity.CRITICAL,
        detail="Reference to a Supabase service-role key, which bypasses row level security.",
        remediation="Use the anon key in the browser; the service-role key must stay on the server.",
        tags=["supabase", "database"],
    ),
    SecretRule(
        name="Firebase Realtime Database URL",
        pattern=_rx(r"(https://[a-z0-9.\-]+\.(?:firebaseio\.com|firebasedatabase\.app))"),
        group=1,
        severity=Severity.LOW,
        detail="Firebase database endpoint. Verify that its security rules are not public.",
        remediation="Check the database rules; a `.read: true` rule exposes all data.",
        tags=["firebase"],
        public_by_design=True,
    ),
    SecretRule(
        name="Hardcoded Password in URL Parameter",
        pattern=_rx(r"(?i)[?&](?:password|passwd|pwd|token|api_?key|secret)=([^\s\"'&<>]{6,})"),
        group=1,
        severity=Severity.HIGH,
        min_entropy=2.8,
        min_length=8,
        remediation="Move the credential out of the query string; URLs leak via logs and Referer.",
        tags=["credentials"],
    ),
]

# --------------------------------------------------------------------------- #
# Generic keyword assignments
# --------------------------------------------------------------------------- #

#: Keys that imply a genuine credential when paired with a high-entropy value.
SENSITIVE_KEY_RE = re.compile(
    r"(?i)^(?:"
    r"(?:[\w\-]*[_\-.])?(?:password|passwd|pwd|passphrase)"
    r"|(?:[\w\-]*[_\-.])?(?:secret|secrets)"
    r"|(?:[\w\-]*[_\-.])?(?:api[_\-.]?key|apikey|api[_\-.]?secret|apisecret)"
    r"|(?:[\w\-]*[_\-.])?(?:access[_\-.]?token|refresh[_\-.]?token|id[_\-.]?token|auth[_\-.]?token|session[_\-.]?token)"
    r"|(?:[\w\-]*[_\-.])?(?:client[_\-.]?secret|app[_\-.]?secret|consumer[_\-.]?secret)"
    r"|(?:[\w\-]*[_\-.])?(?:private[_\-.]?key|signing[_\-.]?key|encryption[_\-.]?key|secret[_\-.]?key)"
    r"|(?:[\w\-]*[_\-.])?(?:credential|credentials)"
    r"|(?:[\w\-]*[_\-.])?(?:auth|authorization|bearer)"
    r"|(?:[\w\-]*[_\-.])?(?:database[_\-.]?url|db[_\-.]?password|conn(?:ection)?[_\-.]?string)"
    r"|(?:[\w\-]*[_\-.])?(?:token)"
    r")$"
)

#: `name = "value"` in JS/JSON/HTML attributes. The capture groups are
#: (key, value) and the value is then put through the full filter chain.
GENERIC_ASSIGNMENT_RE = re.compile(
    r"""(?P<key>[A-Za-z_$][\w$\-.]{1,48})\s*["']?\s*[:=]\s*["'](?P<value>[^"'\r\n]{6,512})["']"""
)

#: Keys whose value is almost always an enum, not a credential. Checked before
#: entropy so `credentials: "same-origin"` never reaches the report.
NON_SECRET_KEYS = {
    "credentials", "mode", "cache", "redirect", "referrerpolicy", "integrity",
    "method", "type", "name", "id", "class", "classname", "style", "role",
    "autocomplete", "placeholder", "label", "title", "alt", "href", "src",
    "rel", "target", "charset", "lang", "dir", "content", "accept",
    "authorizationurl", "tokenurl", "grant_type", "response_type", "scope",
    "token_type", "tokentype", "auth_type", "authtype", "secretname",
    "keyname", "keypath", "tokenname", "passwordfield", "passwordlabel",
    "passwordplaceholder", "tokenendpoint", "credentialsmode",
}

#: Values under this length can never be a meaningful credential.
GENERIC_MIN_LENGTH = 12
GENERIC_MIN_ENTROPY = 3.3

# --------------------------------------------------------------------------- #
# Secrets that only matter in specific storage sinks
# --------------------------------------------------------------------------- #

STORAGE_SINK_RE = re.compile(
    r"(?i)\b(localStorage|sessionStorage)\s*(?:\.\s*setItem\s*\(\s*|\[\s*)"
    r"[\"']([^\"']*(?:token|jwt|auth|secret|password|credential|session|api[_\-]?key)[^\"']*)[\"']"
)

COOKIE_WRITE_RE = re.compile(r"document\s*\.\s*cookie\s*=")
