"""False-positive control.

Everything a detector wants to report goes through here first. The rules are
deliberately explicit rather than clever, because a scanner that cries wolf is
a scanner nobody reads.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
from typing import Dict, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Placeholder / example values
# --------------------------------------------------------------------------- #

#: Literal values that look like a secret to a regex but never are one.
PLACEHOLDER_VALUES: Set[str] = {
    # generic stand-ins
    "", " ", "-", "--", "n/a", "na", "none", "null", "nil", "undefined", "empty",
    "true", "false", "0", "1", "test", "tests", "testing", "demo", "sample",
    "example", "examples", "dummy", "fake", "mock", "mocked", "placeholder",
    "changeme", "change_me", "todo", "tbd", "xxx", "xxxx", "yyy", "zzz", "foo",
    "bar", "baz", "qwerty", "unknown", "default", "value", "string", "number",
    "boolean", "object", "array", "text", "hidden", "required", "optional",
    # the key name echoed back as the value
    "password", "passwd", "pass", "secret", "secrets", "token", "apikey",
    "api_key", "api-key", "apisecret", "api_secret", "accesstoken",
    "access_token", "refresh_token", "id_token", "clientsecret",
    "client_secret", "client_id", "clientid", "privatekey", "private_key",
    "publickey", "public_key", "credential", "credentials", "authorization",
    "auth", "authtoken", "auth_token", "bearer", "basic", "jwt", "key", "keys",
    "username", "user", "userid", "user_id", "email", "login", "admin",
    "password123", "yourpassword", "your_password", "your-password",
    # fetch/XHR option values that regularly trip naive secret regexes
    "same-origin", "include", "omit", "cors", "no-cors", "navigate",
    "no-store", "no-cache", "force-cache", "only-if-cached", "reload",
    "default-src", "follow", "error", "manual", "application/json",
    # common non-secret enum values
    "on", "off", "yes", "no", "auto", "always", "never", "enabled", "disabled",
    "production", "development", "staging", "local", "localhost",
    "utf-8", "utf8", "get", "post", "put", "patch", "delete", "head", "options",
}

#: Regex shapes that mark a value as a template/placeholder rather than a secret.
_PLACEHOLDER_SHAPES = (
    re.compile(r"^[\s*x•·.\-_=#?]+$", re.I),              # ****, xxxx, ----, ....
    re.compile(r"\$\{[^}]*\}"),                            # ${API_KEY}
    re.compile(r"\{\{[^}]*\}\}"),                          # {{ api_key }}
    re.compile(r"<%[-=]?[\s\S]*?%>"),                      # <%= key %>
    re.compile(r"%\(?[sd]\)?\b"),                          # %s / %(name)s
    re.compile(r"^<[^>]+>$"),                              # <your-key-here>
    re.compile(r"^\[[^\]]+\]$"),                           # [REDACTED]
    re.compile(r"(?i)\b(process\.env|import\.meta\.env|os\.environ)\b"),
    re.compile(r"(?i)^(your|my|the|a|an|some|insert|enter|replace|add|put)[\s_\-]"),
    # "your-key-here", "token goes here" -- but not any value merely ending
    # in those five letters, which would swallow real base64 signatures.
    re.compile(r"(?i)(?:^|[\s_\-])(?:goes[\s_\-]?)?here$"),
    re.compile(r"(?i)^(sk|pk|key|token|secret)[\-_](test|example|sample|xxx|123)"),
    re.compile(r"(?i)^(redacted|removed|hidden|masked|obfuscated|sanitized)$"),
    re.compile(r"^#[0-9a-fA-F]{3,8}$"),                    # CSS colour
    re.compile(r"(?i)^(?:rgba?|hsla?|calc|var|url|translate|matrix)\("),
    re.compile(r"(?i)^\d+(\.\d+)*(px|em|rem|vh|vw|%|s|ms|deg)?$"),  # 1.2.3 / 16px
    re.compile(r"^[/.]{0,2}/[\w\-./]*$"),                  # a bare path
    re.compile(r"(?i)^data:[a-z]+/"),                      # data: URI prefix
)

#: Repeated-run detector: "aaaaaaaaaaaa", "123412341234".
_LOW_VARIETY = re.compile(r"^(.{1,4}?)\1{3,}$")


def is_placeholder(value: str, key: str = "") -> bool:
    """True when `value` is an example/template rather than a live secret."""
    if value is None:
        return True
    stripped = value.strip()
    if not stripped:
        return True
    lowered = stripped.lower()

    if lowered in PLACEHOLDER_VALUES:
        return True
    # `password: "password"`, `apiKey: "apikey"` -- the value echoes the key.
    if key:
        normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
        normalized_value = re.sub(r"[^a-z0-9]", "", lowered)
        if normalized_key and normalized_key == normalized_value:
            return True
    if _LOW_VARIETY.match(stripped):
        return True
    for shape in _PLACEHOLDER_SHAPES:
        if shape.search(stripped):
            return True
    return False


# --------------------------------------------------------------------------- #
# Entropy
# --------------------------------------------------------------------------- #


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = float(len(value))
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


#: `[^\W\d_]` is "any unicode letter". Using [A-Za-z] here meant that
#: "La contrase\u00f1a es obligatoria" did not read as a sentence, and an i18n
#: validation message was reported as a hardcoded credential.
_LETTER = r"[^\W\d_]"
_WORDY = re.compile(r"^{L}+(?:[\s_\-]{L}+)*$".format(L=_LETTER))
_SENTENCE = re.compile(r"{L}{{2,}}\s+{L}{{2,}}\s+{L}{{2,}}".format(L=_LETTER))

#: Three or more letter-words in a row: a phrase, never key material.
_WORD_RUN = re.compile(r"{L}{{2,}}(?:[\s'\u2019]{L}{{2,}}){{2,}}".format(L=_LETTER))

#: `user/change_password`, `api/v1/orders` -- a route constant. Every segment is
#: a lowercase identifier, which is what separates it from base64 key material
#: such as `Xq7Rv2Np/9Lm4Kd8`.
_ROUTE_LIKE = re.compile(
    r"^[a-z][a-z0-9_.\-]*(?:/(?:[a-z0-9_.\-]+|\{[^}]{1,40}\}|:[a-z]\w*))+/?$"
)

#: MIME types look exactly like two-segment routes.
_MIME_LIKE = re.compile(
    r"^(?:application|audio|font|image|message|model|multipart|text|video)/[\w.+\-]+$"
)


def charset_classes(value: str) -> int:
    """How many character classes the value mixes (lower/upper/digit/symbol)."""
    classes = 0
    if re.search(r"[a-z]", value):
        classes += 1
    if re.search(r"[A-Z]", value):
        classes += 1
    if re.search(r"\d", value):
        classes += 1
    if re.search(r"[^\w]", value):
        classes += 1
    return classes


def is_human_text(value: str) -> bool:
    """True when the value reads as a human phrase (a UI string, an i18n message).

    A sentence is never a credential, so this is a hard drop rather than a
    confidence downgrade.
    """
    stripped = value.strip()
    if not stripped or " " not in stripped:
        return False
    if _WORD_RUN.search(stripped):
        return True
    words = re.findall(_LETTER + r"{2,}", stripped)
    if len(words) >= 2 and any(w.lower() in COMMON_WORDS for w in words):
        return True
    return False


def is_route_like(value: str) -> bool:
    """True for path/route constants such as `user/change_password`."""
    stripped = value.strip()
    if not stripped or "/" not in stripped:
        return False
    if _MIME_LIKE.match(stripped):
        return True
    return bool(_ROUTE_LIKE.match(stripped))


def is_mime_type(value: str) -> bool:
    return bool(_MIME_LIKE.match(value.strip()))


def looks_random(value: str, min_length: int = 12, min_entropy: float = 3.0) -> bool:
    """Heuristic: does this look like generated key material?"""
    stripped = value.strip()
    if len(stripped) < min_length:
        return False
    if _SENTENCE.search(stripped) or is_human_text(stripped):
        return False
    if _WORDY.match(stripped) and len(stripped) < 32:
        return False
    if is_route_like(stripped):
        return False
    return shannon_entropy(stripped) >= min_entropy and charset_classes(stripped) >= 2


# --------------------------------------------------------------------------- #
# HTML / prose guards
# --------------------------------------------------------------------------- #

_HTML_TAG = re.compile(r"</?[a-zA-Z][\w:-]*(?:\s[^<>]{0,200})?/?>")
_HTML_ENTITY = re.compile(r"&(?:[a-zA-Z]{2,10}|#\d{2,5});")
_JSX_TAG = re.compile(r"</?[A-Z][\w.]*[\s/>]")


def contains_html(text: str) -> bool:
    """True when the excerpt carries markup, i.e. it is very likely not code."""
    return bool(_HTML_TAG.search(text) or _JSX_TAG.search(text))


def looks_like_prose(text: str, max_word_ratio: float = 0.7) -> bool:
    """True when the text reads like a sentence rather than source code."""
    words = re.findall(r"[A-Za-z']{2,}", text)
    if len(words) < 5:
        return False
    if _HTML_ENTITY.search(text):
        return True
    symbols = len(re.findall(r"[{}();=\[\]<>|&$]", text))
    dictionary_words = sum(1 for w in words if w.lower() in COMMON_WORDS)
    ratio = dictionary_words / float(len(words))
    return ratio >= max_word_ratio and symbols <= 2


#: Small English/Spanish stop-word list. Used to reject "SELECT a plan FROM our
#: catalogue"-style matches where the "table name" is actually an article.
COMMON_WORDS: Set[str] = {
    # english
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "by",
    "at", "from", "as", "is", "are", "be", "was", "were", "this", "that",
    "these", "those", "your", "our", "my", "their", "its", "it", "you", "we",
    "they", "he", "she", "all", "any", "some", "more", "most", "other", "which",
    "what", "where", "when", "who", "how", "why", "here", "there", "please",
    "one", "two", "three", "list", "item", "items", "page", "pages", "below",
    "above", "next", "previous", "click", "select", "choose", "option",
    "options", "available", "up", "down", "out", "over", "under", "again",
    "us", "them", "him", "her", "can", "will", "would", "should", "may",
    "must", "have", "has", "had", "do", "does", "did", "get", "got", "make",
    "made", "see", "seen", "use", "used", "using", "want", "need", "like",
    "new", "old", "best", "free", "now", "today", "time", "day", "year",
    # spanish
    "el", "la", "los", "las", "un", "una", "unos", "unas", "de", "del", "y",
    "o", "en", "con", "por", "para", "que", "se", "su", "sus", "lo", "al",
    "como", "mas", "pero", "sin", "sobre", "entre", "hasta", "desde", "todo",
    "toda", "todos", "todas", "este", "esta", "estos", "estas", "ser", "estar",
    "tiene", "hacer", "puede", "aqui", "alli", "nuestro", "nuestra", "tu",
    "seleccione", "elegir", "elija", "pagina", "inicio", "buscar",
}


# --------------------------------------------------------------------------- #
# Minified / vendor-bundle awareness
# --------------------------------------------------------------------------- #

_VENDOR_HINTS = re.compile(
    r"(?i)/(?:node_modules|vendor|bower_components)/"
    r"|(?:^|/)(?:jquery|bootstrap|lodash|moment|underscore|angular|vue|react"
    r"|polyfill|core-js|regenerator|swiper|slick|gsap|three|chart|d3|axios"
    r"|popper|modernizr|tailwind|fontawesome)[.\-@]?[\d.]*(?:\.min)?\.js"
)


def is_vendor_bundle(url: str) -> bool:
    """Third-party library file: findings there are rarely the site's own bug."""
    return bool(_VENDOR_HINTS.search(url))


def is_minified(source: str) -> bool:
    """Rough minification test, used to decide whether line numbers are useful."""
    sample = source[:20000]
    if not sample:
        return False
    newlines = sample.count("\n")
    if newlines == 0:
        return len(sample) > 500
    return (len(sample) / float(newlines + 1)) > 300


# --------------------------------------------------------------------------- #
# Structural validators (turn FIRM findings into CONFIRMED ones)
# --------------------------------------------------------------------------- #


def _b64url_decode(segment: str) -> Optional[bytes]:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError):
        return None


def decode_jwt(token: str) -> Optional[Tuple[Dict, Dict]]:
    """Return (header, payload) when `token` is a structurally valid JWT.

    A plain `eyJ...` regex matches plenty of base64 that is not a token. Actually
    decoding it is what separates a real JWT from a coincidence.
    """
    parts = token.split(".")
    if len(parts) < 2:
        return None
    raw_header = _b64url_decode(parts[0])
    raw_payload = _b64url_decode(parts[1])
    if not raw_header or not raw_payload:
        return None
    try:
        header = json.loads(raw_header.decode("utf-8", "replace"))
        payload = json.loads(raw_payload.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    if "alg" not in header and "typ" not in header:
        return None
    return header, payload


def looks_like_base64_json(value: str) -> bool:
    decoded = _b64url_decode(value)
    if not decoded:
        return False
    text = decoded.decode("utf-8", "replace").strip()
    return text.startswith("{") or text.startswith("[")


_HEX = re.compile(r"^[0-9a-fA-F]+$")


def is_hash_like(value: str) -> bool:
    """Webpack chunk hashes, sri digests, git sha -- long hex, but not secrets."""
    return bool(_HEX.match(value)) and len(value) in (7, 8, 16, 20, 32, 40, 64, 128)
