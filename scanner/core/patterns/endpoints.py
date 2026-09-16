"""Endpoint, URL and backend discovery patterns."""
from __future__ import annotations

import re

#: Absolute URLs. Kept deliberately conservative about trailing punctuation so
#: that URLs lifted out of minified code do not swallow the next token.
ABSOLUTE_URL_RE = re.compile(
    r"""(?ix)
    \bhttps?://
    (?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}
    (?::\d{2,5})?
    (?:/[^\s"'`<>\\)\]}]*)?
    """
)

#: Protocol-relative URLs: //cdn.example.com/lib.js
PROTOCOL_RELATIVE_RE = re.compile(
    r"""(?ix)(?<![:\w])//((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?:/[^\s"'`<>]*)?)"""
)

#: WebSocket endpoints.
WEBSOCKET_RE = re.compile(r"(?i)\bwss?://[^\s\"'`<>]{4,}")

#: API-looking paths inside string literals: "/api/v2/users", "/graphql".
API_PATH_RE = re.compile(
    r"""(?ix)
    ^/(?:
        api|apis|rest|graphql|gql|v[0-9]{1,2}|rpc|oauth2?|auth|admin|internal|
        webhook|webhooks|_next/data|wp-json|services?|backend|gateway|query
    )
    (?:/[\w\-.~%:@]+|/\$\{[^}]{1,60}\}|/:[\w]+|/\*)*
    /?$
    """
)

#: A path that at least *looks* like an API route even without a known prefix.
GENERIC_API_PATH_RE = re.compile(
    r"""(?ix)
    ^/[\w\-./]{2,120}/(?:
        list|create|update|delete|search|login|logout|register|signup|signin|
        token|refresh|profile|me|upload|download|export|import|status|health|
        checkout|payment|order|orders|users?|customers?|products?|items?
    )(?:/[\w\-.:${}]*)*/?$
    """
)

#: HTTP verb paired with a URL inside code:
#:   fetch(url, {method: "POST"})   axios.post("/api/x")   $.ajax({type:'PUT'})
FETCH_CALL_RE = re.compile(
    r"""(?ix)
    \b(?:fetch|axios|request|http|api|client|instance|\$\.ajax|superagent|ky|got)
    \s*(?:\.\s*(?P<verb>get|post|put|patch|delete|head|options)\s*)?
    \(\s*[`"'](?P<url>[^`"']{1,400})[`"']
    """
)

METHOD_OPTION_RE = re.compile(
    r"""(?ix)\b(?:method|type)\s*:\s*["'](?P<verb>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']"""
)

#: `GET https://example.com/x` as it appears in docs/comments/log strings.
METHOD_URL_RE = re.compile(
    r"""(?i)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://[^\s"'`<>]{4,}|/[\w\-./]{2,120})"""
)

#: Router declarations reveal the full page map of an SPA.
ROUTE_DECLARATION_RE = re.compile(
    r"""(?ix)\bpath\s*:\s*["'](?P<path>/[^"']{0,160})["']"""
)

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24}\b")

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

#: Extensions that are static assets rather than API endpoints.
STATIC_EXTENSIONS = (
    ".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".webp", ".avif", ".ico", ".bmp", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip", ".gz",
    ".txt", ".xml", ".rss", ".atom", ".webmanifest",
)

#: Hosts that are pure CDNs/analytics; not the application's own backend.
NON_BACKEND_HOST_HINTS = (
    "fonts.googleapis.com", "fonts.gstatic.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net", "bootstrapcdn.com", "w3.org", "schema.org",
    "gmpg.org", "purl.org", "creativecommons.org", "github.com",
    "googletagmanager.com", "google-analytics.com", "doubleclick.net",
    "facebook.com", "facebook.net", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "youtube.com", "ytimg.com", "vimeo.com", "wordpress.org",
    "mozilla.org", "apache.org", "wixstatic.com",
)
