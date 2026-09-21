"""Vulnerability and bad-practice patterns.

The SQL rules deserve a note. The previous implementation used

    SELECT\\s+.*\\s+FROM\\s+.*

which matches "Select a plan from our catalogue" in body copy, every CSS
`select` rule followed by the word "from", and any minified line that happens to
contain both words. The rules here instead:

1. only ever run against string literals inside real code regions,
2. require the FROM/INTO/UPDATE target to be a valid SQL identifier,
3. reject identifiers that are ordinary words ("our", "the", "us"),
4. require at least one corroborating SQL token or terminator,
5. reject anything carrying HTML markup.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from scanner.core.models import Severity

# --------------------------------------------------------------------------- #
# SQL
# --------------------------------------------------------------------------- #

#: A quoted/bracketed or bare SQL identifier, optionally schema qualified.
_IDENT = r"[`\"'\[]?[A-Za-z_][A-Za-z0-9_$]{0,62}[`\"'\]]?(?:\s*\.\s*[`\"'\[]?[A-Za-z_][A-Za-z0-9_$]{0,62}[`\"'\]]?)?"

SQL_STATEMENTS = [
    ("SELECT", re.compile(r"\bSELECT\b(?P<body>[\s\S]{1,400}?)\bFROM\b\s+(?P<target>" + _IDENT + r")", re.I)),
    ("INSERT", re.compile(r"\bINSERT\s+(?:IGNORE\s+)?INTO\b\s+(?P<target>" + _IDENT + r")\s*(?P<body>[\s\S]{0,400}?)(?:\(|VALUES|SELECT|SET)", re.I)),
    ("UPDATE", re.compile(r"\bUPDATE\b\s+(?P<target>" + _IDENT + r")\s+SET\b(?P<body>[\s\S]{1,400}?)(?:$|;|WHERE)", re.I)),
    ("DELETE", re.compile(r"\bDELETE\s+FROM\b\s+(?P<target>" + _IDENT + r")(?P<body>[\s\S]{0,400}?)(?:$|;|WHERE)", re.I)),
    ("DROP", re.compile(r"\b(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)\b\s+(?:IF\s+EXISTS\s+)?(?P<target>" + _IDENT + r")(?P<body>)", re.I)),
    ("UNION", re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b(?P<body>[\s\S]{0,200})(?P<target>)", re.I)),
]

#: At least one of these must appear for a candidate to count as real SQL.
SQL_CORROBORATION = re.compile(
    r"""(?ix)
      \b(WHERE|INNER\s+JOIN|LEFT\s+JOIN|RIGHT\s+JOIN|FULL\s+JOIN|CROSS\s+JOIN|JOIN
        |GROUP\s+BY|ORDER\s+BY|HAVING|LIMIT|OFFSET|VALUES|RETURNING|DISTINCT
        |ON\s+CONFLICT|ON\s+DUPLICATE|IS\s+NULL|IS\s+NOT\s+NULL|COUNT\s*\(
        |SUM\s*\(|AVG\s*\(|MAX\s*\(|MIN\s*\(|COALESCE\s*\(|AS\s+\w+)\b
    | \$\d+                    # postgres positional parameter
    | :[A-Za-z_]\w*            # named bind parameter
    | \?\s*(?:,|\)|$)          # positional placeholder
    | ;\s*$                    # statement terminator
    | \*\s*FROM                # SELECT * FROM
    """
)

#: Identifiers that are ordinary words. A "table" called `our` or `the` means
#: the match came from prose, not from SQL.
SQL_STOPWORD_TARGETS = {
    "the", "a", "an", "our", "your", "my", "their", "its", "this", "that",
    "these", "those", "us", "them", "him", "her", "it", "here", "there",
    "all", "any", "some", "more", "most", "other", "another", "which", "what",
    "where", "when", "who", "how", "and", "or", "of", "to", "in", "on", "for",
    "with", "by", "at", "as", "is", "are", "be", "was", "were", "one", "two",
    "list", "below", "above", "top", "left", "right", "center", "none",
    "auto", "inherit", "initial", "unset", "start", "end", "up", "down",
    "el", "la", "los", "las", "un", "una", "de", "del", "nuestro", "nuestra",
    "su", "sus", "tu", "este", "esta", "estos", "estas", "aqui", "todo",
}

#: Interpolation inside a SQL string: the difference between "raw SQL shipped to
#: the client" and "raw SQL shipped to the client *and* concatenated with input".
SQL_INTERPOLATION = re.compile(r"\$\{[^}]{1,120}\}|\+\s*[A-Za-z_$][\w$.\[\]]*|%s|%\(\w+\)s|#\{[^}]+\}")

#: Client-side query builders / ORMs that indicate DB access from the browser.
ORM_PATTERNS = [
    ("Prisma Client in front-end", re.compile(r"\bprisma\s*\.\s*[a-zA-Z_$][\w$]*\s*\.\s*(?:findMany|findFirst|findUnique|create|createMany|update|updateMany|upsert|delete|deleteMany|aggregate|groupBy)\s*\(")),
    ("Knex query builder in front-end", re.compile(r"\bknex\s*\(\s*[\"'][\w.]+[\"']\s*\)\s*\.\s*(?:select|insert|update|del|where)\b")),
    ("Sequelize in front-end", re.compile(r"\bsequelize\s*\.\s*(?:query|define|models)\b|\.\s*findAll\s*\(\s*\{\s*where")),
    ("TypeORM in front-end", re.compile(r"\bcreateQueryBuilder\s*\(|getRepository\s*\(\s*\w+\s*\)")),
    ("Mongoose/MongoDB in front-end", re.compile(r"\bmongoose\s*\.\s*(?:model|connect)\s*\(|\bdb\s*\.\s*collection\s*\(")),
    ("Raw driver query in front-end", re.compile(r"\b(?:pool|client|connection|conn|db)\s*\.\s*(?:query|execute)\s*\(\s*[`\"']")),
    ("Supabase raw filter", re.compile(r"\.\s*(?:rpc|or|filter)\s*\(\s*[`\"'][^`\"']*(?:select|delete|update|--)")),
]

# --------------------------------------------------------------------------- #
# DOM XSS sinks
# --------------------------------------------------------------------------- #

XSS_SINKS = [
    ("React dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML\s*[:=]\s*\{\{?\s*__html"), Severity.MEDIUM),
    ("Vue v-html directive", re.compile(r"\bv-html\s*=\s*[\"'][^\"']+[\"']"), Severity.MEDIUM),
    ("Angular bypassSecurityTrust", re.compile(r"\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\("), Severity.MEDIUM),
    ("innerHTML assignment", re.compile(r"\.\s*(?:innerHTML|outerHTML)\s*(?:\+)?=\s*(?!['\"]\s*['\"])"), Severity.LOW),
    ("document.write", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\("), Severity.LOW),
    ("eval of dynamic input", re.compile(r"\beval\s*\(\s*(?!['\"])"), Severity.MEDIUM),
    ("Function constructor", re.compile(r"\bnew\s+Function\s*\(\s*[^)]"), Severity.LOW),
    ("insertAdjacentHTML", re.compile(r"\.\s*insertAdjacentHTML\s*\("), Severity.LOW),
    ("jQuery html() sink", re.compile(r"\$\([^)]{0,80}\)\s*\.\s*(?:html|append|prepend|after|before|replaceWith)\s*\(\s*(?!['\"])"), Severity.LOW),
    ("setTimeout/setInterval with string", re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]"), Severity.LOW),
    ("postMessage without origin check", re.compile(r"\.\s*postMessage\s*\(\s*[^,]{1,120},\s*[\"']\*[\"']"), Severity.MEDIUM),
]

#: Sources of attacker-controlled data. An XSS sink fed by one of these is the
#: pattern that actually matters, so we look for them in the same statement.
XSS_TAINT_SOURCES = re.compile(
    r"(?i)\b(?:location\s*\.\s*(?:hash|search|href|pathname)|document\s*\.\s*(?:URL|documentURI|referrer|cookie)"
    r"|window\s*\.\s*name|URLSearchParams|searchParams|\bgetParam|\bqueryParams?"
    r"|\breq\s*\.\s*query|\bdecodeURIComponent\s*\()"
)

# --------------------------------------------------------------------------- #
# Other client-side weaknesses
# --------------------------------------------------------------------------- #


@dataclass
class VulnRule:
    name: str
    pattern: "re.Pattern"
    severity: str = Severity.MEDIUM
    detail: str = ""
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    #: when True the rule runs over the whole document, not only code regions
    whole_document: bool = False


MISC_VULN_RULES: List[VulnRule] = [
    VulnRule(
        name="Debug mode enabled",
        pattern=re.compile(r"(?i)\b(?:debug|isDebug|debugMode|DEBUG_MODE)\s*[:=]\s*(?:true|1|[\"']true[\"'])"),
        severity=Severity.LOW,
        detail="A debug flag is enabled in the production bundle.",
        remediation="Disable debug flags in production builds.",
        tags=["config"],
    ),
    VulnRule(
        name="Source map reference",
        pattern=re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)"),
        severity=Severity.LOW,
        detail="The bundle points at a source map, which can expose original source code.",
        remediation="Do not deploy .map files, or restrict them to authenticated users.",
        tags=["exposure"],
    ),
    VulnRule(
        # w3.org/schema.org/purl.org URLs are XML namespace identifiers: they are
        # never dereferenced, so reporting them as insecure traffic is noise.
        name="Insecure HTTP endpoint",
        pattern=re.compile(
            r"""[\"'](http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0"""
            r"""|(?:www\.)?(?:w3|schema|purl|gmpg|xmlns|openurl|ns\.adobe|iptc)\.org"""
            r"""|(?:www\.)?(?:creativecommons|w3c)\.org)"""
            r"""[\w.\-]+\.[a-z]{2,}[^\"'\s]*)[\"']"""
        ),
        severity=Severity.LOW,
        detail="A plain-HTTP endpoint is referenced; traffic to it can be intercepted.",
        remediation="Use HTTPS for every external request.",
        tags=["transport"],
    ),
    VulnRule(
        # A bare `\.local` match also hits `navigator.language` and
        # `node.localName`, so an internal host only counts when it carries a
        # scheme or is the entire contents of a string literal.
        name="Internal / private host reference",
        pattern=re.compile(
            r"""(?ix)
              https?://(?:
                  10\.\d{1,3}\.\d{1,3}\.\d{1,3}
                | 192\.168\.\d{1,3}\.\d{1,3}
                | 172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}
                | [\w\-]+(?:\.[\w\-]+)*\.(?:local|internal|intranet|corp|lan)
              )(?::\d+)?(?:/[^\s"'<>`]*)?
            | ["'](?:
                  10\.\d{1,3}\.\d{1,3}\.\d{1,3}
                | 192\.168\.\d{1,3}\.\d{1,3}
                | 172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}
                | [\w\-]+(?:\.[\w\-]+)*\.(?:local|internal|intranet|corp|lan)
              )(?::\d+)?(?:/[^\s"'<>`]*)?["']
            """
        ),
        severity=Severity.MEDIUM,
        detail="An internal hostname or RFC1918 address leaks internal network layout.",
        remediation="Strip internal hosts from production builds.",
        tags=["exposure", "recon"],
    ),
    VulnRule(
        # The environment word has to be its own DNS label and the host needs at
        # least two further labels. Without that, `dev.to` and
        # `developer.mozilla.org` both register as staging environments.
        name="Staging / pre-production endpoint",
        pattern=re.compile(
            r"""(?ix)
            ["'](https?://
                (?:[\w\-]+\.)*
                (?:[\w\-]+-)?
                (?:dev|test|qa|uat|stage|staging|sandbox|preprod|nonprod|demo)
                (?:-[\w\-]+)?
                \.[\w\-]+\.[a-z]{2,}
                [^"'\s]*)["']
            """
        ),
        severity=Severity.LOW,
        detail="A non-production environment is referenced from the production bundle.",
        remediation="Remove non-production hosts from production builds.",
        tags=["exposure"],
    ),
    VulnRule(
        name="Disabled TLS verification",
        pattern=re.compile(r"(?i)\b(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*[\"']?0|strictSSL\s*:\s*false|verify\s*:\s*False)"),
        severity=Severity.HIGH,
        detail="TLS certificate verification is switched off.",
        remediation="Never disable certificate verification.",
        tags=["transport"],
    ),
    VulnRule(
        name="Permissive CORS in client config",
        pattern=re.compile(r"(?i)(?:Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*|origin\s*:\s*[\"']\*[\"'])"),
        severity=Severity.MEDIUM,
        detail="A wildcard CORS origin is configured.",
        remediation="Pin allowed origins to an explicit list.",
        tags=["cors"],
    ),
    VulnRule(
        name="Client-side authorization decision",
        pattern=re.compile(
            r"(?i)\bif\s*\(\s*!?\s*(?:user|currentUser|session|auth|me|profile|account)"
            r"(?:\??\.\w+){0,3}\s*\.\s*(?:isAdmin|is_admin|admin|role|roles|permissions?|isSuperUser|superuser|canEdit|canDelete)\b"
        ),
        severity=Severity.MEDIUM,
        detail=(
            "An access decision is being made in the browser. Client-side checks are "
            "cosmetic; the same rule must be enforced server-side."
        ),
        remediation="Enforce authorization on the API. Treat the front-end check as UX only.",
        tags=["authz", "broken-access-control"],
    ),
    VulnRule(
        name="Hidden admin route in bundle",
        pattern=re.compile(r"[\"'](/(?:admin|administrator|backoffice|back-office|superadmin|dashboard/admin|internal|manage|console)(?:/[\w\-/:]*)?)[\"']"),
        severity=Severity.LOW,
        detail="An administrative route is referenced in the client bundle.",
        remediation="Make sure the route is protected server-side, not just hidden in the UI.",
        tags=["authz", "recon"],
    ),
    VulnRule(
        name="Credentials written to Web Storage",
        pattern=re.compile(r"(?i)\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*[\"'][^\"']*(?:token|jwt|auth|password|secret|credential|api[_\-]?key)[^\"']*[\"']"),
        severity=Severity.MEDIUM,
        detail="Authentication material is stored in Web Storage, which any XSS can read.",
        remediation="Prefer HttpOnly, Secure, SameSite cookies for session material.",
        tags=["auth", "storage"],
    ),
    VulnRule(
        name="Insecure randomness for security value",
        pattern=re.compile(r"(?i)\b(?:token|nonce|salt|secret|otp|session|uuid|id)\w*\s*=\s*Math\s*\.\s*random\s*\("),
        severity=Severity.MEDIUM,
        detail="Math.random() is not cryptographically secure.",
        remediation="Use crypto.getRandomValues() / crypto.randomUUID().",
        tags=["crypto"],
    ),
    VulnRule(
        name="Weak hashing algorithm",
        pattern=re.compile(r"(?i)\b(?:md5|sha1)\s*\(\s*(?:password|passwd|pwd|secret|token)"),
        severity=Severity.MEDIUM,
        detail="A broken hash function is applied to a credential.",
        remediation="Hash passwords server-side with bcrypt/scrypt/Argon2.",
        tags=["crypto"],
    ),
    VulnRule(
        name="Client-side password comparison",
        pattern=re.compile(r"(?i)\b(?:password|passwd|pwd)\s*(?:===?|!==?)\s*[\"'][^\"']{3,}[\"']"),
        severity=Severity.HIGH,
        detail="A password is compared against a literal in the browser.",
        remediation="Authenticate on the server; never ship the expected password.",
        tags=["auth"],
    ),
    VulnRule(
        # The navigation target has to look like user input. A bare `next` also
        # matches Next.js's own `window.next` global, so the names here are the
        # specific ones that carry a redirect destination.
        name="Open redirect sink",
        pattern=re.compile(
            r"""(?ix)
            (?:location\s*(?:\.\s*href)?\s*=|location\s*\.\s*(?:replace|assign)\s*\()\s*
            [\w$.\[\]]*?
            (?:searchParams|getParam|queryParam|URLSearchParams
              |redirect(?:Url|_url|To|Uri)?|returnUrl|return_to|returnTo
              |callbackUrl|callback_url|continueUrl|nextUrl|next_url
              |dest(?:ination)?(?:Url)?|goto|target_url)
            \b"""
        ),
        severity=Severity.MEDIUM,
        detail="A navigation target is taken from user-controlled input.",
        remediation="Allow-list redirect targets instead of echoing user input.",
        tags=["redirect"],
    ),
    VulnRule(
        name="GraphQL query in client",
        pattern=re.compile(r"(?i)\b(?:query|mutation)\s+\w*\s*(?:\([^)]*\))?\s*\{[\s\S]{10,400}?\}"),
        severity=Severity.INFO,
        detail="GraphQL operations found. Useful for mapping the API surface.",
        remediation="Disable introspection in production and enforce per-field authorization.",
        tags=["graphql", "recon"],
    ),
    VulnRule(
        name="TODO/FIXME security note",
        pattern=re.compile(r"(?i)(?://|/\*|\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)\b[^\n\r*]{0,160}(?:security|auth|password|token|secret|vulnerab|inject|bypass|temporar|hardcoded)"),
        severity=Severity.LOW,
        detail="A developer note flags an unfinished security concern.",
        remediation="Track and resolve the note; remove it from shipped code.",
        tags=["hygiene"],
    ),
]
