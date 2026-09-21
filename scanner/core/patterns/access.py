"""Roles, permissions and access-control patterns.

Front-ends routinely ship the complete role and permission catalogue of the
application. That list is a map of the attack surface: it tells you which
privilege levels exist, what they are called and which API calls guard them.
"""
from __future__ import annotations

import re
from typing import List, Pattern, Set, Tuple

#: `role: "admin"`, `userRole = 'SUPER_ADMIN'`, `"defaultRole":"editor"`
#:
#: The keyword may only appear at the start of the key, after a separator, or at
#: a camelCase boundary. A plain `(?i)[\w$]*rol` would match `Control` -- which
#: is exactly how React's `{Control: "ctrlKey"}` map got reported as a role.
ROLE_ASSIGNMENT_RE = re.compile(
    r"""(?x)
    \b(?P<key>
        (?:[A-Za-z$][\w$]*[_\-.])?
        (?:[Rr]oles?|[Rr]ol|[Pp]erfil|[Pp]rofile|[Uu]ser[_\-]?[Tt]ype|[Aa]ccount[_\-]?[Tt]ype)
      | [a-z0-9_$]+(?:Roles?|Rol|Perfil|Profile|UserType|AccountType)
      | (?:[A-Z$][A-Z0-9_$]*_)?(?:ROLES?|ROL|PERFIL|PROFILE|USER_?TYPE|ACCOUNT_?TYPE)
    )\b
    \s*["']?\s*[:=]\s*
    ["'](?P<value>[A-Za-z][\w .\-]{1,48})["']
    """
)

#: `roles: ["admin", "editor"]`, `permissions: ['user.read', 'user.write']`
ROLE_ARRAY_RE = re.compile(
    r"""(?x)
    \b(?P<key>
        (?:[A-Za-z$][\w$]*[_\-.])?
        (?:[Rr]oles|[Pp]ermissions|[Pp]ermisos|[Ss]copes|[Gg]rants|[Aa]bilities
          |[Pp]rivileges|[Cc]laims|[Aa]uthorities|ACL|acl)
      | [a-z0-9_$]+(?:Roles|Permissions|Permisos|Scopes|Grants|Abilities
          |Privileges|Claims|Authorities|Acl)
      | (?:[A-Z$][A-Z0-9_$]*_)?(?:ROLES|PERMISSIONS|PERMISOS|SCOPES|GRANTS
          |ABILITIES|PRIVILEGES|CLAIMS|AUTHORITIES)
    )\b
    \s*["']?\s*[:=]\s*
    \[(?P<value>[^\]\[]{2,600})\]
    """
)

#: Constant-style role identifiers: ROLE_ADMIN, PERM_DELETE_USER
ROLE_CONSTANT_RE = re.compile(
    r"""["'](?P<value>(?:ROLE|PERM|PERMISSION|SCOPE|GRANT|CAP|ABILITY)_[A-Z][A-Z0-9_]{2,48})["']"""
)

#: Permission strings in the common `resource:action` / `resource.action` shape.
PERMISSION_STRING_RE = re.compile(
    r"""["'](?P<value>[a-z][a-z0-9_\-]{2,32}[.:](?:create|read|write|update|delete|list|view|edit|manage|admin|export|import|approve|publish|\*)(?:[.:][a-z0-9_\-*]{1,32})?)["']"""
)

#: Guard helpers: hasRole('admin'), can('delete', 'user'), checkPermission("x")
PERMISSION_CHECK_RE = re.compile(
    r"""(?ix)
    \b(?P<fn>has(?:Any)?(?:Role|Permission|Scope|Authority)|is(?:Admin|SuperUser|Owner|Staff|Manager)
      |can(?:Access|Edit|Delete|Create|View|Manage)?|check(?:Role|Permission|Access)|require(?:Role|Permission|Auth)
      |authorize|ability|userCan|allowedTo|puede|tienePermiso)
    \s*\(\s*(?P<value>["'][^"']{2,64}["'](?:\s*,\s*["'][^"']{2,64}["'])?)?
    """
)

#: Feature flags that gate privileged UI.
FEATURE_FLAG_RE = re.compile(
    r"""(?ix)\b(?P<key>[\w$]*(?:featureFlag|feature_flag|flags?|toggle|enable[A-Z]\w+|is\w*Enabled))\b
    \s*["']?\s*[:=]\s*(?P<value>true|false|\{[^{}]{0,200}\})"""
)

#: JWT payload claims that carry authorization data.
JWT_AUTHZ_CLAIMS: Tuple[str, ...] = (
    "role", "roles", "scope", "scopes", "permissions", "perms", "groups",
    "authorities", "realm_access", "resource_access", "is_admin", "isAdmin",
    "admin", "user_role", "app_metadata", "https://hasura.io/jwt/claims",
    "x-hasura-default-role", "x-hasura-allowed-roles",
)

#: Role names that indicate elevated privilege when they show up in a bundle.
PRIVILEGED_ROLE_NAMES: Set[str] = {
    "admin", "administrator", "administrador", "superadmin", "super_admin",
    "super-admin", "superuser", "super_user", "root", "owner", "sysadmin",
    "system", "staff", "moderator", "developer", "service_role", "service-role",
    "master", "supervisor", "gerente", "dueno", "propietario",
}

#: Values that look like a role but are really UI/ARIA noise.
ROLE_VALUE_DENYLIST: Set[str] = {
    # ARIA roles
    "button", "link", "dialog", "alert", "alertdialog", "banner", "checkbox",
    "columnheader", "combobox", "complementary", "contentinfo", "definition",
    "document", "feed", "figure", "form", "grid", "gridcell", "group",
    "heading", "img", "list", "listbox", "listitem", "log", "main", "marquee",
    "math", "menu", "menubar", "menuitem", "menuitemcheckbox",
    "menuitemradio", "navigation", "none", "note", "option", "presentation",
    "progressbar", "radio", "radiogroup", "region", "row", "rowgroup",
    "rowheader", "scrollbar", "search", "searchbox", "separator", "slider",
    "spinbutton", "status", "switch", "tab", "table", "tablist", "tabpanel",
    "term", "textbox", "timer", "toolbar", "tooltip", "tree", "treegrid",
    "treeitem", "application", "article", "cell", "directory", "doc-abstract",
    # generic UI / CSS values
    "primary", "secondary", "default", "small", "medium", "large", "true",
    "false", "auto", "inherit", "initial", "unset", "hidden", "visible",
    "text", "number", "email", "password", "submit", "reset", "file", "date",
    "horizontal", "vertical", "left", "right", "center", "top", "bottom",
}

#: Words that mean the "permission" match is actually a MIME type or a path.
PERMISSION_VALUE_DENYLIST_RE = re.compile(
    r"(?i)^(?:image|text|audio|video|application|font|model|multipart|message)[./]"
    r"|^(?:https?|data|blob|file|mailto|tel)[:.]"
    r"|\.(?:js|css|png|jpe?g|gif|svg|webp|woff2?|ttf|eot|ico|json|xml|html?|map)$"
)

#: Direct object reference hints: a client-side id used to fetch another entity.
IDOR_HINT_RE = re.compile(
    r"""(?ix)
    (?:fetch|axios|\$\.(?:get|post|ajax)|api|http)\b[^;\n]{0,80}
    ["'`][^"'`]*/(?:users?|accounts?|customers?|orders?|invoices?|documents?|files?|profiles?|tickets?)/
    (?:\$\{[^}]{1,60}\}|["']\s*\+\s*[\w$.]{1,40}|:id|%s|\d+)
    """
)

#: Authentication bypass smells.
AUTH_BYPASS_RE: List[Tuple[str, Pattern]] = [
    (
        "Hardcoded auth bypass flag",
        re.compile(r"(?i)\b(?:skipAuth|bypassAuth|disableAuth|noAuth|authDisabled|isAuthenticated)\s*[:=]\s*(?:true|1)"),
    ),
    (
        "Development backdoor",
        re.compile(r"(?i)\b(?:backdoor|godMode|god_mode|masterPassword|master_password|devLogin|impersonate)\b"),
    ),
    (
        "Role forced client-side",
        re.compile(r"(?i)\b(?:user|currentUser|session|me|profile)(?:\??\.\w+){0,2}\s*\.\s*(?:role|roles|isAdmin)\s*=\s*[\"'][^\"']+[\"']"),
    ),
]
