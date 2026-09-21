# Scan Blunder Front

![Scan Blunder Front Banner](screenshot/Captura%20desde%202026-05-10%2013-47-47.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-75%20passing-brightgreen.svg)](tests/)

**Scan Blunder Front** is a security scanner for front-end applications
(React, Next.js, Vue, Nuxt, Angular, Svelte, WordPress, Laravel, static sites…).
It fetches the page, walks its entire bundle, and reports exposed secrets,
client-side SQL, authorization logic running in the browser, the backends the
app talks to, and the full stack with versions.

The design goal is **not reporting noise**: every finding passes through a
filter chain before it reaches the report.

## What it detects

| Area | Examples |
|---|---|
| **Secrets** | AWS, Google, Stripe, GitHub, GitLab, Slack, SendGrid, Twilio, OpenAI, Anthropic, npm, Firebase, Supabase, PEM keys, database connection strings, JWTs (decoded, with their claims read) |
| **SQL in the front-end** | real `SELECT/INSERT/UPDATE/DELETE`, distinguishing raw SQL from **concatenated** (injectable) SQL, plus client-side ORMs (Prisma, Knex, Sequelize, TypeORM, Mongoose) |
| **Roles and permissions** | role catalogues, granular permissions (`invoice.delete`), client-side checks (`hasRole`, `can`), bypass flags (`skipAuth`), privileged roles inside JWTs |
| **Endpoints and backends** | API routes with their real HTTP method, GraphQL, WebSockets, SPA router paths, relative route tables extracted from the bundle, and the list of backend hosts |
| **Technologies and versions** | frameworks, libraries, bundlers, CMS, server and CDN — via headers, cookies, banners, filenames and `?ver=`; enumerates **WordPress plugins and themes with their versions** |
| **Third-party services** | analytics, payments, identity, monitoring, CDNs, support |
| **Client-side vulnerabilities** | DOM XSS sinks (with taint detection), open redirect, disabled TLS, permissive CORS, credentials in `localStorage`, `Math.random()` for security values, internal hosts, staging environments |
| **Exposure** | published source maps, Next.js `serverRuntimeConfig`, environment variables in `__NEXT_DATA__`, versions in headers, sensitive paths (`/.env`, `/.git/config`, `/actuator/env`…) |
| **Headers** | CSP (and its quality), HSTS, X-Frame-Options, dangerous CORS, cookies missing `HttpOnly`/`Secure`/`SameSite` |

## Sample output

```
───────────────────────────────── SCAN SUMMARY ─────────────────────────────────
╭──────────────────────────────────────────────────────────────────────────────╮
│ Target      https://example.com/                                             │
│ Duration    4.3s   ·   41 request(s)   ·   2098 KB scanned                   │
│ Findings    2 CRITICAL  1 HIGH  4 MEDIUM  6 LOW  2 INFO                      │
│ 3 low-confidence finding(s) hidden — rerun with --include-tentative          │
╰──────────────────────────────────────────────────────────────────────────────╯

[+] TECHNOLOGIES & VERSIONS
 Name          Version    Category   Evidence
 ──────────────────────────────────────────────────
 Next.js       14.1.0     framework  package manifest
 React         18.2.0     framework  React.version
 nginx         1.18.0     server     Server header

[!] SECRETS & CREDENTIALS
 Sev        Conf   Issue                Value            Where
 ────────────────────────────────────────────────────────────────────────
 CRITICAL   Conf   AWS Access Key ID    AKIAIOSFO…MPLE   …/app.js:3
 CRITICAL   Conf   JSON Web Token       eyJhbG…YzAb      …/app.js:6
  ▸ JSON Web Token (JWT) Token carries authorization claims: role.
    The token holds a privileged role. The token is still valid.
    fix: Never ship tokens in the bundle; obtain them at runtime.

[!] VULNERABILITIES & BAD PRACTICES
 HIGH       Firm   SQL injection: query built by concatenation in the front-end
```

## How it avoids false positives

This is the part that matters most. A scanner that over-reports does not get read.

1. **Code regexes only run over code.** In an HTML document the scanner extracts
   the contents of `<script>`, inline handlers and `javascript:` URIs. Page copy
   never reaches the detectors, so *"Select a plan from our catalogue"* can never
   be reported as SQL.
2. **Secrets and SQL are read from string literals**, using a JS tokenizer that
   also skips comments. A raw regex can pair the opening quote of one string with
   the closing quote of another and capture a slab of minified code; a tokenizer
   reading from the start of the file cannot.
3. **SQL must be structurally real.** A `SELECT` needs a table that is a valid
   identifier (not `our`, `the`, `nuestro`), a supporting clause (`WHERE`,
   `JOIN`, `VALUES`, a `$1`/`?` parameter) and no markup.
4. **Values are validated, not just matched.** A JWT is actually decoded; if it
   is not valid JSON with claims, it is not a JWT. A generic value needs real
   entropy and length.
5. **Placeholders, prose and routes are rejected.** `credentials:"same-origin"`,
   `api_key:"apikey"`, `${API_KEY}`, `****`, `your-key-here` are dropped. So are
   human sentences — including accented ones, so an i18n message like
   *"La contraseña es obligatoria"* is not key material — and route constants
   like `user/change_password`, which are collected as endpoints instead.
6. **Framework and ARIA context is respected.** `role="button"` is ARIA, not an
   application role. `window.next` is not an open redirect. `navigator.language`
   is not a `.lan` host. Third-party `Server:` headers do not describe your stack.
7. **Every finding carries a confidence** (`CONFIRMED` / `FIRM` / `TENTATIVE`).
   Only the first two are shown by default; `--include-tentative` shows the rest.

## Installation

```bash
git clone https://github.com/AlenMartinez/scan-blunder-front.git
cd scan-blunder-front

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py example.com
```

The scheme is optional: if omitted, `https://` is tried first and it falls back
to `http://` automatically.

### Examples

```bash
# standard scan, 20 threads
python3 main.py https://example.com --threads 20

# also crawl one level of internal pages
python3 main.py https://example.com --depth 1

# show low-confidence findings as well
python3 main.py https://example.com --include-tentative

# secrets and SQL only, without touching sensitive paths
python3 main.py https://example.com --only secrets,sql --no-probe

# pass an authenticated session and exit 2 if anything HIGH or worse is found
python3 main.py https://example.com -H "Cookie: session=abc" --fail-on HIGH

# through Burp / mitmproxy
python3 main.py https://example.com --proxy http://127.0.0.1:8080 --insecure
```

### Main options

| Option | Description |
|---|---|
| `--threads N` | concurrent requests (10) |
| `--depth N` | also crawl N levels of same-site pages (0) |
| `--max-assets N` | cap on files downloaded (300) |
| `--max-size MB` | per-file cap (5) |
| `--no-sourcemaps` | do not download `.map` files |
| `--no-probe` | do not request well-known sensitive paths |
| `--only` / `--skip` | pick detectors: `technology,secrets,sql,xss,misc,access,endpoints,headers` |
| `--timeout` / `--delay` | per-request timeout and minimum delay between requests |
| `--proxy` / `--insecure` | HTTP proxy and disabling TLS verification |
| `-H 'Name: value'` | extra request header (repeatable) |
| `--output DIR` | report directory (`findings`) |
| `--format` | `json`, `md`, `txt` (default `json,md`) |
| `--include-tentative` | show low-confidence findings |
| `--min-severity` | hide findings below that severity |
| `--fail-on SEVERITY` | exit with code 2 if findings reach that level (for CI) |
| `-v` / `-q` | verbose / quiet |

### Reports

Every scan writes to `findings/`:

- `domain_date.json` — full result, meant for automation.
- `domain_date.md` — readable report with detail, location and remediation.
- `domain_date.txt` — with `--format txt`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | scan completed; nothing at or above `--fail-on` |
| `1` | bad arguments, or the target could not be reached |
| `2` | `--fail-on` threshold was met — useful as a CI gate |

## Architecture

```
scanner/
├── cli/          arguments, validation and terminal presentation
├── core/
│   ├── models.py     Finding, Asset, ScanResults, code regions
│   ├── lexer.py      JS tokenizer (string literals and comments)
│   ├── filters.py    entropy, placeholders, HTML/prose guards, validators
│   ├── context.py    scan configuration
│   ├── engine.py     orchestration: crawl, chunks, source maps, probes
│   ├── patterns/     catalogues: secrets, vulns, technologies, access, endpoints
│   ├── detector/     one detector per area, all sharing the same interface
│   └── findings/     report writers (json / md / txt)
└── services/     HTTP client with retries, size caps and link extraction
```

### Adding a check

Most checks are one entry in a pattern catalogue:

```python
# scanner/core/patterns/vulns.py
VulnRule(
    name="Hardcoded feature flag override",
    pattern=re.compile(r"(?i)\bforceEnable\w*\s*[:=]\s*true"),
    severity=Severity.LOW,
    detail="A feature flag is forced on in the production bundle.",
    remediation="Drive flags from configuration, not from shipped constants.",
    tags=["config"],
)
```

Something with its own logic becomes a detector class implementing
`detect(asset) -> Iterable[Finding]`, registered in `DETECTOR_CLASSES`
(`scanner/core/detector/detector_services.py`). Use `asset.code_regions()` rather
than `asset.content` so HTML copy never reaches your regex, and
`iter_string_literals()` when the value you want lives inside a string.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

`tests/test_false_positives.py` and `tests/test_real_reports.py` contain the
specific false positives that earlier versions reported against production
sites. They are regression tests and must keep passing.

**If you find a false positive, that is a bug.** Open an issue with the snippet
that triggered it, or send a pull request adding it to those files alongside the
filter that resolves it.

## Contributing

Pull requests are welcome. A good one:

- adds a test for the behaviour it changes;
- keeps the full suite green (`python3 -m unittest discover -s tests -t .`);
- for a new detection, includes both a true positive and the false positive it
  must not produce;
- explains *why* a filter exists in a comment, so nobody removes it later.

## License

Released under the [MIT License](LICENSE) — free and open source, for the
community.

The license also carries an explicit acceptable-use notice: **responsibility
for running this software rests entirely with whoever runs it.** You choose the
targets, you need the authorization, and you own the consequences. The authors
provide the tool with no warranty and accept no liability for how it is used,
nor for decisions made from its output.

## Authorized use only

The default mode makes active requests, including paths such as `/.env` and
`/.git/config`. Use `--no-probe` to stay within what a browser would do.

Scan only systems you own or have explicit written permission to test. See the
[LICENSE](LICENSE) for the full acceptable-use and responsibility notice.

---
Made for the security community.
