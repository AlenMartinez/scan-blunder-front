"""HTTP layer: fetching, classifying and harvesting links from responses."""
from __future__ import annotations

import re
import threading
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

try:  # urllib3 v2 moved Retry
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    Retry = None  # type: ignore

from scanner.core.models import Asset

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

_JS_TYPES = ("javascript", "ecmascript", "jsx", "typescript")
_TEXTUAL = ("text/", "json", "javascript", "xml", "html", "ecmascript", "css")

#: URL-ish strings inside HTML attributes we care about beyond <script src>.
_LINK_ATTRS = (
    ("script", "src"),
    ("link", "href"),
    ("iframe", "src"),
    ("img", "data-src"),
)

_INLINE_URL_RE = re.compile(r"""["'`]([^"'`\s]+\.(?:js|mjs|json))(?:\?[^"'`\s]*)?["'`]""")


class HttpClient:
    """A small, polite HTTP client with retries, size caps and asset typing."""

    def __init__(
        self,
        timeout: int = 15,
        max_bytes: int = 5 * 1024 * 1024,
        verify_tls: bool = True,
        proxy: Optional[str] = None,
        user_agent: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        delay: float = 0.0,
    ):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.delay = delay
        self._delay_lock = threading.Lock()
        self._last_request = 0.0

        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers.update(
            {
                "User-Agent": user_agent or DEFAULT_USER_AGENT,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )
        if extra_headers:
            self.session.headers.update(extra_headers)
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

        if Retry is not None:
            retry = Retry(
                total=2,
                backoff_factor=0.4,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET", "HEAD"]),
            )
            adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32, pool_connections=32)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

    # -- fetching -------------------------------------------------------------- #
    def fetch(self, url: str) -> Tuple[Optional[Asset], Optional[str]]:
        """Return (asset, error). Streams the body so oversized files are capped."""
        self._throttle()
        try:
            response = self.session.get(
                url, timeout=self.timeout, allow_redirects=True, stream=True
            )
        except requests.exceptions.SSLError as exc:
            return None, "TLS error: {}".format(_short(exc))
        except requests.exceptions.Timeout:
            return None, "timeout after {}s".format(self.timeout)
        except requests.RequestException as exc:
            return None, _short(exc)

        try:
            content_type = response.headers.get("Content-Type", "")
            headers = dict(response.headers)
            status = response.status_code

            if not _is_textual(content_type):
                response.close()
                return (
                    Asset(url=response.url, content="", content_type=content_type,
                          status=status, headers=headers, kind="binary"),
                    None,
                )

            body = self._read_capped(response)
        finally:
            response.close()

        asset = Asset(
            url=response.url,
            content=body,
            content_type=content_type,
            status=status,
            headers=headers,
            kind=classify(response.url, content_type, body),
        )
        return asset, None

    def head_exists(self, url: str) -> Tuple[bool, int, str]:
        """Cheap existence probe used for sensitive-path checks."""
        self._throttle()
        try:
            response = self.session.get(
                url, timeout=self.timeout, allow_redirects=False, stream=True
            )
            status = response.status_code
            content_type = response.headers.get("Content-Type", "")
            preview = ""
            if status == 200 and _is_textual(content_type):
                preview = self._read_capped(response, limit=2048)
            response.close()
            return status == 200, status, preview
        except requests.RequestException:
            return False, 0, ""

    # -- helpers ---------------------------------------------------------------- #
    def _read_capped(self, response, limit: Optional[int] = None) -> str:
        cap = limit or self.max_bytes
        chunks: List[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= cap:
                break
        raw = b"".join(chunks)[:cap]
        encoding = response.encoding or "utf-8"
        try:
            return raw.decode(encoding, errors="replace")
        except (LookupError, TypeError):
            return raw.decode("utf-8", errors="replace")

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        with self._delay_lock:
            elapsed = time.time() - self._last_request
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self._last_request = time.time()


# --------------------------------------------------------------------------- #
# Response classification and link extraction
# --------------------------------------------------------------------------- #


def _is_textual(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    if not lowered:
        return True  # servers that omit it are usually serving text
    return any(token in lowered for token in _TEXTUAL)


def classify(url: str, content_type: str, body: str) -> str:
    lowered = (content_type or "").lower()
    path = urlparse(url).path.lower()

    if path.endswith(".map"):
        return "map"
    if any(token in lowered for token in _JS_TYPES) or path.endswith((".js", ".mjs", ".cjs")):
        return "js"
    if "json" in lowered or path.endswith(".json"):
        return "json"
    if "css" in lowered or path.endswith(".css"):
        return "css"
    if "html" in lowered or path.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp")):
        return "html"
    if not lowered and body.lstrip()[:200].lower().startswith(("<!doctype html", "<html")):
        return "html"
    return "other"


def extract_links(asset: Asset, base_url: str) -> Dict[str, Set[str]]:
    """Return {"scripts": …, "pages": …, "sourcemaps": …} discovered in an asset."""
    scripts: Set[str] = set()
    pages: Set[str] = set()
    sourcemaps: Set[str] = set()

    if asset.kind == "html":
        soup = _soup(asset.content)
        if soup is not None:
            for tag_name, attr in _LINK_ATTRS:
                for tag in soup.find_all(tag_name):
                    value = tag.get(attr)
                    if not value:
                        continue
                    resolved = _resolve(asset.url, value)
                    if not resolved:
                        continue
                    if tag_name == "link":
                        rel = " ".join(tag.get("rel") or []).lower()
                        as_attr = (tag.get("as") or "").lower()
                        if resolved.split("?")[0].endswith(".js") or as_attr == "script" \
                                or "modulepreload" in rel:
                            scripts.add(resolved)
                        continue
                    if tag_name == "script":
                        scripts.add(resolved)

            for anchor in soup.find_all("a", href=True):
                resolved = _resolve(asset.url, anchor["href"])
                if resolved and _same_site(resolved, base_url):
                    pages.add(resolved.split("#")[0])

    # JS/JSON chunks referencing further chunks, plus any inline reference.
    if asset.kind in ("js", "json", "html"):
        for match in _INLINE_URL_RE.finditer(asset.content):
            candidate = match.group(1)
            if candidate.startswith(("http", "/", "./", "../")):
                resolved = _resolve(asset.url, candidate)
                if resolved and _same_site(resolved, base_url):
                    scripts.add(resolved)

    if asset.kind in ("js", "css"):
        for match in re.finditer(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)", asset.content):
            reference = match.group(1).strip()
            if reference.startswith("data:"):
                continue
            resolved = _resolve(asset.url, reference)
            if resolved:
                sourcemaps.add(resolved)

    return {"scripts": scripts, "pages": pages, "sourcemaps": sourcemaps}


def _soup(html: str) -> Optional[BeautifulSoup]:
    for parser in ("html.parser",):
        try:
            return BeautifulSoup(html, parser)
        except Exception:
            continue
    return None


def _resolve(base: str, value: str) -> Optional[str]:
    value = (value or "").strip()
    if not value or value.startswith(("data:", "javascript:", "mailto:", "tel:", "#", "blob:")):
        return None
    try:
        resolved = urljoin(base, value)
    except ValueError:
        return None
    if not resolved.startswith(("http://", "https://")):
        return None
    return resolved


def _same_site(url: str, base_url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    base_host = (urlparse(base_url).hostname or "").lower()
    if not host or not base_host:
        return False
    if host == base_host:
        return True
    registrable = ".".join(base_host.split(".")[-2:])
    return host.endswith("." + registrable)


def _short(exc: Exception) -> str:
    text = str(exc)
    return text[:160] + ("…" if len(text) > 160 else "")
