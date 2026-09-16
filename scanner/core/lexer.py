"""A deliberately small JavaScript tokenizer.

Detectors do not run raw regexes over whole files. They run them over *string
literals*, because every secret, every SQL statement and every endpoint that a
front-end ships is, necessarily, inside a string. Scanning literals instead of
raw bytes is what removes the bulk of the false positives:

    <p>Select a plan from our catalogue</p>   ->  never tokenized (not code)
    // SELECT * FROM users -- old query       ->  comment, skipped by default
    const q = "SELECT * FROM users WHERE id=" ->  a literal, reported

The tokenizer is regex driven rather than character driven so that it stays
fast on the multi-megabyte minified bundles that real sites serve.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, List, Optional

_TOKEN_RE = re.compile(
    r"""
      (?P<line_comment>//[^\n\r]*)
    | (?P<block_comment>/\*[\s\S]*?\*/)
    | (?P<dq>"(?:[^"\\\r\n]|\\.)*")
    | (?P<sq>'(?:[^'\\\r\n]|\\.)*')
    | (?P<tpl>`(?:[^`\\]|\\.)*`)
    """,
    re.VERBOSE,
)

_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "0": "\0",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "`": "`",
    "/": "/",
}

_UNICODE_ESCAPE = re.compile(r"\\u\{?([0-9a-fA-F]{1,6})\}?|\\x([0-9a-fA-F]{2})")


@dataclass
class StringLiteral:
    """A string literal found in source, with absolute positions."""

    value: str          # decoded contents (no surrounding quotes)
    raw: str            # exactly as written, quotes included
    start: int          # absolute offset of the opening quote
    end: int            # absolute offset just past the closing quote
    quote: str          # ' " or `
    interpolated: bool  # template literal containing ${...}

    @property
    def inner_start(self) -> int:
        return self.start + 1


@dataclass
class Comment:
    text: str
    start: int
    end: int
    block: bool


def _decode(raw_body: str) -> str:
    """Resolve the escape sequences that matter for pattern matching."""
    if "\\" not in raw_body:
        return raw_body

    def _unicode_sub(match: "re.Match") -> str:
        code = match.group(1) or match.group(2)
        try:
            return chr(int(code, 16))
        except (ValueError, OverflowError):
            return match.group(0)

    decoded = _UNICODE_ESCAPE.sub(_unicode_sub, raw_body)

    out: List[str] = []
    index = 0
    length = len(decoded)
    while index < length:
        char = decoded[index]
        if char == "\\" and index + 1 < length:
            nxt = decoded[index + 1]
            out.append(_ESCAPES.get(nxt, nxt))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def iter_string_literals(
    source: str,
    base_offset: int = 0,
    include_comments: bool = False,
) -> Iterator[StringLiteral]:
    """Yield every string/template literal in `source`.

    `base_offset` is added to every position so callers can map back to the
    original document when the source is an extracted <script> block.
    """
    for match in _TOKEN_RE.finditer(source):
        kind = match.lastgroup
        if kind in ("line_comment", "block_comment"):
            continue
        raw = match.group()
        body = raw[1:-1]
        quote = raw[0]
        yield StringLiteral(
            value=_decode(body),
            raw=raw,
            start=base_offset + match.start(),
            end=base_offset + match.end(),
            quote=quote,
            interpolated=quote == "`" and "${" in body,
        )


def iter_comments(source: str, base_offset: int = 0) -> Iterator[Comment]:
    """Yield every comment. Useful for finding commented-out credentials."""
    for match in _TOKEN_RE.finditer(source):
        kind = match.lastgroup
        if kind not in ("line_comment", "block_comment"):
            continue
        raw = match.group()
        yield Comment(
            text=raw,
            start=base_offset + match.start(),
            end=base_offset + match.end(),
            block=kind == "block_comment",
        )


def strip_comments(source: str) -> str:
    """Blank out comments while preserving every byte offset."""

    def _blank(match: "re.Match") -> str:
        if match.lastgroup in ("line_comment", "block_comment"):
            # keep newlines so line numbers stay correct
            return re.sub(r"[^\n]", " ", match.group())
        return match.group()

    return _TOKEN_RE.sub(_blank, source)


def preceding_identifier(source: str, offset: int, window: int = 80) -> str:
    """The property/variable name a literal is being assigned to, if any.

    Given `const apiKey = "..."`, `{ password: "..." }` or `token="..."`, this
    returns `apiKey`, `password`, `token`. Detectors use it to tell a real
    assignment apart from an arbitrary string that merely sits near a keyword.
    """
    start = max(0, offset - window)
    prefix = source[start:offset]
    match = re.search(
        r"""([A-Za-z_$][\w$\-]*)\s*["']?\s*[:=]\s*(?:new\s+\w+\s*\(\s*)?$""",
        prefix,
    )
    return match.group(1) if match else ""


def find_enclosing_region(regions: List, offset: int) -> Optional[int]:
    """Index of the region containing `offset`, or None."""
    for index, (region_offset, text) in enumerate(regions):
        if region_offset <= offset < region_offset + len(text):
            return index
    return None
