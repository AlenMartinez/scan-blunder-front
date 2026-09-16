"""Argument validation."""
from __future__ import annotations

import argparse
import ipaddress
import re
from urllib.parse import urlparse, urlunparse

#: URLs whose scheme we filled in, so the engine knows it may retry over HTTP.
_INFERRED_SCHEMES = set()

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-_]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-_]{1,63}(?<!-))*\.?$"
)


def url_validator(value: str) -> str:
    """Accept `example.com` as well as a full URL, and normalise the result."""
    candidate = (value or "").strip()
    if not candidate:
        raise argparse.ArgumentTypeError("The target URL is empty.")

    if "://" not in candidate:
        candidate = "https://" + candidate
        _INFERRED_SCHEMES.add(candidate)

    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise argparse.ArgumentTypeError(
            "Unsupported scheme '{}'. Use http:// or https://.".format(parsed.scheme)
        )
    if not parsed.hostname:
        raise argparse.ArgumentTypeError("'{}' has no hostname.".format(value))

    host = parsed.hostname
    if not _is_ip(host) and not _HOSTNAME.match(host):
        raise argparse.ArgumentTypeError("'{}' is not a valid hostname.".format(host))

    path = parsed.path or "/"
    normalized = urlunparse(
        (parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, "")
    )
    if candidate in _INFERRED_SCHEMES:
        _INFERRED_SCHEMES.add(normalized)
    return normalized


def scheme_was_inferred(url: str) -> bool:
    """True when `url_validator` supplied the https:// prefix itself."""
    return url in _INFERRED_SCHEMES


def header_validator(value: str) -> tuple:
    """`-H "Cookie: a=b"` -> ("Cookie", "a=b")"""
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            "Headers must look like 'Name: value' (got '{}').".format(value)
        )
    name, _, header_value = value.partition(":")
    name = name.strip()
    if not name:
        raise argparse.ArgumentTypeError("Header name cannot be empty.")
    return name, header_value.strip()


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("'{}' is not a number.".format(value))
    if number < 1:
        raise argparse.ArgumentTypeError("Value must be at least 1.")
    return number


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
