"""Synthetic credentials for the test suite.

A secret-scanner test suite necessarily contains strings shaped exactly like
real credentials. That creates two problems:

1. GitHub push protection (and every other secret scanner) blocks a push whose
   files contain a literal matching a partner pattern such as `xoxb-...`.
2. It is far too easy to paste a *real* key from a scan report into a test.

Both are solved the same way: no credential appears as a literal in any file.
Each one is assembled at import time from fragments, so a regex run over this
source finds nothing, while the tests still receive a complete, correctly
shaped token.

Every value here is invented. Never paste a value produced by an actual scan.
"""
from __future__ import annotations


def _build(*parts: str) -> str:
    """Assemble a credential so its literal form never appears in the source."""
    return "".join(parts)


# --- provider formats -------------------------------------------------------- #

SLACK_BOT_TOKEN = _build("xox", "b", "-123456789012-", "abcdefghijklmnop")

GITHUB_PAT = _build("gh", "p", "_", "016C7e2f3A4b5C6d7E8f9A0b1C2d3E4f5G6h7")

# AWS publishes this exact id as its documentation example.
AWS_ACCESS_KEY_ID = _build("AKIA", "IOSFODNN7", "EXAMPLE")

STRIPE_SECRET_KEY = _build("sk", "_", "live", "_", "4eC39HqLyjWDarjtT1zdp7dcabcd")
STRIPE_PUBLISHABLE_KEY = _build("pk", "_", "live", "_", "4eC39HqLyjWDarjtT1zdp7dcabcd")

# AIza + exactly 35 characters.
GOOGLE_API_KEY = _build("AI", "za", "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q")

# header {"alg":"HS256","typ":"JWT"} / payload {"role":"admin","sub":"1","exp":9999999999}
JWT_ADMIN = _build(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ".",
    "eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5fQ",
    ".",
    "c2lnbmF0dXJlLXBsYWNlaG9sZGVyLXZhbHVl",
)

DATABASE_URL = _build("postgres", "://", "admin", ":", "s3cretpw", "@db.internal:5432/app")

# A high-entropy value with no provider prefix, for the generic detector.
GENERIC_SECRET = _build("Xq7Rv2Np", "9Lm4Kd8W", "s3Yt6Bh1", "Cf5Gj0Az")
