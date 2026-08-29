"""RFC 8785 canonicalization and domain-separated content digests."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, cast

import rfc8785


def canonical_bytes(value: object) -> bytes:
    """Return strict JSON Canonicalization Scheme bytes."""
    return rfc8785.dumps(cast(Any, value))


def content_digest(domain: str, value: Mapping[str, object]) -> str:
    """Hash canonical significant data under an ASCII, NUL-separated domain."""
    if not domain.isascii() or "\x00" in domain or not domain:
        raise ValueError("digest domain must be nonempty ASCII without NUL")
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + canonical_bytes(value)).hexdigest()
