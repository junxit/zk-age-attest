"""Base64url helpers (unpadded) for JSON transport envelopes."""

from __future__ import annotations

import base64


def b64u(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    """Decode unpadded base64url to bytes.

    Raises:
        ValueError: If the input is not valid base64url.
    """
    pad = -len(text) % 4
    try:
        return base64.urlsafe_b64decode(text + "=" * pad)
    except Exception as exc:
        raise ValueError("invalid base64url") from exc


def as_int(value: object) -> int:
    """Strictly narrow a parsed-JSON value to int (booleans rejected).

    Raises:
        ValueError: If the value is not an integer.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("expected an integer")
    return value


def as_str(value: object) -> str:
    """Strictly narrow a parsed-JSON value to str.

    Raises:
        ValueError: If the value is not a string.
    """
    if not isinstance(value, str):
        raise ValueError("expected a string")
    return value
