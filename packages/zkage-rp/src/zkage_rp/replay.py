"""Pending-challenge store with pop-before-verify semantics.

The pending entry is removed atomically BEFORE any cryptography runs. A
missing entry (never issued, already redeemed, or expired) is indistinguishable
from a replay by design, and a malformed redemption burns its own challenge —
only the party inside the TLS session that received the nonce can do that.
This eliminates the verify-then-mark TOCTOU double-spend race entirely.

Demo store is in-process; a multi-node RP needs an atomic shared pop
(e.g., Redis GETDEL), as documented in DESIGN.md.
"""

from __future__ import annotations

import threading
from typing import Protocol

from zkage_core.token import Challenge


class PendingStore(Protocol):
    """What the RP needs from any pending-challenge store (in-process or shared)."""

    def put(self, challenge: Challenge) -> None:
        """Register a freshly issued challenge."""
        ...

    def pop(self, nonce: bytes) -> Challenge | None:
        """Atomically remove and return the pending challenge, if any."""
        ...

    def sweep(self, now: int) -> int:
        """Drop expired challenges; returns how many were removed."""
        ...

    def __len__(self) -> int:
        """Number of currently pending challenges."""
        ...


class PendingChallengeStore:
    """Thread-safe in-memory pending-challenge store keyed by nonce."""

    def __init__(self) -> None:
        self._pending: dict[bytes, Challenge] = {}
        self._lock = threading.Lock()

    def put(self, challenge: Challenge) -> None:
        """Register a freshly issued challenge."""
        with self._lock:
            self._pending[challenge.nonce] = challenge

    def pop(self, nonce: bytes) -> Challenge | None:
        """Atomically remove and return the pending challenge, if any."""
        with self._lock:
            return self._pending.pop(nonce, None)

    def sweep(self, now: int) -> int:
        """Drop expired challenges; returns how many were removed."""
        with self._lock:
            expired = [n for n, c in self._pending.items() if c.expires_at <= now]
            for nonce in expired:
                del self._pending[nonce]
            return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._pending)
