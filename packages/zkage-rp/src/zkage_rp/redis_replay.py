"""Redis-backed pending-challenge store: pop-before-verify across RP nodes.

Same contract as the in-process store (``zkage_rp.replay``), but the atomic
pop is Redis ``GETDEL``, so multiple RP workers/nodes share one pending set
without reintroducing the TOCTOU double-spend race (DESIGN §6.4). Challenges
self-expire via Redis TTL, so ``sweep`` is a no-op by construction.

The client is duck-typed (anything with ``set``/``getdel``/``scan_iter``) so
tests can inject ``fakeredis`` and production injects ``redis.Redis`` — this
package gains no hard dependency either way.
"""

from __future__ import annotations

import json
import time
from typing import Any, Protocol

from zkage_core.token import Challenge

_KEY_PREFIX = "zkage:pending:"
#: TTL grace so a challenge is still poppable (and burnable) just after expiry.
_TTL_GRACE = 60


class RedisLike(Protocol):
    """The slice of the Redis client API this store needs."""

    def set(self, name: str, value: str, ex: int) -> Any: ...

    def getdel(self, name: str) -> Any: ...

    def scan_iter(self, match: str) -> Any: ...


class RedisPendingChallengeStore:
    """Shared pending-challenge store; atomic ``GETDEL`` pop, TTL-based expiry."""

    def __init__(self, client: RedisLike) -> None:
        self._client = client

    @staticmethod
    def _key(nonce: bytes) -> str:
        return _KEY_PREFIX + nonce.hex()

    def put(self, challenge: Challenge) -> None:
        """Register a freshly issued challenge with a TTL past its expiry."""
        ttl = max(1, challenge.expires_at - int(time.time()) + _TTL_GRACE)
        self._client.set(self._key(challenge.nonce), json.dumps(challenge.to_json_dict()), ttl)

    def pop(self, nonce: bytes) -> Challenge | None:
        """Atomically remove and return the pending challenge, if any."""
        raw = self._client.getdel(self._key(nonce))
        if not raw:
            return None
        try:
            return Challenge.from_json_dict(json.loads(raw))
        except (ValueError, TypeError, KeyError):
            return None

    def sweep(self, now: int) -> int:
        """No-op: Redis TTLs expire challenges; returns 0 by construction."""
        return 0

    def __len__(self) -> int:
        return sum(1 for _ in self._client.scan_iter(match=_KEY_PREFIX + "*"))
