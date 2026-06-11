"""Per-account issuance rate limiting.

Rate limits are the issuer's only anti-farming lever — it cannot see token
contents, so it bounds *throughput*. The limit is account-global, not
per-scope: per-scope budgets would multiply a proxy's throughput by the number
of scopes.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass

_DAY = 86_400


@dataclass
class _BucketState:
    tokens: float
    last: float
    day: int
    day_count: int


class RateLimiter:
    """Token bucket plus a daily cap, with an injectable clock value.

    Defaults: burst of 5, sustained ~2/minute, 50/day.
    """

    def __init__(
        self, capacity: int = 5, refill_seconds: float = 30.0, daily_cap: int = 50
    ) -> None:
        self.capacity = capacity
        self.refill_seconds = refill_seconds
        self.daily_cap = daily_cap
        self._state: dict[bytes, _BucketState] = {}
        self._lock = threading.Lock()

    def check(self, key: bytes, now: float) -> tuple[bool, int]:
        """Consume one issuance slot for ``key`` if available.

        Args:
            key: Account identifier.
            now: Current unix seconds (caller-supplied).

        Returns:
            ``(allowed, retry_after_seconds)``; ``retry_after_seconds`` is 0
            when allowed.
        """
        with self._lock:
            state = self._state.get(key)
            if state is None:
                state = _BucketState(float(self.capacity), now, int(now // _DAY), 0)
                self._state[key] = state

            state.tokens = min(
                float(self.capacity), state.tokens + (now - state.last) / self.refill_seconds
            )
            state.last = now

            today = int(now // _DAY)
            if today != state.day:
                state.day = today
                state.day_count = 0

            if state.day_count >= self.daily_cap:
                return False, max(1, int((state.day + 1) * _DAY - now))
            if state.tokens < 1.0:
                return False, max(1, math.ceil((1.0 - state.tokens) * self.refill_seconds))

            state.tokens -= 1.0
            state.day_count += 1
            return True, 0
