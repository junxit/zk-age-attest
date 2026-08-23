"""Redis pending-store profile: shared pop-before-verify via GETDEL semantics."""

from __future__ import annotations

import pytest

from zkage_core.token import make_challenge
from zkage_rp.redis_replay import RedisPendingChallengeStore

redis = pytest.importorskip("fakeredis", reason="fakeredis not installed")


@pytest.fixture()
def store() -> RedisPendingChallengeStore:
    return RedisPendingChallengeStore(redis.FakeRedis())


def test_put_then_pop_roundtrip(store: RedisPendingChallengeStore) -> None:
    challenge = make_challenge("rp.test", 18, now=1_000)
    store.put(challenge)

    assert len(store) == 1
    popped = store.pop(challenge.nonce)
    assert popped is not None and popped.nonce == challenge.nonce
    assert popped.digest() == challenge.digest()
    assert len(store) == 0


def test_pop_is_burn_once(store: RedisPendingChallengeStore) -> None:
    challenge = make_challenge("rp.test", 18, now=1_000)
    store.put(challenge)

    assert store.pop(challenge.nonce) is not None
    assert store.pop(challenge.nonce) is None  # replay finds nothing


def test_unknown_nonce_pops_none(store: RedisPendingChallengeStore) -> None:
    assert store.pop(bytes(32)) is None


def test_sweep_is_ttl_noop(store: RedisPendingChallengeStore) -> None:
    store.put(make_challenge("rp.test", 18, now=1_000))
    assert store.sweep(now=2_000_000) == 0  # expiry is Redis's job
    assert len(store) == 1  # FakeRedis honors TTL lazily; entry still present


def test_shared_across_store_instances() -> None:
    """Two RP workers sharing one Redis see one pending set (multi-node story)."""
    client = redis.FakeRedis()
    first = RedisPendingChallengeStore(client)
    second = RedisPendingChallengeStore(client)

    challenge = make_challenge("rp.test", 18, now=1_000)
    first.put(challenge)

    assert second.pop(challenge.nonce) is not None
    assert first.pop(challenge.nonce) is None
