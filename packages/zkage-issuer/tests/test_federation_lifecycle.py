"""Key-lifecycle battery: rotation, revocation, hot-reload of a running state."""

from __future__ import annotations

import pytest

from zkage_core import keys, translog
from zkage_issuer.federation import (
    FederationState,
    FederationStateError,
    active_keyset,
    init_state,
    revoke_scope_key,
    rotate_scope_key,
)

NOW = 1_750_000_000


@pytest.fixture(scope="module")
def fed(tmp_path_factory: pytest.TempPathFactory):
    """A fresh, initialized federation directory shared by the lifecycle tests."""
    state_dir = tmp_path_factory.mktemp("fed")
    init_state(state_dir, now=NOW)
    return state_dir


def load(fed) -> FederationState:
    return FederationState.load(fed, now=NOW)


def test_rotate_creates_epoch_two(fed) -> None:
    old = active_keyset(_records(fed), NOW)
    old18 = next(r for r in old if r.scope == 18)

    new = rotate_scope_key(fed, 18, now=NOW)

    assert new.epoch == 2 and new.key_id != old18.key_id
    records = _records(fed)
    assert translog.verify_chain(records) == records[-1].record_hash
    # Chain narrates retire → activate for scope 18.
    tail = [r.status for r in records if r.scope == 18][-2:]
    assert tail == ["retired", "active"]
    # Keyset projection now carries only the new key.
    keyset = {r.scope: r for r in active_keyset(records, NOW)}
    assert keyset[18].key_id == new.key_id and keyset[18].epoch == 2
    assert keyset[13].epoch == 1  # untouched scopes unaffected
    # The new private key is on disk and matches the logged record.
    pem = fed / "issuer" / "scope_keys" / "18_2.pem"
    assert keys.key_id_of(keys.load_private_key_pem(pem.read_bytes()).public_key()) == new.key_id


def _records(fed) -> list[translog.LogRecord]:
    records = translog.from_jsonl((fed / "public" / "log.jsonl").read_text())
    translog.verify_chain(records)
    return records


def test_revoke_drops_scope_from_keyset(fed) -> None:
    revoke_scope_key(fed, 13, now=NOW)

    records = _records(fed)
    assert [r.status for r in records if r.scope == 13][-1] == "revoked"
    scopes = {r.scope for r in active_keyset(records, NOW)}
    assert 13 not in scopes
    with pytest.raises(FederationStateError, match="no active key"):
        revoke_scope_key(fed, 13, now=NOW)  # nothing left to revoke
    # Issuer-side effect: no signing key resolves for the revoked scope.
    with pytest.raises(FederationStateError, match="no active key"):
        load(fed).active_key(13, NOW)


def test_rotate_after_revoke_needs_no_active_key(fed) -> None:
    """Recovery from revocation is rotation; it must not require an active key."""
    new = rotate_scope_key(fed, 13, now=NOW)
    assert new.epoch == 2
    records = _records(fed)
    statuses = [r.status for r in records if r.scope == 13]
    assert statuses.count("revoked") == 1  # no spurious retire record
    assert active_record(fed, 13).key_id == new.key_id


def active_record(fed, scope: int) -> keys.ScopeKeyRecord:
    record = translog.active_record_for(_records(fed), scope, NOW)
    assert record is not None
    return record.to_scope_key_record()


def test_running_state_hot_reloads(fed) -> None:
    """A loaded FederationState picks up on-disk rotation via maybe_reload."""
    state = load(fed)
    before = state.active_key(16, NOW)[0].key_id

    rotate_scope_key(fed, 16, now=NOW)
    state.maybe_reload(NOW)

    after = state.active_key(16, NOW)[0]
    assert after.key_id != before and after.epoch == 2
    # And a no-op reload is exactly that.
    head_before = state.signed_head
    state.maybe_reload(NOW)
    assert state.signed_head == head_before


def test_init_refuses_then_lifecycle_requires_init(tmp_path) -> None:
    with pytest.raises(FederationStateError, match="missing"):
        rotate_scope_key(tmp_path, 18, now=NOW)
    init_state(tmp_path, now=NOW)
    rotate_scope_key(tmp_path, 21, now=NOW)
    assert active_record(tmp_path, 21).epoch == 2
