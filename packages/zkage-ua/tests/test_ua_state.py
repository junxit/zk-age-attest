"""UA state keystore round-trip and error handling."""

from pathlib import Path

import pytest

from zkage_core import translog
from zkage_ua.state import StateError, UAState, load_state, save_state


def make_state() -> UAState:
    return UAState(
        issuer_url="http://issuer.test",
        account_id=bytes(16),
        device_sk_raw=bytes(32),
        max_scope=18,
        log_public_raw=bytes(32),
        pinned_size=0,
        pinned_head=translog.GENESIS_PREV,
    )


def test_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "state.json"
    state = make_state()
    save_state(path, state)
    assert load_state(path) == state


def test_with_pin(tmp_path: Path) -> None:
    state = make_state().with_pin(4, b"\x01" * 32)
    assert state.pinned_size == 4 and state.pinned_head == b"\x01" * 32


def test_missing_state(tmp_path: Path) -> None:
    with pytest.raises(StateError, match="enroll"):
        load_state(tmp_path / "nope.json")


def test_malformed_state(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{not json")
    with pytest.raises(StateError, match="malformed"):
        load_state(path)
    path.write_text('{"version": 1}')
    with pytest.raises(StateError, match="malformed"):
        load_state(path)
