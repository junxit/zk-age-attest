"""Transparency-log battery: tamper, fork, rollback, head signature, key selection."""

import dataclasses

import pytest

from zkage_core import devicekey, translog


def make_log() -> list[translog.LogRecord]:
    """Three records: scope-18 key (epoch 1), scope-13 key, then revoke the 18 key."""
    records: list[translog.LogRecord] = []
    records.append(
        translog.append_record(
            records,
            ts=100,
            scope=18,
            epoch=1,
            key_id=bytes([1]) * 32,
            spki=b"spki-18-1",
            not_before=0,
            not_after=10_000,
            status="active",
        )
    )
    records.append(
        translog.append_record(
            records,
            ts=110,
            scope=13,
            epoch=1,
            key_id=bytes([2]) * 32,
            spki=b"spki-13-1",
            not_before=0,
            not_after=10_000,
            status="active",
        )
    )
    records.append(
        translog.append_record(
            records,
            ts=120,
            scope=18,
            epoch=1,
            key_id=bytes([1]) * 32,
            spki=b"spki-18-1",
            not_before=0,
            not_after=10_000,
            status="revoked",
        )
    )
    return records


def test_verify_chain_ok_and_empty() -> None:
    records = make_log()
    head = translog.verify_chain(records)
    assert head == records[-1].record_hash
    assert translog.verify_chain([]) == translog.GENESIS_PREV


def test_tampered_record_detected() -> None:
    records = make_log()
    records[1] = dataclasses.replace(records[1], spki=b"evil-spki")
    with pytest.raises(translog.LogError, match="hash mismatch"):
        translog.verify_chain(records)


def test_relinked_tamper_detected_by_extension_check() -> None:
    """Recomputing hashes after a tamper defeats verify_chain but not the pinned head."""
    records = make_log()
    pinned_size, pinned_head = len(records), records[-1].record_hash
    forked: list[translog.LogRecord] = []
    forked.append(
        translog.append_record(
            forked,
            ts=100,
            scope=18,
            epoch=1,
            key_id=bytes([9]) * 32,
            spki=b"evil",
            not_before=0,
            not_after=10_000,
            status="active",
        )
    )
    forked.append(
        translog.append_record(
            forked,
            ts=110,
            scope=13,
            epoch=1,
            key_id=bytes([2]) * 32,
            spki=b"spki-13-1",
            not_before=0,
            not_after=10_000,
            status="active",
        )
    )
    forked.append(
        translog.append_record(
            forked,
            ts=120,
            scope=18,
            epoch=1,
            key_id=bytes([9]) * 32,
            spki=b"evil",
            not_before=0,
            not_after=10_000,
            status="active",
        )
    )
    translog.verify_chain(forked)  # internally consistent fork...
    with pytest.raises(translog.LogError, match="fork"):
        translog.check_extension(pinned_size, pinned_head, forked)  # ...but not an extension


def test_rollback_detected() -> None:
    records = make_log()
    with pytest.raises(translog.LogError, match="rollback"):
        translog.check_extension(len(records), records[-1].record_hash, records[:2])


def test_valid_extension_accepted() -> None:
    records = make_log()
    pinned_size, pinned_head = len(records), records[-1].record_hash
    extended = list(records)
    extended.append(
        translog.append_record(
            extended,
            ts=130,
            scope=18,
            epoch=2,
            key_id=bytes([3]) * 32,
            spki=b"spki-18-2",
            not_before=0,
            not_after=20_000,
            status="active",
        )
    )
    head = translog.check_extension(pinned_size, pinned_head, extended)
    assert head == extended[-1].record_hash
    # First sync (nothing pinned) accepts any consistent log.
    assert translog.check_extension(0, translog.GENESIS_PREV, extended) == head


def test_signed_head_round_trip_and_tamper() -> None:
    records = make_log()
    log_key = devicekey.generate_device_key()
    head = translog.sign_head(log_key, len(records), records[-1].record_hash, ts=999)
    translog.verify_head(log_key.public_key(), head)

    parsed = translog.SignedHead.from_json_dict(head.to_json_dict())
    translog.verify_head(log_key.public_key(), parsed)

    bad_size = dataclasses.replace(head, size=head.size + 1)
    with pytest.raises(translog.LogError):
        translog.verify_head(log_key.public_key(), bad_size)
    other = devicekey.generate_device_key()
    with pytest.raises(translog.LogError):
        translog.verify_head(other.public_key(), head)


def test_active_record_honors_revocation_window_and_epoch() -> None:
    records = make_log()
    # The only scope-18 key was revoked by the last record.
    assert translog.active_record_for(records, 18, now=500) is None
    assert translog.active_record_for(records, 13, now=500) is not None

    records.append(
        translog.append_record(
            records,
            ts=130,
            scope=18,
            epoch=2,
            key_id=bytes([3]) * 32,
            spki=b"spki-18-2",
            not_before=200,
            not_after=20_000,
            status="active",
        )
    )
    records.append(
        translog.append_record(
            records,
            ts=140,
            scope=18,
            epoch=3,
            key_id=bytes([4]) * 32,
            spki=b"spki-18-3",
            not_before=15_000,
            not_after=30_000,
            status="active",
        )
    )
    chosen = translog.active_record_for(records, 18, now=500)
    assert chosen is not None and chosen.epoch == 2  # epoch 3 not yet valid
    chosen = translog.active_record_for(records, 18, now=16_000)
    assert chosen is not None and chosen.epoch == 3  # overlap: highest valid epoch wins
    assert translog.active_record_for(records, 18, now=25_000) is not None
    assert translog.active_record_for(records, 21, now=500) is None


def test_jsonl_round_trip() -> None:
    records = make_log()
    parsed = translog.from_jsonl(translog.to_jsonl(records))
    assert parsed == records
    translog.verify_chain(parsed)
    with pytest.raises(translog.LogError):
        translog.from_jsonl('{"seq": "broken"\n')
