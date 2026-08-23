"""Hash-chained, signed key transparency log (MVP).

The log records federation scope keys only — never per-issuance data — so it
grows ~8 records/quarter. Each record hash covers the previous record's hash
(append-only chain); the head is signed by a dedicated log key. User agents
pin the last head they saw and require every refresh to be an append-only
extension, which converts per-user key targeting and log rollback into loud,
detectable failures. RPs gossip their view of the head inside challenges, so
sustaining a split view requires issuer+RP collusion.

Canonical record bytes (the hash preimage) use a fixed field-order binary
serialization — never JSON re-serialization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from zkage_core.encoding import as_int, as_str, b64u, unb64u
from zkage_core.keys import KEY_STATUSES, ScopeKeyRecord
from zkage_core.token import SCOPES

LOG_HEAD_TAG = b"zkage/v1/loghead\x00"
GENESIS_PREV = bytes(32)

#: How many trailing record hashes a UA accepts as an RP's gossiped ``log_head``.
#: RPs refresh asynchronously, so their view may legitimately lag several
#: appends behind (one rotation writes two records); a forked log's hashes
#: never appear anywhere in the honest chain, so lag tolerance costs none of
#: the split-view detection.
GOSSIP_LAG_TOLERANCE = 16

_STATUS_CODE = {name: i + 1 for i, name in enumerate(KEY_STATUSES)}


class LogError(Exception):
    """The transparency log is inconsistent, tampered with, or not an extension."""


@dataclass(frozen=True)
class LogRecord:
    """One append-only log entry describing a scope key's registration or status change."""

    seq: int
    ts: int
    scope: int
    epoch: int
    key_id: bytes
    spki: bytes
    not_before: int
    not_after: int
    status: str
    prev_hash: bytes
    record_hash: bytes

    def canonical_bytes(self) -> bytes:
        """Fixed-layout hash preimage (excludes prev_hash/record_hash)."""
        return (
            self.seq.to_bytes(8, "big")
            + self.ts.to_bytes(8, "big")
            + bytes([self.scope])
            + self.epoch.to_bytes(4, "big")
            + self.key_id
            + len(self.spki).to_bytes(4, "big")
            + self.spki
            + self.not_before.to_bytes(8, "big")
            + self.not_after.to_bytes(8, "big")
            + bytes([_STATUS_CODE[self.status]])
        )

    def to_scope_key_record(self) -> ScopeKeyRecord:
        """Project onto the keyset record shape consumed by RPs/verifier."""
        return ScopeKeyRecord(
            scope=self.scope,
            epoch=self.epoch,
            key_id=self.key_id,
            spki=self.spki,
            not_before=self.not_before,
            not_after=self.not_after,
            status=self.status,
        )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "scope": self.scope,
            "epoch": self.epoch,
            "key_id": b64u(self.key_id),
            "spki": b64u(self.spki),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "status": self.status,
            "prev_hash": b64u(self.prev_hash),
            "record_hash": b64u(self.record_hash),
        }

    @classmethod
    def from_json_dict(cls, data: dict[str, object]) -> LogRecord:
        try:
            return cls(
                seq=as_int(data["seq"]),
                ts=as_int(data["ts"]),
                scope=as_int(data["scope"]),
                epoch=as_int(data["epoch"]),
                key_id=unb64u(as_str(data["key_id"])),
                spki=unb64u(as_str(data["spki"])),
                not_before=as_int(data["not_before"]),
                not_after=as_int(data["not_after"]),
                status=as_str(data["status"]),
                prev_hash=unb64u(as_str(data["prev_hash"])),
                record_hash=unb64u(as_str(data["record_hash"])),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise LogError("malformed log record") from exc


def _record_hash(prev_hash: bytes, canonical: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(prev_hash + canonical).digest()


def append_record(
    records: list[LogRecord],
    *,
    ts: int,
    scope: int,
    epoch: int,
    key_id: bytes,
    spki: bytes,
    not_before: int,
    not_after: int,
    status: str,
) -> LogRecord:
    """Append a record, chaining its hash to the current head.

    Returns the new record (the caller appends it to its store).

    Raises:
        LogError: If fields are invalid.
    """
    if status not in KEY_STATUSES:
        raise LogError("unknown status")
    if scope not in SCOPES:
        raise LogError("unknown scope")
    if len(key_id) != 32:
        raise LogError("key_id must be 32 bytes")
    prev_hash = records[-1].record_hash if records else GENESIS_PREV
    record = LogRecord(
        seq=len(records),
        ts=ts,
        scope=scope,
        epoch=epoch,
        key_id=key_id,
        spki=spki,
        not_before=not_before,
        not_after=not_after,
        status=status,
        prev_hash=prev_hash,
        record_hash=b"",
    )
    return LogRecord(
        **{**record.__dict__, "record_hash": _record_hash(prev_hash, record.canonical_bytes())}
    )


def verify_chain(records: list[LogRecord]) -> bytes:
    """Verify the full hash chain.

    Returns:
        The head hash (GENESIS_PREV for an empty log).

    Raises:
        LogError: On any sequence, linkage, or hash mismatch.
    """
    prev = GENESIS_PREV
    for i, record in enumerate(records):
        if record.seq != i:
            raise LogError(f"sequence mismatch at {i}")
        if record.status not in KEY_STATUSES:
            raise LogError(f"unknown status at {i}")
        if record.prev_hash != prev:
            raise LogError(f"chain linkage broken at {i}")
        expected = _record_hash(prev, record.canonical_bytes())
        if record.record_hash != expected:
            raise LogError(f"record hash mismatch at {i}")
        prev = record.record_hash
    return prev


def check_extension(pinned_size: int, pinned_head: bytes, records: list[LogRecord]) -> bytes:
    """Require ``records`` to be an append-only extension of a pinned view.

    Args:
        pinned_size: Number of records in the previously verified view.
        pinned_head: Head hash of the previously verified view.
        records: The freshly fetched full log.

    Returns:
        The new head hash.

    Raises:
        LogError: On tamper, rollback (new log shorter), or fork (prefix
            hash differs from the pinned head).
    """
    head = verify_chain(records)
    if pinned_size == 0:
        return head
    if len(records) < pinned_size:
        raise LogError("log rollback: fewer records than pinned view")
    if records[pinned_size - 1].record_hash != pinned_head:
        raise LogError("log fork: pinned head is not a prefix of the new log")
    return head


@dataclass(frozen=True)
class SignedHead:
    """A signed statement of the log's current size and head hash."""

    size: int
    head_hash: bytes
    ts: int
    signature: bytes

    def to_json_dict(self) -> dict[str, object]:
        return {
            "size": self.size,
            "head_hash": b64u(self.head_hash),
            "ts": self.ts,
            "signature": b64u(self.signature),
        }

    @classmethod
    def from_json_dict(cls, data: dict[str, object]) -> SignedHead:
        try:
            return cls(
                size=as_int(data["size"]),
                head_hash=unb64u(as_str(data["head_hash"])),
                ts=as_int(data["ts"]),
                signature=unb64u(as_str(data["signature"])),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise LogError("malformed signed head") from exc


def _head_bytes(size: int, head_hash: bytes, ts: int) -> bytes:
    return LOG_HEAD_TAG + size.to_bytes(8, "big") + head_hash + ts.to_bytes(8, "big")


def sign_head(
    log_key: ed25519.Ed25519PrivateKey, size: int, head_hash: bytes, ts: int
) -> SignedHead:
    """Sign the current head with the dedicated log key."""
    return SignedHead(size, head_hash, ts, log_key.sign(_head_bytes(size, head_hash, ts)))


def verify_head(log_public: ed25519.Ed25519PublicKey, head: SignedHead) -> None:
    """Verify a signed head.

    Raises:
        LogError: If the signature is invalid.
    """
    try:
        log_public.verify(head.signature, _head_bytes(head.size, head.head_hash, head.ts))
    except InvalidSignature as exc:
        raise LogError("invalid log head signature") from exc


def active_record_for(records: list[LogRecord], scope: int, now: int) -> LogRecord | None:
    """The currently active key record for a scope, honoring later status changes.

    A key's effective status is its latest record's status. Among keys whose
    effective status is ``active`` and whose validity window covers ``now``,
    the highest epoch wins.
    """
    latest_by_key: dict[bytes, LogRecord] = {}
    for record in records:
        if record.scope == scope:
            latest_by_key[record.key_id] = record
    candidates = [
        r
        for r in latest_by_key.values()
        if r.status == "active" and r.not_before <= now <= r.not_after
    ]
    return max(candidates, key=lambda r: r.epoch, default=None)


def to_jsonl(records: list[LogRecord]) -> str:
    """Serialize the log as JSON Lines."""
    return "".join(json.dumps(r.to_json_dict(), separators=(",", ":")) + "\n" for r in records)


def from_jsonl(text: str) -> list[LogRecord]:
    """Parse a JSON Lines log. Callers must run :func:`verify_chain` afterwards.

    Raises:
        LogError: On undecodable lines.
    """
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LogError("undecodable log line") from exc
        records.append(LogRecord.from_json_dict(data))
    return records
