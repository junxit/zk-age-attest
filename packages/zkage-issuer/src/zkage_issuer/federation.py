"""Federation state: scope signing keys, log key, and the transparency log.

State directory layout (created by ``scripts/init_federation.py``)::

    <state>/
      issuer/
        scope_keys/<scope>_<epoch>.pem   RSA private keys (demo: unencrypted)
        log_key.pem                      Ed25519 log-signing key
        issuer.sqlite                    accounts + request ids (runtime)
      public/
        log.jsonl                        the transparency log
        log_head.json                    signed head (re-signed at app start
                                         and by every rotate/revoke)
        keyset.json                      active-keys projection for RPs
        log_pub.b64                      raw log public key (UA pinning, TOFU)

Lifecycle: :func:`rotate_scope_key` introduces a new epoch for a scope (the
previous key is retired immediately — the one-key-per-scope keyset projection
gives a grace period no meaning), and :func:`revoke_scope_key` is the DESIGN.md
§4 compromise response. Both append to the hash chain and re-publish the signed
head atomically; a running issuer picks changes up via
``FederationState.maybe_reload``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from zkage_core import keys, translog
from zkage_core.encoding import b64u
from zkage_core.token import SCOPES

DEFAULT_VALIDITY = 90 * 86_400


class FederationStateError(Exception):
    """The state directory is missing, incomplete, or inconsistent."""


def _ed25519_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _load_ed25519_pem(pem: bytes) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise FederationStateError("log key must be Ed25519")
    return key


def active_keyset(records: list[translog.LogRecord], now: int) -> list[keys.ScopeKeyRecord]:
    """Project the currently active key per scope out of the log."""
    out = []
    for scope in SCOPES:
        record = translog.active_record_for(records, scope, now)
        if record is not None:
            out.append(record.to_scope_key_record())
    return out


def _read_log(state_dir: Path) -> list[translog.LogRecord]:
    """Load and chain-verify the transparency log from disk."""
    try:
        records = translog.from_jsonl((state_dir / "public" / "log.jsonl").read_text())
    except FileNotFoundError as exc:
        raise FederationStateError(
            f"federation state missing in {state_dir}; run scripts/init_federation.py"
        ) from exc
    except translog.LogError as exc:
        raise FederationStateError(f"corrupt transparency log: {exc}") from exc
    translog.verify_chain(records)  # guarded above; belt-and-suspenders
    return records


def _publish(state_dir: Path, records: list[translog.LogRecord], now: int) -> None:
    """Atomically re-publish the log, signed head, and RP keyset projection."""
    public_dir = state_dir / "public"
    log_key = _load_ed25519_pem((state_dir / "issuer" / "log_key.pem").read_bytes())
    head_hash = translog.verify_chain(records)
    head = translog.sign_head(log_key, len(records), head_hash, now)

    _write_json_atomic(public_dir / "log_head.json", head.to_json_dict())
    _write_json_atomic(
        public_dir / "keyset.json", keys.keyset_to_json_dict(active_keyset(records, now))
    )
    _write_text_atomic(public_dir / "log.jsonl", translog.to_jsonl(records))


def _write_text_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def _write_json_atomic(path: Path, data: dict[str, object]) -> None:
    import json

    _write_text_atomic(path, json.dumps(data, indent=1) + "\n")


def rotate_scope_key(
    state_dir: Path,
    scope: int,
    now: int,
    *,
    bits: int = 2048,
    validity_seconds: int = DEFAULT_VALIDITY,
) -> keys.ScopeKeyRecord:
    """Introduce epoch N+1 for ``scope``: new active key, previous key retired.

    Rotation is safe against an already-revoked scope (no retirement record is
    appended when nothing is active). The new private key is written to
    ``issuer/scope_keys/<scope>_<N+1>.pem``; the log, signed head, and keyset
    are republished atomically.

    Returns:
        The new active key record.

    Raises:
        FederationStateError: If the state is missing/corrupt, the scope has no
            key history, or the modulus size violates key policy.
    """
    if scope not in SCOPES:
        raise FederationStateError(f"scope must be one of {SCOPES}")
    records = _read_log(state_dir)
    prior_epochs = [r.epoch for r in records if r.scope == scope]
    if not prior_epochs:
        raise FederationStateError(f"no key history for scope {scope}")
    current = translog.active_record_for(records, scope, now)
    if current is not None:
        # Retire first so the chain narrates retire → activate.
        records.append(
            translog.append_record(
                records,
                ts=now,
                scope=current.scope,
                epoch=current.epoch,
                key_id=current.key_id,
                spki=current.spki,
                not_before=current.not_before,
                not_after=now,  # validity ends at rotation time
                status="retired",
            )
        )

    epoch = max(prior_epochs) + 1
    private = keys.generate_scope_key(bits)
    public = private.public_key()
    (state_dir / "issuer" / "scope_keys" / f"{scope}_{epoch}.pem").write_bytes(
        keys.private_key_pem(private)
    )
    new_record = translog.append_record(
        records,
        ts=now,
        scope=scope,
        epoch=epoch,
        key_id=keys.key_id_of(public),
        spki=keys.spki_der(public),
        not_before=now,
        not_after=now + validity_seconds,
        status="active",
    )
    records.append(new_record)
    _publish(state_dir, records, now)
    return new_record.to_scope_key_record()


def revoke_scope_key(state_dir: Path, scope: int, now: int) -> None:
    """Append a ``revoked`` record for the active key of ``scope`` (DESIGN §4).

    After revocation the scope has no active key: the issuer refuses issuance
    for it, RPs drop it from their refreshed keysets, and pinned UAs fail
    closed before any issuance. Recovery is a fresh :func:`rotate_scope_key`.

    Raises:
        FederationStateError: If the state is missing/corrupt or the scope has
            no currently active key.
    """
    if scope not in SCOPES:
        raise FederationStateError(f"scope must be one of {SCOPES}")
    records = _read_log(state_dir)
    current = translog.active_record_for(records, scope, now)
    if current is None:
        raise FederationStateError(f"no active key for scope {scope}")
    records.append(
        translog.append_record(
            records,
            ts=now,
            scope=current.scope,
            epoch=current.epoch,
            key_id=current.key_id,
            spki=current.spki,
            not_before=current.not_before,
            not_after=current.not_after,
            status="revoked",
        )
    )
    _publish(state_dir, records, now)


def init_state(
    state_dir: Path,
    now: int,
    *,
    bits: int = 2048,
    validity_seconds: int = DEFAULT_VALIDITY,
) -> None:
    """Create a fresh federation state: one key per scope, genesis log, head.

    Raises:
        FederationStateError: If the directory already contains a federation.
    """
    issuer_dir = state_dir / "issuer"
    public_dir = state_dir / "public"
    if (public_dir / "log.jsonl").exists():
        raise FederationStateError(f"federation already initialized in {state_dir}")
    (issuer_dir / "scope_keys").mkdir(parents=True, exist_ok=True)
    public_dir.mkdir(parents=True, exist_ok=True)

    log_key = ed25519.Ed25519PrivateKey.generate()
    (issuer_dir / "log_key.pem").write_bytes(_ed25519_pem(log_key))
    log_pub_raw = log_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    (public_dir / "log_pub.b64").write_text(b64u(log_pub_raw) + "\n")

    # Demo attestation-authority key for the ``signed`` attester (see
    # attester.py). Production authorities are external; this one stands in.
    attester_key = ed25519.Ed25519PrivateKey.generate()
    (issuer_dir / "attester_key.pem").write_bytes(_ed25519_pem(attester_key))
    attester_pub_raw = attester_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    (public_dir / "attester_pub.b64").write_text(b64u(attester_pub_raw) + "\n")

    records: list[translog.LogRecord] = []
    for scope in SCOPES:
        private = keys.generate_scope_key(bits)
        public = private.public_key()
        (issuer_dir / "scope_keys" / f"{scope}_1.pem").write_bytes(keys.private_key_pem(private))
        records.append(
            translog.append_record(
                records,
                ts=now,
                scope=scope,
                epoch=1,
                key_id=keys.key_id_of(public),
                spki=keys.spki_der(public),
                not_before=now,
                not_after=now + validity_seconds,
                status="active",
            )
        )

    head_hash = translog.verify_chain(records)
    (public_dir / "log.jsonl").write_text(translog.to_jsonl(records))
    head = translog.sign_head(log_key, len(records), head_hash, now)
    _write_json(public_dir / "log_head.json", head.to_json_dict())
    _write_json(public_dir / "keyset.json", keys.keyset_to_json_dict(active_keyset(records, now)))


def _write_json(path: Path, data: dict[str, object]) -> None:
    import json

    path.write_text(json.dumps(data, indent=1) + "\n")


@dataclass
class FederationState:
    """Loaded federation state used by the issuer app."""

    state_dir: Path
    records: list[translog.LogRecord]
    log_key: ed25519.Ed25519PrivateKey
    signed_head: translog.SignedHead
    log_public_raw: bytes
    _scope_keys: dict[tuple[int, int], rsa.RSAPrivateKey]
    _log_mtime_ns: int = 0

    @classmethod
    def load(cls, state_dir: Path, now: int) -> FederationState:
        """Load and verify state; the head is re-signed with a fresh timestamp.

        Raises:
            FederationStateError: On missing files or a corrupt log.
        """
        issuer_dir = state_dir / "issuer"
        public_dir = state_dir / "public"
        log_path = public_dir / "log.jsonl"
        try:
            records = translog.from_jsonl(log_path.read_text())
            head_hash = translog.verify_chain(records)
            log_key = _load_ed25519_pem((issuer_dir / "log_key.pem").read_bytes())
            log_mtime_ns = log_path.stat().st_mtime_ns
        except FileNotFoundError as exc:
            raise FederationStateError(
                f"federation state missing in {state_dir}; run scripts/init_federation.py"
            ) from exc
        except translog.LogError as exc:
            raise FederationStateError(f"corrupt transparency log: {exc}") from exc

        scope_keys: dict[tuple[int, int], rsa.RSAPrivateKey] = {}
        for pem_path in sorted((issuer_dir / "scope_keys").glob("*_*.pem")):
            scope_s, epoch_s = pem_path.stem.split("_", 1)
            scope_keys[(int(scope_s), int(epoch_s))] = keys.load_private_key_pem(
                pem_path.read_bytes()
            )

        log_public_raw = log_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        signed_head = translog.sign_head(log_key, len(records), head_hash, now)
        return cls(
            state_dir, records, log_key, signed_head, log_public_raw, scope_keys, log_mtime_ns
        )

    def maybe_reload(self, now: int) -> None:
        """Reload state if the on-disk transparency log changed (mtime probe).

        Lets a running issuer pick up rotations/revocations written by
        ``scripts/rotate_key.py`` / ``revoke_key.py`` without a restart. The
        probe is a single ``stat``; a failed stat keeps the current view.
        """
        log_path = self.state_dir / "public" / "log.jsonl"
        try:
            mtime_ns = log_path.stat().st_mtime_ns
        except OSError:
            return
        if mtime_ns == self._log_mtime_ns:
            return
        fresh = FederationState.load(self.state_dir, now=now)
        self.__dict__.update(fresh.__dict__)

    def active_key(self, scope: int, now: int) -> tuple[translog.LogRecord, rsa.RSAPrivateKey]:
        """The active log record and private key for a scope.

        Raises:
            FederationStateError: If no active key exists or its PEM is missing.
        """
        record = translog.active_record_for(self.records, scope, now)
        if record is None:
            raise FederationStateError(f"no active key for scope {scope}")
        private = self._scope_keys.get((record.scope, record.epoch))
        if private is None:
            raise FederationStateError(f"missing private key for scope {scope}")
        if keys.key_id_of(private.public_key()) != record.key_id:
            raise FederationStateError(f"private key does not match log for scope {scope}")
        return record, private
