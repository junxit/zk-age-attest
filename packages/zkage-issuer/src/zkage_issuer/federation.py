"""Federation state: scope signing keys, log key, and the transparency log.

State directory layout (created by ``scripts/init_federation.py``)::

    <state>/
      issuer/
        scope_keys/<scope>_<epoch>.pem   RSA private keys (demo: unencrypted)
        log_key.pem                      Ed25519 log-signing key
        issuer.sqlite                    accounts + request ids (runtime)
      public/
        log.jsonl                        the transparency log
        log_head.json                    signed head (re-signed at app start)
        keyset.json                      active-keys projection for RPs
        log_pub.b64                      raw log public key (UA pinning, TOFU)
"""

from __future__ import annotations

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

    @classmethod
    def load(cls, state_dir: Path, now: int) -> FederationState:
        """Load and verify state; the head is re-signed with a fresh timestamp.

        Raises:
            FederationStateError: On missing files or a corrupt log.
        """
        issuer_dir = state_dir / "issuer"
        public_dir = state_dir / "public"
        try:
            records = translog.from_jsonl((public_dir / "log.jsonl").read_text())
            head_hash = translog.verify_chain(records)
            log_key = _load_ed25519_pem((issuer_dir / "log_key.pem").read_bytes())
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
        return cls(state_dir, records, log_key, signed_head, log_public_raw, scope_keys)

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
