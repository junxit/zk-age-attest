"""Ed25519 device keys and issuance-request binding.

The issuance signature MUST cover the hash of the blinded message (plus a
timestamp and request id). Without that binding, anyone could attach a
stranger's blinded message to their own authorized request — industrialized
token proxying. With it, an issuance request authorizes exactly one blinded
message, once, within a narrow time window.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ISSUANCE_TAG = b"zkage/v1/issuance\x00"
ACCOUNT_ID_LEN = 16
REQUEST_ID_LEN = 16

#: Maximum allowed clock skew between UA and issuer for issuance requests.
ISSUANCE_TS_WINDOW = 60


class IssuanceBindingError(Exception):
    """The issuance request binding is malformed or its signature is invalid."""


def generate_device_key() -> ed25519.Ed25519PrivateKey:
    """Generate a device keypair (demo keystore; production: secure hardware)."""
    return ed25519.Ed25519PrivateKey.generate()


def device_public_raw(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Raw 32-byte public key for storage/transport."""
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def device_private_raw(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Raw 32-byte private key for the demo JSON keystore."""
    return private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def load_device_private(raw: bytes) -> ed25519.Ed25519PrivateKey:
    """Load a device private key from raw bytes."""
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def load_device_public(raw: bytes) -> ed25519.Ed25519PublicKey:
    """Load a device public key from raw bytes.

    Raises:
        IssuanceBindingError: If the bytes are not a valid Ed25519 public key.
    """
    try:
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise IssuanceBindingError("invalid device public key") from exc


def issuance_payload(
    account_id: bytes, scope_id: int, blinded_msg: bytes, ts: int, request_id: bytes
) -> bytes:
    """Canonical bytes the device key signs for one issuance request.

    Layout: tag || account_id(16) || scope_id(1) || SHA256(blinded_msg) ||
    ts(8, BE) || request_id(16).

    Raises:
        IssuanceBindingError: If any field violates the layout.
    """
    if len(account_id) != ACCOUNT_ID_LEN:
        raise IssuanceBindingError("account_id must be 16 bytes")
    if not 0 <= scope_id <= 0xFF:
        raise IssuanceBindingError("scope_id out of range")
    if not blinded_msg:
        raise IssuanceBindingError("blinded_msg must be non-empty")
    if not 0 <= ts < 2**64:
        raise IssuanceBindingError("ts out of range")
    if len(request_id) != REQUEST_ID_LEN:
        raise IssuanceBindingError("request_id must be 16 bytes")
    return (
        ISSUANCE_TAG
        + account_id
        + bytes([scope_id])
        + hashlib.sha256(blinded_msg).digest()
        + ts.to_bytes(8, "big")
        + request_id
    )


def sign_issuance(
    private_key: ed25519.Ed25519PrivateKey,
    account_id: bytes,
    scope_id: int,
    blinded_msg: bytes,
    ts: int,
    request_id: bytes,
) -> bytes:
    """Sign one issuance request with the device key."""
    return private_key.sign(issuance_payload(account_id, scope_id, blinded_msg, ts, request_id))


def verify_issuance(
    public_key: ed25519.Ed25519PublicKey,
    signature: bytes,
    account_id: bytes,
    scope_id: int,
    blinded_msg: bytes,
    ts: int,
    request_id: bytes,
) -> None:
    """Verify an issuance-request signature.

    Raises:
        IssuanceBindingError: If the signature does not cover exactly these fields.
    """
    payload = issuance_payload(account_id, scope_id, blinded_msg, ts, request_id)
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise IssuanceBindingError("invalid issuance signature") from exc
