"""Federation scope keys, key policy, and keyset serialization.

Key policy (normative, RFC 9474 Section 7.5 key-substitution considerations):
``e = 65537`` exactly, modulus in {2048, 3072, 4096} bits, and scope keys are
used for nothing but this protocol. The policy is enforced wherever a public
key enters the system (UA and verifier), so a substituted or malformed key is
a loud error.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from zkage_core.encoding import as_int, as_str, b64u, unb64u

ALLOWED_MODULUS_BITS = (2048, 3072, 4096)
REQUIRED_PUBLIC_EXPONENT = 65537
KEY_STATUSES = ("active", "retired", "revoked")


class KeyPolicyError(Exception):
    """A public key violates the federation key policy."""


def generate_scope_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    """Generate a federation scope keypair (demo default 2048; production 3072+).

    Raises:
        KeyPolicyError: If ``bits`` is not an allowed modulus size.
    """
    if bits not in ALLOWED_MODULUS_BITS:
        raise KeyPolicyError(f"modulus bits must be one of {ALLOWED_MODULUS_BITS}")
    return rsa.generate_private_key(public_exponent=REQUIRED_PUBLIC_EXPONENT, key_size=bits)


def spki_der(public_key: rsa.RSAPublicKey) -> bytes:
    """DER-encoded SubjectPublicKeyInfo for a public key."""
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def key_id_of(public_key: rsa.RSAPublicKey) -> bytes:
    """key_id = SHA-256 of the DER SPKI."""
    return hashlib.sha256(spki_der(public_key)).digest()


def load_public_key(spki: bytes) -> rsa.RSAPublicKey:
    """Load and policy-check a public key from DER SPKI bytes.

    Raises:
        KeyPolicyError: If the key is not RSA, has the wrong exponent, or a
            disallowed modulus size.
    """
    try:
        key = serialization.load_der_public_key(spki)
    except Exception as exc:
        raise KeyPolicyError("undecodable SPKI") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyPolicyError("scope keys must be RSA")
    numbers = key.public_numbers()
    if numbers.e != REQUIRED_PUBLIC_EXPONENT:
        raise KeyPolicyError("public exponent must be 65537")
    if numbers.n.bit_length() not in ALLOWED_MODULUS_BITS:
        raise KeyPolicyError(f"modulus bits must be one of {ALLOWED_MODULUS_BITS}")
    return key


def private_key_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize a private key to unencrypted PKCS#8 PEM (demo state only)."""
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def load_private_key_pem(pem: bytes) -> rsa.RSAPrivateKey:
    """Load a private key from PKCS#8 PEM."""
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyPolicyError("scope private keys must be RSA")
    return key


@dataclass(frozen=True)
class ScopeKeyRecord:
    """Public metadata for one federation scope key epoch.

    This is what relying parties pin (their trusted keyset) and what the
    transparency log records.
    """

    scope: int
    epoch: int
    key_id: bytes
    spki: bytes
    not_before: int
    not_after: int
    status: str

    def public_key(self) -> rsa.RSAPublicKey:
        """Load and policy-check this record's public key."""
        key = load_public_key(self.spki)
        if hashlib.sha256(self.spki).digest() != self.key_id:
            raise KeyPolicyError("key_id does not match SPKI")
        return key

    def to_json_dict(self) -> dict[str, object]:
        return {
            "scope": self.scope,
            "epoch": self.epoch,
            "key_id": b64u(self.key_id),
            "spki": b64u(self.spki),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "status": self.status,
        }

    @classmethod
    def from_json_dict(cls, data: dict[str, object]) -> ScopeKeyRecord:
        try:
            record = cls(
                scope=as_int(data["scope"]),
                epoch=as_int(data["epoch"]),
                key_id=unb64u(as_str(data["key_id"])),
                spki=unb64u(as_str(data["spki"])),
                not_before=as_int(data["not_before"]),
                not_after=as_int(data["not_after"]),
                status=as_str(data["status"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise KeyPolicyError("malformed scope key record") from exc
        if record.status not in KEY_STATUSES:
            raise KeyPolicyError("unknown key status")
        if len(record.key_id) != 32:
            raise KeyPolicyError("key_id must be 32 bytes")
        return record


def keyset_to_json_dict(records: list[ScopeKeyRecord]) -> dict[str, object]:
    """Serialize a keyset (e.g., the RP's pinned trust anchors)."""
    return {"version": 1, "keys": [r.to_json_dict() for r in records]}


def keyset_from_json_dict(data: dict[str, object]) -> list[ScopeKeyRecord]:
    """Parse a keyset; strict."""
    keys_raw = data.get("keys")
    if data.get("version") != 1 or not isinstance(keys_raw, list):
        raise KeyPolicyError("malformed keyset")
    records = []
    for item in keys_raw:
        if not isinstance(item, dict):
            raise KeyPolicyError("malformed keyset entry")
        records.append(ScopeKeyRecord.from_json_dict(item))
    return records
