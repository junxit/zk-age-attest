"""Pluggable attester interface.

The attester is the one component that ever touches identity, and it runs at
enrollment only. It returns nothing but a maximum age scope — the issuer never
sees a date of birth or a document. Real implementations (eID, mDL/EUDI proof,
bank check, commercial provider) plug in behind the same interface.
"""

from __future__ import annotations

import base64
import secrets
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from zkage_core.encoding import unb64u
from zkage_core.token import SCOPES


class AttestationError(Exception):
    """The attester could not establish any age scope for this enrollment."""


class Attester(Protocol):
    """Establishes the maximum age scope for an enrolling user."""

    name: str

    def attest(self, claim: dict[str, object]) -> int:
        """Return the maximum scope this user may request (13/16/18/21).

        Raises:
            AttestationError: If no scope can be established.
        """
        ...


def _max_scope_for_age(age: int) -> int:
    eligible = [s for s in SCOPES if age >= s]
    if not eligible:
        raise AttestationError("no age scope attestable")
    return max(eligible)


class StubAttester:
    """DEMO ONLY: trusts a self-declared age. Exists to exercise the protocol.

    The token-issuance protocol is independent of attestation strength; this
    stub stands in where a real eID/mDL/bank attester would integrate.
    """

    name = "stub"

    def attest(self, claim: dict[str, object]) -> int:
        age = claim.get("claimed_age")
        if isinstance(age, bool) or not isinstance(age, int):
            raise AttestationError("claimed_age must be an integer")
        return _max_scope_for_age(int(age))


#: Domain separation + layout for a signed attestation claim:
#: tag(18) ‖ claimed_age(8, big-endian) ‖ nonce(16).
_ATTESTATION_TAG = b"zkage/v1/attest\x00"
_AGE_LEN = 8
_NONCE_LEN = 16


def sign_attestation(authority: ed25519.Ed25519PrivateKey, claimed_age: int, nonce: bytes) -> bytes:
    """Sign one enrollment claim as a mock attestation authority would.

    Raises:
        AttestationError: If the nonce is malformed.
    """
    if len(nonce) != _NONCE_LEN:
        raise AttestationError(f"attestation nonce must be {_NONCE_LEN} bytes")
    payload = _ATTESTATION_TAG + claimed_age.to_bytes(_AGE_LEN, "big") + nonce
    return authority.sign(payload)


class SignedClaimAttester:
    """Verifies an Ed25519-signed age claim from an attestation authority.

    Demonstrates the pluggability contract with real cryptography: the issuer
    learns only ``max_scope`` even though the claim travels signed. The demo
    authority key lives in the state directory (``init_federation.py``);
    production authorities would be external and their keys pinned.
    """

    name = "signed"

    def __init__(self, authority_public_raw: bytes) -> None:
        try:
            self._public = ed25519.Ed25519PublicKey.from_public_bytes(authority_public_raw)
        except Exception as exc:
            raise AttestationError("invalid attestation authority key") from exc

    def attest(self, claim: dict[str, object]) -> int:
        age = claim.get("claimed_age")
        if isinstance(age, bool) or not isinstance(age, int):
            raise AttestationError("claimed_age must be an integer")
        try:
            nonce = unb64u(str(claim.get("nonce", "")))
            signature = unb64u(str(claim.get("attestation", "")))
        except ValueError as exc:
            raise AttestationError("malformed attestation encoding") from exc
        payload = _ATTESTATION_TAG + int(age).to_bytes(_AGE_LEN, "big") + nonce
        try:
            self._public.verify(signature, payload)
        except InvalidSignature as exc:
            raise AttestationError("invalid attestation signature") from exc
        return _max_scope_for_age(int(age))


def fresh_claim_nonce() -> str:
    """A random nonce for :func:`sign_attestation`, base64url-encoded."""
    return base64.urlsafe_b64encode(secrets.token_bytes(_NONCE_LEN)).rstrip(b"=").decode("ascii")
