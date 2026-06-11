"""Pure offline token verification.

``verify_token`` is a pure function: trusted keys, the expected challenge, and
the current time are explicit parameters; it performs no I/O of any kind.
Structural checks run before any cryptography, every failure maps to a precise
:class:`Decision` code (for the RP's internal logs), and RPs are expected to
collapse all non-OK decisions into one uniform external error so the token
state is not an oracle.

The verification path runs zero hand-rolled cryptography: the final check is a
standard RSASSA-PSS verify through OpenSSL via ``cryptography``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, unique

from zkage_core import rsabssa
from zkage_core.keys import KeyPolicyError, ScopeKeyRecord
from zkage_core.token import (
    MAX_TOKEN_LIFETIME,
    Challenge,
    TokenFormatError,
    parse_token,
)


@unique
class Decision(Enum):
    """Exhaustive verification outcomes (internal logging granularity)."""

    OK = "ok"
    MALFORMED = "malformed"
    WRONG_SCOPE = "wrong_scope"
    UNKNOWN_KEY = "unknown_key"
    KEY_SCOPE_MISMATCH = "key_scope_mismatch"
    KEY_NOT_VALID = "key_not_valid"
    CHALLENGE_MISMATCH = "challenge_mismatch"
    EXPIRED = "expired"
    EXPIRY_TOO_FAR = "expiry_too_far"
    BAD_KEY = "bad_key"
    BAD_SIGNATURE_LENGTH = "bad_signature_length"
    BAD_SIGNATURE = "bad_signature"


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of one token verification.

    Attributes:
        decision: The precise outcome code.
        scope: The verified age scope; set only when ``decision is Decision.OK``.
    """

    decision: Decision
    scope: int | None = None

    @property
    def ok(self) -> bool:
        """True when the token verified."""
        return self.decision is Decision.OK


def verify_token(
    wire: bytes,
    trusted_keys: list[ScopeKeyRecord],
    expected: Challenge,
    now: int,
) -> VerifyResult:
    """Verify a redeemed token against one pending challenge. Pure; no I/O.

    The caller MUST have atomically popped the pending challenge keyed by its
    nonce before calling (pop-before-verify), and MUST treat every non-OK
    decision identically in external responses.

    Args:
        wire: The redeemed token bytes (``prepared_msg || signature``).
        trusted_keys: The RP's pinned federation keyset.
        expected: The pending challenge this redemption claims to answer.
        now: Current unix seconds (explicit; the verifier takes no clock).

    Returns:
        A :class:`VerifyResult`; ``scope`` is set on success.
    """
    # 1. Structural parse — exact layout, tag, type, scope alphabet.
    try:
        fields = parse_token(wire)
    except TokenFormatError:
        return VerifyResult(Decision.MALFORMED)

    # 2. The token must claim exactly the challenged scope.
    if fields.scope_id != expected.scope:
        return VerifyResult(Decision.WRONG_SCOPE)

    # 3. The claimed key must be pinned.
    record = next((r for r in trusted_keys if r.key_id == fields.key_id), None)
    if record is None:
        return VerifyResult(Decision.UNKNOWN_KEY)

    # 4. Cross-check key scope == token scope (key-confusion is a loud error).
    if record.scope != fields.scope_id:
        return VerifyResult(Decision.KEY_SCOPE_MISMATCH)

    # 5. The key must be active and inside its validity window.
    if record.status != "active" or not record.not_before <= now <= record.not_after:
        return VerifyResult(Decision.KEY_NOT_VALID)

    # 6. Challenge binding: nonce, expiry, and the digest (which also binds
    #    rp_id) must all match the pending challenge.
    if (
        fields.nonce != expected.nonce
        or fields.expiry != expected.expires_at
        or fields.challenge_digest != expected.digest()
    ):
        return VerifyResult(Decision.CHALLENGE_MISMATCH)

    # 7. Freshness, with a guard against misconfigured long-lived challenges.
    if fields.expiry <= now:
        return VerifyResult(Decision.EXPIRED)
    if fields.expiry - now > MAX_TOKEN_LIFETIME:
        return VerifyResult(Decision.EXPIRY_TOO_FAR)

    # 8. Key policy (RSA, e=65537, allowed modulus, SPKI matches key_id).
    try:
        public_key = record.public_key()
    except KeyPolicyError:
        return VerifyResult(Decision.BAD_KEY)
    if len(fields.signature) != (public_key.public_numbers().n.bit_length() + 7) // 8:
        return VerifyResult(Decision.BAD_SIGNATURE_LENGTH)

    # 9. Cryptographic verification, last: standard RSASSA-PSS via OpenSSL.
    try:
        rsabssa.verify(public_key, fields.prepared_msg, fields.signature)
    except rsabssa.InvalidSignatureError:
        return VerifyResult(Decision.BAD_SIGNATURE)

    return VerifyResult(Decision.OK, scope=fields.scope_id)
