"""v1 token and challenge wire formats.

The signed payload is a fixed-width binary struct (Privacy Pass style): exactly
one valid encoding per token, parsed strictly, never re-serialized for
verification. The signature always covers the exact transmitted bytes.

Prepared message layout (154 bytes), where ``prefix`` is the RFC 9474
PrepareRandomize randomizer::

    prefix            32   CSPRNG (RFC 9474 msg_prefix)
    tag               15   b"zkage/v1/token\\x00"
    token_type         2   uint16 BE; 0x0001 = v1 interactive RSABSSA
    scope_id           1   uint8: one of 13|16|18|21
    key_id            32   SHA-256 of the federation scope key SPKI (DER)
    challenge_digest  32   SHA-256 over the canonical challenge (binds rp_id)
    nonce             32   RP challenge nonce, verbatim
    expiry             8   uint64 BE unix seconds (copied from the challenge)

Wire token = prepared_msg || RSASSA-PSS signature (modulus length).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from zkage_core.encoding import b64u, unb64u

TOKEN_TAG = b"zkage/v1/token\x00"
CHALLENGE_TAG = b"zkage/v1/challenge\x00"
TOKEN_TYPE_V1 = 0x0001
SCOPES = (13, 16, 18, 21)

PREFIX_LEN = 32
MSG_LEN = 122
PREPARED_LEN = PREFIX_LEN + MSG_LEN  # 154
NONCE_LEN = 32
KEY_ID_LEN = 32
DIGEST_LEN = 32

#: Verifier-side guard against misconfigured RPs issuing long-lived challenges.
MAX_TOKEN_LIFETIME = 600
DEFAULT_CHALLENGE_TTL = 300


class TokenFormatError(Exception):
    """The byte string is not a well-formed v1 token."""


class ChallengeFormatError(Exception):
    """The challenge violates the v1 format."""


def challenge_digest(rp_id: str, scope: int, nonce: bytes, expires_at: int) -> bytes:
    """Compute the canonical challenge digest bound into the token.

    Args:
        rp_id: Relying-party identifier (e.g., its hostname).
        scope: Age scope (13, 16, 18, or 21).
        nonce: The RP's 32-byte challenge nonce.
        expires_at: Challenge expiry, unix seconds.

    Returns:
        SHA-256 over the domain-separated canonical challenge encoding.

    Raises:
        ChallengeFormatError: If any field is out of specification.
    """
    rp = rp_id.encode("utf-8")
    if not 0 < len(rp) <= 0xFFFF:
        raise ChallengeFormatError("rp_id must encode to 1..65535 bytes")
    if scope not in SCOPES:
        raise ChallengeFormatError(f"scope must be one of {SCOPES}")
    if len(nonce) != NONCE_LEN:
        raise ChallengeFormatError("nonce must be 32 bytes")
    if not 0 <= expires_at < 2**64:
        raise ChallengeFormatError("expires_at out of range")
    payload = (
        CHALLENGE_TAG
        + len(rp).to_bytes(2, "big")
        + rp
        + bytes([scope])
        + nonce
        + expires_at.to_bytes(8, "big")
    )
    return hashlib.sha256(payload).digest()


@dataclass(frozen=True)
class Challenge:
    """An RP-issued verification challenge.

    Attributes:
        rp_id: Relying-party identifier.
        scope: Required age scope.
        nonce: 32-byte CSPRNG nonce (the replay-cache index).
        expires_at: Unix-seconds expiry.
        log_head: The RP's current view of the transparency-log head hash
            (split-view gossip input for the UA); not part of the digest.
    """

    rp_id: str
    scope: int
    nonce: bytes
    expires_at: int
    log_head: bytes | None = None

    def digest(self) -> bytes:
        """The canonical digest binding rp_id, scope, nonce, and expiry."""
        return challenge_digest(self.rp_id, self.scope, self.nonce, self.expires_at)

    def to_json_dict(self) -> dict[str, object]:
        """Transport encoding (binary fields as unpadded base64url)."""
        out: dict[str, object] = {
            "version": 1,
            "rp_id": self.rp_id,
            "scope": self.scope,
            "nonce": b64u(self.nonce),
            "expires_at": self.expires_at,
        }
        if self.log_head is not None:
            out["log_head"] = b64u(self.log_head)
        return out

    @classmethod
    def from_json_dict(cls, data: dict[str, object]) -> Challenge:
        """Parse the transport encoding; strict on types and lengths."""
        try:
            if data.get("version") != 1:
                raise ChallengeFormatError("unsupported challenge version")
            rp_id = data["rp_id"]
            scope = data["scope"]
            nonce = unb64u(str(data["nonce"]))
            expires_at = data["expires_at"]
            raw_head = data.get("log_head")
            log_head = unb64u(str(raw_head)) if raw_head is not None else None
        except (KeyError, ValueError, TypeError) as exc:
            raise ChallengeFormatError("malformed challenge") from exc
        if (
            not isinstance(rp_id, str)
            or not isinstance(scope, int)
            or not isinstance(expires_at, int)
        ):
            raise ChallengeFormatError("malformed challenge field types")
        if log_head is not None and len(log_head) != DIGEST_LEN:
            raise ChallengeFormatError("log_head must be 32 bytes")
        challenge = cls(rp_id, scope, nonce, expires_at, log_head)
        challenge.digest()  # validates scope/nonce/expiry ranges
        return challenge


def make_challenge(
    rp_id: str,
    scope: int,
    now: int,
    *,
    ttl: int = DEFAULT_CHALLENGE_TTL,
    log_head: bytes | None = None,
    nonce: bytes | None = None,
) -> Challenge:
    """Create a fresh challenge with a CSPRNG nonce.

    RP implementers should always use this rather than rolling their own nonce.

    Args:
        rp_id: Relying-party identifier.
        scope: Required age scope.
        now: Current unix seconds (explicit — core takes no ambient clock).
        ttl: Challenge lifetime in seconds (bounded by MAX_TOKEN_LIFETIME).
        log_head: RP's current transparency-log head hash, if it tracks one.
        nonce: Injectable nonce for tests; generated if omitted.

    Raises:
        ChallengeFormatError: If ttl is out of bounds or fields are invalid.
    """
    if not 0 < ttl <= MAX_TOKEN_LIFETIME:
        raise ChallengeFormatError(f"ttl must be in (0, {MAX_TOKEN_LIFETIME}]")
    challenge = Challenge(
        rp_id=rp_id,
        scope=scope,
        nonce=nonce if nonce is not None else secrets.token_bytes(NONCE_LEN),
        expires_at=now + ttl,
        log_head=log_head,
    )
    challenge.digest()  # validate eagerly
    return challenge


def encode_token_msg(
    scope_id: int, key_id: bytes, challenge_dig: bytes, nonce: bytes, expiry: int
) -> bytes:
    """Encode the 122-byte token message (the input to RFC 9474 ``prepare``).

    Raises:
        TokenFormatError: If any field violates the layout.
    """
    if scope_id not in SCOPES:
        raise TokenFormatError(f"scope_id must be one of {SCOPES}")
    if len(key_id) != KEY_ID_LEN:
        raise TokenFormatError("key_id must be 32 bytes")
    if len(challenge_dig) != DIGEST_LEN:
        raise TokenFormatError("challenge_digest must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise TokenFormatError("nonce must be 32 bytes")
    if not 0 <= expiry < 2**64:
        raise TokenFormatError("expiry out of range")
    msg = (
        TOKEN_TAG
        + TOKEN_TYPE_V1.to_bytes(2, "big")
        + bytes([scope_id])
        + key_id
        + challenge_dig
        + nonce
        + expiry.to_bytes(8, "big")
    )
    assert len(msg) == MSG_LEN
    return msg


def token_msg_for_challenge(challenge: Challenge, key_id: bytes) -> bytes:
    """Build the token message binding a challenge under a given scope key."""
    return encode_token_msg(
        challenge.scope, key_id, challenge.digest(), challenge.nonce, challenge.expires_at
    )


@dataclass(frozen=True)
class TokenFields:
    """A structurally valid parsed token (cryptographically unverified).

    Attributes:
        scope_id: Age scope encoded in the token.
        key_id: SHA-256 of the claimed federation scope key SPKI.
        challenge_digest: The bound canonical challenge digest.
        nonce: The bound RP nonce.
        expiry: The bound expiry (unix seconds).
        prepared_msg: The exact 154 signed bytes (prefix included).
        signature: The RSASSA-PSS signature bytes (length checked against the
            key at verification time, not here).
    """

    scope_id: int
    key_id: bytes
    challenge_digest: bytes
    nonce: bytes
    expiry: int
    prepared_msg: bytes
    signature: bytes


def encode_token(prepared_msg: bytes, signature: bytes) -> bytes:
    """Concatenate the wire token. The signature covers ``prepared_msg`` exactly."""
    if len(prepared_msg) != PREPARED_LEN:
        raise TokenFormatError("prepared_msg must be 154 bytes")
    if not signature:
        raise TokenFormatError("signature must be non-empty")
    return prepared_msg + signature


def parse_token(wire: bytes) -> TokenFields:
    """Strictly parse a wire token; structural checks before any cryptography.

    Args:
        wire: ``prepared_msg || signature``.

    Returns:
        The parsed fields, including the exact signed bytes.

    Raises:
        TokenFormatError: On any structural violation (length, tag, type, scope).
    """
    if len(wire) <= PREPARED_LEN:
        raise TokenFormatError("token too short")
    prepared, signature = wire[:PREPARED_LEN], wire[PREPARED_LEN:]
    msg = prepared[PREFIX_LEN:]
    if msg[:15] != TOKEN_TAG:
        raise TokenFormatError("bad token tag")
    token_type = int.from_bytes(msg[15:17], "big")
    if token_type != TOKEN_TYPE_V1:
        raise TokenFormatError("unsupported token type")
    scope_id = msg[17]
    if scope_id not in SCOPES:
        raise TokenFormatError("unknown scope")
    return TokenFields(
        scope_id=scope_id,
        key_id=msg[18:50],
        challenge_digest=msg[50:82],
        nonce=msg[82:114],
        expiry=int.from_bytes(msg[114:122], "big"),
        prepared_msg=prepared,
        signature=signature,
    )
