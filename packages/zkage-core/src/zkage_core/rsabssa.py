"""RFC 9474 RSA Blind Signatures (RSABSSA).

Implements all four named variants of the RSA Blind Signature Scheme with
Appendix-A-vector-exact intermediates. The blinding path (``prepare``,
``blind``, ``blind_sign``, ``finalize``) is hand-rolled over big-int
arithmetic because no maintained RFC 9474 library exists for Python; the
final verification path (``verify``) delegates to OpenSSL-backed
RSASSA-PSS via ``cryptography`` so relying parties run zero hand-rolled
crypto.

All randomness is injectable (``prefix``, ``salt``, ``r_inv``) so the RFC
test vectors can pin every intermediate value.

Caveat (documented in THREAT-MODEL.md): Python big-int arithmetic is not
constant-time. ``blind_sign`` applies the RFC 9474 Section 7.1 signer-side
multiplicative blinding, but this implementation remains a research
prototype.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_HASH = hashlib.sha384
_H_LEN = 48
_PREFIX_LEN = 32


class RsabssaError(Exception):
    """Base error for RSABSSA operations."""


class EncodingError(RsabssaError):
    """EMSA-PSS encoding failed (RFC 9474: "encoding error")."""


class InvalidInputError(RsabssaError):
    """Input violates protocol preconditions (RFC 9474: "invalid input")."""


class BlindingError(RsabssaError):
    """The blinding factor is not invertible (RFC 9474: "blinding error")."""


class UnexpectedInputSizeError(RsabssaError):
    """A protocol value has the wrong length (RFC 9474: "unexpected input size")."""


class SigningFailureError(RsabssaError):
    """The signer self-check failed (RFC 9474: "signing failure")."""


class InvalidSignatureError(RsabssaError):
    """Signature verification failed (RFC 9474: "invalid signature")."""


@dataclass(frozen=True)
class Variant:
    """One of the four RFC 9474 named variants.

    Attributes:
        name: The RFC 9474 variant name.
        salt_len: PSS salt length in bytes (48 for PSS, 0 for PSSZERO).
        randomized: Whether ``prepare`` prepends a 32-byte random prefix.
    """

    name: str
    salt_len: int
    randomized: bool


RSABSSA_SHA384_PSS_RANDOMIZED = Variant("RSABSSA-SHA384-PSS-Randomized", 48, True)
RSABSSA_SHA384_PSSZERO_RANDOMIZED = Variant("RSABSSA-SHA384-PSSZERO-Randomized", 0, True)
RSABSSA_SHA384_PSS_DETERMINISTIC = Variant("RSABSSA-SHA384-PSS-Deterministic", 48, False)
RSABSSA_SHA384_PSSZERO_DETERMINISTIC = Variant("RSABSSA-SHA384-PSSZERO-Deterministic", 0, False)

VARIANTS: dict[str, Variant] = {
    v.name: v
    for v in (
        RSABSSA_SHA384_PSS_RANDOMIZED,
        RSABSSA_SHA384_PSSZERO_RANDOMIZED,
        RSABSSA_SHA384_PSS_DETERMINISTIC,
        RSABSSA_SHA384_PSSZERO_DETERMINISTIC,
    )
}

#: The variant this protocol uses (blindness holds unconditionally; RFC 9474 §7).
DEFAULT_VARIANT = RSABSSA_SHA384_PSS_RANDOMIZED


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _mgf1(seed: bytes, length: int) -> bytes:
    """MGF1 with SHA-384 (RFC 8017 Appendix B.2.1)."""
    out = bytearray()
    for counter in range((length + _H_LEN - 1) // _H_LEN):
        out += _HASH(seed + counter.to_bytes(4, "big")).digest()
    return bytes(out[:length])


def emsa_pss_encode(msg: bytes, em_bits: int, salt: bytes) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017 Section 9.1.1) with SHA-384/MGF1-SHA384.

    Args:
        msg: Message to encode (hashed internally).
        em_bits: Intended encoded-message bit length (``bit_len(n) - 1``).
        salt: PSS salt; its length is the effective ``sLen``.

    Returns:
        The encoded message EM of ``ceil(em_bits / 8)`` bytes.

    Raises:
        EncodingError: If ``em_bits`` is too small for the hash and salt.
    """
    m_hash = _HASH(msg).digest()
    em_len = (em_bits + 7) // 8
    s_len = len(salt)
    if em_len < _H_LEN + s_len + 2:
        raise EncodingError("encoding error")
    m_prime = b"\x00" * 8 + m_hash + salt
    h = _HASH(m_prime).digest()
    ps = b"\x00" * (em_len - s_len - _H_LEN - 2)
    db = ps + b"\x01" + salt
    db_mask = _mgf1(h, em_len - _H_LEN - 1)
    masked_db = bytearray(a ^ b for a, b in zip(db, db_mask, strict=True))
    excess_bits = 8 * em_len - em_bits
    if excess_bits:
        masked_db[0] &= 0xFF >> excess_bits
    return bytes(masked_db) + h + b"\xbc"


def prepare(
    msg: bytes, variant: Variant = DEFAULT_VARIANT, *, prefix: bytes | None = None
) -> bytes:
    """Prepare a message for blind signing (RFC 9474 Section 4.1).

    Args:
        msg: The application message.
        variant: Protocol variant; randomized variants prepend a 32-byte prefix.
        prefix: Injectable randomizer prefix (test vectors); generated if omitted.

    Returns:
        The prepared message (``prefix || msg`` or ``msg``).

    Raises:
        InvalidInputError: If a prefix is supplied where the variant forbids one,
            or the prefix has the wrong length.
    """
    if not variant.randomized:
        if prefix is not None:
            raise InvalidInputError("identity preparation takes no prefix")
        return msg
    if prefix is None:
        prefix = secrets.token_bytes(_PREFIX_LEN)
    if len(prefix) != _PREFIX_LEN:
        raise InvalidInputError("prefix must be 32 bytes")
    return prefix + msg


def blind(
    public_key: rsa.RSAPublicKey,
    prepared_msg: bytes,
    variant: Variant = DEFAULT_VARIANT,
    *,
    salt: bytes | None = None,
    r_inv: int | None = None,
) -> tuple[bytes, bytes]:
    """Blind a prepared message (RFC 9474 Section 4.2, ``Blind``).

    Args:
        public_key: The signer's RSA public key.
        prepared_msg: Output of :func:`prepare`.
        variant: Protocol variant (determines salt length).
        salt: Injectable PSS salt (test vectors); generated if omitted.
        r_inv: Injectable blinding inverse as an integer (test vectors);
            a fresh blinding factor is generated if omitted.

    Returns:
        A ``(blinded_msg, inv)`` pair, both of modulus length.

    Raises:
        InvalidInputError: If the message representative is not coprime with n,
            or the salt length does not match the variant.
        BlindingError: If the blinding factor is not invertible mod n.
        EncodingError: Propagated from EMSA-PSS encoding.
    """
    numbers = public_key.public_numbers()
    n, e = numbers.n, numbers.e
    k = (n.bit_length() + 7) // 8

    if salt is None:
        salt = secrets.token_bytes(variant.salt_len)
    elif len(salt) != variant.salt_len:
        raise InvalidInputError(f"salt must be {variant.salt_len} bytes for {variant.name}")

    em = emsa_pss_encode(prepared_msg, n.bit_length() - 1, salt)
    m = _os2ip(em)
    if math.gcd(m, n) != 1:
        raise InvalidInputError("invalid input")

    if r_inv is None:
        r = secrets.randbelow(n - 1) + 1
        try:
            r_inv = pow(r, -1, n)
        except ValueError as exc:
            raise BlindingError("blinding error") from exc
    else:
        if not 0 < r_inv < n:
            raise InvalidInputError("blinding inverse out of range")
        try:
            r = pow(r_inv, -1, n)
        except ValueError as exc:
            raise BlindingError("blinding error") from exc

    z = (m * pow(r, e, n)) % n
    return _i2osp(z, k), _i2osp(r_inv, k)


def blind_sign(private_key: rsa.RSAPrivateKey, blinded_msg: bytes) -> bytes:
    """Sign a blinded message (RFC 9474 Section 4.3, ``BlindSign``).

    Applies signer-side multiplicative blinding (RFC 9474 Section 7.1) around
    the private-key operation and self-checks the result via RSAVP1.

    Args:
        private_key: The signer's RSA private key.
        blinded_msg: The blinded message, exactly modulus length.

    Returns:
        The blind signature, of modulus length.

    Raises:
        UnexpectedInputSizeError: If ``blinded_msg`` is not modulus length.
        InvalidInputError: If the representative is not in ``[0, n)``.
        SigningFailureError: If the RSAVP1 self-check fails.
    """
    priv = private_key.private_numbers()
    n, e, d = priv.public_numbers.n, priv.public_numbers.e, priv.d
    k = (n.bit_length() + 7) // 8

    if len(blinded_msg) != k:
        raise UnexpectedInputSizeError("unexpected input size")
    m = _os2ip(blinded_msg)
    if m >= n:
        raise InvalidInputError("invalid input")

    while True:
        z = secrets.randbelow(n - 1) + 1
        try:
            z_inv = pow(z, -1, n)
        except ValueError:  # pragma: no cover - negligible probability
            continue
        break
    s = (pow((m * pow(z, e, n)) % n, d, n) * z_inv) % n

    if pow(s, e, n) != m:
        raise SigningFailureError("signing failure")
    return _i2osp(s, k)


def finalize(
    public_key: rsa.RSAPublicKey,
    prepared_msg: bytes,
    blind_sig: bytes,
    inv: bytes,
    variant: Variant = DEFAULT_VARIANT,
) -> bytes:
    """Unblind and verify a blind signature (RFC 9474 Section 4.4, ``Finalize``).

    Args:
        public_key: The signer's RSA public key.
        prepared_msg: The prepared message that was blinded.
        blind_sig: The signer's blind signature.
        inv: The blinding inverse returned by :func:`blind`.
        variant: Protocol variant (determines salt length for verification).

    Returns:
        A standard RSASSA-PSS signature over ``prepared_msg``.

    Raises:
        UnexpectedInputSizeError: If ``blind_sig`` is not modulus length.
        InvalidSignatureError: If the unblinded signature does not verify.
    """
    n = public_key.public_numbers().n
    k = (n.bit_length() + 7) // 8
    if len(blind_sig) != k:
        raise UnexpectedInputSizeError("unexpected input size")

    s = (_os2ip(blind_sig) * _os2ip(inv)) % n
    sig = _i2osp(s, k)
    verify(public_key, prepared_msg, sig, variant)
    return sig


def verify(
    public_key: rsa.RSAPublicKey,
    prepared_msg: bytes,
    sig: bytes,
    variant: Variant = DEFAULT_VARIANT,
) -> None:
    """Verify a finalized signature (standard RSASSA-PSS via OpenSSL).

    Args:
        public_key: The signer's RSA public key.
        prepared_msg: The prepared message.
        sig: The signature produced by :func:`finalize`.
        variant: Protocol variant (PSS salt length).

    Raises:
        InvalidSignatureError: If verification fails.
    """
    try:
        public_key.verify(
            sig,
            prepared_msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=variant.salt_len),
            hashes.SHA384(),
        )
    except InvalidSignature as exc:
        raise InvalidSignatureError("invalid signature") from exc
