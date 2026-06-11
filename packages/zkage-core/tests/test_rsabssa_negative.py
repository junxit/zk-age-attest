"""Negative and mutation battery for the RSABSSA implementation."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from zkage_core import rsabssa
from zkage_core.rsabssa import (
    RSABSSA_SHA384_PSS_RANDOMIZED as PSS,
)
from zkage_core.rsabssa import (
    RSABSSA_SHA384_PSSZERO_RANDOMIZED as PSSZERO,
)

VECTORS = json.loads((Path(__file__).parent / "vectors" / "rfc9474.json").read_text())
V = VECTORS["RSABSSA-SHA384-PSS-Randomized"]


@pytest.fixture(scope="module")
def vector_key() -> rsa.RSAPrivateKey:
    from test_rsabssa_vectors import key_from_vector

    return key_from_vector(V)


@pytest.fixture(scope="module")
def other_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_verify_rejects_flipped_signature_bit(vector_key: rsa.RSAPrivateKey) -> None:
    prepared, sig = bytes.fromhex(V["prepared_msg"]), bytearray(bytes.fromhex(V["sig"]))
    sig[0] ^= 0x01
    with pytest.raises(rsabssa.InvalidSignatureError):
        rsabssa.verify(vector_key.public_key(), prepared, bytes(sig), PSS)


def test_verify_rejects_tampered_message(vector_key: rsa.RSAPrivateKey) -> None:
    prepared = bytearray(bytes.fromhex(V["prepared_msg"]))
    prepared[-1] ^= 0xFF
    with pytest.raises(rsabssa.InvalidSignatureError):
        rsabssa.verify(vector_key.public_key(), bytes(prepared), bytes.fromhex(V["sig"]), PSS)


def test_verify_rejects_wrong_public_key(other_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(rsabssa.InvalidSignatureError):
        rsabssa.verify(
            other_key.public_key(), bytes.fromhex(V["prepared_msg"]), bytes.fromhex(V["sig"]), PSS
        )


def test_verify_rejects_truncated_signature(vector_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(rsabssa.InvalidSignatureError):
        rsabssa.verify(
            vector_key.public_key(),
            bytes.fromhex(V["prepared_msg"]),
            bytes.fromhex(V["sig"])[:-1],
            PSS,
        )


def test_verify_rejects_wrong_salt_length_variant(vector_key: rsa.RSAPrivateKey) -> None:
    """A PSS(48) signature must not verify under the PSSZERO variant."""
    with pytest.raises(rsabssa.InvalidSignatureError):
        rsabssa.verify(
            vector_key.public_key(),
            bytes.fromhex(V["prepared_msg"]),
            bytes.fromhex(V["sig"]),
            PSSZERO,
        )


def test_finalize_rejects_corrupted_blind_signature(vector_key: rsa.RSAPrivateKey) -> None:
    blind_sig = bytearray(bytes.fromhex(V["blind_sig"]))
    blind_sig[10] ^= 0x40
    with pytest.raises(rsabssa.InvalidSignatureError):
        rsabssa.finalize(
            vector_key.public_key(),
            bytes.fromhex(V["prepared_msg"]),
            bytes(blind_sig),
            bytes.fromhex(V["inv"]),
            PSS,
        )


def test_finalize_rejects_wrong_inverse(vector_key: rsa.RSAPrivateKey) -> None:
    inv = bytearray(bytes.fromhex(V["inv"]))
    inv[-1] ^= 0x02
    with pytest.raises(rsabssa.InvalidSignatureError):
        rsabssa.finalize(
            vector_key.public_key(),
            bytes.fromhex(V["prepared_msg"]),
            bytes.fromhex(V["blind_sig"]),
            bytes(inv),
            PSS,
        )


def test_finalize_rejects_short_blind_signature(vector_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(rsabssa.UnexpectedInputSizeError):
        rsabssa.finalize(
            vector_key.public_key(),
            bytes.fromhex(V["prepared_msg"]),
            bytes.fromhex(V["blind_sig"])[:-1],
            bytes.fromhex(V["inv"]),
            PSS,
        )


def test_blind_sign_rejects_wrong_length(vector_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(rsabssa.UnexpectedInputSizeError):
        rsabssa.blind_sign(vector_key, b"\x01" * 17)


def test_blind_sign_rejects_representative_geq_n(vector_key: rsa.RSAPrivateKey) -> None:
    n = vector_key.public_key().public_numbers().n
    k = (n.bit_length() + 7) // 8
    with pytest.raises(rsabssa.InvalidInputError):
        rsabssa.blind_sign(vector_key, n.to_bytes(k, "big"))


def test_blind_rejects_wrong_salt_length(vector_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(rsabssa.InvalidInputError):
        rsabssa.blind(
            vector_key.public_key(), bytes.fromhex(V["prepared_msg"]), PSS, salt=b"\x00" * 47
        )


def test_blind_rejects_out_of_range_inverse(vector_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(rsabssa.InvalidInputError):
        rsabssa.blind(
            vector_key.public_key(),
            bytes.fromhex(V["prepared_msg"]),
            PSS,
            salt=bytes.fromhex(V["salt"]),
            r_inv=0,
        )


def test_prepare_rejects_bad_prefix_length() -> None:
    with pytest.raises(rsabssa.InvalidInputError):
        rsabssa.prepare(b"hello", PSS, prefix=b"\x00" * 31)


def test_prepare_identity_rejects_prefix() -> None:
    with pytest.raises(rsabssa.InvalidInputError):
        rsabssa.prepare(b"hello", rsabssa.RSABSSA_SHA384_PSS_DETERMINISTIC, prefix=b"\x00" * 32)


def test_emsa_pss_encode_rejects_tiny_modulus() -> None:
    with pytest.raises(rsabssa.EncodingError):
        rsabssa.emsa_pss_encode(b"msg", em_bits=256, salt=b"\x00" * 48)


def test_unblinded_signature_is_standard_pss(vector_key: rsa.RSAPrivateKey) -> None:
    """The finalized signature must verify as plain RSASSA-PSS (interop check)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    vector_key.public_key().verify(
        bytes.fromhex(V["sig"]),
        bytes.fromhex(V["prepared_msg"]),
        padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
        hashes.SHA384(),
    )
