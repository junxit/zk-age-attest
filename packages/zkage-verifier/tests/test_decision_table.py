"""Decision-table battery: every verification outcome is reachable and correct.

Each case builds a real blind-signed token and perturbs exactly one thing.
A final test asserts the case list covers the entire Decision enum, so adding
a decision without a test fails the build.
"""

import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from zkage_core import keys, rsabssa, token
from zkage_verifier import Decision, verify_token

NOW = 1_000_000
RP = "demo-rp.example"

Case = tuple[str, Decision, bytes, list[keys.ScopeKeyRecord], token.Challenge, int]


def issue_token(sk: rsa.RSAPrivateKey, key_id: bytes, challenge: token.Challenge) -> bytes:
    """Run the full prepare/blind/blind-sign/finalize flow for a challenge."""
    msg = token.token_msg_for_challenge(challenge, key_id)
    prepared = rsabssa.prepare(msg)
    blinded, inv = rsabssa.blind(sk.public_key(), prepared)
    blind_sig = rsabssa.blind_sign(sk, blinded)
    sig = rsabssa.finalize(sk.public_key(), prepared, blind_sig, inv)
    return token.encode_token(prepared, sig)


def make_record(sk: rsa.RSAPrivateKey, scope: int = 18) -> keys.ScopeKeyRecord:
    public = sk.public_key()
    return keys.ScopeKeyRecord(
        scope=scope,
        epoch=1,
        key_id=keys.key_id_of(public),
        spki=keys.spki_der(public),
        not_before=0,
        not_after=10_000_000,
        status="active",
    )


@pytest.fixture(scope="module")
def cases() -> list[Case]:
    sk = keys.generate_scope_key(2048)
    record = make_record(sk)
    trusted = [record]
    challenge = token.make_challenge(RP, 18, now=NOW)
    wire = issue_token(sk, record.key_id, challenge)
    out: list[Case] = [("valid token", Decision.OK, wire, trusted, challenge, NOW)]

    out.append(("garbage bytes", Decision.MALFORMED, b"junk", trusted, challenge, NOW))
    bad_tag = bytearray(wire)
    bad_tag[32] ^= 0xFF
    out.append(("flipped tag byte", Decision.MALFORMED, bytes(bad_tag), trusted, challenge, NOW))

    expected_21 = token.Challenge(RP, 21, challenge.nonce, challenge.expires_at)
    out.append(("challenged for 21", Decision.WRONG_SCOPE, wire, trusted, expected_21, NOW))

    unknown_kid = bytearray(wire)
    unknown_kid[50] ^= 0x01  # first key_id byte
    out.append(
        ("unknown key id", Decision.UNKNOWN_KEY, bytes(unknown_kid), trusted, challenge, NOW)
    )

    lying_scope = [dataclasses.replace(record, scope=13)]
    out.append(
        ("keyset lies about scope", Decision.KEY_SCOPE_MISMATCH, wire, lying_scope, challenge, NOW)
    )

    out.append(
        (
            "revoked key",
            Decision.KEY_NOT_VALID,
            wire,
            [dataclasses.replace(record, status="revoked")],
            challenge,
            NOW,
        )
    )
    out.append(
        (
            "key not yet valid",
            Decision.KEY_NOT_VALID,
            wire,
            [dataclasses.replace(record, not_before=NOW + 10)],
            challenge,
            NOW,
        )
    )

    other_nonce = token.Challenge(RP, 18, bytes(32), challenge.expires_at)
    out.append(("nonce mismatch", Decision.CHALLENGE_MISMATCH, wire, trusted, other_nonce, NOW))
    other_rp = token.Challenge("evil.example", 18, challenge.nonce, challenge.expires_at)
    out.append(("rp_id mismatch", Decision.CHALLENGE_MISMATCH, wire, trusted, other_rp, NOW))
    other_expiry = token.Challenge(RP, 18, challenge.nonce, challenge.expires_at + 1)
    out.append(("expiry mismatch", Decision.CHALLENGE_MISMATCH, wire, trusted, other_expiry, NOW))

    out.append(
        ("expired token", Decision.EXPIRED, wire, trusted, challenge, challenge.expires_at + 1)
    )

    far = token.Challenge(RP, 18, challenge.nonce, NOW + 5_000)
    far_wire = issue_token(sk, record.key_id, far)
    out.append(("far-future expiry", Decision.EXPIRY_TOO_FAR, far_wire, trusted, far, NOW))

    tampered_spki = [dataclasses.replace(record, spki=record.spki + b"x")]
    out.append(("spki/key_id mismatch", Decision.BAD_KEY, wire, tampered_spki, challenge, NOW))

    weak_sk = rsa.generate_private_key(public_exponent=3, key_size=2048)
    weak_record = make_record(weak_sk)
    weak_wire = issue_token(weak_sk, weak_record.key_id, challenge)
    out.append(
        ("policy-violating key (e=3)", Decision.BAD_KEY, weak_wire, [weak_record], challenge, NOW)
    )

    out.append(
        ("truncated signature", Decision.BAD_SIGNATURE_LENGTH, wire[:-1], trusted, challenge, NOW)
    )

    flipped_sig = bytearray(wire)
    flipped_sig[-1] ^= 0x01
    out.append(
        (
            "flipped signature bit",
            Decision.BAD_SIGNATURE,
            bytes(flipped_sig),
            trusted,
            challenge,
            NOW,
        )
    )
    return out


def test_decision_table(cases: list[Case]) -> None:
    for name, expected_decision, wire, trusted, challenge, now in cases:
        result = verify_token(wire, trusted, challenge, now)
        assert result.decision is expected_decision, (
            f"{name}: expected {expected_decision}, got {result.decision}"
        )
        if expected_decision is Decision.OK:
            assert result.ok and result.scope == 18
        else:
            assert not result.ok and result.scope is None


def test_every_decision_code_is_exercised(cases: list[Case]) -> None:
    exercised = {decision for _, decision, *_ in cases}
    assert exercised == set(Decision), f"uncovered decisions: {set(Decision) - exercised}"
