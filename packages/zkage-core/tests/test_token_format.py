"""Token and challenge codec battery: round-trips, strictness, digest sensitivity."""

import pytest

from zkage_core import token

KEY_ID = bytes([0x11]) * 32
NONCE = bytes([0x22]) * 32
EXPIRY = 1_781_234_567
RP = "demo-rp.example"
PREFIX = bytes(range(32))
SIG = bytes([0x33]) * 256


def build_wire(scope: int = 18) -> bytes:
    digest = token.challenge_digest(RP, scope, NONCE, EXPIRY)
    msg = token.encode_token_msg(scope, KEY_ID, digest, NONCE, EXPIRY)
    return token.encode_token(PREFIX + msg, SIG)


def test_round_trip() -> None:
    wire = build_wire()
    fields = token.parse_token(wire)
    assert fields.scope_id == 18
    assert fields.key_id == KEY_ID
    assert fields.nonce == NONCE
    assert fields.expiry == EXPIRY
    assert fields.challenge_digest == token.challenge_digest(RP, 18, NONCE, EXPIRY)
    assert fields.prepared_msg == wire[: token.PREPARED_LEN]
    assert fields.signature == SIG
    assert fields.prepared_msg + fields.signature == wire


def test_parse_rejects_too_short() -> None:
    wire = build_wire()
    for cut in (0, 10, token.PREPARED_LEN):  # PREPARED_LEN → empty signature
        with pytest.raises(token.TokenFormatError):
            token.parse_token(wire[:cut])


def test_parse_rejects_bad_tag() -> None:
    wire = bytearray(build_wire())
    wire[32] ^= 0xFF  # first tag byte
    with pytest.raises(token.TokenFormatError):
        token.parse_token(bytes(wire))


def test_parse_rejects_bad_type() -> None:
    wire = bytearray(build_wire())
    wire[48] = 0x02  # token_type low byte
    with pytest.raises(token.TokenFormatError):
        token.parse_token(bytes(wire))


def test_parse_rejects_unknown_scope() -> None:
    wire = bytearray(build_wire())
    wire[49] = 17
    with pytest.raises(token.TokenFormatError):
        token.parse_token(bytes(wire))


def test_encode_rejects_bad_fields() -> None:
    digest = token.challenge_digest(RP, 18, NONCE, EXPIRY)
    with pytest.raises(token.TokenFormatError):
        token.encode_token_msg(17, KEY_ID, digest, NONCE, EXPIRY)
    with pytest.raises(token.TokenFormatError):
        token.encode_token_msg(18, KEY_ID[:-1], digest, NONCE, EXPIRY)
    with pytest.raises(token.TokenFormatError):
        token.encode_token_msg(18, KEY_ID, digest, NONCE + b"x", EXPIRY)
    with pytest.raises(token.TokenFormatError):
        token.encode_token_msg(18, KEY_ID, digest, NONCE, 2**64)
    with pytest.raises(token.TokenFormatError):
        token.encode_token(b"\x00" * 153, SIG)
    with pytest.raises(token.TokenFormatError):
        token.encode_token(b"\x00" * 154, b"")


def test_challenge_digest_sensitive_to_every_field() -> None:
    base = token.challenge_digest(RP, 18, NONCE, EXPIRY)
    assert token.challenge_digest("other.example", 18, NONCE, EXPIRY) != base
    assert token.challenge_digest(RP, 21, NONCE, EXPIRY) != base
    assert token.challenge_digest(RP, 18, bytes(32), EXPIRY) != base
    assert token.challenge_digest(RP, 18, NONCE, EXPIRY + 1) != base


def test_challenge_digest_validates_inputs() -> None:
    with pytest.raises(token.ChallengeFormatError):
        token.challenge_digest("", 18, NONCE, EXPIRY)
    with pytest.raises(token.ChallengeFormatError):
        token.challenge_digest(RP, 19, NONCE, EXPIRY)
    with pytest.raises(token.ChallengeFormatError):
        token.challenge_digest(RP, 18, NONCE[:-1], EXPIRY)


def test_make_challenge_fresh_nonces_and_ttl_bounds() -> None:
    c1 = token.make_challenge(RP, 18, now=1000)
    c2 = token.make_challenge(RP, 18, now=1000)
    assert c1.nonce != c2.nonce
    assert c1.expires_at == 1000 + token.DEFAULT_CHALLENGE_TTL
    with pytest.raises(token.ChallengeFormatError):
        token.make_challenge(RP, 18, now=1000, ttl=token.MAX_TOKEN_LIFETIME + 1)
    with pytest.raises(token.ChallengeFormatError):
        token.make_challenge(RP, 18, now=1000, ttl=0)


def test_challenge_json_round_trip() -> None:
    challenge = token.make_challenge(RP, 18, now=1000, log_head=bytes(32))
    parsed = token.Challenge.from_json_dict(challenge.to_json_dict())
    assert parsed == challenge


def test_challenge_json_rejects_malformed() -> None:
    good = token.make_challenge(RP, 18, now=1000).to_json_dict()
    for mutate in (
        {"version": 2},
        {"scope": 19},
        {"nonce": "AAA"},
        {"expires_at": "soon"},
        {"log_head": "AAA"},
    ):
        with pytest.raises(token.ChallengeFormatError):
            token.Challenge.from_json_dict({**good, **mutate})
    with pytest.raises(token.ChallengeFormatError):
        token.Challenge.from_json_dict({k: v for k, v in good.items() if k != "nonce"})


def test_token_msg_for_challenge_matches_manual_encoding() -> None:
    challenge = token.make_challenge(RP, 18, now=1000, nonce=NONCE)
    msg = token.token_msg_for_challenge(challenge, KEY_ID)
    assert msg == token.encode_token_msg(
        18, KEY_ID, challenge.digest(), NONCE, challenge.expires_at
    )
