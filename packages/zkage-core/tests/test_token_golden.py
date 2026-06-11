"""Format freeze: the committed golden token must reproduce byte-for-byte.

If this test fails, the wire format changed — that is a normative protocol
change and requires a DESIGN.md update plus a new token_type, not a silent fix.
"""

from pathlib import Path

from zkage_core import token

GOLDEN = (Path(__file__).parent / "vectors" / "golden_token.hex").read_text().strip()


def build_golden_wire() -> bytes:
    prefix = bytes(range(32))
    key_id = bytes([0x11]) * 32
    nonce = bytes([0x22]) * 32
    expiry = 1_781_234_567
    digest = token.challenge_digest("demo-rp.example", 18, nonce, expiry)
    msg = token.encode_token_msg(18, key_id, digest, nonce, expiry)
    return token.encode_token(prefix + msg, bytes([0x33]) * 256)


def test_golden_token_frozen() -> None:
    assert build_golden_wire().hex() == GOLDEN


def test_golden_token_parses() -> None:
    fields = token.parse_token(bytes.fromhex(GOLDEN))
    assert fields.scope_id == 18
    assert fields.expiry == 1_781_234_567
    assert fields.signature == bytes([0x33]) * 256
