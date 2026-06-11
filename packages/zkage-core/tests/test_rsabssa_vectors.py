"""Step-level validation of the RSABSSA implementation against RFC 9474 Appendix A.

Every intermediate the RFC publishes (`prepared_msg`, `encoded_msg`, `blinded_msg`,
`blind_sig`, `sig`) must reproduce byte-for-byte, for all four named variants.
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from zkage_core import rsabssa

VECTORS = json.loads((Path(__file__).parent / "vectors" / "rfc9474.json").read_text())


def key_from_vector(v: dict) -> rsa.RSAPrivateKey:
    p, q = int(v["p"], 16), int(v["q"], 16)
    n, e, d = int(v["n"], 16), int(v["e"], 16), int(v["d"], 16)
    public = rsa.RSAPublicNumbers(e, n)
    private = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=public,
    )
    return private.private_key()


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_full_protocol_reproduces_all_intermediates(name: str) -> None:
    v = VECTORS[name]
    variant = rsabssa.VARIANTS[name]
    sk = key_from_vector(v)
    pk = sk.public_key()
    n_bits = pk.public_numbers().n.bit_length()

    msg = bytes.fromhex(v["msg"])
    prefix = bytes.fromhex(v["msg_prefix"]) if v.get("msg_prefix") else None
    prepared = rsabssa.prepare(msg, variant, prefix=prefix)
    assert prepared.hex() == v["prepared_msg"], "Prepare mismatch"

    salt = bytes.fromhex(v["salt"]) if v["salt"] else b""
    assert len(salt) == variant.salt_len
    em = rsabssa.emsa_pss_encode(prepared, n_bits - 1, salt)
    assert em.hex() == v["encoded_msg"], "EMSA-PSS-ENCODE mismatch"

    blinded, inv = rsabssa.blind(pk, prepared, variant, salt=salt, r_inv=int(v["inv"], 16))
    assert blinded.hex() == v["blinded_msg"], "Blind mismatch"
    assert inv.hex().lstrip("0") == v["inv"].lstrip("0")

    blind_sig = rsabssa.blind_sign(sk, blinded)
    assert blind_sig.hex() == v["blind_sig"], "BlindSign mismatch"

    sig = rsabssa.finalize(pk, prepared, blind_sig, inv, variant)
    assert sig.hex() == v["sig"], "Finalize mismatch"

    rsabssa.verify(pk, prepared, sig, variant)  # must not raise


def test_randomized_blindness_yields_distinct_blinded_messages() -> None:
    """Two blindings of the same prepared message must differ (fresh r each time)."""
    v = VECTORS["RSABSSA-SHA384-PSS-Randomized"]
    pk = key_from_vector(v).public_key()
    prepared = bytes.fromhex(v["prepared_msg"])
    b1, _ = rsabssa.blind(pk, prepared)
    b2, _ = rsabssa.blind(pk, prepared)
    assert b1 != b2
