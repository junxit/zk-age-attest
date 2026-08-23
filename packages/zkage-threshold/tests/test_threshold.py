"""Threshold PoC battery: quorum math, wire compatibility, failure modes."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from zkage_threshold import (
    ShareBundle,
    ThresholdDeal,
    ThresholdError,
    blind_sign_thresholded,
    deal_from_private_key,
)

from zkage_core import rsabssa
from zkage_core.keys import generate_scope_key

PARTIES = ("operator-a", "operator-b", "operator-c")


@pytest.fixture(scope="module")
def deal() -> ThresholdDeal:
    key = generate_scope_key(2048)
    return deal_from_private_key(key, PARTIES)


def _public_key(n: int, e: int) -> rsa.RSAPublicKey:
    return rsa.RSAPublicNumbers(e, n).public_key()


def _fresh_blinded(deal: ThresholdDeal) -> tuple[bytes, bytes, bytes]:
    """A fresh blinded message: returns (prepared, blinded, blinding_inverse)."""
    prepared = rsabssa.prepare(b"threshold-poc message")
    blinded, inv = rsabssa.blind(_public_key(deal.n, deal.e), prepared)
    return prepared, blinded, inv


def test_every_pair_forms_a_quorum(deal: ThresholdDeal) -> None:
    """Any 2 of the 3 operators produce a valid signature."""
    for pair in deal.quorum():
        _, blinded, _inv = _fresh_blinded(deal)
        m = int.from_bytes(blinded, "big")
        sig = blind_sign_thresholded(deal, pair, blinded)
        assert pow(int.from_bytes(sig, "big"), deal.e, deal.n) == m % deal.n


def test_combined_signature_finalizes_like_blind_sign(deal: ThresholdDeal) -> None:
    """End-to-end wire compatibility: threshold output flows through finalize."""
    public = _public_key(deal.n, deal.e)
    prepared, blinded, inv = _fresh_blinded(deal)
    blind_sig = blind_sign_thresholded(deal, ("operator-a", "operator-b"), blinded)

    sig = rsabssa.finalize(public, prepared, blind_sig, inv)
    rsabssa.verify(public, prepared, sig)  # must not raise


def test_single_operator_cannot_sign(deal: ThresholdDeal) -> None:
    """One partial alone satisfies neither combine nor the e-th power check."""
    _, blinded, _inv = _fresh_blinded(deal)
    m = int.from_bytes(blinded, "big")

    lone = deal.bundles["operator-a"].partial_sign(m, "operator-b")
    assert pow(lone, deal.e, deal.n) != m % deal.n  # not a signature by itself

    with pytest.raises(ThresholdError):
        blind_sign_thresholded(deal, ("operator-a", "operator-a"), blinded)


def test_misbehaving_operator_caught_at_combine(deal: ThresholdDeal) -> None:
    """Garbage from one operator trips the combiner's self-check."""

    class LyingBundle(ShareBundle):
        def partial_sign(self, blinded_msg: bytes | int, partner: str) -> int:
            return 42

    poisoned_deal = ThresholdDeal(
        n=deal.n,
        e=deal.e,
        threshold=deal.threshold,
        parties=deal.parties,
        bundles={
            **deal.bundles,
            "operator-c": LyingBundle("operator-c", deal.n, deal.e, {"operator-a": 1}),
        },
    )
    with pytest.raises(ThresholdError, match="misbehaving"):
        blind_sign_thresholded(poisoned_deal, ("operator-a", "operator-c"), b"\x01" * 256)


def test_deal_constraints() -> None:
    key = generate_scope_key(2048)
    with pytest.raises(ThresholdError):
        deal_from_private_key(key, PARTIES[:2])
    with pytest.raises(ThresholdError):
        deal_from_private_key(key, ("x", "x", "y"))
    with pytest.raises(ThresholdError):
        deal_from_private_key(key, PARTIES, threshold=3)
