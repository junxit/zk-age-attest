"""EXPERIMENTAL: 2-of-3 threshold RSA blind-signing for zk-age-attest (v1.5 starter).

Wire-compatible with :mod:`zkage_core.rsabssa`: a combined threshold signature
``s`` satisfies ``s^e ≡ blinded_msg (mod n)``, so ``finalize``/``verify`` and
every downstream consumer work unchanged — no client or protocol change.

Construction: PAIRWISE-ADDITIVE sharing of the signing exponent (not full
Shoup Δ-correction — see the module docstring in ``zkage_threshold.threshold``).
"""

from zkage_threshold.threshold import (
    ShareBundle,
    ThresholdDeal,
    ThresholdError,
    blind_sign_thresholded,
    deal_from_private_key,
)

__version__ = "0.1.0"

__all__ = [
    "ShareBundle",
    "ThresholdDeal",
    "ThresholdError",
    "blind_sign_thresholded",
    "deal_from_private_key",
]
