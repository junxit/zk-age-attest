"""Pairwise-additive 2-of-3 threshold RSA (EXPERIMENTAL v1.5 starter).

Idea: the signing exponent is shared ADDITIVELY over every pair of parties.
For each unordered pair ``(i, j)`` the dealer picks a uniform ``r_ij`` and sets
``r_ji = d - r_ij (mod λ(n))``, handing ``r_ij`` to party ``i`` and ``r_ji``
to party ``j``. Any two parties then sign a blinded message representative
``m`` with one modular exponentiation each::

    s = m^{r_ij} · m^{r_ji} ≡ m^d   (mod n)

so ``s^e ≡ m`` exactly — byte-for-byte the same contract as
``zkage_core.rsabssa.blind_sign`` output, and the signer-side multiplicative
blinding of RFC 9474 §7.1 can be wrapped around each partial exponentiation.

Why not Shoup: Shoup's Δ-correction gives compact per-party state and public
partial-signature verification, at the cost of delicate interpolation
arithmetic. This construction trades those away for a correctness argument
that fits in two lines — appropriate for a spike whose goal is demonstrating
wire-compatibility. The DESIGN.md §9 threshold path can swap in full Shoup
later without changing the client or the wire.

Trust model / caveats (inherited from the trusted-dealer interim, DESIGN §9):
the dealer knows ``d`` and λ(n); partial signatures are NOT publicly
verifiable (a malicious operator could return garbage — detected at combine
time by the ``s^e ≡ m`` self-check); no party may reuse its shares across
different keys. Partial exponents must never be revealed; only their power
residue leaves the operator.
"""

from __future__ import annotations

import itertools
import math
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa


class ThresholdError(Exception):
    """Threshold setup or combination failed."""


def _representative(value: bytes | int, n: int) -> int:
    """Integer representative of a blinded message, range-checked."""
    m = int.from_bytes(value, "big") if isinstance(value, bytes) else value
    if not 0 <= m < n:
        raise ThresholdError("blinded message representative out of range")
    return m


@dataclass(frozen=True)
class ShareBundle:
    """One operator's threshold key material: its additive shares per partner.

    Treat like a private key: never publish, never log, never reuse across keys.
    """

    party: str
    n: int
    e: int
    partners: dict[str, int]

    def partial_sign(self, blinded_msg: bytes | int, partner: str) -> int:
        """One exponentiation toward a quorum signature with ``partner``.

        Applies RFC 9474 §7.1-style multiplicative blinding around the private
        operation: the exponentiation input ``m·z^e`` is randomized, and the
        correction divides out ``z^{e·r}`` afterwards (the operator owns ``r``,
        so no secret beyond its own share is needed — unlike plain §7.1, where
        ``z^{e·d} = z`` lets the signer divide by ``z`` alone).

        Args:
            blinded_msg: The client's blinded message (modulus-length bytes)
                or its integer representative.
            partner: The other quorum member this partial combines with.

        Returns:
            The corrected power residue ``m^r (mod n)`` — safe to send to the
            combiner; ``z`` and the raw blinded exponentiation never leave.

        Raises:
            ThresholdError: On unknown partners or out-of-range messages.
        """
        if partner not in self.partners:
            raise ThresholdError(f"no share for partner {partner!r}")
        n = self.n
        m = _representative(blinded_msg, n)
        share = self.partners[partner]
        z, _ = _random_invertible(n)
        blinded_input = (m * pow(z, self.e, n)) % n
        raw = pow(blinded_input, share, n)
        correction = pow(z, self.e * share, n)
        return raw * pow(correction, -1, n) % n


@dataclass(frozen=True)
class ThresholdDeal:
    """Everything a dealer produces for one signing key: public params + shares."""

    n: int
    e: int
    threshold: int
    parties: tuple[str, ...]
    bundles: dict[str, ShareBundle] = field(default_factory=dict)

    def quorum(self) -> list[tuple[str, str]]:
        """Every pair of parties that can form a signing quorum."""
        return list(itertools.combinations(self.parties, 2))


def deal_from_private_key(
    private_key: rsa.RSAPrivateKey,
    parties: tuple[str, ...] = ("operator-a", "operator-b", "operator-c"),
    *,
    threshold: int = 2,
) -> ThresholdDeal:
    """Split an RSA signing key into pairwise-additive shares.

    Args:
        private_key: The federation scope key to thresholdize.
        parties: Operator identifiers (exactly 3 supported in this spike).
        threshold: Must be 2 (pairs are the only quorums implemented).

    Returns:
        The deal: public parameters plus one :class:`ShareBundle` per party.

    Raises:
        ThresholdError: If parameters deviate from the spike's constraints.
    """
    if threshold != 2:
        raise ThresholdError("this spike implements 2-of-N pairs only")
    if len(parties) != 3 or len(set(parties)) != len(parties):
        raise ThresholdError("this spike deals to exactly 3 uniquely named parties")

    priv = private_key.private_numbers()
    n, e = priv.public_numbers.n, priv.public_numbers.e
    lam = (priv.p - 1) * (priv.q - 1) // math.gcd(priv.p - 1, priv.q - 1)
    d = pow(e, -1, lam)

    half = lam // 2
    shares: dict[str, dict[str, int]] = {name: {} for name in parties}
    for left, right in itertools.combinations(parties, 2):
        # Uniform split of d over this pair: r + s ≡ d (mod λ).
        r = secrets.randbelow(half)
        s = (d - r) % lam
        shares[left][right] = r
        shares[right][left] = s

    return ThresholdDeal(
        n=n,
        e=e,
        threshold=threshold,
        parties=parties,
        bundles={
            name: ShareBundle(party=name, n=n, e=e, partners=partners)
            for name, partners in shares.items()
        },
    )


def blind_sign_thresholded(
    deal: ThresholdDeal, quorum: tuple[str, str], blinded_msg: bytes | int
) -> bytes:
    """RFC 9474 ``BlindSign`` via a 2-party quorum; output matches ``blind_sign``.

    Each quorum operator exponentiates under its own additive share (with
    §7.1-style input blinding applied internally); the combiner multiplies the
    partials — the shares sum to the full signing exponent — and self-checks.

    Args:
        deal: The threshold deal for this key.
        quorum: Exactly two distinct party names from the deal.
        blinded_msg: The client's blinded message (modulus-length bytes).

    Returns:
        A signature ``s`` with ``s^e ≡ blinded_msg (mod n)``, identical in
        contract to :func:`zkage_core.rsabssa.blind_sign` output.

    Raises:
        ThresholdError: On bad inputs, unknown operators, or a failed
            self-check (a misbehaving operator returning garbage).
    """
    left, right = quorum
    if len(set(quorum)) != 2 or left not in deal.bundles or right not in deal.bundles:
        raise ThresholdError("quorum must be two distinct dealt parties")
    m = _representative(blinded_msg, deal.n)

    s = (
        deal.bundles[left].partial_sign(m, right) * deal.bundles[right].partial_sign(m, left)
    ) % deal.n

    if pow(s, deal.e, deal.n) != m % deal.n:
        raise ThresholdError("threshold signing failure (misbehaving operator?)")
    return s.to_bytes((deal.n.bit_length() + 7) // 8, "big")


def _random_invertible(n: int) -> tuple[int, int]:
    """A uniform invertible element of Z_n* and its inverse (signer blinding)."""
    while True:
        z = secrets.randbelow(n - 1) + 1
        try:
            return z, pow(z, -1, n)
        except ValueError:  # pragma: no cover - negligible probability
            continue
