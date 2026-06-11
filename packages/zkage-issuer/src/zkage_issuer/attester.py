"""Pluggable attester interface.

The attester is the one component that ever touches identity, and it runs at
enrollment only. It returns nothing but a maximum age scope — the issuer never
sees a date of birth or a document. Real implementations (eID, mDL/EUDI proof,
bank check, commercial provider) plug in behind the same interface.
"""

from __future__ import annotations

from typing import Protocol

from zkage_core.token import SCOPES


class AttestationError(Exception):
    """The attester could not establish any age scope for this enrollment."""


class Attester(Protocol):
    """Establishes the maximum age scope for an enrolling user."""

    name: str

    def attest(self, claim: dict[str, object]) -> int:
        """Return the maximum scope this user may request (13/16/18/21).

        Raises:
            AttestationError: If no scope can be established.
        """
        ...


class StubAttester:
    """DEMO ONLY: trusts a self-declared age. Exists to exercise the protocol.

    The token-issuance protocol is independent of attestation strength; this
    stub stands in where a real eID/mDL/bank attester would integrate.
    """

    name = "stub"

    def attest(self, claim: dict[str, object]) -> int:
        age = claim.get("claimed_age")
        if isinstance(age, bool) or not isinstance(age, int):
            raise AttestationError("claimed_age must be an integer")
        eligible = [s for s in SCOPES if age >= s]
        if not eligible:
            raise AttestationError("no age scope attestable")
        return max(eligible)
