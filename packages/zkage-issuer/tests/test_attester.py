"""Signed-claims attester: authority-signed enrollment claims, tamper rejection."""

from __future__ import annotations

import base64
import secrets
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from zkage_core.encoding import b64u
from zkage_issuer.app import create_app
from zkage_issuer.attester import (
    AttestationError,
    SignedClaimAttester,
    StubAttester,
    fresh_claim_nonce,
    sign_attestation,
)
from zkage_issuer.federation import FederationState, init_state
from zkage_issuer.ratelimit import RateLimiter
from zkage_issuer.store import IssuerStore

NOW = 1_750_000_000


@pytest.fixture(scope="module")
def signed_env(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """Issuer app with the signed attester registered under its demo authority."""
    state_dir = tmp_path_factory.mktemp("attest-state")
    init_state(state_dir, now=NOW)
    state = FederationState.load(state_dir, now=NOW)
    store = IssuerStore(state_dir / "issuer" / "issuer.sqlite")
    authority = ed25519.Ed25519PrivateKey.generate()
    public_raw = authority.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    attesters = {"stub": StubAttester(), "signed": SignedClaimAttester(public_raw)}
    client = TestClient(create_app(state, store, RateLimiter(), attesters, lambda: NOW))
    return SimpleNamespace(client=client, authority=authority)


def _claim(authority: ed25519.Ed25519PrivateKey, age: int) -> dict[str, object]:
    nonce = bytes(base64.urlsafe_b64decode(fresh_claim_nonce() + "=="))
    return {
        "claimed_age": age,
        "nonce": b64u(nonce),
        "attestation": b64u(sign_attestation(authority, age, nonce)),
    }


def _enroll(signed_env: SimpleNamespace, claim: dict[str, object]) -> object:
    return signed_env.client.post(
        "/enroll",
        json={
            "device_pub": b64u(secrets.token_bytes(32)),
            "attester": "signed",
            "claim": claim,
        },
    )


def test_signed_claim_enrolls(signed_env: SimpleNamespace) -> None:
    resp = _enroll(signed_env, _claim(signed_env.authority, 21))
    assert resp.status_code == 200 and resp.json()["max_scope"] == 21


def test_tampered_age_rejected(signed_env: SimpleNamespace) -> None:
    claim = _claim(signed_env.authority, 21)
    claim["claimed_age"] = 25  # bump the age without re-signing
    resp = _enroll(signed_env, claim)
    assert resp.status_code == 403 and resp.json()["error"] == "attestation_failed"


def test_wrong_authority_rejected(signed_env: SimpleNamespace) -> None:
    stranger = ed25519.Ed25519PrivateKey.generate()
    resp = _enroll(signed_env, _claim(stranger, 21))
    assert resp.status_code == 403 and resp.json()["error"] == "attestation_failed"


def test_garbled_encoding_rejected(signed_env: SimpleNamespace) -> None:
    bad_claims: list[dict[str, object]] = [
        {"claimed_age": 21},
        {"claimed_age": 21, "nonce": "!!", "attestation": "!!"},
    ]
    for claim in bad_claims:
        resp = _enroll(signed_env, claim)
        assert resp.status_code == 403 and resp.json()["error"] == "attestation_failed"


def test_sign_attestation_nonce_validation() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(AttestationError, match="nonce"):
        sign_attestation(key, 21, b"short")
