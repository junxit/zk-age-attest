"""Issuer API battery: enrollment, issuance binding, abuse controls, log endpoints."""

import secrets
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from zkage_core import devicekey, keys, rsabssa, token, translog
from zkage_core.encoding import b64u, unb64u
from zkage_issuer.app import create_app
from zkage_issuer.attester import StubAttester
from zkage_issuer.federation import FederationState, init_state
from zkage_issuer.ratelimit import RateLimiter
from zkage_issuer.store import IssuerStore

NOW = 1_750_000_000
RP = "demo-rp.example"


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    state_dir = tmp_path_factory.mktemp("state")
    init_state(state_dir, now=NOW)
    state = FederationState.load(state_dir, now=NOW)
    store = IssuerStore(state_dir / "issuer" / "issuer.sqlite")
    limiter = RateLimiter(capacity=2, refill_seconds=10_000.0, daily_cap=50)
    app = create_app(state, store, limiter, {"stub": StubAttester()}, lambda: NOW)
    return SimpleNamespace(client=TestClient(app), state=state)


def enroll(client: TestClient, age: int = 25) -> tuple[bytes, ed25519.Ed25519PrivateKey]:
    sk = devicekey.generate_device_key()
    resp = client.post(
        "/enroll",
        json={"device_pub": b64u(devicekey.device_public_raw(sk)), "claim": {"claimed_age": age}},
    )
    assert resp.status_code == 200, resp.text
    return unb64u(resp.json()["account_id"]), sk


def issue_body(
    account_id: bytes,
    sk: ed25519.Ed25519PrivateKey,
    scope: int,
    blinded: bytes,
    *,
    ts: int = NOW,
    request_id: bytes | None = None,
    signature: bytes | None = None,
) -> dict[str, object]:
    request_id = request_id if request_id is not None else secrets.token_bytes(16)
    if signature is None:
        signature = devicekey.sign_issuance(sk, account_id, scope, blinded, ts, request_id)
    return {
        "account_id": b64u(account_id),
        "scope": scope,
        "blinded_msg": b64u(blinded),
        "ts": ts,
        "request_id": b64u(request_id),
        "signature": b64u(signature),
    }


def dummy_blinded() -> bytes:
    return bytes([1]) + secrets.token_bytes(255)  # < n for any 2048-bit modulus


def test_enroll_happy_path(env: SimpleNamespace) -> None:
    account_id, _ = enroll(env.client, age=25)
    assert len(account_id) == 16


def test_enroll_age_maps_to_max_scope(env: SimpleNamespace) -> None:
    sk = devicekey.generate_device_key()
    resp = env.client.post(
        "/enroll",
        json={"device_pub": b64u(devicekey.device_public_raw(sk)), "claim": {"claimed_age": 16}},
    )
    assert resp.status_code == 200 and resp.json()["max_scope"] == 16


def test_enroll_underage_rejected(env: SimpleNamespace) -> None:
    sk = devicekey.generate_device_key()
    resp = env.client.post(
        "/enroll",
        json={"device_pub": b64u(devicekey.device_public_raw(sk)), "claim": {"claimed_age": 9}},
    )
    assert resp.status_code == 403 and resp.json()["error"] == "attestation_failed"


def test_enroll_bad_device_key_and_attester(env: SimpleNamespace) -> None:
    resp = env.client.post("/enroll", json={"device_pub": b64u(b"short"), "claim": {}})
    assert resp.status_code == 400 and resp.json()["error"] == "bad_device_key"
    sk = devicekey.generate_device_key()
    resp = env.client.post(
        "/enroll",
        json={"device_pub": b64u(devicekey.device_public_raw(sk)), "attester": "nope"},
    )
    assert resp.status_code == 400 and resp.json()["error"] == "unknown_attester"


def test_issue_happy_path_token_verifies(env: SimpleNamespace) -> None:
    """Full issuer-side flow: the returned blind signature finalizes into a token
    that the pure verifier accepts against the published keyset."""
    from zkage_verifier import verify_token

    account_id, sk = enroll(env.client, age=25)

    keyset = keys.keyset_from_json_dict(env.client.get("/keys").json())
    record = next(r for r in keyset if r.scope == 18)
    public_key = record.public_key()

    challenge = token.make_challenge(RP, 18, now=NOW)
    msg = token.token_msg_for_challenge(challenge, record.key_id)
    prepared = rsabssa.prepare(msg)
    blinded, inv = rsabssa.blind(public_key, prepared)

    resp = env.client.post("/issue", json=issue_body(account_id, sk, 18, blinded))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert unb64u(body["key_id"]) == record.key_id

    sig = rsabssa.finalize(public_key, prepared, unb64u(body["blind_sig"]), inv)
    wire = token.encode_token(prepared, sig)
    result = verify_token(wire, keyset, challenge, now=NOW)
    assert result.ok and result.scope == 18


def test_issue_bad_signature_rejected(env: SimpleNamespace) -> None:
    account_id, sk = enroll(env.client)
    body = issue_body(account_id, sk, 18, dummy_blinded(), signature=bytes(64))
    resp = env.client.post("/issue", json=body)
    assert resp.status_code == 401 and resp.json()["error"] == "bad_issuance_signature"


def test_issue_signature_must_bind_blinded_msg(env: SimpleNamespace) -> None:
    """Anti-proxying: a valid signature over blinded A must not authorize blinded B."""
    account_id, sk = enroll(env.client)
    request_id = secrets.token_bytes(16)
    sig_for_a = devicekey.sign_issuance(sk, account_id, 18, dummy_blinded(), NOW, request_id)
    body = issue_body(
        account_id, sk, 18, dummy_blinded(), request_id=request_id, signature=sig_for_a
    )
    resp = env.client.post("/issue", json=body)
    assert resp.status_code == 401 and resp.json()["error"] == "bad_issuance_signature"


def test_issue_unknown_account(env: SimpleNamespace) -> None:
    sk = devicekey.generate_device_key()
    body = issue_body(secrets.token_bytes(16), sk, 18, dummy_blinded())
    resp = env.client.post("/issue", json=body)
    assert resp.status_code == 401 and resp.json()["error"] == "unknown_or_expired_account"


def test_issue_over_scope_forbidden(env: SimpleNamespace) -> None:
    account_id, sk = enroll(env.client, age=16)
    resp = env.client.post("/issue", json=issue_body(account_id, sk, 18, dummy_blinded()))
    assert resp.status_code == 403 and resp.json()["error"] == "scope_not_authorized"


def test_issue_stale_timestamp(env: SimpleNamespace) -> None:
    account_id, sk = enroll(env.client)
    resp = env.client.post(
        "/issue", json=issue_body(account_id, sk, 18, dummy_blinded(), ts=NOW - 120)
    )
    assert resp.status_code == 401 and resp.json()["error"] == "stale_request"


def test_issue_replayed_request_id(env: SimpleNamespace) -> None:
    account_id, sk = enroll(env.client)
    body = issue_body(account_id, sk, 18, dummy_blinded())
    assert env.client.post("/issue", json=body).status_code == 200
    resp = env.client.post("/issue", json=body)
    assert resp.status_code == 401 and resp.json()["error"] == "replayed_request"


def test_issue_rate_limited(env: SimpleNamespace) -> None:
    account_id, sk = enroll(env.client)
    for _ in range(2):
        resp = env.client.post("/issue", json=issue_body(account_id, sk, 18, dummy_blinded()))
        assert resp.status_code == 200
    resp = env.client.post("/issue", json=issue_body(account_id, sk, 18, dummy_blinded()))
    assert resp.status_code == 429 and resp.json()["error"] == "rate_limited"
    assert int(resp.headers["Retry-After"]) >= 1


def test_log_endpoints_consistent(env: SimpleNamespace) -> None:
    records = translog.from_jsonl(env.client.get("/log").text)
    head_hash = translog.verify_chain(records)

    payload = env.client.get("/log/head").json()
    head = translog.SignedHead.from_json_dict(payload["head"])
    log_public = devicekey.load_device_public(unb64u(payload["log_public_key"]))
    translog.verify_head(log_public, head)
    assert head.head_hash == head_hash and head.size == len(records)

    keyset = keys.keyset_from_json_dict(env.client.get("/keys").json())
    assert sorted(r.scope for r in keyset) == [13, 16, 18, 21]
    for record in keyset:
        record.public_key()  # policy + key_id consistency
