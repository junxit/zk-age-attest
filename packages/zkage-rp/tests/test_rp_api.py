"""RP endpoint battery: challenge issuance, uniform rejection, sweep behavior."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from zkage_core import keys, token
from zkage_core.encoding import b64u
from zkage_rp.app import _UNIFORM_FAILURE, create_app

NOW = 1_750_000_000
RP = "demo-rp.example"


@pytest.fixture(scope="module")
def env() -> SimpleNamespace:
    sk = keys.generate_scope_key(2048)
    record = keys.ScopeKeyRecord(
        scope=18,
        epoch=1,
        key_id=keys.key_id_of(sk.public_key()),
        spki=keys.spki_der(sk.public_key()),
        not_before=0,
        not_after=NOW * 2,
        status="active",
    )
    clock = {"now": NOW}
    app = create_app([record], RP, lambda: clock["now"], lambda: b"\x07" * 32)
    return SimpleNamespace(client=TestClient(app), clock=clock, app=app)


def test_challenge_shape(env: SimpleNamespace) -> None:
    resp = env.client.get("/challenge?scope=18")
    assert resp.status_code == 200
    challenge = token.Challenge.from_json_dict(resp.json())
    assert challenge.rp_id == RP and challenge.scope == 18
    assert challenge.expires_at == env.clock["now"] + token.DEFAULT_CHALLENGE_TTL
    assert challenge.log_head == b"\x07" * 32


def test_challenge_rejects_bad_scope(env: SimpleNamespace) -> None:
    assert env.client.get("/challenge?scope=17").status_code == 400


def test_redeem_uniform_failures(env: SimpleNamespace) -> None:
    bodies = []
    for bad in ("&&not-b64", b64u(b"short"), b64u(bytes(410))):
        resp = env.client.post("/redeem", json={"token": bad})
        assert resp.status_code == 400
        bodies.append(resp.json())
    assert all(body == _UNIFORM_FAILURE for body in bodies)


def test_unknown_nonce_is_uniform(env: SimpleNamespace) -> None:
    """A structurally valid token with no pending challenge gets the same error."""
    digest = token.challenge_digest(RP, 18, bytes(32), NOW + 60)
    msg = token.encode_token_msg(18, bytes(32), digest, bytes(32), NOW + 60)
    wire = token.encode_token(bytes(32) + msg, bytes(256))
    resp = env.client.post("/redeem", json={"token": b64u(wire)})
    assert resp.status_code == 400 and resp.json() == _UNIFORM_FAILURE


def test_sweep_drops_expired_challenges(env: SimpleNamespace) -> None:
    env.client.get("/challenge?scope=18")
    store = env.app.state.pending
    before = len(store)
    assert before >= 1
    env.clock["now"] += token.DEFAULT_CHALLENGE_TTL + 1
    env.client.get("/challenge?scope=18")  # triggers sweep
    assert len(store) == 1  # only the fresh one survives


def test_index_page_renders(env: SimpleNamespace) -> None:
    resp = env.client.get("/")
    assert resp.status_code == 200 and RP in resp.text and "over-18" in resp.text
