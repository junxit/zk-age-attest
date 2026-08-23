"""Adversarial battery: replay, expiry, scope confusion, forgery, cross-RP replay,
malformed input uniformity, and the UA's fail-closed checks (key substitution,
log rollback, split view)."""

from __future__ import annotations

import dataclasses
import secrets
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

from zkage_core import devicekey, keys, rsabssa, translog
from zkage_core import token as token_mod
from zkage_core.encoding import b64u, unb64u
from zkage_core.token import Challenge, encode_token, encode_token_msg
from zkage_ua import client as ua_client
from zkage_ua.state import load_state, save_state

UNIFORM = {"verified": False, "error": "invalid_or_unknown"}


def enroll(world: SimpleNamespace, tmp_path: Path, age: int = 21) -> Path:
    state_path = tmp_path / f"ua-{secrets.token_hex(4)}.json"
    ua_client.enroll(world.http, "http://issuer.test", age, state_path)
    return state_path


def fetch_challenge(world: SimpleNamespace, scope: int = 18, host: str = "rp.test") -> Challenge:
    resp = world.http.get(f"http://{host}/challenge?scope={scope}")
    return Challenge.from_json_dict(resp.json())


def obtain_token(
    world: SimpleNamespace,
    state_path: Path,
    challenge: Challenge,
    *,
    token_scope: int | None = None,
) -> bytes:
    """Issue a token bound to ``challenge``; optionally lie about the token scope."""
    state = load_state(state_path)
    scope = token_scope if token_scope is not None else challenge.scope
    record = next(r for r in world.keyset if r.scope == scope)
    public_key = record.public_key()

    msg = encode_token_msg(
        scope, record.key_id, challenge.digest(), challenge.nonce, challenge.expires_at
    )
    prepared = rsabssa.prepare(msg)
    blinded, inv = rsabssa.blind(public_key, prepared)

    device = devicekey.load_device_private(state.device_sk_raw)
    request_id = secrets.token_bytes(16)
    now = world.clock["now"]
    sig = devicekey.sign_issuance(device, state.account_id, scope, blinded, now, request_id)
    resp = world.http.post(
        "http://issuer.test/issue",
        json={
            "account_id": b64u(state.account_id),
            "scope": scope,
            "blinded_msg": b64u(blinded),
            "ts": now,
            "request_id": b64u(request_id),
            "signature": b64u(sig),
        },
    )
    assert resp.status_code == 200, resp.text
    final = rsabssa.finalize(public_key, prepared, unb64u(resp.json()["blind_sig"]), inv)
    return encode_token(prepared, final)


def redeem(world: SimpleNamespace, wire: bytes, host: str = "rp.test") -> object:
    return world.http.post(f"http://{host}/redeem", json={"token": b64u(wire)})


def test_replay_rejected_uniformly(world: SimpleNamespace, tmp_path: Path) -> None:
    state_path = enroll(world, tmp_path)
    challenge = fetch_challenge(world)
    wire = obtain_token(world, state_path, challenge)

    first = redeem(world, wire)
    assert first.status_code == 200 and first.json() == {"verified": True, "scope": 18}

    second = redeem(world, wire)
    assert second.status_code == 400 and second.json() == UNIFORM


def test_expired_challenge_rejected(world: SimpleNamespace, tmp_path: Path) -> None:
    state_path = enroll(world, tmp_path)
    challenge = fetch_challenge(world)
    wire = obtain_token(world, state_path, challenge)
    world.clock["now"] = challenge.expires_at + 1
    resp = redeem(world, wire)
    assert resp.status_code == 400 and resp.json() == UNIFORM


def test_scope_confusion_rejected(world: SimpleNamespace, tmp_path: Path) -> None:
    """A token carrying scope 13 must not satisfy an over-18 challenge, even when
    correctly signed under the scope-13 key and bound to the same nonce."""
    state_path = enroll(world, tmp_path)
    challenge = fetch_challenge(world, scope=18)
    wire = obtain_token(world, state_path, challenge, token_scope=13)
    resp = redeem(world, wire)
    assert resp.status_code == 400 and resp.json() == UNIFORM
    assert world.rp_app.state.decisions[-1].value == "wrong_scope"


def test_forged_signature_rejected(world: SimpleNamespace, tmp_path: Path) -> None:
    state_path = enroll(world, tmp_path)
    challenge = fetch_challenge(world)
    wire = obtain_token(world, state_path, challenge)
    forged = wire[: token_mod.PREPARED_LEN] + secrets.token_bytes(256)
    resp = redeem(world, forged)
    assert resp.status_code == 400 and resp.json() == UNIFORM
    assert world.rp_app.state.decisions[-1].value == "bad_signature"


def test_cross_rp_replay_rejected(
    world: SimpleNamespace, federation_dir: Path, tmp_path: Path
) -> None:
    """A token redeemed at rp.test is dead at a second RP: no pending nonce there."""
    from zkage_rp.app import create_app as create_rp_app

    rp2 = create_rp_app(world.keyset, "rp2.test", lambda: world.clock["now"])
    world.transport.register("rp2.test", rp2)

    state_path = enroll(world, tmp_path)
    challenge = fetch_challenge(world)
    wire = obtain_token(world, state_path, challenge)
    assert redeem(world, wire).status_code == 200

    resp = redeem(world, wire, host="rp2.test")
    assert resp.status_code == 400 and resp.json() == UNIFORM


def test_malformed_tokens_uniform(world: SimpleNamespace) -> None:
    bodies = []
    for bad in ("!!!", b64u(b"tiny"), b64u(secrets.token_bytes(410))):
        resp = world.http.post("http://rp.test/redeem", json={"token": bad})
        assert resp.status_code == 400
        bodies.append(resp.json())
    assert all(b == UNIFORM for b in bodies)


def test_all_failure_modes_externally_indistinguishable(
    world: SimpleNamespace, tmp_path: Path
) -> None:
    """Replay, forgery, scope confusion, garbage: byte-identical responses."""
    state_path = enroll(world, tmp_path)
    failures = []

    challenge = fetch_challenge(world)
    wire = obtain_token(world, state_path, challenge)
    redeem(world, wire)
    failures.append(redeem(world, wire))  # replay

    challenge2 = fetch_challenge(world)
    wire2 = obtain_token(world, state_path, challenge2)
    failures.append(
        redeem(world, wire2[: token_mod.PREPARED_LEN] + secrets.token_bytes(256))
    )  # forgery (burns challenge2)

    challenge3 = fetch_challenge(world, scope=18)
    failures.append(redeem(world, obtain_token(world, state_path, challenge3, token_scope=13)))

    failures.append(world.http.post("http://rp.test/redeem", json={"token": "@@"}))

    assert {f.status_code for f in failures} == {400}
    assert all(f.json() == UNIFORM for f in failures)


def _evil_issuer_base(world: SimpleNamespace) -> FastAPI:
    """An issuer that serves the HONEST log but misbehaves elsewhere."""
    evil = FastAPI()
    state = world.state

    @evil.get("/log")
    def log() -> PlainTextResponse:
        return PlainTextResponse(translog.to_jsonl(state.records))

    @evil.get("/log/head")
    def head() -> object:
        return {
            "head": state.signed_head.to_json_dict(),
            "log_public_key": b64u(state.log_public_raw),
        }

    return evil


def _point_ua_at(state_path: Path, issuer_url: str) -> None:
    state = load_state(state_path)
    save_state(state_path, dataclasses.replace(state, issuer_url=issuer_url))


def _rogue_key_for(honest_record: keys.ScopeKeyRecord) -> rsa.RSAPrivateKey:
    """A rogue key whose modulus is at least as large as the honest one's.

    The UA blinds against the honest (transparency-logged) modulus, so the
    blinded message is uniform in ``[0, n_honest)``. ``rsabssa.blind_sign``
    rejects ``m >= n``, so a rogue key with a smaller modulus makes the evil
    issuer raise -- and the UA then reports a transport error instead of
    reaching the key-substitution check this test exists to exercise. Measured
    over 1560 key pairs that misfires on ~7% of runs. Requiring
    ``n_rogue >= n_honest`` keeps the substitution itself the only variable.
    """
    honest_n = honest_record.public_key().public_numbers().n
    while True:
        rogue = keys.generate_scope_key(2048)
        if rogue.private_numbers().public_numbers.n >= honest_n:
            return rogue


def test_ua_aborts_on_key_substitution(world: SimpleNamespace, tmp_path: Path) -> None:
    """Issuer signs with a rogue key while claiming the logged key id: the UA's
    Finalize check against the transparency-logged key fails closed, and no
    token ever reaches the RP."""
    evil = _evil_issuer_base(world)
    honest_record = next(r for r in world.keyset if r.scope == 18)
    rogue = _rogue_key_for(honest_record)

    @evil.post("/issue")
    async def issue(request: Request) -> object:
        body = await request.json()
        blind_sig = rsabssa.blind_sign(rogue, unb64u(body["blinded_msg"]))
        return {
            "blind_sig": b64u(blind_sig),
            "key_id": b64u(honest_record.key_id),  # the lie
            "scope": 18,
            "epoch": 1,
        }

    world.transport.register("evil.test", evil)
    state_path = enroll(world, tmp_path)
    _point_ua_at(state_path, "http://evil.test")

    with pytest.raises(ua_client.UAError, match="key substitution"):
        ua_client.verify_with_rp(
            world.http, state_path, "http://rp.test", 18, now=world.clock["now"]
        )
    assert world.rp_app.state.decisions == [], (
        f"a token reached the RP despite the fail-closed abort: {world.rp_app.state.decisions}"
    )


def test_ua_aborts_on_log_rollback(world: SimpleNamespace, tmp_path: Path) -> None:
    """A (compromised) issuer serving a truncated log with a freshly signed head
    cannot get past the UA's pinned append-only check."""
    state_path = enroll(world, tmp_path)  # pins all 4 records

    truncated = world.state.records[:2]
    head = translog.sign_head(
        world.state.log_key, 2, translog.verify_chain(truncated), world.clock["now"]
    )
    evil = FastAPI()

    @evil.get("/log")
    def log() -> PlainTextResponse:
        return PlainTextResponse(translog.to_jsonl(truncated))

    @evil.get("/log/head")
    def evil_head() -> object:
        return {"head": head.to_json_dict(), "log_public_key": b64u(world.state.log_public_raw)}

    world.transport.register("evil.test", evil)
    _point_ua_at(state_path, "http://evil.test")

    with pytest.raises(ua_client.UAError, match="rollback"):
        ua_client.verify_with_rp(
            world.http, state_path, "http://rp.test", 18, now=world.clock["now"]
        )


def test_ua_aborts_on_split_view(world: SimpleNamespace, tmp_path: Path) -> None:
    """An RP gossiping a log head the UA cannot reconcile triggers an abort
    before any issuance happens."""
    from zkage_rp.app import create_app as create_rp_app

    forked_rp = create_rp_app(
        world.keyset,
        "forked-rp.test",
        lambda: world.clock["now"],
        lambda: secrets.token_bytes(32),
    )
    world.transport.register("forked-rp.test", forked_rp)

    state_path = enroll(world, tmp_path)
    with pytest.raises(ua_client.UAError, match="split-view"):
        ua_client.verify_with_rp(
            world.http, state_path, "http://forked-rp.test", 18, now=world.clock["now"]
        )


def _register_mini_rp(
    world: SimpleNamespace,
    host: str,
    *,
    rp_id: str | None = None,
    challenge_ttl_pad: int = 0,
    redeem_response: object | None = None,
) -> FastAPI:
    """A minimal stand-in RP: honest-looking challenge, canned redeem reply."""
    from fastapi.responses import Response

    mini = FastAPI()
    used_id = rp_id if rp_id is not None else host

    @mini.get("/challenge")
    def challenge(scope: int = 18) -> object:
        c = fetch_challenge(world, scope=scope)
        return dataclasses.replace(
            c,
            rp_id=used_id,
            expires_at=c.expires_at + challenge_ttl_pad,
            nonce=secrets.token_bytes(32),
        ).to_json_dict()

    @mini.post("/redeem")
    def redeem() -> object:
        if isinstance(redeem_response, Response):
            return redeem_response
        return {"verified": True, "scope": 18}

    world.transport.register(host, mini)
    return mini


def test_ua_survives_non_json_redemption_reply(world: SimpleNamespace, tmp_path: Path) -> None:
    """A gateway error page instead of JSON is a clean UAError, not a crash."""
    from fastapi.responses import PlainTextResponse

    _register_mini_rp(
        world,
        "html-rp.test",
        rp_id="html-rp.test",
        redeem_response=PlainTextResponse("<html>502 Bad Gateway</html>", status_code=502),
    )

    state_path = enroll(world, tmp_path)
    with pytest.raises(ua_client.UAError, match="malformed response"):
        ua_client.verify_with_rp(
            world.http, state_path, "http://html-rp.test", 18, now=world.clock["now"]
        )


def test_ua_aborts_when_challenge_rp_id_mismatches_host(
    world: SimpleNamespace, tmp_path: Path
) -> None:
    """A challenge minted for another rp_id never leaves this UA as a token."""
    _register_mini_rp(world, "bait.test", rp_id="somewhere-else.example")

    state_path = enroll(world, tmp_path)
    with pytest.raises(ua_client.UAError, match="rp_id"):
        ua_client.verify_with_rp(
            world.http, state_path, "http://bait.test", 18, now=world.clock["now"]
        )
    assert world.rp_app.state.decisions == []  # nothing was redeemed anywhere


def test_ua_aborts_on_overlong_challenge_lifetime(world: SimpleNamespace, tmp_path: Path) -> None:
    """An RP issuing beyond MAX_TOKEN_LIFETIME gets no issuance request at all."""
    _register_mini_rp(world, "stale.test", rp_id="stale.test", challenge_ttl_pad=100_000)

    state_path = enroll(world, tmp_path)
    with pytest.raises(ua_client.UAError, match="lifetime exceeds"):
        ua_client.verify_with_rp(
            world.http, state_path, "http://stale.test", 18, now=world.clock["now"]
        )
