"""Issuer FastAPI application.

The issuer authenticates *who may request a token* (device-key binding, rate
limits) and blind-signs *an opaque blob*. It never sees nonces, finished
tokens, or relying parties. Everything it can ever store is in
``zkage_issuer.store`` — auditors start there.
"""

from __future__ import annotations

import contextlib
import os
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from zkage_core import devicekey, rsabssa, translog
from zkage_core.encoding import b64u, unb64u
from zkage_core.keys import keyset_to_json_dict
from zkage_core.token import SCOPES
from zkage_issuer.attester import AttestationError, Attester, SignedClaimAttester, StubAttester
from zkage_issuer.federation import FederationState, FederationStateError, active_keyset
from zkage_issuer.ratelimit import RateLimiter
from zkage_issuer.store import Account, IssuerStore

DEFAULT_ACCOUNT_VALIDITY = 365 * 86_400


class EnrollRequest(BaseModel):
    device_pub: str
    attester: str = "stub"
    claim: dict[str, object] = Field(default_factory=dict)


class IssueRequest(BaseModel):
    account_id: str
    scope: int
    blinded_msg: str
    ts: int
    request_id: str
    signature: str


def _err(status: int, code: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status, headers=headers)


def create_app(
    state: FederationState,
    store: IssuerStore,
    limiter: RateLimiter,
    attesters: dict[str, Attester],
    clock: Callable[[], int],
) -> FastAPI:
    """Build the issuer app with injected state, store, limiter, and clock."""
    app = FastAPI(title="zkage-issuer", version="0.1.0")

    @app.post("/enroll")
    def enroll(req: EnrollRequest) -> object:
        try:
            device_pub = unb64u(req.device_pub)
            devicekey.load_device_public(device_pub)
        except (ValueError, devicekey.IssuanceBindingError):
            return _err(400, "bad_device_key")

        # One account per device key (Sybil control): a live enrollment is
        # returned as-is — re-enrolling never mints a fresh per-account rate
        # budget, and the claim is not re-attested while the account stands.
        now = clock()
        existing = store.get_account_by_device(device_pub)
        if existing is not None and existing.expires_at > now:
            return {
                "account_id": b64u(existing.account_id),
                "max_scope": existing.max_scope,
                "expires_at": existing.expires_at,
            }

        attester = attesters.get(req.attester)
        if attester is None:
            return _err(400, "unknown_attester")
        try:
            max_scope = attester.attest(req.claim)
        except AttestationError:
            return _err(403, "attestation_failed")

        if existing is not None:
            # Expired: renew in place (the unique index forbids a second row),
            # applying the fresh attestation result.
            account = Account(
                account_id=existing.account_id,
                device_pub=device_pub,
                max_scope=max_scope,
                enrolled_at=now,
                expires_at=now + DEFAULT_ACCOUNT_VALIDITY,
            )
            store.renew_account(
                existing.account_id,
                max_scope=max_scope,
                enrolled_at=now,
                expires_at=account.expires_at,
            )
            return {
                "account_id": b64u(account.account_id),
                "max_scope": max_scope,
                "expires_at": account.expires_at,
            }

        account = Account(
            account_id=uuid.uuid4().bytes,
            device_pub=device_pub,
            max_scope=max_scope,
            enrolled_at=now,
            expires_at=now + DEFAULT_ACCOUNT_VALIDITY,
        )
        if not store.add_account(account):
            # A concurrent enrollment for this device won the unique slot.
            winner = store.get_account_by_device(device_pub)
            if winner is None:  # pragma: no cover - slot existed a moment ago
                return _err(500, "enrollment_conflict")
            account = winner
        return {
            "account_id": b64u(account.account_id),
            "max_scope": account.max_scope,
            "expires_at": account.expires_at,
        }

    @app.post("/issue")
    def issue(req: IssueRequest) -> object:
        try:
            account_id = unb64u(req.account_id)
            blinded_msg = unb64u(req.blinded_msg)
            request_id = unb64u(req.request_id)
            signature = unb64u(req.signature)
        except ValueError:
            return _err(400, "bad_encoding")
        if req.scope not in SCOPES:
            return _err(400, "bad_scope")

        now = clock()
        state.maybe_reload(now)  # pick up on-disk rotations/revocations
        account = store.get_account(account_id)
        if account is None or account.expires_at <= now:
            return _err(401, "unknown_or_expired_account")

        # Authenticate first: the signature must bind THIS blinded message
        # (anti-proxying), this scope, a fresh timestamp, and a fresh request id.
        try:
            device_pub = devicekey.load_device_public(account.device_pub)
            devicekey.verify_issuance(
                device_pub, signature, account_id, req.scope, blinded_msg, req.ts, request_id
            )
        except devicekey.IssuanceBindingError:
            return _err(401, "bad_issuance_signature")
        if abs(req.ts - now) > devicekey.ISSUANCE_TS_WINDOW:
            return _err(401, "stale_request")
        if not store.mark_request(request_id, now):
            return _err(401, "replayed_request")

        if req.scope > account.max_scope:
            return _err(403, "scope_not_authorized")

        allowed, retry_after = limiter.check(account_id, float(now))
        if not allowed:
            return _err(429, "rate_limited", headers={"Retry-After": str(retry_after)})

        try:
            record, private_key = state.active_key(req.scope, now)
        except FederationStateError:
            return _err(500, "no_active_key")
        try:
            blind_sig = rsabssa.blind_sign(private_key, blinded_msg)
        except rsabssa.RsabssaError:
            return _err(400, "unsignable_blinded_msg")

        return {
            "blind_sig": b64u(blind_sig),
            "key_id": b64u(record.key_id),
            "scope": record.scope,
            "epoch": record.epoch,
        }

    @app.get("/keys")
    def keyset() -> object:
        now = clock()
        state.maybe_reload(now)
        return keyset_to_json_dict(active_keyset(state.records, now))

    @app.get("/log")
    def log() -> PlainTextResponse:
        state.maybe_reload(clock())
        return PlainTextResponse(translog.to_jsonl(state.records))

    @app.get("/log/head")
    def log_head() -> object:
        state.maybe_reload(clock())
        return {
            "head": state.signed_head.to_json_dict(),
            "log_public_key": b64u(state.log_public_raw),
        }

    return app


def create_demo_app() -> FastAPI:
    """Uvicorn factory: ``ZKAGE_STATE`` selects the state dir (default ./demo-state)."""
    state_dir = Path(os.environ.get("ZKAGE_STATE", "./demo-state"))
    now = int(time.time())
    state = FederationState.load(state_dir, now)
    store = IssuerStore(state_dir / "issuer" / "issuer.sqlite")

    attesters: dict[str, Attester] = {"stub": StubAttester()}
    attester_pub_path = state_dir / "public" / "attester_pub.b64"
    with contextlib.suppress(FileNotFoundError):
        # A federation predating the signed attester keeps the stub only.
        attesters["signed"] = SignedClaimAttester(unb64u(attester_pub_path.read_text().strip()))

    return create_app(state, store, RateLimiter(), attesters, lambda: int(time.time()))
