"""Demo relying party.

Issues challenges and redeems tokens. Verification is the pure
``zkage_verifier.verify_token`` against a static, pinned keyset — the
redemption path makes zero network calls. All failures return one uniform
external error (no token-state oracle); precise decisions go to the RP's own
log only.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from zkage_core.encoding import unb64u
from zkage_core.keys import KeyPolicyError, ScopeKeyRecord, keyset_from_json_dict
from zkage_core.token import SCOPES, TokenFormatError, make_challenge, parse_token
from zkage_rp.replay import PendingChallengeStore, PendingStore
from zkage_verifier import Decision, verify_token

logger = logging.getLogger("zkage_rp")

_UNIFORM_FAILURE = {"verified": False, "error": "invalid_or_unknown"}


class RedeemRequest(BaseModel):
    token: str


def keyset_file_provider(path: Path) -> Callable[[], list[ScopeKeyRecord]]:
    """Build a keyset provider that re-reads ``path`` on every redemption.

    This is the RP-side half of rotation/revocation: when the issuer
    republishes ``keyset.json``, the next redemption sees the new trust anchors
    without an application restart. Re-reading per redemption is deliberate —
    the file holds one record per scope (the log grows ~8 records/quarter), so
    the cost is nil and no staleness window can survive a request boundary.

    Fail-closed: a missing, unreadable, or malformed keyset yields an empty
    list, so nothing verifies rather than something stale verifying.
    """

    def provide() -> list[ScopeKeyRecord]:
        try:
            return keyset_from_json_dict(json.loads(path.read_text()))
        except (OSError, ValueError, KeyPolicyError):
            return []

    return provide


def create_app(
    keyset: list[ScopeKeyRecord] | Callable[[], list[ScopeKeyRecord]],
    rp_id: str,
    clock: Callable[[], int],
    log_head_provider: Callable[[], bytes | None] = lambda: None,
    pending_store: PendingStore | None = None,
) -> FastAPI:
    """Build the RP app with an injected keyset, identity, clock, and log head.

    ``keyset`` may be a static list (tests) or a zero-arg provider consulted
    at each redemption (demo/production refresh via :func:`keyset_file_provider`).
    ``pending_store`` swaps the in-process nonce store for a shared one
    (e.g., :class:`zkage_rp.redis_replay.RedisPendingChallengeStore`).
    """
    app = FastAPI(title="zkage-rp", version="0.1.0")
    store = pending_store if pending_store is not None else PendingChallengeStore()
    app.state.pending = store
    app.state.decisions = []  # internal log of Decision values (introspectable in tests)

    def current_keyset() -> list[ScopeKeyRecord]:
        return keyset() if callable(keyset) else keyset

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _INDEX_HTML.replace("__RP_ID__", rp_id)

    @app.get("/challenge")
    def challenge(scope: int = 18) -> object:
        if scope not in SCOPES:
            return JSONResponse({"error": "bad_scope"}, status_code=400)
        now = clock()
        store.sweep(now)
        fresh = make_challenge(rp_id, scope, now, log_head=log_head_provider())
        store.put(fresh)
        return fresh.to_json_dict()

    def _reject(decision: Decision) -> JSONResponse:
        app.state.decisions.append(decision)
        logger.info("redemption rejected: %s", decision.value)
        return JSONResponse(_UNIFORM_FAILURE, status_code=400)

    @app.post("/redeem")
    def redeem(req: RedeemRequest) -> object:
        now = clock()
        store.sweep(now)
        try:
            wire = unb64u(req.token)
            fields = parse_token(wire)  # structural only; no crypto yet
        except (ValueError, TokenFormatError):
            return _reject(Decision.MALFORMED)

        # Pop-before-verify: burn the pending challenge before any crypto.
        pending = store.pop(fields.nonce)
        if pending is None:
            return _reject(Decision.CHALLENGE_MISMATCH)

        result = verify_token(wire, current_keyset(), pending, now)
        app.state.decisions.append(result.decision)
        if not result.ok:
            logger.info("redemption rejected: %s", result.decision.value)
            return JSONResponse(_UNIFORM_FAILURE, status_code=400)
        return {"verified": True, "scope": result.scope}

    return app


def create_demo_app() -> FastAPI:
    """Uvicorn factory.

    Env: ``ZKAGE_KEYSET`` (default ./demo-state/public/keyset.json),
    ``ZKAGE_RP_ID`` (default 127.0.0.1 — must match the hostname UAs use to
    reach this RP; the UA aborts on a challenge/rp_id mismatch),
    ``ZKAGE_REDIS_URL`` (optional; enables the shared Redis pending store for
    multi-worker deployments). The keyset is re-read per redemption
    (rotation/revocation take effect without restart); the log head for
    split-view gossip is read from log_head.json next to the keyset.
    """
    keyset_path = Path(os.environ.get("ZKAGE_KEYSET", "./demo-state/public/keyset.json"))
    rp_id = os.environ.get("ZKAGE_RP_ID", "127.0.0.1")

    head_path = keyset_path.parent / "log_head.json"

    def log_head_provider() -> bytes | None:
        try:
            head = json.loads(head_path.read_text())
            return unb64u(str(head["head_hash"]))
        except (OSError, ValueError, KeyError):
            return None

    pending_store = None
    redis_url = os.environ.get("ZKAGE_REDIS_URL")
    if redis_url:
        try:
            import redis
        except ImportError as exc:
            raise RuntimeError(
                "ZKAGE_REDIS_URL is set but the 'redis' package is not installed"
                " (uv pip install redis)"
            ) from exc
        from zkage_rp.redis_replay import RedisPendingChallengeStore

        pending_store = RedisPendingChallengeStore(redis.Redis.from_url(redis_url))

    return create_app(
        keyset_file_provider(keyset_path),
        rp_id,
        lambda: int(time.time()),
        log_head_provider,
        pending_store=pending_store,
    )


_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>__RP_ID__ — age-gated demo</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 3rem auto; padding: 0 1rem; }
  code, pre { background: #f4f4f4; padding: 0.15rem 0.35rem; border-radius: 4px; }
  pre { padding: 0.75rem; overflow-x: auto; }
  .ok { color: #0a7d33; font-weight: 600; }
  .no { color: #b00020; font-weight: 600; }
  button { padding: 0.5rem 1rem; }
  textarea { width: 100%; min-height: 4rem; }
</style>
</head>
<body>
<h1>__RP_ID__</h1>
<p>This demo relying party gates content on <strong>over-18</strong>. It learns only
the age predicate: no identity, no birth date, no issuer operator, no account.</p>

<h2>1. Get a challenge</h2>
<button id="get">Request challenge</button>
<pre id="challenge">(none yet)</pre>
<p>Then run the user agent against this site:</p>
<pre>uv run zkage-ua verify --rp http://127.0.0.1:8002 --scope 18 --state ./ua-state.json</pre>

<h2>2. Or paste a token to redeem manually</h2>
<textarea id="token" placeholder="base64url token"></textarea>
<button id="redeem">Redeem</button>
<p id="result"></p>

<script>
document.getElementById('get').onclick = async () => {
  const r = await fetch('/challenge?scope=18');
  document.getElementById('challenge').textContent = JSON.stringify(await r.json(), null, 1);
};
document.getElementById('redeem').onclick = async () => {
  const token = document.getElementById('token').value.trim();
  const r = await fetch('/redeem', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({token}),
  });
  const body = await r.json();
  const el = document.getElementById('result');
  el.textContent = body.verified ? `verified: over-${body.scope}` : 'rejected (invalid or unknown)';
  el.className = body.verified ? 'ok' : 'no';
};
</script>
</body>
</html>
"""
