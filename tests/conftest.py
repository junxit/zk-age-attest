"""Shared integration fixtures: one federation, in-process issuer+RP, multi-host HTTP."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from zkage_core.keys import keyset_from_json_dict
from zkage_issuer.app import create_app as create_issuer_app
from zkage_issuer.attester import StubAttester
from zkage_issuer.federation import FederationState, init_state
from zkage_issuer.ratelimit import RateLimiter
from zkage_issuer.store import IssuerStore

# Anchored to real time so the CLI (which uses the wall clock) stays inside the
# federation keys' validity window, exactly as in the live demo.
NOW0 = int(time.time())


class MultiAppTransport(httpx.BaseTransport):
    """Route absolute URLs to in-process ASGI apps by hostname (no live servers)."""

    def __init__(self) -> None:
        self._clients: dict[str, TestClient] = {}

    def register(self, host: str, app: object) -> None:
        self._clients[host] = TestClient(app, raise_server_exceptions=False)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        client = self._clients[request.url.host]
        target = request.url.path or "/"
        if request.url.query:
            target += "?" + request.url.query.decode()
        headers = {"content-type": request.headers.get("content-type", "application/json")}
        resp = client.request(request.method, target, content=request.content, headers=headers)
        return httpx.Response(resp.status_code, headers=resp.headers, content=resp.content)


@pytest.fixture(scope="session")
def federation_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    state_dir = tmp_path_factory.mktemp("federation")
    init_state(state_dir, now=NOW0)
    return state_dir


def build_world(federation_dir: Path, tmp_path: Path, rp_id: str = "demo-rp.example"):
    """Fresh issuer + RP apps over the shared federation keys, isolated stores."""
    from zkage_rp.app import create_app as create_rp_app

    clock = {"now": int(time.time())}

    def clock_fn() -> int:
        return clock["now"]

    state = FederationState.load(federation_dir, now=clock["now"])
    store = IssuerStore(tmp_path / "issuer.sqlite")
    limiter = RateLimiter(capacity=1000, refill_seconds=0.001, daily_cap=100_000)
    issuer_app = create_issuer_app(state, store, limiter, {"stub": StubAttester()}, clock_fn)

    keyset = keyset_from_json_dict(
        json.loads((federation_dir / "public" / "keyset.json").read_text())
    )
    rp_app = create_rp_app(keyset, rp_id, clock_fn, lambda: state.signed_head.head_hash)

    transport = MultiAppTransport()
    transport.register("issuer.test", issuer_app)
    transport.register("rp.test", rp_app)
    http = httpx.Client(transport=transport)

    return SimpleNamespace(
        http=http,
        clock=clock,
        state=state,
        keyset=keyset,
        issuer_app=issuer_app,
        rp_app=rp_app,
        transport=transport,
    )


@pytest.fixture()
def world(federation_dir: Path, tmp_path: Path) -> SimpleNamespace:
    return build_world(federation_dir, tmp_path)
