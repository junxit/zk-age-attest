"""End-to-end key lifecycle: a running federation rotates and revokes live.

The issuer hot-reloads on log change; the demo RP re-reads its keyset per
redemption; pinned UAs accept the appended log as an extension. Together:
rotation retires old tokens' trust anchors at the next redemption, and
revocation fails closed before any issuance.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

# The `world` and `federation_dir` fixtures come from sibling conftest.py.
from test_adversarial import UNIFORM, enroll, fetch_challenge, obtain_token, redeem

from zkage_issuer.federation import revoke_scope_key, rotate_scope_key
from zkage_rp.app import create_app as create_rp_app
from zkage_rp.app import keyset_file_provider
from zkage_ua import client as ua_client
from zkage_verifier import Decision


def test_rotation_end_to_end(world: SimpleNamespace, federation_dir: Path, tmp_path: Path) -> None:
    """Stockpiled pre-rotation tokens die at redemption; fresh flows just work."""
    rp = create_rp_app(
        keyset_file_provider(federation_dir / "public" / "keyset.json"),
        "rp3.test",
        lambda: world.clock["now"],
        lambda: world.state.signed_head.head_hash,
    )
    world.transport.register("rp3.test", rp)

    state_path = enroll(world, tmp_path)

    # Pre-rotation, epoch 1: a token redeems fine at the refreshing RP.
    challenge = fetch_challenge(world, host="rp3.test")
    wire = obtain_token(world, state_path, challenge)
    assert redeem(world, wire, host="rp3.test").json() == {"verified": True, "scope": 18}

    # Mint a second epoch-1 token but hold on to it (stockpiled).
    held_challenge = fetch_challenge(world, host="rp3.test")
    held_wire = obtain_token(world, state_path, held_challenge)

    old_key_id = next(r for r in world.keyset if r.scope == 18).key_id

    # Rotate on disk; nothing restarts.
    new_record = rotate_scope_key(federation_dir, 18, now=world.clock["now"])
    assert new_record.epoch == 2 and new_record.key_id != old_key_id

    # The stockpiled epoch-1 token dies at its first post-rotation redemption:
    # the refreshed RP no longer knows the retired key.
    resp = redeem(world, held_wire, host="rp3.test")
    assert resp.status_code == 400 and resp.json() == UNIFORM
    assert rp.state.decisions[-1] is Decision.UNKNOWN_KEY

    # A fresh flow crosses the whole stack: the UA extends its pinned log
    # (four records became six), the issuer hot-reloaded to the epoch-2 key
    # mid-request, and the RP verifies under the new keyset entry.
    result = ua_client.verify_with_rp(
        world.http, state_path, "http://rp3.test", 18, now=world.clock["now"]
    )
    assert result == {"verified": True, "scope": 18}


def test_revocation_fails_closed_at_the_ua(
    world: SimpleNamespace, federation_dir: Path, tmp_path: Path
) -> None:
    """After revoking scope 13, the UA refuses to even request issuance."""
    state_path = enroll(world, tmp_path)

    # Sanity first: scope 13 works before revocation.
    result = ua_client.verify_with_rp(
        world.http, state_path, "http://rp.test", 13, now=world.clock["now"]
    )
    assert result == {"verified": True, "scope": 13}
    decisions_before = len(world.rp_app.state.decisions)

    revoke_scope_key(federation_dir, 13, now=world.clock["now"])

    with pytest.raises(ua_client.UAError, match="no active federation key"):
        ua_client.verify_with_rp(
            world.http, state_path, "http://rp.test", 13, now=world.clock["now"]
        )
    assert len(world.rp_app.state.decisions) == decisions_before  # RP saw nothing

    # Other scopes unaffected.
    result = ua_client.verify_with_rp(
        world.http, state_path, "http://rp.test", 18, now=world.clock["now"]
    )
    assert result == {"verified": True, "scope": 18}
