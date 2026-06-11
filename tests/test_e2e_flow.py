"""End-to-end: enroll → challenge → blind issuance → finalize → redeem, plus the CLI."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from zkage_ua import cli
from zkage_ua import client as ua_client


def test_full_flow_over_18(world: SimpleNamespace, tmp_path: Path) -> None:
    state_path = tmp_path / "ua-state.json"
    state = ua_client.enroll(world.http, "http://issuer.test", 21, state_path)
    assert state.max_scope == 21
    assert state.pinned_size == 4  # one log record per scope

    result = ua_client.verify_with_rp(
        world.http, state_path, "http://rp.test", 18, now=world.clock["now"]
    )
    assert result == {"verified": True, "scope": 18}

    # The RP's internal log shows exactly one OK decision and nothing else.
    decisions = world.rp_app.state.decisions
    assert [d.value for d in decisions] == ["ok"]


def test_full_flow_multiple_scopes(world: SimpleNamespace, tmp_path: Path) -> None:
    state_path = tmp_path / "ua-state.json"
    ua_client.enroll(world.http, "http://issuer.test", 21, state_path)
    for scope in (13, 16, 18, 21):
        result = ua_client.verify_with_rp(
            world.http, state_path, "http://rp.test", scope, now=world.clock["now"]
        )
        assert result == {"verified": True, "scope": scope}, f"scope {scope}"


def test_underage_scope_refused_at_issuance(world: SimpleNamespace, tmp_path: Path) -> None:
    state_path = tmp_path / "ua-state.json"
    ua_client.enroll(world.http, "http://issuer.test", 16, state_path)
    with pytest.raises(ua_client.UAError, match="scope_not_authorized"):
        ua_client.verify_with_rp(
            world.http, state_path, "http://rp.test", 18, now=world.clock["now"]
        )
    assert world.rp_app.state.decisions == []  # nothing ever reached the RP


def test_cli_end_to_end(
    world: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The CLI drives the same flow and prints the documented lines."""

    class NoCloseClient:
        """Hand the CLI our fixture client; swallow its context-manager close."""

        def __enter__(self) -> object:
            return world.http

        def __exit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(cli.httpx, "Client", lambda **kwargs: NoCloseClient())
    state_arg = str(tmp_path / "cli-state.json")

    code = cli.main(
        ["enroll", "--issuer", "http://issuer.test", "--claim-age", "21", "--state", state_arg]
    )
    assert code == 0
    assert "enrolled: account active, max scope over-21" in capsys.readouterr().out

    code = cli.main(["verify", "--rp", "http://rp.test", "--scope", "18", "--state", state_arg])
    assert code == 0
    assert "verified: over-18" in capsys.readouterr().out

    code = cli.main(["log-status", "--state", state_arg])
    assert code == 0
    out = capsys.readouterr().out
    assert "log ok: 4 records" in out
