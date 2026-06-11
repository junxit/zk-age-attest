"""Linkability simulation (the audit artifact).

Drives N users x M verifications and records the MAXIMAL view each side could
ever log: the issuer's full issuance requests and the RP's full challenges and
redeemed tokens. Then asserts the two views share **zero content identifiers**
(no common 8-byte substring across any issuer-side and RP-side byte field) and
emits an honest timing-correlation report — the residual the design documents
rather than hides (Risk 1; eliminated by the v2 offline mode).
"""

from __future__ import annotations

import random
import secrets
import statistics
from pathlib import Path

import pytest
from conftest import build_world

from zkage_core import devicekey, rsabssa
from zkage_core.encoding import b64u, unb64u
from zkage_core.token import Challenge, encode_token, token_msg_for_challenge
from zkage_ua import client as ua_client
from zkage_ua.state import load_state

N_USERS = 50
M_VERIFICATIONS = 4
WINDOW = 8  # bytes

REPORT_PATH = Path(__file__).resolve().parents[1] / "linkability-report.txt"


def windows(data: bytes, size: int = WINDOW) -> set[bytes]:
    return {data[i : i + size] for i in range(len(data) - size + 1)}


def test_linkability_simulation(
    federation_dir: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    rng = random.Random(20260610)
    tmp_path = tmp_path_factory.mktemp("sim")
    world = build_world(federation_dir, tmp_path)

    issuer_view: list[dict[str, object]] = []
    rp_view: list[dict[str, object]] = []
    dwells: list[int] = []

    users = []
    for i in range(N_USERS):
        state_path = tmp_path / f"user-{i}.json"
        ua_client.enroll(world.http, "http://issuer.test", 21, state_path)
        users.append(load_state(state_path))

    record18 = next(r for r in world.keyset if r.scope == 18)
    public_key = record18.public_key()

    for user in users:
        device = devicekey.load_device_private(user.device_sk_raw)
        for _ in range(M_VERIFICATIONS):
            world.clock["now"] += rng.randint(1, 30)

            resp = world.http.get("http://rp.test/challenge?scope=18")
            challenge = Challenge.from_json_dict(resp.json())

            msg = token_msg_for_challenge(challenge, record18.key_id)
            prepared = rsabssa.prepare(msg)
            blinded, inv = rsabssa.blind(public_key, prepared)
            request_id = secrets.token_bytes(16)
            issue_ts = world.clock["now"]
            sig = devicekey.sign_issuance(
                device, user.account_id, 18, blinded, issue_ts, request_id
            )
            issue_resp = world.http.post(
                "http://issuer.test/issue",
                json={
                    "account_id": b64u(user.account_id),
                    "scope": 18,
                    "blinded_msg": b64u(blinded),
                    "ts": issue_ts,
                    "request_id": b64u(request_id),
                    "signature": b64u(sig),
                },
            )
            assert issue_resp.status_code == 200
            issuer_view.append(
                {
                    "ts": issue_ts,
                    "account_id": user.account_id,
                    "device_pub": devicekey.device_public_raw(device),
                    "blinded_msg": blinded,
                    "request_id": request_id,
                    "issuance_sig": sig,
                }
            )

            final = rsabssa.finalize(
                public_key, prepared, unb64u(issue_resp.json()["blind_sig"]), inv
            )
            wire = encode_token(prepared, final)

            world.clock["now"] += rng.randint(1, 10)
            redeem = world.http.post("http://rp.test/redeem", json={"token": b64u(wire)})
            assert redeem.json() == {"verified": True, "scope": 18}
            rp_view.append(
                {
                    "ts": world.clock["now"],
                    "nonce": challenge.nonce,
                    "challenge_digest": challenge.digest(),
                    "token": wire,
                }
            )
            dwells.append(world.clock["now"] - issue_ts)

    total = N_USERS * M_VERIFICATIONS
    assert len(issuer_view) == len(rp_view) == total

    # --- Content unlinkability: zero shared >=8-byte substrings across sides.
    issuer_windows: set[bytes] = set()
    for entry in issuer_view:
        for field in ("account_id", "device_pub", "blinded_msg", "request_id", "issuance_sig"):
            issuer_windows |= windows(entry[field])  # type: ignore[arg-type]
    rp_windows: set[bytes] = set()
    for entry in rp_view:
        for field in ("nonce", "challenge_digest", "token"):
            rp_windows |= windows(entry[field])  # type: ignore[arg-type]

    overlap = issuer_windows & rp_windows
    assert overlap == set(), f"shared content identifiers found: {len(overlap)} windows"

    # --- Distinctness: blinded messages and tokens never repeat.
    blinded_set = {e["blinded_msg"] for e in issuer_view}
    token_set = {e["token"] for e in rp_view}
    assert len(blinded_set) == total and len(token_set) == total

    # --- Honest residual: the timing report.
    report = "\n".join(
        [
            "zk-age-attest linkability simulation report",
            "=" * 44,
            f"runs: {total} verifications across {N_USERS} users (scope 18)",
            f"issuer-side byte windows ({WINDOW}B): {len(issuer_windows)}",
            f"rp-side byte windows ({WINDOW}B): {len(rp_windows)}",
            "shared content windows: 0  (content unlinkability holds)",
            "",
            "RESIDUAL (documented, not hidden) — issuance-timing correlation:",
            f"  issuance→redemption dwell (s): min={min(dwells)} "
            f"median={statistics.median(dwells)} max={max(dwells)}",
            "  A colluding issuer+RP can join events on these timestamps when",
            "  traffic is sparse. Mitigations: client jitter, OHTTP relay for",
            "  issuance, traffic volume; eliminated by the v2 offline mode",
            "  (presentations without issuer contact). See THREAT-MODEL.md Risk 1.",
            "",
        ]
    )
    REPORT_PATH.write_text(report)
    print(report)
