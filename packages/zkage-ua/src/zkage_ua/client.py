"""User-agent flows: enroll, transparency-log sync, and verify-with-RP.

The UA is the privacy-critical party: it blinds the challenge before the
issuer sees it, and it refuses to emit a token unless the issuer's signature
verifies under a key from the *verified, pinned* transparency log (failing
closed on key substitution, rollback, fork, or split view).

Fail-closed also means fail-clean: every server response is parsed defensively,
the challenged rp_id must match the RP actually being talked to, and a
challenge whose lifetime exceeds the verifier's maximum is aborted BEFORE any
issuance (so it cannot burn an issuance request or a rate-limit slot).
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from zkage_core import devicekey, rsabssa, translog
from zkage_core.encoding import as_int, as_str, b64u, unb64u
from zkage_core.token import (
    MAX_TOKEN_LIFETIME,
    SCOPES,
    Challenge,
    encode_token,
    token_msg_for_challenge,
)
from zkage_ua.state import UAState, load_state, save_state


class UAError(Exception):
    """A flow failed; the message is safe to show the user."""


def _response_json(resp: httpx.Response, context: str) -> dict[str, object]:
    """Parse a POST response body as a JSON object, cleanly on failure."""
    try:
        data = resp.json()
    except ValueError as exc:
        raise UAError(f"{context}: malformed response ({resp.status_code})") from exc
    if not isinstance(data, dict):
        raise UAError(f"{context}: unexpected response payload")
    return data


def _get_json(http: httpx.Client, url: str) -> dict[str, object]:
    try:
        resp = http.get(url)
    except httpx.HTTPError as exc:
        raise UAError(f"cannot reach {url}: {exc}") from exc
    if resp.status_code != 200:
        raise UAError(f"{url} returned {resp.status_code}")
    data = resp.json()
    if not isinstance(data, dict):
        raise UAError(f"{url} returned unexpected payload")
    return data


def sync_log(http: httpx.Client, state: UAState) -> tuple[list[translog.LogRecord], UAState]:
    """Fetch and verify the transparency log; enforce append-only extension.

    Returns the verified records and the state with an updated pin.

    Raises:
        UAError: On head-signature failure, log-key change, tamper, rollback,
            or fork relative to the pinned head. A changed log-signing key
            aborts permanently by design (TOFU); the documented recovery is to
            delete the state file and re-enroll, which re-pins from scratch.
    """
    head_payload = _get_json(http, f"{state.issuer_url}/log/head")
    try:
        log_public_raw = unb64u(as_str(head_payload["log_public_key"]))
        head_dict = head_payload["head"]
        if not isinstance(head_dict, dict):
            raise ValueError("head must be an object")
        head = translog.SignedHead.from_json_dict(head_dict)
    except (KeyError, ValueError, translog.LogError) as exc:
        raise UAError(f"malformed log head response: {exc}") from exc

    if log_public_raw != state.log_public_raw:
        raise UAError("issuer changed its log signing key; refusing to continue")
    try:
        translog.verify_head(devicekey.load_device_public(log_public_raw), head)
    except (translog.LogError, devicekey.IssuanceBindingError) as exc:
        raise UAError(f"log head signature invalid: {exc}") from exc

    try:
        resp = http.get(f"{state.issuer_url}/log")
    except httpx.HTTPError as exc:
        raise UAError(f"cannot fetch transparency log: {exc}") from exc
    try:
        records = translog.from_jsonl(resp.text)
        chain_head = translog.check_extension(state.pinned_size, state.pinned_head, records)
    except translog.LogError as exc:
        raise UAError(f"transparency log check failed: {exc}") from exc
    if head.size != len(records) or head.head_hash != chain_head:
        raise UAError("signed head does not match the served log")

    return records, state.with_pin(len(records), chain_head)


def enroll(
    http: httpx.Client,
    issuer_url: str,
    claimed_age: int,
    state_path: Path,
    *,
    attester: str = "stub",
    claim: dict[str, object] | None = None,
) -> UAState:
    """Enroll with the issuer, then sync and pin the transparency log.

    Args:
        http: HTTP client.
        issuer_url: Issuer base URL.
        claimed_age: Self-declared age (used by the stub attester only).
        state_path: Where to persist UA state.
        attester: Attester name registered at the issuer.
        claim: Full claim payload override (e.g., an authority-signed
            attestation for ``attester="signed"``); defaults to
            ``{"claimed_age": claimed_age}``.

    Raises:
        UAError: On enrollment rejection or log verification failure.
    """
    device = devicekey.generate_device_key()
    try:
        resp = http.post(
            f"{issuer_url}/enroll",
            json={
                "device_pub": b64u(devicekey.device_public_raw(device)),
                "attester": attester,
                "claim": claim if claim is not None else {"claimed_age": claimed_age},
            },
        )
    except httpx.HTTPError as exc:
        raise UAError(f"cannot reach issuer: {exc}") from exc
    if resp.status_code != 200:
        detail = _response_json(resp, "enrollment").get("error", resp.status_code)
        raise UAError(f"enrollment rejected: {detail}")
    body = _response_json(resp, "enroll")

    head_payload = _get_json(http, f"{issuer_url}/log/head")
    try:
        log_public_raw = unb64u(as_str(head_payload["log_public_key"]))
    except (KeyError, ValueError) as exc:
        raise UAError("issuer did not provide a log public key") from exc

    state = UAState(
        issuer_url=issuer_url,
        account_id=unb64u(as_str(body["account_id"])),
        device_sk_raw=devicekey.device_private_raw(device),
        max_scope=as_int(body["max_scope"]),
        log_public_raw=log_public_raw,
        pinned_size=0,
        pinned_head=translog.GENESIS_PREV,
    )
    _, state = sync_log(http, state)
    save_state(state_path, state)
    return state


def verify_with_rp(
    http: httpx.Client,
    state_path: Path,
    rp_url: str,
    scope: int,
    *,
    now: int | None = None,
) -> dict[str, object]:
    """Run the full verification flow against a relying party.

    Fetch challenge → verify log (split-view check) → blind → authenticated
    issuance → finalize against the logged key → redeem at the RP.

    Returns:
        ``{"verified": bool, "scope": int | None}`` from the RP's response.

    Raises:
        UAError: On any verification, log, or key-substitution failure. No
            token leaves this function unless the logged key verified it.
    """
    state = load_state(state_path)
    now = int(time.time()) if now is None else now

    challenge_data = _get_json(http, f"{rp_url}/challenge?scope={scope}")
    try:
        challenge = Challenge.from_json_dict(challenge_data)
    except Exception as exc:
        raise UAError(f"malformed challenge from RP: {exc}") from exc
    if challenge.scope != scope:
        raise UAError("RP challenge scope does not match the requested scope")

    # The token would bind whatever rp_id the challenge claims — make sure it
    # is the RP the user is actually talking to (challenge-relay hardening).
    challenged_host = urlparse(f"//{challenge.rp_id}").hostname or challenge.rp_id
    if challenged_host != (urlparse(rp_url).hostname or ""):
        raise UAError(
            f"challenge is for rp_id '{challenge.rp_id}', "
            f"but this is '{urlparse(rp_url).hostname}'; aborting"
        )

    # Abort BEFORE any issuance on a challenge that could never verify.
    if challenge.expires_at <= now:
        raise UAError("RP challenge has already expired; aborting")
    if challenge.expires_at - now > MAX_TOKEN_LIFETIME:
        raise UAError("RP challenge lifetime exceeds the protocol maximum; aborting")

    records, state = sync_log(http, state)
    save_state(state_path, state)

    if challenge.log_head is not None:
        # The RP's view may legitimately lag a few appends behind ours (a
        # rotation writes two records); any hash outside the honest chain's
        # recent history is still a loud split-view abort.
        accepted = {r.record_hash for r in records[-translog.GOSSIP_LAG_TOLERANCE :]}
        accepted.add(translog.GENESIS_PREV)
        if challenge.log_head not in accepted:
            raise UAError(
                "RP's view of the transparency log diverges from ours; "
                "possible split-view attack — aborting"
            )

    record = translog.active_record_for(records, scope, now)
    if record is None:
        raise UAError(f"no active federation key for scope {scope}")
    public_key = record.to_scope_key_record().public_key()  # policy + key_id check

    msg = token_msg_for_challenge(challenge, record.key_id)
    prepared = rsabssa.prepare(msg)
    blinded, inv = rsabssa.blind(public_key, prepared)

    device = devicekey.load_device_private(state.device_sk_raw)
    request_id = secrets.token_bytes(16)
    issuance_sig = devicekey.sign_issuance(
        device, state.account_id, scope, blinded, now, request_id
    )
    try:
        resp = http.post(
            f"{state.issuer_url}/issue",
            json={
                "account_id": b64u(state.account_id),
                "scope": scope,
                "blinded_msg": b64u(blinded),
                "ts": now,
                "request_id": b64u(request_id),
                "signature": b64u(issuance_sig),
            },
        )
    except httpx.HTTPError as exc:
        raise UAError(f"cannot reach issuer: {exc}") from exc
    if resp.status_code != 200:
        detail = _response_json(resp, "issuance").get("error", resp.status_code)
        raise UAError(f"issuance refused: {detail}")
    body = _response_json(resp, "issuance")
    if unb64u(as_str(body["key_id"])) != record.key_id:
        raise UAError("issuer signed with a key that is not in the transparency log; aborting")

    try:
        sig = rsabssa.finalize(public_key, prepared, unb64u(as_str(body["blind_sig"])), inv)
    except rsabssa.RsabssaError as exc:
        raise UAError(
            "issuer signature does not verify under the transparency-logged key; "
            "aborting (possible key substitution)"
        ) from exc
    wire = encode_token(prepared, sig)

    try:
        redeem = http.post(f"{rp_url}/redeem", json={"token": b64u(wire)})
    except httpx.HTTPError as exc:
        raise UAError(f"cannot reach RP: {exc}") from exc
    redeem_body = _response_json(redeem, "token redemption")
    return {
        "verified": bool(redeem_body.get("verified", False)),
        "scope": redeem_body.get("scope"),
    }


def log_status(http: httpx.Client, state_path: Path) -> dict[str, object]:
    """Sync the log and report the verified head (updates the pin)."""
    state = load_state(state_path)
    records, state = sync_log(http, state)
    save_state(state_path, state)
    head = records[-1].record_hash if records else translog.GENESIS_PREV
    now = int(time.time())
    # Effective status (latest record per key), not raw record statuses.
    active_scopes = [s for s in SCOPES if translog.active_record_for(records, s, now)]
    return {
        "size": len(records),
        "head": head.hex(),
        "active_scopes": sorted(active_scopes),
    }
