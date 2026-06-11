"""User-agent state: device key, account, issuer URL, and the pinned log head.

Demo keystore: a plaintext JSON file. Production would hold the device key in
secure hardware (Secure Enclave / StrongBox / WebAuthn) — documented residual.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path

from zkage_core.encoding import as_int, as_str, b64u, unb64u

DEFAULT_STATE_PATH = Path.home() / ".zkage-ua" / "state.json"


class StateError(Exception):
    """The UA state file is missing or malformed."""


@dataclass(frozen=True)
class UAState:
    """Everything the UA persists between runs."""

    issuer_url: str
    account_id: bytes
    device_sk_raw: bytes
    max_scope: int
    log_public_raw: bytes
    pinned_size: int
    pinned_head: bytes

    def with_pin(self, size: int, head: bytes) -> UAState:
        """Return a copy with an updated transparency-log pin."""
        return replace(self, pinned_size=size, pinned_head=head)


def save_state(path: Path, state: UAState) -> None:
    """Persist UA state as JSON (parents created; demo plaintext keystore)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "issuer_url": state.issuer_url,
        "account_id": b64u(state.account_id),
        "device_sk": b64u(state.device_sk_raw),
        "max_scope": state.max_scope,
        "log_public_key": b64u(state.log_public_raw),
        "pinned_size": state.pinned_size,
        "pinned_head": b64u(state.pinned_head),
    }
    path.write_text(json.dumps(payload, indent=1) + "\n")


def load_state(path: Path) -> UAState:
    """Load UA state.

    Raises:
        StateError: If the file is missing or malformed.
    """
    try:
        data = json.loads(path.read_text())
        if data.get("version") != 1:
            raise StateError("unsupported state version")
        return UAState(
            issuer_url=as_str(data["issuer_url"]),
            account_id=unb64u(as_str(data["account_id"])),
            device_sk_raw=unb64u(as_str(data["device_sk"])),
            max_scope=as_int(data["max_scope"]),
            log_public_raw=unb64u(as_str(data["log_public_key"])),
            pinned_size=as_int(data["pinned_size"]),
            pinned_head=unb64u(as_str(data["pinned_head"])),
        )
    except FileNotFoundError as exc:
        raise StateError(f"no UA state at {path}; run `zkage-ua enroll` first") from exc
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed UA state at {path}") from exc
