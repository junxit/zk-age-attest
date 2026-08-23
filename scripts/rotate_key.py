"""Rotate a federation scope key: new epoch becomes active, old key retires.

Usage:
    uv run python scripts/rotate_key.py --state demo-state --scope 18 [--bits 2048]

Appends ``retired`` (old key) then ``active`` (new epoch) records to the
transparency log and republishes the signed head and RP keyset. A running
issuer picks the change up on its next request (mtime hot-reload); demo RPs
re-read keyset.json per redemption. UAs accept the change because the pinned
log view extends append-only.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from zkage_core.token import SCOPES
from zkage_issuer.federation import FederationStateError, rotate_scope_key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("demo-state"))
    parser.add_argument("--scope", type=int, required=True, choices=SCOPES)
    parser.add_argument("--bits", type=int, default=2048, choices=(2048, 3072, 4096))
    args = parser.parse_args()

    try:
        record = rotate_scope_key(args.state, args.scope, now=int(time.time()), bits=args.bits)
    except FederationStateError as exc:
        print(f"error: {exc}")
        return 1

    print(f"rotated scope {record.scope}: epoch {record.epoch} active")
    print(f"  new key_id: {record.key_id.hex()}")
    print(f"  valid until: {record.not_after}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
