"""Revoke the active federation scope key for one age scope (compromise response).

Usage:
    uv run python scripts/revoke_key.py --state demo-state --scope 18

Appends a ``revoked`` record to the transparency log (DESIGN.md §4) and
republishes the signed head and RP keyset. Effects: the issuer refuses
issuance for that scope, refreshed RPs drop it from their keyset, and pinned
UAs fail closed before any issuance. Recovery: rotate a fresh epoch with
scripts/rotate_key.py.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from zkage_core.token import SCOPES
from zkage_issuer.federation import FederationStateError, revoke_scope_key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("demo-state"))
    parser.add_argument("--scope", type=int, required=True, choices=SCOPES)
    args = parser.parse_args()

    try:
        revoke_scope_key(args.state, args.scope, now=int(time.time()))
    except FederationStateError as exc:
        print(f"error: {exc}")
        return 1

    print(f"revoked active key for scope {args.scope}; no issuance until you rotate")
    print("recovery: uv run python scripts/rotate_key.py --state ... --scope ...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
