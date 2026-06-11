"""Initialize a demo federation state directory.

Usage:
    uv run python scripts/init_federation.py --state demo-state [--bits 2048]

Creates one RSA scope key per age scope (13/16/18/21), the Ed25519 log key,
the genesis transparency log, a signed head, and the RP keyset projection.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from zkage_issuer.federation import FederationStateError, init_state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("demo-state"))
    parser.add_argument("--bits", type=int, default=2048, choices=(2048, 3072, 4096))
    args = parser.parse_args()

    try:
        init_state(args.state, now=int(time.time()), bits=args.bits)
    except FederationStateError as exc:
        print(f"error: {exc}")
        return 1
    print(f"federation initialized in {args.state}/")
    print(f"  issuer secrets: {args.state}/issuer/   (keys + runtime db — keep private)")
    print(f"  public surface: {args.state}/public/   (log, signed head, keyset)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
