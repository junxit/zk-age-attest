"""zkage-ua command-line interface: enroll | verify | log-status."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

from zkage_core.token import SCOPES
from zkage_ua import client
from zkage_ua.state import DEFAULT_STATE_PATH, StateError


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--state",
        type=Path,
        default=DEFAULT_STATE_PATH,
        help=f"state file (default: {DEFAULT_STATE_PATH})",
    )

    parser = argparse.ArgumentParser(prog="zkage-ua", description="zk-age-attest user agent")
    sub = parser.add_subparsers(dest="command", required=True)

    enroll = sub.add_parser(
        "enroll", parents=[common], help="enroll with an issuer and pin its key log"
    )
    enroll.add_argument("--issuer", required=True, help="issuer base URL")
    enroll.add_argument(
        "--claim-age", type=int, required=True, help="claimed age (stub attester, demo only)"
    )

    verify = sub.add_parser(
        "verify", parents=[common], help="prove an age scope to a relying party"
    )
    verify.add_argument("--rp", required=True, help="relying party base URL")
    verify.add_argument("--scope", type=int, required=True, choices=SCOPES)

    sub.add_parser(
        "log-status", parents=[common], help="verify and show the pinned transparency log head"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _parser().parse_args(argv)
    try:
        with httpx.Client(timeout=10.0) as http:
            if args.command == "enroll":
                state = client.enroll(http, args.issuer, args.claim_age, args.state)
                print(f"enrolled: account active, max scope over-{state.max_scope}")
                print(f"log pinned: {state.pinned_size} records")
                return 0
            if args.command == "verify":
                result = client.verify_with_rp(http, args.state, args.rp, args.scope)
                if result["verified"]:
                    print(f"verified: over-{result['scope']}")
                    return 0
                print("not verified: relying party rejected the token", file=sys.stderr)
                return 1
            if args.command == "log-status":
                status = client.log_status(http, args.state)
                print(f"log ok: {status['size']} records, head {status['head'][:16]}…")
                print(f"active scopes: {status['active_scopes']}")
                return 0
    except (client.UAError, StateError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
