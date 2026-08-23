"""Mock attestation authority: sign an age claim for the ``signed`` attester.

Usage:
    uv run python scripts/sign_claim.py --state demo-state --age 21

Prints a JSON claim envelope; feed it to enrollment with:

    uv run zkage-ua enroll --attester signed --claim-file claim.json ...

DEMO ONLY: reads the demo authority key from the issuer state directory. A
production attester is an external service that verifies real identity
documents and signs claims under its own pinned key.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from zkage_core.encoding import b64u
from zkage_issuer.attester import fresh_claim_nonce, sign_attestation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("demo-state"))
    parser.add_argument("--age", type=int, required=True)
    args = parser.parse_args()

    key_path = args.state / "issuer" / "attester_key.pem"
    try:
        pem = key_path.read_bytes()
    except FileNotFoundError:
        print(f"error: no authority key at {key_path}; run init_federation.py", file=sys.stderr)
        return 1
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        print(f"error: {key_path} is not an Ed25519 key", file=sys.stderr)
        return 1

    nonce = bytes(base64.urlsafe_b64decode(fresh_claim_nonce() + "=="))
    signature = sign_attestation(key, args.age, nonce)
    envelope = {
        "claimed_age": args.age,
        "nonce": b64u(nonce),
        "attestation": b64u(signature),
        "signed_at": int(time.time()),
    }
    print(json.dumps(envelope, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
