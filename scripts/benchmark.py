"""Benchmark the RSABSSA primitive path and (optionally) write docs/BENCHMARKS.md.

Usage:
    uv run python scripts/benchmark.py [--iterations 100] [--write]

Timings are wall-clock means over injectable-randomness-free calls (fresh
randomness per call, as in production). Absolute numbers vary by machine;
the table format is deterministic so regeneration produces no formatting churn.
"""

from __future__ import annotations

import argparse
import statistics
import time
from pathlib import Path

from zkage_core import rsabssa
from zkage_core import token as token_mod
from zkage_core.keys import generate_scope_key

DOC_PATH = Path(__file__).resolve().parents[1] / "docs" / "BENCHMARKS.md"
RP_ID = "benchmark.example"
NOW = 1_800_000_000


def bench_ms(fn, iterations: int) -> float:
    """Mean milliseconds per call of ``fn`` over ``iterations`` runs (one warmup)."""
    fn()  # warmup
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.mean(samples)


def measure(bits: int, iterations: int) -> dict[str, float]:
    """Per-operation means for one modulus size."""
    key = generate_scope_key(bits)
    challenge = token_mod.make_challenge(RP_ID, 18, now=NOW)
    msg = token_mod.token_msg_for_challenge(challenge, b"\x01" * 32)

    prepared = rsabssa.prepare(msg)
    blinded, inv = rsabssa.blind(key.public_key(), prepared)
    blind_sig = rsabssa.blind_sign(key, blinded)
    sig = rsabssa.finalize(key.public_key(), prepared, blind_sig, inv)

    return {
        "prepare": bench_ms(lambda: rsabssa.prepare(msg), iterations),
        "blind": bench_ms(lambda: rsabssa.blind(key.public_key(), prepared), iterations),
        "blind_sign": bench_ms(lambda: rsabssa.blind_sign(key, blinded), iterations),
        "finalize": bench_ms(
            lambda: rsabssa.finalize(key.public_key(), prepared, blind_sig, inv), iterations
        ),
        "verify": bench_ms(lambda: rsabssa.verify(key.public_key(), prepared, sig), iterations),
    }


OPS = ("prepare", "blind", "blind_sign", "finalize", "verify")


def report(results: dict[int, dict[str, float]], iterations: int) -> str:
    """Deterministic-format markdown report."""
    lines = [
        "# Benchmarks",
        "",
        "Mean wall-clock cost of the RFC 9474 primitive path in this workspace's"
        " reference implementation (CPython big-int math plus OpenSSL for"
        " verification). Regenerate with:",
        "",
        "```bash",
        "uv run python scripts/benchmark.py --write",
        "```",
        "",
        "Absolute numbers are hardware-dependent; treat them as order-of-magnitude"
        " envelopes for the prototype, not guarantees.",
        "",
        f"Iterations per cell: {iterations}. Variant:"
        f" {rsabssa.DEFAULT_VARIANT.name} (SHA-384, sLen=48).",
        "",
        "| operation | 2048-bit (ms/op) | 3072-bit (ms/op) |",
        "|---|---|---|",
    ]
    for op in OPS:
        cells = " | ".join(f"{results[bits][op]:.3f}" for bits in (2048, 3072))
        lines.append(f"| {op} | {cells} |")
    lines += [
        "",
        "## Issuance throughput envelope (per account)",
        "",
        "The issuer rate limiter bounds farming independently of crypto speed"
        " (burst 5, refill ~1 token/30 s, hard cap 50/day):",
        "",
        "| horizon | max tokens/account |",
        "|---|---|",
        "| immediately (burst) | 5 |",
        "| first hour | ~7 |",
        "| first day | 50 |",
        "",
        "Client-side cost dominates a verification (~tens of ms at 2048 bits below);"
        " server-side `blind_sign` is one private RSA op. The demo RP's offline"
        " redemption path performs exactly one PSS verify per token.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--write", action="store_true", help="write docs/BENCHMARKS.md")
    args = parser.parse_args()

    results = {bits: measure(bits, args.iterations) for bits in (2048, 3072)}
    text = report(results, args.iterations)
    if args.write:
        DOC_PATH.write_text(text)
        print(f"wrote {DOC_PATH}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
