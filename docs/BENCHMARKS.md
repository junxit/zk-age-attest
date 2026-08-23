# Benchmarks

Mean wall-clock cost of the RFC 9474 primitive path in this workspace's reference implementation (CPython big-int math plus OpenSSL for verification). Regenerate with:

```bash
uv run python scripts/benchmark.py --write
```

Absolute numbers are hardware-dependent; treat them as order-of-magnitude envelopes for the prototype, not guarantees.

Iterations per cell: 60. Variant: RSABSSA-SHA384-PSS-Randomized (SHA-384, sLen=48).

| operation | 2048-bit (ms/op) | 3072-bit (ms/op) |
|---|---|---|
| prepare | 0.001 | 0.001 |
| blind | 0.473 | 1.011 |
| blind_sign | 26.219 | 81.807 |
| finalize | 0.066 | 0.114 |
| verify | 0.050 | 0.086 |

## Issuance throughput envelope (per account)

The issuer rate limiter bounds farming independently of crypto speed (burst 5, refill ~1 token/30 s, hard cap 50/day):

| horizon | max tokens/account |
|---|---|
| immediately (burst) | 5 |
| first hour | ~7 |
| first day | 50 |

Client-side cost dominates a verification (~tens of ms at 2048 bits below); server-side `blind_sign` is one private RSA op. The demo RP's offline redemption path performs exactly one PSS verify per token.
