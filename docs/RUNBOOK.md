# Operations Runbook

Procedures for running a zk-age-attest demo federation. Companion to
[DESIGN.md](DESIGN.md) (protocol) and [THREAT-MODEL.md](THREAT-MODEL.md) (risk register).

## Daily operations

### Initialize a federation

```bash
uv run python scripts/init_federation.py --state demo-state [--bits 3072]
```

Creates one RSA scope key per scope (epoch 1), the Ed25519 log key,
the genesis transparency log, signed head, and RP keyset. Re-running refuses
to clobber existing state.

### Rotate a scope key

```bash
uv run python scripts/rotate_key.py --state demo-state --scope 18 [--bits 3072]
```

Appends `retired` (old key) + `active` (new epoch) to the log, republishes the
signed head and keyset **atomically** (temp file + rename). Nothing restarts:

- the issuer hot-reloads on its next request (mtime probe),
- the demo RP re-reads keyset.json on every redemption,
- pinned UAs accept the append because their pinned view extends append-only;
  an RP gossiping a lagging head is tolerated within `GOSSIP_LAG_TOLERANCE`.

Planned rotations are also how you change modulus size (`--bits 3072`).

### Revoke a compromised scope key

```bash
uv run python scripts/revoke_key.py --state demo-state --scope 18
```

Appends a `revoked` record. Effects cascade live: issuance for the scope is refused,
refreshed RPs reject outstanding tokens (their key_id left the keyset), UAs fail
closed before any issuance. **Recovery = rotate** (`rotate_key.py`); revocation has
no undo record — the chain narrates history honestly.

## Incident response

### Scope-key compromise suspected

1. `revoke_key.py --scope S` immediately — bounds exposure to one redemption window.
2. Investigate. If the key was not actually misused, recover with `rotate_key.py --scope S`.
3. If tokens were farmed under the key, note R2: tokens are single-use, RP-bound, and
   ≤10 minutes old; the blast radius is bounded by design.

### Log-signing key compromise

The UA pins the log key TOFU at enrollment; a swapped log key aborts every pinned
UA permanently (fail closed). Recovery is user-visible re-enrollment:

1. Rotate the log-signing key out-of-band and republish `log_pub.b64`.
2. Announce re-enrollment; users delete their state file and run `zkage-ua enroll`
   again (fresh TOFU pin). This is the documented residual (client.py `sync_log`);
   production would add witnessed log heads or multi-sig log keys.

### Issuer database compromise

The store holds only `{account_id, device_pub, max_scope, enrolled_at, expires_at}`
(DESIGN §7) plus request ids (10-minute retention). There is no identity data to leak;
re-enrollment restores service.

## Multi-node notes

- **RP nonce store**: the default `PendingChallengeStore` is in-process. For more than
  one worker, use the Redis profile (`ZKAGE_REDIS_URL`, see README) whose atomic
  `GETDEL` pop preserves pop-before-verify across nodes.
- **Rate limiter**: remains single-node even in the Redis profile — budgets are
  per-process. Production deployments should move budgets into the shared store;
  deliberately out of prototype scope.
- **Issuer hot-reload**: probes `log.jsonl`'s mtime per request. Behind multiple
  workers, all workers see the same directory, so rotation propagates to every worker
  on its next request.

## Production guidance (deferred by design)

- **RP trust anchors**: derive the keyset from the *verified* transparency log
  (chain + signed head), not a local file projection. The demo trusts a local
  file written by the same operator that writes the issuer keys — acceptable when
  both live in one trust domain, wrong when they don't.
- Device keys belong in secure hardware; scope keys behind an HSM or threshold
  issuance (see `zkage-threshold`, DESIGN §9).
- Add witnessed Merkle heads (v2 roadmap) to remove reliance on RP head gossip.
