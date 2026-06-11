# zk-age-attest — Protocol Design (v1)

Normative specification of the v1 interactive protocol. The key words MUST,
MUST NOT, SHOULD, and MAY are to be interpreted as in RFC 2119. Byte layouts
in this document are normative; the golden-token test fixture freezes them in
CI, and any change requires a new `token_type`.

## 1. Goals and non-goals

**Goals**

- A relying party (RP) learns exactly one bit: *the bearer satisfies age scope
  S, attested by the federation* — no identity, no birth date, no operator, no
  account, no cross-site handle.
- The issuer learns *who* requests tokens (for abuse control) but never what
  the tokens say, where they are used, or whether they were used: issuance is
  blind (information-theoretic content blindness, RFC 9474 Randomized).
- Issuer-hiding: verification uses one federation key per scope, so the RP
  cannot distinguish operators or upstream attesters.
- The privacy properties are **checkable**: vector-validated crypto, a pure
  no-I/O verifier, a pinned key-transparency log, and a CI linkability
  simulation, rather than policy promises.

**Non-goals (v1)**

- Hiding *that* a user is enrolled from the issuer (it knows its accounts).
- Defeating issuance-timing correlation by a colluding issuer+RP
  (documented residual; eliminated by the v2 offline mode).
- Preventing a willing adult from proxying for a minor (bounded by rate
  limits; no token scheme prevents it — see THREAT-MODEL.md §5).
- Attestation strength: how the attester establishes age is pluggable and out
  of protocol scope.

## 2. Actors

| Actor | Role | Trust required of it |
|---|---|---|
| User Agent (UA) | Blinds challenges, holds the device key, pins the log, fails closed | Trusted by the user (it sees everything the user does) |
| Issuer (federation) | Authenticates accounts, rate-limits, blind-signs | NOT trusted for privacy: blindness + log pinning constrain it |
| Relying party (RP) | Challenges, verifies offline, gates content | NOT trusted: learns only the predicate |
| Attester | Establishes `max_scope` at enrollment only | Trusted for attestation strength only; never sees usage |
| Transparency log | Records scope keys; hash-chained, head-signed | Detectable if it forks, rolls back, or targets users |

```mermaid
sequenceDiagram
    participant RP
    participant UA as User Agent
    participant I as Issuer (federation)
    Note over UA,I: Enrollment (once): attester → max_scope; issuer stores {account_id, device_pub, max_scope, expiry}
    RP->>UA: challenge {rp_id, scope, nonce, expires_at, log_head}
    UA->>UA: sync+pin transparency log; split-view check vs RP's log_head
    UA->>UA: msg = token fields; Prepare(randomize); Blind under scope key
    UA->>I: blinded_msg + device signature over SHA256(blinded_msg)‖ts‖request_id
    I->>I: device-sig auth → ts window → request-id fresh → scope ≤ max → rate limit
    I-->>UA: blind signature (scope key)
    UA->>UA: Finalize; verify against LOGGED key — abort on mismatch
    UA->>RP: token = prepared_msg ‖ signature
    RP->>RP: parse (structural) → POP pending nonce → verify_token (pure, offline)
    RP-->>UA: {verified: true, scope}
```

## 3. Cryptographic foundation

- **Scheme**: RSABSSA-SHA384-PSS-Randomized (RFC 9474). The Randomized
  variant is REQUIRED: message blindness then holds unconditionally
  (RFC 9474 §7, Lysyanskaya), not merely under message-entropy assumptions.
- **Parameters**: SHA-384, MGF1-SHA384, sLen=48, `e = 65537` exactly, modulus
  ∈ {2048 (demo), 3072 (recommended), 4096} bits.
- **Implementation layering** (assurance argument):
  - The *blinding path* (`prepare`, `blind`, `blind_sign`, `finalize`) is
    implemented over big-int arithmetic in `zkage_core.rsabssa` because no
    maintained Python RFC 9474 library exists. It reproduces every
    intermediate of RFC 9474 Appendix A (all four variants) in CI.
  - The *verification path* is one standard RSASSA-PSS verify through
    OpenSSL via `cryptography`. RPs run zero hand-rolled crypto.
- **Signer-side blinding** (RFC 9474 §7.1) is applied inside `blind_sign`.
  Python big-int math is still not constant-time — prototype caveat.
- **Device keys / log heads**: Ed25519.

## 4. Federation scope keys

- One keypair per scope (13, 16, 18, 21) per epoch. Scope is encoded by
  **key separation** and *also* by an explicit byte in the token; the
  verifier MUST cross-check token scope == key scope == challenged scope.
- `key_id = SHA-256(DER SPKI)`.
- Epochs: 90-day validity, 7-day overlap intended; with ≤10-minute tokens
  rotation is operationally trivial. Compromise response: append a `revoked`
  record; exposure is bounded by RP keyset-refresh interval + token TTL.
- Key policy is enforced wherever a key enters (UA and verifier): RSA only,
  `e = 65537`, allowed modulus sizes, `key_id` must match the SPKI hash.
- Scope keys MUST be used for nothing but this protocol (blind-signing is an
  oracle; see THREAT-MODEL.md Risk 4).

## 5. Transparency log

Hash-chained signed JSONL; records describe scope keys only (registration and
status changes), never per-issuance data.

- Record canonical bytes (hash preimage; fixed binary layout, never JSON):
  `seq(8) ‖ ts(8) ‖ scope(1) ‖ epoch(4) ‖ key_id(32) ‖ len4(spki) ‖ spki ‖
  not_before(8) ‖ not_after(8) ‖ status(1)`.
- `record_hash = SHA-256(prev_hash ‖ canonical)`; genesis `prev_hash` = 32
  zero bytes.
- **Signed head**: Ed25519 over `"zkage/v1/loghead\0" ‖ size(8) ‖
  head_hash(32) ‖ ts(8)` under a dedicated log key (pinned by the UA at
  enrollment, TOFU).
- **UA obligations** (fail closed): verify head signature; verify chain;
  require the new log to be an append-only **extension** of the pinned head
  (detects rollback and forks); require the issuance key to be logged-active;
  verify the finalized signature against the *logged* key.
- **Split-view detection**: the RP gossips its current `log_head` inside each
  challenge; the UA accepts it only if it equals its own verified head or the
  immediate predecessor. Sustaining a per-user forked log therefore requires
  issuer+RP collusion — an adversary with that power already has timing
  correlation, so equivocation buys little (THREAT-MODEL.md §4).
- v2: Merkle tree with inclusion/consistency proofs and independent witnesses.

## 6. Wire formats (normative)

### 6.1 Challenge (RP → UA, JSON over the RP's TLS)

```json
{"version": 1, "rp_id": "demo-rp.example", "scope": 18,
 "nonce": "<b64url 32B CSPRNG>", "expires_at": 1781234567,
 "log_head": "<b64url 32B, optional>"}
```

- TTL: default 300 s; the verifier rejects `expiry - now > 600` s.
- RPs MUST create challenges via `zkage_core.token.make_challenge` (CSPRNG
  nonce) and MUST treat the nonce as single-use (§6.4).

`challenge_digest = SHA-256("zkage/v1/challenge\0" ‖ len16(rp_id) ‖ rp_id ‖
scope(1) ‖ nonce(32) ‖ expires_at(8))` — binds rp_id so tokens are
RP-specific even if nonces ever collided.

### 6.2 Token (UA → RP)

`wire = prepared_msg(154) ‖ signature(k)` where `k` = modulus bytes.

```
prepared_msg (154 B):
  prefix            32  RFC 9474 PrepareRandomize randomizer
  tag               15  "zkage/v1/token\0"
  token_type         2  0x0001
  scope_id           1  13|16|18|21
  key_id            32  SHA-256(SPKI of the federation scope key)
  challenge_digest  32  §6.1
  nonce             32  RP nonce, verbatim (replay-cache index)
  expiry             8  uint64 BE unix seconds (copied from challenge)
```

The signature covers the exact transmitted `prepared_msg`; the verifier
parses received bytes and never re-serializes. Exactly one valid encoding
exists per token; parsers MUST reject any deviation (length, tag, type,
scope alphabet).

### 6.3 Issuance request (UA → issuer)

JSON fields: `account_id(16B)`, `scope`, `blinded_msg(k)`, `ts`,
`request_id(16B)`, `signature` — all binary as b64url. The device signature
MUST cover:

```
"zkage/v1/issuance\0" ‖ account_id(16) ‖ scope(1) ‖ SHA256(blinded_msg)(32)
                      ‖ ts(8) ‖ request_id(16)
```

Binding `SHA256(blinded_msg)` is the anti-proxying control: an issuance
request authorizes exactly one blinded message. The issuer MUST enforce, in
order: account exists and unexpired → device signature valid → `|ts − now| ≤
60 s` → `request_id` unseen (10-minute window) → `scope ≤ max_scope` → rate
limit (token bucket: burst 5, ~2/min, 50/day, account-global) → BlindSign.

### 6.4 Verification (RP)

1. Structural parse (no crypto). Reject malformed.
2. **Pop-before-verify**: atomically remove the pending challenge keyed by
   the token's nonce *before any cryptography*. Missing entry (never issued,
   redeemed, or expired) → reject. This makes double-spend a non-race and
   burns the challenge on malformed redemptions — only the TLS peer that
   received the nonce can do that. Multi-node RPs need an atomic shared pop
   (e.g., Redis `GETDEL`).
3. `verify_token(wire, trusted_keys, pending_challenge, now)` — pure
   function; decision order: scope match → key known → key scope cross-check
   → key active/valid → challenge binding (nonce, expiry, digest) → freshness
   (`expiry > now`, `expiry − now ≤ 600`) → key policy → RSASSA-PSS verify.
4. Externally, ALL failures MUST be one uniform error (`invalid_or_unknown`);
   precise `Decision` codes go to the RP's internal logs only.

## 7. Issuer data model (exhaustive)

The issuer's database MUST contain nothing beyond:

| Table | Fields |
|---|---|
| accounts | `account_id(16B opaque)`, `device_pub(32B)`, `max_scope`, `enrolled_at`, `expires_at` |
| seen_requests | `request_id(16B)`, `ts` (10-minute retention) |

No date of birth, no attester artifacts, no blinded messages, no issuance
contents. This table is the first thing an auditor checks
(THREAT-MODEL.md §7). Accounts expire (demo: 365 days) and re-enroll.

## 8. Versioning

`token_type` is a registry: `0x0001` = v1 interactive RSABSSA. Any byte-layout
change allocates a new type; verifiers reject unknown types. The golden-token
CI fixture enforces this discipline.

## 9. Roadmap

- **v1.5 — threshold issuance, wire-compatible.** `BlindSign` is a raw RSA
  private-key operation on an opaque value, so Shoup-style threshold RSA
  applies verbatim: t-of-n operators sign without any client or wire change.
  Interim key generation via a documented trusted-dealer ceremony; the
  federation key becomes "no single operator can issue".
- **v1.5 — OHTTP relay** for issuance traffic (hides UA network identity from
  the issuer) plus optional client jitter (weakens timing correlation).
- **v2 — offline mode.** Enrollment issues a long-lived anonymous credential
  (blind BBS); the UA generates per-presentation proofs bound to the RP nonce
  *locally* — the issuer is not online at presentation time, eliminating
  issuance-timing correlation and issuance rate signals. Issuer-hiding BBS
  (eprint 2025/2080) once standardized; per-verifier pseudonyms for
  rate-limiting without linkability. Target: same RP challenge format, new
  `token_type`.
- **v2 — log witnesses**: Merkle log with independent witnesses
  (Sigstore-style) replacing head gossip.
- **Formal model**: Tamarin/ProVerif model of §6 proving unlinkability under
  issuer+RP collusion (content), and documenting the timing residual.

## 10. References

- RFC 9474 — RSA Blind Signatures; RFC 9576/9578 — Privacy Pass architecture
  and issuance (the token shape here follows its fixed-struct discipline).
- RFC 8017 — PKCS #1 v2.2 (EMSA-PSS).
- Issuer-hiding BBS: eprint.iacr.org/2025/2080. BBS: draft-irtf-cfrg-bbs-signatures.
- Shoup, "Practical Threshold Signatures", EUROCRYPT 2000.
- Brave, "Limitations of ZKPs for age verification" (inherent-limits framing).
