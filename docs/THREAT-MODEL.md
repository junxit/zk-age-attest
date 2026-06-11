# zk-age-attest — Threat Model

What we claim, against whom, what remains, and how to check us.

## 1. Assets and claimed properties

| # | Property | Mechanism | Strength |
|---|---|---|---|
| P1 | RP learns only the age predicate | Token carries scope + challenge binding only | By construction (154-byte struct; nothing else exists to disclose) |
| P2 | Issuer never sees token content, nonce, or RP | RFC 9474 blind issuance (Randomized variant) | Information-theoretic for content |
| P3 | Issuer+RP cannot link by **content** | Blindness + fresh `prefix`/`r` per token | Information-theoretic; measured by the CI linkability simulation |
| P4 | Issuer-hiding from RP | One federation key per scope | By construction (single logical issuer) |
| P5 | Tokens are single-use, per-RP, short-lived | Nonce pop-before-verify; `challenge_digest` binds rp_id; TTL ≤ 600 s | Enforced at verification |
| P6 | Targeted-key attacks are detectable | Key transparency log: UA pins head, requires append-only extension, verifies against logged key; RP head gossip | Fail-closed at the UA |
| P7 | "No phone home" at verification | Pure verifier (no I/O), static keyset | Checkable: dependency graph + AST purity test in CI |

## 2. Adversary models and outcomes

| Adversary | Goal | Outcome |
|---|---|---|
| Curious RP | Identify or re-identify users | Gets P1/P5 only; cross-site linking by token content impossible (each token is challenge-specific and used once) |
| Curious issuer | Learn where/when tokens are used | Sees only: account X requested a scope-S token at time T (and the UA's IP — see R6). Never the nonce, token, or RP |
| Malicious issuer | Tag a user via a unique key or forked log | UA pinning + extension check + logged-key finalize → abort, detectable (P6) |
| Issuer+RP collusion | Join logs to deanonymize | Content join: impossible (P3). **Timing join: possible — R1, the documented residual** |
| Network observer | Track verification events | Sees UA↔issuer and UA↔RP TLS flows; correlation ≈ R1/R6 |
| Malicious user (adult) | Farm/proxy tokens to minors | Bounded by device-sig binding (one request = one blinded msg) + rate limits + 5-min TTL — R2; not eliminable (§5) |
| Malicious client (minor) | Forge or replay | Forgery = breaking RSA / one-more-forgery (RFC 9474); replay killed by pop-before-verify |
| Compromised UA | Everything the user does | **Out of model** — the UA is the user's trusted agent |

## 3. Per-flow analysis (summary)

- **Enrollment**: identity touches the attester only; issuer receives
  `max_scope` + device pubkey. Spoofing → attester strength (out of scope,
  pluggable); demo stub is intentionally weak.
- **Issuance**: authenticated (device sig), anti-replay (`ts` window +
  `request_id` set), anti-proxy (sig binds `SHA256(blinded_msg)`),
  rate-limited. The signed blob is opaque — see Risk 4 (oracle).
- **Verification**: offline, pure, uniform external errors (no token-state
  oracle); pop-before-verify removes the double-spend race.
- **Log distribution**: head signature + chain + pinned-extension + RP gossip;
  equivocation requires issuer+RP collusion (who already hold R1).

## 4. Risk register (top 5, honest)

| # | Risk | Severity | v1 disposition | v2 |
|---|---|---|---|---|
| R1 | **Issuance-timing correlation** under issuer+RP log join (sparse traffic → near-deterministic) | High for targeted users | Documented + measured: the linkability simulation emits `linkability-report.txt` (content overlap: zero; dwell distribution published). Mitigations: client jitter, OHTTP relay, volume | **Eliminated** by offline presentations |
| R2 | **Token proxying** by a willing adult | Medium, inherent | Device-sig binding makes it per-request; rate limits bound throughput (burst 5, ~2/min, 50/day); 5-min TTL kills stockpiles | Per-verifier pseudonyms enable rate-limiting without linkability |
| R3 | **Per-user key targeting / log equivocation** by the issuer | High if undetected | One key per scope per epoch; UA pin + append-only check + logged-key finalize → fail closed; RP head gossip → split view needs collusion | Witnessed Merkle log |
| R4 | **Blind-signing oracle** (issuer signs attacker-chosen bytes under scope keys) | Medium | Scope keys protocol-exclusive (normative); verifier accepts only the exact 154-byte format under those keys; rate limits bound oracle throughput; e=65537 fixed | Unchanged |
| R5 | **RP implementation footguns** (weak nonces, TOCTOU replay) | Medium | SDK owns the loop: `make_challenge` (CSPRNG) + normative pop-before-verify + uniform errors; adversarial tests cover replay/cross-RP/malformed | Unchanged |

Secondary: **R6** UA network metadata (IP) visible to issuer at issuance →
OHTTP relay (v1.5). **R7** non-constant-time Python big-int math → prototype
caveat; signer-side blinding implemented; production would use a hardened
implementation. **R8** demo keystores unencrypted on disk → production:
hardware-backed device keys, HSM/threshold scope keys.

## 5. Inherent limits (no token scheme escapes these)

Following Brave's ZKP-limits analysis: a cryptographic age token proves a
*credential holder* satisfied the check — never who is physically at the
device. Shared devices, coerced adults, and account lending remain. Browser
fingerprinting can re-link users independently of any token protocol; that
fight belongs to the user agent layer. Attestation strength bounds everything:
a stub attester yields cryptographically perfect tokens about unverified
claims (the demo does exactly this, deliberately).

## 6. Out of scope (v1)

Attester assurance levels; account recovery and multi-device; legal/regulatory
mapping (Arcom double-anonymity, UK OSA HEAA, ISO/IEC 27566 certification —
the architecture is compatible, mapping deferred); side-channel hardening;
DoS resilience beyond rate limits.

## 7. Audit hooks — how to check us

1. **Crypto correctness**: `packages/zkage-core/tests/test_rsabssa_vectors.py`
   reproduces every RFC 9474 Appendix A intermediate, all four variants.
2. **No phone home**: `packages/zkage-verifier` declares `zkage-core` as its
   only dependency (and core only `cryptography`) — verified by
   `test_purity.py` (dependency graph + AST scan: no network/file/env/clock).
3. **What the issuer can store**: the schema in
   `packages/zkage-issuer/src/zkage_issuer/store.py` is the complete list;
   grep the issuer for any other persistence.
4. **Content unlinkability, measured**: `tests/test_linkability_sim.py` joins
   maximal issuer and RP logs (200 runs) and asserts zero shared ≥8-byte
   substrings; it prints and writes the timing residual rather than hiding it.
5. **Fail-closed UA**: `tests/test_adversarial.py` demonstrates abort on key
   substitution, log rollback, and split view — with the RP receiving nothing.
6. **Format freeze**: the golden-token fixture pins the wire format;
   uniform-error tests pin the no-oracle property.
