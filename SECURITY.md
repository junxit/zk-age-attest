# Security Policy

## Scope

zk-age-attest is a **research prototype** (status: 0.1.0, single commit lineage).
It implements RFC 9474 blind signatures and a custom key-transparency log. It is
not audited, not constant-time (Python big-int math), and must not be used in
production — see [THREAT-MODEL.md](docs/THREAT-MODEL.md) for the documented
residuals (issuance-timing correlation, token proxying, unencrypted demo keystores).

## Reporting a vulnerability

Email **security@junxit.example** with:

- A description of the issue and its impact on the protocol claims (P1–P7 in THREAT-MODEL.md)
- Reproduction steps or an adversarial test that demonstrates it

You'll get an acknowledgment within 3 business days, an assessment within 30 days,
and coordinated disclosure on a **90-day timeline**. Please give us the chance to
publish a fix before technical details go public; we will credit reporters who wish to be named.

## What is in scope

- The protocol as specified in docs/DESIGN.md (wire formats, verification checklist, key lifecycle)
- `zkage-core` (RSABSSA, token codec, transparency log), `zkage-verifier`,
  issuer/RP/UA reference services
- The transparency log's append-only/fork/rollback guarantees

## What is out of scope

- Demo conveniences documented as weak by design (StubAttester, plaintext demo keystores,
  in-process stores) — these are called out in the code and threat model already
- Denial of service beyond the documented rate limits
- Compromised user devices (the UA is the user's trusted agent — out of model)

## Supported versions

Only `main` at version 0.1.0. There are no tagged releases yet.
