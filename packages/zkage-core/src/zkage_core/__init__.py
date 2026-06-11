"""Core cryptography for zk-age-attest.

Submodules:
    rsabssa: RFC 9474 RSA blind signatures (RSABSSA), all four named variants.
    token: v1 token and challenge wire formats.
    keys: federation scope keys and keysets.
    devicekey: Ed25519 device keys and issuance-request binding.
    translog: hash-chained, signed key transparency log.

Dependency policy (normative): this package depends on ``cryptography`` only.
"""

__version__ = "0.1.0"
