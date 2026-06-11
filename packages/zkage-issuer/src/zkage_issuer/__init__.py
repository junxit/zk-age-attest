"""zk-age-attest issuer service.

FastAPI application exposing enrollment (pluggable attester), blind token issuance,
and the federation key transparency log. The issuer blind-signs opaque messages: it
never sees nonces, tokens, or relying parties.
"""

__version__ = "0.1.0"
