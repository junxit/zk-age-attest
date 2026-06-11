"""Pure offline verifier SDK for zk-age-attest tokens.

This package performs no network, file, environment, or clock access — time and
trusted keys are explicit parameters. CI enforces this with an AST purity test, and
the dependency graph (zkage-core → cryptography, nothing else) makes the
"no phone home" property checkable rather than promised.
"""

from zkage_verifier.verify import Decision, VerifyResult, verify_token

__all__ = ["Decision", "VerifyResult", "verify_token"]
__version__ = "0.1.0"
