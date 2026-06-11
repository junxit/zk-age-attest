"""Workspace smoke test: every package is importable and versioned."""

import zkage_core
import zkage_issuer
import zkage_rp
import zkage_ua
import zkage_verifier


def test_packages_importable() -> None:
    for pkg in (zkage_core, zkage_verifier, zkage_issuer, zkage_rp, zkage_ua):
        assert pkg.__version__ == "0.1.0"
