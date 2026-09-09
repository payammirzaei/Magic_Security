"""BOLA/IDOR verification v2 re-export (STEP 30)."""

from magic_security.idor import (
    verify_idor_read_access,
    verify_pairwise_idor_read_access,
)

__all__ = [
    "verify_idor_read_access",
    "verify_pairwise_idor_read_access",
]
