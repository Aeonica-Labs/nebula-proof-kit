"""
Nebula Proof Kit - Python SDK

Standalone verification toolkit for Nebula cryptographic proofs.
Anyone can verify. Only Nebula can produce.

For the people. With love and freedom.
"""

from .verify import (
    verify_proof,
    verify_canonical_hash,
    verify_signature,
    verify_merkle_inclusion,
    VerificationResult,
)
from .schemas import validate_schema, ProofType
from .crypto import (
    sha256,
    sha256_hex,
    canonical_json,
    verify_ed25519,
    merkle_root,
)

__version__ = "1.0.0"
__all__ = [
    "verify_proof",
    "verify_canonical_hash",
    "verify_signature",
    "verify_merkle_inclusion",
    "VerificationResult",
    "validate_schema",
    "ProofType",
    "sha256",
    "sha256_hex",
    "canonical_json",
    "verify_ed25519",
    "merkle_root",
]
