"""
Cryptographic Primitives for Nebula Proof Verification

Implements:
- SHA-256 hashing (FIPS 180-4)
- JSON Canonicalization (RFC 8785 / JCS)
- Ed25519 signature verification (RFC 8032)
- Merkle tree operations

No dependencies on Nebula backend - fully standalone.
"""

import hashlib
import json
import base64
from typing import Dict, Any, List, Optional
from collections import OrderedDict

# Optional: Ed25519 support via cryptography library
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    ED25519_AVAILABLE = True
except ImportError:
    ED25519_AVAILABLE = False


def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash (FIPS 180-4).

    Args:
        data: Bytes to hash

    Returns:
        32-byte SHA-256 digest
    """
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash as hex string.

    Args:
        data: Bytes to hash

    Returns:
        64-character hex string
    """
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Dict[str, Any]) -> bytes:
    """
    Serialize to canonical JSON (RFC 8785 / JCS).

    Ensures deterministic serialization for signing:
    - Keys sorted alphabetically (recursive)
    - No extra whitespace
    - Unicode normalized
    - Consistent number formatting

    Args:
        obj: Dictionary to canonicalize

    Returns:
        Canonical JSON bytes (UTF-8 encoded)
    """
    def sort_dict(d):
        if isinstance(d, dict):
            return OrderedDict(sorted((k, sort_dict(v)) for k, v in d.items()))
        elif isinstance(d, list):
            return [sort_dict(item) for item in d]
        else:
            return d

    canonical = sort_dict(obj)

    json_str = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(',', ':'),
        sort_keys=True
    )

    return json_str.encode('utf-8')


def verify_ed25519(
    public_key: bytes,
    message: bytes,
    signature: str | bytes
) -> bool:
    """
    Verify Ed25519 signature (RFC 8032).

    Args:
        public_key: 32-byte Ed25519 public key (raw bytes)
        message: Original message that was signed
        signature: 64-byte signature (base64 string or raw bytes)

    Returns:
        True if signature is valid, False otherwise
    """
    if not ED25519_AVAILABLE:
        raise RuntimeError(
            "Ed25519 verification requires 'cryptography' library. "
            "Install with: pip install cryptography"
        )

    # Handle base64-encoded signature
    if isinstance(signature, str):
        signature = base64.b64decode(signature)

    # Handle base64-encoded public key if passed as string
    if isinstance(public_key, str):
        public_key = base64.b64decode(public_key)

    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, message)
        return True
    except Exception:
        return False


def merkle_root(hashes: List[bytes]) -> bytes:
    """
    Compute Merkle tree root from leaf hashes.

    Canonical merkle tree construction:
    - Padding mode: Duplicate last leaf to next power of 2
    - Hash mode: SHA-256(left || right)
    - Concatenation order: left then right
    - Leaf order: MUST be pre-sorted by caller

    Args:
        hashes: List of leaf hashes (each 32 bytes)

    Returns:
        32-byte Merkle root hash

    Raises:
        ValueError: If hashes list is empty
    """
    if not hashes:
        raise ValueError("Cannot compute merkle root of empty list")

    if len(hashes) == 1:
        return hashes[0]

    # Pad to power of 2 by duplicating last
    while len(hashes) & (len(hashes) - 1) != 0:
        hashes = hashes + [hashes[-1]]

    # Build tree bottom-up
    while len(hashes) > 1:
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            next_level.append(sha256(combined))
        hashes = next_level

    return hashes[0]


def verify_merkle_inclusion(
    leaf_hash: bytes,
    inclusion_proof: List[bytes],
    root_hash: bytes,
    leaf_index: int
) -> bool:
    """
    Verify Merkle inclusion proof.

    Args:
        leaf_hash: Hash of the leaf to verify
        inclusion_proof: List of sibling hashes from leaf to root
        root_hash: Expected Merkle root
        leaf_index: Index of the leaf in the tree

    Returns:
        True if leaf is included in tree with given root
    """
    current = leaf_hash
    index = leaf_index

    for sibling in inclusion_proof:
        if index % 2 == 0:
            # Current is left child
            current = sha256(current + sibling)
        else:
            # Current is right child
            current = sha256(sibling + current)
        index //= 2

    return current == root_hash
