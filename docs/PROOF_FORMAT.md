# Nebula Proof Format Specification

**Version**: 1.0.0
**Status**: Stable
**Last Updated**: 2024-01

## Overview

A Nebula Proof Bundle is a self-contained JSON document that cryptographically attests to a data operation. Every proof can be independently verified without contacting the NebulaGuard backend.

## Proof Bundle Structure

```json
{
  "schema_version": "1.0.0",
  "proof_type": "deletion",
  "proof_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "timestamp": "2024-01-15T10:30:00Z",
  "algorithms": {
    "canonicalization": "RFC8785",
    "hash": "SHA-256",
    "signature": "Ed25519"
  },
  "data": { ... },
  "compliance": { ... },
  "merkle": { ... },
  "anchoring": { ... },
  "signature": { ... }
}
```

## Required Fields

### `schema_version` (string)
Semantic version of the proof schema. Current version: `"1.0.0"`.

### `proof_type` (string)
Type of operation being attested. Must be one of:
- `backup_integrity` - File was stored with integrity verification
- `deletion` - File was cryptographically erased
- `residency` - File is stored in specific geographic region
- `transmission` - File was transmitted between parties
- `reconstruction` - File was reconstructed from fragments

### `proof_id` (string)
Unique 32-character hexadecimal identifier for this proof.

Format: `/^[a-f0-9]{32}$/`

### `timestamp` (string)
ISO 8601 / RFC 3339 timestamp when the proof was generated.

Example: `"2024-01-15T10:30:00Z"`

### `signature` (object)
Cryptographic signature block. See [Signature Block](#signature-block).

## Optional Fields

### `algorithms` (object)
Cryptographic algorithms used:

```json
{
  "canonicalization": "RFC8785",
  "hash": "SHA-256",
  "signature": "Ed25519"
}
```

### `data` (object)
Operation-specific data. Structure varies by `proof_type`.

### `compliance` (object)
Regulatory compliance attestations. See [Compliance Block](#compliance-block).

### `merkle` (object)
Merkle tree data for batch proofs. See [Merkle Block](#merkle-block).

### `anchoring` (object)
Blockchain anchoring information. See [Anchoring Block](#anchoring-block).

---

## Signature Block

The signature block contains the cryptographic signature over the proof content.

```json
{
  "algorithm": "Ed25519",
  "public_key": "base64-encoded-32-byte-public-key",
  "key_id": "nebula-signing-key-2024-01",
  "canonical_hash": "64-char-hex-sha256-hash",
  "value": "base64-encoded-64-byte-signature"
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `algorithm` | string | No | Always `"Ed25519"` |
| `public_key` | string | Yes | Base64-encoded 32-byte Ed25519 public key |
| `key_id` | string | No | Identifier for the signing key |
| `canonical_hash` | string | Yes | SHA-256 hash of canonical JSON (64 hex chars) |
| `value` | string | Yes | Base64-encoded 64-byte Ed25519 signature |

### Signature Verification Process

1. **Extract** all fields except `signature` block
2. **Canonicalize** using RFC 8785 (JCS) - sort keys recursively, no whitespace
3. **Hash** the canonical bytes using SHA-256
4. **Verify** the Ed25519 signature over the canonical bytes
5. **Compare** computed hash with `canonical_hash` field

---

## Compliance Block

Used for regulatory attestations, particularly GDPR Article 17 (Right to Erasure).

```json
{
  "gdpr_article": "17",
  "recovery_impossible": true,
  "sanitization_standard": "NIST-SP-800-88-Rev1",
  "deletion_method": "cryptographic_erasure",
  "verified_by": "automated_audit"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `gdpr_article` | string | GDPR article number (e.g., "17") |
| `recovery_impossible` | boolean | True if data cannot be recovered |
| `sanitization_standard` | string | Standard followed (e.g., NIST SP 800-88) |
| `deletion_method` | string | How deletion was performed |
| `verified_by` | string | Verification mechanism |

### Sanitization Standards

- `NIST-SP-800-88-Rev1` - NIST Guidelines for Media Sanitization
- `DoD-5220.22-M` - DoD 5220.22-M data sanitization
- `ISO-27001` - ISO/IEC 27001 compliant process

---

## Merkle Block

For proofs covering multiple items (e.g., batch deletions), a Merkle tree structure is used.

```json
{
  "algorithm": "SHA-256",
  "root": "64-char-hex-merkle-root",
  "leaf_count": 128,
  "inclusion_proof": [
    "64-char-hex-sibling-1",
    "64-char-hex-sibling-2"
  ],
  "leaf_hash": "64-char-hex-leaf-hash",
  "leaf_index": 42
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | string | Hash algorithm (default: SHA-256) |
| `root` | string | Merkle tree root hash |
| `leaf_count` | integer | Number of leaves in tree |
| `inclusion_proof` | array | Sibling hashes for verification |
| `leaf_hash` | string | Hash of the specific item |
| `leaf_index` | integer | Position of item in tree |

### Tree Construction

1. Pad leaves to next power of 2 (duplicate last leaf)
2. Hash pairs: `SHA-256(left || right)`
3. Repeat until single root remains

---

## Anchoring Block

Optional blockchain anchoring for additional tamper-evidence.

```json
{
  "chain": "ethereum",
  "network": "mainnet",
  "tx_hash": "0x...",
  "block_height": 19000000,
  "block_hash": "0x...",
  "anchored_at": "2024-01-15T10:35:00Z"
}
```

### Supported Chains

| Chain | Network | Description |
|-------|---------|-------------|
| `ethereum` | mainnet, sepolia | Ethereum blockchain |
| `polygon` | mainnet, mumbai | Polygon PoS |
| `bitcoin` | mainnet, testnet | Bitcoin via OP_RETURN |

---

## Proof Type Specifics

### `backup_integrity`

Attests that a file was stored with integrity verification.

```json
{
  "data": {
    "file_id": "uuid",
    "file_hash": "sha256-of-original-file",
    "fragment_count": 5,
    "storage_nodes": ["node-1", "node-2", "node-3"],
    "redundancy_factor": 1.5
  }
}
```

### `deletion`

Attests that a file was cryptographically erased.

```json
{
  "data": {
    "file_id": "uuid",
    "deletion_method": "cryptographic_erasure",
    "fragments_deleted": 5,
    "nodes_confirmed": ["node-1", "node-2", "node-3"]
  },
  "compliance": {
    "gdpr_article": "17",
    "recovery_impossible": true
  }
}
```

### `residency`

Attests to geographic location of data storage.

```json
{
  "data": {
    "file_id": "uuid",
    "region": "eu-west-1",
    "country_code": "IE",
    "jurisdiction": "EU"
  },
  "compliance": {
    "gdpr_article": "44",
    "data_localization": true
  }
}
```

### `transmission`

Attests to secure transmission between parties.

```json
{
  "sender": {
    "organization": "Sender Corp",
    "verified": true
  },
  "receiver": {
    "organization": "Receiver Inc",
    "verified": true
  },
  "channel": {
    "tls_version": "1.3",
    "perfect_forward_secrecy": true
  }
}
```

### `reconstruction`

Attests that a file was successfully reconstructed from fragments.

```json
{
  "data": {
    "file_id": "uuid",
    "original_hash": "sha256-of-reconstructed-file",
    "fragments_used": 3,
    "reconstruction_time_ms": 150
  }
}
```

---

## Example: Complete Deletion Proof

```json
{
  "schema_version": "1.0.0",
  "proof_type": "deletion",
  "proof_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "timestamp": "2024-01-15T10:30:00Z",
  "algorithms": {
    "canonicalization": "RFC8785",
    "hash": "SHA-256",
    "signature": "Ed25519"
  },
  "data": {
    "file_id": "550e8400-e29b-41d4-a716-446655440000",
    "deletion_method": "cryptographic_erasure",
    "fragments_deleted": 5,
    "nodes_confirmed": [
      "node-eu-1.nebulaguard.net",
      "node-eu-2.nebulaguard.net",
      "node-us-1.nebulaguard.net"
    ]
  },
  "compliance": {
    "gdpr_article": "17",
    "recovery_impossible": true,
    "sanitization_standard": "NIST-SP-800-88-Rev1"
  },
  "signature": {
    "algorithm": "Ed25519",
    "public_key": "MCowBQYDK2VwAyEA...",
    "key_id": "nebula-signing-key-2024-01",
    "canonical_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "value": "MEUCIQD..."
  }
}
```

---

## Security Considerations

1. **Never trust unverified proofs** - Always run verification before accepting a proof
2. **Check key rotation** - Verify the `key_id` against known valid signing keys
3. **Timestamp validation** - Ensure timestamps are within acceptable bounds
4. **Anchoring verification** - If blockchain anchoring is present, verify on-chain

## References

- [RFC 8785 - JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://datatracker.ietf.org/doc/html/rfc8032)
- [FIPS 180-4 - Secure Hash Standard (SHA-256)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [NIST SP 800-88 Rev.1 - Guidelines for Media Sanitization](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final)
