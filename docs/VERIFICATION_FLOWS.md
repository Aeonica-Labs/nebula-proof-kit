# Verification Flows

This document describes the verification process for Nebula cryptographic proofs, including step-by-step flows for different verification scenarios.

## Overview

Nebula proofs are designed for **trustless verification**. Anyone with the proof bundle can verify its authenticity without contacting NebulaGuard servers.

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Proof JSON    │───▶│    Verifier     │───▶│  VALID / FAIL   │
│    (input)      │    │  (nebula-proof) │    │    (output)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              │ No network required
                              │ Pure cryptographic verification
                              ▼
```

---

## Standard Verification Flow

### Step 1: Schema Validation

Verify the proof has all required fields in correct format.

```
┌─────────────────────────────────────────────────────────────┐
│                    SCHEMA VALIDATION                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Required Fields:                                           │
│  ✓ proof_type   (backup_integrity|deletion|residency|...)  │
│  ✓ proof_id     (32-char hex: /^[a-f0-9]{32}$/)           │
│  ✓ timestamp    (RFC 3339: 2024-01-15T10:30:00Z)          │
│  ✓ signature    (object with public_key, canonical_hash)   │
│                                                             │
│  Type-Specific:                                             │
│  • deletion  → compliance.recovery_impossible required      │
│  • transmission → sender, receiver objects required         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ PASS
```

### Step 2: Canonical Hash Verification

Verify the declared hash matches the proof content.

```
┌─────────────────────────────────────────────────────────────┐
│                 CANONICAL HASH VERIFICATION                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Extract all fields EXCEPT signature block               │
│                                                             │
│     proof_content = {                                       │
│       proof_type, proof_id, timestamp, data, ...            │
│     }                                                       │
│                                                             │
│  2. Canonicalize using RFC 8785 (JCS)                       │
│     • Sort all keys alphabetically (recursive)              │
│     • No whitespace                                         │
│     • UTF-8 encoding                                        │
│                                                             │
│  3. Compute SHA-256 hash                                    │
│                                                             │
│     computed_hash = SHA256(canonical_bytes)                 │
│                                                             │
│  4. Compare with signature.canonical_hash                   │
│                                                             │
│     computed_hash === declared_hash ? PASS : FAIL           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ PASS
```

### Step 3: Signature Verification

Verify the Ed25519 signature over the canonical content.

```
┌─────────────────────────────────────────────────────────────┐
│                  SIGNATURE VERIFICATION                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Inputs:                                                    │
│  • public_key: 32-byte Ed25519 key (base64)                │
│  • message: canonical JSON bytes (from Step 2)              │
│  • signature: 64-byte Ed25519 signature (base64)            │
│                                                             │
│  Process:                                                   │
│  1. Decode base64 public_key → 32 bytes                    │
│  2. Decode base64 signature → 64 bytes                     │
│  3. Ed25519.verify(signature, message, public_key)          │
│                                                             │
│  Result:                                                    │
│  • true  → Signature is valid, proof is authentic          │
│  • false → Signature invalid, proof may be tampered        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ PASS
```

### Step 4: Type-Specific Checks

Additional verification based on proof type.

```
┌─────────────────────────────────────────────────────────────┐
│                  TYPE-SPECIFIC CHECKS                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DELETION PROOFS:                                           │
│  ✓ compliance.recovery_impossible === true                  │
│  ✓ sanitization_standard is recognized (NIST, DoD, etc.)   │
│                                                             │
│  TRANSMISSION PROOFS:                                       │
│  ✓ sender object present                                    │
│  ✓ receiver object present                                  │
│  ✓ channel.perfect_forward_secrecy === true (recommended)   │
│                                                             │
│  RESIDENCY PROOFS:                                          │
│  ✓ jurisdiction is specified                                │
│  ✓ region matches claimed jurisdiction                      │
│                                                             │
│  BACKUP_INTEGRITY PROOFS:                                   │
│  ✓ fragment_count > 0                                       │
│  ✓ storage_nodes array present                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ PASS

              ╔═══════════════════════════════╗
              ║    ✓ VERIFICATION PASSED      ║
              ╚═══════════════════════════════╝
```

---

## Merkle Inclusion Verification

For proofs that reference a Merkle tree (batch operations).

```
┌─────────────────────────────────────────────────────────────┐
│                 MERKLE INCLUSION PROOF                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Given:                                                     │
│  • leaf_hash: Hash of item being verified                   │
│  • leaf_index: Position in tree (0-indexed)                 │
│  • inclusion_proof: Array of sibling hashes                 │
│  • root: Claimed Merkle root                                │
│                                                             │
│  Process:                                                   │
│                                                             │
│      current = leaf_hash                                    │
│      index = leaf_index                                     │
│                                                             │
│      for sibling in inclusion_proof:                        │
│        if index is even:                                    │
│          current = SHA256(current || sibling)               │
│        else:                                                │
│          current = SHA256(sibling || current)               │
│        index = floor(index / 2)                             │
│                                                             │
│      return current === root                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Visual Example

```
                        ┌───────────┐
                        │   ROOT    │
                        │  H(AB,CD) │
                        └─────┬─────┘
                    ┌─────────┴─────────┐
              ┌─────┴─────┐       ┌─────┴─────┐
              │    AB     │       │    CD     │
              │  H(A,B)   │       │  H(C,D)   │
              └─────┬─────┘       └─────┬─────┘
                ┌───┴───┐           ┌───┴───┐
              ┌─┴─┐   ┌─┴─┐       ┌─┴─┐   ┌─┴─┐
              │ A │   │ B │       │ C │   │ D │
              └───┘   └───┘       └───┘   └───┘
              leaf    leaf        leaf    leaf
              idx=0   idx=1       idx=2   idx=3

To prove leaf C (index=2):
  inclusion_proof = [D, AB]

  Step 1: index=2 (even) → H(C || D) = CD
  Step 2: index=1 (odd)  → H(AB || CD) = ROOT ✓
```

---

## Blockchain Anchoring Verification

Optional verification via public blockchain.

```
┌─────────────────────────────────────────────────────────────┐
│              BLOCKCHAIN ANCHORING VERIFICATION               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Proof contains:                                            │
│  {                                                          │
│    "anchoring": {                                           │
│      "chain": "ethereum",                                   │
│      "network": "mainnet",                                  │
│      "tx_hash": "0xabc...",                                │
│      "block_height": 19000000                               │
│    }                                                        │
│  }                                                          │
│                                                             │
│  Verification Steps:                                        │
│                                                             │
│  1. Query blockchain for transaction:                       │
│     GET eth_getTransactionByHash(tx_hash)                   │
│                                                             │
│  2. Extract embedded data from transaction:                 │
│     • Input data contains proof hash                        │
│     • Or OP_RETURN (Bitcoin)                               │
│                                                             │
│  3. Compare embedded hash with proof's canonical_hash       │
│                                                             │
│  4. Verify block height and timestamp align                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Ethereum Verification Example

```javascript
// Using ethers.js
const tx = await provider.getTransaction(anchoring.tx_hash);
const embeddedHash = tx.data.slice(2); // Remove '0x' prefix

if (embeddedHash === proof.signature.canonical_hash) {
  console.log('Blockchain anchor verified');
  console.log(`Anchored at block ${tx.blockNumber}`);
}
```

---

## CLI Verification Examples

### Basic Verification

```bash
$ nebula-proof verify deletion_proof.json

Nebula Proof Verification
──────────────────────────────────────────────────
Proof ID: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
Type: deletion

  ✓ schema: Schema validation passed
  ✓ canonical_hash: Canonical hash verified
  ✓ signature: Ed25519 signature verified
  ✓ gdpr_recovery_impossible: Data recovery impossible
  ✓ sanitization_standard: NIST SP 800-88 Rev.1 sanitization

──────────────────────────────────────────────────
✓ VERIFICATION PASSED
```

### Detailed Verification with Explanation

```bash
$ nebula-proof verify deletion_proof.json --explain

Nebula Proof Verification
──────────────────────────────────────────────────
Proof ID: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
Type: deletion

  ✓ schema: Schema validation passed
      All required fields present

  ✓ canonical_hash: Canonical hash verified
      hash: e3b0c44298fc1c149afbf4c8...
      algorithm: SHA-256
      canonicalization: RFC 8785 (JCS)

  ✓ signature: Ed25519 signature verified
      algorithm: Ed25519 (RFC 8032)
      key_id: nebula-signing-key-2024-01

  ✓ gdpr_recovery_impossible: Data recovery impossible
      gdpr_article: 17

  ✓ sanitization_standard: NIST SP 800-88 Rev.1 sanitization
      standard: NIST-SP-800-88-Rev1

──────────────────────────────────────────────────
✓ VERIFICATION PASSED
  This proof is cryptographically valid.
  The data integrity and authenticity are confirmed.
```

### JSON Output for CI/CD

```bash
$ nebula-proof verify deletion_proof.json --output json

{
  "valid": true,
  "proofType": "deletion",
  "proofId": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "checks": [
    {
      "name": "schema",
      "passed": true,
      "message": "Schema validation passed"
    },
    {
      "name": "canonical_hash",
      "passed": true,
      "message": "Canonical hash verified",
      "details": {
        "hash": "e3b0c44298fc1c149afbf4c8...",
        "algorithm": "SHA-256"
      }
    },
    {
      "name": "signature",
      "passed": true,
      "message": "Ed25519 signature verified"
    }
  ],
  "errors": []
}
```

### Batch Verification Script

```bash
#!/bin/bash
# verify_all_proofs.sh

PASS=0
FAIL=0

for proof in proofs/*.json; do
  if nebula-proof verify "$proof" --output json | jq -e '.valid' > /dev/null; then
    echo "✓ $proof"
    ((PASS++))
  else
    echo "✗ $proof"
    ((FAIL++))
  fi
done

echo ""
echo "Results: $PASS passed, $FAIL failed"
exit $FAIL
```

---

## Programmatic Verification

### TypeScript

```typescript
import { verifyProof } from '@nebula/proof-kit';
import { readFileSync } from 'fs';

async function verifyDeletionProof(filePath: string) {
  const proof = JSON.parse(readFileSync(filePath, 'utf-8'));

  const result = await verifyProof(proof);

  if (result.valid) {
    console.log('Proof is valid');

    // Check compliance attestations
    const recoveryCheck = result.checks.find(
      c => c.name === 'gdpr_recovery_impossible'
    );

    if (recoveryCheck?.passed) {
      console.log('GDPR Article 17 compliance confirmed');
    }
  } else {
    console.error('Verification failed:', result.errors);
  }

  return result;
}
```

### Python

```python
from nebula_proof import verify_proof
import json

def verify_deletion_proof(file_path: str) -> dict:
    with open(file_path) as f:
        proof = json.load(f)

    result = verify_proof(proof)

    if result.valid:
        print('Proof is valid')

        # Check compliance attestations
        for check in result.checks:
            if check.name == 'gdpr_recovery_impossible' and check.passed:
                print('GDPR Article 17 compliance confirmed')
    else:
        print(f'Verification failed: {result.errors}')

    return result
```

---

## Error Handling

### Common Verification Failures

| Error | Cause | Resolution |
|-------|-------|------------|
| `Missing required field: signature` | Proof JSON is incomplete | Obtain complete proof from source |
| `Canonical hash mismatch` | Proof content was modified | Proof has been tampered with |
| `Ed25519 signature invalid` | Signature doesn't match | Proof was not signed by claimed key |
| `recovery_impossible not confirmed` | Deletion not complete | Contact NebulaGuard for updated proof |

### Handling Verification Results

```typescript
const result = await verifyProof(proof);

switch (true) {
  case result.valid:
    // All checks passed
    processValidProof(proof);
    break;

  case result.errors.includes('Canonical hash mismatch'):
    // Potential tampering
    alertSecurityTeam(proof);
    break;

  case result.errors.some(e => e.includes('signature')):
    // Signature issue
    requestNewProof(proof.proof_id);
    break;

  default:
    // Other failures
    logForReview(proof, result.errors);
}
```

---

## Security Considerations

### Key Rotation

NebulaGuard rotates signing keys periodically. The `key_id` field indicates which key was used:

```json
{
  "signature": {
    "key_id": "nebula-signing-key-2024-01"
  }
}
```

Maintain a list of valid `key_id` values and their corresponding public keys.

### Timestamp Validation

Always validate that proof timestamps are within acceptable bounds:

```python
from datetime import datetime, timedelta

proof_time = datetime.fromisoformat(proof['timestamp'].replace('Z', '+00:00'))
now = datetime.now(proof_time.tzinfo)

# Reject proofs more than 1 year old for certain compliance scenarios
if now - proof_time > timedelta(days=365):
    raise ValueError('Proof too old for compliance requirements')

# Reject proofs dated in the future
if proof_time > now + timedelta(hours=1):
    raise ValueError('Proof timestamp in the future')
```

### Supply Chain Security

- Verify you're using official `nebula-proof-kit` from npm/PyPI
- Check package signatures where available
- Pin dependency versions in production

---

## Troubleshooting

### Debug Mode

Enable verbose logging:

```bash
DEBUG=nebula:* nebula-proof verify proof.json
```

### Manual Verification Steps

If automated verification fails, manually verify:

1. **JSON is valid**: `cat proof.json | jq .`
2. **Has signature block**: `jq '.signature' proof.json`
3. **Hash format**: `jq '.signature.canonical_hash | length' proof.json` (should be 64)
4. **Public key format**: Decode base64, should be 32 bytes

```bash
# Check public key length
echo "BASE64_PUBLIC_KEY" | base64 -d | wc -c
# Should output: 32
```
