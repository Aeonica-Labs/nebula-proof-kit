# Test Vectors

This directory contains test vectors for validating Nebula proof verifier implementations.

## Directory Structure

```
test-vectors/
├── valid/           # Proofs that SHOULD pass verification
│   ├── deletion_proof.json
│   ├── transmission_proof.json
│   ├── backup_integrity_proof.json
│   └── residency_proof.json
├── invalid/         # Proofs that SHOULD fail verification
│   ├── missing_signature.json
│   ├── invalid_proof_id.json
│   ├── invalid_proof_type.json
│   ├── invalid_timestamp.json
│   ├── tampered_content.json
│   ├── missing_public_key.json
│   ├── invalid_canonical_hash.json
│   ├── deletion_missing_compliance.json
│   ├── transmission_missing_receiver.json
│   └── recovery_not_impossible.json
└── README.md
```

## Valid Test Vectors

All proofs in `valid/` should pass schema validation. Note that signature verification may fail unless using the exact test keys.

| File | Proof Type | Description |
|------|------------|-------------|
| `deletion_proof.json` | deletion | GDPR Article 17 deletion with NIST sanitization |
| `transmission_proof.json` | transmission | Dual-party transmission with TLS 1.3 |
| `backup_integrity_proof.json` | backup_integrity | Multi-node storage with Merkle tree |
| `residency_proof.json` | residency | EU data residency attestation |

## Invalid Test Vectors

All proofs in `invalid/` should fail verification. Each file includes:
- `_test_description`: What makes this proof invalid
- `_expected_error`: The error message verifiers should produce

| File | Expected Failure |
|------|------------------|
| `missing_signature.json` | Missing signature block |
| `invalid_proof_id.json` | proof_id not 32-char hex |
| `invalid_proof_type.json` | Invalid proof_type enum |
| `invalid_timestamp.json` | Non-RFC 3339 timestamp |
| `tampered_content.json` | Content modified after signing |
| `missing_public_key.json` | No public_key in signature |
| `invalid_canonical_hash.json` | Hash not 64-char hex |
| `deletion_missing_compliance.json` | Deletion without compliance |
| `transmission_missing_receiver.json` | Transmission without receiver |
| `recovery_not_impossible.json` | GDPR but recovery possible |

## Running Tests

### CLI

```bash
# Test valid proofs (should all pass)
for proof in test-vectors/valid/*.json; do
  echo "Testing: $proof"
  nebula-proof verify "$proof"
done

# Test invalid proofs (should all fail)
for proof in test-vectors/invalid/*.json; do
  echo "Testing: $proof"
  nebula-proof verify "$proof" && echo "UNEXPECTED PASS" || echo "Expected failure"
done
```

### TypeScript

```typescript
import { verifyProof } from '@nebula/proof-kit';
import { readdirSync, readFileSync } from 'fs';

// Test valid proofs
const validDir = './test-vectors/valid';
for (const file of readdirSync(validDir)) {
  const proof = JSON.parse(readFileSync(`${validDir}/${file}`, 'utf-8'));
  const result = await verifyProof(proof);

  // Schema should pass (signature verification needs actual keys)
  const schemaCheck = result.checks.find(c => c.name === 'schema');
  console.assert(schemaCheck?.passed, `${file} schema should pass`);
}

// Test invalid proofs
const invalidDir = './test-vectors/invalid';
for (const file of readdirSync(invalidDir)) {
  const proof = JSON.parse(readFileSync(`${invalidDir}/${file}`, 'utf-8'));
  const result = await verifyProof(proof);

  console.assert(!result.valid, `${file} should fail`);
  console.log(`${file}: ${result.errors[0]}`);
}
```

### Python

```python
from nebula_proof import verify_proof
import json
import os

# Test valid proofs
valid_dir = './test-vectors/valid'
for filename in os.listdir(valid_dir):
    with open(f'{valid_dir}/{filename}') as f:
        proof = json.load(f)
    result = verify_proof(proof)

    # Schema should pass
    schema_check = next((c for c in result.checks if c['name'] == 'schema'), None)
    assert schema_check and schema_check['passed'], f"{filename} schema should pass"

# Test invalid proofs
invalid_dir = './test-vectors/invalid'
for filename in os.listdir(invalid_dir):
    with open(f'{invalid_dir}/{filename}') as f:
        proof = json.load(f)
    result = verify_proof(proof)

    assert not result.valid, f"{filename} should fail"
    print(f"{filename}: {result.errors[0]}")
```

## Adding New Test Vectors

When adding new test vectors:

1. **Valid proofs**: Use real cryptographic signatures or document that signature verification will fail
2. **Invalid proofs**: Include `_test_description` and `_expected_error` fields
3. **Update this README** with the new test case

## Canonical Test Values

For implementations building their own test proofs:

```
Test Ed25519 Private Key (base64):
  DO NOT USE IN PRODUCTION - FOR TESTING ONLY

Test Public Key (base64):
  YvzswcSbGdztT/OuRofz6DjOB/eazB6lz3LTLnyvaqQ=
```
