# Policy Mapping: Regulations to Proof Types

This document maps regulatory requirements to NebulaGuard proof types, explaining how cryptographic proofs satisfy compliance obligations.

## Overview

| Regulation | Article/Section | Proof Type | Key Attestation |
|------------|----------------|------------|-----------------|
| GDPR | Article 17 | `deletion` | `recovery_impossible: true` |
| GDPR | Article 44 | `residency` | `jurisdiction: "EU"` |
| HIPAA | §164.310(d) | `deletion` | `sanitization_standard` |
| SOC 2 | CC6.1 | `backup_integrity` | `fragment_count`, `redundancy` |
| PCI DSS | Req. 3.2 | `deletion` | Secure deletion attestation |

---

## GDPR (General Data Protection Regulation)

### Article 17 - Right to Erasure ("Right to be Forgotten")

**Requirement**: Data subjects can request deletion of their personal data. Controllers must erase data "without undue delay."

**Proof Type**: `deletion`

**Required Attestations**:
```json
{
  "compliance": {
    "gdpr_article": "17",
    "recovery_impossible": true,
    "sanitization_standard": "NIST-SP-800-88-Rev1"
  }
}
```

**Verification Checks**:
1. `recovery_impossible` must be `true`
2. Valid sanitization standard must be specified
3. Cryptographic signature must be valid
4. Timestamp must be within 30 days of request (configurable)

**Auditor Guidance**:
- Use `nebula-proof verify --explain` to see human-readable verification
- Check `nodes_confirmed` matches expected storage topology
- Verify signing key is from authorized Nebula infrastructure

---

### Article 44 - Transfers to Third Countries

**Requirement**: Personal data cannot be transferred outside the EU/EEA without adequate safeguards.

**Proof Type**: `residency`

**Required Attestations**:
```json
{
  "data": {
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

**Verification Checks**:
1. `jurisdiction` must be `"EU"` or approved country
2. All storage nodes must be in compliant regions
3. Proof must be fresh (within retention window)

---

## HIPAA (Health Insurance Portability and Accountability Act)

### §164.310(d) - Device and Media Controls

**Requirement**: Implement policies for the final disposition of ePHI and hardware/media on which it is stored.

**Proof Type**: `deletion`

**Required Attestations**:
```json
{
  "compliance": {
    "hipaa_section": "164.310(d)",
    "media_sanitization": true,
    "sanitization_standard": "NIST-SP-800-88-Rev1"
  }
}
```

**Verification Checks**:
1. Sanitization must follow NIST SP 800-88 or equivalent
2. All storage locations must be confirmed deleted
3. Chain of custody maintained through proof chain

---

### §164.312(e) - Transmission Security

**Requirement**: Implement technical security measures to guard against unauthorized access during transmission.

**Proof Type**: `transmission`

**Required Attestations**:
```json
{
  "channel": {
    "tls_version": "1.3",
    "perfect_forward_secrecy": true,
    "cipher_suite": "TLS_AES_256_GCM_SHA384"
  },
  "compliance": {
    "hipaa_section": "164.312(e)",
    "encryption_in_transit": true
  }
}
```

---

## SOC 2 (Service Organization Control 2)

### CC6.1 - Logical and Physical Access Controls

**Requirement**: The entity implements logical access security software to protect information assets.

**Proof Types**: `backup_integrity`, `residency`

**Mapping**:
- Backup integrity proofs demonstrate data is stored securely with verified redundancy
- Residency proofs demonstrate access is limited to authorized regions

**Audit Evidence**:
```bash
# Generate verification report for SOC 2 auditor
nebula-proof verify backup_proof.json --output json > soc2_evidence.json
```

---

### CC7.2 - System Operations

**Requirement**: The entity monitors system components for anomalies and indicators of compromise.

**Proof Type**: `backup_integrity` (continuous)

**Use Case**: Regular integrity proofs demonstrate ongoing monitoring and verification of stored data.

---

## PCI DSS (Payment Card Industry Data Security Standard)

### Requirement 3.2 - Protect Stored Cardholder Data

**Requirement**: Do not store sensitive authentication data after authorization.

**Proof Type**: `deletion`

**Required Attestations**:
```json
{
  "compliance": {
    "pci_dss_requirement": "3.2",
    "cardholder_data": true,
    "secure_deletion": true
  }
}
```

**Quarterly Audit Process**:
1. Collect all deletion proofs for cardholder data
2. Verify each proof cryptographically
3. Confirm deletion timestamps align with retention policy
4. Generate compliance report

---

### Requirement 9.8 - Media Destruction

**Requirement**: Destroy media when no longer needed for business or legal reasons.

**Proof Type**: `deletion`

**Mapping**: Same as Requirement 3.2, with additional media tracking fields.

---

## CCPA (California Consumer Privacy Act)

### §1798.105 - Right to Deletion

**Requirement**: Consumers have the right to request deletion of personal information.

**Proof Type**: `deletion`

**Required Attestations**:
```json
{
  "compliance": {
    "ccpa_section": "1798.105",
    "consumer_request": true,
    "recovery_impossible": true
  }
}
```

---

## ISO 27001

### A.8.3.2 - Disposal of Media

**Requirement**: Media shall be disposed of securely when no longer required.

**Proof Type**: `deletion`

**Required Attestations**:
```json
{
  "compliance": {
    "iso_27001_control": "A.8.3.2",
    "secure_disposal": true,
    "sanitization_standard": "NIST-SP-800-88-Rev1"
  }
}
```

---

## Compliance Verification Workflow

### For Data Controllers

1. **Request Proof**: After deletion request, obtain proof from NebulaGuard
2. **Verify Independently**:
   ```bash
   nebula-proof verify deletion_proof.json --explain
   ```
3. **Archive for Audit**: Store verified proofs for compliance records
4. **Report to Data Subject**: Provide proof ID as confirmation

### For Auditors

1. **Collect Proof Bundle**: Obtain proofs from organization
2. **Batch Verify**:
   ```bash
   for proof in *.json; do
     nebula-proof verify "$proof" --output json >> audit_results.json
   done
   ```
3. **Check Compliance Fields**: Ensure required attestations present
4. **Verify Signing Keys**: Confirm keys are from authorized infrastructure
5. **Document Findings**: Generate audit report

### For Regulators

1. **Independent Verification**: Use open-source nebula-proof-kit
2. **No Backend Access Required**: All verification is cryptographic
3. **Chain of Custody**: Proofs are tamper-evident
4. **Blockchain Anchoring**: Optional additional verification via public chains

---

## Proof Retention Guidelines

| Regulation | Minimum Retention | Recommended |
|------------|------------------|-------------|
| GDPR | Duration of processing | 7 years |
| HIPAA | 6 years | 10 years |
| SOC 2 | Audit period | 7 years |
| PCI DSS | 1 year | 7 years |
| CCPA | Duration of relationship | 7 years |

---

## Generating Compliance Reports

### GDPR Article 17 Report

```python
from nebula_proof import verify_proof

proofs = load_proofs_for_period("2024-Q1")
gdpr_deletions = [
    p for p in proofs
    if p.get("compliance", {}).get("gdpr_article") == "17"
]

results = []
for proof in gdpr_deletions:
    result = verify_proof(proof)
    results.append({
        "proof_id": proof["proof_id"],
        "timestamp": proof["timestamp"],
        "valid": result.valid,
        "recovery_impossible": proof.get("compliance", {}).get("recovery_impossible")
    })

generate_report(results, "gdpr_q1_2024.pdf")
```

### SOC 2 Audit Evidence

```typescript
import { verifyProof } from '@nebula/proof-kit';

const proofs = await loadAuditProofs();
const results = await Promise.all(
  proofs.map(proof => verifyProof(proof))
);

const auditEvidence = results.map((result, i) => ({
  proofId: proofs[i].proof_id,
  verified: result.valid,
  checks: result.checks.map(c => c.name + ': ' + (c.passed ? 'PASS' : 'FAIL'))
}));

fs.writeFileSync('soc2_evidence.json', JSON.stringify(auditEvidence, null, 2));
```

---

## References

- [GDPR Full Text](https://gdpr-info.eu/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/soc2)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/)
- [CCPA Text](https://oag.ca.gov/privacy/ccpa)
- [ISO 27001:2022](https://www.iso.org/standard/27001)
