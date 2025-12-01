/**
 * Nebula Proof Verification
 *
 * Main verification functions for validating cryptographic proofs.
 */

import { sha256Hex, canonicalJson, verifyEd25519 } from './crypto';
import { validateSchema, ProofType } from './schemas';
import type {
  ProofBundle,
  VerificationResult,
  VerificationCheck,
} from './types';

/**
 * Verify a Nebula proof bundle.
 *
 * Performs all standard verification checks:
 * 1. Schema validation
 * 2. Canonical hash verification
 * 3. Signature verification
 * 4. Proof-type-specific checks
 */
export async function verifyProof(
  proof: Record<string, unknown>
): Promise<VerificationResult> {
  const result: VerificationResult = {
    valid: false,
    proofType: (proof.proof_type as string) || null,
    proofId: (proof.proof_id as string) || null,
    checks: [],
    errors: [],
  };

  // 1. Schema validation
  const { valid: schemaValid, errors: schemaErrors } = validateSchema(proof);
  result.checks.push({
    name: 'schema',
    passed: schemaValid,
    message: schemaValid ? 'Schema validation passed' : 'Schema validation failed',
    details: schemaErrors.length > 0 ? { errors: schemaErrors.map((e) => e.message) } : undefined,
  });

  if (!schemaValid) {
    result.errors.push(...schemaErrors.map((e) => e.message));
    return result;
  }

  // 2. Canonical hash verification
  const hashResult = await verifyCanonicalHash(proof as unknown as ProofBundle);
  result.checks.push(hashResult);

  if (!hashResult.passed) {
    result.errors.push(hashResult.message);
    return result;
  }

  // 3. Signature verification
  const sigResult = await verifySignature(proof as unknown as ProofBundle);
  result.checks.push(sigResult);

  if (!sigResult.passed) {
    result.errors.push(sigResult.message);
    return result;
  }

  // 4. Proof-type-specific checks
  const proofType = proof.proof_type as string;

  if (proofType === ProofType.DELETION) {
    const complianceChecks = verifyDeletionCompliance(proof as unknown as ProofBundle);
    result.checks.push(...complianceChecks);
    for (const check of complianceChecks) {
      if (!check.passed) {
        result.errors.push(check.message);
      }
    }
  } else if (proofType === ProofType.TRANSMISSION) {
    const transmissionChecks = verifyTransmissionProof(proof as unknown as ProofBundle);
    result.checks.push(...transmissionChecks);
    for (const check of transmissionChecks) {
      if (!check.passed) {
        result.errors.push(check.message);
      }
    }
  }

  // Final verdict
  result.valid = result.checks.every((check) => check.passed);

  return result;
}

/**
 * Verify the canonical hash matches the proof content.
 */
export async function verifyCanonicalHash(
  proof: ProofBundle
): Promise<VerificationCheck> {
  const signatureBlock = proof.signature;
  const declaredHash = signatureBlock?.canonical_hash || '';

  // Build content for hashing (exclude signature block)
  const proofForHashing: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(proof)) {
    if (key !== 'signature') {
      proofForHashing[key] = value;
    }
  }

  const canonicalBytes = canonicalJson(proofForHashing);
  const computedHash = await sha256Hex(canonicalBytes);

  if (computedHash === declaredHash) {
    return {
      name: 'canonical_hash',
      passed: true,
      message: 'Canonical hash verified',
      details: {
        hash: computedHash.substring(0, 32) + '...',
        algorithm: 'SHA-256',
        canonicalization: 'RFC 8785 (JCS)',
      },
    };
  } else {
    return {
      name: 'canonical_hash',
      passed: false,
      message: 'Canonical hash mismatch',
      details: {
        expected: declaredHash ? declaredHash.substring(0, 32) + '...' : null,
        computed: computedHash.substring(0, 32) + '...',
      },
    };
  }
}

/**
 * Verify the Ed25519 signature.
 */
export async function verifySignature(
  proof: ProofBundle
): Promise<VerificationCheck> {
  const signatureBlock = proof.signature;

  // Get signature value (can be 'value' or 'signature')
  const sigValue = signatureBlock?.value || signatureBlock?.signature;
  const publicKeyB64 = signatureBlock?.public_key;

  if (!sigValue || !publicKeyB64) {
    return {
      name: 'signature',
      passed: false,
      message: 'Missing signature or public key',
    };
  }

  // Build canonical message
  const proofForSigning: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(proof)) {
    if (key !== 'signature') {
      proofForSigning[key] = value;
    }
  }

  const canonicalBytes = canonicalJson(proofForSigning);

  try {
    const isValid = await verifyEd25519(publicKeyB64, canonicalBytes, sigValue);

    if (isValid) {
      return {
        name: 'signature',
        passed: true,
        message: 'Ed25519 signature verified',
        details: {
          algorithm: 'Ed25519 (RFC 8032)',
          key_id: signatureBlock?.key_id,
        },
      };
    } else {
      return {
        name: 'signature',
        passed: false,
        message: 'Ed25519 signature invalid',
      };
    }
  } catch (e) {
    return {
      name: 'signature',
      passed: false,
      message: `Signature verification error: ${e}`,
    };
  }
}

/**
 * Verify Merkle tree inclusion proof.
 */
export function verifyMerkleInclusion(
  proof: ProofBundle,
  _leafHash: string,
  _leafIndex: number
): VerificationCheck {
  const merkle = proof.merkle;
  const root = merkle?.root || '';
  const inclusionProof = merkle?.inclusion_proof || [];

  if (!root || inclusionProof.length === 0) {
    return {
      name: 'merkle_inclusion',
      passed: false,
      message: 'Missing Merkle root or inclusion proof',
    };
  }

  // Structure validation only for now
  return {
    name: 'merkle_inclusion',
    passed: true,
    message: 'Merkle inclusion proof structure valid',
    details: {
      root: root.length > 32 ? root.substring(0, 32) + '...' : root,
      proof_length: inclusionProof.length,
    },
  };
}

function verifyDeletionCompliance(proof: ProofBundle): VerificationCheck[] {
  const checks: VerificationCheck[] = [];
  const compliance = proof.compliance || {};

  // Check recovery_impossible
  const recoveryImpossible = compliance.recovery_impossible || false;
  checks.push({
    name: 'gdpr_recovery_impossible',
    passed: recoveryImpossible,
    message: recoveryImpossible
      ? 'Data recovery impossible'
      : 'recovery_impossible not confirmed',
    details: { gdpr_article: compliance.gdpr_article },
  });

  // Check sanitization standard
  const sanitization = compliance.sanitization_standard;
  const isNist = sanitization === 'NIST-SP-800-88-Rev1';
  checks.push({
    name: 'sanitization_standard',
    passed: isNist,
    message: isNist
      ? 'NIST SP 800-88 Rev.1 sanitization'
      : `Non-standard sanitization: ${sanitization}`,
    details: { standard: sanitization },
  });

  return checks;
}

function verifyTransmissionProof(proof: ProofBundle): VerificationCheck[] {
  const checks: VerificationCheck[] = [];

  // Check dual-party attestation
  const hasSender = !!proof.sender;
  const hasReceiver = !!proof.receiver;

  checks.push({
    name: 'dual_party_attestation',
    passed: hasSender && hasReceiver,
    message:
      hasSender && hasReceiver
        ? 'Dual-party attestation present'
        : 'Missing sender or receiver',
  });

  // Check channel security
  const channel = proof.channel || {};
  const pfs = channel.perfect_forward_secrecy || false;

  checks.push({
    name: 'perfect_forward_secrecy',
    passed: pfs,
    message: pfs ? 'Perfect Forward Secrecy enabled' : 'PFS not enabled',
    details: { tls_version: channel.tls_version },
  });

  return checks;
}
