/**
 * Schema Validation for Nebula Proofs
 */

import type { ProofBundle, ValidationError } from './types';

export const ProofType = {
  BACKUP_INTEGRITY: 'backup_integrity',
  DELETION: 'deletion',
  RESIDENCY: 'residency',
  TRANSMISSION: 'transmission',
  RECONSTRUCTION: 'reconstruction',
} as const;

const VALID_PROOF_TYPES = Object.values(ProofType);

/**
 * Validate proof bundle against Nebula Proof Schema v1
 */
export function validateSchema(
  proof: Record<string, unknown>
): { valid: boolean; errors: ValidationError[] } {
  const errors: ValidationError[] = [];

  // Required fields
  const requiredFields = ['proof_type', 'proof_id', 'timestamp', 'signature'];

  for (const field of requiredFields) {
    if (!(field in proof)) {
      errors.push({
        field,
        message: `Missing required field: ${field}`,
      });
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  // Proof ID format (32-char hex)
  const proofId = proof.proof_id as string;
  if (!/^[a-f0-9]{32}$/.test(proofId)) {
    errors.push({
      field: 'proof_id',
      message: 'proof_id must be 32-character hex string',
      value: proofId,
    });
  }

  // Proof type validation
  const proofType = proof.proof_type as string;
  if (!VALID_PROOF_TYPES.includes(proofType as typeof VALID_PROOF_TYPES[number])) {
    errors.push({
      field: 'proof_type',
      message: `Invalid proof_type. Must be one of: ${VALID_PROOF_TYPES.join(', ')}`,
      value: proofType,
    });
  }

  // Timestamp format (RFC 3339)
  const timestamp = proof.timestamp as string;
  const rfc3339Pattern =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/;
  if (!rfc3339Pattern.test(timestamp)) {
    errors.push({
      field: 'timestamp',
      message: 'timestamp must be RFC 3339 format',
      value: timestamp,
    });
  }

  // Signature block validation
  const signature = proof.signature;
  if (typeof signature !== 'object' || signature === null) {
    errors.push({
      field: 'signature',
      message: 'signature must be an object',
    });
  } else {
    const sig = signature as Record<string, unknown>;
    const sigRequired = ['public_key', 'canonical_hash'];

    for (const field of sigRequired) {
      if (!(field in sig)) {
        errors.push({
          field: `signature.${field}`,
          message: `Missing required field: signature.${field}`,
        });
      }
    }

    // Signature value can be under 'value' or 'signature'
    if (!('value' in sig) && !('signature' in sig)) {
      errors.push({
        field: 'signature.value',
        message: "Missing signature value (expected 'value' or 'signature' field)",
      });
    }

    // Canonical hash format
    const canonicalHash = sig.canonical_hash as string | undefined;
    if (canonicalHash && !/^[a-f0-9]{64}$/.test(canonicalHash)) {
      errors.push({
        field: 'signature.canonical_hash',
        message: 'canonical_hash must be 64-character hex string',
        value: canonicalHash,
      });
    }
  }

  // Proof-type-specific validation
  if (proofType === ProofType.DELETION) {
    errors.push(...validateDeletionProof(proof as unknown as ProofBundle));
  } else if (proofType === ProofType.TRANSMISSION) {
    errors.push(...validateTransmissionProof(proof as unknown as ProofBundle));
  }

  return { valid: errors.length === 0, errors };
}

function validateDeletionProof(proof: ProofBundle): ValidationError[] {
  const errors: ValidationError[] = [];
  const compliance = proof.compliance;

  if (!compliance || typeof compliance !== 'object') {
    errors.push({
      field: 'compliance',
      message: 'Deletion proofs must have compliance object',
    });
    return errors;
  }

  if (compliance.gdpr_article === '17') {
    if (!('recovery_impossible' in compliance)) {
      errors.push({
        field: 'compliance.recovery_impossible',
        message: 'GDPR Article 17 proofs must specify recovery_impossible',
      });
    }
  }

  return errors;
}

function validateTransmissionProof(proof: ProofBundle): ValidationError[] {
  const errors: ValidationError[] = [];

  if (!proof.sender) {
    errors.push({
      field: 'sender',
      message: 'Transmission proofs must have sender object',
    });
  }

  if (!proof.receiver) {
    errors.push({
      field: 'receiver',
      message: 'Transmission proofs must have receiver object',
    });
  }

  return errors;
}
