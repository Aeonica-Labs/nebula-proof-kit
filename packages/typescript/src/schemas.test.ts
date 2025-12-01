/**
 * Tests for Nebula Proof Schema Validation
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { validateSchema, ProofType } from './schemas';

const TEST_VECTORS_DIR = join(__dirname, '../../../test-vectors');

function loadTestVector(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(TEST_VECTORS_DIR, path), 'utf-8'));
}

describe('validateSchema', () => {
  describe('valid proofs', () => {
    it('should validate deletion proof schema', () => {
      const proof = loadTestVector('valid/deletion_proof.json');
      const { valid, errors } = validateSchema(proof);
      expect(valid).toBe(true);
      expect(errors).toHaveLength(0);
    });

    it('should validate transmission proof schema', () => {
      const proof = loadTestVector('valid/transmission_proof.json');
      const { valid, errors } = validateSchema(proof);
      expect(valid).toBe(true);
      expect(errors).toHaveLength(0);
    });

    it('should validate residency proof schema', () => {
      const proof = loadTestVector('valid/residency_proof.json');
      const { valid, errors } = validateSchema(proof);
      expect(valid).toBe(true);
      expect(errors).toHaveLength(0);
    });

    it('should validate backup integrity proof schema', () => {
      const proof = loadTestVector('valid/backup_integrity_proof.json');
      const { valid, errors } = validateSchema(proof);
      expect(valid).toBe(true);
      expect(errors).toHaveLength(0);
    });
  });

  describe('invalid proofs', () => {
    it('should reject proof with invalid proof_id', () => {
      const proof = loadTestVector('invalid/invalid_proof_id.json');
      const { valid, errors } = validateSchema(proof);
      expect(valid).toBe(false);
      expect(errors.some(e => e.field === 'proof_id')).toBe(true);
    });

    it('should reject proof with invalid proof_type', () => {
      const proof = loadTestVector('invalid/invalid_proof_type.json');
      const { valid, errors } = validateSchema(proof);
      expect(valid).toBe(false);
      expect(errors.some(e => e.field === 'proof_type')).toBe(true);
    });

    it('should reject proof with invalid timestamp', () => {
      const proof = loadTestVector('invalid/invalid_timestamp.json');
      const { valid, errors } = validateSchema(proof);
      expect(valid).toBe(false);
      expect(errors.some(e => e.field === 'timestamp')).toBe(true);
    });

    it('should reject proof missing signature block', () => {
      const proof = loadTestVector('invalid/missing_signature.json');
      const { valid, errors } = validateSchema(proof);
      expect(valid).toBe(false);
      expect(errors.some(e => e.field === 'signature')).toBe(true);
    });

    it('should reject proof missing public_key', () => {
      const proof = loadTestVector('invalid/missing_public_key.json');
      const { valid, errors } = validateSchema(proof);
      expect(valid).toBe(false);
      expect(errors.some(e => e.field.includes('public_key'))).toBe(true);
    });
  });
});

describe('ProofType', () => {
  it('should have all expected proof types', () => {
    expect(ProofType.DELETION).toBe('deletion');
    expect(ProofType.TRANSMISSION).toBe('transmission');
    expect(ProofType.RESIDENCY).toBe('residency');
    expect(ProofType.BACKUP_INTEGRITY).toBe('backup_integrity');
    expect(ProofType.RECONSTRUCTION).toBe('reconstruction');
  });
});
