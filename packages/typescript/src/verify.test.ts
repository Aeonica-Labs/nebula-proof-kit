/**
 * Tests for Nebula Proof Verification
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { verifyProof, verifyCanonicalHash } from './verify';
import type { ProofBundle } from './types';

const TEST_VECTORS_DIR = join(__dirname, '../../../test-vectors');

function loadTestVector(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(TEST_VECTORS_DIR, path), 'utf-8'));
}

describe('verifyProof', () => {
  describe('valid proofs', () => {
    it('should validate deletion proof', async () => {
      const proof = loadTestVector('valid/deletion_proof.json');
      const result = await verifyProof(proof);
      expect(result.proofType).toBe('deletion');
      expect(result.proofId).toBe('39c074f1858b6960a101ec71fe724eb4');
      expect(result.checks.find(c => c.name === 'schema')?.passed).toBe(true);
    });

    it('should validate transmission proof', async () => {
      const proof = loadTestVector('valid/transmission_proof.json');
      const result = await verifyProof(proof);
      expect(result.proofType).toBe('transmission');
      expect(result.checks.find(c => c.name === 'schema')?.passed).toBe(true);
    });

    it('should validate residency proof', async () => {
      const proof = loadTestVector('valid/residency_proof.json');
      const result = await verifyProof(proof);
      expect(result.proofType).toBe('residency');
      expect(result.checks.find(c => c.name === 'schema')?.passed).toBe(true);
    });

    it('should validate backup integrity proof', async () => {
      const proof = loadTestVector('valid/backup_integrity_proof.json');
      const result = await verifyProof(proof);
      expect(result.proofType).toBe('backup_integrity');
      expect(result.checks.find(c => c.name === 'schema')?.passed).toBe(true);
    });
  });

  describe('invalid proofs', () => {
    it('should reject proof with missing signature', async () => {
      const proof = loadTestVector('invalid/missing_signature.json');
      const result = await verifyProof(proof);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject proof with invalid proof_id format', async () => {
      const proof = loadTestVector('invalid/invalid_proof_id.json');
      const result = await verifyProof(proof);
      expect(result.valid).toBe(false);
    });

    it('should reject proof with invalid proof_type', async () => {
      const proof = loadTestVector('invalid/invalid_proof_type.json');
      const result = await verifyProof(proof);
      expect(result.valid).toBe(false);
    });

    it('should reject proof with invalid timestamp', async () => {
      const proof = loadTestVector('invalid/invalid_timestamp.json');
      const result = await verifyProof(proof);
      expect(result.valid).toBe(false);
    });
  });
});

describe('verifyCanonicalHash', () => {
  it('should return canonical_hash check result', async () => {
    const proof = loadTestVector('valid/deletion_proof.json') as unknown as ProofBundle;
    const result = await verifyCanonicalHash(proof);
    expect(result.name).toBe('canonical_hash');
    expect(typeof result.passed).toBe('boolean');
    expect(typeof result.message).toBe('string');
  });

  it('should detect tampered content', async () => {
    const proof = loadTestVector('invalid/tampered_content.json') as unknown as ProofBundle;
    const result = await verifyCanonicalHash(proof);
    expect(result.passed).toBe(false);
    expect(result.message).toContain('mismatch');
  });
});
