/**
 * Tests for Nebula Proof CLI
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { execSync } from 'child_process';
import { join } from 'path';

const CLI_PATH = join(__dirname, '../dist/index.js');
const TEST_VECTORS_DIR = join(__dirname, '../../test-vectors');

function runCli(args: string): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execSync(`node "${CLI_PATH}" ${args}`, {
      encoding: 'utf-8',
      cwd: join(__dirname, '..'),
      shell: '/bin/bash',
    });
    return { stdout, stderr: '', exitCode: 0 };
  } catch (error: unknown) {
    const e = error as { stdout?: string; stderr?: string; status?: number };
    return {
      stdout: e.stdout || '',
      stderr: e.stderr || '',
      exitCode: e.status || 1,
    };
  }
}

describe('CLI', () => {
  beforeAll(() => {
    try {
      execSync('npm run build', { cwd: join(__dirname, '..'), encoding: 'utf-8' });
    } catch {
      // Build might already be done
    }
  });

  describe('verify command', () => {
    it('should verify valid deletion proof', () => {
      const { stdout, exitCode } = runCli(`verify "${TEST_VECTORS_DIR}/valid/deletion_proof.json"`);
      expect(exitCode).toBe(0);
      expect(stdout).toContain('VERIFICATION PASSED');
      expect(stdout).toContain('deletion');
    });

    it('should verify valid transmission proof', () => {
      const { stdout, exitCode } = runCli(`verify "${TEST_VECTORS_DIR}/valid/transmission_proof.json"`);
      expect(exitCode).toBe(0);
      expect(stdout).toContain('VERIFICATION PASSED');
    });

    it('should reject invalid proof with missing signature', () => {
      const { stdout, exitCode } = runCli(`verify "${TEST_VECTORS_DIR}/invalid/missing_signature.json"`);
      expect(exitCode).toBe(1);
      expect(stdout).toContain('VERIFICATION FAILED');
    });

    it('should output JSON with --output json flag', () => {
      const { stdout, exitCode } = runCli(`verify "${TEST_VECTORS_DIR}/valid/deletion_proof.json" --output json`);
      expect(exitCode).toBe(0);
      const result = JSON.parse(stdout);
      expect(result.valid).toBe(true);
      expect(result.proofType).toBe('deletion');
    });
  });

  describe('inspect command', () => {
    it('should inspect proof structure', () => {
      const { stdout, exitCode } = runCli(`inspect "${TEST_VECTORS_DIR}/valid/deletion_proof.json"`);
      expect(exitCode).toBe(0);
      expect(stdout).toContain('Proof Inspection');
      expect(stdout).toContain('deletion');
    });
  });

  describe('merkle-tree command', () => {
    it('should display Merkle tree info', () => {
      const { stdout, exitCode } = runCli(`merkle-tree "${TEST_VECTORS_DIR}/valid/backup_integrity_proof.json"`);
      expect(exitCode).toBe(0);
      expect(stdout).toContain('Merkle Tree');
    });

    it('should handle proof without Merkle data', () => {
      const { stdout, exitCode } = runCli(`merkle-tree "${TEST_VECTORS_DIR}/valid/residency_proof.json"`);
      expect(exitCode).toBe(0);
      expect(stdout).toContain('No Merkle data');
    });
  });

  describe('version and help', () => {
    it('should display version', () => {
      const { stdout, exitCode } = runCli('--version');
      expect(exitCode).toBe(0);
      expect(stdout).toContain('1.0.0');
    });

    it('should display help', () => {
      const { stdout, exitCode } = runCli('--help');
      expect(exitCode).toBe(0);
      expect(stdout).toContain('verify');
      expect(stdout).toContain('inspect');
    });
  });
});
