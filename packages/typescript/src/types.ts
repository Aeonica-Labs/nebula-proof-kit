/**
 * Type definitions for Nebula Proof Kit
 */

/**
 * Supported proof types
 */
export type ProofType =
  | 'backup_integrity'
  | 'deletion'
  | 'residency'
  | 'transmission'
  | 'reconstruction';

/**
 * Signature block in a proof bundle
 */
export interface SignatureBlock {
  algorithm: 'ed25519';
  public_key: string;
  value?: string;
  signature?: string;
  key_id?: string;
  canonical_hash: string;
}

/**
 * Merkle tree data
 */
export interface MerkleData {
  root: string;
  algorithm: 'sha256';
  leaf_count: number;
  inclusion_proof?: string[];
}

/**
 * Node attestation
 */
export interface Attestation {
  node_id: string;
  region?: string;
  shard_hash: string;
  timestamp: string;
  signature?: string;
}

/**
 * Compliance data for deletion proofs
 */
export interface ComplianceData {
  gdpr_article?: string;
  recovery_impossible?: boolean;
  keys_destroyed?: boolean;
  backups_deleted?: boolean;
  sanitization_standard?: string;
  residency_respected?: boolean;
}

/**
 * Blockchain anchoring data
 */
export interface AnchoringData {
  chain: string;
  tx_hash: string;
  block_height: number;
  anchor_timestamp: string;
}

/**
 * Subject of the proof
 */
export interface ProofSubject {
  object_id: string;
  object_hash?: string;
  size_bytes?: number;
}

/**
 * Algorithm specifications
 */
export interface AlgorithmSpec {
  canonicalization: 'JCS';
  hash: 'SHA-256';
  signature: 'Ed25519';
  merkle?: {
    hash: 'SHA-256';
    leaf_encoding: 'utf-8';
    pad_mode: 'power_of_two_duplicate_last';
    concat_order: 'left||right';
  };
}

/**
 * Complete proof bundle
 */
export interface ProofBundle {
  version?: string;
  proof_type: ProofType;
  proof_id: string;
  timestamp: string;
  schema_version?: string;
  subject?: ProofSubject;
  algorithms?: AlgorithmSpec;
  merkle?: MerkleData;
  attestations?: Attestation[];
  compliance?: ComplianceData;
  anchoring?: AnchoringData;
  signature: SignatureBlock;
  bundle_hash?: string;
  // Transmission proof specific
  sender?: { identity: string; signature: string; public_key: string };
  receiver?: { identity: string; signature: string; public_key: string };
  channel?: { tls_version?: string; perfect_forward_secrecy?: boolean };
  // Additional fields
  [key: string]: unknown;
}

/**
 * Individual verification check result
 */
export interface VerificationCheck {
  name: string;
  passed: boolean;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Complete verification result
 */
export interface VerificationResult {
  valid: boolean;
  proofType: ProofType | null;
  proofId: string | null;
  checks: VerificationCheck[];
  errors: string[];
}

/**
 * Schema validation error
 */
export interface ValidationError {
  field: string;
  message: string;
  value?: unknown;
}
