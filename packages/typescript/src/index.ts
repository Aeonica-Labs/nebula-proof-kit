/**
 * Nebula Proof Kit - TypeScript SDK
 *
 * Standalone verification toolkit for Nebula cryptographic proofs.
 * Anyone can verify. Only Nebula can produce.
 *
 * For the people. With love and freedom.
 */

export { verifyProof, verifyCanonicalHash, verifySignature, verifyMerkleInclusion } from './verify';
export { validateSchema, ProofType } from './schemas';
export { sha256, sha256Hex, canonicalJson, verifyEd25519, merkleRoot } from './crypto';
export type {
  ProofBundle,
  VerificationResult,
  VerificationCheck,
  SignatureBlock,
  MerkleData,
  ComplianceData,
  AnchoringData,
} from './types';
