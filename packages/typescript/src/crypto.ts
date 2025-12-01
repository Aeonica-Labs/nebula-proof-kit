/**
 * Cryptographic Primitives for Nebula Proof Verification
 *
 * Implements:
 * - SHA-256 hashing (FIPS 180-4)
 * - JSON Canonicalization (RFC 8785 / JCS)
 * - Ed25519 signature verification (RFC 8032)
 * - Merkle tree operations
 */

import * as ed from '@noble/ed25519';

/**
 * Compute SHA-256 hash using Web Crypto API
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

/**
 * Compute SHA-256 hash as hex string
 */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const hash = await sha256(data);
  return Array.from(hash)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Serialize to canonical JSON (RFC 8785 / JCS)
 *
 * Ensures deterministic serialization for signing:
 * - Keys sorted alphabetically (recursive)
 * - No extra whitespace
 * - Consistent number formatting
 */
export function canonicalJson(obj: Record<string, unknown>): Uint8Array {
  const sortObject = (o: unknown): unknown => {
    if (o === null || typeof o !== 'object') {
      return o;
    }

    if (Array.isArray(o)) {
      return o.map(sortObject);
    }

    const sorted: Record<string, unknown> = {};
    const keys = Object.keys(o as Record<string, unknown>).sort();

    for (const key of keys) {
      sorted[key] = sortObject((o as Record<string, unknown>)[key]);
    }

    return sorted;
  };

  const canonical = sortObject(obj);
  const jsonStr = JSON.stringify(canonical);

  return new TextEncoder().encode(jsonStr);
}

/**
 * Verify Ed25519 signature (RFC 8032)
 *
 * @param publicKey - 32-byte Ed25519 public key (Uint8Array or base64 string)
 * @param message - Message that was signed
 * @param signature - 64-byte signature (Uint8Array or base64 string)
 * @returns True if signature is valid
 */
export async function verifyEd25519(
  publicKey: Uint8Array | string,
  message: Uint8Array,
  signature: Uint8Array | string
): Promise<boolean> {
  try {
    // Handle base64 strings
    const pubKeyBytes =
      typeof publicKey === 'string' ? base64ToBytes(publicKey) : publicKey;

    const sigBytes =
      typeof signature === 'string' ? base64ToBytes(signature) : signature;

    return await ed.verifyAsync(sigBytes, message, pubKeyBytes);
  } catch {
    return false;
  }
}

/**
 * Compute Merkle tree root from leaf hashes
 *
 * Canonical merkle tree construction:
 * - Padding mode: Duplicate last leaf to next power of 2
 * - Hash mode: SHA-256(left || right)
 * - Concatenation order: left then right
 */
export async function merkleRoot(hashes: Uint8Array[]): Promise<Uint8Array> {
  if (hashes.length === 0) {
    throw new Error('Cannot compute merkle root of empty list');
  }

  if (hashes.length === 1) {
    return hashes[0];
  }

  // Pad to power of 2 by duplicating last
  let leaves = [...hashes];
  while ((leaves.length & (leaves.length - 1)) !== 0) {
    leaves.push(leaves[leaves.length - 1]);
  }

  // Build tree bottom-up
  while (leaves.length > 1) {
    const nextLevel: Uint8Array[] = [];

    for (let i = 0; i < leaves.length; i += 2) {
      const combined = new Uint8Array(leaves[i].length + leaves[i + 1].length);
      combined.set(leaves[i], 0);
      combined.set(leaves[i + 1], leaves[i].length);
      nextLevel.push(await sha256(combined));
    }

    leaves = nextLevel;
  }

  return leaves[0];
}

/**
 * Verify Merkle inclusion proof
 */
export async function verifyMerkleInclusion(
  leafHash: Uint8Array,
  inclusionProof: Uint8Array[],
  rootHash: Uint8Array,
  leafIndex: number
): Promise<boolean> {
  let current = leafHash;
  let index = leafIndex;

  for (const sibling of inclusionProof) {
    const combined = new Uint8Array(current.length + sibling.length);

    if (index % 2 === 0) {
      // Current is left child
      combined.set(current, 0);
      combined.set(sibling, current.length);
    } else {
      // Current is right child
      combined.set(sibling, 0);
      combined.set(current, sibling.length);
    }

    current = await sha256(combined);
    index = Math.floor(index / 2);
  }

  return arrayEquals(current, rootHash);
}

// Utility functions

function base64ToBytes(base64: string): Uint8Array {
  const binString = atob(base64);
  return Uint8Array.from(binString, (c) => c.charCodeAt(0));
}

function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export { base64ToBytes, arrayEquals };
