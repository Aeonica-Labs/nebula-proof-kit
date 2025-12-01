/**
 * Tests for Nebula Proof Kit Cryptographic Primitives
 */

import { describe, it, expect } from 'vitest';
import {
  sha256,
  sha256Hex,
  canonicalJson,
  merkleRoot,
  verifyMerkleInclusion,
} from './crypto';

describe('sha256', () => {
  it('should hash empty input correctly', async () => {
    const input = new Uint8Array(0);
    const hash = await sha256Hex(input);
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('should hash "hello" correctly', async () => {
    const input = new TextEncoder().encode('hello');
    const hash = await sha256Hex(input);
    expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  it('should return Uint8Array from sha256', async () => {
    const input = new TextEncoder().encode('test');
    const hash = await sha256(input);
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });
});

describe('canonicalJson', () => {
  it('should sort keys alphabetically', () => {
    const obj = { z: 1, a: 2, m: 3 };
    const canonical = canonicalJson(obj);
    const result = new TextDecoder().decode(canonical);
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it('should handle nested objects', () => {
    const obj = { b: { z: 1, a: 2 }, a: 1 };
    const canonical = canonicalJson(obj);
    const result = new TextDecoder().decode(canonical);
    expect(result).toBe('{"a":1,"b":{"a":2,"z":1}}');
  });

  it('should handle arrays', () => {
    const obj = { arr: [3, 1, 2] };
    const canonical = canonicalJson(obj);
    const result = new TextDecoder().decode(canonical);
    expect(result).toBe('{"arr":[3,1,2]}');
  });

  it('should return Uint8Array', () => {
    const obj = { test: 'value' };
    const canonical = canonicalJson(obj);
    expect(canonical).toBeInstanceOf(Uint8Array);
  });
});

describe('merkleRoot', () => {
  it('should return single hash for single leaf', async () => {
    const leaf = await sha256(new TextEncoder().encode('leaf'));
    const root = await merkleRoot([leaf]);
    expect(root).toEqual(leaf);
  });

  it('should compute root for two leaves', async () => {
    const leaf1 = await sha256(new TextEncoder().encode('leaf1'));
    const leaf2 = await sha256(new TextEncoder().encode('leaf2'));
    const root = await merkleRoot([leaf1, leaf2]);

    const combined = new Uint8Array(leaf1.length + leaf2.length);
    combined.set(leaf1, 0);
    combined.set(leaf2, leaf1.length);
    const expectedRoot = await sha256(combined);
    expect(root).toEqual(expectedRoot);
  });

  it('should throw for empty list', async () => {
    await expect(merkleRoot([])).rejects.toThrow('Cannot compute merkle root of empty list');
  });
});

describe('verifyMerkleInclusion', () => {
  it('should verify inclusion for leaf 0 in 2-leaf tree', async () => {
    const leaf0 = await sha256(new TextEncoder().encode('leaf0'));
    const leaf1 = await sha256(new TextEncoder().encode('leaf1'));

    const combined = new Uint8Array(leaf0.length + leaf1.length);
    combined.set(leaf0, 0);
    combined.set(leaf1, leaf0.length);
    const root = await sha256(combined);

    const isValid = await verifyMerkleInclusion(leaf0, [leaf1], root, 0);
    expect(isValid).toBe(true);
  });

  it('should reject wrong leaf hash', async () => {
    const leaf0 = await sha256(new TextEncoder().encode('leaf0'));
    const leaf1 = await sha256(new TextEncoder().encode('leaf1'));
    const wrongLeaf = await sha256(new TextEncoder().encode('wrong'));

    const combined = new Uint8Array(leaf0.length + leaf1.length);
    combined.set(leaf0, 0);
    combined.set(leaf1, leaf0.length);
    const root = await sha256(combined);

    const isValid = await verifyMerkleInclusion(wrongLeaf, [leaf1], root, 0);
    expect(isValid).toBe(false);
  });
});
