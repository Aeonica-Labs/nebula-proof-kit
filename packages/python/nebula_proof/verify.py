"""
Nebula Proof Verification

Main verification functions for validating cryptographic proofs.
"""

import base64
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from .crypto import sha256, sha256_hex, canonical_json, verify_ed25519
from .schemas import validate_schema, ProofType


@dataclass
class VerificationCheck:
    """Individual verification check result."""
    name: str
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None


@dataclass
class VerificationResult:
    """Complete verification result."""
    valid: bool
    proof_type: Optional[str] = None
    proof_id: Optional[str] = None
    checks: List[VerificationCheck] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "valid": self.valid,
            "proof_type": self.proof_type,
            "proof_id": self.proof_id,
            "checks": [
                {
                    "name": c.name,
                    "passed": c.passed,
                    "message": c.message,
                    "details": c.details
                }
                for c in self.checks
            ],
            "errors": self.errors
        }


def verify_proof(proof: Dict[str, Any]) -> VerificationResult:
    """
    Verify a Nebula proof bundle.

    Performs all standard verification checks:
    1. Schema validation
    2. Canonical hash verification
    3. Signature verification
    4. Proof-type-specific checks

    Args:
        proof: Proof bundle dictionary

    Returns:
        VerificationResult with detailed check results
    """
    result = VerificationResult(
        valid=False,
        proof_type=proof.get("proof_type"),
        proof_id=proof.get("proof_id")
    )

    # 1. Schema validation
    schema_valid, schema_errors = validate_schema(proof)
    result.checks.append(VerificationCheck(
        name="schema",
        passed=schema_valid,
        message="Schema validation passed" if schema_valid else "Schema validation failed",
        details={"errors": [e.message for e in schema_errors]} if schema_errors else None
    ))

    if not schema_valid:
        result.errors.extend([e.message for e in schema_errors])
        return result

    # 2. Canonical hash verification
    hash_result = verify_canonical_hash(proof)
    result.checks.append(hash_result)

    if not hash_result.passed:
        result.errors.append(hash_result.message)
        return result

    # 3. Signature verification
    sig_result = verify_signature(proof)
    result.checks.append(sig_result)

    if not sig_result.passed:
        result.errors.append(sig_result.message)
        return result

    # 4. Proof-type-specific checks
    proof_type = proof.get("proof_type")

    if proof_type == ProofType.DELETION.value:
        compliance_checks = _verify_deletion_compliance(proof)
        result.checks.extend(compliance_checks)
        for check in compliance_checks:
            if not check.passed:
                result.errors.append(check.message)

    elif proof_type == ProofType.TRANSMISSION.value:
        transmission_checks = _verify_transmission_proof(proof)
        result.checks.extend(transmission_checks)
        for check in transmission_checks:
            if not check.passed:
                result.errors.append(check.message)

    # Final verdict
    result.valid = all(check.passed for check in result.checks)

    return result


def verify_canonical_hash(proof: Dict[str, Any]) -> VerificationCheck:
    """
    Verify the canonical hash matches the proof content.

    Args:
        proof: Proof bundle dictionary

    Returns:
        VerificationCheck result
    """
    signature_block = proof.get("signature", {})
    declared_hash = signature_block.get("canonical_hash", "")

    # Build content for hashing (exclude signature block)
    proof_for_hashing = {k: v for k, v in proof.items() if k != "signature"}
    canonical_bytes = canonical_json(proof_for_hashing)
    computed_hash = sha256_hex(canonical_bytes)

    if computed_hash == declared_hash:
        return VerificationCheck(
            name="canonical_hash",
            passed=True,
            message="Canonical hash verified",
            details={
                "hash": computed_hash[:32] + "...",
                "algorithm": "SHA-256",
                "canonicalization": "RFC 8785 (JCS)"
            }
        )
    else:
        return VerificationCheck(
            name="canonical_hash",
            passed=False,
            message="Canonical hash mismatch",
            details={
                "expected": declared_hash[:32] + "..." if declared_hash else None,
                "computed": computed_hash[:32] + "..."
            }
        )


def verify_signature(proof: Dict[str, Any]) -> VerificationCheck:
    """
    Verify the Ed25519 signature.

    Args:
        proof: Proof bundle dictionary

    Returns:
        VerificationCheck result
    """
    signature_block = proof.get("signature", {})

    # Get signature value (can be 'value' or 'signature')
    sig_value = signature_block.get("value") or signature_block.get("signature")
    public_key_b64 = signature_block.get("public_key")

    if not sig_value or not public_key_b64:
        return VerificationCheck(
            name="signature",
            passed=False,
            message="Missing signature or public key"
        )

    # Build canonical message
    proof_for_signing = {k: v for k, v in proof.items() if k != "signature"}
    canonical_bytes = canonical_json(proof_for_signing)

    # Decode public key
    try:
        public_key = base64.b64decode(public_key_b64)
    except Exception as e:
        return VerificationCheck(
            name="signature",
            passed=False,
            message=f"Invalid public key encoding: {e}"
        )

    # Verify signature
    try:
        is_valid = verify_ed25519(public_key, canonical_bytes, sig_value)

        if is_valid:
            return VerificationCheck(
                name="signature",
                passed=True,
                message="Ed25519 signature verified",
                details={
                    "algorithm": "Ed25519 (RFC 8032)",
                    "key_id": signature_block.get("key_id")
                }
            )
        else:
            return VerificationCheck(
                name="signature",
                passed=False,
                message="Ed25519 signature invalid"
            )
    except Exception as e:
        return VerificationCheck(
            name="signature",
            passed=False,
            message=f"Signature verification error: {e}"
        )


def verify_merkle_inclusion(
    proof: Dict[str, Any],
    leaf_hash: str,
    leaf_index: int
) -> VerificationCheck:
    """
    Verify Merkle tree inclusion proof.

    Recomputes the Merkle root from the leaf hash and inclusion proof,
    then compares against the declared root.

    Args:
        proof: Proof bundle dictionary
        leaf_hash: Hash of leaf to verify (hex string)
        leaf_index: Index of leaf in tree

    Returns:
        VerificationCheck result
    """
    merkle = proof.get("merkle", {})
    declared_root = merkle.get("root", "")
    inclusion_proof = merkle.get("inclusion_proof", [])

    if not declared_root:
        return VerificationCheck(
            name="merkle_inclusion",
            passed=False,
            message="Missing Merkle root"
        )

    if not leaf_hash:
        return VerificationCheck(
            name="merkle_inclusion",
            passed=False,
            message="Missing leaf hash for verification"
        )

    if not inclusion_proof:
        # Single leaf tree - leaf hash should equal root
        passed = leaf_hash == declared_root
        return VerificationCheck(
            name="merkle_inclusion",
            passed=passed,
            message="Single-leaf Merkle tree verified" if passed else "Leaf hash does not match root"
        )

    try:
        # Convert hex to bytes and walk up the tree
        current = bytes.fromhex(leaf_hash)
        index = leaf_index

        for sibling_hex in inclusion_proof:
            sibling = bytes.fromhex(sibling_hex)

            if index % 2 == 0:
                # Current is left child
                combined = current + sibling
            else:
                # Current is right child
                combined = sibling + current

            current = sha256(combined)
            index = index // 2

        # Compare computed root with declared root
        computed_root_hex = current.hex()
        passed = computed_root_hex == declared_root

        return VerificationCheck(
            name="merkle_inclusion",
            passed=passed,
            message="Merkle inclusion proof verified" if passed else "Merkle root mismatch - inclusion proof invalid",
            details={
                "declared_root": declared_root[:32] + "..." if len(declared_root) > 32 else declared_root,
                "computed_root": computed_root_hex[:32] + "...",
                "proof_length": len(inclusion_proof),
                "leaf_index": leaf_index
            }
        )
    except Exception as e:
        return VerificationCheck(
            name="merkle_inclusion",
            passed=False,
            message=f"Merkle verification error: {e}"
        )


def _verify_deletion_compliance(proof: Dict[str, Any]) -> List[VerificationCheck]:
    """Verify GDPR/compliance requirements for deletion proofs."""
    checks = []
    compliance = proof.get("compliance", {})

    # Check recovery_impossible
    recovery_impossible = compliance.get("recovery_impossible", False)
    checks.append(VerificationCheck(
        name="gdpr_recovery_impossible",
        passed=recovery_impossible,
        message="Data recovery impossible" if recovery_impossible else "recovery_impossible not confirmed",
        details={"gdpr_article": compliance.get("gdpr_article")}
    ))

    # Check sanitization standard
    sanitization = compliance.get("sanitization_standard")
    is_nist = sanitization == "NIST-SP-800-88-Rev1"
    checks.append(VerificationCheck(
        name="sanitization_standard",
        passed=is_nist,
        message=f"NIST SP 800-88 Rev.1 sanitization" if is_nist else f"Non-standard sanitization: {sanitization}",
        details={"standard": sanitization}
    ))

    # Check keys destroyed (if applicable)
    kms = proof.get("kms_attestation", {})
    if kms:
        keys_destroyed = kms.get("keys_destroyed", False)
        checks.append(VerificationCheck(
            name="keys_destroyed",
            passed=keys_destroyed,
            message="Encryption keys destroyed" if keys_destroyed else "Keys not confirmed destroyed"
        ))

    return checks


def _verify_transmission_proof(proof: Dict[str, Any]) -> List[VerificationCheck]:
    """Verify transmission proof specific requirements."""
    checks = []

    # Check dual-party attestation
    has_sender = "sender" in proof
    has_receiver = "receiver" in proof

    checks.append(VerificationCheck(
        name="dual_party_attestation",
        passed=has_sender and has_receiver,
        message="Dual-party attestation present" if (has_sender and has_receiver) else "Missing sender or receiver"
    ))

    # Check channel security
    channel = proof.get("channel", {})
    pfs = channel.get("perfect_forward_secrecy", False)

    checks.append(VerificationCheck(
        name="perfect_forward_secrecy",
        passed=pfs,
        message="Perfect Forward Secrecy enabled" if pfs else "PFS not enabled",
        details={"tls_version": channel.get("tls_version")}
    ))

    return checks
