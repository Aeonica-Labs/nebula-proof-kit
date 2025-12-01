"""
Schema Validation for Nebula Proofs

Validates proof bundles against the Nebula Proof Schema v1.
"""

from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import re


class ProofType(str, Enum):
    """Supported proof types."""
    BACKUP_INTEGRITY = "backup_integrity"
    DELETION = "deletion"
    RESIDENCY = "residency"
    TRANSMISSION = "transmission"
    RECONSTRUCTION = "reconstruction"


@dataclass
class ValidationError:
    """Schema validation error."""
    field: str
    message: str
    value: Any = None


def validate_schema(proof: Dict[str, Any]) -> Tuple[bool, List[ValidationError]]:
    """
    Validate proof bundle against Nebula Proof Schema v1.

    Args:
        proof: Proof bundle dictionary

    Returns:
        Tuple of (is_valid, list of errors)
    """
    errors = []

    # Required fields
    required_fields = ["proof_type", "proof_id", "timestamp", "signature"]
    for field in required_fields:
        if field not in proof:
            errors.append(ValidationError(
                field=field,
                message=f"Missing required field: {field}"
            ))

    if errors:
        return False, errors

    # Proof ID format (32-char hex)
    proof_id = proof.get("proof_id", "")
    if not re.match(r"^[a-f0-9]{32}$", proof_id):
        errors.append(ValidationError(
            field="proof_id",
            message="proof_id must be 32-character hex string",
            value=proof_id
        ))

    # Proof type validation
    proof_type = proof.get("proof_type", "")
    valid_types = [pt.value for pt in ProofType]
    if proof_type not in valid_types:
        errors.append(ValidationError(
            field="proof_type",
            message=f"Invalid proof_type. Must be one of: {valid_types}",
            value=proof_type
        ))

    # Timestamp format (RFC 3339)
    timestamp = proof.get("timestamp", "")
    rfc3339_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$"
    if not re.match(rfc3339_pattern, timestamp):
        errors.append(ValidationError(
            field="timestamp",
            message="timestamp must be RFC 3339 format",
            value=timestamp
        ))

    # Signature block validation
    signature = proof.get("signature", {})
    if not isinstance(signature, dict):
        errors.append(ValidationError(
            field="signature",
            message="signature must be an object"
        ))
    else:
        sig_required = ["public_key", "canonical_hash"]
        for field in sig_required:
            if field not in signature:
                errors.append(ValidationError(
                    field=f"signature.{field}",
                    message=f"Missing required field: signature.{field}"
                ))

        # Signature value can be under 'value' or 'signature'
        if "value" not in signature and "signature" not in signature:
            errors.append(ValidationError(
                field="signature.value",
                message="Missing signature value (expected 'value' or 'signature' field)"
            ))

        # Canonical hash format
        canonical_hash = signature.get("canonical_hash", "")
        if canonical_hash and not re.match(r"^[a-f0-9]{64}$", canonical_hash):
            errors.append(ValidationError(
                field="signature.canonical_hash",
                message="canonical_hash must be 64-character hex string",
                value=canonical_hash
            ))

    # Proof-type-specific validation
    if proof_type == ProofType.DELETION.value:
        errors.extend(_validate_deletion_proof(proof))
    elif proof_type == ProofType.TRANSMISSION.value:
        errors.extend(_validate_transmission_proof(proof))
    elif proof_type == ProofType.BACKUP_INTEGRITY.value:
        errors.extend(_validate_backup_proof(proof))

    return len(errors) == 0, errors


def _validate_deletion_proof(proof: Dict[str, Any]) -> List[ValidationError]:
    """Validate deletion proof specific fields."""
    errors = []

    compliance = proof.get("compliance", {})
    if not isinstance(compliance, dict):
        errors.append(ValidationError(
            field="compliance",
            message="Deletion proofs must have compliance object"
        ))
        return errors

    # GDPR deletion proofs should have recovery_impossible
    if "gdpr_article" in compliance:
        if compliance.get("gdpr_article") == "17":
            if "recovery_impossible" not in compliance:
                errors.append(ValidationError(
                    field="compliance.recovery_impossible",
                    message="GDPR Article 17 proofs must specify recovery_impossible"
                ))

    return errors


def _validate_transmission_proof(proof: Dict[str, Any]) -> List[ValidationError]:
    """Validate transmission proof specific fields."""
    errors = []

    # Must have sender and receiver
    if "sender" not in proof:
        errors.append(ValidationError(
            field="sender",
            message="Transmission proofs must have sender object"
        ))

    if "receiver" not in proof:
        errors.append(ValidationError(
            field="receiver",
            message="Transmission proofs must have receiver object"
        ))

    return errors


def _validate_backup_proof(proof: Dict[str, Any]) -> List[ValidationError]:
    """Validate backup integrity proof specific fields."""
    errors = []

    # Should have merkle or attestations
    if "merkle" not in proof and "attestations" not in proof:
        errors.append(ValidationError(
            field="merkle",
            message="Backup proofs should have merkle or attestations data"
        ))

    return errors
