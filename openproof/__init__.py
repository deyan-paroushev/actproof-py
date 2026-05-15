# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
openproof: anchor signed JSON manifests; verify anyone's anchored receipts.
"""

from __future__ import annotations

__version__ = "0.1.0"


# ─────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────

# v0.0.2: canonical.py
from openproof.canonical import (
    CanonicalizationError,
    IJSON_MAX_SAFE_INT,
    IJSON_MIN_SAFE_INT,
    canonicalize,
    canonicalize_from_json,
    canonicalize_str,
    hash_canonical,
    hash_canonical_hex,
)

# v0.0.3: manifest.py
from openproof.manifest import (
    BATCHING_PROFILE_SINGLE,
    RECEIPT_PROFILE_V1,
    CatalogueBinding,
    Evidence,
    Issuer,
    Manifest,
    ManifestValidationError,
    Recipient,
    build_manifest,
    hash_email,
    hash_file_bytes,
    hash_json_bytes,
    hash_manifest,
    hash_manifest_hex,
    manifest_from_dict,
    manifest_to_dict,
    normalize_email,
    validate_manifest_shape,
)

# v0.0.4: catalogue.py
from openproof.catalogue import (
    ENV_CATALOGUE_PATH,
    SCHEMA_DISCRIMINATOR,
    Catalogue,
    CatalogueEntry,
    CatalogueLoadError,
    RegulatoryCitation,
    SignaturePolicy,
    ValidationIssue,
    hash_entry_file,
    hash_schema_file,
    load_catalogue,
    validate_manifest,
)

# v0.0.5: receipt.py
from openproof.receipt import (
    ALGORAND_BETANET,
    ALGORAND_MAINNET,
    ALGORAND_TESTNET,
    ARC2_DAPP_NAME,
    ARC2_FORMAT_VERSION_JSON,
    ARC2_NOTE_FORMAT,
    AnchorRecord,
    IssuerEvidence,
    PlaintextRecipient,
    Receipt,
    ReceiptError,
    TimestampToken,
    build_issuer_evidence,
    build_receipt,
    issuer_evidence_from_dict,
    issuer_evidence_to_dict,
    read_issuer_evidence,
    read_receipt,
    receipt_from_dict,
    receipt_to_dict,
    write_issuer_evidence,
    write_receipt,
)

# v0.0.6: timestamp.py
from openproof.timestamp import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TSA_CHAIN,
    SUPPORTED_HASH_ALGORITHMS,
    AcquisitionResult,
    TimestampAuthority,
    TimestampError,
    TSAAttempt,
    acquire_timestamp_token,
)

# v0.0.7: anchor.py
from openproof.anchor import (
    ALGORAND_NOTE_MAX_BYTES,
    DEFAULT_ALGOD_URL_MAINNET,
    DEFAULT_ALGOD_URL_TESTNET,
    DEFAULT_CONFIRMATION_TIMEOUT_SECONDS,
    NOTE_VERSION,
    AnchorError,
    AnchorMode,
    Signer,
    anchor_manifest,
    build_note_bytes,
    build_note_payload,
    build_transaction,
)

# v0.0.8: signers/
from openproof.signers import (
    FORBIDDEN_METHOD_NAMES,
    AlgorandSigner,
    GoogleKMSSigner,
    MnemonicSigner,
    SignerValidationError,
)

# v0.0.9: verify.py
from openproof.verify import (
    DEFAULT_INDEXER_URL_MAINNET,
    DEFAULT_INDEXER_URL_TESTNET,
    SUPPORTED_RECEIPT_PROFILES,
    CheckResult,
    CheckStatus,
    VerificationError,
    VerificationResult,
    verify_receipt,
)


__all__ = [
    "__version__",
    # canonical.py (v0.0.2)
    "canonicalize", "canonicalize_str", "canonicalize_from_json",
    "hash_canonical", "hash_canonical_hex",
    "CanonicalizationError", "IJSON_MAX_SAFE_INT", "IJSON_MIN_SAFE_INT",
    # manifest.py (v0.0.3)
    "Manifest", "CatalogueBinding", "Issuer", "Evidence", "Recipient",
    "build_manifest", "manifest_to_dict", "manifest_from_dict",
    "hash_manifest", "hash_manifest_hex",
    "normalize_email", "hash_email", "hash_file_bytes", "hash_json_bytes",
    "validate_manifest_shape", "ManifestValidationError",
    "RECEIPT_PROFILE_V1", "BATCHING_PROFILE_SINGLE",
    # catalogue.py (v0.0.4)
    "Catalogue", "CatalogueEntry", "RegulatoryCitation", "SignaturePolicy",
    "ValidationIssue", "CatalogueLoadError",
    "load_catalogue", "validate_manifest",
    "hash_entry_file", "hash_schema_file",
    "SCHEMA_DISCRIMINATOR", "ENV_CATALOGUE_PATH",
    # receipt.py (v0.0.5)
    "AnchorRecord", "TimestampToken", "Receipt",
    "PlaintextRecipient", "IssuerEvidence", "ReceiptError",
    "build_receipt", "build_issuer_evidence",
    "receipt_to_dict", "receipt_from_dict",
    "read_receipt", "write_receipt",
    "issuer_evidence_to_dict", "issuer_evidence_from_dict",
    "read_issuer_evidence", "write_issuer_evidence",
    "ALGORAND_MAINNET", "ALGORAND_TESTNET", "ALGORAND_BETANET",
    "ARC2_NOTE_FORMAT", "ARC2_DAPP_NAME", "ARC2_FORMAT_VERSION_JSON",
    # timestamp.py (v0.0.6)
    "TimestampAuthority", "TSAAttempt", "AcquisitionResult",
    "TimestampError", "acquire_timestamp_token",
    "DEFAULT_TSA_CHAIN", "DEFAULT_TIMEOUT_SECONDS",
    "SUPPORTED_HASH_ALGORITHMS",
    # anchor.py (v0.0.7)
    "AnchorMode", "Signer", "AnchorError",
    "anchor_manifest",
    "build_note_payload", "build_note_bytes", "build_transaction",
    "DEFAULT_ALGOD_URL_MAINNET", "DEFAULT_ALGOD_URL_TESTNET",
    "DEFAULT_CONFIRMATION_TIMEOUT_SECONDS",
    "ALGORAND_NOTE_MAX_BYTES", "NOTE_VERSION",
    # signers/ (v0.0.8)
    "AlgorandSigner", "MnemonicSigner", "GoogleKMSSigner",
    "FORBIDDEN_METHOD_NAMES", "SignerValidationError",
    # verify.py (v0.0.9)
    "verify_receipt", "CheckResult", "CheckStatus",
    "VerificationResult", "VerificationError",
    "DEFAULT_INDEXER_URL_MAINNET", "DEFAULT_INDEXER_URL_TESTNET",
    "SUPPORTED_RECEIPT_PROFILES",
]


# ─────────────────────────────────────────────────────────────────
# v0.1.0: All planned v0.x public API has landed. v0.2.0 adds docs and
# the GitHub Action wrapper. v0.3.0 adds the conformance test suite.
# v1.0.0 freezes the API.
# ─────────────────────────────────────────────────────────────────

_PLACEHOLDERS: dict[str, str] = {}


def __getattr__(name: str) -> None:
    if name in _PLACEHOLDERS:
        raise NotImplementedError(
            f"openproof.{name} is part of the planned public API but is not "
            f"yet implemented in this release ({__version__}). "
            f"It {_PLACEHOLDERS[name]}. "
            f"See https://github.com/deyan-paroushev/openproof-py/blob/main/CHANGELOG.md"
        )
    raise AttributeError(f"module 'openproof' has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(_PLACEHOLDERS.keys()))
