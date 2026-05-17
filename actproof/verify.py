# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
End-to-end verification of actproof receipts.

The audit-facing module. Given a receipt, this module answers the question:
"is this an honest commitment to a manifest hash, made at the time the
receipt claims, anchored to the chain the receipt names, validated against
the catalogue the receipt pins?"

Six checks
----------

Each check is independent and produces a ``CheckResult`` with a name,
a status (PASS / FAIL / SKIP / ERROR), an optional diagnostic message,
and an elapsed-seconds measurement. Checks are run in a fixed order; the
orchestrator does NOT short-circuit on failure (so the caller sees the
full picture, not just the first thing that went wrong).

1. **receipt_profile_supported** - the ``receipt_profile`` field is one
   the verifier knows about. v1 verifiers accept ``actproof-jcs-v1``
   only; future v2 verifiers will additionally accept
   ``actproof-scitt-cose-v2``.

2. **manifest_hash_match** - recompute the canonical hash of
   ``receipt.manifest`` and compare to ``receipt.manifest_hash``.
   Catches manifest-substitution attacks. Always runs; needs no network.

3. **note_payload_reproducible** - check that the
   ``receipt.anchor.note_payload_b64`` decodes to the canonical JSON
   payload that ``build_note_payload(manifest_hash, batching_profile)``
   would produce for this receipt. Catches "the receipt's anchor record
   does not match what would actually be on-chain" mismatches. Always
   runs.

4. **catalogue_conformance** - run ``validate_manifest`` against a
   catalogue. Skipped if no catalogue is provided. The catalogue MUST be
   loaded at the git commit named in ``receipt.manifest.catalogue.git_commit``;
   the verifier does NOT fetch the catalogue automatically (that is the
   caller's responsibility, because git-commit fetching depends on the
   caller's environment).

5. **anchor_on_chain** - query an Algorand indexer for the transaction
   identified by ``receipt.anchor.txid``. Compare the on-chain note
   bytes to what the receipt claims they should be. Skipped if no
   indexer client is provided OR if the receipt is a draft (txid empty).

6. **timestamp_signature** - verify the RFC 3161 token's signature via
   ``tsp_client.TSPVerifier``. Confirms the token is well-formed and the
   imprint inside the token equals the receipt's ``manifest_hash``
   bytes. Skipped if ``tsp_client`` is not available.

What this module does NOT do
----------------------------

* **Does not fetch the catalogue.** Pass a pre-loaded ``Catalogue``. The
  ``receipt.manifest.catalogue.git_commit`` value tells you WHICH commit
  to load; loading itself depends on the caller's environment (network
  access, git installation, actproof-events checkout location).

* **Does not validate the TSA certificate chain against the EU Trusted
  List.** ``tsp_client.TSPVerifier`` validates the token structurally
  and checks signature self-consistency; it does NOT verify the TSA's
  cert chains up to a trust anchor in the EUTL or in any other
  jurisdiction's trust list. Full EUTL chain validation is a future
  enhancement (v0.2.x). Users needing legal-grade qualified timestamp
  proof should re-verify the token against their jurisdiction's trust
  list separately.

* **Does not check whether the issuer's address is one the verifier
  recognises.** The receipt records WHICH Algorand address signed the
  anchor transaction (via ``receipt.anchor`` - but actually it doesn't
  even record that directly; the sender is encoded in the transaction
  itself, retrievable from the indexer). Verifying that the signing
  address belongs to the named issuer is a trust-root concern outside
  the scope of this library. Operators establish that link via signed
  publication, address registries, or DNS TXT records.

* **Does not check transaction confirmation depth.** The receipt claims
  a block round; the indexer confirms the transaction is at that round.
  But Algorand blocks have very strong finality (1 round = ~3.3s and
  effectively final under non-byzantine conditions), so depth checking
  is overkill for normal use. Users with paranoid requirements can
  inspect ``receipt.anchor.block_round`` against ``algod_client.status()``
  themselves.

API
---

* ``verify_receipt(receipt, *, ...) -> VerificationResult``
* ``CheckResult`` - one check's outcome (name, status, detail, elapsed).
* ``CheckStatus`` - enum: PASS, FAIL, SKIP, ERROR.
* ``VerificationResult`` - bundle of (receipt, ok, checks).
* ``VerificationError`` - raised if a check encounters an unrecoverable
  setup problem (e.g. malformed receipt structure). Does NOT raise on a
  failed check; that's reported in the result.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from actproof.anchor import build_note_payload
from actproof.canonical import hash_canonical
from actproof.catalogue import (
    Catalogue,
    ValidationIssue,
    validate_manifest,
)
from actproof.manifest import (
    BATCHING_PROFILE_SINGLE,
    Manifest,
    RECEIPT_PROFILE_V1,
    hash_manifest_hex,
    manifest_to_dict,
)
from actproof.receipt import (
    ALGORAND_MAINNET,
    ALGORAND_TESTNET,
    ARC2_DAPP_NAME,
    ARC2_FORMAT_VERSION_JSON,
    ARC2_NOTE_FORMAT,
    Receipt,
)


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# OPTIONAL IMPORTS: tsp_client (for timestamp signature check) and
# algosdk indexer (for on-chain anchor check)
# ─────────────────────────────────────────────────────────────────

try:
    from actproof.timestamp import TSPVerifier as _TSPVerifier
    _TSP_VERIFIER_AVAILABLE: bool = True
except Exception:  # noqa: BLE001
    _TSP_VERIFIER_AVAILABLE = False
    _TSPVerifier = None  # type: ignore[assignment,misc]

try:
    from algosdk.v2client.indexer import IndexerClient
    _INDEXER_AVAILABLE: bool = True
    _INDEXER_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    _INDEXER_AVAILABLE = False
    _INDEXER_ERROR = str(exc)
    IndexerClient = None  # type: ignore[assignment,misc]


__all__ = [
    "verify_receipt",
    "CheckResult",
    "CheckStatus",
    "VerificationResult",
    "VerificationError",
    "DEFAULT_INDEXER_URL_MAINNET",
    "DEFAULT_INDEXER_URL_TESTNET",
    "SUPPORTED_RECEIPT_PROFILES",
]


# ─────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────

DEFAULT_INDEXER_URL_MAINNET: str = "https://mainnet-idx.algonode.cloud"
"""Default Algorand mainnet indexer endpoint (Algonode, free)."""

DEFAULT_INDEXER_URL_TESTNET: str = "https://testnet-idx.algonode.cloud"
"""Default Algorand testnet indexer endpoint (Algonode, free)."""

SUPPORTED_RECEIPT_PROFILES: frozenset[str] = frozenset({RECEIPT_PROFILE_V1})
"""Receipt profiles this verifier knows how to parse. v1 verifier accepts
``actproof-jcs-v1`` only. A future v2 verifier will additionally accept
``actproof-scitt-cose-v2``."""


# ─────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────

class VerificationError(RuntimeError):
    """Raised when verification cannot proceed due to a structural problem.

    Not raised for failed checks (those are reported as FAIL in the result).
    Raised only when the verifier cannot even attempt the checks, e.g.
    if the receipt is so malformed that no checks make sense.
    """


# ─────────────────────────────────────────────────────────────────
# RESULT TYPES
# ─────────────────────────────────────────────────────────────────

class CheckStatus(str, Enum):
    """The outcome of a single verification check."""
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass(frozen=True)
class CheckResult:
    """The outcome of a single verification check.

    Attributes:
        name: Stable check identifier. One of: ``receipt_profile_supported``,
            ``manifest_hash_match``, ``note_payload_reproducible``,
            ``catalogue_conformance``, ``anchor_on_chain``,
            ``timestamp_signature``.
        status: ``CheckStatus.PASS``, ``FAIL``, ``SKIP``, or ``ERROR``.
        detail: Human-readable diagnostic. ``None`` for trivial passes;
            present on FAIL, SKIP, and ERROR to explain what happened.
        elapsed_seconds: Wall-clock time spent on the check.
    """
    name: str
    status: CheckStatus
    detail: Optional[str] = None
    elapsed_seconds: Optional[float] = None

    @property
    def ok(self) -> bool:
        """``True`` if status is PASS or SKIP (no failure)."""
        return self.status in (CheckStatus.PASS, CheckStatus.SKIP)

    @property
    def failed(self) -> bool:
        """``True`` if status is FAIL or ERROR."""
        return self.status in (CheckStatus.FAIL, CheckStatus.ERROR)


@dataclass(frozen=True)
class VerificationResult:
    """End-to-end verification outcome.

    Attributes:
        receipt: The receipt that was verified.
        checks: Tuple of per-check ``CheckResult`` in execution order.
        ok: ``True`` if every check is PASS or SKIP. ``False`` if any
            check is FAIL or ERROR.
    """
    receipt: Receipt
    checks: tuple[CheckResult, ...]
    ok: bool

    def failed_checks(self) -> tuple[CheckResult, ...]:
        """Subset of checks with status FAIL or ERROR."""
        return tuple(c for c in self.checks if c.failed)

    def get_check(self, name: str) -> Optional[CheckResult]:
        """Find a check by name, or None if not present."""
        for c in self.checks:
            if c.name == name:
                return c
        return None


# ─────────────────────────────────────────────────────────────────
# INDIVIDUAL CHECKS
# ─────────────────────────────────────────────────────────────────

def _check_receipt_profile(receipt: Receipt) -> CheckResult:
    """Confirm the receipt_profile is one this verifier supports."""
    started = time.monotonic()
    profile = receipt.receipt_profile
    if profile not in SUPPORTED_RECEIPT_PROFILES:
        return CheckResult(
            name="receipt_profile_supported",
            status=CheckStatus.FAIL,
            detail=(
                f"Unsupported receipt_profile {profile!r}. This verifier "
                f"supports: {sorted(SUPPORTED_RECEIPT_PROFILES)}."
            ),
            elapsed_seconds=time.monotonic() - started,
        )
    return CheckResult(
        name="receipt_profile_supported",
        status=CheckStatus.PASS,
        elapsed_seconds=time.monotonic() - started,
    )


def _check_manifest_hash(receipt: Receipt) -> CheckResult:
    """Recompute the canonical hash of receipt.manifest and compare."""
    started = time.monotonic()
    try:
        recomputed_hex = hash_manifest_hex(receipt.manifest)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="manifest_hash_match",
            status=CheckStatus.ERROR,
            detail=f"Hash recomputation raised: {exc}",
            elapsed_seconds=time.monotonic() - started,
        )

    expected = f"sha256:{recomputed_hex}"
    if receipt.manifest_hash != expected:
        return CheckResult(
            name="manifest_hash_match",
            status=CheckStatus.FAIL,
            detail=(
                f"Receipt declares manifest_hash={receipt.manifest_hash!r} "
                f"but recomputed canonical hash is {expected!r}. The "
                f"manifest may have been tampered with after issuance."
            ),
            elapsed_seconds=time.monotonic() - started,
        )
    return CheckResult(
        name="manifest_hash_match",
        status=CheckStatus.PASS,
        elapsed_seconds=time.monotonic() - started,
    )


def _check_note_payload_reproducible(receipt: Receipt) -> CheckResult:
    """Check that the receipt's on-chain note payload can be rebuilt
    deterministically from manifest_hash + batching_profile."""
    started = time.monotonic()
    try:
        # Strip the "sha256:" prefix to get raw hex.
        hex_part = receipt.manifest_hash
        if hex_part.startswith("sha256:"):
            hex_part = hex_part[len("sha256:"):]
        manifest_hash_bytes = bytes.fromhex(hex_part)

        # Reconstruct the canonical payload bytes.
        expected_payload = build_note_payload(
            manifest_hash_bytes,
            batching_profile=receipt.batching_profile,
        )
        expected_b64 = base64.b64encode(expected_payload).decode("ascii")

        actual_b64 = receipt.anchor.note_payload_b64
        if actual_b64 != expected_b64:
            return CheckResult(
                name="note_payload_reproducible",
                status=CheckStatus.FAIL,
                detail=(
                    f"Receipt anchor.note_payload_b64 does not match "
                    f"what build_note_payload(manifest_hash) would produce. "
                    f"Receipt says payload encodes a different hash, "
                    f"profile, or version than the manifest implies."
                ),
                elapsed_seconds=time.monotonic() - started,
            )
        return CheckResult(
            name="note_payload_reproducible",
            status=CheckStatus.PASS,
            elapsed_seconds=time.monotonic() - started,
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="note_payload_reproducible",
            status=CheckStatus.ERROR,
            detail=f"Reconstruction raised: {exc}",
            elapsed_seconds=time.monotonic() - started,
        )


def _check_catalogue_conformance(
    receipt: Receipt,
    catalogue: Optional[Catalogue],
) -> CheckResult:
    """Run validate_manifest against the catalogue, if one is provided."""
    started = time.monotonic()
    if catalogue is None:
        return CheckResult(
            name="catalogue_conformance",
            status=CheckStatus.SKIP,
            detail=(
                "No catalogue provided. Pass catalogue=Catalogue(...) to "
                "actproof.verify_receipt() to enable this check. The "
                "catalogue must be loaded at the git commit named in "
                "receipt.manifest.catalogue.git_commit."
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    try:
        issues = validate_manifest(receipt.manifest, catalogue)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="catalogue_conformance",
            status=CheckStatus.ERROR,
            detail=f"validate_manifest raised: {exc}",
            elapsed_seconds=time.monotonic() - started,
        )

    if issues:
        codes = ", ".join(sorted({i.code for i in issues}))
        return CheckResult(
            name="catalogue_conformance",
            status=CheckStatus.FAIL,
            detail=(
                f"Manifest failed catalogue validation. "
                f"{len(issues)} issue(s) found with codes: {codes}. "
                f"First issue: {issues[0].message}"
            ),
            elapsed_seconds=time.monotonic() - started,
        )
    return CheckResult(
        name="catalogue_conformance",
        status=CheckStatus.PASS,
        elapsed_seconds=time.monotonic() - started,
    )


def _build_default_indexer_client(network: str) -> Any:
    """Construct an IndexerClient for the given network identifier."""
    if not _INDEXER_AVAILABLE:
        raise VerificationError(
            f"py-algorand-sdk indexer not available: {_INDEXER_ERROR}"
        )
    if network == ALGORAND_MAINNET:
        url = DEFAULT_INDEXER_URL_MAINNET
    elif network == ALGORAND_TESTNET:
        url = DEFAULT_INDEXER_URL_TESTNET
    else:
        # Betanet or custom; user must pass their own client.
        raise VerificationError(
            f"No default indexer for network {network!r}. "
            f"Pass indexer_client=IndexerClient(...) explicitly."
        )
    return IndexerClient("", url)


def _check_anchor_on_chain(
    receipt: Receipt,
    indexer_client: Optional[Any],
) -> CheckResult:
    """Query the Algorand indexer for the transaction; compare note bytes."""
    started = time.monotonic()

    # Skip if the receipt is a draft (no txid).
    if not receipt.anchor.txid:
        return CheckResult(
            name="anchor_on_chain",
            status=CheckStatus.SKIP,
            detail=(
                "Receipt is a draft (anchor.txid is empty). The manifest "
                "was prepared but not submitted to the chain."
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    # Get or build an indexer client.
    if indexer_client is None:
        try:
            indexer_client = _build_default_indexer_client(receipt.anchor.network)
        except VerificationError as exc:
            return CheckResult(
                name="anchor_on_chain",
                status=CheckStatus.SKIP,
                detail=str(exc),
                elapsed_seconds=time.monotonic() - started,
            )

    # Query the transaction.
    try:
        response = indexer_client.transaction(receipt.anchor.txid)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="anchor_on_chain",
            status=CheckStatus.ERROR,
            detail=(
                f"Indexer transaction lookup failed for "
                f"{receipt.anchor.txid}: {exc}"
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    # Extract the transaction's note field. Indexer returns note as base64.
    txn = response.get("transaction", {})
    on_chain_note_b64 = txn.get("note", "")
    if not on_chain_note_b64:
        return CheckResult(
            name="anchor_on_chain",
            status=CheckStatus.FAIL,
            detail=(
                f"Transaction {receipt.anchor.txid} exists but has no "
                f"note field. The transaction is not an actproof anchor."
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    try:
        on_chain_note_bytes = base64.b64decode(on_chain_note_b64)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="anchor_on_chain",
            status=CheckStatus.ERROR,
            detail=f"Cannot decode on-chain note bytes: {exc}",
            elapsed_seconds=time.monotonic() - started,
        )

    # Strip the ARC-2 prefix and compare to the receipt's note_payload_b64.
    expected_prefix = (
        f"{ARC2_DAPP_NAME}:{ARC2_FORMAT_VERSION_JSON}"
    ).encode("ascii")
    if not on_chain_note_bytes.startswith(expected_prefix):
        return CheckResult(
            name="anchor_on_chain",
            status=CheckStatus.FAIL,
            detail=(
                f"On-chain note does not start with the actproof ARC-2 "
                f"prefix {expected_prefix!r}. Got prefix "
                f"{on_chain_note_bytes[:32]!r}."
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    on_chain_payload = on_chain_note_bytes[len(expected_prefix):]
    on_chain_payload_b64 = base64.b64encode(on_chain_payload).decode("ascii")

    if on_chain_payload_b64 != receipt.anchor.note_payload_b64:
        return CheckResult(
            name="anchor_on_chain",
            status=CheckStatus.FAIL,
            detail=(
                f"On-chain note payload does NOT match the receipt's "
                f"declared payload. The receipt's anchor record disagrees "
                f"with what is actually on-chain."
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    return CheckResult(
        name="anchor_on_chain",
        status=CheckStatus.PASS,
        elapsed_seconds=time.monotonic() - started,
    )


def _check_timestamp_signature(receipt: Receipt) -> CheckResult:
    """Verify the RFC 3161 token's signature and imprint."""
    started = time.monotonic()
    if not _TSP_VERIFIER_AVAILABLE:
        return CheckResult(
            name="timestamp_signature",
            status=CheckStatus.SKIP,
            detail=(
                "tsp_client is not available (transitive dependency "
                "conflict; see actproof.timestamp for details). Install "
                "or repair tsp-client to enable this check."
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    # Decode the token bytes and the expected imprint.
    try:
        token_bytes = base64.b64decode(receipt.trusted_timestamp.token_b64)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="timestamp_signature",
            status=CheckStatus.ERROR,
            detail=f"Cannot base64-decode token: {exc}",
            elapsed_seconds=time.monotonic() - started,
        )

    try:
        hex_part = receipt.manifest_hash
        if hex_part.startswith("sha256:"):
            hex_part = hex_part[len("sha256:"):]
        expected_imprint = bytes.fromhex(hex_part)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="timestamp_signature",
            status=CheckStatus.ERROR,
            detail=f"Cannot decode manifest_hash hex: {exc}",
            elapsed_seconds=time.monotonic() - started,
        )

    # Verify the token via tsp_client.
    try:
        verifier = _TSPVerifier()
        verifier.verify(token_bytes, message_digest=expected_imprint)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="timestamp_signature",
            status=CheckStatus.FAIL,
            detail=(
                f"RFC 3161 token verification failed: {exc}. The token "
                f"is malformed, the signature is invalid, or the imprint "
                f"inside the token does not match the receipt's "
                f"manifest_hash."
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    return CheckResult(
        name="timestamp_signature",
        status=CheckStatus.PASS,
        elapsed_seconds=time.monotonic() - started,
    )


# ─────────────────────────────────────────────────────────────────
# PUBLIC ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────

def verify_receipt(
    receipt: Receipt,
    *,
    catalogue: Optional[Catalogue] = None,
    indexer_client: Optional[Any] = None,
    skip_anchor_check: bool = False,
    skip_timestamp_check: bool = False,
    skip_catalogue_check: bool = False,
) -> VerificationResult:
    """Verify a receipt end-to-end.

    Runs the six checks in order, collecting all results. Does NOT short-
    circuit on a failed check; the caller sees the full breakdown.

    Args:
        receipt: The receipt to verify.
        catalogue: Optional pre-loaded ``Catalogue``. If ``None`` (or
            ``skip_catalogue_check=True``), the catalogue_conformance check
            is skipped. The caller is responsible for loading the catalogue
            at the git commit named in ``receipt.manifest.catalogue.git_commit``.
        indexer_client: Optional ``algosdk.v2client.indexer.IndexerClient``.
            If ``None``, a default Algonode public indexer is used based on
            the receipt's ``network`` field. If the receipt is a draft
            (no txid), the on-chain check is skipped regardless.
        skip_anchor_check: Explicitly skip the on-chain anchor check.
        skip_timestamp_check: Explicitly skip the timestamp signature check.
        skip_catalogue_check: Explicitly skip the catalogue conformance
            check (alternative to passing ``catalogue=None``).

    Returns:
        ``VerificationResult`` with per-check status and an overall ``ok``.

    Raises:
        VerificationError: Only for unrecoverable structural issues; failed
            checks are reported in the result, never raised.
    """
    checks: list[CheckResult] = []

    checks.append(_check_receipt_profile(receipt))
    checks.append(_check_manifest_hash(receipt))
    checks.append(_check_note_payload_reproducible(receipt))

    if skip_catalogue_check:
        checks.append(CheckResult(
            name="catalogue_conformance",
            status=CheckStatus.SKIP,
            detail="Explicitly skipped via skip_catalogue_check=True.",
        ))
    else:
        checks.append(_check_catalogue_conformance(receipt, catalogue))

    if skip_anchor_check:
        checks.append(CheckResult(
            name="anchor_on_chain",
            status=CheckStatus.SKIP,
            detail="Explicitly skipped via skip_anchor_check=True.",
        ))
    else:
        checks.append(_check_anchor_on_chain(receipt, indexer_client))

    if skip_timestamp_check:
        checks.append(CheckResult(
            name="timestamp_signature",
            status=CheckStatus.SKIP,
            detail="Explicitly skipped via skip_timestamp_check=True.",
        ))
    else:
        checks.append(_check_timestamp_signature(receipt))

    ok = all(c.ok for c in checks)
    return VerificationResult(
        receipt=receipt,
        checks=tuple(checks),
        ok=ok,
    )
