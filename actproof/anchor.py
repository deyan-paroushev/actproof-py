# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Anchor a manifest hash to the Algorand ledger via an ARC-2 disclosed-mode note.

This is the module that touches money. Each call to ``anchor_manifest`` (in
production mode) submits a real, signed, 0-Algo self-payment transaction to
mainnet. The transaction carries a small JSON note containing the
``manifest_hash``; that note plus its txid and confirmation round are the
on-chain commitment.

Three modes per the architectural review
----------------------------------------

* ``AnchorMode.DRAFT`` - build the note bytes and the Algorand transaction
  object, do NOT sign, do NOT submit. Returns an ``AnchorRecord`` with
  ``txid=""`` and ``block_round=None``. Useful for previewing what will go
  on-chain, for offline test workflows, and for CI smoke tests that should
  never burn real Algos.
* ``AnchorMode.DEMO`` - sign and submit to **testnet**. Real transaction,
  real confirmation, but on the test network where transaction fees are
  paid in test Algos. Used for end-to-end staging tests, integration suites,
  partner demos.
* ``AnchorMode.PRODUCTION`` - sign and submit to **mainnet**. Real
  transaction with non-zero economic value (the 1000-microAlgo fee, plus
  the durability cost of permanent ledger storage).

The mode is an explicit argument with no default. Callers must say which
network they want. There is no "if I don't say anything, please submit to
mainnet."

ARC-2 disclosed-mode note format
--------------------------------

The on-chain note is::

    actproof:j{"h":"<hex>","t":"<batching_profile>","v":1}

After the ``actproof:j`` ARC-2 prefix, the payload is RFC 8785 canonical
JSON with three short fields:

* ``"h"`` - the manifest_hash as lowercase hex (no ``"sha256:"`` prefix to
  keep size minimal; the algorithm is implied by length and by ARC-2 dapp
  name actproof always using SHA-256 in v1).
* ``"t"`` - the batching profile (``"single_attestation_anchor_v1"`` in v1).
* ``"v"`` - the format version (``1``).

Total bytes well under the 1000-byte Algorand note limit (about 125 bytes
for SHA-256, leaving plenty of headroom for future formats).

Signer abstraction
------------------

This module defines a ``Signer`` Protocol with two operations: ``address``
(the Algorand address being anchored from) and ``sign_transaction(txn)``
(sign a built ``Transaction``, return a ``SignedTransaction``). Concrete
implementations land in v0.0.8 (``actproof.signers``): ``KMSSigner`` for
AWS KMS production use, ``MnemonicSigner`` for testing only. The Protocol
deliberately exposes ONLY transaction signing; concrete classes enforce
the discipline that the underlying key never signs arbitrary bytes.

API
---

* ``anchor_manifest(manifest_hash, *, signer, mode, ...) -> AnchorRecord``
* ``build_note_payload(manifest_hash, batching_profile) -> bytes``
* ``build_note_bytes(manifest_hash, batching_profile) -> bytes``
* ``build_transaction(manifest_hash, *, signer_address, suggested_params,
  batching_profile) -> PaymentTxn``
* ``AnchorMode`` - the three-mode enum.
* ``Signer`` - the signer Protocol.
* ``AnchorError`` - raised on submission or confirmation problems.
* Constants: ``DEFAULT_ALGOD_URL_MAINNET``, ``DEFAULT_ALGOD_URL_TESTNET``,
  ``DEFAULT_CONFIRMATION_TIMEOUT_SECONDS``, ``ALGORAND_NOTE_MAX_BYTES``,
  ``NOTE_VERSION``.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable

from actproof.canonical import canonicalize
from actproof.manifest import BATCHING_PROFILE_SINGLE
from actproof.receipt import (
    ALGORAND_MAINNET,
    ALGORAND_TESTNET,
    ARC2_DAPP_NAME,
    ARC2_FORMAT_VERSION_JSON,
    ARC2_NOTE_FORMAT,
    AnchorRecord,
)


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# OPTIONAL IMPORT: py-algorand-sdk
# ─────────────────────────────────────────────────────────────────

try:
    from algosdk import transaction as _algo_txn
    from algosdk.v2client.algod import AlgodClient
    _ALGOSDK_AVAILABLE: bool = True
    _ALGOSDK_ERROR: Optional[str] = None
    PaymentTxn = _algo_txn.PaymentTxn
    SignedTransaction = _algo_txn.SignedTransaction
    SuggestedParams = _algo_txn.SuggestedParams
    Transaction = _algo_txn.Transaction
except Exception as exc:  # noqa: BLE001
    # py-algorand-sdk is a hard dependency; mirror the timestamp.py pattern
    # of staying importable even if a transitive conflict (e.g. msgpack,
    # cryptography, websockets) breaks the loader. Failures surface at
    # call time.
    _ALGOSDK_AVAILABLE = False
    _ALGOSDK_ERROR = str(exc)
    PaymentTxn = None  # type: ignore[assignment,misc]
    SignedTransaction = None  # type: ignore[assignment,misc]
    SuggestedParams = None  # type: ignore[assignment,misc]
    Transaction = None  # type: ignore[assignment,misc]
    AlgodClient = None  # type: ignore[assignment,misc]


__all__ = [
    "AnchorMode",
    "AnchorError",
    "Signer",
    "anchor_manifest",
    "build_note_payload",
    "build_note_bytes",
    "build_transaction",
    "DEFAULT_ALGOD_URL_MAINNET",
    "DEFAULT_ALGOD_URL_TESTNET",
    "DEFAULT_CONFIRMATION_TIMEOUT_SECONDS",
    "ALGORAND_NOTE_MAX_BYTES",
    "NOTE_VERSION",
]


# ─────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────

DEFAULT_ALGOD_URL_MAINNET: str = "https://mainnet-api.algonode.cloud"
"""Default public algod endpoint for mainnet (Algonode, free)."""

DEFAULT_ALGOD_URL_TESTNET: str = "https://testnet-api.algonode.cloud"
"""Default public algod endpoint for testnet (Algonode, free)."""

DEFAULT_CONFIRMATION_TIMEOUT_SECONDS: float = 60.0
"""Default time to wait for a transaction to confirm on-chain (Algorand
blocks are ~3.3 seconds; 60s covers roughly 18 rounds)."""

ALGORAND_NOTE_MAX_BYTES: int = 1000
"""Algorand transaction note max size in bytes (protocol limit)."""

NOTE_VERSION: int = 1
"""Note format version. Increment when the ``h``/``t``/``v`` payload
structure changes (would require coordinated rollout of verifiers)."""

_ARC2_PREFIX: bytes = b"actproof:j"
"""ARC-2 note prefix: dapp_name + ':' + format_version."""


# ─────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────

class AnchorError(RuntimeError):
    """Raised on submission, signing, or confirmation problems.

    Subclass of ``RuntimeError`` rather than ``ValueError`` because the
    typical failure mode here is operational (network down, signer
    unavailable, confirmation timed out) rather than input-validation.
    """


# ─────────────────────────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────────────────────────

class AnchorMode(str, Enum):
    """Three operational modes for ``anchor_manifest``.

    * ``DRAFT`` - build the transaction without signing or submitting.
      Returns an ``AnchorRecord`` with ``txid=""`` and ``block_round=None``.
      Network defaults to testnet for the recorded ``network`` field.
    * ``DEMO`` - sign and submit to **testnet**.
    * ``PRODUCTION`` - sign and submit to **mainnet**.
    """
    DRAFT = "draft"
    DEMO = "demo"
    PRODUCTION = "production"


# ─────────────────────────────────────────────────────────────────
# SIGNER PROTOCOL
# ─────────────────────────────────────────────────────────────────

@runtime_checkable
class Signer(Protocol):
    """Sign Algorand transactions. Implementations land in v0.0.8.

    Concrete implementations in ``actproof.signers``:

    * ``KMSSigner`` - AWS KMS-backed Ed25519 signing for production.
    * ``MnemonicSigner`` - mnemonic-based local signing for testing only.

    Defense-in-depth note: implementations should sign ONLY Algorand
    transactions, never arbitrary bytes. The Protocol enforces this
    structurally (it only exposes ``sign_transaction``); the v0.0.8
    abstract base class additionally enforces it at class-definition
    time via ``__init_subclass__``.

    Attributes:
        address: The signer's 58-character base32 Algorand address.

    Methods:
        sign_transaction(txn): Sign a built ``Transaction``, return a
            ``SignedTransaction``.
    """

    @property
    def address(self) -> str:
        """The signer's 58-character base32 Algorand address."""
        ...

    def sign_transaction(self, txn: Any) -> Any:
        """Sign an Algorand transaction. Returns a ``SignedTransaction``.

        Args:
            txn: An ``algosdk.transaction.Transaction`` (typically a
                ``PaymentTxn``).

        Returns:
            An ``algosdk.transaction.SignedTransaction``.
        """
        ...


# ─────────────────────────────────────────────────────────────────
# NOTE CONSTRUCTION
# ─────────────────────────────────────────────────────────────────

def build_note_payload(
    manifest_hash: bytes,
    batching_profile: str = BATCHING_PROFILE_SINGLE,
) -> bytes:
    """Build the ARC-2 disclosed-mode note payload bytes (without prefix).

    The payload is RFC 8785 canonical JSON with three short fields:
    ``h`` (manifest hash hex), ``t`` (batching profile), ``v`` (version).

    Args:
        manifest_hash: Raw bytes of the manifest hash. Typically 32 bytes
            for SHA-256.
        batching_profile: The batching profile identifier. Defaults to
            ``"single_attestation_anchor_v1"`` (v1).

    Returns:
        Canonical JSON payload as UTF-8 bytes. To get the full note bytes,
        prepend ``actproof:j``.
    """
    payload_dict = {
        "h": manifest_hash.hex(),
        "t": batching_profile,
        "v": NOTE_VERSION,
    }
    # RFC 8785 sorts keys alphabetically; payload becomes h, t, v.
    return canonicalize(payload_dict)


def build_note_bytes(
    manifest_hash: bytes,
    batching_profile: str = BATCHING_PROFILE_SINGLE,
) -> bytes:
    """Build the full on-chain note bytes, including the ARC-2 prefix.

    Args:
        manifest_hash: Raw bytes of the manifest hash.
        batching_profile: The batching profile identifier.

    Returns:
        Note bytes: ``b"actproof:j" + canonical_payload_bytes``. Goes
        directly into the ``note`` field of an Algorand transaction.

    Raises:
        AnchorError: If the resulting note exceeds the Algorand 1000-byte
            note limit (this should not happen for sensible inputs).
    """
    payload = build_note_payload(manifest_hash, batching_profile)
    note_bytes = _ARC2_PREFIX + payload
    if len(note_bytes) > ALGORAND_NOTE_MAX_BYTES:
        raise AnchorError(
            f"Note size {len(note_bytes)} bytes exceeds Algorand limit "
            f"{ALGORAND_NOTE_MAX_BYTES} bytes. This should not happen for "
            f"a SHA-256 single-attestation anchor; check the batching "
            f"profile string length."
        )
    return note_bytes


# ─────────────────────────────────────────────────────────────────
# TRANSACTION CONSTRUCTION
# ─────────────────────────────────────────────────────────────────

def build_transaction(
    manifest_hash: bytes,
    *,
    signer_address: str,
    suggested_params: Any,
    batching_profile: str = BATCHING_PROFILE_SINGLE,
) -> Any:
    """Build the unsigned Algorand transaction carrying the anchor note.

    The transaction is a 0-Algo self-payment: ``sender = receiver =
    signer_address``, ``amount = 0``, note = the ARC-2 disclosed-mode
    note bytes. The 0-Algo self-payment pattern is the standard way to
    publish a note on Algorand without moving funds.

    Args:
        manifest_hash: Raw bytes of the manifest hash to anchor.
        signer_address: Algorand address (58 chars base32) that will
            both send and receive the 0-Algo payment.
        suggested_params: ``algosdk.transaction.SuggestedParams`` from
            ``algod_client.suggested_params()``. Caller must fetch this
            before calling; the function does not reach out for it.
        batching_profile: The batching profile identifier. Defaults to v1.

    Returns:
        An unsigned ``algosdk.transaction.PaymentTxn``.

    Raises:
        AnchorError: If py-algorand-sdk is unavailable.
    """
    _ensure_algosdk()
    note = build_note_bytes(manifest_hash, batching_profile)
    return PaymentTxn(
        sender=signer_address,
        sp=suggested_params,
        receiver=signer_address,
        amt=0,
        note=note,
    )


# ─────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────

def _ensure_algosdk() -> None:
    """Raise AnchorError if py-algorand-sdk is not importable."""
    if not _ALGOSDK_AVAILABLE:
        raise AnchorError(
            f"py-algorand-sdk is required but cannot be imported: "
            f"{_ALGOSDK_ERROR}. Install or repair with: "
            f"pip install 'py-algorand-sdk>=2.6.1'"
        )


def _network_for_mode(mode: AnchorMode) -> str:
    """Map an AnchorMode to its associated network identifier."""
    if mode is AnchorMode.PRODUCTION:
        return ALGORAND_MAINNET
    return ALGORAND_TESTNET  # DRAFT and DEMO both use testnet semantics


def _default_algod_url_for_mode(mode: AnchorMode) -> str:
    if mode is AnchorMode.PRODUCTION:
        return DEFAULT_ALGOD_URL_MAINNET
    return DEFAULT_ALGOD_URL_TESTNET


def _make_algod_client(
    algod_client: Optional[Any],
    algod_url: Optional[str],
    algod_token: Optional[str],
    mode: AnchorMode,
) -> Any:
    """Return an AlgodClient, either passed-in or constructed from args."""
    _ensure_algosdk()
    if algod_client is not None:
        return algod_client
    url = algod_url or _default_algod_url_for_mode(mode)
    token = algod_token or ""
    return AlgodClient(token, url)


def _wait_for_confirmation(
    algod_client: Any,
    txid: str,
    timeout_seconds: float,
) -> tuple[int, str]:
    """Poll algod until ``txid`` is confirmed. Returns (block_round, iso_ts).

    Raises:
        AnchorError: On timeout or if algod reports an error.
    """
    deadline = time.monotonic() + timeout_seconds
    last_round_pending: Optional[int] = None
    while True:
        try:
            tx_info = algod_client.pending_transaction_info(txid)
        except Exception as exc:  # noqa: BLE001
            raise AnchorError(
                f"algod.pending_transaction_info failed for {txid}: {exc}"
            ) from exc

        confirmed_round = tx_info.get("confirmed-round") or 0
        if confirmed_round > 0:
            confirmed_at = datetime.now(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            )
            return int(confirmed_round), confirmed_at

        pool_error = tx_info.get("pool-error")
        if pool_error:
            raise AnchorError(
                f"Transaction {txid} rejected by algod pool: {pool_error}"
            )

        if time.monotonic() >= deadline:
            raise AnchorError(
                f"Timed out after {timeout_seconds}s waiting for {txid} to "
                f"confirm (last pending round seen: {last_round_pending})"
            )

        last_round_pending = tx_info.get("last-round")
        # Algorand block time is ~3.3s; poll every 1s for responsiveness.
        time.sleep(1.0)


# ─────────────────────────────────────────────────────────────────
# PUBLIC ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────

def anchor_manifest(
    manifest_hash: bytes,
    *,
    signer: Signer,
    mode: AnchorMode,
    algod_client: Optional[Any] = None,
    algod_url: Optional[str] = None,
    algod_token: Optional[str] = None,
    batching_profile: str = BATCHING_PROFILE_SINGLE,
    wait_for_confirmation: bool = True,
    confirmation_timeout_seconds: float = DEFAULT_CONFIRMATION_TIMEOUT_SECONDS,
) -> AnchorRecord:
    """Anchor a manifest hash to Algorand.

    The end-to-end flow:

    1. Build the ARC-2 disclosed-mode note bytes from ``manifest_hash``.
    2. If ``mode`` is ``DRAFT``: return an unanchored AnchorRecord.
    3. Otherwise: fetch ``suggested_params`` from algod.
    4. Build the unsigned ``PaymentTxn``.
    5. Sign via ``signer.sign_transaction``.
    6. Submit to algod.
    7. If ``wait_for_confirmation``: poll until confirmed (or timeout).
    8. Return an ``AnchorRecord`` populated with the result.

    Args:
        manifest_hash: Raw bytes of the manifest hash to anchor.
            Typically 32 bytes (SHA-256).
        signer: A ``Signer`` implementation. Provides the Algorand address
            and signs the built transaction.
        mode: One of ``AnchorMode.DRAFT``, ``DEMO``, or ``PRODUCTION``.
            No default; must be explicit.
        algod_client: Optional pre-built ``AlgodClient``. If not provided,
            one is constructed from ``algod_url`` and ``algod_token``, or
            from Algonode defaults based on ``mode``.
        algod_url: Optional algod HTTPS URL. Defaults per mode.
        algod_token: Optional algod auth token. Default empty (public nodes
            accept empty tokens).
        batching_profile: Batching profile identifier. v1 default.
        wait_for_confirmation: If ``True`` (default), poll until the
            submitted transaction confirms or the timeout expires. If
            ``False``, return as soon as the transaction is submitted
            with ``block_round=None`` and ``confirmed_at=None``.
        confirmation_timeout_seconds: How long to wait for confirmation.
            Default 60.0 seconds.

    Returns:
        An ``AnchorRecord`` ready to slot into a ``Receipt`` via
        ``build_receipt``.

    Raises:
        AnchorError: If py-algorand-sdk is unavailable, the signer rejects
            the transaction, algod refuses to submit, or confirmation times
            out.
    """
    _ensure_algosdk()

    # Build the note bytes. Same in all three modes; the note is the
    # commitment, the transaction is the carrier.
    note_bytes = build_note_bytes(manifest_hash, batching_profile)
    note_payload_b64 = base64.b64encode(note_bytes[len(_ARC2_PREFIX):]).decode("ascii")

    network = _network_for_mode(mode)

    # DRAFT mode: don't sign, don't submit, don't fetch suggested_params.
    if mode is AnchorMode.DRAFT:
        logger.info(
            "DRAFT anchor: built note (%d bytes) for hash %s; not submitting",
            len(note_bytes), manifest_hash.hex()[:16],
        )
        return AnchorRecord(
            network=network,
            txid="",
            block_round=None,
            confirmed_at=None,
            note_format=ARC2_NOTE_FORMAT,
            note_dapp_name=ARC2_DAPP_NAME,
            note_format_version=ARC2_FORMAT_VERSION_JSON,
            note_payload_b64=note_payload_b64,
        )

    # DEMO and PRODUCTION: real submission.
    client = _make_algod_client(algod_client, algod_url, algod_token, mode)

    # Fetch suggested params (algod call).
    try:
        suggested_params = client.suggested_params()
    except Exception as exc:  # noqa: BLE001
        raise AnchorError(
            f"algod.suggested_params() failed for mode {mode.value}: {exc}"
        ) from exc

    # Build the unsigned transaction.
    unsigned_txn = build_transaction(
        manifest_hash,
        signer_address=signer.address,
        suggested_params=suggested_params,
        batching_profile=batching_profile,
    )

    # Sign via the signer abstraction. The signer enforces "transactions
    # only, never raw bytes" at its own boundary.
    try:
        signed_txn = signer.sign_transaction(unsigned_txn)
    except Exception as exc:  # noqa: BLE001
        raise AnchorError(
            f"Signer rejected transaction: {exc}"
        ) from exc

    # Submit to algod.
    try:
        txid = client.send_transaction(signed_txn)
    except Exception as exc:  # noqa: BLE001
        raise AnchorError(
            f"algod.send_transaction failed for mode {mode.value}: {exc}"
        ) from exc

    logger.info(
        "Submitted txn %s in mode=%s, hash=%s",
        txid, mode.value, manifest_hash.hex()[:16],
    )

    # Optionally wait for confirmation.
    block_round: Optional[int] = None
    confirmed_at: Optional[str] = None
    if wait_for_confirmation:
        block_round, confirmed_at = _wait_for_confirmation(
            client, txid, confirmation_timeout_seconds,
        )
        logger.info(
            "Confirmed txn %s in round %d at %s",
            txid, block_round, confirmed_at,
        )

    return AnchorRecord(
        network=network,
        txid=txid,
        block_round=block_round,
        confirmed_at=confirmed_at,
        note_format=ARC2_NOTE_FORMAT,
        note_dapp_name=ARC2_DAPP_NAME,
        note_format_version=ARC2_FORMAT_VERSION_JSON,
        note_payload_b64=note_payload_b64,
    )
