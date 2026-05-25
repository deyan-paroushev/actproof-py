# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: Apache-2.0
"""
Receipt: the artifact that travels outside the issuing platform.

A receipt wraps everything an independent verifier needs to confirm a
commitment was made and anchored: the canonical manifest, its hash, the
on-chain anchor record (network, txid, block round, the ARC-2 note payload),
the RFC 3161 trusted timestamp token, and the two profile discriminators
(``receipt_profile`` and ``batching_profile``). The receipt is the file
recipients receive, the file gets attached to compliance reports, the file
ends up in auditors' archives.

Two artifacts
-------------

This module models two distinct files an issuer produces per commitment:

1. ``Receipt`` - the **public** artifact. Contains no plaintext emails or
   internal identifiers. The manifest already uses hashed emails for
   recipients; the receipt inherits that property. Safe to publish, attach
   to outgoing email, or stash on a public webpage.

2. ``IssuerEvidence`` - the **private** addendum the issuer keeps locally.
   Carries the plaintext-to-hash mapping for recipient emails (so the
   issuer can later identify "which auditor was on this anchor?") plus any
   internal user identifiers. Linked to its public receipt by
   ``manifest_hash``.

The two files are stored separately. The library reads and writes each
independently; the issuer's workflow is "anchor → write receipt JSON →
write issuer evidence JSON" as two operations.

Verification flow (implemented in v0.0.9)
-----------------------------------------

A verifier holding a receipt JSON file performs:

1. Read the receipt with ``read_receipt(path)``.
2. Recompute ``manifest_hash`` from ``receipt.manifest`` via
   ``hash_manifest_hex(manifest)``. Compare to ``receipt.manifest_hash``.
   This is the JCS-canonical hash check.
3. Validate the manifest against the catalogue at the pinned
   ``catalogue_git_commit`` (the verifier fetches the catalogue at that
   commit).
4. Look up ``receipt.anchor.txid`` on ``receipt.anchor.network``. Fetch
   the transaction's note bytes. Compare them directly to
   ``receipt.anchor.on_chain_note``, which carries the full ARC-2 note,
   prefix included, in three encodings (utf8, hex, base64).
5. Verify ``receipt.trusted_timestamp.token_b64`` is a valid RFC 3161
   token issued by the named TSA, whose imprint equals
   ``receipt.manifest_hash``.

The verifier returns a structured ``VerificationResult`` (lands in v0.0.9).
This module is concerned with reading, writing, and structurally validating
receipts; the cryptographic verification lives elsewhere.

Reserved forward-compat slots
-----------------------------

The ``receipt_profile`` field is a discriminator. The v1 value
``"actproof-jcs-v1"`` declares the JSON canonical layout this module
implements. A future v2 will introduce ``"actproof-scitt-cose-v2"`` once
RFC 9943 (SCITT Receipts) leaves AUTH48 and publishes. That format will
add a ``cose_sign1_b64`` field carrying a COSE_Sign1 signature over the
manifest hash, and a ``scitt_transparent_statement`` pointer to a SCITT
transparency service. Those fields are not present in v1 receipts; the
``receipt_profile`` discriminator lets verifiers route to the right parser.

JSON file format
----------------

Receipts are written as pretty-printed JSON (2-space indent) for human
readability. The verifier does NOT depend on receipt-file formatting:
the manifest within the receipt is re-canonicalised before hashing, so
whitespace in the receipt file is meaningless. Only the canonical manifest
bytes (computed by the verifier) feed into the hash check.

API
---

* ``build_receipt(*, manifest, anchor, trusted_timestamp, ...) -> Receipt``
* ``receipt_to_dict(r) -> dict``
* ``receipt_from_dict(d) -> Receipt``
* ``read_receipt(path) -> Receipt``
* ``write_receipt(path, receipt) -> None``
* ``build_issuer_evidence(*, manifest_hash, ...) -> IssuerEvidence``
* ``issuer_evidence_to_dict(ev) -> dict``
* ``issuer_evidence_from_dict(d) -> IssuerEvidence``
* ``read_issuer_evidence(path) -> IssuerEvidence``
* ``write_issuer_evidence(path, evidence) -> None``

Exceptions
~~~~~~~~~~

* ``ReceiptError`` - raised on I/O or parse problems.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from actproof.manifest import (
    BATCHING_PROFILE_SINGLE,
    RECEIPT_PROFILE_V1,
    Manifest,
    hash_manifest_hex,
    manifest_from_dict,
    manifest_to_dict,
)

__all__ = [
    "AnchorRecord",
    "OnChainNote",
    "on_chain_note_from_bytes",
    "TimestampToken",
    "Receipt",
    "PlaintextRecipient",
    "IssuerEvidence",
    "ReceiptError",
    "build_receipt",
    "receipt_to_dict",
    "receipt_from_dict",
    "read_receipt",
    "write_receipt",
    "build_issuer_evidence",
    "issuer_evidence_to_dict",
    "issuer_evidence_from_dict",
    "read_issuer_evidence",
    "write_issuer_evidence",
    "ALGORAND_MAINNET",
    "ALGORAND_TESTNET",
    "ALGORAND_BETANET",
    "ARC2_NOTE_FORMAT",
    "ARC2_DAPP_NAME",
    "ARC2_FORMAT_VERSION_JSON",
]


# ─────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────

ALGORAND_MAINNET: str = "algorand-mainnet"
ALGORAND_TESTNET: str = "algorand-testnet"
ALGORAND_BETANET: str = "algorand-betanet"

_VALID_NETWORKS: frozenset[str] = frozenset(
    {ALGORAND_MAINNET, ALGORAND_TESTNET, ALGORAND_BETANET}
)

ARC2_NOTE_FORMAT: str = "arc-2"
"""The note format identifier per Algorand ARC-2."""

ARC2_DAPP_NAME: str = "actproof"
"""The dapp name actproof uses in the ARC-2 note prefix."""

ARC2_FORMAT_VERSION_JSON: str = "j"
"""The ARC-2 format version for disclosed-mode JSON payloads."""


# ─────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────

class ReceiptError(ValueError):
    """Raised when a receipt cannot be read, parsed, or has structural problems.

    Subclass of ``ValueError`` so callers can catch ``ValueError`` for unified
    handling, or ``ReceiptError`` specifically.
    """


# ─────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class OnChainNote:
    """The exact on-chain ARC-2 note, in three encodings of one byte string.

    All three fields encode the SAME bytes: the full transaction note as it
    sits on the ledger, ARC-2 prefix included
    (``actproof:j{"h":...,"t":...,"v":1}``). They are not three values and
    not three hashes. They are three views of one note, carried so a reviewer
    can match the receipt against whatever form a block explorer, an indexer
    API, or a forensic hex view happens to present.

    Attributes:
        utf8: The note decoded as UTF-8 text. The human-readable form, the
            same string a block explorer shows in its note field.
        hex: Lowercase hex of the note bytes, no ``0x`` prefix. The form for
            byte-for-byte comparison when a UI may have altered whitespace,
            escaping, or Unicode display.
        base64: Standard base64 (with padding) of the note bytes. The form
            many indexer and algod APIs return binary note data in.
    """
    utf8: str
    hex: str
    base64: str


def on_chain_note_from_bytes(note_bytes: bytes) -> OnChainNote:
    """Encode one note byte string into the three receipt encodings.

    This is the single derivation point for the three encodings. The caller
    passes the exact note bytes that were (or will be) placed on-chain, and
    every encoding is computed from that one value here, so the three can
    never drift apart.

    Args:
        note_bytes: The full ARC-2 note bytes, prefix included, exactly as
            carried in the Algorand transaction ``note`` field.

    Returns:
        An ``OnChainNote`` carrying the utf8, hex, and base64 encodings of
        ``note_bytes``.
    """
    return OnChainNote(
        utf8=note_bytes.decode("utf-8"),
        hex=note_bytes.hex(),
        base64=base64.b64encode(note_bytes).decode("ascii"),
    )


@dataclass(frozen=True)
class AnchorRecord:
    """The on-chain anchor commitment for one manifest.

    Carries everything a verifier needs to look up the transaction on the
    right network and confirm the note bytes contain the expected manifest
    hash. For unanchored draft receipts, ``block_round`` and ``confirmed_at``
    are ``None`` and ``txid`` may be empty.

    Attributes:
        network: One of ``"algorand-mainnet"``, ``"algorand-testnet"``,
            ``"algorand-betanet"``. Module-level constants
            ``ALGORAND_MAINNET`` etc. spell these out.
        txid: 52-character base32 Algorand transaction ID. Empty for draft
            receipts (anchor not yet submitted).
        block_round: Algorand round in which the transaction confirmed,
            or ``None`` if not yet confirmed.
        confirmed_at: ISO 8601 UTC timestamp of confirmation, or ``None``.
        note_format: ARC-2 note format identifier. Always ``"arc-2"`` in v1.
        note_dapp_name: ARC-2 dapp name prefix. Always ``"actproof"`` in v1.
        note_format_version: ARC-2 format version. Always ``"j"`` (JSON
            disclosed mode) in v1.
        note_payload_b64: Base64 (standard, with padding) encoding of the
            note payload bytes - the part AFTER the ARC-2 prefix
            ``"actproof:j"``. The full prefixed note, ready-encoded, is also
            available in ``on_chain_note``.
        on_chain_note: The full on-chain ARC-2 note, prefix included, in
            three encodings (utf8, hex, base64). This is what a reviewer
            compares against a block explorer: ``note_payload_b64`` carries
            only the payload after the prefix, so it does not match the note
            an explorer shows, whereas ``on_chain_note`` carries the note
            exactly as the ledger holds it. Derived from the note bytes at
            anchor time. When a receipt that predates this field is read, it
            is reconstructed from ``note_payload_b64`` and the ARC-2 prefix,
            which is lossless.
    """
    network: str
    txid: str
    block_round: Optional[int]
    confirmed_at: Optional[str]
    note_format: str
    note_dapp_name: str
    note_format_version: str
    note_payload_b64: str
    on_chain_note: Optional[OnChainNote] = None

    def __post_init__(self) -> None:
        """Reconstruct ``on_chain_note`` when the caller did not supply it.

        ``on_chain_note`` is a derived field. ``anchor_manifest`` supplies it
        directly from the note bytes it builds. Older receipts predate the
        field, and some call sites build the record from the structured
        fields only; in those cases the full note is rebuilt here from
        ``note_payload_b64`` and the ARC-2 prefix. The payload base64 plus
        the prefix is exactly the note, so the reconstruction is lossless
        and cannot diverge from the note ``build_note_bytes`` produced.
        """
        if self.on_chain_note is None:
            prefix = f"{self.note_dapp_name}:{self.note_format_version}"
            note_bytes = prefix.encode("utf-8") + base64.b64decode(
                self.note_payload_b64
            )
            object.__setattr__(
                self, "on_chain_note", on_chain_note_from_bytes(note_bytes)
            )


@dataclass(frozen=True)
class TimestampToken:
    """An RFC 3161 trusted timestamp token over the manifest hash.

    The TSA's signed assertion that the manifest hash existed at a given
    moment, vouched for by a certified TSA whose certificate chain anchors
    in a trust list (EU Trust List, Adobe AATL, etc.). Storing the raw
    DER-encoded token bytes lets any verifier re-check the signature.

    Attributes:
        tsa_url: HTTP(S) URL of the TSA the token came from. Useful for
            diagnostics but NOT load-bearing for verification (the TSA
            identity is inside the token itself).
        tsa_name: Human-readable TSA name (e.g. ``"QuoVadis EU"``).
        token_b64: Base64 (standard, with padding) of the DER-encoded
            RFC 3161 TSToken. Load-bearing - this is what gets verified.
        policy_oid: Policy OID under which the TSA issued the token. May
            be ``None`` if the TSA did not assert a policy.
        hash_alg: Hash algorithm used for the timestamp imprint, lowercase
            (e.g. ``"sha-256"``). Must match the algorithm used to compute
            the manifest hash.
        imprint_hex: Lowercase hex of the imprint (typically the
            ``manifest_hash`` raw bytes). The verifier checks this matches
            the receipt's ``manifest_hash`` value.
        timestamp: ISO 8601 UTC timestamp extracted from the token for
            convenience. Authoritative value is inside ``token_b64``.
    """
    tsa_url: str
    tsa_name: str
    token_b64: str
    policy_oid: Optional[str]
    hash_alg: str
    imprint_hex: str
    timestamp: str


@dataclass(frozen=True)
class Receipt:
    """A public actproof receipt. Contains no plaintext PII.

    Bundles the canonical manifest, its content hash, the on-chain anchor
    record, the RFC 3161 timestamp token, and the profile discriminators
    that tell a verifier how to parse what it is reading.

    Attributes:
        receipt_profile: Discriminator for receipt layout. v1 is
            ``"actproof-jcs-v1"``. The constant ``RECEIPT_PROFILE_V1``
            from ``actproof.manifest`` spells this out.
        issued_at: ISO 8601 UTC timestamp when the receipt was produced.
            Typically equals ``manifest.issued_at``.
        manifest: The full ``Manifest`` object. The verifier re-canonicalises
            this to recompute the hash check.
        manifest_hash: ``"sha256:..."`` of the canonical manifest bytes.
            Cached at receipt-issue time and stored explicitly so verifiers
            can spot manifest-substitution attacks at a glance.
        anchor: On-chain anchor record.
        trusted_timestamp: RFC 3161 token over the manifest hash.
        batching_profile: ``"single_attestation_anchor_v1"`` for v1. The
            constant ``BATCHING_PROFILE_SINGLE`` from ``actproof.manifest``
            spells this out.
    """
    receipt_profile: str
    issued_at: str
    manifest: Manifest
    manifest_hash: str
    anchor: AnchorRecord
    trusted_timestamp: TimestampToken
    batching_profile: str


@dataclass(frozen=True)
class PlaintextRecipient:
    """A recipient's plaintext email paired with the hash carried in the manifest.

    Stored only inside ``IssuerEvidence``, never inside a public ``Receipt``.

    Attributes:
        email_plaintext: The recipient's email address as the issuer entered it.
        email_hash: ``"sha256:..."`` computed via ``hash_email(email_plaintext)``.
            Must equal one of the ``email_hash`` values in the corresponding
            manifest's ``recipients`` list.
    """
    email_plaintext: str
    email_hash: str


@dataclass(frozen=True)
class IssuerEvidence:
    """The issuer's private addendum to a public receipt.

    Carries plaintext recipient emails (so the issuer can later answer
    "which auditor received this anchor?") and any internal user
    identifiers. Linked to its public receipt by ``manifest_hash``.

    NOT distributed. Lives in the issuer's vault, document management
    system, or compliance archive. If the issuer is later asked by an
    auditor "show me the original recipient list," they pull the
    ``IssuerEvidence`` file from local storage.

    Attributes:
        receipt_profile: Same value as the linked ``Receipt.receipt_profile``,
            so verifiers can confirm the addendum matches the receipt's profile.
        manifest_hash: Same value as the linked ``Receipt.manifest_hash``.
            This is what binds the addendum to the receipt.
        plaintext_recipients: Tuple of plaintext-to-hash mappings, one per
            recipient. Each ``email_hash`` MUST be present in the linked
            manifest's recipients list (the verifier can check this).
        issuer_user_id: Optional internal user identifier (Auth0 sub,
            internal SSO ID, etc.) of the person at the issuing organisation
            who actually clicked "anchor". Useful for internal audit; never
            published.
        internal_notes: Optional free-form text the issuer attaches at
            anchor time (e.g. "reviewed by legal team 2026-05-13",
            internal case reference).
    """
    receipt_profile: str
    manifest_hash: str
    plaintext_recipients: tuple[PlaintextRecipient, ...]
    issuer_user_id: Optional[str]
    internal_notes: Optional[str]


# ─────────────────────────────────────────────────────────────────
# CONSTRUCTION
# ─────────────────────────────────────────────────────────────────

def build_receipt(
    *,
    manifest: Manifest,
    anchor: AnchorRecord,
    trusted_timestamp: TimestampToken,
    issued_at: Optional[str] = None,
    receipt_profile: str = RECEIPT_PROFILE_V1,
    batching_profile: str = BATCHING_PROFILE_SINGLE,
) -> Receipt:
    """Construct a ``Receipt`` from a manifest plus anchor and timestamp.

    Computes ``manifest_hash`` from the canonical manifest bytes. Defaults
    ``issued_at`` to the manifest's ``issued_at`` value if not provided.

    Args:
        manifest: The committed manifest.
        anchor: The on-chain anchor record.
        trusted_timestamp: The RFC 3161 timestamp token.
        issued_at: When the receipt was produced. Defaults to
            ``manifest.issued_at``.
        receipt_profile: Receipt layout discriminator. Defaults to v1.
        batching_profile: Batching discriminator. Defaults to single.

    Returns:
        A populated ``Receipt`` instance.
    """
    if issued_at is None:
        issued_at = manifest.issued_at

    manifest_hash = "sha256:" + hash_manifest_hex(manifest)

    return Receipt(
        receipt_profile=receipt_profile,
        issued_at=issued_at,
        manifest=manifest,
        manifest_hash=manifest_hash,
        anchor=anchor,
        trusted_timestamp=trusted_timestamp,
        batching_profile=batching_profile,
    )


def build_issuer_evidence(
    *,
    manifest_hash: str,
    plaintext_recipients: Sequence[PlaintextRecipient] = (),
    issuer_user_id: Optional[str] = None,
    internal_notes: Optional[str] = None,
    receipt_profile: str = RECEIPT_PROFILE_V1,
) -> IssuerEvidence:
    """Construct an ``IssuerEvidence`` addendum linked to a public receipt.

    Args:
        manifest_hash: ``"sha256:..."`` of the public receipt's manifest.
            Must match the linked ``Receipt.manifest_hash``.
        plaintext_recipients: Plaintext-to-hash mappings for recipients.
        issuer_user_id: Optional internal user identifier.
        internal_notes: Optional free-form notes.
        receipt_profile: Receipt profile discriminator (must match the
            linked receipt's). Defaults to v1.

    Returns:
        A populated ``IssuerEvidence`` instance.
    """
    return IssuerEvidence(
        receipt_profile=receipt_profile,
        manifest_hash=manifest_hash,
        plaintext_recipients=tuple(plaintext_recipients),
        issuer_user_id=issuer_user_id,
        internal_notes=internal_notes,
    )


# ─────────────────────────────────────────────────────────────────
# SERIALISATION: AnchorRecord, TimestampToken
# ─────────────────────────────────────────────────────────────────

def _anchor_to_dict(a: AnchorRecord) -> dict[str, Any]:
    # on_chain_note is always populated: __post_init__ derives it when a
    # caller does not pass one, so it is never None on a constructed record.
    assert a.on_chain_note is not None
    return {
        "network": a.network,
        "txid": a.txid,
        "block_round": a.block_round,
        "confirmed_at": a.confirmed_at,
        "note_format": a.note_format,
        "note_dapp_name": a.note_dapp_name,
        "note_format_version": a.note_format_version,
        "note_payload_b64": a.note_payload_b64,
        "on_chain_note": {
            "utf8": a.on_chain_note.utf8,
            "hex": a.on_chain_note.hex,
            "base64": a.on_chain_note.base64,
        },
    }


def _anchor_from_dict(d: Mapping[str, Any]) -> AnchorRecord:
    try:
        # on_chain_note is optional in the JSON. Receipts written before the
        # field existed omit it; AnchorRecord.__post_init__ then reconstructs
        # it from note_payload_b64 when None is passed here.
        raw_note = d.get("on_chain_note")
        on_chain_note = (
            OnChainNote(
                utf8=raw_note["utf8"],
                hex=raw_note["hex"],
                base64=raw_note["base64"],
            )
            if raw_note is not None
            else None
        )
        return AnchorRecord(
            network=d["network"],
            txid=d["txid"],
            block_round=d["block_round"],
            confirmed_at=d["confirmed_at"],
            note_format=d["note_format"],
            note_dapp_name=d["note_dapp_name"],
            note_format_version=d["note_format_version"],
            note_payload_b64=d["note_payload_b64"],
            on_chain_note=on_chain_note,
        )
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise ReceiptError(f"Cannot parse anchor record: {exc}") from exc


def _timestamp_to_dict(t: TimestampToken) -> dict[str, Any]:
    return {
        "tsa_url": t.tsa_url,
        "tsa_name": t.tsa_name,
        "token_b64": t.token_b64,
        "policy_oid": t.policy_oid,
        "hash_alg": t.hash_alg,
        "imprint_hex": t.imprint_hex,
        "timestamp": t.timestamp,
    }


def _timestamp_from_dict(d: Mapping[str, Any]) -> TimestampToken:
    try:
        return TimestampToken(
            tsa_url=d["tsa_url"],
            tsa_name=d["tsa_name"],
            token_b64=d["token_b64"],
            policy_oid=d["policy_oid"],
            hash_alg=d["hash_alg"],
            imprint_hex=d["imprint_hex"],
            timestamp=d["timestamp"],
        )
    except (KeyError, TypeError, AttributeError) as exc:
        raise ReceiptError(f"Cannot parse timestamp token: {exc}") from exc


# ─────────────────────────────────────────────────────────────────
# SERIALISATION: Receipt
# ─────────────────────────────────────────────────────────────────

def receipt_to_dict(r: Receipt) -> dict[str, Any]:
    """Convert a ``Receipt`` to a plain dict for JSON serialisation.

    Args:
        r: The receipt to serialise.

    Returns:
        A nested dict with all receipt fields.
    """
    return {
        "receipt_profile": r.receipt_profile,
        "issued_at": r.issued_at,
        "manifest": manifest_to_dict(r.manifest),
        "manifest_hash": r.manifest_hash,
        "anchor": _anchor_to_dict(r.anchor),
        "trusted_timestamp": _timestamp_to_dict(r.trusted_timestamp),
        "batching_profile": r.batching_profile,
    }


def receipt_from_dict(d: Mapping[str, Any]) -> Receipt:
    """Parse a dict back into a ``Receipt``.

    Used when reading a receipt from disk or from an external source.

    Args:
        d: A dict matching the receipt JSON layout.

    Returns:
        A reconstructed ``Receipt``.

    Raises:
        ReceiptError: If a required field is missing or has the wrong type.
    """
    try:
        return Receipt(
            receipt_profile=d["receipt_profile"],
            issued_at=d["issued_at"],
            manifest=manifest_from_dict(d["manifest"]),
            manifest_hash=d["manifest_hash"],
            anchor=_anchor_from_dict(d["anchor"]),
            trusted_timestamp=_timestamp_from_dict(d["trusted_timestamp"]),
            batching_profile=d["batching_profile"],
        )
    except (KeyError, TypeError, AttributeError) as exc:
        raise ReceiptError(f"Cannot parse receipt: {exc}") from exc


# ─────────────────────────────────────────────────────────────────
# SERIALISATION: IssuerEvidence
# ─────────────────────────────────────────────────────────────────

def issuer_evidence_to_dict(ev: IssuerEvidence) -> dict[str, Any]:
    """Convert an ``IssuerEvidence`` to a plain dict for JSON serialisation.

    Args:
        ev: The evidence to serialise.

    Returns:
        A nested dict.
    """
    return {
        "receipt_profile": ev.receipt_profile,
        "manifest_hash": ev.manifest_hash,
        "plaintext_recipients": [
            {
                "email_plaintext": p.email_plaintext,
                "email_hash": p.email_hash,
            }
            for p in ev.plaintext_recipients
        ],
        "issuer_user_id": ev.issuer_user_id,
        "internal_notes": ev.internal_notes,
    }


def issuer_evidence_from_dict(d: Mapping[str, Any]) -> IssuerEvidence:
    """Parse a dict back into an ``IssuerEvidence``.

    Args:
        d: A dict matching the issuer evidence JSON layout.

    Returns:
        A reconstructed ``IssuerEvidence``.

    Raises:
        ReceiptError: If a required field is missing or has the wrong type.
    """
    try:
        recipients = tuple(
            PlaintextRecipient(
                email_plaintext=p["email_plaintext"],
                email_hash=p["email_hash"],
            )
            for p in d.get("plaintext_recipients", [])
        )
        return IssuerEvidence(
            receipt_profile=d["receipt_profile"],
            manifest_hash=d["manifest_hash"],
            plaintext_recipients=recipients,
            issuer_user_id=d.get("issuer_user_id"),
            internal_notes=d.get("internal_notes"),
        )
    except (KeyError, TypeError, AttributeError) as exc:
        raise ReceiptError(f"Cannot parse issuer evidence: {exc}") from exc


# ─────────────────────────────────────────────────────────────────
# FILESYSTEM I/O
# ─────────────────────────────────────────────────────────────────

def read_receipt(path: Path) -> Receipt:
    """Read a receipt from a JSON file on disk.

    Args:
        path: Path to the receipt JSON file.

    Returns:
        The parsed ``Receipt``.

    Raises:
        ReceiptError: If the file cannot be read, parsed as JSON, or
            interpreted as a receipt.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise ReceiptError(f"Cannot read receipt file {path}: {exc}") from exc

    try:
        data = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"Receipt file {path} is not valid JSON: {exc}") from exc

    return receipt_from_dict(data)


def write_receipt(path: Path, receipt: Receipt) -> None:
    """Write a receipt to disk as pretty-printed JSON.

    The 2-space indent makes the file human-readable; the verifier does NOT
    depend on file formatting (the manifest within is re-canonicalised
    before hashing).

    Args:
        path: Destination file path.
        receipt: The receipt to write.

    Raises:
        ReceiptError: If the file cannot be written.
    """
    try:
        data = receipt_to_dict(receipt)
        text = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)
        path.write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReceiptError(f"Cannot write receipt to {path}: {exc}") from exc


def read_issuer_evidence(path: Path) -> IssuerEvidence:
    """Read an issuer evidence addendum from disk.

    Args:
        path: Path to the issuer evidence JSON file.

    Returns:
        The parsed ``IssuerEvidence``.

    Raises:
        ReceiptError: If the file cannot be read or parsed.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise ReceiptError(f"Cannot read evidence file {path}: {exc}") from exc

    try:
        data = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"Evidence file {path} is not valid JSON: {exc}") from exc

    return issuer_evidence_from_dict(data)


def write_issuer_evidence(path: Path, evidence: IssuerEvidence) -> None:
    """Write issuer evidence to disk as pretty-printed JSON.

    Args:
        path: Destination file path.
        evidence: The evidence to write.

    Raises:
        ReceiptError: If the file cannot be written.
    """
    try:
        data = issuer_evidence_to_dict(evidence)
        text = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)
        path.write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReceiptError(f"Cannot write evidence to {path}: {exc}") from exc
