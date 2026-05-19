# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: Apache-2.0
"""
Canonical manifest envelope for actproof.

A manifest is the structured commitment an issuer makes. It declares which
catalogue entry it implements, who the issuer is, what is being claimed, what
evidence files back the claim, and which recipients are designated witnesses.
The manifest's canonical bytes (via RFC 8785 JCS) produce the hash that gets
anchored on the public ledger and timestamped by the QTSP. That hash is the
load-bearing artifact: identical input bytes must always produce identical
canonical bytes, on any platform, in any year, forever.

Wire shape
----------

When canonicalized, a manifest produces JSON of this shape:

::

    {
      "batching_profile": "single_attestation_anchor_v1",
      "catalogue": {
        "act_type_id": "op:eu.nis2.art20.management_body_approval.v1",
        "entry_hash": "sha256:abc...",
        "entry_version": 1,
        "git_commit": "0123abcd...",
        "schema_hash": "sha256:def...",
        "source_uri": "https://github.com/deyan-paroushev/actproof-events"
      },
      "claim": {
        "approving_body_name": "Board of Directors",
        "decision_date": "2026-05-14",
        "...": "..."
      },
      "evidence": [
        {
          "byte_size": 482991,
          "filename_normalized": "minutes_2026-05-14.pdf",
          "label": "signed_resolution_or_minutes",
          "mime_type": "application/pdf",
          "sha256": "sha256:..."
        }
      ],
      "issued_at": "2026-05-14T08:23:11Z",
      "issuer": {
        "authority_label": "Management Body",
        "org_name": "Sofia Tech Holdings AD"
      },
      "receipt_profile": "actproof-jcs-v1",
      "recipients": [
        {
          "email_hash": "sha256:...",
          "org_name": "Auditor AD",
          "role": "external_auditor"
        }
      ],
      "title": "NIS2 Article 20 management body approval, May 2026"
    }

After canonicalization (RFC 8785), every object's keys are sorted in Unicode
code-point order. The example above already shows the sorted form.

Design choices
--------------

**Label-bound evidence.** Each ``Evidence`` carries its catalogue-required
``label`` inline. This deviates from a naive design that would store evidence
hashes and labels in two separate lists and require the verifier to correlate
them. Label-bound evidence means the manifest itself states "this file
satisfies this required label," which is what a downstream verifier actually
needs to check. (Pattern carried forward from the architectural review.)

**Catalogue pinning.** The ``catalogue`` block pins five things: which
entry (``act_type_id``), which version (``entry_version``), where it lives
(``source_uri``), exactly which version of the spec repo (``git_commit``),
the SHA-256 of the entry JSON bytes (``entry_hash``), and the SHA-256 of
the schema JSON bytes (``schema_hash``). Together these make the receipt
independently re-verifiable: anyone can fetch the catalogue at the pinned
commit, recompute the entry hash, and confirm that what was used was what
the receipt claims.

**Hashed recipient emails.** The public manifest contains only
``email_hash`` for each recipient (SHA-256 of normalised plaintext). The
plaintext email lives only in the issuer-side receipt. A public verifier
can confirm that a particular email was designated by computing the hash
and comparing; a public observer cannot enumerate recipients without
already knowing the plaintext.

**Frozen dataclasses, no Pydantic.** This module uses ``@dataclass(frozen=True)``
throughout. Frozen for immutability (a manifest's identity is its hash; mutating
fields after construction would invalidate that). No Pydantic so the library
stays lightweight; validation is a separate explicit function that callers
invoke when they want it.

API
---

Construction:

* ``build_manifest(*, ...) -> Manifest`` - construct from keyword arguments.
* ``manifest_from_dict(d) -> Manifest`` - parse from a dict (e.g. from a receipt).

Serialisation:

* ``manifest_to_dict(m) -> dict`` - produce a dict suitable for canonicalisation.
* ``hash_manifest(m) -> bytes`` - canonicalise + SHA-256 raw digest (32 bytes).
* ``hash_manifest_hex(m) -> str`` - canonicalise + SHA-256 hex digest.

Helpers:

* ``normalize_email(email) -> str`` - lowercase + strip whitespace.
* ``hash_email(email) -> str`` - return ``"sha256:..."`` of normalised email.
* ``hash_file_bytes(content) -> str`` - return ``"sha256:..."`` of raw file bytes.
* ``hash_json_bytes(json_bytes) -> str`` - return ``"sha256:..."`` of canonical JSON bytes.

Validation:

* ``validate_manifest_shape(m) -> None`` - shape validation (sha256 formats,
  ISO 8601 timestamps, non-empty required fields). Raises
  ``ManifestValidationError`` on the first problem.

Catalogue conformance (does this manifest's claim match its act type's
required fields) is checked separately by ``actproof.catalogue.validate_manifest``
landing in v0.0.4.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence

from actproof.canonical import canonicalize, hash_canonical

__all__ = [
    "Manifest",
    "CatalogueBinding",
    "Issuer",
    "Evidence",
    "Recipient",
    "build_manifest",
    "manifest_to_dict",
    "manifest_from_dict",
    "hash_manifest",
    "hash_manifest_hex",
    "normalize_email",
    "hash_email",
    "hash_file_bytes",
    "hash_json_bytes",
    "validate_manifest_shape",
    "ManifestValidationError",
    "RECEIPT_PROFILE_V1",
    "BATCHING_PROFILE_SINGLE",
]


# ─────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────

RECEIPT_PROFILE_V1: str = "actproof-jcs-v1"
"""The receipt profile identifier for v1 (JSON-canonical, no COSE bridge).

When the SCITT COSE_Sign1 bridge lands (post-RFC 9943 publication), v2
will be ``"actproof-scitt-cose-v2"``, and the receipt's ``receipt_profile``
field is the discriminator that lets verifiers route to the right parser.
"""

BATCHING_PROFILE_SINGLE: str = "single_attestation_anchor_v1"
"""The batching profile identifier for v1 (one attestation per anchor).

When Merkle batching lands in a future release, the new profile will be
``"merkle_batch_v1"`` and the receipt's ``batching_profile`` field will
declare which is in use.
"""

_SHA256_HEX_PATTERN: re.Pattern[str] = re.compile(r"^sha256:[0-9a-f]{64}$")
"""Pattern for SHA-256 hash strings: ``"sha256:"`` + 64 lowercase hex chars."""

_GIT_COMMIT_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-f]{40}$")
"""Pattern for git commit SHAs: 40 lowercase hex chars."""

_ISO_8601_PATTERN: re.Pattern[str] = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)
"""Pattern for ISO 8601 UTC timestamps: ``YYYY-MM-DDTHH:MM:SS[.fff]Z``."""


# ─────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────

class ManifestValidationError(ValueError):
    """Raised when a manifest's shape is structurally invalid.

    Subclass of ``ValueError`` so callers can catch ``ValueError`` if they
    prefer unified handling, or ``ManifestValidationError`` specifically
    when they need to distinguish manifest shape errors from other value
    errors.
    """


# ─────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CatalogueBinding:
    """Pins which catalogue entry, version, and source revision this manifest implements.

    Together the six required fields make the receipt independently verifiable:
    anyone can fetch the catalogue source at the pinned commit, locate the
    entry by ``act_type_id``, recompute the entry hash, and confirm that
    what was used matches what the receipt claims.

    Two additional optional fields name the pip-installable Python package
    that provides the catalogue bytes. They are populated automatically when
    the catalogue is loaded from an installed ``actproof-events`` package
    (via ``pip install actproof[events]``); they remain ``None`` when the
    catalogue is sourced via git submodule, vendored copy, or volume mount.
    The package fields are convenience provenance: a verifier with the
    package name and version can ``pip install`` the exact release whose
    bytes hash to ``entry_hash``, without having to clone the git repo
    and check out the ``git_commit``. The cryptographic binding remains
    ``entry_hash``; the package fields make the source easier to obtain.

    Attributes:
        act_type_id: The catalogue entry's act_type_id, e.g.
            ``"op:eu.nis2.art20.management_body_approval.v1"``.
        entry_version: The integer version of the entry.
        source_uri: URI of the catalogue source, typically a GitHub repo URL.
        git_commit: 40-character git SHA-1 commit of the catalogue at issue time.
        entry_hash: SHA-256 of the entry JSON file bytes, as ``"sha256:..."``.
        schema_hash: SHA-256 of the catalogue schema JSON bytes, as ``"sha256:..."``.
        source_package_name: Optional Python distribution name of the package
            that provided the catalogue bytes (typically ``"actproof-events"``).
            ``None`` when the catalogue was sourced via git, vendoring, or
            volume mount rather than a pip install.
        source_package_version: Optional version string of the source package
            at load time (e.g. ``"1.4.0rc1"``). Pairs with
            ``source_package_name`` to allow a verifier to
            ``pip install actproof-events==<version>`` and obtain byte-exact
            catalogue bytes. ``None`` when ``source_package_name`` is ``None``.
    """
    act_type_id: str
    entry_version: int
    source_uri: str
    git_commit: str
    entry_hash: str
    schema_hash: str
    source_package_name: Optional[str] = None
    source_package_version: Optional[str] = None


@dataclass(frozen=True)
class Issuer:
    """The party making the commitment.

    Public fields only. Internal identifiers (Auth0 user ID, internal user
    record ID, etc.) belong in the issuer-side receipt artifact, not in
    the public manifest.

    Attributes:
        org_name: Legal or trading name of the issuing organisation.
        authority_label: Role under which the issuer acts, e.g.
            ``"Management Body"`` for NIS2 Article 20, ``"Operator"`` for
            EUDR, ``"Maintainer"`` for a software release.
    """
    org_name: str
    authority_label: str


@dataclass(frozen=True)
class Evidence:
    """A single evidence file bound to its catalogue-required label.

    Each ``Evidence`` carries its label inline so that a verifier can read
    the manifest and immediately answer: "which file satisfies which required
    evidence label?" The label MUST be one of the entry's
    ``required_evidence_labels`` (this is checked by
    ``actproof.catalogue.validate_manifest``, not here).

    Attributes:
        label: The catalogue-required evidence label this file satisfies.
        filename_normalized: NFC-normalised filename with no path components,
            no leading dot, no shell metacharacters.
        byte_size: File size in bytes. Must be positive.
        mime_type: IANA media type, e.g. ``"application/pdf"``.
        sha256: SHA-256 of the file bytes, as ``"sha256:..."``.
    """
    label: str
    filename_normalized: str
    byte_size: int
    mime_type: str
    sha256: str


@dataclass(frozen=True)
class Recipient:
    """A designated recipient (witness) of the manifest.

    The public manifest contains only ``email_hash``. Plaintext email
    lives in the issuer-side receipt artifact, NOT here. A verifier
    proves a particular email was designated by computing the hash and
    comparing; a public observer cannot enumerate recipients without
    already knowing the plaintext addresses.

    Attributes:
        role: Role from the catalogue entry's ``recommended_witness_roles``,
            e.g. ``"external_auditor"``, ``"competent_authority_supervisor"``.
        org_name: Legal or trading name of the recipient organisation.
        email_hash: ``"sha256:..."`` of the normalised (lowercase, trimmed)
            recipient email address.
    """
    role: str
    org_name: str
    email_hash: str


@dataclass(frozen=True)
class Manifest:
    """The canonical envelope. Once committed, every field is immutable.

    Attributes:
        receipt_profile: ``"actproof-jcs-v1"`` for this release.
        issued_at: ISO 8601 UTC timestamp with ``Z`` suffix.
        catalogue: Catalogue binding (which entry, which version, which
            source revision).
        issuer: The party making the commitment.
        title: Human-readable title for the commitment, e.g.
            ``"NIS2 Article 20 management body approval, May 2026"``.
        claim: Catalogue-typed claim fields, a mapping whose keys match
            the entry's ``required_claim_fields`` plus any
            ``optional_claim_fields``. Field values are JSON-serialisable
            primitives (str, int, bool, None) or nested dicts/lists.
        evidence: Tuple of ``Evidence`` records, one per uploaded file.
        recipients: Tuple of ``Recipient`` records, one per designated witness.
        batching_profile: ``"single_attestation_anchor_v1"`` for this release.
    """
    receipt_profile: str
    issued_at: str
    catalogue: CatalogueBinding
    issuer: Issuer
    title: str
    claim: Mapping[str, Any]
    evidence: tuple[Evidence, ...]
    recipients: tuple[Recipient, ...]
    batching_profile: str


# ─────────────────────────────────────────────────────────────────
# CONSTRUCTION
# ─────────────────────────────────────────────────────────────────

def build_manifest(
    *,
    act_type_id: str,
    catalogue_entry_version: int,
    catalogue_source_uri: str,
    catalogue_git_commit: str,
    catalogue_entry_hash: str,
    catalogue_schema_hash: str,
    issuer_org_name: str,
    issuer_authority_label: str,
    title: str,
    claim: Mapping[str, Any],
    evidence: Sequence[Evidence],
    recipients: Sequence[Recipient],
    issued_at: str,
    receipt_profile: str = RECEIPT_PROFILE_V1,
    batching_profile: str = BATCHING_PROFILE_SINGLE,
    catalogue_source_package_name: Optional[str] = None,
    catalogue_source_package_version: Optional[str] = None,
) -> Manifest:
    """Construct a Manifest from raw fields.

    Use this rather than calling the ``Manifest`` constructor directly.
    Builds nested dataclasses, coerces evidence and recipients to tuples
    for immutability, and produces a fully populated ``Manifest`` ready
    to canonicalise.

    All arguments are keyword-only to prevent positional misuse.

    Args:
        act_type_id: Catalogue entry act_type_id.
        catalogue_entry_version: Integer entry version.
        catalogue_source_uri: URI of the catalogue source.
        catalogue_git_commit: 40-char git SHA-1 of the catalogue source.
        catalogue_entry_hash: ``"sha256:..."`` of the entry JSON bytes.
        catalogue_schema_hash: ``"sha256:..."`` of the catalogue schema JSON.
        issuer_org_name: Issuing organisation name.
        issuer_authority_label: Role under which issuer acts.
        title: Human-readable manifest title.
        claim: Catalogue-typed claim fields.
        evidence: Sequence of ``Evidence`` records.
        recipients: Sequence of ``Recipient`` records.
        issued_at: ISO 8601 UTC timestamp with ``Z`` suffix.
        receipt_profile: Receipt profile discriminator. Defaults to v1.
        batching_profile: Batching profile discriminator. Defaults to single.
        catalogue_source_package_name: Optional pip distribution name of the
            package that provided the catalogue bytes (typically
            ``"actproof-events"``). Leave ``None`` when sourcing the catalogue
            from a git submodule, vendored copy, or volume mount. Pass both
            this and ``catalogue_source_package_version`` together, or
            neither.
        catalogue_source_package_version: Optional version string of the
            source package at issue time (e.g. ``"1.4.0rc1"``).

    Returns:
        A fully populated, immutable ``Manifest`` instance.

    Raises:
        ManifestValidationError: If exactly one of
            ``catalogue_source_package_name`` and
            ``catalogue_source_package_version`` is provided. The two
            are both-or-neither; either commit to package provenance
            fully or omit it entirely.
    """
    # Both-or-neither enforcement (mirrors manifest_from_dict). One-sided
    # package provenance would silently round-trip to a different shape
    # via manifest_to_dict, which is a correctness hazard. Reject up front.
    if (catalogue_source_package_name is None) != (catalogue_source_package_version is None):
        raise ManifestValidationError(
            "catalogue_source_package_name and catalogue_source_package_version "
            "must either both be provided or both be None. "
            f"Got catalogue_source_package_name={catalogue_source_package_name!r}, "
            f"catalogue_source_package_version={catalogue_source_package_version!r}."
        )
    if catalogue_source_package_name is not None and not isinstance(catalogue_source_package_name, str):
        raise ManifestValidationError(
            f"catalogue_source_package_name must be a string when present, "
            f"got {type(catalogue_source_package_name).__name__}."
        )
    if catalogue_source_package_version is not None and not isinstance(catalogue_source_package_version, str):
        raise ManifestValidationError(
            f"catalogue_source_package_version must be a string when present, "
            f"got {type(catalogue_source_package_version).__name__}."
        )

    return Manifest(
        receipt_profile=receipt_profile,
        issued_at=issued_at,
        catalogue=CatalogueBinding(
            act_type_id=act_type_id,
            entry_version=catalogue_entry_version,
            source_uri=catalogue_source_uri,
            git_commit=catalogue_git_commit,
            entry_hash=catalogue_entry_hash,
            schema_hash=catalogue_schema_hash,
            source_package_name=catalogue_source_package_name,
            source_package_version=catalogue_source_package_version,
        ),
        issuer=Issuer(
            org_name=issuer_org_name,
            authority_label=issuer_authority_label,
        ),
        title=title,
        claim=dict(claim),  # defensive copy
        evidence=tuple(evidence),
        recipients=tuple(recipients),
        batching_profile=batching_profile,
    )


# ─────────────────────────────────────────────────────────────────
# SERIALISATION
# ─────────────────────────────────────────────────────────────────

def manifest_to_dict(m: Manifest) -> dict[str, Any]:
    """Convert a ``Manifest`` to a plain dict suitable for canonicalisation.

    The output is what gets passed to ``canonicalize()`` to produce the
    canonical bytes that are hashed and anchored.

    Backwards compatibility: the optional catalogue fields
    ``source_package_name`` and ``source_package_version`` are only
    emitted when both are populated. When both are ``None``, they are
    omitted entirely from the canonical output, so manifests built
    before these fields existed produce byte-identical canonical bytes
    (and therefore byte-identical hashes) as they did before.

    Args:
        m: The Manifest to serialise.

    Returns:
        A nested dict with all manifest fields.
    """
    catalogue_block: dict[str, Any] = {
        "act_type_id": m.catalogue.act_type_id,
        "entry_version": m.catalogue.entry_version,
        "source_uri": m.catalogue.source_uri,
        "git_commit": m.catalogue.git_commit,
        "entry_hash": m.catalogue.entry_hash,
        "schema_hash": m.catalogue.schema_hash,
    }
    # Emit the optional package fields only when both are populated. This
    # preserves byte-exact canonical bytes for manifests issued before
    # these fields existed (where both are None).
    if (
        m.catalogue.source_package_name is not None
        and m.catalogue.source_package_version is not None
    ):
        catalogue_block["source_package_name"] = m.catalogue.source_package_name
        catalogue_block["source_package_version"] = m.catalogue.source_package_version

    return {
        "receipt_profile": m.receipt_profile,
        "issued_at": m.issued_at,
        "catalogue": catalogue_block,
        "issuer": {
            "org_name": m.issuer.org_name,
            "authority_label": m.issuer.authority_label,
        },
        "title": m.title,
        "claim": dict(m.claim),
        "evidence": [
            {
                "label": e.label,
                "filename_normalized": e.filename_normalized,
                "byte_size": e.byte_size,
                "mime_type": e.mime_type,
                "sha256": e.sha256,
            }
            for e in m.evidence
        ],
        "recipients": [
            {
                "role": r.role,
                "org_name": r.org_name,
                "email_hash": r.email_hash,
            }
            for r in m.recipients
        ],
        "batching_profile": m.batching_profile,
    }


def manifest_from_dict(d: Mapping[str, Any]) -> Manifest:
    """Parse a dict back into a ``Manifest``.

    Used primarily by the verifier, which receives a receipt with the
    manifest as a nested dict and needs to reconstruct the typed object
    for inspection.

    Backwards compatibility: the optional catalogue fields
    ``source_package_name`` and ``source_package_version`` are read via
    ``.get(...)`` so receipts predating these fields parse without
    raising. Receipts that carry them populate the corresponding
    ``CatalogueBinding`` attributes.

    The two package fields are both-or-neither: a manifest that carries
    one of them but not the other is malformed and parsing raises
    ``ManifestValidationError``. This prevents a roundtrip discrepancy
    where the input dict had one field, the parsed object stores it
    silently, and re-serialisation via ``manifest_to_dict`` drops both
    (because ``manifest_to_dict`` emits both only when both are set).
    Either commit to package provenance fully or omit it entirely.

    Args:
        d: A dict matching the canonical manifest shape.

    Returns:
        A reconstructed ``Manifest`` instance.

    Raises:
        ManifestValidationError: If a required field is missing or has
            the wrong type, or if exactly one of the optional package
            fields is present.
    """
    try:
        catalogue_dict = d["catalogue"]
        issuer_dict = d["issuer"]

        # Both-or-neither enforcement for the optional package fields.
        # Catches malformed manifests with one field set and the other
        # absent or None, which would lose information on roundtrip.
        source_package_name = catalogue_dict.get("source_package_name")
        source_package_version = catalogue_dict.get("source_package_version")
        if (source_package_name is None) != (source_package_version is None):
            raise ManifestValidationError(
                "catalogue.source_package_name and catalogue.source_package_version "
                "must either both be present or both be omitted. "
                f"Got source_package_name={source_package_name!r}, "
                f"source_package_version={source_package_version!r}."
            )
        if source_package_name is not None and not isinstance(source_package_name, str):
            raise ManifestValidationError(
                f"catalogue.source_package_name must be a string when present, "
                f"got {type(source_package_name).__name__}."
            )
        if source_package_version is not None and not isinstance(source_package_version, str):
            raise ManifestValidationError(
                f"catalogue.source_package_version must be a string when present, "
                f"got {type(source_package_version).__name__}."
            )

        return Manifest(
            receipt_profile=d["receipt_profile"],
            issued_at=d["issued_at"],
            catalogue=CatalogueBinding(
                act_type_id=catalogue_dict["act_type_id"],
                entry_version=int(catalogue_dict["entry_version"]),
                source_uri=catalogue_dict["source_uri"],
                git_commit=catalogue_dict["git_commit"],
                entry_hash=catalogue_dict["entry_hash"],
                schema_hash=catalogue_dict["schema_hash"],
                source_package_name=source_package_name,
                source_package_version=source_package_version,
            ),
            issuer=Issuer(
                org_name=issuer_dict["org_name"],
                authority_label=issuer_dict["authority_label"],
            ),
            title=d["title"],
            claim=dict(d["claim"]),
            evidence=tuple(
                Evidence(
                    label=e["label"],
                    filename_normalized=e["filename_normalized"],
                    byte_size=int(e["byte_size"]),
                    mime_type=e["mime_type"],
                    sha256=e["sha256"],
                )
                for e in d.get("evidence", [])
            ),
            recipients=tuple(
                Recipient(
                    role=r["role"],
                    org_name=r["org_name"],
                    email_hash=r["email_hash"],
                )
                for r in d.get("recipients", [])
            ),
            batching_profile=d["batching_profile"],
        )
    except (KeyError, TypeError) as exc:
        raise ManifestValidationError(
            f"Cannot parse manifest dict: {exc}"
        ) from exc


# ─────────────────────────────────────────────────────────────────
# HASHING
# ─────────────────────────────────────────────────────────────────

def hash_manifest(m: Manifest) -> bytes:
    """Canonicalise a manifest and return the SHA-256 raw digest (32 bytes).

    This is the hash that gets anchored to the public ledger inside the
    ARC-2 disclosed-mode note.

    Args:
        m: The manifest to hash.

    Returns:
        The 32-byte SHA-256 digest of the canonical manifest bytes.
    """
    return hash_canonical(manifest_to_dict(m))


def hash_manifest_hex(m: Manifest) -> str:
    """Canonicalise a manifest and return the SHA-256 hex digest.

    Args:
        m: The manifest to hash.

    Returns:
        64-character lowercase hex string.
    """
    return hash_manifest(m).hex()


# ─────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────

def normalize_email(email: str) -> str:
    """Normalise an email address for hashing.

    Lowercase, strip leading/trailing whitespace. Does NOT validate the
    address format, does NOT canonicalise plus-addressing, does NOT do
    any provider-specific normalisation (like Gmail's dot insensitivity).
    The goal is reproducibility, not deliverability validation.

    Args:
        email: The plaintext email address.

    Returns:
        Lowercased, stripped email string.
    """
    return email.strip().lower()


def hash_email(email: str) -> str:
    """Return the ``"sha256:..."`` hash of a normalised email.

    Args:
        email: The plaintext email address.

    Returns:
        ``"sha256:"`` followed by 64 lowercase hex characters.
    """
    normalized = normalize_email(email)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def hash_file_bytes(content: bytes) -> str:
    """Return the ``"sha256:..."`` hash of raw file bytes.

    Args:
        content: The file's raw byte content.

    Returns:
        ``"sha256:"`` followed by 64 lowercase hex characters.
    """
    digest = hashlib.sha256(content).hexdigest()
    return f"sha256:{digest}"


def hash_json_bytes(json_bytes: bytes) -> str:
    """Return the ``"sha256:..."`` hash of (canonical) JSON bytes.

    Useful for computing ``catalogue_entry_hash`` and ``catalogue_schema_hash``
    from the on-disk JSON files in the actproof-events repository.

    Args:
        json_bytes: The JSON file's raw bytes (typically the contents of
            a catalogue entry .json file).

    Returns:
        ``"sha256:"`` followed by 64 lowercase hex characters.
    """
    digest = hashlib.sha256(json_bytes).hexdigest()
    return f"sha256:{digest}"


# ─────────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────────

def validate_manifest_shape(m: Manifest) -> None:
    """Validate that a manifest is structurally well-formed.

    Checks formats of sha256 strings, git commit SHAs, ISO 8601 timestamps,
    byte sizes, and non-emptiness of required strings. Does NOT check
    whether the claim fields satisfy a particular catalogue entry's
    requirements (that is ``actproof.catalogue.validate_manifest``,
    landing in v0.0.4).

    Args:
        m: The manifest to validate.

    Raises:
        ManifestValidationError: On the first shape problem found.
    """
    # Receipt profile and batching profile.
    if not m.receipt_profile:
        raise ManifestValidationError("receipt_profile is empty")
    if not m.batching_profile:
        raise ManifestValidationError("batching_profile is empty")

    # Issued-at timestamp.
    if not _ISO_8601_PATTERN.match(m.issued_at):
        raise ManifestValidationError(
            f"issued_at {m.issued_at!r} is not ISO 8601 UTC "
            f"(expected YYYY-MM-DDTHH:MM:SS[.fff]Z)"
        )
    # Also verify it actually parses; the regex catches most shapes but
    # leaves room for impossible dates like 2026-13-32.
    try:
        # Python 3.11+ accepts the Z suffix directly; for older versions
        # we replace it explicitly to avoid surprises.
        datetime.fromisoformat(m.issued_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ManifestValidationError(
            f"issued_at {m.issued_at!r} is not a valid datetime: {exc}"
        ) from exc

    # Catalogue binding.
    if not m.catalogue.act_type_id:
        raise ManifestValidationError("catalogue.act_type_id is empty")
    if m.catalogue.entry_version < 1:
        raise ManifestValidationError(
            f"catalogue.entry_version {m.catalogue.entry_version} must be >= 1"
        )
    if not m.catalogue.source_uri:
        raise ManifestValidationError("catalogue.source_uri is empty")
    if not _GIT_COMMIT_PATTERN.match(m.catalogue.git_commit):
        raise ManifestValidationError(
            f"catalogue.git_commit {m.catalogue.git_commit!r} is not "
            f"40 lowercase hex characters"
        )
    if not _SHA256_HEX_PATTERN.match(m.catalogue.entry_hash):
        raise ManifestValidationError(
            f"catalogue.entry_hash {m.catalogue.entry_hash!r} is not in "
            f"'sha256:<64 lowercase hex>' format"
        )
    if not _SHA256_HEX_PATTERN.match(m.catalogue.schema_hash):
        raise ManifestValidationError(
            f"catalogue.schema_hash {m.catalogue.schema_hash!r} is not in "
            f"'sha256:<64 lowercase hex>' format"
        )

    # Issuer.
    if not m.issuer.org_name:
        raise ManifestValidationError("issuer.org_name is empty")
    if not m.issuer.authority_label:
        raise ManifestValidationError("issuer.authority_label is empty")

    # Title.
    if not m.title:
        raise ManifestValidationError("title is empty")

    # Evidence.
    for i, e in enumerate(m.evidence):
        if not e.label:
            raise ManifestValidationError(f"evidence[{i}].label is empty")
        if not e.filename_normalized:
            raise ManifestValidationError(
                f"evidence[{i}].filename_normalized is empty"
            )
        if e.byte_size <= 0:
            raise ManifestValidationError(
                f"evidence[{i}].byte_size {e.byte_size} must be > 0"
            )
        if not e.mime_type:
            raise ManifestValidationError(f"evidence[{i}].mime_type is empty")
        if not _SHA256_HEX_PATTERN.match(e.sha256):
            raise ManifestValidationError(
                f"evidence[{i}].sha256 {e.sha256!r} is not in "
                f"'sha256:<64 lowercase hex>' format"
            )

    # Recipients.
    for i, r in enumerate(m.recipients):
        if not r.role:
            raise ManifestValidationError(f"recipients[{i}].role is empty")
        if not r.org_name:
            raise ManifestValidationError(f"recipients[{i}].org_name is empty")
        if not _SHA256_HEX_PATTERN.match(r.email_hash):
            raise ManifestValidationError(
                f"recipients[{i}].email_hash {r.email_hash!r} is not in "
                f"'sha256:<64 lowercase hex>' format"
            )
