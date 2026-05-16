# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Load and query the openproof-events catalogue (v2 and v3 entries). Validate
manifests against entries.

A catalogue is a directory tree of JSON files; each file describes one regulated
or governance act type (NIS2 Article 20 management body approval, EUDR DDS
preparation, software release, board resolution, etc.). The catalogue is
maintained in a separate repository (openproof-events) under a permissive
license. This module reads it, indexes the entries by act_type_id, computes
content hashes for catalogue binding, and validates whether a manifest's claim
satisfies its entry's required fields and evidence labels.

Schema versions
---------------

Entries may carry one of two schema discriminators:

- ``"openproof.act_catalogue_entry.v2"`` (introduced in openproof-events
  v1.4-rc1): fifteen wire-schema fields covering claim shape, evidence,
  signature policy, regulatory citation, and provenance.
- ``"openproof.act_catalogue_entry.v3"`` (introduced in openproof-events
  v1.5-rc1): strict additive superset of v2. Adds four optional sub-objects
  for richer act-type semantics: ``regulated_context_profile``,
  ``prior_receipts_profile``, ``reliance_context``, ``disclosure_profile``.

Both are accepted by the loader. v2 entries leave the four v3 fields on
``CatalogueEntry`` at ``None``. v3 entries populate them where the JSON
declares the corresponding blocks; absent blocks remain ``None``.

Path resolution
---------------

The catalogue is located on disk. How the bytes get there (git submodule,
vendored copy, volume mount, fresh clone in CI) is a deployment decision the
library does not constrain. Resolution order:

1. The ``acts_path`` argument to ``load_catalogue`` if provided.
2. ``$OPENPROOF_CATALOGUE_PATH`` environment variable.
3. ``./openproof-events/catalogue/acts/`` relative to the current working dir.
4. ``./vendor/openproof-events/catalogue/acts/`` relative to the current working dir.

The schema file is located by default relative to the acts path at
``../../spec/schemas/``. Resolution tries v3 first
(``act_catalogue_entry.v3.json``), falls back to v2
(``act_catalogue_entry.v2.json``). Whichever file is found is hashed into
``Catalogue.schema_hash`` for receipt binding.

What gets loaded
----------------

The loader walks the acts directory tree, reading every ``*.json`` file. Files
are filtered:

- Files in any ``_deprecated`` subdirectory are skipped. v1 entries archived
  there are preserved for historical reference but are not loaded for new
  issuance.
- Files matching ``*.test_vectors.json`` are skipped. Those are test fixtures,
  not entries.
- Files whose top-level ``schema`` field is not one of the recognised
  discriminators (``SCHEMA_DISCRIMINATORS``) are silently skipped (could be
  schema files, READMEs in JSON, or other unrelated artifacts).
- Duplicate ``act_type_id`` raises ``CatalogueLoadError``.

What gets validated
-------------------

``validate_manifest(manifest, catalogue)`` checks:

1. The manifest's ``act_type_id`` exists in the loaded catalogue.
2. The manifest's ``entry_version`` matches the loaded entry's version.
3. The manifest's ``entry_hash`` matches the loaded entry's content hash.
4. Every ``required_claim_field`` is present and non-empty in the manifest's claim.
5. Every ``required_evidence_label`` has at least one ``Evidence`` in the manifest.
6. Every ``Evidence.label`` is declared by the entry (in required or optional).
7. The ``schema`` discriminator on the entry is one of
   ``SCHEMA_DISCRIMINATORS``.

Returns a ``list[ValidationIssue]``. An empty list means valid. The caller
decides how to act on issues (treat all as errors, distinguish by ``code``, etc.).

Catalogue binding helpers
-------------------------

``hash_entry_file(path) -> str`` returns ``"sha256:..."`` of the raw entry
JSON bytes. This is what gets stored in ``CatalogueBinding.entry_hash`` at
manifest issue time. Hashing raw file bytes (not canonical bytes) matches the
git-pinned model: anyone with the catalogue at the pinned commit can recompute
the hash with ``sha256sum entry.json`` and confirm.

``hash_schema_file(path) -> str`` returns ``"sha256:..."`` of the schema file
bytes, for ``CatalogueBinding.schema_hash``.

API
---

* ``load_catalogue(...) -> Catalogue``
* ``validate_manifest(manifest, catalogue) -> list[ValidationIssue]``
* ``hash_entry_file(path) -> str``
* ``hash_schema_file(path) -> str``

Data classes
~~~~~~~~~~~~

* ``CatalogueEntry`` - one entry from the catalogue. v2 entries populate
  fifteen v2 wire-schema fields plus two derived fields (``source_path``,
  ``entry_hash``). v3 entries additionally populate up to four optional
  sub-objects (see below); they default to ``None`` on v2 entries and on
  v3 entries that do not declare them.
* ``RegulatoryCitation`` - optional regulatory anchor (v2+).
* ``SignaturePolicy`` - signature evidence requirements (v2+).
* ``RegulatedContextProfile`` - optional v3 block constraining the receipt
  envelope ``regulated_context`` shape for this act type.
* ``PriorReceiptsProfile`` - optional v3 block declaring bilateral
  lifecycle expectations (which ``prior_receipts`` roles MUST or MAY appear).
* ``RelianceContext`` - optional v3 block naming who issues, who relies,
  and who later verifies.
* ``DisclosureProfile`` - optional v3 block declaring per-field disclosure
  tier (public, commitment, private) and bilateral back-propagation scope.
* ``Catalogue`` - the loaded collection (entries dict + provenance metadata).
* ``ValidationIssue`` - one finding from manifest validation.

Exceptions
~~~~~~~~~~

* ``CatalogueLoadError`` - raised on filesystem or parse problems at load.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional

from openproof.manifest import Manifest

logger = logging.getLogger(__name__)

__all__ = [
    "Catalogue",
    "CatalogueEntry",
    "RegulatoryCitation",
    "SignaturePolicy",
    "RegulatedContextProfile",
    "PriorReceiptsProfile",
    "RelianceContext",
    "DisclosureProfile",
    "ValidationIssue",
    "CatalogueLoadError",
    "load_catalogue",
    "validate_manifest",
    "hash_entry_file",
    "hash_schema_file",
    "SCHEMA_DISCRIMINATOR",
    "SCHEMA_DISCRIMINATOR_V2",
    "SCHEMA_DISCRIMINATOR_V3",
    "SCHEMA_DISCRIMINATORS",
    "ENV_CATALOGUE_PATH",
]


# ─────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────

SCHEMA_DISCRIMINATOR_V2: str = "openproof.act_catalogue_entry.v2"
"""Schema discriminator for v2 catalogue entries (fifteen wire-schema fields,
no v3 sub-objects)."""

SCHEMA_DISCRIMINATOR_V3: str = "openproof.act_catalogue_entry.v3"
"""Schema discriminator for v3 catalogue entries (fifteen v2 fields plus four
optional sub-objects: ``regulated_context_profile``, ``prior_receipts_profile``,
``reliance_context``, ``disclosure_profile``)."""

SCHEMA_DISCRIMINATORS: frozenset[str] = frozenset({
    SCHEMA_DISCRIMINATOR_V2,
    SCHEMA_DISCRIMINATOR_V3,
})
"""Set of all schema discriminator strings recognised by this loader.
Membership check: ``entry_data["schema"] in SCHEMA_DISCRIMINATORS``."""

SCHEMA_DISCRIMINATOR: str = SCHEMA_DISCRIMINATOR_V2
"""Backward-compatible alias for ``SCHEMA_DISCRIMINATOR_V2``. Retained so that
external consumers that imported this name from openproof v0.1.0 continue to
work. New code should use ``SCHEMA_DISCRIMINATOR_V2`` and
``SCHEMA_DISCRIMINATOR_V3`` directly, and ``SCHEMA_DISCRIMINATORS`` for
membership checks."""

ENV_CATALOGUE_PATH: str = "OPENPROOF_CATALOGUE_PATH"
"""Environment variable consulted for the catalogue acts path."""

_FALLBACK_ACTS_PATHS: tuple[str, ...] = (
    "openproof-events/catalogue/acts",
    "vendor/openproof-events/catalogue/acts",
)
"""Filesystem locations to try if no path is given and the env var is unset."""

_SCHEMA_RELATIVE_PATH_V3: tuple[str, ...] = (
    "..", "..", "spec", "schemas", "act_catalogue_entry.v3.json",
)
"""Default v3 schema path relative to the acts directory."""

_SCHEMA_RELATIVE_PATH_V2: tuple[str, ...] = (
    "..", "..", "spec", "schemas", "act_catalogue_entry.v2.json",
)
"""Default v2 schema path relative to the acts directory."""


# ─────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────

class CatalogueLoadError(RuntimeError):
    """Raised when the catalogue cannot be loaded (path missing, parse error,
    duplicate act_type_id, invalid entry shape).
    """


# ─────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RegulatoryCitation:
    """Regulatory anchor for an act type (may be ``None`` on the parent entry).

    Attributes:
        instrument: Name of the regulatory instrument, e.g.
            ``"Directive (EU) 2022/2555"``.
        article: Article, section, or paragraph reference.
        jurisdiction: ISO 3166-1 alpha-2, ISO 3166-2 subdivision, or
            supranational tag (``"EU"``, ``"UN"``).
        in_force_from: ISO 8601 date when the instrument took effect.
    """
    instrument: str
    article: str
    jurisdiction: str
    in_force_from: str


@dataclass(frozen=True)
class SignaturePolicy:
    """Signature evidence requirements for an act type.

    Attributes:
        minimum: One of ``"issuer_record"``, ``"external_signature"``, or
            ``"either"``. ``issuer_record`` is a platform-recorded commit
            action with metadata (email, IP, UA, token hash, timestamp); it
            is evidence, NOT an Advanced Electronic Signature under
            eIDAS Regulation 910/2014. ``external_signature`` requires an
            externally produced signature artifact (QES, AES, signed PDF).
            ``either`` accepts both.
        supports: Tuple of evidence labels for externally produced signature
            artifacts the act type recognises.
    """
    minimum: str
    supports: tuple[str, ...]


# ─────────────────────────────────────────────────────────────────
# v3 OPTIONAL SUB-OBJECTS
#
# These four dataclasses correspond to the four optional blocks added in
# the act_catalogue_entry.v3 schema. They are absent on v2 entries and
# optional on v3 entries. Where present in JSON, they are parsed into
# these dataclasses and exposed via the corresponding CatalogueEntry
# fields. Where absent, the CatalogueEntry field stays ``None``.
# ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RegulatedContextProfile:
    """Constrains the receipt envelope ``regulated_context`` shape for an act type.

    Introduced in act_catalogue_entry.v3. Validators MAY use this to reject
    receipts whose ``regulated_context.context_type`` or ``submission_stage``
    are not permitted by the issuing act type.

    Attributes:
        allowed_context_types: Tuple of permitted ``context_type`` values.
            A non-empty subset of ``{"transaction_or_shipment",
            "incident_lifecycle", "reporting_period", "assurance_handoff",
            "release_or_publication"}``.
        allowed_submission_stages: Tuple of permitted ``submission_stage``
            values. Each stage belongs grammatically to one of the
            ``allowed_context_types`` per the receipt envelope spec. Empty
            tuple means no stage restriction beyond what the envelope
            schema enforces.
        default_context_type: ``context_type`` assumed when an issuer does
            not supply one. ``None`` means no default. If present, MUST be
            a member of ``allowed_context_types``.
    """
    allowed_context_types: tuple[str, ...]
    allowed_submission_stages: tuple[str, ...] = ()
    default_context_type: Optional[str] = None


@dataclass(frozen=True)
class PriorReceiptsProfile:
    """Declares bilateral lifecycle expectations for receipts under an act type.

    Introduced in act_catalogue_entry.v3. Validators MAY use this to reject
    ``prior_receipts`` entries whose role is not declared, or to require
    that certain roles be present.

    openproof-events v1.5-rc1 entries leave this block absent (or empty)
    because the May 19 dogfood does not exercise bilateral propagation.
    The first exercised pair lands in v1.5-rc2 by May 30.

    Attributes:
        required_roles: Tuple of role identifiers that MUST appear in a
            receipt's ``prior_receipts`` array. Empty tuple means no
            prior receipts required.
        optional_roles: Tuple of role identifiers that MAY appear in a
            receipt's ``prior_receipts`` array.
    """
    required_roles: tuple[str, ...] = ()
    optional_roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelianceContext:
    """Names who issues, who relies, and who later verifies receipts under this act type.

    Introduced in act_catalogue_entry.v3. Conveys the act type's intended
    reliance pattern in a structured form, so downstream tooling can
    surface it without parsing prose documentation.

    Attributes:
        issuer_role: Functional description of the entity issuing receipts
            under this act type. Example: ``"open-source maintainer
            issuing a release attestation"``.
        counterparty_action: What the counterparty does on receiving the
            receipt. Example: ``"competent authority supervisor records
            the attestation in the supervisory file"``.
        later_verifiers: Tuple of categories of third parties expected to
            verify the receipt independently at later points in time.
            Example: ``("regulator", "external_auditor", "public")``.
        reliance_statement: One-sentence statement of what the receipt
            asserts that the counterparty and later verifiers may rely
            upon. ``None`` if not declared.
    """
    issuer_role: str
    counterparty_action: str
    later_verifiers: tuple[str, ...]
    reliance_statement: Optional[str] = None


@dataclass(frozen=True)
class DisclosureProfile:
    """Per-field disclosure tier and bilateral back-propagation scope.

    Introduced in act_catalogue_entry.v3. Declares which manifest fields
    are stored cleartext, which are stored as salted SHA-256 commitments,
    and which are omitted from the manifest entirely. Also declares which
    fields are surfaced back to each prior-receipt role in the automatic
    disclosure receipt generated at settlement.

    Three tiers:

    - ``public``: cleartext in the canonical manifest.
    - ``commitment``: salted SHA-256 hash in the manifest; cleartext lives
      only in the issuer's holder receipt. Commitment construction is
      ``sha256(salt || ":" || qualified_field_name || ":" || canonical_value)``.
    - ``private``: omitted from the manifest entirely; lives only in the
      holder receipt.

    Catalogue releases MAY restrict the use of the private tier.
    openproof-events v1.5-rc1 entries MUST have ``private_fields = ()``
    (a constraint enforced by the catalogue validator, not by this
    dataclass).

    Field references in the three tier tuples MAY be simple claim field
    names (e.g. ``"supplier_name"``) or dotted manifest paths
    (e.g. ``"manifest.title"``, ``"manifest.issuer.legal_name"``,
    ``"manifest.evidence[].label"``, ``"manifest.recipients[].org_name"``).
    Fields not named in any of the three tier tuples default to public.

    Attributes:
        public_fields: Tuple of field references stored cleartext in the
            canonical manifest.
        commitment_fields: Tuple of field references stored as salted
            SHA-256 commitments in the canonical manifest.
        private_fields: Tuple of field references omitted from the
            manifest entirely.
        back_propagation_scope: Mapping from a ``prior_receipts`` role to
            a tuple of field references visible to that prior receipt's
            issuer in the automatic disclosure receipt generated at
            settlement. Empty mapping means no automatic back-propagation
            declared. Multiple roles MAY be declared even if a given
            catalogue release exercises only one.
    """
    public_fields: tuple[str, ...]
    commitment_fields: tuple[str, ...]
    private_fields: tuple[str, ...]
    back_propagation_scope: Mapping[str, tuple[str, ...]] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class CatalogueEntry:
    """A single catalogue entry. Fifteen v2 wire-schema fields, two derived
    fields, and four optional v3 sub-objects.

    v2 entries populate the fifteen v2 wire-schema fields. The four v3
    sub-object fields default to ``None`` and remain ``None`` on v2 entries.
    v3 entries additionally populate up to four of the optional sub-objects;
    fields not declared in JSON remain ``None``.

    Attributes:
        schema: Schema discriminator. ``"openproof.act_catalogue_entry.v2"``
            for v2 entries, ``"openproof.act_catalogue_entry.v3"`` for v3
            entries.
        act_type_id: Canonical identifier under ``op:`` namespace.
        claim_type: snake_case semantic shape identifier.
        display_name: Human-readable display name.
        regulatory_citation: Optional regulatory anchor.
        required_claim_fields: Tuple of claim field names that MUST be present
            and non-empty in a manifest's claim.
        optional_claim_fields: Tuple of claim field names a manifest MAY use.
        required_evidence_labels: Tuple of evidence labels that MUST each be
            covered by at least one ``Evidence`` in a manifest.
        eligible_issuer_roles: Tuple of issuer authority labels (e.g.
            ``"essential_entity"``) that can issue this act type.
        recommended_witness_roles: Tuple of recipient roles typically
            designated as witnesses for this act type.
        signature_policy: Signature requirements.
        version: Integer version of this entry.
        supersedes: act_type_id of the entry this one supersedes, or ``None``.
        maintainer: Identifier of the entry's maintainer.
        test_vector_reference: Path or URI of the test vectors file.
        source_path: Local filesystem path the entry was loaded from. Derived,
            not part of the wire schema. Useful for debugging.
        entry_hash: ``"sha256:..."`` of the raw entry JSON file bytes. Derived
            at load time. Goes into ``CatalogueBinding.entry_hash`` at manifest
            issue time.
        regulated_context_profile: Optional v3 block constraining the receipt
            envelope ``regulated_context`` shape for this act type. ``None``
            for v2 entries and for v3 entries that do not declare the block.
        prior_receipts_profile: Optional v3 block declaring bilateral
            lifecycle expectations. ``None`` for v2 entries and for v3
            entries that do not declare the block.
        reliance_context: Optional v3 block naming the issuer role,
            counterparty action, and later verifiers. ``None`` for v2
            entries and for v3 entries that do not declare the block.
        disclosure_profile: Optional v3 block declaring per-field disclosure
            tier and back-propagation scope. ``None`` for v2 entries and for
            v3 entries that do not declare the block.
    """
    schema: str
    act_type_id: str
    claim_type: str
    display_name: str
    regulatory_citation: Optional[RegulatoryCitation]
    required_claim_fields: tuple[str, ...]
    optional_claim_fields: tuple[str, ...]
    required_evidence_labels: tuple[str, ...]
    eligible_issuer_roles: tuple[str, ...]
    recommended_witness_roles: tuple[str, ...]
    signature_policy: SignaturePolicy
    version: int
    supersedes: Optional[str]
    maintainer: str
    test_vector_reference: str
    # Derived fields:
    source_path: str = ""
    entry_hash: str = ""
    # v3 optional sub-objects (None for v2 entries; populated from JSON on v3
    # entries that declare them; remain None on v3 entries that do not).
    # Placed after derived fields to preserve positional construction for any
    # caller relying on the v2 field order (source_path, entry_hash).
    regulated_context_profile: Optional[RegulatedContextProfile] = None
    prior_receipts_profile: Optional[PriorReceiptsProfile] = None
    reliance_context: Optional[RelianceContext] = None
    disclosure_profile: Optional[DisclosureProfile] = None


@dataclass(frozen=True)
class Catalogue:
    """The loaded catalogue: indexed entries plus provenance metadata.

    Attributes:
        entries: Mapping from ``act_type_id`` to ``CatalogueEntry``.
        source_root: Filesystem path the catalogue was loaded from (the
            ``catalogue/acts/`` directory).
        source_uri: External URI of the catalogue source repository (e.g.
            GitHub URL), if known. May be ``None`` if not provided.
        git_commit: 40-character git SHA-1 of the catalogue source at load
            time, if known. May be ``None`` if the catalogue is not in a
            git working tree or the caller did not provide it.
        schema_hash: ``"sha256:..."`` of the catalogue schema file bytes.
            Empty string if the schema file could not be located.
    """
    entries: Mapping[str, CatalogueEntry]
    source_root: str
    source_uri: Optional[str]
    git_commit: Optional[str]
    schema_hash: str

    def get(self, act_type_id: str) -> Optional[CatalogueEntry]:
        """Look up an entry by ``act_type_id``. Returns ``None`` if absent."""
        return self.entries.get(act_type_id)

    def list_entries(self) -> list[CatalogueEntry]:
        """Return all entries sorted by display_name."""
        return sorted(self.entries.values(), key=lambda e: e.display_name)

    def __len__(self) -> int:
        return len(self.entries)

    def __contains__(self, act_type_id: object) -> bool:
        return act_type_id in self.entries


@dataclass(frozen=True)
class ValidationIssue:
    """One finding from manifest validation.

    Attributes:
        code: Machine-readable code, one of:

            - ``UNKNOWN_ACT_TYPE``: manifest's act_type_id not in catalogue.
            - ``ENTRY_VERSION_MISMATCH``: manifest cites a different version.
            - ``ENTRY_HASH_MISMATCH``: manifest's entry_hash differs from
              what's in the loaded catalogue.
            - ``SCHEMA_HASH_MISMATCH``: manifest's schema_hash differs from
              what's in the loaded catalogue.
            - ``MISSING_REQUIRED_CLAIM_FIELD``: a required claim field is
              absent or empty in the manifest's claim.
            - ``MISSING_REQUIRED_EVIDENCE_LABEL``: a required evidence label
              has no covering ``Evidence`` in the manifest.
            - ``UNKNOWN_EVIDENCE_LABEL``: an ``Evidence`` carries a label
              not declared by the entry (neither required nor optional).
        message: Human-readable description.
        field: JSON-Path-style location (e.g. ``"claim.decision_date"``,
            ``"evidence[2].label"``), or ``None`` for top-level issues.
    """
    code: str
    message: str
    field: Optional[str] = None


# ─────────────────────────────────────────────────────────────────
# PATH RESOLUTION
# ─────────────────────────────────────────────────────────────────

def _resolve_acts_path(explicit: Optional[Path]) -> Path:
    """Resolve the catalogue acts path from arg, env var, or fallbacks."""
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if not path.is_dir():
            raise CatalogueLoadError(
                f"acts_path {explicit!r} is not a directory (resolved to {path})"
            )
        return path

    env_value = os.environ.get(ENV_CATALOGUE_PATH)
    if env_value:
        path = Path(env_value).expanduser().resolve()
        if not path.is_dir():
            raise CatalogueLoadError(
                f"{ENV_CATALOGUE_PATH}={env_value!r} is not a directory "
                f"(resolved to {path})"
            )
        return path

    for fallback in _FALLBACK_ACTS_PATHS:
        candidate = Path(fallback).resolve()
        if candidate.is_dir():
            return candidate

    raise CatalogueLoadError(
        f"Could not locate the catalogue acts directory. "
        f"Pass acts_path explicitly, set {ENV_CATALOGUE_PATH}, "
        f"or place the catalogue at one of: {', '.join(_FALLBACK_ACTS_PATHS)}."
    )


def _resolve_schema_path(acts_path: Path) -> Optional[Path]:
    """Find the schema file relative to the acts directory.

    Tries v3 first (``act_catalogue_entry.v3.json``), falls back to v2
    (``act_catalogue_entry.v2.json``). Returns ``None`` if neither file
    exists. Catalogues that ship v3 entries should have the v3 schema file
    present; catalogues that ship only v2 entries may have only the v2
    schema file. Whichever file is found is what gets hashed into
    ``Catalogue.schema_hash``.
    """
    for relative_parts in (_SCHEMA_RELATIVE_PATH_V3, _SCHEMA_RELATIVE_PATH_V2):
        candidate = acts_path.joinpath(*relative_parts).resolve()
        if candidate.is_file():
            return candidate
    return None


# ─────────────────────────────────────────────────────────────────
# PARSING
# ─────────────────────────────────────────────────────────────────

def _parse_entry(data: dict, source_path: str, entry_hash: str) -> CatalogueEntry:
    """Build a ``CatalogueEntry`` from a parsed JSON dict.

    Accepts entries with either the v2 or v3 schema discriminator. v3 entries
    additionally parse the four optional sub-objects (``regulated_context_profile``,
    ``prior_receipts_profile``, ``reliance_context``, ``disclosure_profile``)
    into their respective dataclasses where the corresponding JSON blocks
    are present; absent blocks leave the field at ``None``. v2 entries
    never populate the v3 fields, even if the JSON happens to carry them
    (this matches the loader's general tolerance for extra dict keys; the
    v2 JSON schema file enforces strict ``additionalProperties: false`` for
    consumers that validate at the schema-file level).

    Raises:
        CatalogueLoadError: If the schema discriminator is not recognised,
            or a required field on the entry or on a present v3 sub-object
            is missing or wrong-typed.
    """
    schema_value = data.get("schema")
    if schema_value not in SCHEMA_DISCRIMINATORS:
        raise CatalogueLoadError(
            f"Not a recognised catalogue entry: schema={schema_value!r} at "
            f"{source_path}. Expected one of: {sorted(SCHEMA_DISCRIMINATORS)}"
        )

    try:
        citation_data = data.get("regulatory_citation")
        citation: Optional[RegulatoryCitation] = None
        if citation_data is not None:
            citation = RegulatoryCitation(
                instrument=citation_data["instrument"],
                article=citation_data["article"],
                jurisdiction=citation_data["jurisdiction"],
                in_force_from=citation_data["in_force_from"],
            )

        sig_data = data["signature_policy"]
        sig_policy = SignaturePolicy(
            minimum=sig_data["minimum"],
            supports=tuple(sig_data.get("supports", [])),
        )

        # v3 optional sub-objects. Populated only when the entry is v3 AND
        # the corresponding block is present in JSON. v2 entries always
        # yield None for all four (extra dict keys on v2 entries are
        # tolerated by the Python loader but ignored here; the v2 JSON
        # schema file enforces strict additionalProperties:false at
        # schema-validation time for consumers that run that check).
        regulated_context_profile: Optional[RegulatedContextProfile] = None
        prior_receipts_profile: Optional[PriorReceiptsProfile] = None
        reliance_context: Optional[RelianceContext] = None
        disclosure_profile: Optional[DisclosureProfile] = None

        if schema_value == SCHEMA_DISCRIMINATOR_V3:
            rcp_data = data.get("regulated_context_profile")
            if rcp_data is not None:
                regulated_context_profile = RegulatedContextProfile(
                    allowed_context_types=tuple(rcp_data["allowed_context_types"]),
                    allowed_submission_stages=tuple(
                        rcp_data.get("allowed_submission_stages", [])
                    ),
                    default_context_type=rcp_data.get("default_context_type"),
                )

            prp_data = data.get("prior_receipts_profile")
            if prp_data is not None:
                prior_receipts_profile = PriorReceiptsProfile(
                    required_roles=tuple(prp_data.get("required_roles", [])),
                    optional_roles=tuple(prp_data.get("optional_roles", [])),
                )

            rc_data = data.get("reliance_context")
            if rc_data is not None:
                reliance_context = RelianceContext(
                    issuer_role=rc_data["issuer_role"],
                    counterparty_action=rc_data["counterparty_action"],
                    later_verifiers=tuple(rc_data["later_verifiers"]),
                    reliance_statement=rc_data.get("reliance_statement"),
                )

            dp_data = data.get("disclosure_profile")
            if dp_data is not None:
                bps_raw = dp_data.get("back_propagation_scope") or {}
                back_prop = {
                    role: tuple(field_refs)
                    for role, field_refs in bps_raw.items()
                }
                disclosure_profile = DisclosureProfile(
                    public_fields=tuple(dp_data["public_fields"]),
                    commitment_fields=tuple(dp_data["commitment_fields"]),
                    private_fields=tuple(dp_data["private_fields"]),
                    back_propagation_scope=back_prop,
                )

        return CatalogueEntry(
            schema=schema_value,
            act_type_id=data["act_type_id"],
            claim_type=data["claim_type"],
            display_name=data["display_name"],
            regulatory_citation=citation,
            required_claim_fields=tuple(data["required_claim_fields"]),
            optional_claim_fields=tuple(data.get("optional_claim_fields", [])),
            required_evidence_labels=tuple(data["required_evidence_labels"]),
            eligible_issuer_roles=tuple(data["eligible_issuer_roles"]),
            recommended_witness_roles=tuple(data["recommended_witness_roles"]),
            signature_policy=sig_policy,
            version=int(data["version"]),
            supersedes=data.get("supersedes"),
            maintainer=data["maintainer"],
            test_vector_reference=data["test_vector_reference"],
            source_path=source_path,
            entry_hash=entry_hash,
            regulated_context_profile=regulated_context_profile,
            prior_receipts_profile=prior_receipts_profile,
            reliance_context=reliance_context,
            disclosure_profile=disclosure_profile,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CatalogueLoadError(
            f"Cannot parse catalogue entry at {source_path}: {exc}"
        ) from exc


def _scan_acts_directory(acts_path: Path) -> dict[str, CatalogueEntry]:
    """Walk the acts directory and load all v2 and v3 entries.

    Skipped:
        - Files in any ``_deprecated`` subdirectory.
        - Files matching ``*.test_vectors.json``.
        - Files whose top-level ``schema`` is not in ``SCHEMA_DISCRIMINATORS``
          (silently, as a permissive allowance for other JSON files in tree).

    Raises:
        CatalogueLoadError: If two entries share an ``act_type_id``.
    """
    entries: dict[str, CatalogueEntry] = {}

    for json_path in sorted(acts_path.rglob("*.json")):
        if "_deprecated" in json_path.parts:
            continue
        if json_path.name.endswith(".test_vectors.json"):
            continue

        try:
            raw_bytes = json_path.read_bytes()
        except OSError as exc:
            logger.warning("Could not read %s: %s", json_path, exc)
            continue

        try:
            data = json.loads(raw_bytes)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping malformed JSON at %s: %s", json_path, exc)
            continue

        if not isinstance(data, dict) or data.get("schema") not in SCHEMA_DISCRIMINATORS:
            # Could be a schema file, a README in JSON, etc. Not an error.
            continue

        entry_hash = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        entry = _parse_entry(data, str(json_path), entry_hash)

        if entry.act_type_id in entries:
            existing = entries[entry.act_type_id]
            raise CatalogueLoadError(
                f"Duplicate act_type_id {entry.act_type_id!r}: "
                f"{json_path} conflicts with {existing.source_path}"
            )

        entries[entry.act_type_id] = entry

    return entries


# ─────────────────────────────────────────────────────────────────
# PUBLIC LOADER
# ─────────────────────────────────────────────────────────────────

def load_catalogue(
    acts_path: Optional[Path] = None,
    *,
    schema_path: Optional[Path] = None,
    source_uri: Optional[str] = None,
    git_commit: Optional[str] = None,
) -> Catalogue:
    """Load the catalogue from disk.

    Args:
        acts_path: Optional path to the ``catalogue/acts/`` directory. If
            ``None``, resolves from ``$OPENPROOF_CATALOGUE_PATH`` or fallback
            locations.
        schema_path: Optional path to the schema JSON file. If ``None``,
            looks for ``../../spec/schemas/act_catalogue_entry.v3.json``
            relative to the acts path first, then falls back to
            ``act_catalogue_entry.v2.json``.
        source_uri: Optional external URI of the catalogue repository.
            Stored on the resulting ``Catalogue`` for receipt provenance.
        git_commit: Optional 40-character git SHA-1 of the catalogue at
            load time. Stored on the resulting ``Catalogue`` for receipt
            provenance.

    Returns:
        A ``Catalogue`` with all v2 and v3 entries indexed by ``act_type_id``.

    Raises:
        CatalogueLoadError: If the path cannot be resolved or contains
            structural problems (duplicate act_type_ids, malformed entries).
    """
    resolved_acts = _resolve_acts_path(acts_path)
    entries = _scan_acts_directory(resolved_acts)

    # Compute schema_hash if we can find the schema file.
    schema_hash = ""
    actual_schema_path = schema_path or _resolve_schema_path(resolved_acts)
    if actual_schema_path is not None and actual_schema_path.is_file():
        schema_hash = hash_schema_file(actual_schema_path)
    elif schema_path is not None:
        # Caller passed a path explicitly; if it doesn't exist, that's an error.
        raise CatalogueLoadError(
            f"schema_path {schema_path!r} is not a file"
        )
    # If we couldn't find the schema, schema_hash stays empty. Callers
    # populating CatalogueBinding will need to provide it some other way.

    logger.info(
        "Loaded %d catalogue entries from %s: %s",
        len(entries), resolved_acts, sorted(entries.keys()),
    )

    return Catalogue(
        entries=entries,
        source_root=str(resolved_acts),
        source_uri=source_uri,
        git_commit=git_commit,
        schema_hash=schema_hash,
    )


# ─────────────────────────────────────────────────────────────────
# HASH HELPERS
# ─────────────────────────────────────────────────────────────────

def hash_entry_file(path: Path) -> str:
    """Compute ``"sha256:..."`` of a catalogue entry file's raw bytes.

    Hashes the raw file bytes, not canonical bytes. This matches the
    git-pinned model: anyone with the catalogue at the pinned commit can
    recompute the hash with ``sha256sum`` and get the same value. Sensitive
    to file formatting (line endings, trailing newline), but stable when
    the source of truth is a git tree.

    Args:
        path: Path to the entry JSON file.

    Returns:
        ``"sha256:"`` followed by 64 lowercase hex characters.

    Raises:
        OSError: If the file cannot be read.
    """
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def hash_schema_file(path: Path) -> str:
    """Compute ``"sha256:..."`` of the catalogue schema file's raw bytes.

    Args:
        path: Path to the schema JSON file.

    Returns:
        ``"sha256:"`` followed by 64 lowercase hex characters.

    Raises:
        OSError: If the file cannot be read.
    """
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


# ─────────────────────────────────────────────────────────────────
# MANIFEST VALIDATION
# ─────────────────────────────────────────────────────────────────

def validate_manifest(
    manifest: Manifest, catalogue: Catalogue
) -> list[ValidationIssue]:
    """Validate a manifest's claim and evidence against its catalogue entry.

    Performs seven checks (see module docstring for the full list).
    Returns a list of issues; an empty list means the manifest is valid
    against the loaded catalogue.

    Catalogue conformance is one of several validation layers a complete
    verifier runs. The others are: ``validate_manifest_shape`` (structural
    well-formedness), and the receipt verifier (chain anchor, RFC 3161
    token, evidence file hashes). This module covers the catalogue layer
    only.

    Args:
        manifest: The manifest to validate.
        catalogue: The loaded catalogue to validate against.

    Returns:
        A list of ``ValidationIssue``. Empty list means valid.
    """
    issues: list[ValidationIssue] = []

    # 1. Act type known?
    entry = catalogue.get(manifest.catalogue.act_type_id)
    if entry is None:
        issues.append(
            ValidationIssue(
                code="UNKNOWN_ACT_TYPE",
                message=(
                    f"act_type_id {manifest.catalogue.act_type_id!r} is not "
                    f"in the loaded catalogue. Known act_type_ids: "
                    f"{sorted(catalogue.entries.keys())}"
                ),
                field="catalogue.act_type_id",
            )
        )
        # Can't continue any other checks without an entry.
        return issues

    # 2. Entry version matches?
    if entry.version != manifest.catalogue.entry_version:
        issues.append(
            ValidationIssue(
                code="ENTRY_VERSION_MISMATCH",
                message=(
                    f"manifest cites entry_version {manifest.catalogue.entry_version} "
                    f"but loaded catalogue has version {entry.version} for "
                    f"{manifest.catalogue.act_type_id}"
                ),
                field="catalogue.entry_version",
            )
        )

    # 3. Entry hash matches?
    if entry.entry_hash and entry.entry_hash != manifest.catalogue.entry_hash:
        issues.append(
            ValidationIssue(
                code="ENTRY_HASH_MISMATCH",
                message=(
                    f"manifest cites entry_hash {manifest.catalogue.entry_hash!r} "
                    f"but loaded catalogue entry hashes to {entry.entry_hash!r}. "
                    f"The manifest may have been issued against a different "
                    f"version of the catalogue (pinned at a different commit)."
                ),
                field="catalogue.entry_hash",
            )
        )

    # 4. Schema hash matches?
    if catalogue.schema_hash and catalogue.schema_hash != manifest.catalogue.schema_hash:
        issues.append(
            ValidationIssue(
                code="SCHEMA_HASH_MISMATCH",
                message=(
                    f"manifest cites schema_hash {manifest.catalogue.schema_hash!r} "
                    f"but loaded catalogue schema hashes to {catalogue.schema_hash!r}."
                ),
                field="catalogue.schema_hash",
            )
        )

    # 5. Required claim fields all present and non-empty?
    for required_field in entry.required_claim_fields:
        value = manifest.claim.get(required_field)
        if value is None:
            issues.append(
                ValidationIssue(
                    code="MISSING_REQUIRED_CLAIM_FIELD",
                    message=(
                        f"required claim field {required_field!r} is "
                        f"missing from manifest.claim"
                    ),
                    field=f"claim.{required_field}",
                )
            )
        elif isinstance(value, str) and not value.strip():
            issues.append(
                ValidationIssue(
                    code="MISSING_REQUIRED_CLAIM_FIELD",
                    message=(
                        f"required claim field {required_field!r} is "
                        f"empty in manifest.claim"
                    ),
                    field=f"claim.{required_field}",
                )
            )

    # 6. Required evidence labels all covered by at least one Evidence?
    attached_labels = {e.label for e in manifest.evidence}
    for required_label in entry.required_evidence_labels:
        if required_label not in attached_labels:
            issues.append(
                ValidationIssue(
                    code="MISSING_REQUIRED_EVIDENCE_LABEL",
                    message=(
                        f"required evidence label {required_label!r} has no "
                        f"covering file in manifest.evidence. Attached labels: "
                        f"{sorted(attached_labels)}"
                    ),
                    field="evidence",
                )
            )

    # 7. Each evidence label is recognised by the entry?
    known_evidence_labels = set(entry.required_evidence_labels)
    # The signature_policy.supports list contains evidence labels for
    # externally produced signature artifacts; those are also recognised.
    known_evidence_labels.update(entry.signature_policy.supports)
    for i, ev in enumerate(manifest.evidence):
        if ev.label not in known_evidence_labels:
            issues.append(
                ValidationIssue(
                    code="UNKNOWN_EVIDENCE_LABEL",
                    message=(
                        f"evidence[{i}].label {ev.label!r} is not declared "
                        f"by entry {entry.act_type_id}. Known labels: "
                        f"{sorted(known_evidence_labels)}"
                    ),
                    field=f"evidence[{i}].label",
                )
            )

    return issues
