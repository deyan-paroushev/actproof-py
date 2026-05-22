# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: Apache-2.0
"""
Load and query the actproof-events catalogue (v2 and v3 entries). Validate
manifests against entries.

A catalogue is a directory tree of JSON files; each file describes one regulated
or governance act type (NIS2 Article 20 management body approval, EUDR DDS
preparation, software release, board resolution, etc.). The catalogue is
maintained in a separate repository (actproof-events) under a permissive
license. This module reads it, indexes the entries by act_type_id, computes
content hashes for catalogue binding, and validates whether a manifest's claim
satisfies its entry's required fields and evidence labels.

Schema versions
---------------

Entries may carry one of two schema discriminators:

- ``"actproof.act_catalogue_entry.v2"`` (introduced in actproof-events
  v1.4-rc1): fifteen wire-schema fields covering claim shape, evidence,
  signature policy, regulatory citation, and provenance.
- ``"actproof.act_catalogue_entry.v3"`` (introduced in actproof-events
  v1.5-rc1): strict additive superset of v2. Adds optional blocks for
  richer act-type semantics. The blocks this loader exposes as typed
  ``CatalogueEntry`` fields are ``regulated_context_profile``,
  ``prior_receipts_profile``, ``reliance_context``, ``disclosure_profile``,
  and ``claim_field_types``.

Both are accepted by the loader. v2 entries leave the optional v3 fields on
``CatalogueEntry`` at ``None``. v3 entries populate them where the JSON
declares the corresponding blocks; absent blocks remain ``None``.

Path resolution
---------------

The catalogue is located on disk. How the bytes get there (pip-installed
``actproof-events`` package, git submodule, vendored copy, volume mount, fresh
clone in CI) is a deployment decision the library does not constrain.
Resolution order:

1. The ``acts_path`` argument to ``load_catalogue`` if provided.
2. ``$ACTPROOF_CATALOGUE_PATH`` environment variable.
3. The installed ``actproof-events`` Python package, when importable. This
   covers ``pip install actproof[events]`` and editable installs of the
   events repo.
4. ``./actproof-events/catalogue/acts/`` relative to the current working dir.
5. ``./vendor/actproof-events/catalogue/acts/`` relative to the current working dir.

The schema file is located relative to the acts path. Two layouts are
tried: ``../../spec/schemas/`` (source-tree layout where ``catalogue/`` and
``spec/`` are siblings at the repo root) and ``../../schemas/`` (installed
package layout where the wheel bundles ``catalogue/`` and ``schemas/``
side by side under ``actproof_events/data/``). Within each layout
resolution tries v3 first (``act_catalogue_entry.v3.json``), falls back to
v2 (``act_catalogue_entry.v2.json``). Whichever file is found is hashed
into ``Catalogue.schema_hash`` for receipt binding.

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

from actproof.manifest import Manifest

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

SCHEMA_DISCRIMINATOR_V2: str = "actproof.act_catalogue_entry.v2"
"""Schema discriminator for v2 catalogue entries (fifteen wire-schema fields,
no v3 sub-objects)."""

SCHEMA_DISCRIMINATOR_V3: str = "actproof.act_catalogue_entry.v3"
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
external consumers that imported this name from actproof v0.1.0 continue to
work. New code should use ``SCHEMA_DISCRIMINATOR_V2`` and
``SCHEMA_DISCRIMINATOR_V3`` directly, and ``SCHEMA_DISCRIMINATORS`` for
membership checks."""

ENV_CATALOGUE_PATH: str = "ACTPROOF_CATALOGUE_PATH"
"""Environment variable consulted for the catalogue acts path."""

_FALLBACK_ACTS_PATHS: tuple[str, ...] = (
    "actproof-events/catalogue/acts",
    "vendor/actproof-events/catalogue/acts",
)
"""Filesystem locations to try if no path is given and the env var is unset."""

_SCHEMA_RELATIVE_PATHS_V3: tuple[tuple[str, ...], ...] = (
    ("..", "..", "spec", "schemas", "act_catalogue_entry.v3.json"),
    ("..", "..", "schemas", "act_catalogue_entry.v3.json"),
)
"""Default v3 schema paths relative to the acts directory. First tuple is the
source-tree layout (``catalogue/acts/`` sibling of ``spec/schemas/`` under the
repo root). Second tuple is the installed-package layout (``data/catalogue/acts/``
sibling of ``data/schemas/`` inside the bundled wheel)."""

_SCHEMA_RELATIVE_PATHS_V2: tuple[tuple[str, ...], ...] = (
    ("..", "..", "spec", "schemas", "act_catalogue_entry.v2.json"),
    ("..", "..", "schemas", "act_catalogue_entry.v2.json"),
)
"""Default v2 schema paths relative to the acts directory, same two layouts."""

# Backward-compatible single-tuple aliases for any external consumer that
# imported the private names. Public API is via _resolve_schema_path().
_SCHEMA_RELATIVE_PATH_V3: tuple[str, ...] = _SCHEMA_RELATIVE_PATHS_V3[0]
_SCHEMA_RELATIVE_PATH_V2: tuple[str, ...] = _SCHEMA_RELATIVE_PATHS_V2[0]


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

    actproof-events v1.5-rc1 entries leave this block absent (or empty)
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
    actproof-events v1.5-rc1 entries MUST have ``private_fields = ()``
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
    fields, and the optional v3 fields.

    v2 entries populate the fifteen v2 wire-schema fields. The optional v3
    fields default to ``None`` and remain ``None`` on v2 entries. v3
    entries additionally populate the optional v3 fields wherever the JSON
    declares the corresponding block; fields not declared remain ``None``.

    Attributes:
        schema: Schema discriminator. ``"actproof.act_catalogue_entry.v2"``
            for v2 entries, ``"actproof.act_catalogue_entry.v3"`` for v3
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
        claim_field_types: Optional v3 mapping from each claim field name to
            its primitive data type (one of string, text, boolean, integer,
            number, date, datetime, email, string_list). ``None`` for v2
            entries and for v3 entries that do not declare the block. A
            consumer reading a claim field absent from the map should treat
            it as ``string``.
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
    claim_field_types: Optional[Mapping[str, str]] = None


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
        source_package_name: Optional Python distribution name of the
            package that supplied the catalogue bytes. Populated
            automatically by :func:`load_catalogue` when the catalogue is
            resolved from an installed ``actproof-events`` package (i.e.
            ``pip install actproof[events]``). ``None`` when the catalogue
            is sourced via explicit path, environment variable, or
            filesystem fallback. Callers building manifests can pass this
            value through to ``build_manifest(catalogue_source_package_name=...)``
            so the resulting receipt records pip-installable provenance
            alongside the git-based pinning.
        source_package_version: Optional version string of the source
            package at load time (e.g. ``"1.4.0rc1"``). Set whenever
            ``source_package_name`` is set; ``None`` otherwise.
    """
    entries: Mapping[str, CatalogueEntry]
    source_root: str
    source_uri: Optional[str]
    git_commit: Optional[str]
    schema_hash: str
    source_package_name: Optional[str] = None
    source_package_version: Optional[str] = None

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
            - ``SOURCE_PACKAGE_NAME_MISMATCH``: manifest pins one
              installable package name (e.g. ``"actproof-events"``) and the
              loaded catalogue was sourced from a differently-named
              package. Only fires when both sides have set the optional
              field.
            - ``SOURCE_PACKAGE_VERSION_MISMATCH``: same as above for the
              version string. Only fires when both sides have set the
              optional field.
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

def _resolve_from_packaged_events() -> Optional[Path]:
    """Try to resolve the acts path from the installed ``actproof-events`` package.

    Returns the catalogue ``acts`` directory path if the package is importable
    and exposes ``get_catalogue_path()`` (introduced in actproof-events
    v1.4.0rc1) and that path resolves to an existing directory. Returns
    ``None`` if the package is not installed, the function is absent (older
    package version), or the bundled directory cannot be located on disk.

    The returned value from ``get_catalogue_path()`` may be a :class:`Path`,
    a :class:`str`, or any :class:`os.PathLike`; we coerce via ``Path(value)``
    so future actproof-events releases that change their return type do not
    silently break catalogue resolution.

    This branch sits between the environment variable and the filesystem
    fallbacks in :func:`_resolve_acts_path`'s priority order, so callers
    using ``pip install actproof[events]`` get the bundled catalogue
    automatically while explicit configuration (constructor arg or env var)
    continues to win.
    """
    try:
        import actproof_events  # type: ignore[import-not-found]
    except ImportError:
        return None
    get_path = getattr(actproof_events, "get_catalogue_path", None)
    if get_path is None:
        return None
    try:
        raw = get_path()
    except Exception:  # pragma: no cover - defensive against package bugs
        return None
    if raw is None:
        return None
    # Coerce to Path: accepts Path, str, and os.PathLike. TypeError when
    # the return value is none of those (e.g. int) drops us back to None
    # rather than propagating.
    try:
        path = Path(raw).expanduser().resolve()
    except TypeError:
        return None
    if not path.is_dir():
        return None
    return path


def _resolve_acts_path(explicit: Optional[Path]) -> Path:
    """Resolve the catalogue acts path from arg, env var, installed package, or fallbacks."""
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

    packaged = _resolve_from_packaged_events()
    if packaged is not None:
        return packaged

    for fallback in _FALLBACK_ACTS_PATHS:
        candidate = Path(fallback).resolve()
        if candidate.is_dir():
            return candidate

    raise CatalogueLoadError(
        f"Could not locate the catalogue acts directory. "
        f"Pass acts_path explicitly, set {ENV_CATALOGUE_PATH}, "
        f"install the actproof-events package (e.g. pip install actproof[events]), "
        f"or place the catalogue at one of: {', '.join(_FALLBACK_ACTS_PATHS)}."
    )


def _resolve_schema_path(acts_path: Path) -> Optional[Path]:
    """Find the schema file relative to the acts directory.

    Tries v3 first (``act_catalogue_entry.v3.json``), falls back to v2
    (``act_catalogue_entry.v2.json``). For each version tries two layouts
    in order: the source-tree layout (``../../spec/schemas/`` from acts,
    where ``catalogue/`` and ``spec/`` are siblings at the repo root) and
    the installed-package layout (``../../schemas/`` from acts, where the
    wheel bundles ``catalogue/acts/`` and ``schemas/`` side by side under
    ``actproof_events/data/``).

    Returns ``None`` if no candidate file exists. Catalogues that ship v3
    entries should have the v3 schema file present; catalogues that ship
    only v2 entries may have only the v2 schema file. Whichever file is
    found is what gets hashed into ``Catalogue.schema_hash``.
    """
    for relative_parts in (*_SCHEMA_RELATIVE_PATHS_V3, *_SCHEMA_RELATIVE_PATHS_V2):
        candidate = acts_path.joinpath(*relative_parts).resolve()
        if candidate.is_file():
            return candidate
    return None


def _resolve_schema_paths(acts_path: Path) -> dict[str, Path]:
    """Resolve the schema file for each entry schema version.

    Returns a mapping from schema discriminator to the schema file found
    on disk, for whichever of the v2 and v3 schema files are present next
    to the catalogue. Used to build per-version validators for load-time
    schema validation.

    This is distinct from :func:`_resolve_schema_path`, which returns the
    single file hashed into ``Catalogue.schema_hash``. Both consult the
    same source-tree and installed-package layouts.
    """
    resolved: dict[str, Path] = {}
    for discriminator, relative_sets in (
        (SCHEMA_DISCRIMINATOR_V3, _SCHEMA_RELATIVE_PATHS_V3),
        (SCHEMA_DISCRIMINATOR_V2, _SCHEMA_RELATIVE_PATHS_V2),
    ):
        for relative_parts in relative_sets:
            candidate = acts_path.joinpath(*relative_parts).resolve()
            if candidate.is_file():
                resolved[discriminator] = candidate
                break
    return resolved


def _build_schema_validators(
    schema_paths: Mapping[str, Path],
) -> dict[str, object]:
    """Build a JSON Schema validator for each resolved schema file.

    The ``jsonschema`` package is imported here, not at module import time,
    so that importing :mod:`actproof.catalogue` never requires
    ``jsonschema``. The package is needed only when ``load_catalogue`` runs
    with ``validate_schema=True`` (the default). A clear, actionable error
    is raised if the package is absent.

    Returns a mapping from schema discriminator to a
    ``jsonschema.Draft202012Validator``. Each schema file is itself checked
    against the 2020-12 metaschema before use.

    Raises:
        CatalogueLoadError: If ``jsonschema`` is not installed, or a schema
            file cannot be read, parsed, or is not a valid JSON Schema.
    """
    try:
        from jsonschema.exceptions import SchemaError
        from jsonschema.validators import Draft202012Validator
    except ImportError as exc:
        raise CatalogueLoadError(
            "Schema validation was requested (validate_schema=True) but the "
            "'jsonschema' package is not installed. Install it with "
            "'pip install jsonschema', or call "
            "load_catalogue(validate_schema=False) to skip validation."
        ) from exc

    validators: dict[str, object] = {}
    for discriminator, schema_path in schema_paths.items():
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
        except (OSError, json.JSONDecodeError, SchemaError) as exc:
            raise CatalogueLoadError(
                f"Cannot load catalogue schema {schema_path}: {exc}"
            ) from exc
        validators[discriminator] = Draft202012Validator(schema)
    return validators


# ─────────────────────────────────────────────────────────────────
# PARSING
# ─────────────────────────────────────────────────────────────────

def _parse_entry(data: dict, source_path: str, entry_hash: str) -> CatalogueEntry:
    """Build a ``CatalogueEntry`` from a parsed JSON dict.

    Accepts entries with either the v2 or v3 schema discriminator. v3 entries
    additionally parse the optional v3 blocks (``regulated_context_profile``,
    ``prior_receipts_profile``, ``reliance_context``, ``disclosure_profile``,
    and ``claim_field_types``) where the corresponding JSON blocks are
    present; absent blocks leave the field at ``None``. v2 entries
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
        claim_field_types: Optional[Mapping[str, str]] = None

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

            cft_data = data.get("claim_field_types")
            if cft_data is not None:
                claim_field_types = dict(cft_data)

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
            claim_field_types=claim_field_types,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CatalogueLoadError(
            f"Cannot parse catalogue entry at {source_path}: {exc}"
        ) from exc


def _scan_acts_directory(
    acts_path: Path,
    *,
    schema_validators: Optional[Mapping[str, object]] = None,
) -> dict[str, CatalogueEntry]:
    """Walk the acts directory and load all v2 and v3 entries.

    Skipped:
        - Files in any ``_deprecated`` subdirectory.
        - Files matching ``*.test_vectors.json``.
        - Files whose top-level ``schema`` is not in ``SCHEMA_DISCRIMINATORS``
          (silently, as a permissive allowance for other JSON files in tree).

    Args:
        acts_path: The ``catalogue/acts/`` directory to walk.
        schema_validators: Optional mapping from schema discriminator to a
            JSON Schema validator. When provided, every recognised entry is
            validated against the validator for its discriminator before it
            is parsed, and a non-conforming entry stops the load. When
            ``None``, no schema validation is performed.

    Raises:
        CatalogueLoadError: If two entries share an ``act_type_id``, or if
            schema validation is enabled and an entry does not conform to
            its declared JSON Schema.
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

        if schema_validators is not None:
            validator = schema_validators.get(data["schema"])
            if validator is None:
                raise CatalogueLoadError(
                    f"Schema validation is enabled but no schema file was "
                    f"found for {data['schema']!r}, needed to validate "
                    f"{json_path}. Ship the matching schema file with the "
                    f"catalogue, or load with validate_schema=False."
                )
            schema_errors = sorted(
                validator.iter_errors(data),
                key=lambda err: list(err.path),
            )
            if schema_errors:
                detail = "; ".join(
                    f"{'/'.join(str(p) for p in err.path) or '(root)'}: "
                    f"{err.message}"
                    for err in schema_errors
                )
                raise CatalogueLoadError(
                    f"Catalogue entry {json_path} does not conform to the "
                    f"{data['schema']} JSON Schema: {detail}"
                )

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
    validate_schema: bool = True,
) -> Catalogue:
    """Load the catalogue from disk.

    Args:
        acts_path: Optional path to the ``catalogue/acts/`` directory. If
            ``None``, resolves from ``$ACTPROOF_CATALOGUE_PATH`` or fallback
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
        validate_schema: When ``True`` (the default), every catalogue entry
            is validated against its declared JSON Schema at load time, and
            a non-conforming entry stops the load with ``CatalogueLoadError``.
            This makes the reference loader refuse to surface non-conforming
            entries, the behaviour conforming loaders in other languages are
            expected to match. Requires the ``jsonschema`` package and the
            schema files to be present next to the catalogue. Pass ``False``
            to skip validation, for development or for environments without
            the schema files or ``jsonschema``.

    Returns:
        A ``Catalogue`` with all v2 and v3 entries indexed by ``act_type_id``.
        When the catalogue was resolved from the installed
        ``actproof-events`` package (priority 3 in the resolution order),
        the returned ``Catalogue`` also carries ``source_package_name`` and
        ``source_package_version`` set to that package's distribution name
        and version. Callers can pass these to ``build_manifest`` so
        receipts record pip-installable provenance alongside the existing
        git-based catalogue pinning.

    Raises:
        CatalogueLoadError: If the path cannot be resolved or contains
            structural problems (duplicate act_type_ids, malformed entries);
            if ``validate_schema`` is ``True`` and an entry does not conform
            to its JSON Schema; or if ``validate_schema`` is ``True`` and the
            schema files or the ``jsonschema`` package are unavailable.
    """
    resolved_acts = _resolve_acts_path(acts_path)

    # Load-time schema validation. On by default: an entry that does not
    # conform to its declared JSON Schema stops the load. This makes the
    # reference loader refuse to surface non-conforming entries, which is
    # the behaviour conforming loaders are expected to match. Pass
    # validate_schema=False to skip it.
    schema_validators: Optional[Mapping[str, object]] = None
    if validate_schema:
        validation_schema_paths = _resolve_schema_paths(resolved_acts)
        if not validation_schema_paths:
            raise CatalogueLoadError(
                f"validate_schema is True but no catalogue entry schema file "
                f"was found next to {resolved_acts}. Expected "
                f"act_catalogue_entry.v3.json (and/or the v2 file) under the "
                f"catalogue's spec/schemas directory. Ship the schema with "
                f"the catalogue, or call load_catalogue(validate_schema=False)."
            )
        schema_validators = _build_schema_validators(validation_schema_paths)

    entries = _scan_acts_directory(
        resolved_acts, schema_validators=schema_validators
    )

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

    # Detect pip-installable provenance: if no explicit path was given and
    # the resolved acts path came from the actproof-events Python package,
    # record the package name and version so receipts can pin to
    # ``pip install actproof-events==<version>`` alongside the git pinning.
    # This is best-effort and never raises: receipts can still be built
    # without these fields by callers who source the catalogue via git
    # submodule, vendoring, or volume mount.
    source_package_name: Optional[str] = None
    source_package_version: Optional[str] = None
    if acts_path is None:
        packaged = _resolve_from_packaged_events()
        if packaged is not None and packaged == resolved_acts:
            # Read the version from the installed distribution metadata
            # rather than the package's __version__ attribute. The
            # distribution metadata is the authoritative source (set at
            # install time from pyproject.toml or the wheel metadata);
            # the __version__ attribute is convenience that may or may
            # not be set, and can drift from the metadata if the package
            # forgot to update one side. importlib.metadata is in the
            # standard library from Python 3.8 onward.
            from importlib.metadata import PackageNotFoundError, version
            try:
                source_package_version = version("actproof-events")
                source_package_name = "actproof-events"
            except PackageNotFoundError:
                # The package files are present on disk (we resolved
                # the path through _resolve_from_packaged_events) but
                # the distribution metadata is missing. This is a
                # corner case for editable installs that did not run
                # ``pip install -e .`` correctly, or for namespace
                # packages without distribution metadata. Fall through
                # silently: the catalogue still loads, callers just
                # get no package provenance.
                pass

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
        source_package_name=source_package_name,
        source_package_version=source_package_version,
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

    Performs up to nine checks. Seven always run; two additional ones
    (SOURCE_PACKAGE_NAME_MISMATCH, SOURCE_PACKAGE_VERSION_MISMATCH) only
    fire when both the manifest and the loaded catalogue carry the
    optional package-provenance fields. See the ``ValidationIssue``
    docstring for the full code list. Returns a list of issues; an
    empty list means the manifest is valid against the loaded catalogue.

    The two package-provenance checks are diagnostic. The cryptographic
    binding between a manifest and the catalogue bytes it implements is
    ``entry_hash`` and ``schema_hash``; those checks already cover any
    byte-level drift. The package name and version checks give a
    clearer error message when the operator's environment has a
    different installed version than the issuer used at issue time.

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

    # 4a. Source package name matches (only when both sides have set it)?
    # The optional source_package_name and source_package_version fields
    # are pip-installable-provenance metadata. They are NOT a substitute
    # for the cryptographic entry_hash and schema_hash checks above; the
    # bytes binding is still authoritative. These two checks give
    # operators a clearer diagnostic when a mismatch occurs ("you have
    # actproof-events 1.4.1 installed but the receipt was issued against
    # 1.4.0rc1") than the entry_hash mismatch alone would.
    if (
        manifest.catalogue.source_package_name
        and catalogue.source_package_name
        and manifest.catalogue.source_package_name != catalogue.source_package_name
    ):
        issues.append(
            ValidationIssue(
                code="SOURCE_PACKAGE_NAME_MISMATCH",
                message=(
                    f"manifest pins source_package_name "
                    f"{manifest.catalogue.source_package_name!r} but loaded "
                    f"catalogue was sourced from {catalogue.source_package_name!r}. "
                    f"This is package-provenance metadata, not a cryptographic "
                    f"binding (entry_hash already covers the bytes), but indicates "
                    f"the operator's environment differs from the issuer's."
                ),
                field="catalogue.source_package_name",
            )
        )

    # 4b. Source package version matches (only when both sides have set it)?
    if (
        manifest.catalogue.source_package_version
        and catalogue.source_package_version
        and manifest.catalogue.source_package_version != catalogue.source_package_version
    ):
        issues.append(
            ValidationIssue(
                code="SOURCE_PACKAGE_VERSION_MISMATCH",
                message=(
                    f"manifest pins source_package_version "
                    f"{manifest.catalogue.source_package_version!r} but loaded "
                    f"catalogue was sourced from version "
                    f"{catalogue.source_package_version!r}. "
                    f"This is package-provenance metadata, not a cryptographic "
                    f"binding (entry_hash already covers the bytes), but signals "
                    f"that ``pip install`` with the receipt's pinned version may "
                    f"be required to reproduce byte-for-byte."
                ),
                field="catalogue.source_package_version",
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
