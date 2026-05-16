# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Tests for the v3 catalogue surface added in openproof v0.1.1.

The existing ``tests/test_catalogue.py`` covers the v2 surface and remains
unchanged. This file covers everything added in v0.1.1:

* TestV3Dataclasses: construction, immutability, and field defaults for the
  four new frozen dataclasses (``RegulatedContextProfile``,
  ``PriorReceiptsProfile``, ``RelianceContext``, ``DisclosureProfile``).
* TestDiscriminatorConstants: ``SCHEMA_DISCRIMINATOR_V2``,
  ``SCHEMA_DISCRIMINATOR_V3``, ``SCHEMA_DISCRIMINATORS``, and the
  backward-compat alias ``SCHEMA_DISCRIMINATOR``.
* TestParseV3Entry: a v3 entry with all four optional blocks parses to the
  expected dataclass values. Partial v3 entries (only some blocks declared)
  leave the undeclared fields at ``None``. Empty optional blocks
  (``back_propagation_scope = {}``) parse to empty mappings.
* TestParseRobustness: missing required fields inside a present v3 sub-object
  raise ``CatalogueLoadError`` with the offending field name in the message.
  Unknown discriminators raise a message naming both accepted discriminators.
* TestSchemaPathResolution: the v3 schema file is preferred when both v2 and
  v3 files exist. Falls back to v2 when only v2 is present. Returns ``None``
  when neither is present.
* TestMixedCatalogue: v2 and v3 entries coexist in one catalogue. The walker
  silently skips files whose ``schema`` field is not in
  ``SCHEMA_DISCRIMINATORS``.
* TestBackwardCompat: v2-only catalogues load identically to v0.1.0 with all
  four v3 fields on every ``CatalogueEntry`` at ``None``. v2 entries that
  happen to carry v3 blocks have those blocks ignored. The old
  ``SCHEMA_DISCRIMINATOR`` name still imports and equals v2.
* TestRealV1_4Catalogue: against the real openproof-events v1.4-rc1
  catalogue (skipped if not available), every entry parses as v2 and all
  four v3 fields are ``None``.

Synthetic catalogues are built in pytest's ``tmp_path``. The
``_write_v3_entry`` and ``_write_v2_entry`` helpers mirror the
``_write_entry`` helper in ``test_catalogue.py``.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from openproof.catalogue import (
    SCHEMA_DISCRIMINATOR,
    SCHEMA_DISCRIMINATOR_V2,
    SCHEMA_DISCRIMINATOR_V3,
    SCHEMA_DISCRIMINATORS,
    CatalogueLoadError,
    DisclosureProfile,
    PriorReceiptsProfile,
    RegulatedContextProfile,
    RelianceContext,
    hash_schema_file,
    load_catalogue,
)

# Used by TestRealV1_4Catalogue; skipped if the catalogue is not available.
from tests import (
    REAL_ACTS_PATH,
    skip_if_no_real_catalogue as pytestmark_real_catalogue,
)

# ``_parse_entry`` is private. Imported only by TestParseRobustness to assert
# the defensive discriminator-check error message. The walker path
# (``load_catalogue``) does not exercise this branch because unknown
# discriminators are silently skipped at the walker level.
from openproof.catalogue import _parse_entry as _parse_entry_internal


# ─────────────────────────────────────────────────────────────────
# Helpers: write v2/v3 entries and schema files into tmp_path
# ─────────────────────────────────────────────────────────────────

def _base_entry_dict(
    act_type_id: str,
    *,
    schema: str,
    version: int = 1,
) -> dict:
    """Return the dict shared by v2 and v3 minimal entries."""
    return {
        "schema": schema,
        "act_type_id": act_type_id,
        "claim_type": "test_claim",
        "display_name": f"Test entry for {act_type_id}",
        "regulatory_citation": None,
        "required_claim_fields": ["field_a"],
        "optional_claim_fields": [],
        "required_evidence_labels": ["label_a"],
        "eligible_issuer_roles": ["test_role"],
        "recommended_witness_roles": [],
        "signature_policy": {"minimum": "issuer_record", "supports": []},
        "version": version,
        "supersedes": None,
        "maintainer": "test",
        "test_vector_reference": "tests/fixtures/test.test_vectors.json",
    }


def _write_v2_entry(target_dir: Path, act_type_id: str, **kwargs) -> Path:
    """Write a minimal v2 entry. Returns its Path."""
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = act_type_id.replace("op:", "").replace(":", "_") + ".v1.json"
    path = target_dir / filename
    data = _base_entry_dict(act_type_id, schema=SCHEMA_DISCRIMINATOR_V2, **kwargs)
    path.write_text(json.dumps(data, indent=2))
    return path


def _write_v3_entry(
    target_dir: Path,
    act_type_id: str,
    *,
    version: int = 1,
    regulated_context_profile: dict | None = None,
    prior_receipts_profile: dict | None = None,
    reliance_context: dict | None = None,
    disclosure_profile: dict | None = None,
    extras: dict | None = None,
) -> Path:
    """Write a v3 entry. Optional blocks omitted from JSON when ``None``."""
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = act_type_id.replace("op:", "").replace(":", "_") + ".v1.json"
    path = target_dir / filename
    data = _base_entry_dict(act_type_id, schema=SCHEMA_DISCRIMINATOR_V3, version=version)
    if regulated_context_profile is not None:
        data["regulated_context_profile"] = regulated_context_profile
    if prior_receipts_profile is not None:
        data["prior_receipts_profile"] = prior_receipts_profile
    if reliance_context is not None:
        data["reliance_context"] = reliance_context
    if disclosure_profile is not None:
        data["disclosure_profile"] = disclosure_profile
    if extras is not None:
        data.update(extras)
    path.write_text(json.dumps(data, indent=2))
    return path


def _write_v2_schema(target_dir: Path) -> Path:
    """Write a placeholder v2 schema file at the conventional location."""
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / "act_catalogue_entry.v2.json"
    path.write_bytes(b'{"$schema":"placeholder-v2"}')
    return path


def _write_v3_schema(target_dir: Path) -> Path:
    """Write a placeholder v3 schema file at the conventional location."""
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / "act_catalogue_entry.v3.json"
    path.write_bytes(b'{"$schema":"placeholder-v3"}')
    return path


def _make_layout(tmp_path: Path) -> tuple[Path, Path]:
    """Return (acts_dir, schemas_dir) at the standard openproof-events layout."""
    acts = tmp_path / "openproof-events" / "catalogue" / "acts"
    schemas = tmp_path / "openproof-events" / "spec" / "schemas"
    return acts, schemas


# Reusable substantive sub-object payloads for the "full v3 entry" tests.

_FULL_RCP = {
    "allowed_context_types": ["release_or_publication"],
    "allowed_submission_stages": ["prepared", "published", "superseded", "withdrawn"],
    "default_context_type": "release_or_publication",
}

_FULL_PRP = {
    "required_roles": [],
    "optional_roles": ["upstream_dependency_release"],
}

_FULL_RC = {
    "issuer_role": "open-source maintainer issuing a release attestation",
    "counterparty_action": "downstream consumer accepts the release for packaging",
    "later_verifiers": ["grant_evaluator", "downstream_integrator", "public_archive"],
    "reliance_statement": (
        "The named release was published at the stated commit on the stated date."
    ),
}

_FULL_DP = {
    "public_fields": [
        "release_org",
        "release_repository",
        "release_version",
        "release_commit_sha",
        "release_published_at",
        "manifest.title",
        "manifest.issuer.legal_name",
    ],
    "commitment_fields": [],
    "private_fields": [],
    "back_propagation_scope": {
        "upstream_dependency_release": ["manifest.claim.release_version"],
    },
}


# ─────────────────────────────────────────────────────────────────
# Group 1: v3 dataclass construction, immutability, defaults
# ─────────────────────────────────────────────────────────────────

class TestV3Dataclasses:

    def test_regulated_context_profile_constructs(self) -> None:
        rcp = RegulatedContextProfile(
            allowed_context_types=("release_or_publication",),
            allowed_submission_stages=("prepared", "published"),
            default_context_type="release_or_publication",
        )
        assert rcp.allowed_context_types == ("release_or_publication",)
        assert rcp.allowed_submission_stages == ("prepared", "published")
        assert rcp.default_context_type == "release_or_publication"

    def test_regulated_context_profile_defaults(self) -> None:
        rcp = RegulatedContextProfile(allowed_context_types=("incident_lifecycle",))
        assert rcp.allowed_submission_stages == ()
        assert rcp.default_context_type is None

    def test_regulated_context_profile_frozen(self) -> None:
        rcp = RegulatedContextProfile(allowed_context_types=("incident_lifecycle",))
        with pytest.raises(FrozenInstanceError):
            rcp.allowed_context_types = ()  # type: ignore[misc]

    def test_prior_receipts_profile_all_defaults(self) -> None:
        prp = PriorReceiptsProfile()
        assert prp.required_roles == ()
        assert prp.optional_roles == ()

    def test_prior_receipts_profile_with_values(self) -> None:
        prp = PriorReceiptsProfile(
            required_roles=("supplier_dispatch_evidence",),
            optional_roles=("audit_witness",),
        )
        assert prp.required_roles == ("supplier_dispatch_evidence",)
        assert prp.optional_roles == ("audit_witness",)

    def test_prior_receipts_profile_frozen(self) -> None:
        prp = PriorReceiptsProfile()
        with pytest.raises(FrozenInstanceError):
            prp.required_roles = ("x",)  # type: ignore[misc]

    def test_reliance_context_required_fields(self) -> None:
        rc = RelianceContext(
            issuer_role="EU operator",
            counterparty_action="competent authority records the DDS",
            later_verifiers=("regulator", "downstream_buyer"),
        )
        assert rc.issuer_role == "EU operator"
        assert rc.counterparty_action == "competent authority records the DDS"
        assert rc.later_verifiers == ("regulator", "downstream_buyer")

    def test_reliance_context_optional_statement_default_none(self) -> None:
        rc = RelianceContext(
            issuer_role="x",
            counterparty_action="y",
            later_verifiers=("z",),
        )
        assert rc.reliance_statement is None

    def test_reliance_context_frozen(self) -> None:
        rc = RelianceContext(
            issuer_role="x", counterparty_action="y", later_verifiers=("z",)
        )
        with pytest.raises(FrozenInstanceError):
            rc.issuer_role = "w"  # type: ignore[misc]

    def test_disclosure_profile_constructs(self) -> None:
        dp = DisclosureProfile(
            public_fields=("a", "b"),
            commitment_fields=("c",),
            private_fields=("d",),
        )
        assert dp.public_fields == ("a", "b")
        assert dp.commitment_fields == ("c",)
        assert dp.private_fields == ("d",)

    def test_disclosure_profile_back_propagation_default_empty(self) -> None:
        dp = DisclosureProfile(public_fields=(), commitment_fields=(), private_fields=())
        assert dict(dp.back_propagation_scope) == {}

    def test_disclosure_profile_with_back_propagation_scope(self) -> None:
        dp = DisclosureProfile(
            public_fields=(),
            commitment_fields=(),
            private_fields=(),
            back_propagation_scope={
                "supplier_dispatch_evidence": ("manifest.claim.country",),
                "audit_witness": ("manifest.claim.commodity",),
            },
        )
        assert dp.back_propagation_scope["supplier_dispatch_evidence"] == (
            "manifest.claim.country",
        )
        assert dp.back_propagation_scope["audit_witness"] == (
            "manifest.claim.commodity",
        )

    def test_disclosure_profile_frozen(self) -> None:
        dp = DisclosureProfile(public_fields=(), commitment_fields=(), private_fields=())
        with pytest.raises(FrozenInstanceError):
            dp.public_fields = ("x",)  # type: ignore[misc]

    def test_disclosure_profile_each_default_factory_is_independent(self) -> None:
        """The default_factory=dict must yield a fresh dict per instance."""
        dp_a = DisclosureProfile(public_fields=(), commitment_fields=(), private_fields=())
        dp_b = DisclosureProfile(public_fields=(), commitment_fields=(), private_fields=())
        assert dp_a.back_propagation_scope is not dp_b.back_propagation_scope


# ─────────────────────────────────────────────────────────────────
# Group 2: discriminator constants
# ─────────────────────────────────────────────────────────────────

class TestDiscriminatorConstants:

    def test_v2_value(self) -> None:
        assert SCHEMA_DISCRIMINATOR_V2 == "openproof.act_catalogue_entry.v2"

    def test_v3_value(self) -> None:
        assert SCHEMA_DISCRIMINATOR_V3 == "openproof.act_catalogue_entry.v3"

    def test_discriminators_set_membership(self) -> None:
        assert SCHEMA_DISCRIMINATOR_V2 in SCHEMA_DISCRIMINATORS
        assert SCHEMA_DISCRIMINATOR_V3 in SCHEMA_DISCRIMINATORS
        assert "openproof.act_catalogue_entry.v999" not in SCHEMA_DISCRIMINATORS
        assert "" not in SCHEMA_DISCRIMINATORS
        assert None not in SCHEMA_DISCRIMINATORS

    def test_discriminators_is_frozenset(self) -> None:
        assert isinstance(SCHEMA_DISCRIMINATORS, frozenset)
        assert len(SCHEMA_DISCRIMINATORS) == 2

    def test_backward_compat_alias_equals_v2(self) -> None:
        """``SCHEMA_DISCRIMINATOR`` is retained as an alias for v2 so that
        external consumers that imported it from openproof v0.1.0 continue
        to work."""
        assert SCHEMA_DISCRIMINATOR == SCHEMA_DISCRIMINATOR_V2


# ─────────────────────────────────────────────────────────────────
# Group 3: parsing v3 entries
# ─────────────────────────────────────────────────────────────────

class TestParseV3Entry:

    def test_full_v3_entry_parses_all_four_blocks(self, tmp_path: Path) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(
            acts / "test",
            "op:test.full.v1",
            regulated_context_profile=_FULL_RCP,
            prior_receipts_profile=_FULL_PRP,
            reliance_context=_FULL_RC,
            disclosure_profile=_FULL_DP,
        )
        _write_v3_schema(schemas)

        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:test.full.v1")
        assert entry is not None
        assert entry.schema == SCHEMA_DISCRIMINATOR_V3

        assert entry.regulated_context_profile == RegulatedContextProfile(
            allowed_context_types=("release_or_publication",),
            allowed_submission_stages=("prepared", "published", "superseded", "withdrawn"),
            default_context_type="release_or_publication",
        )
        assert entry.prior_receipts_profile == PriorReceiptsProfile(
            required_roles=(),
            optional_roles=("upstream_dependency_release",),
        )
        assert entry.reliance_context == RelianceContext(
            issuer_role=_FULL_RC["issuer_role"],
            counterparty_action=_FULL_RC["counterparty_action"],
            later_verifiers=tuple(_FULL_RC["later_verifiers"]),
            reliance_statement=_FULL_RC["reliance_statement"],
        )
        assert entry.disclosure_profile is not None
        assert entry.disclosure_profile.public_fields == tuple(_FULL_DP["public_fields"])
        assert entry.disclosure_profile.commitment_fields == ()
        assert entry.disclosure_profile.private_fields == ()
        assert dict(entry.disclosure_profile.back_propagation_scope) == {
            "upstream_dependency_release": ("manifest.claim.release_version",),
        }

    def test_v3_entry_with_no_optional_blocks(self, tmp_path: Path) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(acts / "test", "op:test.minimal.v1")
        _write_v3_schema(schemas)

        entry = load_catalogue(acts_path=acts).get("op:test.minimal.v1")
        assert entry is not None
        assert entry.schema == SCHEMA_DISCRIMINATOR_V3
        assert entry.regulated_context_profile is None
        assert entry.prior_receipts_profile is None
        assert entry.reliance_context is None
        assert entry.disclosure_profile is None

    def test_v3_entry_with_only_disclosure_profile(self, tmp_path: Path) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(
            acts / "test",
            "op:test.disc_only.v1",
            disclosure_profile={
                "public_fields": ["a"],
                "commitment_fields": ["b"],
                "private_fields": [],
            },
        )
        _write_v3_schema(schemas)

        entry = load_catalogue(acts_path=acts).get("op:test.disc_only.v1")
        assert entry is not None
        assert entry.regulated_context_profile is None
        assert entry.prior_receipts_profile is None
        assert entry.reliance_context is None
        assert entry.disclosure_profile is not None
        assert entry.disclosure_profile.public_fields == ("a",)
        assert entry.disclosure_profile.commitment_fields == ("b",)
        assert entry.disclosure_profile.private_fields == ()

    def test_v3_entry_with_only_reliance_context(self, tmp_path: Path) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(
            acts / "test",
            "op:test.rc_only.v1",
            reliance_context={
                "issuer_role": "x",
                "counterparty_action": "y",
                "later_verifiers": ["z"],
            },
        )
        _write_v3_schema(schemas)

        entry = load_catalogue(acts_path=acts).get("op:test.rc_only.v1")
        assert entry is not None
        assert entry.reliance_context is not None
        assert entry.reliance_context.reliance_statement is None
        assert entry.disclosure_profile is None

    def test_disclosure_profile_back_propagation_scope_values_are_tuples(
        self, tmp_path: Path
    ) -> None:
        """``back_propagation_scope`` lists in JSON must become tuples on the
        dataclass, matching the rest of the project's immutability
        convention."""
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(
            acts / "test",
            "op:test.bps.v1",
            disclosure_profile={
                "public_fields": [],
                "commitment_fields": [],
                "private_fields": [],
                "back_propagation_scope": {
                    "role_a": ["f1", "f2"],
                    "role_b": [],
                },
            },
        )
        _write_v3_schema(schemas)

        entry = load_catalogue(acts_path=acts).get("op:test.bps.v1")
        assert entry is not None
        assert entry.disclosure_profile is not None
        scope = entry.disclosure_profile.back_propagation_scope
        assert isinstance(scope["role_a"], tuple)
        assert scope["role_a"] == ("f1", "f2")
        assert isinstance(scope["role_b"], tuple)
        assert scope["role_b"] == ()

    def test_disclosure_profile_omitted_back_propagation_yields_empty_dict(
        self, tmp_path: Path
    ) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(
            acts / "test",
            "op:test.no_bps.v1",
            disclosure_profile={
                "public_fields": [],
                "commitment_fields": [],
                "private_fields": [],
            },
        )
        _write_v3_schema(schemas)

        entry = load_catalogue(acts_path=acts).get("op:test.no_bps.v1")
        assert entry is not None
        assert entry.disclosure_profile is not None
        assert dict(entry.disclosure_profile.back_propagation_scope) == {}


# ─────────────────────────────────────────────────────────────────
# Group 4: parse robustness — malformed v3 sub-objects raise
# ─────────────────────────────────────────────────────────────────

class TestParseRobustness:

    def test_missing_reliance_context_required_field_raises(
        self, tmp_path: Path
    ) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(
            acts / "test",
            "op:test.bad_rc.v1",
            reliance_context={
                # missing required "issuer_role"
                "counterparty_action": "x",
                "later_verifiers": ["regulator"],
            },
        )
        _write_v3_schema(schemas)

        with pytest.raises(CatalogueLoadError) as exc:
            load_catalogue(acts_path=acts)
        assert "issuer_role" in str(exc.value)

    def test_missing_disclosure_profile_required_field_raises(
        self, tmp_path: Path
    ) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(
            acts / "test",
            "op:test.bad_dp.v1",
            disclosure_profile={
                "public_fields": ["x"],
                "commitment_fields": [],
                # missing required "private_fields"
            },
        )
        _write_v3_schema(schemas)

        with pytest.raises(CatalogueLoadError) as exc:
            load_catalogue(acts_path=acts)
        assert "private_fields" in str(exc.value)

    def test_missing_regulated_context_profile_required_field_raises(
        self, tmp_path: Path
    ) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(
            acts / "test",
            "op:test.bad_rcp.v1",
            regulated_context_profile={
                # missing required "allowed_context_types"
                "default_context_type": "release_or_publication",
            },
        )
        _write_v3_schema(schemas)

        with pytest.raises(CatalogueLoadError) as exc:
            load_catalogue(acts_path=acts)
        assert "allowed_context_types" in str(exc.value)

    def test_unknown_discriminator_raises_via_internal_parse(self) -> None:
        """The walker silently skips files whose ``schema`` is not in
        ``SCHEMA_DISCRIMINATORS`` (see TestMixedCatalogue). The defensive
        error message in ``_parse_entry`` is reachable only via a direct
        call. Documented here to lock the message shape so any future
        loader that calls ``_parse_entry`` directly gets a helpful error."""
        with pytest.raises(CatalogueLoadError) as exc:
            _parse_entry_internal(
                {"schema": "openproof.act_catalogue_entry.v999"},
                "/fake/path.json",
                "sha256:dummy",
            )
        msg = str(exc.value)
        assert "Not a recognised catalogue entry" in msg
        assert SCHEMA_DISCRIMINATOR_V2 in msg
        assert SCHEMA_DISCRIMINATOR_V3 in msg


# ─────────────────────────────────────────────────────────────────
# Group 5: schema path resolution prefers v3
# ─────────────────────────────────────────────────────────────────

class TestSchemaPathResolution:

    def test_v3_schema_preferred_when_both_present(self, tmp_path: Path) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(acts / "test", "op:test.entry.v1")
        v2_schema = _write_v2_schema(schemas)
        v3_schema = _write_v3_schema(schemas)

        cat = load_catalogue(acts_path=acts)
        assert cat.schema_hash == hash_schema_file(v3_schema)
        assert cat.schema_hash != hash_schema_file(v2_schema)

    def test_falls_back_to_v2_when_only_v2_present(self, tmp_path: Path) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v2_entry(acts / "test", "op:test.entry.v1")
        v2_schema = _write_v2_schema(schemas)

        cat = load_catalogue(acts_path=acts)
        assert cat.schema_hash == hash_schema_file(v2_schema)

    def test_returns_empty_when_neither_schema_present(self, tmp_path: Path) -> None:
        """If neither schema file is on disk, ``schema_hash`` is empty.
        Callers can supply a hash some other way (e.g. by passing an
        explicit ``schema_path``)."""
        acts, _schemas = _make_layout(tmp_path)
        _write_v2_entry(acts / "test", "op:test.entry.v1")
        # Deliberately do NOT write any schema file.

        cat = load_catalogue(acts_path=acts)
        assert cat.schema_hash == ""

    def test_explicit_schema_path_overrides_auto_resolution(
        self, tmp_path: Path
    ) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(acts / "test", "op:test.entry.v1")
        _write_v3_schema(schemas)
        v2_schema = _write_v2_schema(schemas)

        cat = load_catalogue(acts_path=acts, schema_path=v2_schema)
        assert cat.schema_hash == hash_schema_file(v2_schema)


# ─────────────────────────────────────────────────────────────────
# Group 6: mixed catalogue (v2 + v3 entries coexist)
# ─────────────────────────────────────────────────────────────────

class TestMixedCatalogue:

    def test_v2_and_v3_entries_coexist(self, tmp_path: Path) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v2_entry(acts / "test", "op:test.v2_entry.v1")
        _write_v3_entry(
            acts / "test",
            "op:test.v3_entry.v1",
            reliance_context={
                "issuer_role": "x",
                "counterparty_action": "y",
                "later_verifiers": ["z"],
            },
        )
        _write_v3_schema(schemas)

        cat = load_catalogue(acts_path=acts)
        assert len(cat) == 2

        v2_entry = cat.get("op:test.v2_entry.v1")
        v3_entry = cat.get("op:test.v3_entry.v1")
        assert v2_entry is not None
        assert v3_entry is not None
        assert v2_entry.schema == SCHEMA_DISCRIMINATOR_V2
        assert v3_entry.schema == SCHEMA_DISCRIMINATOR_V3
        # v2 entry has v3 fields all None; v3 entry has the one declared block.
        assert v2_entry.reliance_context is None
        assert v3_entry.reliance_context is not None
        assert v3_entry.reliance_context.issuer_role == "x"

    def test_walker_silently_skips_unknown_discriminator(
        self, tmp_path: Path
    ) -> None:
        """A JSON file with a ``schema`` field that is not in
        ``SCHEMA_DISCRIMINATORS`` is skipped silently. It does not raise
        and does not prevent neighbouring valid entries from loading."""
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(acts / "test", "op:test.good.v1")
        # A file whose schema is a future or unknown discriminator.
        bogus_path = acts / "test" / "bogus.json"
        bogus_path.write_text(json.dumps({
            "schema": "openproof.act_catalogue_entry.v999",
            "act_type_id": "op:test.bogus.v1",
        }))
        _write_v3_schema(schemas)

        cat = load_catalogue(acts_path=acts)
        assert cat.get("op:test.good.v1") is not None
        assert cat.get("op:test.bogus.v1") is None
        assert len(cat) == 1

    def test_walker_silently_skips_non_dict_json(self, tmp_path: Path) -> None:
        acts, schemas = _make_layout(tmp_path)
        _write_v3_entry(acts / "test", "op:test.good.v1")
        (acts / "test" / "an_array.json").write_text("[1, 2, 3]")
        _write_v3_schema(schemas)

        cat = load_catalogue(acts_path=acts)
        assert len(cat) == 1


# ─────────────────────────────────────────────────────────────────
# Group 7: backward compatibility
# ─────────────────────────────────────────────────────────────────

class TestBackwardCompat:

    def test_v2_only_catalogue_loads_unchanged(self, tmp_path: Path) -> None:
        """A catalogue containing only v2 entries (no v3 schema file)
        should load with behaviour byte-identical to v0.1.0: every entry
        is v2, all four v3 ``CatalogueEntry`` fields are ``None``."""
        acts, schemas = _make_layout(tmp_path)
        _write_v2_entry(acts / "test", "op:test.alpha.v1")
        _write_v2_entry(acts / "test", "op:test.beta.v1")
        _write_v2_schema(schemas)

        cat = load_catalogue(acts_path=acts)
        assert len(cat) == 2
        for entry in cat.list_entries():
            assert entry.schema == SCHEMA_DISCRIMINATOR_V2
            assert entry.regulated_context_profile is None
            assert entry.prior_receipts_profile is None
            assert entry.reliance_context is None
            assert entry.disclosure_profile is None

    def test_v3_blocks_on_v2_entries_are_ignored(self, tmp_path: Path) -> None:
        """If a v2 entry carries v3 blocks (defensively, against a misedited
        file), the parser ignores them. The JSON schema file is what
        enforces strict ``additionalProperties: false`` on v2 entries for
        consumers that validate at the schema-file level."""
        acts, schemas = _make_layout(tmp_path)
        target_dir = acts / "test"
        target_dir.mkdir(parents=True, exist_ok=True)
        data = _base_entry_dict("op:test.v2_with_v3_blocks.v1", schema=SCHEMA_DISCRIMINATOR_V2)
        # Defensively add v3 blocks that should be ignored on a v2 entry.
        data["disclosure_profile"] = {
            "public_fields": ["should_be_ignored"],
            "commitment_fields": [],
            "private_fields": [],
        }
        data["reliance_context"] = {
            "issuer_role": "ignored",
            "counterparty_action": "ignored",
            "later_verifiers": ["ignored"],
        }
        (target_dir / "v2_with_extras.json").write_text(json.dumps(data, indent=2))
        _write_v2_schema(schemas)

        entry = load_catalogue(acts_path=acts).get("op:test.v2_with_v3_blocks.v1")
        assert entry is not None
        assert entry.schema == SCHEMA_DISCRIMINATOR_V2
        assert entry.disclosure_profile is None
        assert entry.reliance_context is None

    def test_existing_schema_discriminator_name_still_importable(self) -> None:
        """A consumer who imported ``SCHEMA_DISCRIMINATOR`` from openproof
        v0.1.0 (the only discriminator name that existed at the time)
        keeps working unchanged: the name still imports and still equals
        the v2 discriminator string."""
        from openproof.catalogue import SCHEMA_DISCRIMINATOR as imported
        assert imported == "openproof.act_catalogue_entry.v2"

    def test_catalogue_entry_v2_positional_construction_unchanged(self) -> None:
        """Positional construction of ``CatalogueEntry`` with the v2 field
        order (fifteen wire-schema fields plus two derived) still works.
        The four new v3 fields were appended after the derived fields
        precisely so positional callers do not break."""
        from openproof.catalogue import CatalogueEntry, SignaturePolicy
        sp = SignaturePolicy(minimum="issuer_record", supports=())
        entry = CatalogueEntry(
            "openproof.act_catalogue_entry.v2",
            "op:example.test.v1", "test", "Test entry", None,
            ("required_field",), (), ("evidence_label",),
            ("test_issuer",), (), sp, 1, None, "test", "test.test_vectors.json",
        )
        assert entry.source_path == ""
        assert entry.entry_hash == ""
        assert entry.regulated_context_profile is None
        assert entry.disclosure_profile is None


# ─────────────────────────────────────────────────────────────────
# Group 8: real openproof-events v1.4-rc1 catalogue
# ─────────────────────────────────────────────────────────────────

@pytestmark_real_catalogue
class TestRealV1_4Catalogue:
    """v1.4-rc1 ships only v2 entries. Loading it with v0.1.1 must yield
    every entry as v2 with all four v3 fields at ``None``. This protects
    against regressions where an additive change to the parser accidentally
    affects v2 loading."""

    def test_all_real_entries_load_as_v2(self) -> None:
        cat = load_catalogue(acts_path=REAL_ACTS_PATH)
        assert len(cat) >= 1
        for entry in cat.list_entries():
            assert entry.schema == SCHEMA_DISCRIMINATOR_V2, (
                f"{entry.act_type_id} is not v2; this test is for v1.4-rc1 "
                f"only. Update or split the test once v1.5-rc1 lands."
            )

    def test_all_real_entries_have_v3_fields_none(self) -> None:
        cat = load_catalogue(acts_path=REAL_ACTS_PATH)
        for entry in cat.list_entries():
            assert entry.regulated_context_profile is None
            assert entry.prior_receipts_profile is None
            assert entry.reliance_context is None
            assert entry.disclosure_profile is None
