# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Tests for actproof.catalogue.

Eleven test groups:

* TestDataClasses: construction and immutability of the five frozen dataclasses.
* TestPathResolution: env var, fallback paths, explicit path, missing path.
* TestLoadCatalogue: happy path against the real actproof-events v1.4-rc1 catalogue.
* TestScanFilters: _deprecated and *.test_vectors.json are skipped.
* TestDuplicateDetection: two entries with the same act_type_id raise.
* TestSchemaDiscriminator: only entries with the v2 discriminator are loaded.
* TestHashHelpers: hash_entry_file and hash_schema_file produce stable hashes.
* TestValidateManifest: each of the seven check paths in validate_manifest.
* TestValidateRealisticManifests: full NIS2 and EUDR manifest validation.
* TestValidationIssueCodes: every documented issue code is reachable.
* TestCatalogueQueryAPI: .get, .list_entries, ``in`` operator, len().

The real catalogue lives in the actproof-events repository on disk. For tests
that need a controlled environment, we build small catalogues in pytest's
``tmp_path``.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from actproof.catalogue import (
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
from actproof.manifest import (
    Evidence,
    Recipient,
    build_manifest,
    hash_email,
)

# Path to the real actproof-events v1.4-rc1 catalogue fixtures.
# Resolved via ACTPROOF_EVENTS_ROOT env var or ../actproof-events sibling.
# Tests that require the real catalogue use the @pytestmark_real_catalogue
# decorator to skip when it is not present.
from tests import (
    REAL_ACTPROOF_EVENTS_ROOT,
    REAL_ACTS_PATH,
    REAL_SCHEMA_PATH,
    skip_if_no_real_catalogue as pytestmark_real_catalogue,
)


# ─────────────────────────────────────────────────────────────────
# Fixtures: build a small synthetic catalogue in tmp_path
# ─────────────────────────────────────────────────────────────────

def _write_entry(
    target_dir: Path,
    act_type_id: str,
    *,
    version: int = 1,
    required_claim_fields: list[str] | None = None,
    optional_claim_fields: list[str] | None = None,
    required_evidence_labels: list[str] | None = None,
    signature_supports: list[str] | None = None,
    schema: str = SCHEMA_DISCRIMINATOR,
) -> Path:
    """Write a minimal valid entry JSON file. Returns its Path."""
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = act_type_id.replace("op:", "").replace(":", "_") + ".v1.json"
    path = target_dir / filename
    data = {
        "schema": schema,
        "act_type_id": act_type_id,
        "claim_type": act_type_id.split(".")[-2] if "." in act_type_id else "test",
        "display_name": f"Test entry for {act_type_id}",
        "regulatory_citation": None,
        "required_claim_fields": required_claim_fields or ["field_a", "field_b"],
        "optional_claim_fields": optional_claim_fields or [],
        "required_evidence_labels": required_evidence_labels or ["label_a"],
        "eligible_issuer_roles": ["test_role"],
        "recommended_witness_roles": ["test_witness"],
        "signature_policy": {
            "minimum": "issuer_record",
            "supports": signature_supports or [],
        },
        "version": version,
        "supersedes": None,
        "maintainer": "test",
        "test_vector_reference": "tests/fixtures",
    }
    path.write_text(json.dumps(data, indent=2))
    return path


def _write_schema(target_dir: Path) -> Path:
    """Write a placeholder schema file. Returns its Path."""
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / "act_catalogue_entry.v2.json"
    # The actual content doesn't matter for our tests; we just need bytes.
    path.write_bytes(b'{"$schema":"placeholder"}')
    return path


@pytest.fixture
def synthetic_catalogue_root(tmp_path: Path) -> Path:
    """Build a small catalogue at tmp_path mirroring the actproof-events layout."""
    acts = tmp_path / "actproof-events" / "catalogue" / "acts"
    schemas = tmp_path / "actproof-events" / "spec" / "schemas"

    _write_entry(
        acts / "eu" / "test_v1",
        "op:eu.test.alpha.v1",
        required_claim_fields=["name", "date"],
        required_evidence_labels=["doc_a"],
        signature_supports=["external_qes_pdf"],
    )
    _write_entry(
        acts / "eu" / "test_v1",
        "op:eu.test.beta.v1",
        required_claim_fields=["title", "amount_minor_units"],
        required_evidence_labels=["doc_b", "doc_c"],
    )
    _write_schema(schemas)
    return tmp_path / "actproof-events"


# ─────────────────────────────────────────────────────────────────
# Group 1: Data classes
# ─────────────────────────────────────────────────────────────────

class TestDataClasses:

    def test_regulatory_citation_constructs(self) -> None:
        c = RegulatoryCitation(
            instrument="Directive X",
            article="20",
            jurisdiction="EU",
            in_force_from="2024-10-18",
        )
        assert c.instrument == "Directive X"

    def test_regulatory_citation_frozen(self) -> None:
        c = RegulatoryCitation(
            instrument="X", article="1", jurisdiction="EU", in_force_from="2020-01-01"
        )
        with pytest.raises(FrozenInstanceError):
            c.article = "2"  # type: ignore[misc]

    def test_signature_policy_constructs(self) -> None:
        p = SignaturePolicy(minimum="issuer_record", supports=("qes",))
        assert p.minimum == "issuer_record"
        assert p.supports == ("qes",)

    def test_catalogue_entry_constructs(self) -> None:
        e = CatalogueEntry(
            schema=SCHEMA_DISCRIMINATOR,
            act_type_id="op:test.v1",
            claim_type="test_claim",
            display_name="Test",
            regulatory_citation=None,
            required_claim_fields=("a",),
            optional_claim_fields=(),
            required_evidence_labels=(),
            eligible_issuer_roles=("x",),
            recommended_witness_roles=("y",),
            signature_policy=SignaturePolicy("issuer_record", ()),
            version=1,
            supersedes=None,
            maintainer="test",
            test_vector_reference="test",
        )
        assert e.act_type_id == "op:test.v1"
        # Derived fields default to empty strings.
        assert e.source_path == ""
        assert e.entry_hash == ""

    def test_validation_issue_constructs(self) -> None:
        i = ValidationIssue(code="X", message="y")
        assert i.code == "X"
        assert i.field is None

    def test_catalogue_query_api(self) -> None:
        entries = {
            "op:a.v1": CatalogueEntry(
                schema=SCHEMA_DISCRIMINATOR,
                act_type_id="op:a.v1",
                claim_type="test",
                display_name="A",
                regulatory_citation=None,
                required_claim_fields=(),
                optional_claim_fields=(),
                required_evidence_labels=(),
                eligible_issuer_roles=(),
                recommended_witness_roles=(),
                signature_policy=SignaturePolicy("issuer_record", ()),
                version=1,
                supersedes=None,
                maintainer="",
                test_vector_reference="",
            ),
        }
        c = Catalogue(
            entries=entries,
            source_root="/tmp",
            source_uri=None,
            git_commit=None,
            schema_hash="",
        )
        assert c.get("op:a.v1") is entries["op:a.v1"]
        assert c.get("op:missing.v1") is None
        assert len(c) == 1
        assert "op:a.v1" in c
        assert c.list_entries()[0].display_name == "A"


# ─────────────────────────────────────────────────────────────────
# Group 2: Path resolution
# ─────────────────────────────────────────────────────────────────

class TestPathResolution:

    def test_explicit_path(self, synthetic_catalogue_root: Path) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        assert len(cat) == 2

    def test_explicit_path_not_a_directory(self, tmp_path: Path) -> None:
        non_dir = tmp_path / "does-not-exist"
        with pytest.raises(CatalogueLoadError, match="not a directory"):
            load_catalogue(acts_path=non_dir)

    def test_env_var(
        self, synthetic_catalogue_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        monkeypatch.setenv(ENV_CATALOGUE_PATH, str(acts))
        cat = load_catalogue()
        assert len(cat) == 2

    def test_env_var_invalid_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv(ENV_CATALOGUE_PATH, str(tmp_path / "nope"))
        with pytest.raises(CatalogueLoadError, match="not a directory"):
            load_catalogue()

    def test_no_path_no_env_no_fallback_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        # cd into an empty directory with no fallback paths and no env var.
        monkeypatch.delenv(ENV_CATALOGUE_PATH, raising=False)
        monkeypatch.chdir(tmp_path)
        with pytest.raises(CatalogueLoadError, match="Could not locate"):
            load_catalogue()


# ─────────────────────────────────────────────────────────────────
# Group 3: Loading (synthetic + real)
# ─────────────────────────────────────────────────────────────────

class TestLoadCatalogue:

    def test_loads_synthetic_catalogue(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        assert "op:eu.test.alpha.v1" in cat
        assert "op:eu.test.beta.v1" in cat

    def test_loads_schema_hash_from_default_location(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        assert cat.schema_hash.startswith("sha256:")
        assert len(cat.schema_hash) == len("sha256:") + 64

    def test_schema_hash_empty_when_schema_missing(self, tmp_path: Path) -> None:
        acts = tmp_path / "acts"
        _write_entry(acts, "op:test.v1")
        # No schema file at ../../spec/schemas/.
        cat = load_catalogue(acts_path=acts)
        assert cat.schema_hash == ""

    def test_explicit_schema_path(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        schema = synthetic_catalogue_root / "spec" / "schemas" / "act_catalogue_entry.v2.json"
        cat = load_catalogue(acts_path=acts, schema_path=schema)
        assert cat.schema_hash.startswith("sha256:")

    def test_explicit_schema_path_missing_raises(
        self, synthetic_catalogue_root: Path, tmp_path: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        bad_schema = tmp_path / "nope.json"
        with pytest.raises(CatalogueLoadError, match="not a file"):
            load_catalogue(acts_path=acts, schema_path=bad_schema)

    def test_source_uri_and_git_commit_preserved(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(
            acts_path=acts,
            source_uri="https://github.com/example/repo",
            git_commit="a" * 40,
        )
        assert cat.source_uri == "https://github.com/example/repo"
        assert cat.git_commit == "a" * 40

    @pytestmark_real_catalogue
    def test_loads_real_catalogue(self) -> None:
        """Smoke test against the actual actproof-events v1.4-rc1 fixtures."""
        cat = load_catalogue(acts_path=REAL_ACTS_PATH)
        assert "op:eu.nis2.art20.management_body_approval.v1" in cat
        assert "op:eu.eudr.dds_preparation.v1" in cat
        assert len(cat) >= 2

    @pytestmark_real_catalogue
    def test_real_nis2_entry_has_expected_fields(self) -> None:
        cat = load_catalogue(acts_path=REAL_ACTS_PATH)
        nis2 = cat.get("op:eu.nis2.art20.management_body_approval.v1")
        assert nis2 is not None
        assert nis2.claim_type == "management_body_approval"
        assert "approving_body_name" in nis2.required_claim_fields
        assert "signed_resolution_or_minutes" in nis2.required_evidence_labels
        assert nis2.regulatory_citation is not None
        assert nis2.regulatory_citation.instrument == "Directive (EU) 2022/2555"
        assert nis2.regulatory_citation.in_force_from == "2024-10-18"
        assert nis2.entry_hash.startswith("sha256:")


# ─────────────────────────────────────────────────────────────────
# Group 4: Scan filters
# ─────────────────────────────────────────────────────────────────

class TestScanFilters:

    def test_skips_deprecated_directory(self, tmp_path: Path) -> None:
        acts = tmp_path / "acts"
        _write_entry(acts / "eu" / "current", "op:eu.current.v1")
        _write_entry(acts / "eu" / "_deprecated", "op:eu.old.v1")
        cat = load_catalogue(acts_path=acts)
        assert "op:eu.current.v1" in cat
        assert "op:eu.old.v1" not in cat

    def test_skips_test_vectors_files(self, tmp_path: Path) -> None:
        acts = tmp_path / "acts"
        _write_entry(acts, "op:test.v1")
        # Write a file that would otherwise be parseable but is a test vector.
        tv = acts / "test.v1.test_vectors.json"
        tv.write_text('{"schema": "actproof.test_vectors.v1", "data": []}')
        cat = load_catalogue(acts_path=acts)
        assert len(cat) == 1

    def test_skips_files_with_wrong_schema(self, tmp_path: Path) -> None:
        acts = tmp_path / "acts"
        _write_entry(acts, "op:test.v1")
        # A JSON file with a different schema discriminator should be ignored.
        wrong = acts / "wrong.json"
        wrong.write_text('{"schema": "something.else.v1", "data": "x"}')
        cat = load_catalogue(acts_path=acts)
        assert len(cat) == 1

    def test_skips_non_dict_json(self, tmp_path: Path) -> None:
        acts = tmp_path / "acts"
        _write_entry(acts, "op:test.v1")
        # A JSON file with a top-level array (not a catalogue entry).
        arr = acts / "array.json"
        arr.write_text("[1, 2, 3]")
        cat = load_catalogue(acts_path=acts)
        assert len(cat) == 1

    def test_skips_malformed_json(self, tmp_path: Path) -> None:
        acts = tmp_path / "acts"
        _write_entry(acts, "op:test.v1")
        bad = acts / "bad.json"
        bad.write_text("not valid json {")
        cat = load_catalogue(acts_path=acts)
        # Bad files are skipped with a warning, not a crash.
        assert len(cat) == 1


# ─────────────────────────────────────────────────────────────────
# Group 5: Duplicate detection
# ─────────────────────────────────────────────────────────────────

class TestDuplicateDetection:

    def test_duplicate_act_type_id_raises(self, tmp_path: Path) -> None:
        acts = tmp_path / "acts"
        _write_entry(acts / "first", "op:dup.v1")
        _write_entry(acts / "second", "op:dup.v1")
        with pytest.raises(CatalogueLoadError, match="Duplicate"):
            load_catalogue(acts_path=acts)


# ─────────────────────────────────────────────────────────────────
# Group 6: Hash helpers
# ─────────────────────────────────────────────────────────────────

class TestHashHelpers:

    def test_hash_entry_file_format(self, tmp_path: Path) -> None:
        path = tmp_path / "entry.json"
        path.write_bytes(b'{"x":1}')
        h = hash_entry_file(path)
        assert h.startswith("sha256:")
        assert len(h) == len("sha256:") + 64

    def test_hash_entry_file_reproducible(self, tmp_path: Path) -> None:
        path = tmp_path / "entry.json"
        path.write_bytes(b'{"x":1}')
        assert hash_entry_file(path) == hash_entry_file(path)

    def test_hash_entry_file_sensitive_to_content(self, tmp_path: Path) -> None:
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_bytes(b'{"x":1}')
        b.write_bytes(b'{"x":2}')
        assert hash_entry_file(a) != hash_entry_file(b)

    def test_hash_entry_file_sensitive_to_whitespace(self, tmp_path: Path) -> None:
        # Raw-bytes hashing means whitespace changes the hash.
        # This is intentional: see module docstring.
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_bytes(b'{"x":1}')
        b.write_bytes(b'{"x": 1}')  # extra space
        assert hash_entry_file(a) != hash_entry_file(b)

    def test_hash_schema_file(self, tmp_path: Path) -> None:
        path = tmp_path / "schema.json"
        path.write_bytes(b"schema content")
        h = hash_schema_file(path)
        assert h.startswith("sha256:")


# ─────────────────────────────────────────────────────────────────
# Helpers for manifest building in validation tests
# ─────────────────────────────────────────────────────────────────

def _build_test_manifest(
    *,
    act_type_id: str = "op:eu.test.alpha.v1",
    entry_version: int = 1,
    entry_hash: str = "sha256:" + "a" * 64,
    schema_hash: str = "sha256:" + "b" * 64,
    claim: dict | None = None,
    evidence_specs: list[tuple[str, str]] | None = None,
):
    """Build a manifest with sensible defaults for validation tests.

    Args:
        act_type_id: The act_type_id to bind.
        entry_version: Catalogue entry version.
        entry_hash: Catalogue entry hash.
        schema_hash: Catalogue schema hash.
        claim: Claim dict. Defaults to {'name': 'x', 'date': '2026-01-01'}.
        evidence_specs: List of (label, fake_content) tuples.
            Defaults to one entry labelled 'doc_a'.
    """
    if claim is None:
        claim = {"name": "x", "date": "2026-01-01"}
    if evidence_specs is None:
        evidence_specs = [("doc_a", "fake content")]

    evidence = [
        Evidence(
            label=label,
            filename_normalized=f"{label}.pdf",
            byte_size=len(content),
            mime_type="application/pdf",
            sha256="sha256:" + "f" * 64,
        )
        for label, content in evidence_specs
    ]

    return build_manifest(
        act_type_id=act_type_id,
        catalogue_entry_version=entry_version,
        catalogue_source_uri="https://example.com",
        catalogue_git_commit="0" * 40,
        catalogue_entry_hash=entry_hash,
        catalogue_schema_hash=schema_hash,
        issuer_org_name="Test Corp",
        issuer_authority_label="Test Role",
        title="Test",
        claim=claim,
        evidence=evidence,
        recipients=[
            Recipient(
                role="test_witness",
                org_name="Witness Co",
                email_hash=hash_email("w@x.com"),
            )
        ],
        issued_at="2026-05-14T12:00:00Z",
    )


# ─────────────────────────────────────────────────────────────────
# Group 7: validate_manifest - happy path and each check
# ─────────────────────────────────────────────────────────────────

class TestValidateManifest:

    def test_valid_manifest_no_issues(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:eu.test.alpha.v1")
        assert entry is not None

        m = _build_test_manifest(
            entry_hash=entry.entry_hash,
            schema_hash=cat.schema_hash,
        )
        issues = validate_manifest(m, cat)
        assert issues == []

    def test_unknown_act_type(self, synthetic_catalogue_root: Path) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)

        m = _build_test_manifest(act_type_id="op:not.in.catalogue.v1")
        issues = validate_manifest(m, cat)
        assert len(issues) == 1
        assert issues[0].code == "UNKNOWN_ACT_TYPE"

    def test_entry_version_mismatch(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:eu.test.alpha.v1")
        assert entry is not None

        m = _build_test_manifest(
            entry_version=99,
            entry_hash=entry.entry_hash,
            schema_hash=cat.schema_hash,
        )
        codes = [i.code for i in validate_manifest(m, cat)]
        assert "ENTRY_VERSION_MISMATCH" in codes

    def test_entry_hash_mismatch(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)

        m = _build_test_manifest(
            entry_hash="sha256:" + "0" * 64,  # wrong
            schema_hash=cat.schema_hash,
        )
        codes = [i.code for i in validate_manifest(m, cat)]
        assert "ENTRY_HASH_MISMATCH" in codes

    def test_schema_hash_mismatch(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:eu.test.alpha.v1")
        assert entry is not None

        m = _build_test_manifest(
            entry_hash=entry.entry_hash,
            schema_hash="sha256:" + "0" * 64,  # wrong
        )
        codes = [i.code for i in validate_manifest(m, cat)]
        assert "SCHEMA_HASH_MISMATCH" in codes

    def test_missing_required_claim_field(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:eu.test.alpha.v1")
        assert entry is not None

        # The synthetic entry requires "name" and "date"; omit "date".
        m = _build_test_manifest(
            entry_hash=entry.entry_hash,
            schema_hash=cat.schema_hash,
            claim={"name": "x"},
        )
        issues = validate_manifest(m, cat)
        codes = [i.code for i in issues]
        assert "MISSING_REQUIRED_CLAIM_FIELD" in codes
        # The field path includes which field was missing.
        missing_fields = [i.field for i in issues if i.code == "MISSING_REQUIRED_CLAIM_FIELD"]
        assert "claim.date" in missing_fields

    def test_empty_required_claim_field(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:eu.test.alpha.v1")
        assert entry is not None

        m = _build_test_manifest(
            entry_hash=entry.entry_hash,
            schema_hash=cat.schema_hash,
            claim={"name": "x", "date": "   "},  # empty/whitespace
        )
        codes = [i.code for i in validate_manifest(m, cat)]
        assert "MISSING_REQUIRED_CLAIM_FIELD" in codes

    def test_missing_required_evidence_label(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:eu.test.alpha.v1")
        assert entry is not None

        # The synthetic entry requires evidence label "doc_a"; provide nothing.
        m = _build_test_manifest(
            entry_hash=entry.entry_hash,
            schema_hash=cat.schema_hash,
            evidence_specs=[],
        )
        codes = [i.code for i in validate_manifest(m, cat)]
        assert "MISSING_REQUIRED_EVIDENCE_LABEL" in codes

    def test_unknown_evidence_label(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:eu.test.alpha.v1")
        assert entry is not None

        m = _build_test_manifest(
            entry_hash=entry.entry_hash,
            schema_hash=cat.schema_hash,
            evidence_specs=[
                ("doc_a", "x"),         # required: covers requirement
                ("mystery_doc", "y"),   # unknown: should be flagged
            ],
        )
        codes = [i.code for i in validate_manifest(m, cat)]
        assert "UNKNOWN_EVIDENCE_LABEL" in codes

    def test_signature_policy_supports_labels_accepted(
        self, synthetic_catalogue_root: Path
    ) -> None:
        # The alpha entry's signature_policy.supports includes "external_qes_pdf".
        # Evidence with that label should be accepted (not flagged as unknown).
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:eu.test.alpha.v1")
        assert entry is not None

        m = _build_test_manifest(
            entry_hash=entry.entry_hash,
            schema_hash=cat.schema_hash,
            evidence_specs=[
                ("doc_a", "x"),
                ("external_qes_pdf", "y"),  # in supports list
            ],
        )
        codes = [i.code for i in validate_manifest(m, cat)]
        assert "UNKNOWN_EVIDENCE_LABEL" not in codes


# ─────────────────────────────────────────────────────────────────
# Group 8: Realistic manifests against real catalogue
# ─────────────────────────────────────────────────────────────────

@pytestmark_real_catalogue
class TestValidateRealisticManifests:

    def test_valid_nis2_manifest(self) -> None:
        cat = load_catalogue(acts_path=REAL_ACTS_PATH)
        entry = cat.get("op:eu.nis2.art20.management_body_approval.v1")
        assert entry is not None

        m = build_manifest(
            act_type_id="op:eu.nis2.art20.management_body_approval.v1",
            catalogue_entry_version=entry.version,
            catalogue_source_uri="https://github.com/deyan-paroushev/actproof-events",
            catalogue_git_commit="a" * 40,
            catalogue_entry_hash=entry.entry_hash,
            catalogue_schema_hash=cat.schema_hash,
            issuer_org_name="Sofia Tech Holdings AD",
            issuer_authority_label="Management Body",
            title="NIS2 approval, May 2026",
            claim={
                "approving_body_name": "Board of Directors",
                "decision_date": "2026-05-14",
                "approved_measures_summary": "Annual programme",
                "authority_basis_reference": "Statutes Art. 12",
                "responsible_officers": "CIO, CISO",
                "implementation_oversight_reference": "Internal audit Q3",
            },
            evidence=[
                Evidence(
                    label="signed_resolution_or_minutes",
                    filename_normalized="minutes.pdf",
                    byte_size=1000,
                    mime_type="application/pdf",
                    sha256="sha256:" + "c" * 64,
                ),
                Evidence(
                    label="risk_management_measures_document",
                    filename_normalized="measures.pdf",
                    byte_size=2000,
                    mime_type="application/pdf",
                    sha256="sha256:" + "d" * 64,
                ),
            ],
            recipients=[
                Recipient(
                    role="external_auditor",
                    org_name="Auditor AD",
                    email_hash=hash_email("a@a.com"),
                )
            ],
            issued_at="2026-05-14T08:23:11Z",
        )
        issues = validate_manifest(m, cat)
        assert issues == [], f"Expected no issues, got: {issues}"

    def test_valid_eudr_manifest(self) -> None:
        cat = load_catalogue(acts_path=REAL_ACTS_PATH)
        entry = cat.get("op:eu.eudr.dds_preparation.v1")
        assert entry is not None

        # Build with the entry's actual required fields.
        claim = {f: f"value-for-{f}" for f in entry.required_claim_fields}
        evidence = [
            Evidence(
                label=label,
                filename_normalized=f"{label}.bin",
                byte_size=100,
                mime_type="application/octet-stream",
                sha256="sha256:" + "1" * 64,
            )
            for label in entry.required_evidence_labels
        ]

        m = build_manifest(
            act_type_id=entry.act_type_id,
            catalogue_entry_version=entry.version,
            catalogue_source_uri="https://github.com/deyan-paroushev/actproof-events",
            catalogue_git_commit="b" * 40,
            catalogue_entry_hash=entry.entry_hash,
            catalogue_schema_hash=cat.schema_hash,
            issuer_org_name="Smart Organic AD",
            issuer_authority_label="Operator",
            title="EUDR DDS for shipment lot 001",
            claim=claim,
            evidence=evidence,
            recipients=[],
            issued_at="2026-05-14T09:30:00Z",
        )
        issues = validate_manifest(m, cat)
        assert issues == [], f"Expected no issues, got: {issues}"


# ─────────────────────────────────────────────────────────────────
# Group 9: All documented issue codes are reachable
# ─────────────────────────────────────────────────────────────────

class TestValidationIssueCodes:
    """Every code listed in the ValidationIssue docstring is exercisable
    via at least one validation path. This guards against silent code drift
    (someone refactoring the validator and removing a code without updating
    the docstring).
    """

    def test_all_documented_codes_reachable(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        entry = cat.get("op:eu.test.alpha.v1")
        assert entry is not None

        # Build a manifest that violates several rules at once.
        m = build_manifest(
            act_type_id="op:eu.test.alpha.v1",
            catalogue_entry_version=99,  # wrong: ENTRY_VERSION_MISMATCH
            catalogue_source_uri="x",
            catalogue_git_commit="0" * 40,
            catalogue_entry_hash="sha256:" + "0" * 64,  # wrong: ENTRY_HASH_MISMATCH
            catalogue_schema_hash="sha256:" + "0" * 64,  # wrong: SCHEMA_HASH_MISMATCH
            issuer_org_name="x",
            issuer_authority_label="y",
            title="t",
            claim={},  # missing required: MISSING_REQUIRED_CLAIM_FIELD
            evidence=[
                Evidence(
                    label="mystery",  # not declared: UNKNOWN_EVIDENCE_LABEL
                    filename_normalized="f.pdf",
                    byte_size=10,
                    mime_type="application/pdf",
                    sha256="sha256:" + "e" * 64,
                )
            ],
            # No "doc_a": MISSING_REQUIRED_EVIDENCE_LABEL
            recipients=[],
            issued_at="2026-05-14T12:00:00Z",
        )
        codes = {i.code for i in validate_manifest(m, cat)}

        expected_subset = {
            "ENTRY_VERSION_MISMATCH",
            "ENTRY_HASH_MISMATCH",
            "SCHEMA_HASH_MISMATCH",
            "MISSING_REQUIRED_CLAIM_FIELD",
            "MISSING_REQUIRED_EVIDENCE_LABEL",
            "UNKNOWN_EVIDENCE_LABEL",
        }
        assert expected_subset.issubset(codes), (
            f"Expected codes {expected_subset} to all appear, got {codes}"
        )

    def test_unknown_act_type_is_reachable(
        self, synthetic_catalogue_root: Path
    ) -> None:
        acts = synthetic_catalogue_root / "catalogue" / "acts"
        cat = load_catalogue(acts_path=acts)
        m = _build_test_manifest(act_type_id="op:not.real.v1")
        codes = {i.code for i in validate_manifest(m, cat)}
        assert "UNKNOWN_ACT_TYPE" in codes
