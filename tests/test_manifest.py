# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: Apache-2.0
"""
Tests for actproof.manifest.

Eleven test groups:

* TestDataClasses: construction, immutability of the five frozen dataclasses.
* TestBuildManifest: build_manifest happy path and keyword-only enforcement.
* TestSerialisation: manifest_to_dict and manifest_from_dict roundtrip.
* TestHashing: hash_manifest reproducibility (load-bearing property) and
  consistency with hash_manifest_hex.
* TestEmailHelpers: normalize_email and hash_email edge cases.
* TestFileAndJsonHelpers: hash_file_bytes and hash_json_bytes.
* TestShapeValidation: validate_manifest_shape on good and bad inputs.
* TestRealisticShapes: NIS2, EUDR, software release manifest shapes.
* TestDeterminism: same input always produces same canonical bytes.
* TestConstants: receipt_profile and batching_profile defaults.
* TestIntegrationWithCanonical: the manifest dict round-trips through
  canonicalize without error.

Run with::

    pytest tests/test_manifest.py -v
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError

import pytest

from actproof.canonical import canonicalize
from actproof.manifest import (
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


# ─────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def valid_catalogue() -> CatalogueBinding:
    return CatalogueBinding(
        act_type_id="op:eu.nis2.art20.management_body_approval.v1",
        entry_version=1,
        source_uri="https://github.com/deyan-paroushev/actproof-events",
        git_commit="0" * 40,
        entry_hash="sha256:" + "a" * 64,
        schema_hash="sha256:" + "b" * 64,
    )


@pytest.fixture
def valid_issuer() -> Issuer:
    return Issuer(
        org_name="Sofia Tech Holdings AD",
        authority_label="Management Body",
    )


@pytest.fixture
def valid_evidence() -> Evidence:
    return Evidence(
        label="signed_resolution_or_minutes",
        filename_normalized="minutes_2026-05-14.pdf",
        byte_size=482991,
        mime_type="application/pdf",
        sha256="sha256:" + "c" * 64,
    )


@pytest.fixture
def valid_recipient() -> Recipient:
    return Recipient(
        role="external_auditor",
        org_name="Auditor AD",
        email_hash="sha256:" + "d" * 64,
    )


@pytest.fixture
def valid_manifest(
    valid_catalogue: CatalogueBinding,
    valid_issuer: Issuer,
    valid_evidence: Evidence,
    valid_recipient: Recipient,
) -> Manifest:
    return Manifest(
        receipt_profile=RECEIPT_PROFILE_V1,
        issued_at="2026-05-14T08:23:11Z",
        catalogue=valid_catalogue,
        issuer=valid_issuer,
        title="NIS2 Article 20 management body approval, May 2026",
        claim={
            "approving_body_name": "Board of Directors",
            "decision_date": "2026-05-14",
            "approved_measures_summary": "Annual cybersecurity programme",
            "authority_basis_reference": "Statutes Art. 12",
            "responsible_officers": "CIO, CISO",
            "implementation_oversight_reference": "Internal audit Q3",
        },
        evidence=(valid_evidence,),
        recipients=(valid_recipient,),
        batching_profile=BATCHING_PROFILE_SINGLE,
    )


# ─────────────────────────────────────────────────────────────────
# Group 1: Dataclass construction and immutability
# ─────────────────────────────────────────────────────────────────

class TestDataClasses:

    def test_catalogue_binding_constructs(self, valid_catalogue: CatalogueBinding) -> None:
        assert valid_catalogue.act_type_id == "op:eu.nis2.art20.management_body_approval.v1"
        assert valid_catalogue.entry_version == 1

    def test_catalogue_binding_frozen(self, valid_catalogue: CatalogueBinding) -> None:
        with pytest.raises(FrozenInstanceError):
            valid_catalogue.entry_version = 99  # type: ignore[misc]

    def test_issuer_constructs(self, valid_issuer: Issuer) -> None:
        assert valid_issuer.org_name == "Sofia Tech Holdings AD"

    def test_issuer_frozen(self, valid_issuer: Issuer) -> None:
        with pytest.raises(FrozenInstanceError):
            valid_issuer.org_name = "Other Corp"  # type: ignore[misc]

    def test_evidence_constructs(self, valid_evidence: Evidence) -> None:
        assert valid_evidence.label == "signed_resolution_or_minutes"
        assert valid_evidence.byte_size == 482991

    def test_evidence_frozen(self, valid_evidence: Evidence) -> None:
        with pytest.raises(FrozenInstanceError):
            valid_evidence.byte_size = 0  # type: ignore[misc]

    def test_recipient_constructs(self, valid_recipient: Recipient) -> None:
        assert valid_recipient.role == "external_auditor"

    def test_recipient_frozen(self, valid_recipient: Recipient) -> None:
        with pytest.raises(FrozenInstanceError):
            valid_recipient.role = "other_role"  # type: ignore[misc]

    def test_manifest_constructs(self, valid_manifest: Manifest) -> None:
        assert valid_manifest.receipt_profile == "actproof-jcs-v1"
        assert valid_manifest.batching_profile == "single_attestation_anchor_v1"
        assert len(valid_manifest.evidence) == 1
        assert len(valid_manifest.recipients) == 1

    def test_manifest_frozen(self, valid_manifest: Manifest) -> None:
        with pytest.raises(FrozenInstanceError):
            valid_manifest.title = "Other Title"  # type: ignore[misc]

    def test_manifest_evidence_is_tuple_not_list(
        self, valid_manifest: Manifest
    ) -> None:
        # Tuples are immutable; lists are not.
        assert isinstance(valid_manifest.evidence, tuple)
        assert isinstance(valid_manifest.recipients, tuple)


# ─────────────────────────────────────────────────────────────────
# Group 2: build_manifest helper
# ─────────────────────────────────────────────────────────────────

class TestBuildManifest:

    def test_happy_path(self) -> None:
        m = build_manifest(
            act_type_id="op:test.v1",
            catalogue_entry_version=1,
            catalogue_source_uri="https://example.com/catalogue",
            catalogue_git_commit="0" * 40,
            catalogue_entry_hash="sha256:" + "a" * 64,
            catalogue_schema_hash="sha256:" + "b" * 64,
            issuer_org_name="Test Corp",
            issuer_authority_label="Operator",
            title="Test commitment",
            claim={"field": "value"},
            evidence=[
                Evidence(
                    label="some_label",
                    filename_normalized="file.pdf",
                    byte_size=100,
                    mime_type="application/pdf",
                    sha256="sha256:" + "c" * 64,
                )
            ],
            recipients=[],
            issued_at="2026-05-14T12:00:00Z",
        )
        assert isinstance(m, Manifest)
        assert m.receipt_profile == RECEIPT_PROFILE_V1
        assert m.batching_profile == BATCHING_PROFILE_SINGLE
        assert m.catalogue.act_type_id == "op:test.v1"

    def test_keyword_only(self) -> None:
        # All build_manifest arguments are keyword-only.
        with pytest.raises(TypeError, match="positional"):
            build_manifest(
                "op:test.v1",  # type: ignore[misc]
                1, "uri", "0" * 40,
                "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                "Corp", "Operator", "Title", {}, [], [],
                "2026-05-14T12:00:00Z",
            )

    def test_evidence_coerced_to_tuple(self) -> None:
        # Pass a list; expect a tuple back.
        m = build_manifest(
            act_type_id="op:test.v1",
            catalogue_entry_version=1,
            catalogue_source_uri="uri",
            catalogue_git_commit="0" * 40,
            catalogue_entry_hash="sha256:" + "a" * 64,
            catalogue_schema_hash="sha256:" + "b" * 64,
            issuer_org_name="Corp",
            issuer_authority_label="Operator",
            title="Title",
            claim={},
            evidence=[],  # list
            recipients=[],  # list
            issued_at="2026-05-14T12:00:00Z",
        )
        assert isinstance(m.evidence, tuple)
        assert isinstance(m.recipients, tuple)

    def test_claim_is_defensively_copied(self) -> None:
        # Mutating the original claim dict after construction must not
        # affect the manifest.
        original_claim = {"x": 1}
        m = build_manifest(
            act_type_id="op:test.v1",
            catalogue_entry_version=1,
            catalogue_source_uri="uri",
            catalogue_git_commit="0" * 40,
            catalogue_entry_hash="sha256:" + "a" * 64,
            catalogue_schema_hash="sha256:" + "b" * 64,
            issuer_org_name="Corp",
            issuer_authority_label="Operator",
            title="Title",
            claim=original_claim,
            evidence=[],
            recipients=[],
            issued_at="2026-05-14T12:00:00Z",
        )
        original_claim["x"] = 999
        assert m.claim["x"] == 1


# ─────────────────────────────────────────────────────────────────
# Group 3: Serialisation
# ─────────────────────────────────────────────────────────────────

class TestSerialisation:

    def test_to_dict_includes_all_top_level_fields(
        self, valid_manifest: Manifest
    ) -> None:
        d = manifest_to_dict(valid_manifest)
        expected_keys = {
            "receipt_profile", "issued_at", "catalogue", "issuer", "title",
            "claim", "evidence", "recipients", "batching_profile",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_catalogue_structure(self, valid_manifest: Manifest) -> None:
        d = manifest_to_dict(valid_manifest)
        catalogue = d["catalogue"]
        assert catalogue["act_type_id"] == "op:eu.nis2.art20.management_body_approval.v1"
        assert catalogue["entry_version"] == 1
        assert catalogue["source_uri"].endswith("actproof-events")
        assert len(catalogue["git_commit"]) == 40
        assert catalogue["entry_hash"].startswith("sha256:")
        assert catalogue["schema_hash"].startswith("sha256:")

    def test_to_dict_issuer_structure(self, valid_manifest: Manifest) -> None:
        d = manifest_to_dict(valid_manifest)
        assert d["issuer"]["org_name"] == "Sofia Tech Holdings AD"
        assert d["issuer"]["authority_label"] == "Management Body"

    def test_to_dict_evidence_is_list_of_dicts(
        self, valid_manifest: Manifest
    ) -> None:
        d = manifest_to_dict(valid_manifest)
        assert isinstance(d["evidence"], list)
        assert len(d["evidence"]) == 1
        e = d["evidence"][0]
        assert e["label"] == "signed_resolution_or_minutes"
        assert e["filename_normalized"] == "minutes_2026-05-14.pdf"
        assert e["byte_size"] == 482991
        assert e["mime_type"] == "application/pdf"
        assert e["sha256"].startswith("sha256:")

    def test_to_dict_recipients_is_list_of_dicts(
        self, valid_manifest: Manifest
    ) -> None:
        d = manifest_to_dict(valid_manifest)
        assert isinstance(d["recipients"], list)
        assert len(d["recipients"]) == 1
        r = d["recipients"][0]
        assert r["role"] == "external_auditor"
        assert r["org_name"] == "Auditor AD"
        assert r["email_hash"].startswith("sha256:")

    def test_from_dict_roundtrips(self, valid_manifest: Manifest) -> None:
        d = manifest_to_dict(valid_manifest)
        reconstructed = manifest_from_dict(d)
        # Reconstructed manifest must equal the original (frozen dataclasses
        # support equality by field values).
        assert reconstructed == valid_manifest

    def test_from_dict_rejects_missing_field(self) -> None:
        bad = {
            "receipt_profile": "actproof-jcs-v1",
            "issued_at": "2026-05-14T12:00:00Z",
            # missing "catalogue"
            "issuer": {"org_name": "x", "authority_label": "y"},
            "title": "t",
            "claim": {},
            "evidence": [],
            "recipients": [],
            "batching_profile": "single_attestation_anchor_v1",
        }
        with pytest.raises(ManifestValidationError):
            manifest_from_dict(bad)

    def test_from_dict_handles_missing_evidence_list_as_empty(self) -> None:
        # If evidence/recipients are entirely absent from the input dict,
        # treat as empty rather than failing.
        d = {
            "receipt_profile": "actproof-jcs-v1",
            "issued_at": "2026-05-14T12:00:00Z",
            "catalogue": {
                "act_type_id": "op:t.v1",
                "entry_version": 1,
                "source_uri": "u",
                "git_commit": "0" * 40,
                "entry_hash": "sha256:" + "a" * 64,
                "schema_hash": "sha256:" + "b" * 64,
            },
            "issuer": {"org_name": "x", "authority_label": "y"},
            "title": "t",
            "claim": {},
            # no evidence or recipients keys
            "batching_profile": "single_attestation_anchor_v1",
        }
        m = manifest_from_dict(d)
        assert m.evidence == ()
        assert m.recipients == ()


# ─────────────────────────────────────────────────────────────────
# Group 4: Hashing
# ─────────────────────────────────────────────────────────────────

class TestHashing:
    """The most load-bearing property in this module."""

    def test_hash_manifest_returns_32_bytes(self, valid_manifest: Manifest) -> None:
        digest = hash_manifest(valid_manifest)
        assert isinstance(digest, bytes)
        assert len(digest) == 32

    def test_hash_manifest_hex_returns_64_chars(
        self, valid_manifest: Manifest
    ) -> None:
        digest = hash_manifest_hex(valid_manifest)
        assert isinstance(digest, str)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_hash_manifest_and_hash_manifest_hex_agree(
        self, valid_manifest: Manifest
    ) -> None:
        raw = hash_manifest(valid_manifest)
        hex_str = hash_manifest_hex(valid_manifest)
        assert raw.hex() == hex_str

    def test_hash_reproducible_across_calls(
        self, valid_manifest: Manifest
    ) -> None:
        # The same manifest hashed ten times produces the same bytes.
        results = [hash_manifest(valid_manifest) for _ in range(10)]
        assert len(set(results)) == 1

    def test_hash_independent_of_claim_field_order(self) -> None:
        # Building two manifests with the same claim fields in different
        # insertion order must produce identical hashes.
        common_kwargs = dict(
            act_type_id="op:t.v1",
            catalogue_entry_version=1,
            catalogue_source_uri="uri",
            catalogue_git_commit="0" * 40,
            catalogue_entry_hash="sha256:" + "a" * 64,
            catalogue_schema_hash="sha256:" + "b" * 64,
            issuer_org_name="Corp",
            issuer_authority_label="Operator",
            title="t",
            evidence=[],
            recipients=[],
            issued_at="2026-05-14T12:00:00Z",
        )
        m1 = build_manifest(claim={"a": 1, "b": 2, "c": 3}, **common_kwargs)
        m2 = build_manifest(claim={"c": 3, "b": 2, "a": 1}, **common_kwargs)
        assert hash_manifest(m1) == hash_manifest(m2)

    def test_hash_changes_when_field_changes(
        self, valid_manifest: Manifest
    ) -> None:
        # Sanity: a change in one field must produce a different hash.
        # Replace the title via dataclass replacement helper.
        from dataclasses import replace
        modified = replace(valid_manifest, title="A DIFFERENT TITLE")
        assert hash_manifest(valid_manifest) != hash_manifest(modified)


# ─────────────────────────────────────────────────────────────────
# Group 5: Email helpers
# ─────────────────────────────────────────────────────────────────

class TestEmailHelpers:

    def test_normalize_lowercases(self) -> None:
        assert normalize_email("Auditor@FIRM.com") == "auditor@firm.com"

    def test_normalize_strips_whitespace(self) -> None:
        assert normalize_email("  auditor@firm.com  ") == "auditor@firm.com"

    def test_normalize_strips_then_lowercases(self) -> None:
        assert normalize_email("  AUDITOR@firm.com\n") == "auditor@firm.com"

    def test_hash_email_format(self) -> None:
        h = hash_email("auditor@firm.com")
        assert h.startswith("sha256:")
        assert len(h) == len("sha256:") + 64

    def test_hash_email_reproducible(self) -> None:
        assert hash_email("auditor@firm.com") == hash_email("auditor@firm.com")

    def test_hash_email_case_insensitive(self) -> None:
        # Different case in input produces same hash (because of normalisation).
        assert hash_email("Auditor@FIRM.com") == hash_email("auditor@firm.com")

    def test_hash_email_whitespace_insensitive(self) -> None:
        assert hash_email("  auditor@firm.com  ") == hash_email("auditor@firm.com")

    def test_hash_email_value_known(self) -> None:
        # Pin the actual hash value so an accidental change to normalisation
        # is caught immediately.
        expected = "sha256:" + hashlib.sha256(b"auditor@firm.com").hexdigest()
        assert hash_email("Auditor@FIRM.com") == expected

    def test_hash_email_unicode_localpart(self) -> None:
        # Unicode locals are valid per RFC 6531. Hash should not error.
        h = hash_email("müller@firma.de")
        assert h.startswith("sha256:")


# ─────────────────────────────────────────────────────────────────
# Group 6: File and JSON hash helpers
# ─────────────────────────────────────────────────────────────────

class TestFileAndJsonHelpers:

    def test_hash_file_bytes_format(self) -> None:
        h = hash_file_bytes(b"hello world")
        assert h.startswith("sha256:")
        assert len(h) == len("sha256:") + 64

    def test_hash_file_bytes_known_value(self) -> None:
        # sha256("hello world") is a well-known constant.
        expected = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert hash_file_bytes(b"hello world") == expected

    def test_hash_file_bytes_empty(self) -> None:
        # sha256("") is also a well-known constant.
        expected = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert hash_file_bytes(b"") == expected

    def test_hash_json_bytes_format(self) -> None:
        h = hash_json_bytes(b'{"a":1}')
        assert h.startswith("sha256:")

    def test_hash_json_bytes_matches_file_hash_for_same_input(self) -> None:
        # hash_json_bytes and hash_file_bytes are the same algorithm; the
        # function exists for semantic clarity, not behavioural difference.
        assert hash_file_bytes(b'{"a":1}') == hash_json_bytes(b'{"a":1}')


# ─────────────────────────────────────────────────────────────────
# Group 7: Shape validation
# ─────────────────────────────────────────────────────────────────

class TestShapeValidation:

    def test_valid_manifest_passes(self, valid_manifest: Manifest) -> None:
        # Should not raise.
        validate_manifest_shape(valid_manifest)

    def test_empty_title_rejected(self, valid_manifest: Manifest) -> None:
        from dataclasses import replace
        bad = replace(valid_manifest, title="")
        with pytest.raises(ManifestValidationError, match="title is empty"):
            validate_manifest_shape(bad)

    def test_bad_iso8601_rejected(self, valid_manifest: Manifest) -> None:
        from dataclasses import replace
        bad = replace(valid_manifest, issued_at="2026-05-14 08:23:11")  # no T, no Z
        with pytest.raises(ManifestValidationError, match="ISO 8601"):
            validate_manifest_shape(bad)

    def test_bad_iso8601_missing_z(self, valid_manifest: Manifest) -> None:
        from dataclasses import replace
        bad = replace(valid_manifest, issued_at="2026-05-14T08:23:11")
        with pytest.raises(ManifestValidationError):
            validate_manifest_shape(bad)

    def test_bad_git_commit_too_short(
        self, valid_manifest: Manifest, valid_catalogue: CatalogueBinding
    ) -> None:
        from dataclasses import replace
        bad_catalogue = replace(valid_catalogue, git_commit="abc123")
        bad = replace(valid_manifest, catalogue=bad_catalogue)
        with pytest.raises(ManifestValidationError, match="git_commit"):
            validate_manifest_shape(bad)

    def test_bad_git_commit_uppercase(
        self, valid_manifest: Manifest, valid_catalogue: CatalogueBinding
    ) -> None:
        from dataclasses import replace
        bad_catalogue = replace(valid_catalogue, git_commit="A" * 40)  # uppercase
        bad = replace(valid_manifest, catalogue=bad_catalogue)
        with pytest.raises(ManifestValidationError, match="git_commit"):
            validate_manifest_shape(bad)

    def test_bad_entry_hash_no_prefix(
        self, valid_manifest: Manifest, valid_catalogue: CatalogueBinding
    ) -> None:
        from dataclasses import replace
        bad_catalogue = replace(valid_catalogue, entry_hash="a" * 64)  # missing "sha256:"
        bad = replace(valid_manifest, catalogue=bad_catalogue)
        with pytest.raises(ManifestValidationError, match="entry_hash"):
            validate_manifest_shape(bad)

    def test_bad_entry_hash_uppercase(
        self, valid_manifest: Manifest, valid_catalogue: CatalogueBinding
    ) -> None:
        from dataclasses import replace
        bad_catalogue = replace(valid_catalogue, entry_hash="sha256:" + "A" * 64)
        bad = replace(valid_manifest, catalogue=bad_catalogue)
        with pytest.raises(ManifestValidationError, match="entry_hash"):
            validate_manifest_shape(bad)

    def test_entry_version_zero_rejected(
        self, valid_manifest: Manifest, valid_catalogue: CatalogueBinding
    ) -> None:
        from dataclasses import replace
        bad_catalogue = replace(valid_catalogue, entry_version=0)
        bad = replace(valid_manifest, catalogue=bad_catalogue)
        with pytest.raises(ManifestValidationError, match="entry_version"):
            validate_manifest_shape(bad)

    def test_empty_issuer_org_rejected(
        self, valid_manifest: Manifest, valid_issuer: Issuer
    ) -> None:
        from dataclasses import replace
        bad_issuer = replace(valid_issuer, org_name="")
        bad = replace(valid_manifest, issuer=bad_issuer)
        with pytest.raises(ManifestValidationError, match="issuer.org_name"):
            validate_manifest_shape(bad)

    def test_zero_byte_evidence_rejected(
        self, valid_manifest: Manifest, valid_evidence: Evidence
    ) -> None:
        from dataclasses import replace
        bad_evidence = replace(valid_evidence, byte_size=0)
        bad = replace(valid_manifest, evidence=(bad_evidence,))
        with pytest.raises(ManifestValidationError, match="byte_size"):
            validate_manifest_shape(bad)

    def test_negative_byte_evidence_rejected(
        self, valid_manifest: Manifest, valid_evidence: Evidence
    ) -> None:
        from dataclasses import replace
        bad_evidence = replace(valid_evidence, byte_size=-1)
        bad = replace(valid_manifest, evidence=(bad_evidence,))
        with pytest.raises(ManifestValidationError, match="byte_size"):
            validate_manifest_shape(bad)

    def test_empty_evidence_label_rejected(
        self, valid_manifest: Manifest, valid_evidence: Evidence
    ) -> None:
        from dataclasses import replace
        bad_evidence = replace(valid_evidence, label="")
        bad = replace(valid_manifest, evidence=(bad_evidence,))
        with pytest.raises(ManifestValidationError, match="evidence"):
            validate_manifest_shape(bad)

    def test_bad_evidence_sha256_rejected(
        self, valid_manifest: Manifest, valid_evidence: Evidence
    ) -> None:
        from dataclasses import replace
        bad_evidence = replace(valid_evidence, sha256="not-a-hash")
        bad = replace(valid_manifest, evidence=(bad_evidence,))
        with pytest.raises(ManifestValidationError, match="sha256"):
            validate_manifest_shape(bad)

    def test_bad_recipient_email_hash_rejected(
        self, valid_manifest: Manifest, valid_recipient: Recipient
    ) -> None:
        from dataclasses import replace
        bad_recipient = replace(valid_recipient, email_hash="not-a-hash")
        bad = replace(valid_manifest, recipients=(bad_recipient,))
        with pytest.raises(ManifestValidationError, match="email_hash"):
            validate_manifest_shape(bad)


# ─────────────────────────────────────────────────────────────────
# Group 8: Realistic shapes
# ─────────────────────────────────────────────────────────────────

class TestRealisticShapes:

    def test_nis2_manifest(self) -> None:
        m = build_manifest(
            act_type_id="op:eu.nis2.art20.management_body_approval.v1",
            catalogue_entry_version=1,
            catalogue_source_uri="https://github.com/deyan-paroushev/actproof-events",
            catalogue_git_commit="0" * 40,
            catalogue_entry_hash="sha256:" + "a" * 64,
            catalogue_schema_hash="sha256:" + "b" * 64,
            issuer_org_name="Sofia Tech Holdings AD",
            issuer_authority_label="Management Body",
            title="NIS2 Article 20 approval, May 2026",
            claim={
                "approving_body_name": "Board of Directors",
                "decision_date": "2026-05-14",
                "approved_measures_summary": "Annual cybersecurity programme",
                "authority_basis_reference": "Statutes Art. 12",
                "responsible_officers": "CIO, CISO",
                "implementation_oversight_reference": "Internal audit Q3",
            },
            evidence=[
                Evidence(
                    label="signed_resolution_or_minutes",
                    filename_normalized="minutes_2026-05-14.pdf",
                    byte_size=482991,
                    mime_type="application/pdf",
                    sha256="sha256:" + "c" * 64,
                ),
                Evidence(
                    label="risk_management_measures_document",
                    filename_normalized="measures.pdf",
                    byte_size=1052336,
                    mime_type="application/pdf",
                    sha256="sha256:" + "d" * 64,
                ),
            ],
            recipients=[
                Recipient(
                    role="external_auditor",
                    org_name="Auditor AD",
                    email_hash=hash_email("auditor@firm.com"),
                ),
                Recipient(
                    role="competent_authority_supervisor",
                    org_name="National Cybersecurity Agency",
                    email_hash=hash_email("supervisor@authority.bg"),
                ),
            ],
            issued_at="2026-05-14T08:23:11Z",
        )
        validate_manifest_shape(m)
        digest = hash_manifest_hex(m)
        assert len(digest) == 64

    def test_eudr_manifest(self) -> None:
        m = build_manifest(
            act_type_id="op:eu.eudr.dds_preparation.v1",
            catalogue_entry_version=1,
            catalogue_source_uri="https://github.com/deyan-paroushev/actproof-events",
            catalogue_git_commit="1" * 40,
            catalogue_entry_hash="sha256:" + "e" * 64,
            catalogue_schema_hash="sha256:" + "b" * 64,
            issuer_org_name="Smart Organic AD",
            issuer_authority_label="Operator",
            title="EUDR DDS for coffee shipment, lot CO-2026-05-14-001",
            claim={
                "operator_org_name": "Smart Organic AD",
                "operator_eori": "BG203456789",
                "product_commodity_codes": ["0901", "1801"],
                "country_of_production": "BR",
                "preparation_timestamp": "2026-05-14T08:00:00Z",
            },
            evidence=[
                Evidence(
                    label="geojson_plot_geometries",
                    filename_normalized="plots.geojson",
                    byte_size=24576,
                    mime_type="application/geo+json",
                    sha256="sha256:" + "f" * 64,
                ),
                Evidence(
                    label="due_diligence_screening_report",
                    filename_normalized="screening.pdf",
                    byte_size=192384,
                    mime_type="application/pdf",
                    sha256="sha256:" + "1" * 64,
                ),
            ],
            recipients=[
                Recipient(
                    role="downstream_buyer",
                    org_name="Kaufland",
                    email_hash=hash_email("procurement@kaufland.de"),
                ),
            ],
            issued_at="2026-05-14T09:30:00Z",
        )
        validate_manifest_shape(m)

    def test_software_release_manifest(self) -> None:
        m = build_manifest(
            act_type_id="op:actproof.software_release.v1",
            catalogue_entry_version=1,
            catalogue_source_uri="https://github.com/deyan-paroushev/actproof-events",
            catalogue_git_commit="2" * 40,
            catalogue_entry_hash="sha256:" + "3" * 64,
            catalogue_schema_hash="sha256:" + "b" * 64,
            issuer_org_name="Advisa EOOD",
            issuer_authority_label="Maintainer",
            title="actproof-py v0.0.3",
            claim={
                "release_tag": "v0.0.3",
                "released_at": "2026-05-14T16:00:00Z",
                "source_url": "https://github.com/deyan-paroushev/actproof-py",
                "git_commit": "abc" + "0" * 37,
            },
            evidence=[
                Evidence(
                    label="release_notes",
                    filename_normalized="CHANGELOG.md",
                    byte_size=4096,
                    mime_type="text/markdown",
                    sha256="sha256:" + "4" * 64,
                ),
            ],
            recipients=[],  # software release: public, no specific witnesses
            issued_at="2026-05-14T16:00:00Z",
        )
        validate_manifest_shape(m)


# ─────────────────────────────────────────────────────────────────
# Group 9: Determinism / canonical bytes integration
# ─────────────────────────────────────────────────────────────────

class TestDeterminism:

    def test_canonical_bytes_match_across_calls(
        self, valid_manifest: Manifest
    ) -> None:
        d1 = manifest_to_dict(valid_manifest)
        d2 = manifest_to_dict(valid_manifest)
        # Both dicts produce identical canonical bytes.
        assert canonicalize(d1) == canonicalize(d2)

    def test_canonical_bytes_match_after_roundtrip(
        self, valid_manifest: Manifest
    ) -> None:
        d = manifest_to_dict(valid_manifest)
        reconstructed = manifest_from_dict(d)
        d2 = manifest_to_dict(reconstructed)
        assert canonicalize(d) == canonicalize(d2)
        assert hash_manifest(valid_manifest) == hash_manifest(reconstructed)


# ─────────────────────────────────────────────────────────────────
# Group 10: Constants
# ─────────────────────────────────────────────────────────────────

class TestConstants:

    def test_receipt_profile_v1_value(self) -> None:
        assert RECEIPT_PROFILE_V1 == "actproof-jcs-v1"

    def test_batching_profile_single_value(self) -> None:
        assert BATCHING_PROFILE_SINGLE == "single_attestation_anchor_v1"


# ─────────────────────────────────────────────────────────────────
# Group 11: Integration with canonical.canonicalize
# ─────────────────────────────────────────────────────────────────

class TestIntegrationWithCanonical:

    def test_manifest_dict_canonicalises_without_error(
        self, valid_manifest: Manifest
    ) -> None:
        # The manifest dict must contain only types that strict-mode JCS accepts.
        d = manifest_to_dict(valid_manifest)
        canonical_bytes = canonicalize(d)
        assert isinstance(canonical_bytes, bytes)

    def test_canonical_bytes_have_sorted_keys(
        self, valid_manifest: Manifest
    ) -> None:
        d = manifest_to_dict(valid_manifest)
        canonical = canonicalize(d).decode("utf-8")
        # Top-level keys must appear in alphabetical order in canonical bytes.
        keys_in_order = (
            "batching_profile", "catalogue", "claim", "evidence", "issued_at",
            "issuer", "receipt_profile", "recipients", "title",
        )
        positions = [canonical.index(f'"{k}":') for k in keys_in_order]
        assert positions == sorted(positions)

    def test_canonical_bytes_round_trip_through_json(
        self, valid_manifest: Manifest
    ) -> None:
        d = manifest_to_dict(valid_manifest)
        canonical = canonicalize(d)
        # Re-parse the canonical bytes; reconstruct a manifest; rehash.
        parsed = json.loads(canonical.decode("utf-8"))
        reconstructed = manifest_from_dict(parsed)
        assert hash_manifest(reconstructed) == hash_manifest(valid_manifest)
