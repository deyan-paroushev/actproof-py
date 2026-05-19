# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the bugfix delivery on Steps 4 and 5a per ChatGPT's review.

Six test groups:

* TestPackageFieldsBothOrNeither_FromDict: ``manifest_from_dict`` rejects
  manifests where exactly one of ``source_package_name`` and
  ``source_package_version`` is present. The two are both-or-neither;
  one-sided pairs would roundtrip to a different shape and lose the set
  field on re-serialisation, which is a correctness hazard.
* TestPackageFieldsBothOrNeither_BuildManifest: the same enforcement at
  the construction path.
* TestPackageFieldsTypeChecks: both fields, when present, must be strings.
* TestImportlibMetadataVersion: ``load_catalogue`` reads the installed
  distribution version via ``importlib.metadata.version()``, not from
  ``actproof_events.__version__``. This matters when an editable install
  has a stale ``__version__`` attribute that does not match the
  distribution metadata.
* TestResolveFromPackagedEventsTypeCoercion: ``_resolve_from_packaged_events``
  coerces ``str``, ``os.PathLike``, and ``pathlib.Path`` return values via
  ``Path(...)``, and returns ``None`` for unconvertible types rather than
  raising.
* TestValidationIssueCodes_PackageMismatch: the new
  ``SOURCE_PACKAGE_NAME_MISMATCH`` and ``SOURCE_PACKAGE_VERSION_MISMATCH``
  codes fire when manifest and loaded catalogue disagree on package
  provenance, and do NOT fire when only one side has it (because that is
  not an error: a verifier may legitimately load the catalogue a
  different way than the issuer did).
"""

from __future__ import annotations

import os
import sys
import types
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from actproof.catalogue import (
    Catalogue,
    ValidationIssue,
    _resolve_from_packaged_events,
    load_catalogue,
    validate_manifest,
)
from actproof.manifest import (
    CatalogueBinding,
    ManifestValidationError,
    build_manifest,
    hash_email,
    manifest_from_dict,
    manifest_to_dict,
)


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _minimal_manifest_dict(**catalogue_overrides: object) -> dict:
    """Return a valid canonical-shape manifest dict for parser tests."""
    catalogue = {
        "act_type_id": "op:actproof.software_release.v1",
        "entry_version": 1,
        "source_uri": "https://example.com/r",
        "git_commit": "0" * 40,
        "entry_hash": "sha256:" + ("a" * 64),
        "schema_hash": "sha256:" + ("b" * 64),
    }
    catalogue.update(catalogue_overrides)
    return {
        "receipt_profile": "actproof-jcs-v1",
        "issued_at": "2026-05-19T00:00:00Z",
        "catalogue": catalogue,
        "issuer": {
            "org_name": "Test Issuer",
            "authority_label": "open_source_maintainer",
        },
        "title": "Test manifest",
        "claim": {
            "release_org": "Test",
            "release_repository": "https://example.com/r",
            "release_version": "v0.0.1",
            "release_commit_sha": "1" * 40,
            "release_published_at": "2026-05-19T00:00:00Z",
        },
        "evidence": [
            {
                "label": "release_manifest",
                "filename_normalized": "manifest.txt",
                "byte_size": 1,
                "mime_type": "text/plain",
                "sha256": "sha256:" + ("c" * 64),
            }
        ],
        "recipients": [
            {
                "role": "public_archive",
                "org_name": "Test recipient",
                "email_hash": hash_email("a@example.com"),
            }
        ],
        "batching_profile": "single_attestation_anchor_v1",
    }


def _kwargs_for_build_manifest(**catalogue_overrides: object) -> dict:
    """Return kwargs for build_manifest that produce a valid manifest."""
    base = {
        "act_type_id": "op:actproof.software_release.v1",
        "catalogue_entry_version": 1,
        "catalogue_source_uri": "https://example.com/r",
        "catalogue_git_commit": "0" * 40,
        "catalogue_entry_hash": "sha256:" + ("a" * 64),
        "catalogue_schema_hash": "sha256:" + ("b" * 64),
        "issuer_org_name": "Test Issuer",
        "issuer_authority_label": "open_source_maintainer",
        "title": "Test manifest",
        "claim": {
            "release_org": "Test",
            "release_repository": "https://example.com/r",
            "release_version": "v0.0.1",
            "release_commit_sha": "1" * 40,
            "release_published_at": "2026-05-19T00:00:00Z",
        },
        "evidence": [],
        "recipients": [],
        "issued_at": "2026-05-19T00:00:00Z",
    }
    base.update(catalogue_overrides)
    return base


# ─────────────────────────────────────────────────────────────────
# TestPackageFieldsBothOrNeither_FromDict
# ─────────────────────────────────────────────────────────────────

class TestPackageFieldsBothOrNeither_FromDict:
    """manifest_from_dict rejects one-sided package fields."""

    def test_both_absent_succeeds(self) -> None:
        """The default case (no package provenance) parses cleanly."""
        d = _minimal_manifest_dict()
        m = manifest_from_dict(d)
        assert m.catalogue.source_package_name is None
        assert m.catalogue.source_package_version is None

    def test_both_present_succeeds(self) -> None:
        """When both fields are present, parsing succeeds and the values land."""
        d = _minimal_manifest_dict(
            source_package_name="actproof-events",
            source_package_version="1.4.0rc1",
        )
        m = manifest_from_dict(d)
        assert m.catalogue.source_package_name == "actproof-events"
        assert m.catalogue.source_package_version == "1.4.0rc1"

    def test_only_name_set_raises(self) -> None:
        d = _minimal_manifest_dict(source_package_name="actproof-events")
        with pytest.raises(ManifestValidationError, match="both be present or both be omitted"):
            manifest_from_dict(d)

    def test_only_version_set_raises(self) -> None:
        d = _minimal_manifest_dict(source_package_version="1.4.0rc1")
        with pytest.raises(ManifestValidationError, match="both be present or both be omitted"):
            manifest_from_dict(d)

    def test_one_explicit_null_one_set_raises(self) -> None:
        """Explicit None on one side, value on the other, is the same
        case as omission. Both formulations should raise."""
        d = _minimal_manifest_dict(
            source_package_name="actproof-events",
            source_package_version=None,
        )
        with pytest.raises(ManifestValidationError, match="both be present or both be omitted"):
            manifest_from_dict(d)


# ─────────────────────────────────────────────────────────────────
# TestPackageFieldsBothOrNeither_BuildManifest
# ─────────────────────────────────────────────────────────────────

class TestPackageFieldsBothOrNeither_BuildManifest:
    """build_manifest rejects one-sided package fields at construction time."""

    def test_both_absent_succeeds(self) -> None:
        m = build_manifest(**_kwargs_for_build_manifest())
        assert m.catalogue.source_package_name is None
        assert m.catalogue.source_package_version is None

    def test_both_present_succeeds(self) -> None:
        m = build_manifest(
            **_kwargs_for_build_manifest(
                catalogue_source_package_name="actproof-events",
                catalogue_source_package_version="1.4.0rc1",
            )
        )
        assert m.catalogue.source_package_name == "actproof-events"
        assert m.catalogue.source_package_version == "1.4.0rc1"

    def test_only_name_set_raises(self) -> None:
        with pytest.raises(ManifestValidationError, match="both be provided or both be None"):
            build_manifest(
                **_kwargs_for_build_manifest(
                    catalogue_source_package_name="actproof-events",
                )
            )

    def test_only_version_set_raises(self) -> None:
        with pytest.raises(ManifestValidationError, match="both be provided or both be None"):
            build_manifest(
                **_kwargs_for_build_manifest(
                    catalogue_source_package_version="1.4.0rc1",
                )
            )


# ─────────────────────────────────────────────────────────────────
# TestPackageFieldsTypeChecks
# ─────────────────────────────────────────────────────────────────

class TestPackageFieldsTypeChecks:
    """The two fields, when present, must be strings."""

    def test_non_string_name_raises_in_from_dict(self) -> None:
        d = _minimal_manifest_dict(
            source_package_name=123,
            source_package_version="1.4.0rc1",
        )
        with pytest.raises(ManifestValidationError, match="source_package_name must be a string"):
            manifest_from_dict(d)

    def test_non_string_version_raises_in_from_dict(self) -> None:
        d = _minimal_manifest_dict(
            source_package_name="actproof-events",
            source_package_version=1.4,
        )
        with pytest.raises(ManifestValidationError, match="source_package_version must be a string"):
            manifest_from_dict(d)

    def test_non_string_name_raises_in_build_manifest(self) -> None:
        with pytest.raises(ManifestValidationError, match="must be a string"):
            build_manifest(
                **_kwargs_for_build_manifest(
                    catalogue_source_package_name=123,
                    catalogue_source_package_version="1.4.0rc1",
                )
            )

    def test_non_string_version_raises_in_build_manifest(self) -> None:
        with pytest.raises(ManifestValidationError, match="must be a string"):
            build_manifest(
                **_kwargs_for_build_manifest(
                    catalogue_source_package_name="actproof-events",
                    catalogue_source_package_version=42,
                )
            )


# ─────────────────────────────────────────────────────────────────
# TestImportlibMetadataVersion
# ─────────────────────────────────────────────────────────────────

class TestImportlibMetadataVersion:
    """load_catalogue uses importlib.metadata.version, not __version__."""

    def test_version_read_via_importlib_metadata(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """When importlib.metadata.version returns 'X.Y.Z' but the
        package's __version__ attribute is something else, the
        Catalogue should record the importlib.metadata value.
        """
        # Set the env to nothing and cwd to empty so resolution falls
        # through to the packaged events path.
        monkeypatch.delenv("ACTPROOF_CATALOGUE_PATH", raising=False)
        monkeypatch.chdir(tmp_path)

        # Confirm the metadata reads "actproof-events" at SOME version
        from importlib.metadata import version as md_version, PackageNotFoundError
        try:
            md_version("actproof-events")
        except PackageNotFoundError:
            pytest.skip("actproof-events not installed as a distribution")

        # Mock importlib.metadata.version inside the catalogue module so
        # we control what load_catalogue reads.
        import actproof.catalogue as cat_mod

        # The function imports inside load_catalogue; patch sys.modules.
        with patch("importlib.metadata.version", return_value="9.9.9-test"):
            cat = load_catalogue()

        assert cat.source_package_name == "actproof-events"
        assert cat.source_package_version == "9.9.9-test"

    def test_handles_package_not_found(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """When importlib.metadata raises PackageNotFoundError, the
        catalogue still loads, just without package provenance."""
        monkeypatch.delenv("ACTPROOF_CATALOGUE_PATH", raising=False)
        monkeypatch.chdir(tmp_path)

        from importlib.metadata import PackageNotFoundError
        with patch(
            "importlib.metadata.version",
            side_effect=PackageNotFoundError("simulated"),
        ):
            cat = load_catalogue()

        # Catalogue loads cleanly
        assert len(cat) > 0
        # but no package provenance
        assert cat.source_package_name is None
        assert cat.source_package_version is None


# ─────────────────────────────────────────────────────────────────
# TestResolveFromPackagedEventsTypeCoercion
# ─────────────────────────────────────────────────────────────────

class TestResolveFromPackagedEventsTypeCoercion:
    """_resolve_from_packaged_events coerces Path-like return values."""

    def _stub_actproof_events(
        self,
        monkeypatch: pytest.MonkeyPatch,
        return_value: object,
    ) -> None:
        """Replace actproof_events.get_catalogue_path with a callable
        that returns the given value."""
        stub = types.ModuleType("actproof_events")
        stub.get_catalogue_path = lambda: return_value  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "actproof_events", stub)

    def test_accepts_str(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A return value of ``str`` is coerced via Path(...) and resolved."""
        self._stub_actproof_events(monkeypatch, str(tmp_path))
        result = _resolve_from_packaged_events()
        assert result == tmp_path.resolve()

    def test_accepts_pathlike(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A return value of ``os.PathLike`` (e.g. ``pathlib.PurePath``)
        is coerced via Path(...) and resolved."""
        class MyPathLike:
            def __init__(self, p: Path) -> None:
                self._p = str(p)

            def __fspath__(self) -> str:
                return self._p

        self._stub_actproof_events(monkeypatch, MyPathLike(tmp_path))
        result = _resolve_from_packaged_events()
        assert result == tmp_path.resolve()

    def test_accepts_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A return value of ``Path`` works as before."""
        self._stub_actproof_events(monkeypatch, tmp_path)
        result = _resolve_from_packaged_events()
        assert result == tmp_path.resolve()

    def test_returns_none_for_unconvertible(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An int return value cannot be coerced and yields None
        rather than raising TypeError."""
        self._stub_actproof_events(monkeypatch, 12345)
        assert _resolve_from_packaged_events() is None

    def test_returns_none_for_nonexistent_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A Path that does not exist on disk yields None."""
        self._stub_actproof_events(monkeypatch, "/nonexistent/path/foo/bar")
        assert _resolve_from_packaged_events() is None


# ─────────────────────────────────────────────────────────────────
# TestValidationIssueCodes_PackageMismatch
# ─────────────────────────────────────────────────────────────────

class TestValidationIssueCodes_PackageMismatch:
    """validate_manifest emits the new mismatch codes when both sides have
    package fields and they differ."""

    def _build_catalogue_with_package(
        self, name: str, version: str
    ) -> Catalogue:
        """Construct a Catalogue with package provenance fields set."""
        from actproof.catalogue import CatalogueEntry, SignaturePolicy
        # Build a minimal entry for the validate_manifest path
        sp = SignaturePolicy(minimum="issuer_record", supports=())
        entry = CatalogueEntry(
            schema="actproof.act_catalogue_entry.v3",
            act_type_id="op:actproof.software_release.v1",
            claim_type="software_release",
            display_name="Test",
            regulatory_citation=None,
            required_claim_fields=(
                "release_org",
                "release_repository",
                "release_version",
                "release_commit_sha",
                "release_published_at",
            ),
            optional_claim_fields=(),
            required_evidence_labels=(),
            eligible_issuer_roles=("open_source_maintainer",),
            recommended_witness_roles=(),
            signature_policy=sp,
            version=1,
            supersedes=None,
            maintainer="test",
            test_vector_reference=None,
            entry_hash="sha256:" + ("a" * 64),
            regulated_context_profile=None,
            prior_receipts_profile=None,
            reliance_context=None,
            disclosure_profile=None,
        )
        return Catalogue(
            entries={entry.act_type_id: entry},
            source_root="/test",
            source_uri=None,
            git_commit=None,
            schema_hash="sha256:" + ("b" * 64),
            source_package_name=name,
            source_package_version=version,
        )

    def test_no_issue_when_both_sides_match(self) -> None:
        m = build_manifest(
            **_kwargs_for_build_manifest(
                catalogue_source_package_name="actproof-events",
                catalogue_source_package_version="1.4.0rc1",
            )
        )
        cat = self._build_catalogue_with_package("actproof-events", "1.4.0rc1")
        issues = validate_manifest(m, cat)
        # No package-mismatch issues
        codes = {i.code for i in issues}
        assert "SOURCE_PACKAGE_NAME_MISMATCH" not in codes
        assert "SOURCE_PACKAGE_VERSION_MISMATCH" not in codes

    def test_name_mismatch_flagged(self) -> None:
        m = build_manifest(
            **_kwargs_for_build_manifest(
                catalogue_source_package_name="actproof-events",
                catalogue_source_package_version="1.4.0rc1",
            )
        )
        cat = self._build_catalogue_with_package("other-events-pkg", "1.4.0rc1")
        issues = validate_manifest(m, cat)
        codes = {i.code for i in issues}
        assert "SOURCE_PACKAGE_NAME_MISMATCH" in codes
        # Find the issue and confirm the field path
        nm = next(i for i in issues if i.code == "SOURCE_PACKAGE_NAME_MISMATCH")
        assert nm.field == "catalogue.source_package_name"
        assert "actproof-events" in nm.message
        assert "other-events-pkg" in nm.message

    def test_version_mismatch_flagged(self) -> None:
        m = build_manifest(
            **_kwargs_for_build_manifest(
                catalogue_source_package_name="actproof-events",
                catalogue_source_package_version="1.4.0rc1",
            )
        )
        cat = self._build_catalogue_with_package("actproof-events", "1.4.1")
        issues = validate_manifest(m, cat)
        codes = {i.code for i in issues}
        assert "SOURCE_PACKAGE_VERSION_MISMATCH" in codes
        vm = next(i for i in issues if i.code == "SOURCE_PACKAGE_VERSION_MISMATCH")
        assert "1.4.0rc1" in vm.message
        assert "1.4.1" in vm.message

    def test_no_issue_when_only_manifest_has_package(self) -> None:
        """Manifest has package fields, catalogue does not. This is not
        an error: the verifier may have legitimately loaded the catalogue
        another way (env var, vendored copy). No mismatch issue should
        fire."""
        m = build_manifest(
            **_kwargs_for_build_manifest(
                catalogue_source_package_name="actproof-events",
                catalogue_source_package_version="1.4.0rc1",
            )
        )
        cat = self._build_catalogue_with_package(None, None)  # type: ignore[arg-type]
        issues = validate_manifest(m, cat)
        codes = {i.code for i in issues}
        assert "SOURCE_PACKAGE_NAME_MISMATCH" not in codes
        assert "SOURCE_PACKAGE_VERSION_MISMATCH" not in codes

    def test_no_issue_when_only_catalogue_has_package(self) -> None:
        """Catalogue has package fields, manifest does not. Symmetric to
        the above: not an error. (Older manifest, newer verifier.)"""
        m = build_manifest(**_kwargs_for_build_manifest())
        cat = self._build_catalogue_with_package("actproof-events", "1.4.0rc1")
        issues = validate_manifest(m, cat)
        codes = {i.code for i in issues}
        assert "SOURCE_PACKAGE_NAME_MISMATCH" not in codes
        assert "SOURCE_PACKAGE_VERSION_MISMATCH" not in codes
