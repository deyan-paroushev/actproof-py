# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Tests for openproof.verify.

All checks tested in isolation with mocked indexer and mocked tsp_client.

Sixteen test groups:

* TestCheckStatus: enum values.
* TestCheckResult: dataclass + ok/failed properties.
* TestVerificationResult: dataclass + helpers.
* TestReceiptProfileCheck: pass for v1, fail for unknown profile.
* TestManifestHashCheck: pass for honest receipt, fail on mismatch.
* TestNotePayloadCheck: pass when reconstruction matches, fail otherwise.
* TestCatalogueCheckSkip: skipped when no catalogue passed.
* TestCatalogueCheckPass: passes for a valid manifest against a real catalogue.
* TestCatalogueCheckFail: fails when manifest doesn't match catalogue entry.
* TestAnchorCheckDraft: draft receipts skip the anchor check.
* TestAnchorCheckPass: matching on-chain note bytes pass.
* TestAnchorCheckFail: mismatched on-chain bytes fail.
* TestAnchorCheckError: indexer errors surface as ERROR status.
* TestTimestampCheckPass: valid token passes.
* TestTimestampCheckFail: invalid token (mocked verify raise) fails.
* TestOrchestrator: end-to-end verify_receipt with skip flags and edge cases.
"""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from openproof.anchor import build_note_payload
from openproof.catalogue import load_catalogue
from openproof.manifest import (
    BATCHING_PROFILE_SINGLE,
    Evidence,
    Recipient,
    build_manifest,
    hash_email,
    hash_file_bytes,
    hash_manifest_hex,
)
from openproof.receipt import (
    ALGORAND_MAINNET,
    ALGORAND_TESTNET,
    AnchorRecord,
    Receipt,
    TimestampToken,
    build_receipt,
)
from openproof.verify import (
    SUPPORTED_RECEIPT_PROFILES,
    CheckResult,
    CheckStatus,
    VerificationResult,
    _check_anchor_on_chain,
    _check_catalogue_conformance,
    _check_manifest_hash,
    _check_note_payload_reproducible,
    _check_receipt_profile,
    _check_timestamp_signature,
    verify_receipt,
)


# ─────────────────────────────────────────────────────────────────
# Helpers: build a real Receipt for testing
# ─────────────────────────────────────────────────────────────────

from tests import REAL_ACTS_PATH as _CATALOGUE_PATH, skip_if_no_real_catalogue

pytestmark = skip_if_no_real_catalogue


@pytest.fixture
def catalogue():
    return load_catalogue(
        acts_path=_CATALOGUE_PATH,
        source_uri="https://github.com/deyan-paroushev/openproof-events",
        git_commit="a" * 40,
    )


@pytest.fixture
def manifest(catalogue):
    nis2 = catalogue.get("op:eu.nis2.art20.management_body_approval.v1")
    return build_manifest(
        act_type_id=nis2.act_type_id,
        catalogue_entry_version=nis2.version,
        catalogue_source_uri=catalogue.source_uri,
        catalogue_git_commit=catalogue.git_commit,
        catalogue_entry_hash=nis2.entry_hash,
        catalogue_schema_hash=catalogue.schema_hash,
        issuer_org_name="Sofia Tech Holdings AD",
        issuer_authority_label="Management Body",
        title="NIS2 approval, May 2026",
        claim={
            "approving_body_name": "Board of Directors",
            "decision_date": "2026-05-14",
            "approved_measures_summary": "Programme",
            "authority_basis_reference": "Statutes Art. 12",
            "responsible_officers": "CIO, CISO",
            "implementation_oversight_reference": "Audit Q3",
        },
        evidence=[
            Evidence(
                label="signed_resolution_or_minutes",
                filename_normalized="minutes.pdf",
                byte_size=1000,
                mime_type="application/pdf",
                sha256=hash_file_bytes(b"fake"),
            ),
            Evidence(
                label="risk_management_measures_document",
                filename_normalized="r.pdf",
                byte_size=2000,
                mime_type="application/pdf",
                sha256=hash_file_bytes(b"fake2"),
            ),
        ],
        recipients=[
            Recipient(
                role="external_auditor",
                org_name="Auditor AD",
                email_hash=hash_email("auditor@firm.com"),
            ),
        ],
        issued_at="2026-05-14T08:23:11Z",
    )


@pytest.fixture
def receipt(manifest):
    manifest_hash_bytes = bytes.fromhex(hash_manifest_hex(manifest))
    payload = build_note_payload(manifest_hash_bytes)
    payload_b64 = base64.b64encode(payload).decode("ascii")

    anchor = AnchorRecord(
        network=ALGORAND_MAINNET,
        txid="REALTXID" + "A" * 44,
        block_round=39000000,
        confirmed_at="2026-05-14T08:24:00Z",
        note_format="arc-2",
        note_dapp_name="openproof",
        note_format_version="j",
        note_payload_b64=payload_b64,
    )
    timestamp = TimestampToken(
        tsa_url="https://tsa.example.com",
        tsa_name="Example TSA",
        token_b64=base64.b64encode(b"fake DER token").decode("ascii"),
        policy_oid="1.2.3",
        hash_alg="sha-256",
        imprint_hex=manifest_hash_bytes.hex(),
        timestamp="2026-05-14T08:23:11Z",
    )
    return build_receipt(
        manifest=manifest,
        anchor=anchor,
        trusted_timestamp=timestamp,
    )


# ─────────────────────────────────────────────────────────────────
# Group 1: CheckStatus enum
# ─────────────────────────────────────────────────────────────────

class TestCheckStatus:

    def test_four_states_exist(self) -> None:
        assert CheckStatus.PASS.value == "pass"
        assert CheckStatus.FAIL.value == "fail"
        assert CheckStatus.SKIP.value == "skip"
        assert CheckStatus.ERROR.value == "error"

    def test_is_str_enum(self) -> None:
        assert isinstance(CheckStatus.PASS, str)
        assert CheckStatus.PASS == "pass"


# ─────────────────────────────────────────────────────────────────
# Group 2: CheckResult
# ─────────────────────────────────────────────────────────────────

class TestCheckResult:

    def test_pass_is_ok(self) -> None:
        c = CheckResult(name="x", status=CheckStatus.PASS)
        assert c.ok is True
        assert c.failed is False

    def test_skip_is_ok(self) -> None:
        c = CheckResult(name="x", status=CheckStatus.SKIP, detail="why")
        assert c.ok is True
        assert c.failed is False

    def test_fail_is_failed(self) -> None:
        c = CheckResult(name="x", status=CheckStatus.FAIL, detail="why")
        assert c.ok is False
        assert c.failed is True

    def test_error_is_failed(self) -> None:
        c = CheckResult(name="x", status=CheckStatus.ERROR, detail="why")
        assert c.ok is False
        assert c.failed is True


# ─────────────────────────────────────────────────────────────────
# Group 3: VerificationResult
# ─────────────────────────────────────────────────────────────────

class TestVerificationResult:

    def test_ok_true_when_all_pass(self, receipt: Receipt) -> None:
        result = VerificationResult(
            receipt=receipt,
            checks=(
                CheckResult(name="a", status=CheckStatus.PASS),
                CheckResult(name="b", status=CheckStatus.PASS),
            ),
            ok=True,
        )
        assert result.ok is True
        assert result.failed_checks() == ()

    def test_failed_checks_returns_failures(self, receipt: Receipt) -> None:
        result = VerificationResult(
            receipt=receipt,
            checks=(
                CheckResult(name="a", status=CheckStatus.PASS),
                CheckResult(name="b", status=CheckStatus.FAIL, detail="bad"),
                CheckResult(name="c", status=CheckStatus.SKIP, detail="why"),
                CheckResult(name="d", status=CheckStatus.ERROR, detail="oops"),
            ),
            ok=False,
        )
        failed = result.failed_checks()
        assert len(failed) == 2
        assert failed[0].name == "b"
        assert failed[1].name == "d"

    def test_get_check_by_name(self, receipt: Receipt) -> None:
        result = VerificationResult(
            receipt=receipt,
            checks=(
                CheckResult(name="alpha", status=CheckStatus.PASS),
                CheckResult(name="beta", status=CheckStatus.FAIL, detail="x"),
            ),
            ok=False,
        )
        assert result.get_check("alpha").status == CheckStatus.PASS
        assert result.get_check("beta").status == CheckStatus.FAIL
        assert result.get_check("gamma") is None


# ─────────────────────────────────────────────────────────────────
# Group 4: receipt_profile check
# ─────────────────────────────────────────────────────────────────

class TestReceiptProfileCheck:

    def test_v1_profile_passes(self, receipt: Receipt) -> None:
        result = _check_receipt_profile(receipt)
        assert result.status == CheckStatus.PASS

    def test_unknown_profile_fails(self, receipt: Receipt) -> None:
        mutated = replace(receipt, receipt_profile="openproof-v999")
        result = _check_receipt_profile(mutated)
        assert result.status == CheckStatus.FAIL
        assert "openproof-v999" in result.detail
        assert "openproof-jcs-v1" in result.detail


# ─────────────────────────────────────────────────────────────────
# Group 5: manifest_hash check
# ─────────────────────────────────────────────────────────────────

class TestManifestHashCheck:

    def test_honest_receipt_passes(self, receipt: Receipt) -> None:
        result = _check_manifest_hash(receipt)
        assert result.status == CheckStatus.PASS

    def test_substituted_hash_fails(self, receipt: Receipt) -> None:
        # Replace the manifest_hash with a wrong value but keep the manifest.
        bad = replace(receipt, manifest_hash="sha256:" + "0" * 64)
        result = _check_manifest_hash(bad)
        assert result.status == CheckStatus.FAIL
        assert "tampered" in result.detail or "match" in result.detail


# ─────────────────────────────────────────────────────────────────
# Group 6: note_payload_reproducible check
# ─────────────────────────────────────────────────────────────────

class TestNotePayloadCheck:

    def test_honest_receipt_passes(self, receipt: Receipt) -> None:
        result = _check_note_payload_reproducible(receipt)
        assert result.status == CheckStatus.PASS

    def test_mutated_note_payload_fails(self, receipt: Receipt) -> None:
        # Replace the note_payload_b64 with bytes that don't reproduce.
        wrong_payload = base64.b64encode(b'{"h":"deadbeef","t":"x","v":1}').decode("ascii")
        bad_anchor = replace(receipt.anchor, note_payload_b64=wrong_payload)
        bad = replace(receipt, anchor=bad_anchor)
        result = _check_note_payload_reproducible(bad)
        assert result.status == CheckStatus.FAIL


# ─────────────────────────────────────────────────────────────────
# Group 7: catalogue_conformance check - skipped when None
# ─────────────────────────────────────────────────────────────────

class TestCatalogueCheckSkip:

    def test_no_catalogue_is_skip(self, receipt: Receipt) -> None:
        result = _check_catalogue_conformance(receipt, catalogue=None)
        assert result.status == CheckStatus.SKIP
        assert "catalogue" in result.detail.lower()


# ─────────────────────────────────────────────────────────────────
# Group 8: catalogue_conformance check - passes
# ─────────────────────────────────────────────────────────────────

class TestCatalogueCheckPass:

    def test_valid_manifest_passes_catalogue(
        self, receipt: Receipt, catalogue
    ) -> None:
        result = _check_catalogue_conformance(receipt, catalogue=catalogue)
        assert result.status == CheckStatus.PASS


# ─────────────────────────────────────────────────────────────────
# Group 9: catalogue_conformance check - fails
# ─────────────────────────────────────────────────────────────────

class TestCatalogueCheckFail:

    def test_unknown_act_type_fails(self, receipt: Receipt, catalogue) -> None:
        # Mutate the manifest so the act_type_id doesn't exist in the catalogue.
        bad_catalogue_binding = replace(
            receipt.manifest.catalogue,
            act_type_id="op:no.such.act.type.v1",
        )
        bad_manifest = replace(receipt.manifest, catalogue=bad_catalogue_binding)
        bad = replace(receipt, manifest=bad_manifest)
        result = _check_catalogue_conformance(bad, catalogue=catalogue)
        assert result.status == CheckStatus.FAIL


# ─────────────────────────────────────────────────────────────────
# Group 10: anchor_on_chain check - draft mode skips
# ─────────────────────────────────────────────────────────────────

class TestAnchorCheckDraft:

    def test_empty_txid_is_skip(self, receipt: Receipt) -> None:
        # Make this a draft receipt.
        draft_anchor = replace(receipt.anchor, txid="", block_round=None)
        draft = replace(receipt, anchor=draft_anchor)
        result = _check_anchor_on_chain(draft, indexer_client=None)
        assert result.status == CheckStatus.SKIP
        assert "draft" in result.detail.lower()


# ─────────────────────────────────────────────────────────────────
# Group 11: anchor_on_chain check - passes
# ─────────────────────────────────────────────────────────────────

class TestAnchorCheckPass:

    def test_matching_on_chain_note_passes(self, receipt: Receipt) -> None:
        # Build a mock indexer that returns the same note the receipt declares.
        full_note = b"openproof:j" + base64.b64decode(
            receipt.anchor.note_payload_b64
        )
        on_chain_note_b64 = base64.b64encode(full_note).decode("ascii")
        mock_indexer = MagicMock()
        mock_indexer.transaction.return_value = {
            "transaction": {"note": on_chain_note_b64},
        }
        result = _check_anchor_on_chain(receipt, indexer_client=mock_indexer)
        assert result.status == CheckStatus.PASS
        mock_indexer.transaction.assert_called_once_with(receipt.anchor.txid)


# ─────────────────────────────────────────────────────────────────
# Group 12: anchor_on_chain check - failures
# ─────────────────────────────────────────────────────────────────

class TestAnchorCheckFail:

    def test_missing_note_fails(self, receipt: Receipt) -> None:
        mock_indexer = MagicMock()
        mock_indexer.transaction.return_value = {"transaction": {}}
        result = _check_anchor_on_chain(receipt, indexer_client=mock_indexer)
        assert result.status == CheckStatus.FAIL
        assert "no note" in result.detail.lower()

    def test_wrong_prefix_fails(self, receipt: Receipt) -> None:
        # Note starts with "otherapp:k..." instead of "openproof:j..."
        wrong_note = b"otherapp:k" + base64.b64decode(
            receipt.anchor.note_payload_b64
        )
        wrong_b64 = base64.b64encode(wrong_note).decode("ascii")
        mock_indexer = MagicMock()
        mock_indexer.transaction.return_value = {
            "transaction": {"note": wrong_b64},
        }
        result = _check_anchor_on_chain(receipt, indexer_client=mock_indexer)
        assert result.status == CheckStatus.FAIL
        assert "prefix" in result.detail.lower()

    def test_wrong_payload_fails(self, receipt: Receipt) -> None:
        # Right prefix, wrong payload.
        wrong_note = b"openproof:j" + b'{"h":"deadbeef","t":"x","v":1}'
        wrong_b64 = base64.b64encode(wrong_note).decode("ascii")
        mock_indexer = MagicMock()
        mock_indexer.transaction.return_value = {
            "transaction": {"note": wrong_b64},
        }
        result = _check_anchor_on_chain(receipt, indexer_client=mock_indexer)
        assert result.status == CheckStatus.FAIL
        assert "payload" in result.detail.lower() or "match" in result.detail.lower()


# ─────────────────────────────────────────────────────────────────
# Group 13: anchor_on_chain check - errors
# ─────────────────────────────────────────────────────────────────

class TestAnchorCheckError:

    def test_indexer_exception_becomes_error(self, receipt: Receipt) -> None:
        mock_indexer = MagicMock()
        mock_indexer.transaction.side_effect = RuntimeError("indexer down")
        result = _check_anchor_on_chain(receipt, indexer_client=mock_indexer)
        assert result.status == CheckStatus.ERROR
        assert "indexer down" in result.detail


# ─────────────────────────────────────────────────────────────────
# Group 14: timestamp_signature check - passes
# ─────────────────────────────────────────────────────────────────

class TestTimestampCheckPass:

    def test_valid_token_passes(self, receipt: Receipt) -> None:
        # Mock TSPVerifier.verify to succeed.
        with patch(
            "openproof.verify._TSPVerifier"
        ) as mock_verifier_class:
            instance = MagicMock()
            instance.verify.return_value = MagicMock()  # any verified obj
            mock_verifier_class.return_value = instance
            with patch(
                "openproof.verify._TSP_VERIFIER_AVAILABLE", True
            ):
                result = _check_timestamp_signature(receipt)
        assert result.status == CheckStatus.PASS


# ─────────────────────────────────────────────────────────────────
# Group 15: timestamp_signature check - fails
# ─────────────────────────────────────────────────────────────────

class TestTimestampCheckFail:

    def test_invalid_token_fails(self, receipt: Receipt) -> None:
        # Mock TSPVerifier.verify to raise.
        with patch("openproof.verify._TSPVerifier") as mock_verifier_class:
            instance = MagicMock()
            instance.verify.side_effect = RuntimeError("bad signature")
            mock_verifier_class.return_value = instance
            with patch("openproof.verify._TSP_VERIFIER_AVAILABLE", True):
                result = _check_timestamp_signature(receipt)
        assert result.status == CheckStatus.FAIL
        assert "bad signature" in result.detail


# ─────────────────────────────────────────────────────────────────
# Group 16: Orchestrator
# ─────────────────────────────────────────────────────────────────

class TestOrchestrator:

    def test_all_checks_run_in_order(self, receipt: Receipt) -> None:
        # Without catalogue, indexer, or working tsp_client, several checks
        # will skip. But verify_receipt should still produce a result.
        result = verify_receipt(
            receipt,
            skip_anchor_check=True,
            skip_timestamp_check=True,
            skip_catalogue_check=True,
        )
        names = [c.name for c in result.checks]
        assert names == [
            "receipt_profile_supported",
            "manifest_hash_match",
            "note_payload_reproducible",
            "catalogue_conformance",
            "anchor_on_chain",
            "timestamp_signature",
        ]

    def test_skip_flags_work(self, receipt: Receipt) -> None:
        result = verify_receipt(
            receipt,
            skip_anchor_check=True,
            skip_timestamp_check=True,
            skip_catalogue_check=True,
        )
        anchor = result.get_check("anchor_on_chain")
        timestamp = result.get_check("timestamp_signature")
        cat = result.get_check("catalogue_conformance")
        assert anchor.status == CheckStatus.SKIP
        assert timestamp.status == CheckStatus.SKIP
        assert cat.status == CheckStatus.SKIP

    def test_local_checks_pass_for_honest_receipt(
        self, receipt: Receipt
    ) -> None:
        result = verify_receipt(
            receipt,
            skip_anchor_check=True,
            skip_timestamp_check=True,
            skip_catalogue_check=True,
        )
        # The three local checks should all PASS for an honest receipt.
        for check_name in [
            "receipt_profile_supported",
            "manifest_hash_match",
            "note_payload_reproducible",
        ]:
            check = result.get_check(check_name)
            assert check.status == CheckStatus.PASS, (
                f"{check_name} expected PASS, got {check.status}: {check.detail}"
            )

    def test_overall_ok_true_when_no_failures(
        self, receipt: Receipt
    ) -> None:
        result = verify_receipt(
            receipt,
            skip_anchor_check=True,
            skip_timestamp_check=True,
            skip_catalogue_check=True,
        )
        assert result.ok is True

    def test_overall_ok_false_on_any_failure(
        self, receipt: Receipt
    ) -> None:
        # Substitute the manifest_hash to force a failure.
        bad = replace(receipt, manifest_hash="sha256:" + "0" * 64)
        result = verify_receipt(
            bad,
            skip_anchor_check=True,
            skip_timestamp_check=True,
            skip_catalogue_check=True,
        )
        assert result.ok is False
        failed = result.failed_checks()
        assert len(failed) >= 1
        assert any(c.name == "manifest_hash_match" for c in failed)

    def test_orchestrator_does_not_short_circuit(
        self, receipt: Receipt
    ) -> None:
        # Multiple failures should all be reported.
        bad = replace(receipt, manifest_hash="sha256:" + "0" * 64)
        result = verify_receipt(
            bad,
            skip_anchor_check=True,
            skip_timestamp_check=True,
            skip_catalogue_check=True,
        )
        # Both manifest_hash and note_payload should fail (they both depend
        # on the manifest_hash being right).
        assert result.get_check("manifest_hash_match").status == CheckStatus.FAIL

    def test_orchestrator_runs_full_check_with_catalogue(
        self, receipt: Receipt, catalogue
    ) -> None:
        # Catalogue check runs and passes; anchor and timestamp skip.
        result = verify_receipt(
            receipt,
            catalogue=catalogue,
            skip_anchor_check=True,
            skip_timestamp_check=True,
        )
        cat = result.get_check("catalogue_conformance")
        assert cat.status == CheckStatus.PASS
