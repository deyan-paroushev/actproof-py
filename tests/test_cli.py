# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Tests for the actproof CLI.

Uses Click's CliRunner. No real network calls; the anchor command tests
mock the underlying anchor_manifest function so they exercise the CLI
plumbing without touching algod.

Six test groups:

* TestMainGroup: --version and --help.
* TestValidate: validate command happy path, errors, JSON output.
* TestVerify: verify command for honest and tampered receipts.
* TestAnchor: anchor command for DRAFT mode (no network), env var handling.
* TestAnchorSignerSelection: error paths when neither signer source given,
  or both given.
* TestExitCodes: each command returns the right exit code.
"""

from __future__ import annotations

import base64
import json
import os
import warnings
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from actproof.anchor import build_note_payload
from actproof.catalogue import load_catalogue
from actproof.cli import main
from actproof.manifest import (
    Evidence,
    Recipient,
    build_manifest,
    hash_email,
    hash_file_bytes,
    hash_manifest_hex,
    manifest_to_dict,
)
from actproof.receipt import (
    ALGORAND_MAINNET,
    AnchorRecord,
    TimestampToken,
    build_receipt,
    write_receipt,
)


from tests import REAL_ACTS_PATH as _CATALOGUE_DIR, skip_if_no_real_catalogue

pytestmark = skip_if_no_real_catalogue

_TEST_MNEMONIC = (
    "total monkey oven casino taxi maximum furnace approve cliff lizard "
    "address apple laundry consider hair flash file kingdom prosper arrive "
    "rifle area inch abandon grass"
)


# ─────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _build_manifest_dict() -> dict:
    """Build a manifest dict suitable for writing to a temp file."""
    cat = load_catalogue(
        acts_path=_CATALOGUE_DIR,
        source_uri="https://github.com/deyan-paroushev/actproof-events",
        git_commit="a" * 40,
    )
    nis2 = cat.get("op:eu.nis2.art20.management_body_approval.v1")
    m = build_manifest(
        act_type_id=nis2.act_type_id,
        catalogue_entry_version=nis2.version,
        catalogue_source_uri=cat.source_uri,
        catalogue_git_commit=cat.git_commit,
        catalogue_entry_hash=nis2.entry_hash,
        catalogue_schema_hash=cat.schema_hash,
        issuer_org_name="Sofia Tech AD",
        issuer_authority_label="Management Body",
        title="NIS2 approval, May 2026",
        claim={
            "approving_body_name": "Board",
            "decision_date": "2026-05-14",
            "approved_measures_summary": "P",
            "authority_basis_reference": "S",
            "responsible_officers": "CIO",
            "implementation_oversight_reference": "A",
        },
        evidence=[
            Evidence(
                label="signed_resolution_or_minutes",
                filename_normalized="m.pdf", byte_size=100,
                mime_type="application/pdf",
                sha256=hash_file_bytes(b"x"),
            ),
            Evidence(
                label="risk_management_measures_document",
                filename_normalized="r.pdf", byte_size=200,
                mime_type="application/pdf",
                sha256=hash_file_bytes(b"y"),
            ),
        ],
        recipients=[],
        issued_at="2026-05-14T08:23:11Z",
    )
    return manifest_to_dict(m)


@pytest.fixture
def manifest_file(tmp_path: Path) -> Path:
    """Write a valid manifest to a temp file and return its path."""
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(_build_manifest_dict()), encoding="utf-8")
    return path


@pytest.fixture
def receipt_file(tmp_path: Path) -> Path:
    """Write a valid receipt to a temp file and return its path."""
    from actproof.manifest import manifest_from_dict, hash_manifest

    manifest_dict = _build_manifest_dict()
    manifest = manifest_from_dict(manifest_dict)
    manifest_hash_bytes = hash_manifest(manifest)
    payload = build_note_payload(manifest_hash_bytes)
    payload_b64 = base64.b64encode(payload).decode("ascii")

    anchor = AnchorRecord(
        network=ALGORAND_MAINNET,
        txid="DEMOTXID" + "A" * 44,
        block_round=39000000,
        confirmed_at="2026-05-14T08:24:00Z",
        note_format="arc-2",
        note_dapp_name="actproof",
        note_format_version="j",
        note_payload_b64=payload_b64,
    )
    ts = TimestampToken(
        tsa_url="https://x", tsa_name="Test TSA",
        token_b64=base64.b64encode(b"fake").decode("ascii"),
        policy_oid="1.2.3", hash_alg="sha-256",
        imprint_hex=manifest_hash_bytes.hex(),
        timestamp="2026-05-14T08:23:11Z",
    )
    receipt = build_receipt(manifest=manifest, anchor=anchor, trusted_timestamp=ts)
    path = tmp_path / "receipt.json"
    write_receipt(path, receipt)
    return path


# ─────────────────────────────────────────────────────────────────
# Group 1: Main group
# ─────────────────────────────────────────────────────────────────

class TestMainGroup:

    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "actproof" in result.output

    def test_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        # Three subcommands listed.
        assert "anchor" in result.output
        assert "verify" in result.output
        assert "validate" in result.output

    def test_no_subcommand_shows_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, [])
        # Click returns 0 or 2 for missing subcommand depending on version.
        # Either way, help text appears.
        assert "anchor" in result.output or result.exit_code != 0


# ─────────────────────────────────────────────────────────────────
# Group 2: validate command
# ─────────────────────────────────────────────────────────────────

class TestValidate:

    def test_validate_happy_path(
        self, runner: CliRunner, manifest_file: Path
    ) -> None:
        result = runner.invoke(main, [
            "validate", str(manifest_file),
            "--catalogue", str(_CATALOGUE_DIR),
            "--git-commit", "a" * 40,
            "--source-uri", "https://github.com/deyan-paroushev/actproof-events",
        ])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output
        assert "No validation issues" in result.output

    def test_validate_json_output(
        self, runner: CliRunner, manifest_file: Path
    ) -> None:
        result = runner.invoke(main, [
            "validate", str(manifest_file),
            "--catalogue", str(_CATALOGUE_DIR),
            "--git-commit", "a" * 40,
            "--source-uri", "https://github.com/x/y",
            "--json",
        ])
        assert result.exit_code == 0, result.output
        # Find a JSON object in the output and parse it.
        data = json.loads(result.output)
        assert data["ok"] is True
        assert data["issues"] == []

    def test_validate_catches_unknown_act(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        # Build a manifest with a bogus act_type_id.
        m = _build_manifest_dict()
        m["catalogue"]["act_type_id"] = "op:no.such.act.v1"
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(m), encoding="utf-8")
        result = runner.invoke(main, [
            "validate", str(bad),
            "--catalogue", str(_CATALOGUE_DIR),
            "--git-commit", "a" * 40,
            "--source-uri", "https://x",
        ])
        assert result.exit_code == 1
        assert "FAIL" in result.output
        assert "UNKNOWN_ACT_TYPE" in result.output

    def test_validate_missing_file(self, runner: CliRunner) -> None:
        result = runner.invoke(main, [
            "validate", "/does/not/exist.json",
            "--catalogue", str(_CATALOGUE_DIR),
            "--git-commit", "a" * 40,
            "--source-uri", "https://x",
        ])
        # Click rejects non-existent paths with exit code 2.
        assert result.exit_code == 2


# ─────────────────────────────────────────────────────────────────
# Group 3: verify command
# ─────────────────────────────────────────────────────────────────

class TestVerify:

    def test_verify_honest_receipt(
        self, runner: CliRunner, receipt_file: Path
    ) -> None:
        result = runner.invoke(main, [
            "verify", str(receipt_file),
            "--catalogue", str(_CATALOGUE_DIR),
            "--git-commit", "a" * 40,
            "--source-uri", "https://x",
            "--skip-anchor",
            "--skip-timestamp",
        ])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output
        # The three local checks should appear as PASS.
        assert "receipt_profile_supported" in result.output
        assert "manifest_hash_match" in result.output

    def test_verify_skip_catalogue_when_not_given(
        self, runner: CliRunner, receipt_file: Path
    ) -> None:
        result = runner.invoke(main, [
            "verify", str(receipt_file),
            "--skip-anchor",
            "--skip-timestamp",
        ])
        # No catalogue path → catalogue check is skipped automatically.
        # Local checks should still pass.
        assert result.exit_code == 0, result.output
        assert "catalogue_conformance" in result.output

    def test_verify_json_output(
        self, runner: CliRunner, receipt_file: Path
    ) -> None:
        result = runner.invoke(main, [
            "verify", str(receipt_file),
            "--skip-anchor",
            "--skip-timestamp",
            "--json",
        ])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["ok"] is True
        assert "checks" in data
        assert len(data["checks"]) == 6

    def test_verify_tampered_receipt_fails(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        # Build a receipt then mutate the JSON to corrupt manifest_hash.
        from actproof.manifest import manifest_from_dict, hash_manifest
        manifest_dict = _build_manifest_dict()
        manifest = manifest_from_dict(manifest_dict)
        manifest_hash_bytes = hash_manifest(manifest)
        payload = build_note_payload(manifest_hash_bytes)
        payload_b64 = base64.b64encode(payload).decode("ascii")

        anchor = AnchorRecord(
            network=ALGORAND_MAINNET, txid="X" * 52,
            block_round=1, confirmed_at="2026-01-01T00:00:00Z",
            note_format="arc-2", note_dapp_name="actproof",
            note_format_version="j", note_payload_b64=payload_b64,
        )
        ts = TimestampToken(
            tsa_url="https://x", tsa_name="X",
            token_b64=base64.b64encode(b"f").decode("ascii"),
            policy_oid=None, hash_alg="sha-256",
            imprint_hex=manifest_hash_bytes.hex(),
            timestamp="2026-01-01T00:00:00Z",
        )
        receipt = build_receipt(manifest=manifest, anchor=anchor, trusted_timestamp=ts)
        # Tamper: replace manifest_hash.
        tampered = replace(receipt, manifest_hash="sha256:" + "0" * 64)
        path = tmp_path / "bad.json"
        write_receipt(path, tampered)

        result = runner.invoke(main, [
            "verify", str(path),
            "--skip-anchor",
            "--skip-timestamp",
        ])
        assert result.exit_code == 1
        assert "FAIL" in result.output
        assert "manifest_hash_match" in result.output

    def test_verify_requires_git_commit_with_catalogue(
        self, runner: CliRunner, receipt_file: Path
    ) -> None:
        # --catalogue without --git-commit is a usage error.
        result = runner.invoke(main, [
            "verify", str(receipt_file),
            "--catalogue", str(_CATALOGUE_DIR),
            # missing --git-commit
        ])
        assert result.exit_code == 2
        assert "git-commit" in result.output


# ─────────────────────────────────────────────────────────────────
# Group 4: anchor command (DRAFT mode, no network)
# ─────────────────────────────────────────────────────────────────

class TestAnchor:

    def test_anchor_draft_mode_with_mnemonic_env(
        self,
        runner: CliRunner,
        manifest_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ACTPROOF_MNEMONIC", _TEST_MNEMONIC)
        receipt_out = tmp_path / "anchored.receipt.json"
        result = runner.invoke(main, [
            "anchor", str(manifest_file),
            "--mode", "draft",
            "--output", str(receipt_out),
            "--skip-timestamp",
        ])
        assert result.exit_code == 0, result.output
        assert receipt_out.is_file()
        # Loading the receipt back should work.
        from actproof.receipt import read_receipt
        loaded = read_receipt(receipt_out)
        assert loaded.anchor.txid == ""  # draft mode

    def test_anchor_draft_evidence_output(
        self,
        runner: CliRunner,
        manifest_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The CLI accepts but does not require --evidence-output. When omitted,
        # only the receipt is written.
        monkeypatch.setenv("ACTPROOF_MNEMONIC", _TEST_MNEMONIC)
        receipt_out = tmp_path / "r.json"
        result = runner.invoke(main, [
            "anchor", str(manifest_file),
            "--mode", "draft",
            "--output", str(receipt_out),
            "--skip-timestamp",
        ])
        assert result.exit_code == 0
        # No evidence file produced.
        assert not (tmp_path / "anything.issuer.json").exists()

    def test_anchor_mode_required(
        self,
        runner: CliRunner,
        manifest_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ACTPROOF_MNEMONIC", _TEST_MNEMONIC)
        result = runner.invoke(main, [
            "anchor", str(manifest_file),
            # missing --mode
            "--output", str(tmp_path / "r.json"),
        ])
        # Click rejects missing required option with code 2.
        assert result.exit_code == 2
        assert "mode" in result.output.lower()


# ─────────────────────────────────────────────────────────────────
# Group 5: anchor signer selection error paths
# ─────────────────────────────────────────────────────────────────

class TestAnchorSignerSelection:

    def test_no_signer_source_errors(
        self,
        runner: CliRunner,
        manifest_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Clear the env var to ensure no mnemonic is available.
        monkeypatch.delenv("ACTPROOF_MNEMONIC", raising=False)
        result = runner.invoke(main, [
            "anchor", str(manifest_file),
            "--mode", "draft",
            "--output", str(tmp_path / "r.json"),
            "--skip-timestamp",
        ])
        assert result.exit_code == 2
        # The error must explain BOTH paths exist.
        assert "ACTPROOF_MNEMONIC" in result.output
        assert "kms-resource" in result.output

    def test_error_when_both_kms_and_mnemonic_set(
        self,
        runner: CliRunner,
        manifest_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ACTPROOF_MNEMONIC", _TEST_MNEMONIC)
        result = runner.invoke(main, [
            "anchor", str(manifest_file),
            "--mode", "draft",
            "--kms-resource", "projects/x/cryptoKeyVersions/1",
            "--output", str(tmp_path / "r.json"),
            "--skip-timestamp",
        ])
        # Choosing one is required.
        assert result.exit_code == 2
        assert "ACTPROOF_MNEMONIC" in result.output


# ─────────────────────────────────────────────────────────────────
# Group 6: Exit codes
# ─────────────────────────────────────────────────────────────────

class TestExitCodes:

    def test_validate_exit_zero_on_pass(
        self, runner: CliRunner, manifest_file: Path
    ) -> None:
        result = runner.invoke(main, [
            "validate", str(manifest_file),
            "--catalogue", str(_CATALOGUE_DIR),
            "--git-commit", "a" * 40,
            "--source-uri", "https://x",
        ])
        assert result.exit_code == 0

    def test_verify_exit_zero_on_pass(
        self, runner: CliRunner, receipt_file: Path
    ) -> None:
        result = runner.invoke(main, [
            "verify", str(receipt_file),
            "--skip-anchor",
            "--skip-timestamp",
        ])
        assert result.exit_code == 0

    def test_anchor_exit_zero_on_pass(
        self,
        runner: CliRunner,
        manifest_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ACTPROOF_MNEMONIC", _TEST_MNEMONIC)
        result = runner.invoke(main, [
            "anchor", str(manifest_file),
            "--mode", "draft",
            "--output", str(tmp_path / "r.json"),
            "--skip-timestamp",
        ])
        assert result.exit_code == 0
