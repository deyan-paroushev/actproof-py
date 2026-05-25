# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: Apache-2.0
"""
Tests for actproof.receipt.

Eleven test groups:

* TestDataClasses: construction and immutability for all five dataclasses.
* TestBuildReceipt: build_receipt computes manifest_hash correctly, defaults work.
* TestBuildIssuerEvidence: build_issuer_evidence happy path and defaults.
* TestAnchorSerialisation: AnchorRecord to_dict/from_dict roundtrip.
* TestTimestampSerialisation: TimestampToken to_dict/from_dict roundtrip.
* TestReceiptSerialisation: Receipt to_dict/from_dict roundtrip with embedded manifest.
* TestIssuerEvidenceSerialisation: IssuerEvidence to_dict/from_dict roundtrip.
* TestFileIO: read_receipt/write_receipt and read/write_issuer_evidence work on disk.
* TestErrorHandling: malformed JSON, missing fields, missing files.
* TestRealisticShapes: draft (unanchored), demo (testnet), production (mainnet).
* TestReceiptEvidenceLinkage: IssuerEvidence.manifest_hash matches Receipt.manifest_hash.

Run with::

    pytest tests/test_receipt.py -v
"""

from __future__ import annotations

import base64
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from actproof.manifest import (
    BATCHING_PROFILE_SINGLE,
    RECEIPT_PROFILE_V1,
    Evidence,
    Recipient,
    build_manifest,
    hash_email,
    hash_manifest_hex,
)
from actproof.receipt import (
    ALGORAND_MAINNET,
    ALGORAND_TESTNET,
    ARC2_DAPP_NAME,
    ARC2_FORMAT_VERSION_JSON,
    ARC2_NOTE_FORMAT,
    AnchorRecord,
    IssuerEvidence,
    OnChainNote,
    PlaintextRecipient,
    Receipt,
    ReceiptError,
    TimestampToken,
    build_issuer_evidence,
    build_receipt,
    issuer_evidence_from_dict,
    issuer_evidence_to_dict,
    on_chain_note_from_bytes,
    read_issuer_evidence,
    read_receipt,
    receipt_from_dict,
    receipt_to_dict,
    write_issuer_evidence,
    write_receipt,
)


# ─────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def valid_manifest():
    return build_manifest(
        act_type_id="op:eu.nis2.art20.management_body_approval.v1",
        catalogue_entry_version=1,
        catalogue_source_uri="https://github.com/deyan-paroushev/actproof-events",
        catalogue_git_commit="0" * 40,
        catalogue_entry_hash="sha256:" + "a" * 64,
        catalogue_schema_hash="sha256:" + "b" * 64,
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
                byte_size=482991,
                mime_type="application/pdf",
                sha256="sha256:" + "c" * 64,
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
def valid_anchor() -> AnchorRecord:
    # A fake but well-formed Algorand txid (52-char base32).
    return AnchorRecord(
        network=ALGORAND_MAINNET,
        txid="ACTPROOF" + "A" * 43,  # 52 chars total
        block_round=39000000,
        confirmed_at="2026-05-14T08:24:00Z",
        note_format=ARC2_NOTE_FORMAT,
        note_dapp_name=ARC2_DAPP_NAME,
        note_format_version=ARC2_FORMAT_VERSION_JSON,
        note_payload_b64=base64.b64encode(
            b'{"h":"abc","t":"single_attestation_anchor_v1","v":1}'
        ).decode("ascii"),
    )


@pytest.fixture
def valid_timestamp() -> TimestampToken:
    return TimestampToken(
        tsa_url="https://tsa.example.com/tsr",
        tsa_name="Example TSA",
        token_b64=base64.b64encode(b"fake DER-encoded RFC 3161 token").decode("ascii"),
        policy_oid="1.2.3.4.5",
        hash_alg="sha-256",
        imprint_hex="a" * 64,
        timestamp="2026-05-14T08:23:11Z",
    )


@pytest.fixture
def valid_receipt(valid_manifest, valid_anchor, valid_timestamp) -> Receipt:
    return build_receipt(
        manifest=valid_manifest,
        anchor=valid_anchor,
        trusted_timestamp=valid_timestamp,
    )


@pytest.fixture
def valid_issuer_evidence(valid_receipt) -> IssuerEvidence:
    return build_issuer_evidence(
        manifest_hash=valid_receipt.manifest_hash,
        plaintext_recipients=[
            PlaintextRecipient(
                email_plaintext="auditor@firm.com",
                email_hash=hash_email("auditor@firm.com"),
            ),
        ],
        issuer_user_id="auth0|user_12345",
        internal_notes="Reviewed by legal 2026-05-13.",
    )


# ─────────────────────────────────────────────────────────────────
# Group 1: Dataclass construction and immutability
# ─────────────────────────────────────────────────────────────────

class TestDataClasses:

    def test_anchor_constructs(self, valid_anchor: AnchorRecord) -> None:
        assert valid_anchor.network == ALGORAND_MAINNET
        assert valid_anchor.block_round == 39000000

    def test_anchor_frozen(self, valid_anchor: AnchorRecord) -> None:
        with pytest.raises(FrozenInstanceError):
            valid_anchor.network = "other"  # type: ignore[misc]

    def test_anchor_allows_unanchored_state(self) -> None:
        # Draft mode: anchor not yet submitted.
        a = AnchorRecord(
            network=ALGORAND_TESTNET,
            txid="",
            block_round=None,
            confirmed_at=None,
            note_format=ARC2_NOTE_FORMAT,
            note_dapp_name=ARC2_DAPP_NAME,
            note_format_version=ARC2_FORMAT_VERSION_JSON,
            note_payload_b64="",
        )
        assert a.txid == ""
        assert a.block_round is None

    def test_timestamp_constructs(self, valid_timestamp: TimestampToken) -> None:
        assert valid_timestamp.tsa_name == "Example TSA"
        assert valid_timestamp.policy_oid == "1.2.3.4.5"

    def test_timestamp_frozen(self, valid_timestamp: TimestampToken) -> None:
        with pytest.raises(FrozenInstanceError):
            valid_timestamp.tsa_name = "Other TSA"  # type: ignore[misc]

    def test_timestamp_allows_null_policy_oid(self) -> None:
        t = TimestampToken(
            tsa_url="https://x",
            tsa_name="X",
            token_b64="ABC",
            policy_oid=None,
            hash_alg="sha-256",
            imprint_hex="a" * 64,
            timestamp="2026-05-14T12:00:00Z",
        )
        assert t.policy_oid is None

    def test_receipt_constructs(self, valid_receipt: Receipt) -> None:
        assert valid_receipt.receipt_profile == RECEIPT_PROFILE_V1
        assert valid_receipt.batching_profile == BATCHING_PROFILE_SINGLE
        assert valid_receipt.manifest_hash.startswith("sha256:")

    def test_receipt_frozen(self, valid_receipt: Receipt) -> None:
        with pytest.raises(FrozenInstanceError):
            valid_receipt.receipt_profile = "v2"  # type: ignore[misc]

    def test_plaintext_recipient_constructs(self) -> None:
        p = PlaintextRecipient(
            email_plaintext="a@b.com",
            email_hash=hash_email("a@b.com"),
        )
        assert p.email_plaintext == "a@b.com"

    def test_plaintext_recipient_frozen(self) -> None:
        p = PlaintextRecipient(email_plaintext="a@b.com", email_hash="x")
        with pytest.raises(FrozenInstanceError):
            p.email_plaintext = "c@d.com"  # type: ignore[misc]

    def test_issuer_evidence_constructs(
        self, valid_issuer_evidence: IssuerEvidence
    ) -> None:
        assert valid_issuer_evidence.receipt_profile == RECEIPT_PROFILE_V1
        assert len(valid_issuer_evidence.plaintext_recipients) == 1
        assert valid_issuer_evidence.issuer_user_id == "auth0|user_12345"

    def test_issuer_evidence_frozen(
        self, valid_issuer_evidence: IssuerEvidence
    ) -> None:
        with pytest.raises(FrozenInstanceError):
            valid_issuer_evidence.issuer_user_id = "other"  # type: ignore[misc]

    def test_issuer_evidence_allows_no_recipients(self) -> None:
        ev = build_issuer_evidence(
            manifest_hash="sha256:" + "0" * 64,
            plaintext_recipients=[],
        )
        assert ev.plaintext_recipients == ()

    def test_issuer_evidence_optional_fields(self) -> None:
        ev = build_issuer_evidence(manifest_hash="sha256:" + "0" * 64)
        assert ev.issuer_user_id is None
        assert ev.internal_notes is None


# ─────────────────────────────────────────────────────────────────
# Group 2: build_receipt
# ─────────────────────────────────────────────────────────────────

class TestBuildReceipt:

    def test_computes_manifest_hash(
        self, valid_manifest, valid_anchor: AnchorRecord, valid_timestamp: TimestampToken
    ) -> None:
        r = build_receipt(
            manifest=valid_manifest,
            anchor=valid_anchor,
            trusted_timestamp=valid_timestamp,
        )
        expected = "sha256:" + hash_manifest_hex(valid_manifest)
        assert r.manifest_hash == expected

    def test_defaults_issued_at_to_manifest(
        self, valid_manifest, valid_anchor, valid_timestamp
    ) -> None:
        r = build_receipt(
            manifest=valid_manifest,
            anchor=valid_anchor,
            trusted_timestamp=valid_timestamp,
        )
        assert r.issued_at == valid_manifest.issued_at

    def test_explicit_issued_at_overrides_manifest(
        self, valid_manifest, valid_anchor, valid_timestamp
    ) -> None:
        r = build_receipt(
            manifest=valid_manifest,
            anchor=valid_anchor,
            trusted_timestamp=valid_timestamp,
            issued_at="2026-12-31T23:59:59Z",
        )
        assert r.issued_at == "2026-12-31T23:59:59Z"

    def test_default_profile_constants(
        self, valid_manifest, valid_anchor, valid_timestamp
    ) -> None:
        r = build_receipt(
            manifest=valid_manifest,
            anchor=valid_anchor,
            trusted_timestamp=valid_timestamp,
        )
        assert r.receipt_profile == RECEIPT_PROFILE_V1
        assert r.batching_profile == BATCHING_PROFILE_SINGLE

    def test_keyword_only_args(self, valid_manifest, valid_anchor, valid_timestamp) -> None:
        with pytest.raises(TypeError, match="positional"):
            build_receipt(valid_manifest, valid_anchor, valid_timestamp)  # type: ignore[misc]


# ─────────────────────────────────────────────────────────────────
# Group 3: build_issuer_evidence
# ─────────────────────────────────────────────────────────────────

class TestBuildIssuerEvidence:

    def test_happy_path(self) -> None:
        ev = build_issuer_evidence(
            manifest_hash="sha256:" + "a" * 64,
            plaintext_recipients=[
                PlaintextRecipient("a@b.com", hash_email("a@b.com")),
            ],
            issuer_user_id="x",
            internal_notes="y",
        )
        assert ev.manifest_hash.startswith("sha256:")
        assert ev.issuer_user_id == "x"
        assert ev.internal_notes == "y"

    def test_recipients_coerced_to_tuple(self) -> None:
        # Pass a list, get a tuple back (for immutability).
        ev = build_issuer_evidence(
            manifest_hash="sha256:" + "0" * 64,
            plaintext_recipients=[
                PlaintextRecipient("a@b.com", "sha256:" + "0" * 64),
            ],
        )
        assert isinstance(ev.plaintext_recipients, tuple)

    def test_default_receipt_profile(self) -> None:
        ev = build_issuer_evidence(manifest_hash="sha256:" + "0" * 64)
        assert ev.receipt_profile == RECEIPT_PROFILE_V1


# ─────────────────────────────────────────────────────────────────
# Group 4: AnchorRecord serialisation
# ─────────────────────────────────────────────────────────────────

class TestAnchorSerialisation:
    """Test the private serialisation helpers indirectly via receipt_to_dict
    and receipt_from_dict (which delegate to _anchor_to_dict/_anchor_from_dict)."""

    def test_anchor_roundtrips(
        self, valid_receipt: Receipt
    ) -> None:
        d = receipt_to_dict(valid_receipt)
        anchor_dict = d["anchor"]
        # All 9 fields present.
        expected_keys = {
            "network", "txid", "block_round", "confirmed_at",
            "note_format", "note_dapp_name", "note_format_version",
            "note_payload_b64", "on_chain_note",
        }
        assert set(anchor_dict.keys()) == expected_keys

    def test_unanchored_anchor_serialises_with_nulls(
        self, valid_manifest, valid_timestamp
    ) -> None:
        draft_anchor = AnchorRecord(
            network=ALGORAND_TESTNET,
            txid="",
            block_round=None,
            confirmed_at=None,
            note_format=ARC2_NOTE_FORMAT,
            note_dapp_name=ARC2_DAPP_NAME,
            note_format_version=ARC2_FORMAT_VERSION_JSON,
            note_payload_b64="",
        )
        r = build_receipt(
            manifest=valid_manifest,
            anchor=draft_anchor,
            trusted_timestamp=valid_timestamp,
        )
        d = receipt_to_dict(r)
        assert d["anchor"]["block_round"] is None
        assert d["anchor"]["confirmed_at"] is None
        assert d["anchor"]["txid"] == ""

        # Roundtrip preserves the unanchored state.
        r2 = receipt_from_dict(d)
        assert r2.anchor.block_round is None
        assert r2.anchor.confirmed_at is None


# ─────────────────────────────────────────────────────────────────
# Group 5: TimestampToken serialisation
# ─────────────────────────────────────────────────────────────────

class TestTimestampSerialisation:

    def test_timestamp_roundtrips(self, valid_receipt: Receipt) -> None:
        d = receipt_to_dict(valid_receipt)
        ts_dict = d["trusted_timestamp"]
        expected_keys = {
            "tsa_url", "tsa_name", "token_b64", "policy_oid",
            "hash_alg", "imprint_hex", "timestamp",
        }
        assert set(ts_dict.keys()) == expected_keys

    def test_null_policy_oid_preserved(
        self, valid_manifest, valid_anchor
    ) -> None:
        ts = TimestampToken(
            tsa_url="https://x",
            tsa_name="X",
            token_b64="ABC",
            policy_oid=None,
            hash_alg="sha-256",
            imprint_hex="a" * 64,
            timestamp="2026-05-14T12:00:00Z",
        )
        r = build_receipt(
            manifest=valid_manifest,
            anchor=valid_anchor,
            trusted_timestamp=ts,
        )
        d = receipt_to_dict(r)
        assert d["trusted_timestamp"]["policy_oid"] is None
        r2 = receipt_from_dict(d)
        assert r2.trusted_timestamp.policy_oid is None


# ─────────────────────────────────────────────────────────────────
# Group 6: Receipt serialisation
# ─────────────────────────────────────────────────────────────────

class TestReceiptSerialisation:

    def test_to_dict_includes_all_top_level_fields(
        self, valid_receipt: Receipt
    ) -> None:
        d = receipt_to_dict(valid_receipt)
        expected = {
            "receipt_profile", "issued_at", "manifest", "manifest_hash",
            "anchor", "trusted_timestamp", "batching_profile",
        }
        assert set(d.keys()) == expected

    def test_from_dict_roundtrips(self, valid_receipt: Receipt) -> None:
        d = receipt_to_dict(valid_receipt)
        reconstructed = receipt_from_dict(d)
        assert reconstructed == valid_receipt

    def test_manifest_is_nested_dict(self, valid_receipt: Receipt) -> None:
        d = receipt_to_dict(valid_receipt)
        # manifest is a full dict, not just a hash reference.
        assert isinstance(d["manifest"], dict)
        assert "catalogue" in d["manifest"]
        assert "issuer" in d["manifest"]
        assert "evidence" in d["manifest"]

    def test_manifest_hash_is_present_alongside_manifest(
        self, valid_receipt: Receipt
    ) -> None:
        # The receipt stores BOTH the full manifest and its hash. This is
        # deliberate: the hash is what was anchored on-chain; the manifest
        # is what regenerates that hash when recanonicalised.
        d = receipt_to_dict(valid_receipt)
        assert d["manifest_hash"].startswith("sha256:")
        # Verify the hash actually matches the manifest's hash.
        from actproof.manifest import manifest_from_dict
        m_back = manifest_from_dict(d["manifest"])
        assert d["manifest_hash"] == "sha256:" + hash_manifest_hex(m_back)

    def test_from_dict_rejects_missing_field(self) -> None:
        bad = {
            "receipt_profile": "actproof-jcs-v1",
            "issued_at": "2026-05-14T12:00:00Z",
            # missing "manifest"
        }
        with pytest.raises(ReceiptError, match="Cannot parse"):
            receipt_from_dict(bad)


# ─────────────────────────────────────────────────────────────────
# Group 7: IssuerEvidence serialisation
# ─────────────────────────────────────────────────────────────────

class TestIssuerEvidenceSerialisation:

    def test_to_dict_includes_all_fields(
        self, valid_issuer_evidence: IssuerEvidence
    ) -> None:
        d = issuer_evidence_to_dict(valid_issuer_evidence)
        expected = {
            "receipt_profile", "manifest_hash", "plaintext_recipients",
            "issuer_user_id", "internal_notes",
        }
        assert set(d.keys()) == expected

    def test_plaintext_recipients_serialised(
        self, valid_issuer_evidence: IssuerEvidence
    ) -> None:
        d = issuer_evidence_to_dict(valid_issuer_evidence)
        assert len(d["plaintext_recipients"]) == 1
        p = d["plaintext_recipients"][0]
        assert p["email_plaintext"] == "auditor@firm.com"
        assert p["email_hash"].startswith("sha256:")

    def test_from_dict_roundtrips(
        self, valid_issuer_evidence: IssuerEvidence
    ) -> None:
        d = issuer_evidence_to_dict(valid_issuer_evidence)
        reconstructed = issuer_evidence_from_dict(d)
        assert reconstructed == valid_issuer_evidence

    def test_handles_missing_recipients_as_empty(self) -> None:
        d = {
            "receipt_profile": "actproof-jcs-v1",
            "manifest_hash": "sha256:" + "0" * 64,
            # no plaintext_recipients key
            "issuer_user_id": None,
            "internal_notes": None,
        }
        ev = issuer_evidence_from_dict(d)
        assert ev.plaintext_recipients == ()


# ─────────────────────────────────────────────────────────────────
# Group 8: File I/O
# ─────────────────────────────────────────────────────────────────

class TestFileIO:

    def test_write_then_read_receipt(
        self, tmp_path: Path, valid_receipt: Receipt
    ) -> None:
        path = tmp_path / "receipt.json"
        write_receipt(path, valid_receipt)
        assert path.is_file()

        loaded = read_receipt(path)
        assert loaded == valid_receipt

    def test_receipt_file_is_pretty_printed(
        self, tmp_path: Path, valid_receipt: Receipt
    ) -> None:
        path = tmp_path / "receipt.json"
        write_receipt(path, valid_receipt)
        text = path.read_text(encoding="utf-8")
        # Pretty-printed with 2-space indent should have newlines.
        assert "\n" in text
        assert "  " in text  # at least one indent level
        # And valid JSON.
        json.loads(text)

    def test_receipt_file_ends_with_newline(
        self, tmp_path: Path, valid_receipt: Receipt
    ) -> None:
        path = tmp_path / "receipt.json"
        write_receipt(path, valid_receipt)
        text = path.read_text(encoding="utf-8")
        assert text.endswith("\n")

    def test_write_then_read_issuer_evidence(
        self, tmp_path: Path, valid_issuer_evidence: IssuerEvidence
    ) -> None:
        path = tmp_path / "evidence.json"
        write_issuer_evidence(path, valid_issuer_evidence)
        assert path.is_file()

        loaded = read_issuer_evidence(path)
        assert loaded == valid_issuer_evidence

    def test_receipt_and_evidence_can_share_directory(
        self,
        tmp_path: Path,
        valid_receipt: Receipt,
        valid_issuer_evidence: IssuerEvidence,
    ) -> None:
        # Realistic workflow: issuer writes both files side-by-side.
        receipt_path = tmp_path / "abc123.receipt.json"
        evidence_path = tmp_path / "abc123.issuer.json"

        write_receipt(receipt_path, valid_receipt)
        write_issuer_evidence(evidence_path, valid_issuer_evidence)

        # Both files exist and roundtrip independently.
        assert receipt_path.is_file()
        assert evidence_path.is_file()
        assert read_receipt(receipt_path) == valid_receipt
        assert read_issuer_evidence(evidence_path) == valid_issuer_evidence


# ─────────────────────────────────────────────────────────────────
# Group 9: Error handling
# ─────────────────────────────────────────────────────────────────

class TestErrorHandling:

    def test_read_receipt_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ReceiptError, match="Cannot read"):
            read_receipt(tmp_path / "nonexistent.json")

    def test_read_receipt_malformed_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not valid json {")
        with pytest.raises(ReceiptError, match="not valid JSON"):
            read_receipt(path)

    def test_read_receipt_wrong_structure(self, tmp_path: Path) -> None:
        path = tmp_path / "wrong.json"
        path.write_text('{"hello": "world"}')
        with pytest.raises(ReceiptError, match="Cannot parse"):
            read_receipt(path)

    def test_read_issuer_evidence_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ReceiptError, match="Cannot read"):
            read_issuer_evidence(tmp_path / "nope.json")

    def test_read_issuer_evidence_malformed(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("[1, 2, 3]")  # array, not object
        with pytest.raises(ReceiptError, match="Cannot parse"):
            read_issuer_evidence(path)


# ─────────────────────────────────────────────────────────────────
# Group 10: Realistic shapes (draft, demo, production)
# ─────────────────────────────────────────────────────────────────

class TestRealisticShapes:

    def test_draft_receipt_unanchored(
        self, valid_manifest, valid_timestamp
    ) -> None:
        """Draft mode: anchor not yet submitted. block_round, confirmed_at, txid empty."""
        draft_anchor = AnchorRecord(
            network=ALGORAND_TESTNET,  # draft typically uses testnet
            txid="",
            block_round=None,
            confirmed_at=None,
            note_format=ARC2_NOTE_FORMAT,
            note_dapp_name=ARC2_DAPP_NAME,
            note_format_version=ARC2_FORMAT_VERSION_JSON,
            note_payload_b64="",
        )
        r = build_receipt(
            manifest=valid_manifest,
            anchor=draft_anchor,
            trusted_timestamp=valid_timestamp,
        )
        # Receipt still has a manifest_hash even when not yet anchored.
        assert r.manifest_hash.startswith("sha256:")
        assert r.anchor.network == ALGORAND_TESTNET

    def test_demo_receipt_testnet_with_anchor(
        self, valid_manifest, valid_timestamp
    ) -> None:
        """Demo mode: testnet, real anchor with real txid."""
        demo_anchor = AnchorRecord(
            network=ALGORAND_TESTNET,
            txid="DEMO" + "A" * 48,
            block_round=42_000_000,
            confirmed_at="2026-05-14T08:24:00Z",
            note_format=ARC2_NOTE_FORMAT,
            note_dapp_name=ARC2_DAPP_NAME,
            note_format_version=ARC2_FORMAT_VERSION_JSON,
            note_payload_b64=base64.b64encode(b'{"h":"...","t":"...","v":1}').decode("ascii"),
        )
        r = build_receipt(
            manifest=valid_manifest,
            anchor=demo_anchor,
            trusted_timestamp=valid_timestamp,
        )
        assert r.anchor.network == ALGORAND_TESTNET
        assert r.anchor.block_round == 42_000_000

    def test_production_receipt_mainnet(
        self, valid_manifest, valid_anchor: AnchorRecord, valid_timestamp: TimestampToken
    ) -> None:
        """Production mode: mainnet, fully confirmed."""
        r = build_receipt(
            manifest=valid_manifest,
            anchor=valid_anchor,
            trusted_timestamp=valid_timestamp,
        )
        assert r.anchor.network == ALGORAND_MAINNET
        assert r.anchor.block_round is not None
        assert r.anchor.confirmed_at is not None


# ─────────────────────────────────────────────────────────────────
# Group 11: Receipt-evidence linkage
# ─────────────────────────────────────────────────────────────────

class TestReceiptEvidenceLinkage:
    """The IssuerEvidence's manifest_hash must match the public Receipt's
    manifest_hash. This is the binding that lets the issuer (later) match
    a public receipt to its private addendum.
    """

    def test_manifest_hash_matches(
        self, valid_receipt: Receipt, valid_issuer_evidence: IssuerEvidence
    ) -> None:
        assert valid_receipt.manifest_hash == valid_issuer_evidence.manifest_hash

    def test_receipt_profile_matches(
        self, valid_receipt: Receipt, valid_issuer_evidence: IssuerEvidence
    ) -> None:
        assert valid_receipt.receipt_profile == valid_issuer_evidence.receipt_profile

    def test_plaintext_recipient_hashes_match_manifest(
        self, valid_receipt: Receipt, valid_issuer_evidence: IssuerEvidence
    ) -> None:
        # Each PlaintextRecipient's email_hash should appear in the
        # manifest's recipients list. This is what lets a verifier confirm
        # that the plaintext mapping is honest.
        manifest_email_hashes = {r.email_hash for r in valid_receipt.manifest.recipients}
        evidence_email_hashes = {
            p.email_hash for p in valid_issuer_evidence.plaintext_recipients
        }
        assert evidence_email_hashes.issubset(manifest_email_hashes)


# ─────────────────────────────────────────────────────────────────
# Group 12: on-chain note encodings (utf8 / hex / base64)
# ─────────────────────────────────────────────────────────────────

class TestOnChainNoteEncodings:
    """The three encodings are three views of one note byte string.

    They must decode to identical bytes, carry the full ARC-2 prefix, be
    reconstructed when an older receipt omits them, and survive a
    to_dict/from_dict roundtrip.
    """

    # A realistic full note: the ARC-2 prefix plus a canonical h/t/v payload.
    _NOTE_BYTES = (
        b'actproof:j{"h":"'
        + b"3f40a9e5f6666c6f3ddbb061e5df57e09db1659d9d904122cb77c15a7876f702"
        + b'","t":"single_attestation_anchor_v1","v":1}'
    )

    def test_encodings_decode_to_the_same_bytes(self) -> None:
        note = on_chain_note_from_bytes(self._NOTE_BYTES)
        assert isinstance(note, OnChainNote)
        # One value, three encodings: all three decode back to the note.
        assert note.utf8.encode("utf-8") == self._NOTE_BYTES
        assert bytes.fromhex(note.hex) == self._NOTE_BYTES
        assert base64.b64decode(note.base64) == self._NOTE_BYTES

    def test_utf8_carries_the_full_arc2_prefix(self) -> None:
        note = on_chain_note_from_bytes(self._NOTE_BYTES)
        assert note.utf8.startswith("actproof:j")

    def test_hex_is_lowercase_without_0x_prefix(self) -> None:
        note = on_chain_note_from_bytes(self._NOTE_BYTES)
        assert not note.hex.startswith("0x")
        assert note.hex == note.hex.lower()

    def test_on_chain_note_is_frozen(self) -> None:
        note = on_chain_note_from_bytes(self._NOTE_BYTES)
        with pytest.raises(FrozenInstanceError):
            note.utf8 = "other"  # type: ignore[misc]

    def test_anchor_reconstructs_note_when_json_omits_it(
        self, valid_receipt: Receipt
    ) -> None:
        # Simulate a receipt written before on_chain_note existed: it carries
        # note_payload_b64 (the prefix-stripped payload) but no on_chain_note.
        d = receipt_to_dict(valid_receipt)
        del d["anchor"]["on_chain_note"]
        r = receipt_from_dict(d)
        note = r.anchor.on_chain_note
        # The full note is reconstructed from note_payload_b64 + the prefix.
        assert note is not None
        payload = base64.b64decode(r.anchor.note_payload_b64)
        expected = (
            f"{r.anchor.note_dapp_name}:{r.anchor.note_format_version}"
        ).encode("utf-8") + payload
        assert note.utf8.encode("utf-8") == expected
        assert note.utf8.startswith("actproof:j")
        # The legacy payload field still lacks the prefix. That mismatch
        # against a block explorer is exactly what on_chain_note closes.
        assert not payload.startswith(b"actproof:j")

    def test_on_chain_note_survives_receipt_roundtrip(
        self, valid_receipt: Receipt
    ) -> None:
        d = receipt_to_dict(valid_receipt)
        assert "on_chain_note" in d["anchor"]
        r2 = receipt_from_dict(d)
        note = r2.anchor.on_chain_note
        assert note is not None
        # Still one consistent value in three encodings after the roundtrip.
        assert note.utf8.encode("utf-8") == bytes.fromhex(note.hex)
        assert base64.b64decode(note.base64) == bytes.fromhex(note.hex)

    def test_bad_payload_base64_raises_receipt_error(
        self, valid_receipt: Receipt
    ) -> None:
        # A receipt with no on_chain_note and an unparseable note_payload_b64
        # should fail cleanly as a ReceiptError, not a raw binascii error.
        d = receipt_to_dict(valid_receipt)
        del d["anchor"]["on_chain_note"]
        d["anchor"]["note_payload_b64"] = "not!valid!base64!"
        with pytest.raises(ReceiptError):
            receipt_from_dict(d)
