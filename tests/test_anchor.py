# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Tests for openproof.anchor.

Mocks AlgodClient and Signer so the suite runs offline.

Twelve test groups:

* TestAnchorMode: enum values and string conversion.
* TestConstants: default URLs, timeouts, max note size.
* TestNotePayload: build_note_payload produces canonical bytes with sorted keys.
* TestNoteBytes: build_note_bytes prepends "openproof:j" prefix.
* TestNoteSizeLimit: oversized batching_profile strings are rejected.
* TestDraftMode: anchor_manifest in DRAFT mode does no signing/submission.
* TestSignerProtocol: simple objects satisfy the Signer Protocol.
* TestBuildTransaction: build_transaction produces a 0-Algo self-payment with note.
* TestAnchorManifestHappyPath: full flow with mocked algod and signer.
* TestAnchorManifestErrorPaths: signer fails / algod fails / pool error / timeout.
* TestWaitForConfirmation: polling logic.
* TestNetworkSelection: mode -> network mapping.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Optional

import pytest

from openproof.anchor import (
    ALGORAND_NOTE_MAX_BYTES,
    DEFAULT_ALGOD_URL_MAINNET,
    DEFAULT_ALGOD_URL_TESTNET,
    DEFAULT_CONFIRMATION_TIMEOUT_SECONDS,
    NOTE_VERSION,
    AnchorError,
    AnchorMode,
    Signer,
    anchor_manifest,
    build_note_bytes,
    build_note_payload,
    build_transaction,
)
from openproof.manifest import BATCHING_PROFILE_SINGLE
from openproof.receipt import (
    ALGORAND_MAINNET,
    ALGORAND_TESTNET,
    ARC2_DAPP_NAME,
    ARC2_FORMAT_VERSION_JSON,
    ARC2_NOTE_FORMAT,
)


# ─────────────────────────────────────────────────────────────────
# Test fixtures: fake Signer and fake AlgodClient
# ─────────────────────────────────────────────────────────────────

class _FakeSigner:
    """Implements the Signer Protocol with a fixed address and recording sign."""

    def __init__(
        self,
        address: str = "OPENPROOF" + "A" * 49,
        sign_raises: Optional[Exception] = None,
    ) -> None:
        self._address = address
        self._sign_raises = sign_raises
        self.signed_txns: list[Any] = []

    @property
    def address(self) -> str:
        return self._address

    def sign_transaction(self, txn: Any) -> Any:
        if self._sign_raises is not None:
            raise self._sign_raises
        self.signed_txns.append(txn)
        # Return a fake "signed transaction" - a tuple is fine for tests.
        return ("signed", txn)


class _FakeAlgodClient:
    """Stand-in for algosdk.v2client.algod.AlgodClient."""

    def __init__(
        self,
        suggested_params_raises: Optional[Exception] = None,
        send_raises: Optional[Exception] = None,
        confirm_after_polls: int = 1,
        pool_error: Optional[str] = None,
    ) -> None:
        self.suggested_params_raises = suggested_params_raises
        self.send_raises = send_raises
        self.confirm_after_polls = confirm_after_polls
        self.pool_error = pool_error
        self.poll_count = 0
        self.last_txn_sent: Optional[Any] = None

    def suggested_params(self) -> Any:
        if self.suggested_params_raises is not None:
            raise self.suggested_params_raises
        # Return a real-ish SuggestedParams. We use a SimpleNamespace-like
        # object with the fields algosdk needs.
        from algosdk.transaction import SuggestedParams
        return SuggestedParams(
            fee=1000,
            first=1,
            last=1001,
            gh="test-genesis-hash" + "=" * 16,  # base64-ish padding
            gen="test-network",
            flat_fee=True,
        )

    def send_transaction(self, signed_txn: Any) -> str:
        if self.send_raises is not None:
            raise self.send_raises
        self.last_txn_sent = signed_txn
        return "FAKETXID" + "B" * 44  # 52 chars

    def pending_transaction_info(self, txid: str) -> dict[str, Any]:
        if self.pool_error is not None:
            return {
                "pool-error": self.pool_error,
                "confirmed-round": 0,
                "last-round": 100,
            }
        self.poll_count += 1
        if self.poll_count >= self.confirm_after_polls:
            return {
                "confirmed-round": 12345678,
                "last-round": 12345678,
            }
        return {"confirmed-round": 0, "last-round": 100 + self.poll_count}


_VALID_HASH = bytes.fromhex(
    "f1352245dbbbc67497b49d43f9fae82fcb8b0b2fd154a76d59c1f0dced1246fa"
)


# ─────────────────────────────────────────────────────────────────
# Group 1: AnchorMode enum
# ─────────────────────────────────────────────────────────────────

class TestAnchorMode:

    def test_three_modes_exist(self) -> None:
        assert AnchorMode.DRAFT.value == "draft"
        assert AnchorMode.DEMO.value == "demo"
        assert AnchorMode.PRODUCTION.value == "production"

    def test_mode_is_str_subclass(self) -> None:
        # str subclass enum lets us serialise the value directly.
        assert isinstance(AnchorMode.DRAFT, str)
        assert AnchorMode.DRAFT == "draft"

    def test_mode_comparison(self) -> None:
        assert AnchorMode.DRAFT != AnchorMode.PRODUCTION
        assert AnchorMode.DRAFT is AnchorMode.DRAFT


# ─────────────────────────────────────────────────────────────────
# Group 2: Constants
# ─────────────────────────────────────────────────────────────────

class TestConstants:

    def test_default_algod_urls(self) -> None:
        assert "mainnet" in DEFAULT_ALGOD_URL_MAINNET
        assert "testnet" in DEFAULT_ALGOD_URL_TESTNET
        assert DEFAULT_ALGOD_URL_MAINNET.startswith("https://")
        assert DEFAULT_ALGOD_URL_TESTNET.startswith("https://")

    def test_note_max_bytes_matches_algorand_protocol(self) -> None:
        assert ALGORAND_NOTE_MAX_BYTES == 1000

    def test_note_version(self) -> None:
        assert NOTE_VERSION == 1

    def test_confirmation_timeout_is_reasonable(self) -> None:
        # Algorand block time is ~3.3s; 60s allows roughly 18 rounds.
        assert 10.0 <= DEFAULT_CONFIRMATION_TIMEOUT_SECONDS <= 600.0


# ─────────────────────────────────────────────────────────────────
# Group 3: Note payload construction
# ─────────────────────────────────────────────────────────────────

class TestNotePayload:

    def test_payload_is_bytes(self) -> None:
        payload = build_note_payload(_VALID_HASH)
        assert isinstance(payload, bytes)

    def test_payload_is_canonical_json(self) -> None:
        payload = build_note_payload(_VALID_HASH)
        # Parse to confirm it's valid JSON.
        parsed = json.loads(payload.decode("utf-8"))
        assert "h" in parsed
        assert "t" in parsed
        assert "v" in parsed

    def test_payload_keys_sorted(self) -> None:
        payload = build_note_payload(_VALID_HASH).decode("utf-8")
        # In canonical JSON, keys are sorted: h, t, v.
        h_pos = payload.index('"h"')
        t_pos = payload.index('"t"')
        v_pos = payload.index('"v"')
        assert h_pos < t_pos < v_pos

    def test_payload_hash_value_is_hex(self) -> None:
        payload = build_note_payload(_VALID_HASH)
        parsed = json.loads(payload.decode("utf-8"))
        assert parsed["h"] == _VALID_HASH.hex()
        assert len(parsed["h"]) == 64  # SHA-256 hex

    def test_payload_default_profile(self) -> None:
        payload = build_note_payload(_VALID_HASH)
        parsed = json.loads(payload.decode("utf-8"))
        assert parsed["t"] == BATCHING_PROFILE_SINGLE

    def test_payload_custom_profile(self) -> None:
        payload = build_note_payload(_VALID_HASH, batching_profile="other_v1")
        parsed = json.loads(payload.decode("utf-8"))
        assert parsed["t"] == "other_v1"

    def test_payload_version(self) -> None:
        payload = build_note_payload(_VALID_HASH)
        parsed = json.loads(payload.decode("utf-8"))
        assert parsed["v"] == NOTE_VERSION

    def test_payload_no_whitespace(self) -> None:
        # Canonical JSON has no insignificant whitespace.
        payload = build_note_payload(_VALID_HASH)
        text = payload.decode("utf-8")
        assert " " not in text
        assert "\n" not in text

    def test_payload_reproducible(self) -> None:
        a = build_note_payload(_VALID_HASH)
        b = build_note_payload(_VALID_HASH)
        assert a == b


# ─────────────────────────────────────────────────────────────────
# Group 4: Full note bytes (with ARC-2 prefix)
# ─────────────────────────────────────────────────────────────────

class TestNoteBytes:

    def test_note_starts_with_arc2_prefix(self) -> None:
        note = build_note_bytes(_VALID_HASH)
        assert note.startswith(b"openproof:j")

    def test_note_payload_after_prefix(self) -> None:
        note = build_note_bytes(_VALID_HASH)
        payload = note[len(b"openproof:j"):]
        # Should equal what build_note_payload returns standalone.
        assert payload == build_note_payload(_VALID_HASH)

    def test_note_size_within_limit(self) -> None:
        note = build_note_bytes(_VALID_HASH)
        # ~125 bytes for SHA-256 single anchor; well under 1000.
        assert len(note) <= ALGORAND_NOTE_MAX_BYTES

    def test_note_size_for_sha256_v1_is_under_150(self) -> None:
        # Concrete size budget for the v1 format with SHA-256.
        note = build_note_bytes(_VALID_HASH)
        assert len(note) < 150

    def test_note_decodes_to_expected_structure(self) -> None:
        note = build_note_bytes(_VALID_HASH)
        text = note.decode("utf-8")
        assert text.startswith("openproof:j{")
        # The JSON portion should contain all three keys.
        json_part = text[len("openproof:j"):]
        parsed = json.loads(json_part)
        assert set(parsed.keys()) == {"h", "t", "v"}


# ─────────────────────────────────────────────────────────────────
# Group 5: Note size limit enforcement
# ─────────────────────────────────────────────────────────────────

class TestNoteSizeLimit:

    def test_oversized_batching_profile_rejected(self) -> None:
        # Force an oversized note by feeding a huge batching_profile string.
        huge_profile = "x" * (ALGORAND_NOTE_MAX_BYTES + 100)
        with pytest.raises(AnchorError, match="exceeds Algorand limit"):
            build_note_bytes(_VALID_HASH, batching_profile=huge_profile)


# ─────────────────────────────────────────────────────────────────
# Group 6: DRAFT mode
# ─────────────────────────────────────────────────────────────────

class TestDraftMode:

    def test_draft_returns_anchor_record_without_txid(self) -> None:
        signer = _FakeSigner()
        result = anchor_manifest(_VALID_HASH, signer=signer, mode=AnchorMode.DRAFT)
        assert result.txid == ""
        assert result.block_round is None
        assert result.confirmed_at is None

    def test_draft_does_not_call_signer(self) -> None:
        signer = _FakeSigner()
        anchor_manifest(_VALID_HASH, signer=signer, mode=AnchorMode.DRAFT)
        # No signing should have happened.
        assert signer.signed_txns == []

    def test_draft_network_is_testnet(self) -> None:
        signer = _FakeSigner()
        result = anchor_manifest(_VALID_HASH, signer=signer, mode=AnchorMode.DRAFT)
        assert result.network == ALGORAND_TESTNET

    def test_draft_note_payload_is_base64(self) -> None:
        signer = _FakeSigner()
        result = anchor_manifest(_VALID_HASH, signer=signer, mode=AnchorMode.DRAFT)
        # The base64 payload should decode to the canonical JSON payload.
        decoded = base64.b64decode(result.note_payload_b64)
        parsed = json.loads(decoded.decode("utf-8"))
        assert parsed["h"] == _VALID_HASH.hex()

    def test_draft_note_format_constants_recorded(self) -> None:
        signer = _FakeSigner()
        result = anchor_manifest(_VALID_HASH, signer=signer, mode=AnchorMode.DRAFT)
        assert result.note_format == ARC2_NOTE_FORMAT
        assert result.note_dapp_name == ARC2_DAPP_NAME
        assert result.note_format_version == ARC2_FORMAT_VERSION_JSON


# ─────────────────────────────────────────────────────────────────
# Group 7: Signer Protocol satisfaction
# ─────────────────────────────────────────────────────────────────

class TestSignerProtocol:

    def test_fake_signer_satisfies_protocol(self) -> None:
        # _FakeSigner is a plain class; the Protocol is structural.
        signer = _FakeSigner()
        assert isinstance(signer, Signer)

    def test_object_missing_address_does_not_satisfy(self) -> None:
        class _MissingAddress:
            def sign_transaction(self, txn): return txn
        # isinstance against a runtime_checkable Protocol checks attributes.
        # Note: Protocol attribute existence checking has known caveats; we
        # mostly trust structural usage downstream.
        bad = _MissingAddress()
        assert not isinstance(bad, Signer)


# ─────────────────────────────────────────────────────────────────
# Group 8: build_transaction
# ─────────────────────────────────────────────────────────────────

class TestBuildTransaction:

    def test_builds_payment_txn(self) -> None:
        algod = _FakeAlgodClient()
        sp = algod.suggested_params()
        signer_addr = "OPENPROOF" + "A" * 49
        txn = build_transaction(
            _VALID_HASH,
            signer_address=signer_addr,
            suggested_params=sp,
        )
        # Should be a PaymentTxn instance.
        from algosdk.transaction import PaymentTxn
        assert isinstance(txn, PaymentTxn)

    def test_payment_is_self_zero_value(self) -> None:
        algod = _FakeAlgodClient()
        sp = algod.suggested_params()
        signer_addr = "OPENPROOF" + "A" * 49
        txn = build_transaction(
            _VALID_HASH,
            signer_address=signer_addr,
            suggested_params=sp,
        )
        # Sender == receiver, amount == 0.
        assert txn.sender == signer_addr
        assert txn.receiver == signer_addr
        assert txn.amt == 0

    def test_note_field_set(self) -> None:
        algod = _FakeAlgodClient()
        sp = algod.suggested_params()
        signer_addr = "OPENPROOF" + "A" * 49
        txn = build_transaction(
            _VALID_HASH,
            signer_address=signer_addr,
            suggested_params=sp,
        )
        # Note should start with the ARC-2 prefix.
        assert txn.note.startswith(b"openproof:j")


# ─────────────────────────────────────────────────────────────────
# Group 9: anchor_manifest happy path (DEMO and PRODUCTION)
# ─────────────────────────────────────────────────────────────────

class TestAnchorManifestHappyPath:

    def test_demo_mode_submits_and_confirms(self) -> None:
        signer = _FakeSigner()
        algod = _FakeAlgodClient(confirm_after_polls=1)
        result = anchor_manifest(
            _VALID_HASH,
            signer=signer,
            mode=AnchorMode.DEMO,
            algod_client=algod,
        )
        assert result.network == ALGORAND_TESTNET
        assert result.txid.startswith("FAKETXID")
        assert result.block_round == 12345678
        assert result.confirmed_at is not None

    def test_production_mode_submits_and_confirms(self) -> None:
        signer = _FakeSigner()
        algod = _FakeAlgodClient(confirm_after_polls=1)
        result = anchor_manifest(
            _VALID_HASH,
            signer=signer,
            mode=AnchorMode.PRODUCTION,
            algod_client=algod,
        )
        assert result.network == ALGORAND_MAINNET
        assert result.txid.startswith("FAKETXID")
        assert result.block_round == 12345678

    def test_signer_called_once(self) -> None:
        signer = _FakeSigner()
        algod = _FakeAlgodClient()
        anchor_manifest(
            _VALID_HASH,
            signer=signer,
            mode=AnchorMode.DEMO,
            algod_client=algod,
        )
        assert len(signer.signed_txns) == 1

    def test_skip_confirmation(self) -> None:
        signer = _FakeSigner()
        algod = _FakeAlgodClient()
        result = anchor_manifest(
            _VALID_HASH,
            signer=signer,
            mode=AnchorMode.DEMO,
            algod_client=algod,
            wait_for_confirmation=False,
        )
        assert result.txid.startswith("FAKETXID")
        # Without polling, block_round and confirmed_at stay None.
        assert result.block_round is None
        assert result.confirmed_at is None
        # algod was not polled.
        assert algod.poll_count == 0


# ─────────────────────────────────────────────────────────────────
# Group 10: anchor_manifest error paths
# ─────────────────────────────────────────────────────────────────

class TestAnchorManifestErrorPaths:

    def test_signer_failure_propagates(self) -> None:
        signer = _FakeSigner(sign_raises=RuntimeError("KMS denied"))
        algod = _FakeAlgodClient()
        with pytest.raises(AnchorError, match="Signer rejected"):
            anchor_manifest(
                _VALID_HASH,
                signer=signer,
                mode=AnchorMode.DEMO,
                algod_client=algod,
            )

    def test_suggested_params_failure_propagates(self) -> None:
        signer = _FakeSigner()
        algod = _FakeAlgodClient(
            suggested_params_raises=ConnectionError("algod unreachable"),
        )
        with pytest.raises(AnchorError, match="suggested_params"):
            anchor_manifest(
                _VALID_HASH,
                signer=signer,
                mode=AnchorMode.DEMO,
                algod_client=algod,
            )

    def test_send_failure_propagates(self) -> None:
        signer = _FakeSigner()
        algod = _FakeAlgodClient(
            send_raises=RuntimeError("transaction pool full"),
        )
        with pytest.raises(AnchorError, match="send_transaction"):
            anchor_manifest(
                _VALID_HASH,
                signer=signer,
                mode=AnchorMode.DEMO,
                algod_client=algod,
            )

    def test_pool_error_during_polling(self) -> None:
        signer = _FakeSigner()
        algod = _FakeAlgodClient(pool_error="signature verification failed")
        with pytest.raises(AnchorError, match="pool"):
            anchor_manifest(
                _VALID_HASH,
                signer=signer,
                mode=AnchorMode.DEMO,
                algod_client=algod,
            )

    def test_confirmation_timeout(self) -> None:
        # Algod never confirms (confirm_after_polls is huge); timeout fires.
        signer = _FakeSigner()
        algod = _FakeAlgodClient(confirm_after_polls=10**9)
        with pytest.raises(AnchorError, match="Timed out"):
            anchor_manifest(
                _VALID_HASH,
                signer=signer,
                mode=AnchorMode.DEMO,
                algod_client=algod,
                # Very short timeout for the test.
                confirmation_timeout_seconds=0.05,
            )


# ─────────────────────────────────────────────────────────────────
# Group 11: Confirmation polling logic
# ─────────────────────────────────────────────────────────────────

class TestWaitForConfirmation:

    def test_polls_until_confirmed(self) -> None:
        # confirm_after_polls=3 means algod returns "confirmed-round > 0"
        # on the 3rd poll.
        signer = _FakeSigner()
        algod = _FakeAlgodClient(confirm_after_polls=3)
        result = anchor_manifest(
            _VALID_HASH,
            signer=signer,
            mode=AnchorMode.DEMO,
            algod_client=algod,
            confirmation_timeout_seconds=30.0,
        )
        # By the time we got a confirmation, algod was polled at least 3x.
        assert algod.poll_count >= 3
        assert result.block_round == 12345678


# ─────────────────────────────────────────────────────────────────
# Group 12: Network selection by mode
# ─────────────────────────────────────────────────────────────────

class TestNetworkSelection:

    def test_draft_records_testnet(self) -> None:
        signer = _FakeSigner()
        result = anchor_manifest(_VALID_HASH, signer=signer, mode=AnchorMode.DRAFT)
        assert result.network == ALGORAND_TESTNET

    def test_demo_records_testnet(self) -> None:
        signer = _FakeSigner()
        algod = _FakeAlgodClient()
        result = anchor_manifest(
            _VALID_HASH, signer=signer,
            mode=AnchorMode.DEMO, algod_client=algod,
        )
        assert result.network == ALGORAND_TESTNET

    def test_production_records_mainnet(self) -> None:
        signer = _FakeSigner()
        algod = _FakeAlgodClient()
        result = anchor_manifest(
            _VALID_HASH, signer=signer,
            mode=AnchorMode.PRODUCTION, algod_client=algod,
        )
        assert result.network == ALGORAND_MAINNET
