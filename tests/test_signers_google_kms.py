# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: Apache-2.0
"""
Tests for actproof.signers.google_kms.

Mocked tests only; no real GCP KMS calls. Real-network tests (a deploy
that has access to a real KMS keyring) belong in a separate suite marked
``@pytest.mark.slow``.

Six test groups:

* TestImportAvailability: GoogleKMSSigner is either a class or None
  depending on whether google-cloud-kms is installed.
* TestConstructionValidation: kms_resource_name must contain
  'cryptoKeyVersions/' or instantiation raises.
* TestAddressDerivation: address property triggers get_public_key and
  returns the derived Algorand address.
* TestSignTransaction: sign_transaction validates, computes bytes-to-sign,
  calls asymmetric_sign, assembles a SignedTransaction.
* TestCRCValidation: response CRC32C mismatches cause RuntimeError.
* TestForbiddenMethodEnforcement: cannot add sign_bytes to a subclass.
"""

from __future__ import annotations

import warnings
from typing import Any
from unittest.mock import MagicMock

import pytest

# These tests exercise actproof.signers.google_kms, which depends on
# google-cloud-kms and google-crc32c. Both ship via the ``[gcp]`` extra.
# Without them, the GoogleKMSSigner class exists only as a stub that
# raises on instantiation. Skip the entire module rather than reporting
# 16 failures in environments that do not install the GCP extra (a
# common case for catalogue-only development and CI runs that do not
# touch the signer subsystem).
pytest.importorskip(
    "google.cloud.kms",
    reason=(
        "google-cloud-kms is not installed. "
        "Install actproof's optional GCP extra: pip install 'actproof[gcp]'. "
        "These tests do not make real KMS calls but require the client "
        "library to be importable."
    ),
)
pytest.importorskip(
    "google_crc32c",
    reason=(
        "google-crc32c is not installed (part of the [gcp] extra). "
        "Install actproof's optional GCP extra: pip install 'actproof[gcp]'."
    ),
)

# Conditional import: skip the whole module if google-cloud-kms is not present.
try:
    from actproof.signers.google_kms import (
        ALGORAND_SIGN_PREFIX,
        GoogleKMSSigner,
        _derive_algorand_address,
    )
    _GCP_AVAILABLE = True
except Exception:
    _GCP_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _GCP_AVAILABLE,
    reason="google-cloud-kms not installed (install with: pip install 'actproof[gcp]')",
)


# Real Ed25519 keypair for test vector. The address is deterministic.
_TEST_RAW_PUBKEY = bytes.fromhex(
    # 32 bytes of test public key material.
    "1c8e3c5a8c8e0e2a5f7b9c3a4e6d8f0a2c4e6f8a1b3d5e7f9b1c3a5e7c9d1f3a"
)


def _build_test_pem() -> bytes:
    """Build an SPKI-PEM-encoded Ed25519 public key for tests."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    pub = Ed25519PublicKey.from_public_bytes(_TEST_RAW_PUBKEY)
    return pub.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def _build_actproof_txn(sender: str) -> Any:
    """Build a well-formed actproof transaction for the given sender."""
    from algosdk.transaction import SuggestedParams
    from actproof.anchor import build_transaction

    sp = SuggestedParams(
        fee=1000, first=1, last=1001,
        gh="test-genesis-hash" + "=" * 16,
        gen="test-network", flat_fee=True,
    )
    return build_transaction(
        bytes.fromhex("d" * 64),
        signer_address=sender,
        suggested_params=sp,
    )


def _make_mock_kms_client(
    pem_bytes: bytes,
    signature_bytes: bytes,
    pem_crc: int | None = None,
    sig_crc: int | None = None,
    verified_data_crc: bool = True,
    resource_name: str | None = None,
) -> MagicMock:
    """Build a mock KMS client whose get_public_key and asymmetric_sign
    return the supplied bytes.

    v0.3.0 enforces ``response.name == request.name`` fail-closed, so
    every response mock must set the ``name`` attribute to the
    resource path the signer was constructed with.
    """
    import google_crc32c

    if pem_crc is None:
        pem_crc = int(google_crc32c.value(pem_bytes))
    if sig_crc is None:
        sig_crc = int(google_crc32c.value(signature_bytes))
    if resource_name is None:
        resource_name = _VALID_KMS_PATH

    pubkey_response = MagicMock()
    pubkey_response.name = resource_name
    pubkey_response.pem = pem_bytes.decode("utf-8")
    pubkey_response.pem_crc32c = pem_crc

    sign_response = MagicMock()
    sign_response.name = resource_name
    sign_response.signature = signature_bytes
    sign_response.signature_crc32c = sig_crc
    sign_response.verified_data_crc32c = verified_data_crc

    client = MagicMock()
    client.get_public_key.return_value = pubkey_response
    client.asymmetric_sign.return_value = sign_response
    return client


_VALID_KMS_PATH = (
    "projects/actproof-test/locations/europe-west4/keyRings/anchoring/"
    "cryptoKeys/anchor-signer-v1/cryptoKeyVersions/1"
)


# ─────────────────────────────────────────────────────────────────
# Group 1: Import availability
# ─────────────────────────────────────────────────────────────────

class TestImportAvailability:

    def test_class_importable(self) -> None:
        assert GoogleKMSSigner is not None

    def test_inherits_algorand_signer(self) -> None:
        from actproof.signers.interface import AlgorandSigner
        assert issubclass(GoogleKMSSigner, AlgorandSigner)


# ─────────────────────────────────────────────────────────────────
# Group 2: Construction validation
# ─────────────────────────────────────────────────────────────────

class TestConstructionValidation:

    def test_invalid_kms_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="cryptoKeyVersions"):
            GoogleKMSSigner(
                kms_resource_name="not-a-kms-path",
                kms_client=MagicMock(),
            )

    def test_empty_kms_path_rejected(self) -> None:
        with pytest.raises(ValueError):
            GoogleKMSSigner(kms_resource_name="", kms_client=MagicMock())

    def test_valid_path_constructs(self) -> None:
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=MagicMock(),
        )
        assert signer is not None

    def test_construction_makes_no_kms_call(self) -> None:
        # Construction must NOT trigger a KMS network call. The first
        # call is on first address access.
        client = MagicMock()
        GoogleKMSSigner(kms_resource_name=_VALID_KMS_PATH, kms_client=client)
        client.get_public_key.assert_not_called()
        client.asymmetric_sign.assert_not_called()


# ─────────────────────────────────────────────────────────────────
# Group 3: Address derivation
# ─────────────────────────────────────────────────────────────────

class TestAddressDerivation:

    def test_first_address_access_calls_kms(self) -> None:
        pem = _build_test_pem()
        client = _make_mock_kms_client(pem, signature_bytes=b"x" * 64)
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=client,
        )
        _ = signer.address
        client.get_public_key.assert_called_once()

    def test_address_is_58_chars(self) -> None:
        pem = _build_test_pem()
        client = _make_mock_kms_client(pem, signature_bytes=b"x" * 64)
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=client,
        )
        assert len(signer.address) == 58

    def test_address_cached_across_calls(self) -> None:
        pem = _build_test_pem()
        client = _make_mock_kms_client(pem, signature_bytes=b"x" * 64)
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=client,
        )
        _ = signer.address
        _ = signer.address
        _ = signer.address
        # KMS get_public_key should be called only once due to caching.
        assert client.get_public_key.call_count == 1

    def test_derive_address_helper_matches_algosdk(self) -> None:
        from algosdk import encoding
        expected = encoding.encode_address(_TEST_RAW_PUBKEY)
        actual = _derive_algorand_address(_TEST_RAW_PUBKEY)
        assert actual == expected

    def test_derive_address_rejects_wrong_length(self) -> None:
        with pytest.raises(ValueError, match="32-byte"):
            _derive_algorand_address(b"too-short")


# ─────────────────────────────────────────────────────────────────
# Group 4: sign_transaction
# ─────────────────────────────────────────────────────────────────

class TestSignTransaction:

    def test_calls_asymmetric_sign_with_data_field(self) -> None:
        pem = _build_test_pem()
        fake_sig = b"f" * 64
        client = _make_mock_kms_client(pem, signature_bytes=fake_sig)
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=client,
        )

        txn = _build_actproof_txn(sender=signer.address)
        signed = signer.sign_transaction(txn)

        # asymmetric_sign was called.
        client.asymmetric_sign.assert_called_once()
        # Inspect the request payload: it must use 'data' (not 'digest').
        call_args = client.asymmetric_sign.call_args
        request = call_args.kwargs["request"]
        assert "data" in request
        assert "digest" not in request
        # Data starts with TX prefix per Algorand signing rule.
        assert request["data"].startswith(ALGORAND_SIGN_PREFIX)
        # SignedTransaction is assembled.
        from algosdk.transaction import SignedTransaction
        assert isinstance(signed, SignedTransaction)

    def test_signature_round_trips_to_signed_transaction(self) -> None:
        pem = _build_test_pem()
        fake_sig = bytes(range(64))  # deterministic, 64 bytes
        client = _make_mock_kms_client(pem, signature_bytes=fake_sig)
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=client,
        )
        txn = _build_actproof_txn(sender=signer.address)
        signed = signer.sign_transaction(txn)

        import base64
        expected_b64 = base64.b64encode(fake_sig).decode("ascii")
        assert signed.signature == expected_b64

    def test_invalid_transaction_rejected_before_kms_call(self) -> None:
        # Validation should happen before KMS is contacted.
        pem = _build_test_pem()
        client = _make_mock_kms_client(pem, signature_bytes=b"x" * 64)
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=client,
        )

        # Trigger address (to populate cache) so get_public_key is counted.
        _ = signer.address
        initial_get_count = client.get_public_key.call_count

        # Now try to sign a bad transaction (wrong sender).
        bad_txn = _build_actproof_txn(sender="B" * 58)
        from actproof.signers.interface import SignerValidationError
        with pytest.raises(SignerValidationError):
            signer.sign_transaction(bad_txn)

        # asymmetric_sign was NOT called for the bad txn.
        client.asymmetric_sign.assert_not_called()


# ─────────────────────────────────────────────────────────────────
# Group 5: CRC validation
# ─────────────────────────────────────────────────────────────────

class TestCRCValidation:

    def test_pem_crc_mismatch_raises(self) -> None:
        pem = _build_test_pem()
        client = _make_mock_kms_client(
            pem, signature_bytes=b"x" * 64, pem_crc=999999  # wrong CRC
        )
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=client,
        )
        with pytest.raises(RuntimeError, match="CRC32C"):
            _ = signer.address

    def test_signature_crc_mismatch_raises(self) -> None:
        pem = _build_test_pem()
        fake_sig = b"f" * 64
        client = _make_mock_kms_client(
            pem, signature_bytes=fake_sig, sig_crc=999999  # wrong CRC
        )
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=client,
        )
        txn = _build_actproof_txn(sender=signer.address)
        with pytest.raises(RuntimeError, match="CRC32C"):
            signer.sign_transaction(txn)

    def test_unverified_data_crc_raises(self) -> None:
        # KMS reports it could NOT verify our request data CRC.
        pem = _build_test_pem()
        client = _make_mock_kms_client(
            pem, signature_bytes=b"f" * 64, verified_data_crc=False
        )
        signer = GoogleKMSSigner(
            kms_resource_name=_VALID_KMS_PATH,
            kms_client=client,
        )
        txn = _build_actproof_txn(sender=signer.address)
        with pytest.raises(RuntimeError, match="CRC32C"):
            signer.sign_transaction(txn)


# ─────────────────────────────────────────────────────────────────
# Group 6: Forbidden-method enforcement applies to GoogleKMSSigner subclasses
# ─────────────────────────────────────────────────────────────────

class TestForbiddenMethodEnforcement:

    def test_cannot_add_sign_bytes_to_google_kms_signer(self) -> None:
        with pytest.raises(TypeError, match="forbidden method"):
            class _Bad(GoogleKMSSigner):  # type: ignore[misc]
                def sign_bytes(self, b): return None
