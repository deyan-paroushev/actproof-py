# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Tests for openproof.signers.interface.

Six test groups:

* TestForbiddenMethodNames: the FORBIDDEN_METHOD_NAMES set is complete.
* TestSubclassEnforcement: __init_subclass__ rejects forbidden method names.
* TestAbstractMethods: subclasses must implement address and sign_transaction.
* TestValidateTransactionPasses: a well-formed openproof transaction passes.
* TestValidateTransactionRejects: each of the five default checks rejects bad inputs.
* TestSignerValidationError: it's a ValueError subclass for unified handling.
"""

from __future__ import annotations

import pytest

from openproof.signers.interface import (
    FORBIDDEN_METHOD_NAMES,
    AlgorandSigner,
    SignerValidationError,
)


# ─────────────────────────────────────────────────────────────────
# Helper: minimal concrete signer for validation tests
# ─────────────────────────────────────────────────────────────────

class _MinimalSigner(AlgorandSigner):
    """Bare-minimum concrete signer for testing the validation method.

    Returns a fixed address; sign_transaction just validates and returns
    a sentinel.
    """
    def __init__(self, address: str = "X" * 58) -> None:
        self._address = address

    @property
    def address(self) -> str:
        return self._address

    def sign_transaction(self, txn):  # type: ignore[no-untyped-def]
        self.validate_transaction(txn)
        return "signed-sentinel"


def _build_valid_txn(sender: str = "X" * 58) -> object:
    """Build an openproof-shape Transaction using openproof.anchor."""
    from algosdk.transaction import SuggestedParams
    from openproof.anchor import build_transaction

    sp = SuggestedParams(
        fee=1000, first=1, last=1001,
        gh="test-genesis-hash" + "=" * 16,
        gen="test-network", flat_fee=True,
    )
    return build_transaction(
        bytes.fromhex("a" * 64),
        signer_address=sender,
        suggested_params=sp,
    )


# ─────────────────────────────────────────────────────────────────
# Group 1: Forbidden method names set
# ─────────────────────────────────────────────────────────────────

class TestForbiddenMethodNames:

    def test_contains_sign_bytes(self) -> None:
        assert "sign_bytes" in FORBIDDEN_METHOD_NAMES

    def test_contains_sign_data(self) -> None:
        assert "sign_data" in FORBIDDEN_METHOD_NAMES

    def test_contains_plain_sign(self) -> None:
        assert "sign" in FORBIDDEN_METHOD_NAMES

    def test_contains_asymmetric_sign(self) -> None:
        assert "asymmetric_sign" in FORBIDDEN_METHOD_NAMES

    def test_does_not_contain_sign_transaction(self) -> None:
        # sign_transaction is the ALLOWED method.
        assert "sign_transaction" not in FORBIDDEN_METHOD_NAMES

    def test_is_frozenset(self) -> None:
        assert isinstance(FORBIDDEN_METHOD_NAMES, frozenset)


# ─────────────────────────────────────────────────────────────────
# Group 2: __init_subclass__ enforcement
# ─────────────────────────────────────────────────────────────────

class TestSubclassEnforcement:

    def test_subclass_with_sign_bytes_rejected(self) -> None:
        with pytest.raises(TypeError, match="forbidden method"):
            class _Bad(AlgorandSigner):
                @property
                def address(self): return ""
                def sign_transaction(self, txn): return None
                def sign_bytes(self, b): return None  # forbidden

    def test_subclass_with_sign_data_rejected(self) -> None:
        with pytest.raises(TypeError, match="forbidden method"):
            class _Bad(AlgorandSigner):
                @property
                def address(self): return ""
                def sign_transaction(self, txn): return None
                def sign_data(self, d): return None  # forbidden

    def test_subclass_with_plain_sign_rejected(self) -> None:
        with pytest.raises(TypeError, match="forbidden method"):
            class _Bad(AlgorandSigner):
                @property
                def address(self): return ""
                def sign_transaction(self, txn): return None
                def sign(self, x): return None  # forbidden (just 'sign')

    def test_subclass_with_asymmetric_sign_rejected(self) -> None:
        with pytest.raises(TypeError, match="forbidden method"):
            class _Bad(AlgorandSigner):
                @property
                def address(self): return ""
                def sign_transaction(self, txn): return None
                def asymmetric_sign(self, x): return None  # forbidden

    def test_subclass_with_multiple_forbidden_names_rejected(self) -> None:
        with pytest.raises(TypeError, match="forbidden method"):
            class _Bad(AlgorandSigner):
                @property
                def address(self): return ""
                def sign_transaction(self, txn): return None
                def sign_bytes(self, x): return None  # forbidden
                def sign_data(self, x): return None  # also forbidden

    def test_error_message_names_offending_method(self) -> None:
        with pytest.raises(TypeError) as exc_info:
            class _Bad(AlgorandSigner):
                @property
                def address(self): return ""
                def sign_transaction(self, txn): return None
                def sign_message(self, m): return None
        assert "sign_message" in str(exc_info.value)

    def test_clean_subclass_succeeds(self) -> None:
        # A subclass with only sign_transaction (no forbidden names) works.
        class _Clean(AlgorandSigner):
            @property
            def address(self): return "X" * 58
            def sign_transaction(self, txn): return None
        # Construction works.
        instance = _Clean()
        assert instance.address == "X" * 58


# ─────────────────────────────────────────────────────────────────
# Group 3: Abstract method enforcement
# ─────────────────────────────────────────────────────────────────

class TestAbstractMethods:

    def test_cannot_instantiate_base_class(self) -> None:
        # AlgorandSigner itself has abstract methods; can't instantiate.
        with pytest.raises(TypeError, match="abstract"):
            AlgorandSigner()  # type: ignore[abstract]

    def test_subclass_missing_address_cannot_instantiate(self) -> None:
        class _MissingAddress(AlgorandSigner):
            def sign_transaction(self, txn): return None
        with pytest.raises(TypeError, match="abstract"):
            _MissingAddress()  # type: ignore[abstract]

    def test_subclass_missing_sign_transaction_cannot_instantiate(self) -> None:
        class _MissingSign(AlgorandSigner):
            @property
            def address(self): return ""
        with pytest.raises(TypeError, match="abstract"):
            _MissingSign()  # type: ignore[abstract]

    def test_complete_subclass_instantiates(self) -> None:
        signer = _MinimalSigner()
        assert signer.address == "X" * 58


# ─────────────────────────────────────────────────────────────────
# Group 4: validate_transaction passes for good input
# ─────────────────────────────────────────────────────────────────

class TestValidateTransactionPasses:

    def test_well_formed_openproof_txn_passes(self) -> None:
        signer = _MinimalSigner(address="A" * 58)
        txn = _build_valid_txn(sender="A" * 58)
        # Should not raise.
        signer.validate_transaction(txn)

    def test_sign_transaction_via_minimal_subclass(self) -> None:
        signer = _MinimalSigner(address="A" * 58)
        txn = _build_valid_txn(sender="A" * 58)
        result = signer.sign_transaction(txn)
        # Our minimal signer returns a sentinel after validation.
        assert result == "signed-sentinel"


# ─────────────────────────────────────────────────────────────────
# Group 5: validate_transaction rejects bad inputs
# ─────────────────────────────────────────────────────────────────

class TestValidateTransactionRejects:

    def test_not_a_transaction_rejected(self) -> None:
        signer = _MinimalSigner()
        with pytest.raises(SignerValidationError, match="Transaction"):
            signer.validate_transaction("not a transaction")

    def test_wrong_sender_rejected(self) -> None:
        signer = _MinimalSigner(address="A" * 58)
        # Build a txn whose sender is NOT the signer's address.
        txn = _build_valid_txn(sender="B" * 58)
        with pytest.raises(SignerValidationError, match="sender"):
            signer.validate_transaction(txn)

    def test_wrong_receiver_rejected(self) -> None:
        # We need a txn where sender == signer.address but receiver != sender.
        # Build with sender = signer.address, then mutate the receiver.
        signer = _MinimalSigner(address="A" * 58)
        txn = _build_valid_txn(sender="A" * 58)
        txn.receiver = "B" * 58  # type: ignore[attr-defined]
        with pytest.raises(SignerValidationError, match="receiver"):
            signer.validate_transaction(txn)

    def test_nonzero_amount_rejected(self) -> None:
        signer = _MinimalSigner(address="A" * 58)
        txn = _build_valid_txn(sender="A" * 58)
        txn.amt = 1  # type: ignore[attr-defined]
        with pytest.raises(SignerValidationError, match="amount"):
            signer.validate_transaction(txn)

    def test_missing_note_prefix_rejected(self) -> None:
        signer = _MinimalSigner(address="A" * 58)
        txn = _build_valid_txn(sender="A" * 58)
        txn.note = b"wrong:prefix" + txn.note[11:]  # type: ignore[attr-defined]
        with pytest.raises(SignerValidationError, match="prefix"):
            signer.validate_transaction(txn)

    def test_note_is_not_bytes_rejected(self) -> None:
        signer = _MinimalSigner(address="A" * 58)
        txn = _build_valid_txn(sender="A" * 58)
        txn.note = "openproof:j..."  # type: ignore[attr-defined]  # string, not bytes
        with pytest.raises(SignerValidationError, match="bytes"):
            signer.validate_transaction(txn)


# ─────────────────────────────────────────────────────────────────
# Group 6: SignerValidationError is a ValueError
# ─────────────────────────────────────────────────────────────────

class TestSignerValidationError:

    def test_is_value_error_subclass(self) -> None:
        assert issubclass(SignerValidationError, ValueError)

    def test_catchable_as_value_error(self) -> None:
        signer = _MinimalSigner()
        try:
            signer.validate_transaction("not a transaction")
        except ValueError:
            pass  # Caught as ValueError; good.
        else:
            pytest.fail("Expected ValueError")
