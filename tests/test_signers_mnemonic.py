# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Tests for actproof.signers.mnemonic.

Six test groups:

* TestConstruction: valid mnemonic, address derivation, deterministic.
* TestInvalidMnemonic: empty, wrong word count, bad checksum.
* TestWarningEmission: UserWarning fires on construction.
* TestSignTransaction: well-formed actproof txn is signed; SignedTransaction returned.
* TestValidationFailure: signer refuses to sign transactions that violate policy.
* TestForbiddenMethodEnforcement: MnemonicSigner cannot be subclassed with sign_bytes.
"""

from __future__ import annotations

import warnings

import pytest

from actproof.signers import (
    AlgorandSigner,
    MnemonicSigner,
    SignerValidationError,
)


# A real, valid Algorand mnemonic for testing. Generated specifically for
# this test file; not a real wallet. Address: derived deterministically.
_TEST_MNEMONIC = (
    "total monkey oven casino taxi maximum furnace approve cliff lizard "
    "address apple laundry consider hair flash file kingdom prosper arrive "
    "rifle area inch abandon grass"
)
_TEST_ADDRESS = "5NO6LZDFQNXI7NVF77WHCBPNLHFFWREIIGDHRJRWF2NG7K26SLLT6255BA"


def _build_actproof_txn(sender: str):
    """Build a well-formed actproof transaction for the given sender."""
    from algosdk.transaction import SuggestedParams
    from actproof.anchor import build_transaction

    sp = SuggestedParams(
        fee=1000, first=1, last=1001,
        gh="test-genesis-hash" + "=" * 16,
        gen="test-network", flat_fee=True,
    )
    return build_transaction(
        bytes.fromhex("b" * 64),
        signer_address=sender,
        suggested_params=sp,
    )


@pytest.fixture
def signer() -> MnemonicSigner:
    """A MnemonicSigner with warnings suppressed (we test the warning separately)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        return MnemonicSigner(_TEST_MNEMONIC)


# ─────────────────────────────────────────────────────────────────
# Group 1: Construction
# ─────────────────────────────────────────────────────────────────

class TestConstruction:

    def test_valid_mnemonic_constructs(self, signer: MnemonicSigner) -> None:
        assert signer is not None
        assert isinstance(signer, MnemonicSigner)
        assert isinstance(signer, AlgorandSigner)

    def test_address_is_58_chars(self, signer: MnemonicSigner) -> None:
        assert len(signer.address) == 58

    def test_address_is_deterministic(self, signer: MnemonicSigner) -> None:
        # Same mnemonic produces same address.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=UserWarning)
            signer2 = MnemonicSigner(_TEST_MNEMONIC)
        assert signer.address == signer2.address

    def test_mnemonic_whitespace_normalised(self) -> None:
        # Extra spaces between words should be tolerated.
        ugly = _TEST_MNEMONIC.replace(" ", "  ")  # double-spaced
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=UserWarning)
            signer = MnemonicSigner(ugly)
        # Same address as clean mnemonic.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=UserWarning)
            clean = MnemonicSigner(_TEST_MNEMONIC)
        assert signer.address == clean.address


# ─────────────────────────────────────────────────────────────────
# Group 2: Invalid mnemonic
# ─────────────────────────────────────────────────────────────────

class TestInvalidMnemonic:

    def test_empty_mnemonic_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            MnemonicSigner("")

    def test_whitespace_only_mnemonic_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            MnemonicSigner("    \n   ")

    def test_wrong_word_count_rejected(self) -> None:
        with pytest.raises(ValueError, match="25 words"):
            MnemonicSigner("only three words here")

    def test_too_many_words_rejected(self) -> None:
        too_many = " ".join(["word"] * 30)
        with pytest.raises(ValueError, match="25 words"):
            MnemonicSigner(too_many)

    def test_bad_checksum_rejected(self) -> None:
        # 25 words but the checksum word is wrong.
        # Take a valid mnemonic and replace the last (checksum) word.
        words = _TEST_MNEMONIC.split()
        words[-1] = "abandon"  # not the right checksum
        bad = " ".join(words)
        with pytest.raises(ValueError, match="checksum|derive|private"):
            MnemonicSigner(bad)


# ─────────────────────────────────────────────────────────────────
# Group 3: Warning emission
# ─────────────────────────────────────────────────────────────────

class TestWarningEmission:

    def test_user_warning_emitted_on_construction(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            MnemonicSigner(_TEST_MNEMONIC)
        # At least one UserWarning should have been caught.
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) >= 1

    def test_warning_message_mentions_testing_only(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            MnemonicSigner(_TEST_MNEMONIC)
        msg = str(caught[0].message)
        assert "testing only" in msg.lower() or "production" in msg.lower()

    def test_warning_message_mentions_hsm(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            MnemonicSigner(_TEST_MNEMONIC)
        msg = str(caught[0].message)
        # Should mention "HSM" or one of the production-key options.
        assert (
            "HSM" in msg or "hardware security" in msg.lower()
            or "KMS" in msg
        )


# ─────────────────────────────────────────────────────────────────
# Group 4: Signing valid transactions
# ─────────────────────────────────────────────────────────────────

class TestSignTransaction:

    def test_signs_valid_actproof_txn(self, signer: MnemonicSigner) -> None:
        from algosdk.transaction import SignedTransaction
        txn = _build_actproof_txn(sender=signer.address)
        signed = signer.sign_transaction(txn)
        assert isinstance(signed, SignedTransaction)

    def test_signed_transaction_has_signature(
        self, signer: MnemonicSigner
    ) -> None:
        txn = _build_actproof_txn(sender=signer.address)
        signed = signer.sign_transaction(txn)
        # The signature field is set (base64 string of the Ed25519 sig).
        assert signed.signature is not None
        assert len(signed.signature) > 0

    def test_signing_is_deterministic_for_same_inputs(
        self, signer: MnemonicSigner
    ) -> None:
        # Ed25519 is deterministic; same key + same message = same signature.
        from algosdk.transaction import SuggestedParams
        from actproof.anchor import build_transaction

        sp = SuggestedParams(
            fee=1000, first=1, last=1001,
            gh="test-genesis-hash" + "=" * 16,
            gen="test-network", flat_fee=True,
        )
        hash_bytes = bytes.fromhex("c" * 64)

        # Two separate builds of the same transaction.
        txn1 = build_transaction(
            hash_bytes, signer_address=signer.address, suggested_params=sp
        )
        txn2 = build_transaction(
            hash_bytes, signer_address=signer.address, suggested_params=sp
        )
        sig1 = signer.sign_transaction(txn1).signature
        sig2 = signer.sign_transaction(txn2).signature
        assert sig1 == sig2


# ─────────────────────────────────────────────────────────────────
# Group 5: Validation failures
# ─────────────────────────────────────────────────────────────────

class TestValidationFailure:

    def test_refuses_wrong_sender(self, signer: MnemonicSigner) -> None:
        other = "B" * 58
        txn = _build_actproof_txn(sender=other)
        with pytest.raises(SignerValidationError, match="sender"):
            signer.sign_transaction(txn)

    def test_refuses_non_self_payment(self, signer: MnemonicSigner) -> None:
        txn = _build_actproof_txn(sender=signer.address)
        txn.receiver = "B" * 58  # mutate to break self-payment
        with pytest.raises(SignerValidationError, match="receiver"):
            signer.sign_transaction(txn)

    def test_refuses_nonzero_amount(self, signer: MnemonicSigner) -> None:
        txn = _build_actproof_txn(sender=signer.address)
        txn.amt = 1
        with pytest.raises(SignerValidationError, match="amount"):
            signer.sign_transaction(txn)

    def test_refuses_wrong_note_prefix(self, signer: MnemonicSigner) -> None:
        txn = _build_actproof_txn(sender=signer.address)
        txn.note = b"otherapp:k" + txn.note[10:]
        with pytest.raises(SignerValidationError, match="prefix"):
            signer.sign_transaction(txn)


# ─────────────────────────────────────────────────────────────────
# Group 6: Forbidden-method enforcement applies to MnemonicSigner subclasses
# ─────────────────────────────────────────────────────────────────

class TestForbiddenMethodEnforcement:

    def test_cannot_add_sign_bytes_to_mnemonic_signer(self) -> None:
        # Even subclassing MnemonicSigner, the ABC's __init_subclass__
        # hook still fires.
        with pytest.raises(TypeError, match="forbidden method"):
            class _Bad(MnemonicSigner):
                def sign_bytes(self, b): return None
