# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: Apache-2.0
"""
Tests for v0.3.0 signer policy and security hardening.

Covers:

* Configurable ``allowed_note_prefixes`` (positive, negative, single-
  bytes UX, multi-prefix, empty rejection).
* Configurable ``max_fee_microalgos`` (default, raised, below-minimum
  rejection).
* Hard rejection of attack-vector fields: ``rekey_to``,
  ``close_remainder_to``, ``group``, ``lease``.
* Hard rejection of non-PaymentTxn transaction types.
* Hard rejection of out-of-range fees.
* Fail-closed on missing ``super().__init__()`` in subclasses.
* ``__init_subclass__`` walks the MRO and rejects mixin-inherited
  forbidden methods.
* ``_assemble_signed_transaction`` rejects malformed signature
  lengths.
* GoogleKMSSigner integrity verification: ``response.name`` mismatch,
  ``verified_data_crc32c`` false/missing, signature length wrong,
  ``signature_crc32c`` missing, ``pem_crc32c`` missing.
* Cryptographic equivalence: the new strict-policy MnemonicSigner
  produces the same bytes as the v0.2.0 strict-policy MnemonicSigner
  for an actproof:j note (since the policy did not change the bytes
  signed; it only changed what shapes are accepted).
"""

from __future__ import annotations

import base64
from typing import Any, Optional
from unittest import mock

import pytest

from actproof.signers.interface import (
    ALGORAND_DEFAULT_MAX_FEE_MICROALGOS,
    ALGORAND_MIN_FEE_MICROALGOS,
    AlgorandSigner,
    FORBIDDEN_METHOD_NAMES,
    SignerValidationError,
)


# ─────────────────────────────────────────────────────────────────
# TEST FIXTURES
# ─────────────────────────────────────────────────────────────────

# A known-good Algorand mnemonic generated for the actproof test
# suite. 25 words, valid checksum.
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon"
)


def _make_mnemonic_signer(**kwargs):
    """Construct a MnemonicSigner with the UserWarning suppressed."""
    import warnings

    from actproof.signers.mnemonic import MnemonicSigner

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        # The 25-word "abandon" mnemonic above fails the algosdk
        # checksum on purpose (it is the canonical invalid mnemonic).
        # For tests that need a valid signer instance, use the
        # generated test mnemonic below.
        return MnemonicSigner(_VALID_TEST_MNEMONIC, **kwargs)


# Generated once with algosdk.account.generate_account() for the
# test suite. The corresponding address is computed at import time
# below.
_VALID_TEST_MNEMONIC = (
    "vendor blouse detail front old place trip first major jungle "
    "width grunt proof solar achieve lake valley gift skull mushroom "
    "mule when output abandon raw"
)


@pytest.fixture(scope="module")
def signer_address():
    """The Algorand address derived from _VALID_TEST_MNEMONIC."""
    from algosdk import account, mnemonic

    pk = mnemonic.to_private_key(_VALID_TEST_MNEMONIC)
    return account.address_from_private_key(pk)


@pytest.fixture
def signer(signer_address):
    """A MnemonicSigner with default (strict) policy."""
    return _make_mnemonic_signer()


def _build_payment_txn(
    sender: str,
    receiver: Optional[str] = None,
    amt: int = 0,
    note: bytes = b"actproof:j{}",
    fee: int = 1000,
    rekey_to: Optional[str] = None,
    close_remainder_to: Optional[str] = None,
    lease: Optional[bytes] = None,
):
    """Build a PaymentTxn with reasonable defaults for testing."""
    from algosdk import transaction as algo_txn

    sp = algo_txn.SuggestedParams(
        fee=fee,
        first=1,
        last=1000,
        gh="JBR3KGFEWPEE5SAQ6IWU6EEBZMHXD4CZU6WCBXWGF57XBZIJHIRA",
        gen="testnet-v1.0",
        flat_fee=True,
    )
    return algo_txn.PaymentTxn(
        sender=sender,
        sp=sp,
        receiver=receiver if receiver is not None else sender,
        amt=amt,
        note=note,
        close_remainder_to=close_remainder_to,
        lease=lease,
        rekey_to=rekey_to,
    )


# ─────────────────────────────────────────────────────────────────
# 1. CONFIGURABLE NOTE PREFIXES
# ─────────────────────────────────────────────────────────────────

class TestAllowedNotePrefixes:
    """Configuration and policy semantics for allowed_note_prefixes."""

    def test_default_accepts_actproof_prefix(self, signer, signer_address):
        txn = _build_payment_txn(signer_address, note=b"actproof:j{}")
        signer.validate_transaction(txn)  # no exception

    def test_default_rejects_other_prefix(self, signer, signer_address):
        txn = _build_payment_txn(
            signer_address,
            note=b"quoruna/v1:{}",
        )
        with pytest.raises(SignerValidationError, match="prefixes"):
            signer.validate_transaction(txn)

    def test_custom_single_prefix_accepts_match(self, signer_address):
        s = _make_mnemonic_signer(allowed_note_prefixes=[b"quoruna/v1:"])
        txn = _build_payment_txn(signer_address, note=b"quoruna/v1:{}")
        s.validate_transaction(txn)

    def test_custom_single_prefix_rejects_default(self, signer_address):
        s = _make_mnemonic_signer(allowed_note_prefixes=[b"quoruna/v1:"])
        txn = _build_payment_txn(signer_address, note=b"actproof:j{}")
        with pytest.raises(SignerValidationError):
            s.validate_transaction(txn)

    def test_single_bytes_value_accepted_ergonomically(self, signer_address):
        """UX: passing b'...' directly (not wrapped in a list) works."""
        s = _make_mnemonic_signer(allowed_note_prefixes=b"quoruna/v1:")
        txn = _build_payment_txn(signer_address, note=b"quoruna/v1:{}")
        s.validate_transaction(txn)

    def test_single_bytearray_value_accepted(self, signer_address):
        s = _make_mnemonic_signer(
            allowed_note_prefixes=bytearray(b"quoruna/v1:")
        )
        txn = _build_payment_txn(signer_address, note=b"quoruna/v1:{}")
        s.validate_transaction(txn)

    def test_multiple_prefixes_any_match_accepted(self, signer_address):
        s = _make_mnemonic_signer(
            allowed_note_prefixes=[b"actproof:j", b"quoruna/v1:"]
        )
        for prefix in (b"actproof:j{}", b"quoruna/v1:{}"):
            txn = _build_payment_txn(signer_address, note=prefix)
            s.validate_transaction(txn)

    def test_empty_list_rejected(self):
        with pytest.raises(ValueError, match="at least one prefix"):
            _make_mnemonic_signer(allowed_note_prefixes=[])

    def test_empty_prefix_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            _make_mnemonic_signer(allowed_note_prefixes=[b""])

    def test_non_bytes_element_raises_typeerror(self):
        with pytest.raises(TypeError, match="must be bytes"):
            _make_mnemonic_signer(allowed_note_prefixes=["string"])

    def test_non_bytes_element_typeerror_hints_at_single_bytes(self):
        """The error message should guide the user to the single-bytes
        form."""
        with pytest.raises(TypeError, match="pass the bytes value"):
            _make_mnemonic_signer(allowed_note_prefixes=["string"])


# ─────────────────────────────────────────────────────────────────
# 2. SENDER, RECEIVER, AMOUNT (NON-CONFIGURABLE)
# ─────────────────────────────────────────────────────────────────

class TestSenderReceiverAmount:
    """The strict 0-ALGO self-payment shape is non-configurable in v0.3.0."""

    def test_wrong_sender_rejected(self, signer):
        other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
        txn = _build_payment_txn(other)
        with pytest.raises(SignerValidationError, match="sender"):
            signer.validate_transaction(txn)

    def test_wrong_receiver_rejected(self, signer, signer_address):
        other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
        txn = _build_payment_txn(signer_address, receiver=other)
        with pytest.raises(SignerValidationError, match="receiver"):
            signer.validate_transaction(txn)

    def test_nonzero_amount_rejected(self, signer, signer_address):
        txn = _build_payment_txn(signer_address, amt=1)
        with pytest.raises(SignerValidationError, match="amount must be 0"):
            signer.validate_transaction(txn)


# ─────────────────────────────────────────────────────────────────
# 3. CRITICAL ATTACK-VECTOR FIELDS (REJECTED FAIL-CLOSED)
# ─────────────────────────────────────────────────────────────────

class TestRejectAttackVectorFields:
    """The fields that v0.2.0 missed and that v0.3.0 closes.

    These rejections are non-configurable hard invariants. There is no
    legitimate anchoring use case for any of these fields.
    """

    def test_rejects_rekey_to(self, signer, signer_address):
        """The MyAlgo $3M drain attack class."""
        attacker = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
        txn = _build_payment_txn(signer_address, rekey_to=attacker)
        with pytest.raises(SignerValidationError, match="rekey"):
            signer.validate_transaction(txn)

    def test_rejects_close_remainder_to(self, signer, signer_address):
        """Drains all remaining ALGO and closes the account."""
        attacker = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
        txn = _build_payment_txn(
            signer_address, close_remainder_to=attacker
        )
        with pytest.raises(SignerValidationError, match="close"):
            signer.validate_transaction(txn)

    def test_rejects_lease(self, signer, signer_address):
        """Lease blocks other transactions; not an anchoring use case."""
        txn = _build_payment_txn(signer_address, lease=b"x" * 32)
        with pytest.raises(SignerValidationError, match="lease"):
            signer.validate_transaction(txn)

    def test_rejects_group(self, signer, signer_address):
        """Grouped transactions create sandwich-attack surface."""
        from algosdk import transaction as algo_txn

        txn = _build_payment_txn(signer_address)
        # Assign a group ID manually.
        txn.group = b"x" * 32
        with pytest.raises(SignerValidationError, match="group"):
            signer.validate_transaction(txn)


# ─────────────────────────────────────────────────────────────────
# 4. TRANSACTION TYPE (ONLY PaymentTxn ACCEPTED)
# ─────────────────────────────────────────────────────────────────

class TestRequirePaymentTxn:
    """Only PaymentTxn is accepted; other types are rejected."""

    def test_rejects_asset_transfer_txn(self, signer, signer_address):
        from algosdk import transaction as algo_txn

        sp = algo_txn.SuggestedParams(
            fee=1000,
            first=1,
            last=1000,
            gh="JBR3KGFEWPEE5SAQ6IWU6EEBZMHXD4CZU6WCBXWGF57XBZIJHIRA",
            gen="testnet-v1.0",
            flat_fee=True,
        )
        txn = algo_txn.AssetTransferTxn(
            sender=signer_address,
            sp=sp,
            receiver=signer_address,
            amt=0,
            index=1,
            note=b"actproof:j{}",
        )
        with pytest.raises(SignerValidationError, match="PaymentTxn"):
            signer.validate_transaction(txn)

    def test_rejects_key_registration_txn(self, signer, signer_address):
        from algosdk import transaction as algo_txn

        sp = algo_txn.SuggestedParams(
            fee=1000,
            first=1,
            last=1000,
            gh="JBR3KGFEWPEE5SAQ6IWU6EEBZMHXD4CZU6WCBXWGF57XBZIJHIRA",
            gen="testnet-v1.0",
            flat_fee=True,
        )
        # KeyregNonparticipatingTxn is the simplest variant to build.
        txn = algo_txn.KeyregNonparticipatingTxn(
            sender=signer_address,
            sp=sp,
            note=b"actproof:j{}",
        )
        with pytest.raises(SignerValidationError, match="PaymentTxn"):
            signer.validate_transaction(txn)

    def test_rejects_non_transaction_object(self, signer):
        class FakeTxn:
            sender = "X"
            receiver = "X"
            amt = 0
            note = b"actproof:j{}"

        with pytest.raises(SignerValidationError, match="PaymentTxn"):
            signer.validate_transaction(FakeTxn())


# ─────────────────────────────────────────────────────────────────
# 5. FEE BOUNDED
# ─────────────────────────────────────────────────────────────────

class TestFeeBounded:
    """Fee must be in [ALGORAND_MIN_FEE_MICROALGOS, max_fee_microalgos]."""

    def test_default_max_is_protocol_minimum(self, signer, signer_address):
        # Default fee = 1000 microALGOs = ALGORAND_MIN_FEE_MICROALGOS.
        txn = _build_payment_txn(signer_address, fee=1000)
        signer.validate_transaction(txn)

    def test_fee_above_default_max_rejected(self, signer, signer_address):
        txn = _build_payment_txn(signer_address, fee=1001)
        with pytest.raises(SignerValidationError, match="exceeds"):
            signer.validate_transaction(txn)

    def test_high_fee_attack_rejected(self, signer, signer_address):
        """Without a fee cap, an attacker could burn ALGO via fees."""
        txn = _build_payment_txn(signer_address, fee=100_000_000)
        with pytest.raises(SignerValidationError, match="exceeds"):
            signer.validate_transaction(txn)

    def test_fee_below_protocol_minimum_rejected(
        self, signer, signer_address
    ):
        txn = _build_payment_txn(signer_address, fee=999)
        with pytest.raises(SignerValidationError, match="below.*minimum"):
            signer.validate_transaction(txn)

    def test_raised_max_fee_accepts_higher_fee(self, signer_address):
        s = _make_mnemonic_signer(max_fee_microalgos=10_000)
        txn = _build_payment_txn(signer_address, fee=10_000)
        s.validate_transaction(txn)

    def test_raised_max_fee_still_rejects_above(self, signer_address):
        s = _make_mnemonic_signer(max_fee_microalgos=10_000)
        txn = _build_payment_txn(signer_address, fee=10_001)
        with pytest.raises(SignerValidationError, match="exceeds"):
            s.validate_transaction(txn)

    def test_max_fee_below_protocol_minimum_rejected(self):
        with pytest.raises(ValueError, match="protocol minimum"):
            _make_mnemonic_signer(max_fee_microalgos=999)

    def test_max_fee_must_be_int(self):
        with pytest.raises(TypeError, match="must be int"):
            _make_mnemonic_signer(max_fee_microalgos="1000")

    def test_max_fee_bool_rejected(self):
        """bool is a subclass of int; explicitly reject it."""
        with pytest.raises(TypeError, match="must be int"):
            _make_mnemonic_signer(max_fee_microalgos=True)


# ─────────────────────────────────────────────────────────────────
# 6. NOTE TYPE CHECK
# ─────────────────────────────────────────────────────────────────

class TestNoteValidation:
    def test_string_note_rejected(self, signer, signer_address):
        # algosdk lets us assign a non-bytes note; validation catches it.
        txn = _build_payment_txn(signer_address, note=b"actproof:j{}")
        txn.note = "actproof:j{}"  # type: ignore[assignment]
        with pytest.raises(SignerValidationError, match="must be bytes"):
            signer.validate_transaction(txn)

    def test_none_note_rejected(self, signer, signer_address):
        txn = _build_payment_txn(signer_address, note=b"actproof:j{}")
        txn.note = None
        with pytest.raises(SignerValidationError, match="must be bytes"):
            signer.validate_transaction(txn)

    def test_oversized_note_rejected(self, signer, signer_address):
        """ChatGPT v0.3.0 review Finding C: notes above the protocol
        maximum (1024 bytes) must be rejected before the KMS call.

        algosdk itself rejects oversized notes at PaymentTxn
        construction time, so this test mutates the note attribute
        after construction to verify the signer's own belt-and-
        suspenders check fires."""
        from actproof.signers.interface import ALGORAND_MAX_NOTE_BYTES

        txn = _build_payment_txn(signer_address, note=b"actproof:j{}")
        # Mutate after construction (algosdk's own check would block
        # this at __init__).
        oversized = b"actproof:j" + (b"x" * ALGORAND_MAX_NOTE_BYTES)
        assert len(oversized) > ALGORAND_MAX_NOTE_BYTES
        txn.note = oversized
        with pytest.raises(SignerValidationError, match="maximum"):
            signer.validate_transaction(txn)

    def test_note_at_maximum_accepted(self, signer, signer_address):
        """The boundary case: exactly ALGORAND_MAX_NOTE_BYTES is OK."""
        from actproof.signers.interface import ALGORAND_MAX_NOTE_BYTES

        prefix = b"actproof:j"
        # Pad with 'x' bytes to land at exactly the maximum.
        padding = b"x" * (ALGORAND_MAX_NOTE_BYTES - len(prefix))
        note = prefix + padding
        assert len(note) == ALGORAND_MAX_NOTE_BYTES
        txn = _build_payment_txn(signer_address, note=note)
        signer.validate_transaction(txn)  # no exception


# ─────────────────────────────────────────────────────────────────
# 7. SUBCLASS DISCIPLINE (MRO WALK, FAIL-CLOSED INIT)
# ─────────────────────────────────────────────────────────────────

class TestSubclassDiscipline:
    """__init_subclass__ walks the MRO; missing super().__init__()
    is loud."""

    def test_directly_defined_forbidden_method_rejected(self):
        with pytest.raises(TypeError, match="forbidden method"):

            class BadDirect(AlgorandSigner):
                def sign_bytes(self, payload: bytes):
                    return payload

                @property
                def address(self) -> str:
                    return ""

                def sign_transaction(self, txn):
                    return None

    def test_mixin_inherited_forbidden_method_rejected(self):
        """The v0.3.0 MRO walk catches what cls.__dict__ alone missed."""

        class RawSigningMixin:
            def sign_raw(self, payload: bytes):
                return payload

        with pytest.raises(TypeError, match="MRO"):

            class BadViaMixin(RawSigningMixin, AlgorandSigner):
                @property
                def address(self) -> str:
                    return ""

                def sign_transaction(self, txn):
                    return None

    def test_clean_subclass_succeeds(self):
        # Constructs without raising; this is the positive case.
        class GoodSigner(AlgorandSigner):
            @property
            def address(self) -> str:
                return ""

            def sign_transaction(self, txn):
                return None

        # Class definition itself does not raise.
        assert GoodSigner is not None

    def test_missing_super_init_fails_closed(self, signer_address):
        """A subclass that forgets super().__init__() must not silently
        run with default policy. Earlier drafts patched this up
        silently; v0.3.0 fails closed."""

        class ForgetfulSigner(AlgorandSigner):
            def __init__(self):
                # Intentionally no super().__init__().
                pass

            @property
            def address(self) -> str:
                return signer_address

            def sign_transaction(self, txn):
                self.validate_transaction(txn)
                return None

        forgetful = ForgetfulSigner()
        txn = _build_payment_txn(signer_address)
        with pytest.raises(RuntimeError, match="super\\(\\).__init__"):
            forgetful.validate_transaction(txn)


# ─────────────────────────────────────────────────────────────────
# 8. SIGNATURE ASSEMBLY
# ─────────────────────────────────────────────────────────────────

class TestSignatureAssembly:
    """_assemble_signed_transaction rejects malformed signature
    lengths."""

    def test_rejects_short_signature(self, signer_address):
        from actproof.signers.google_kms import (
            _assemble_signed_transaction,
        )

        txn = _build_payment_txn(signer_address)
        with pytest.raises(RuntimeError, match="64 bytes"):
            _assemble_signed_transaction(txn, b"abc")

    def test_rejects_long_signature(self, signer_address):
        from actproof.signers.google_kms import (
            _assemble_signed_transaction,
        )

        txn = _build_payment_txn(signer_address)
        with pytest.raises(RuntimeError, match="64 bytes"):
            _assemble_signed_transaction(txn, b"x" * 65)

    def test_rejects_non_bytes_signature(self, signer_address):
        from actproof.signers.google_kms import (
            _assemble_signed_transaction,
        )

        txn = _build_payment_txn(signer_address)
        with pytest.raises(RuntimeError, match="must be bytes"):
            _assemble_signed_transaction(
                txn, "x" * 64  # type: ignore[arg-type]
            )

    def test_accepts_exactly_64_bytes(self, signer_address):
        from actproof.signers.google_kms import (
            _assemble_signed_transaction,
        )

        txn = _build_payment_txn(signer_address)
        # Returns a SignedTransaction object; we only verify no
        # exception.
        result = _assemble_signed_transaction(txn, b"\x00" * 64)
        assert result is not None


# ─────────────────────────────────────────────────────────────────
# 9. GOOGLE KMS SIGNER INTEGRITY (MOCKED CLIENT)
# ─────────────────────────────────────────────────────────────────

# We test the KMS signer's response verification with mocked
# KeyManagementServiceClient. The actual KMS API call surface is large
# and external; what matters here is that our code fails closed on
# every category of malformed response.

_REQ_NAME = (
    "projects/test/locations/europe-west4/keyRings/r/cryptoKeys/k/"
    "cryptoKeyVersions/1"
)


def _make_kms_signer_with_mock(mock_client):
    """Construct a GoogleKMSSigner with a mock client, skipping the
    optional-dependency check."""
    from actproof.signers.google_kms import GoogleKMSSigner

    return GoogleKMSSigner(_REQ_NAME, kms_client=mock_client)


@pytest.fixture
def real_pem_response():
    """A KMS get_public_key response with a real Ed25519 SPKI PEM and
    a correct CRC32C."""
    import google_crc32c
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    private_key = Ed25519PrivateKey.generate()
    pubkey = private_key.public_key()
    pem_str = pubkey.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    pem_bytes = pem_str.encode("utf-8")
    pem_crc = int(google_crc32c.value(pem_bytes))

    response = mock.MagicMock()
    response.name = _REQ_NAME
    response.pem = pem_str
    response.pem_crc32c = pem_crc
    return response


@pytest.fixture
def real_sign_response():
    """A KMS asymmetric_sign response with a valid-shape 64-byte
    signature and correct CRC32C."""
    import google_crc32c

    sig = b"\x00" * ED25519_SIG_LEN_BYTES
    sig_crc = int(google_crc32c.value(sig))

    response = mock.MagicMock()
    response.name = _REQ_NAME
    response.signature = sig
    response.signature_crc32c = sig_crc
    response.verified_data_crc32c = True
    return response


ED25519_SIG_LEN_BYTES = 64


# Optional-dependency gate: skip the KMS integrity test class entirely
# when google-cloud-kms / google-crc32c / cryptography are not
# installed. When the [gcp] optional extra is present the tests run;
# otherwise pytest reports them as skipped with a clear reason. This
# is the release-quality gate (ChatGPT v0.3.0 review Finding A).
try:
    import google.cloud.kms_v1  # noqa: F401
    import google_crc32c  # noqa: F401
    import cryptography  # noqa: F401
    _GCP_TEST_DEPS_AVAILABLE = True
    _GCP_TEST_DEPS_REASON = ""
except ImportError as _exc:
    _GCP_TEST_DEPS_AVAILABLE = False
    _GCP_TEST_DEPS_REASON = (
        f"Requires google-cloud-kms, google-crc32c, cryptography "
        f"(install with: pip install 'actproof[gcp]'). Missing: {_exc}"
    )


@pytest.mark.skipif(
    not _GCP_TEST_DEPS_AVAILABLE,
    reason=_GCP_TEST_DEPS_REASON,
)
class TestKMSSignerIntegrity:
    """Fail-closed verification of KMS response fields."""

    def test_response_name_mismatch_rejected(self, real_pem_response):
        bad_response = real_pem_response
        bad_response.name = _REQ_NAME + "/wrong"
        mock_client = mock.MagicMock()
        mock_client.get_public_key.return_value = bad_response

        s = _make_kms_signer_with_mock(mock_client)
        with pytest.raises(RuntimeError, match="response.name mismatch"):
            _ = s.address

    def test_pem_crc_mismatch_rejected(self, real_pem_response):
        bad_response = real_pem_response
        bad_response.pem_crc32c = (
            real_pem_response.pem_crc32c + 1
        ) & 0xFFFFFFFF
        mock_client = mock.MagicMock()
        mock_client.get_public_key.return_value = bad_response

        s = _make_kms_signer_with_mock(mock_client)
        with pytest.raises(RuntimeError, match="CRC32C mismatch"):
            _ = s.address

    def test_pem_crc_missing_rejected(self, real_pem_response):
        # Strip the attribute.
        bad_response = mock.MagicMock(spec=["name", "pem"])
        bad_response.name = real_pem_response.name
        bad_response.pem = real_pem_response.pem
        mock_client = mock.MagicMock()
        mock_client.get_public_key.return_value = bad_response

        s = _make_kms_signer_with_mock(mock_client)
        with pytest.raises(RuntimeError, match="missing pem_crc32c"):
            _ = s.address

    def test_sign_response_name_mismatch_rejected(
        self, signer_address, real_pem_response, real_sign_response
    ):
        bad_sign = real_sign_response
        bad_sign.name = _REQ_NAME + "/wrong"

        mock_client = mock.MagicMock()
        mock_client.get_public_key.return_value = real_pem_response
        mock_client.asymmetric_sign.return_value = bad_sign

        s = _make_kms_signer_with_mock(mock_client)
        txn = _build_payment_txn(s.address)
        with pytest.raises(
            RuntimeError, match="response.name mismatch"
        ):
            s.sign_transaction(txn)

    def test_verified_data_crc_false_rejected(
        self, real_pem_response, real_sign_response
    ):
        bad_sign = real_sign_response
        bad_sign.verified_data_crc32c = False

        mock_client = mock.MagicMock()
        mock_client.get_public_key.return_value = real_pem_response
        mock_client.asymmetric_sign.return_value = bad_sign

        s = _make_kms_signer_with_mock(mock_client)
        txn = _build_payment_txn(s.address)
        with pytest.raises(
            RuntimeError, match="verified_data_crc32c"
        ):
            s.sign_transaction(txn)

    def test_verified_data_crc_missing_rejected(
        self, real_pem_response, real_sign_response
    ):
        bad_sign = mock.MagicMock(
            spec=["name", "signature", "signature_crc32c"]
        )
        bad_sign.name = real_sign_response.name
        bad_sign.signature = real_sign_response.signature
        bad_sign.signature_crc32c = real_sign_response.signature_crc32c

        mock_client = mock.MagicMock()
        mock_client.get_public_key.return_value = real_pem_response
        mock_client.asymmetric_sign.return_value = bad_sign

        s = _make_kms_signer_with_mock(mock_client)
        txn = _build_payment_txn(s.address)
        with pytest.raises(
            RuntimeError, match="missing verified_data_crc32c"
        ):
            s.sign_transaction(txn)

    def test_signature_wrong_length_rejected(
        self, real_pem_response, real_sign_response
    ):
        import google_crc32c

        bad_sig = b"\x00" * 32  # Wrong length
        real_sign_response.signature = bad_sig
        real_sign_response.signature_crc32c = int(
            google_crc32c.value(bad_sig)
        )

        mock_client = mock.MagicMock()
        mock_client.get_public_key.return_value = real_pem_response
        mock_client.asymmetric_sign.return_value = real_sign_response

        s = _make_kms_signer_with_mock(mock_client)
        txn = _build_payment_txn(s.address)
        with pytest.raises(RuntimeError, match="64 bytes"):
            s.sign_transaction(txn)

    def test_signature_crc_mismatch_rejected(
        self, real_pem_response, real_sign_response
    ):
        real_sign_response.signature_crc32c = (
            real_sign_response.signature_crc32c + 1
        ) & 0xFFFFFFFF

        mock_client = mock.MagicMock()
        mock_client.get_public_key.return_value = real_pem_response
        mock_client.asymmetric_sign.return_value = real_sign_response

        s = _make_kms_signer_with_mock(mock_client)
        txn = _build_payment_txn(s.address)
        with pytest.raises(
            RuntimeError, match="signature CRC32C mismatch"
        ):
            s.sign_transaction(txn)

    def test_signature_crc_missing_rejected(
        self, real_pem_response, real_sign_response
    ):
        bad_sign = mock.MagicMock(
            spec=["name", "signature", "verified_data_crc32c"]
        )
        bad_sign.name = real_sign_response.name
        bad_sign.signature = real_sign_response.signature
        bad_sign.verified_data_crc32c = True

        mock_client = mock.MagicMock()
        mock_client.get_public_key.return_value = real_pem_response
        mock_client.asymmetric_sign.return_value = bad_sign

        s = _make_kms_signer_with_mock(mock_client)
        txn = _build_payment_txn(s.address)
        with pytest.raises(
            RuntimeError, match="missing signature_crc32c"
        ):
            s.sign_transaction(txn)


# ─────────────────────────────────────────────────────────────────
# 10. CRYPTOGRAPHIC EQUIVALENCE (regression: same bytes signed)
# ─────────────────────────────────────────────────────────────────

class TestCryptographicEquivalence:
    """The strict-policy MnemonicSigner in v0.3.0 produces byte-
    identical output to a v0.2.0 strict-policy MnemonicSigner for an
    actproof:j 0-ALGO self-payment. The validation tightening doesn't
    change what gets signed; it only changes what shapes are accepted.
    """

    def test_signed_bytes_match_algosdk_native(
        self, signer, signer_address
    ):
        from algosdk import mnemonic

        txn = _build_payment_txn(signer_address)
        signed = signer.sign_transaction(txn)

        # algosdk's native sign produces an identical SignedTransaction.
        pk = mnemonic.to_private_key(_VALID_TEST_MNEMONIC)
        native = txn.sign(pk)

        assert signed.signature == native.signature
