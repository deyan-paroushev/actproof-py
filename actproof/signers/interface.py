# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Abstract base class for Algorand signers in actproof.

The structural invariant: every signer subclass signs ONLY Algorand
transactions, never arbitrary bytes. This module enforces that invariant
at class-definition time via ``__init_subclass__``; a subclass that
defines a method named ``sign_bytes`` (or any similar raw-byte path)
fails to construct, and the program that tried to import it fails to
start. The desired property is "security regression cannot land latent."

Why this matters
----------------

If the Ed25519 anchoring key is held in HSM-backed KMS, the operator
(the platform, the SRE on call) cannot extract the key material. KMS
itself, however, will happily sign any byte sequence if asked. The
defense-in-depth move is that the signer adapter, the only piece of
actproof code that holds a reference to the KMS client, MUST NEVER
expose a code path that calls the underlying sign with anything other
than a properly-built Algorand transaction.

A future refactor that adds ``sign_bytes`` because "it would be useful
for one thing" would silently expose every Algorand key the signer
holds. ``__init_subclass__`` makes that refactor impossible: the
module that defines the offending subclass fails to import, the test
suite fails red, the CI fails the deploy. The error is loud and
correct, instead of quiet and dangerous.

Concrete subclasses
-------------------

* ``MnemonicSigner`` (testing only) holds a 25-word mnemonic in process
  memory.
* ``GoogleKMSSigner`` (production for GCP users) holds a reference to a
  KMS key version resource path; the key itself stays in the HSM.
* User-supplied subclasses for AWS CloudHSM, Azure Key Vault, HashiCorp
  Vault, etc. As long as the subclass extends ``AlgorandSigner`` and
  implements ``address`` plus ``sign_transaction``, it satisfies the
  contract.

Validation
----------

The ABC also provides ``validate_transaction(txn)`` which concrete
subclasses MUST call before signing. The default validation checks:

1. ``txn`` is an ``algosdk.transaction.Transaction`` instance.
2. ``txn.sender`` equals ``self.address``.
3. ``txn.receiver`` equals ``txn.sender`` (0-Algo self-payment pattern).
4. ``txn.amt`` equals zero.
5. ``txn.note`` is bytes and starts with the actproof ARC-2 prefix
   (``b"actproof:j"``).

Subclasses can override ``validate_transaction`` to add additional
checks (fee bounds, network ID matching, etc.); they should ``super()``
into the base check or duplicate its logic.

References
----------

This module is the structural ancestor of every other signer in
actproof. The validation policy is the security ancestor of every
on-chain commitment the library produces.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Final, FrozenSet


__all__ = [
    "AlgorandSigner",
    "FORBIDDEN_METHOD_NAMES",
    "SignerValidationError",
]


# ─────────────────────────────────────────────────────────────────
# FORBIDDEN METHOD NAMES
# ─────────────────────────────────────────────────────────────────

FORBIDDEN_METHOD_NAMES: Final[FrozenSet[str]] = frozenset({
    "sign_bytes",
    "sign_data",
    "sign_raw",
    "sign_message",
    "sign_digest",
    "sign",
    "raw_sign",
    "asymmetric_sign",
})
"""Method names that ``AlgorandSigner`` subclasses MUST NOT define.

Each represents a way to expose raw-byte signing on top of the typed
transaction signing path. The list is conservative: if a method name looks
like it could lure a future developer into bypassing the transaction-only
discipline, it is here.
"""


# ─────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────

class SignerValidationError(ValueError):
    """Raised by ``AlgorandSigner.validate_transaction`` on policy violation.

    Subclass of ``ValueError`` so callers can catch ``ValueError`` if they
    prefer unified handling, or ``SignerValidationError`` specifically to
    distinguish signer-policy errors from other input-validation errors.
    """


# ─────────────────────────────────────────────────────────────────
# CONSTANTS USED IN DEFAULT VALIDATION
# ─────────────────────────────────────────────────────────────────

_ACTPROOF_NOTE_PREFIX: Final[bytes] = b"actproof:j"


# ─────────────────────────────────────────────────────────────────
# THE ABSTRACT BASE CLASS
# ─────────────────────────────────────────────────────────────────

class AlgorandSigner(ABC):
    """Abstract Algorand transaction signer for actproof.

    Concrete subclasses provide the cryptographic backend (mnemonic, KMS,
    HSM, etc.). This base class enforces two structural rules at the level
    of the class hierarchy:

    1. The only signing-related method exposed on the public interface
       is ``sign_transaction``, which accepts a fully-built
       ``algosdk.transaction.Transaction`` object.
    2. Subclasses cannot add raw-byte signing methods. Defining any
       method whose name appears in ``FORBIDDEN_METHOD_NAMES`` raises
       ``TypeError`` at the moment the subclass is defined (via
       ``__init_subclass__``). Adding such a method later in a refactor
       causes the import of the module to fail, which is the desired
       behaviour: the program does not start, rather than the security
       regression sitting latent.

    Subclasses MUST also implement:

    * ``address`` (property) - the 58-character base32 Algorand address.
    * ``sign_transaction(txn)`` - validate the transaction (via
      ``self.validate_transaction(txn)`` or equivalent) and return a
      ``SignedTransaction``.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Reject any subclass that defines a forbidden method name.

        Python calls this hook at the moment a subclass is created,
        BEFORE any code that imports the subclass can use it. The check
        inspects ``cls.__dict__`` (methods defined directly on this
        subclass), not ``dir(cls)`` (which would also include inherited
        methods). A subclass cannot accidentally inherit a forbidden
        method from somewhere else and pass the check; the check is
        about what THIS specific subclass introduces.

        Raises:
            TypeError: If any forbidden method name appears in the
                subclass's own ``__dict__``. The error message names
                every forbidden method actually found, plus lists the
                full forbidden set so the developer can immediately see
                which name they used and what the alternatives are.
        """
        super().__init_subclass__(**kwargs)
        forbidden_in_subclass = FORBIDDEN_METHOD_NAMES & set(cls.__dict__.keys())
        if forbidden_in_subclass:
            raise TypeError(
                f"{cls.__name__} defines forbidden method(s) "
                f"{sorted(forbidden_in_subclass)}. AlgorandSigner subclasses "
                f"MUST NOT expose any raw-byte signing surface. The only "
                f"signing method allowed on this interface is "
                f"sign_transaction(txn) -> SignedTransaction. "
                f"Complete list of forbidden method names: "
                f"{sorted(FORBIDDEN_METHOD_NAMES)}."
            )

    @property
    @abstractmethod
    def address(self) -> str:
        """The 58-character base32 Algorand address this signer signs for.

        Implementations may cache lazily (the first access triggers a key
        derivation or remote call; subsequent accesses return the cached
        value).
        """
        ...

    @abstractmethod
    def sign_transaction(self, txn: Any) -> Any:
        """Sign an Algorand transaction.

        Concrete implementations MUST call ``self.validate_transaction(txn)``
        (or implement equivalent checks) before invoking the underlying
        signing backend.

        Args:
            txn: An ``algosdk.transaction.Transaction``, typically a
                ``PaymentTxn`` built by ``actproof.anchor.build_transaction``.

        Returns:
            An ``algosdk.transaction.SignedTransaction`` ready for
            submission to algod.

        Raises:
            SignerValidationError: If the transaction violates the signing
                policy (wrong sender, non-zero amount, missing or wrong
                note prefix).
            RuntimeError: If the underlying signing backend returns an
                error.
        """
        ...

    # ─────────────────────────────────────────────────────────────
    # DEFAULT VALIDATION (subclasses MUST call this before signing)
    # ─────────────────────────────────────────────────────────────

    def validate_transaction(self, txn: Any) -> None:
        """Validate an Algorand transaction against the actproof policy.

        Concrete subclasses call this from inside ``sign_transaction``
        before invoking the underlying signing backend. The default checks:

        1. ``txn`` is an ``algosdk.transaction.Transaction`` instance.
        2. ``txn.sender`` equals ``self.address``.
        3. ``txn.receiver`` equals ``txn.sender`` (0-Algo self-payment).
        4. ``txn.amt`` equals 0.
        5. ``txn.note`` is bytes and starts with ``b"actproof:j"``.

        Subclasses can extend by overriding this method (call ``super()``
        first, then add extra checks).

        Args:
            txn: The transaction to validate.

        Raises:
            SignerValidationError: On the first policy violation found.
        """
        # We avoid importing algosdk at module top to keep this file
        # importable even if py-algorand-sdk has a transitive problem.
        # The isinstance check happens dynamically.
        try:
            from algosdk.transaction import Transaction
        except Exception as exc:  # noqa: BLE001
            raise SignerValidationError(
                f"py-algorand-sdk not importable: {exc}"
            ) from exc

        if not isinstance(txn, Transaction):
            raise SignerValidationError(
                f"Expected algosdk Transaction, got {type(txn).__name__}"
            )

        # The sender must match this signer's address.
        if getattr(txn, "sender", None) != self.address:
            raise SignerValidationError(
                f"Transaction sender {getattr(txn, 'sender', None)!r} does "
                f"not match signer address {self.address!r}. The signer "
                f"must own the sender's private key."
            )

        # Self-payment pattern: receiver equals sender.
        if getattr(txn, "receiver", None) != self.address:
            raise SignerValidationError(
                f"Transaction receiver {getattr(txn, 'receiver', None)!r} "
                f"does not equal sender (signer address {self.address!r}). "
                f"actproof anchors use the 0-Algo self-payment pattern."
            )

        # Zero-value: actproof anchors never transfer Algos.
        amount = getattr(txn, "amt", None)
        if amount != 0:
            raise SignerValidationError(
                f"Transaction amount must be 0, got {amount}. actproof "
                f"anchors are 0-Algo self-payments; the note field carries "
                f"the commitment, not a value transfer."
            )

        # Note must start with the ARC-2 prefix.
        note = getattr(txn, "note", None)
        if not isinstance(note, (bytes, bytearray)):
            raise SignerValidationError(
                f"Transaction note must be bytes, got "
                f"{type(note).__name__ if note is not None else 'None'}."
            )
        if not note.startswith(_ACTPROOF_NOTE_PREFIX):
            raise SignerValidationError(
                f"Transaction note must start with the actproof ARC-2 "
                f"prefix {_ACTPROOF_NOTE_PREFIX!r}. Got prefix "
                f"{bytes(note)[:32]!r}."
            )
