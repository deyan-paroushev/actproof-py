# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Abstract base class for Algorand signers in actproof.

The structural invariant: every signer subclass signs ONLY Algorand
payment transactions whose construction matches a strict anchoring
policy, never arbitrary bytes. This module enforces that invariant at
class-definition time via ``__init_subclass__``; a subclass that
defines a method named ``sign_bytes`` (or any similar raw-byte path)
fails to construct, and the program that tried to import it fails to
start. The desired property is "security regression cannot land latent."

Threat model
------------

actproof signers are designed for an attacker who already has the
ability to construct an ``algosdk`` ``Transaction`` and pass it to
``sign_transaction``. That is the realistic threat. An attacker who has
compromised the application above the signer can craft anything; the
signer's job is to ensure that even with that compromise, the only
on-chain effect is a benign anchoring payment, not key theft or fund
drain.

The Algorand transaction format has fields beyond ``sender``,
``receiver``, ``amt``, and ``note`` that are documented attack
vectors:

* ``rekey_to``: transfers signing authority for the account to a new
  address. After confirmation the original key no longer controls the
  account. Documented as a primary attack vector by Trail of Bits and
  Coinspect; used in the February 2023 MyAlgo wallet drain that took
  approximately 3.3 million USD across roughly 25 accounts.
* ``close_remainder_to``: drains all remaining ALGO to a specified
  address and closes the sender's account. Cannot be undone.
* ``fee``: an attacker who can set an arbitrarily high fee can burn
  ALGO through fees even on a zero-amount self-payment.
* ``group``: making a transaction part of an atomic group enables
  sandwich attacks and unintended side effects from co-grouped
  transactions.
* ``lease``: a non-empty lease blocks other transactions with the same
  lease key from confirming during the validity window; this is a
  griefing vector but rarely a value-loss vector. Still rejected for
  the same defense-in-depth reason.

A v0.2.0 signer that validated only sender, receiver, amount, and note
prefix would happily authorize a 0-ALGO self-payment carrying
``rekey_to=attacker``. v0.3.0 closes this gap with hard, non-
configurable rejection of these fields. See the SECURITY.md file for
the full advisory.

Why the strict default
----------------------

The configurable kwargs from the v0.2.0-era design space were
intentionally narrowed in v0.3.0. The two booleans
``require_self_payment`` and ``require_zero_amount`` from the original
v0.3.0 draft were removed: turning either off makes the signer accept
ApplicationCallTxn, AssetTransferTxn, KeyRegistrationTxn, and other
transaction types that are out of scope for an anchoring signer. The
v0.3.0 policy is intentionally strict: only PaymentTxn, only self-pay,
only 0 ALGO, only the configured note prefix, no rekey, no close, no
group, no lease, fee bounded.

The only configurable knob in v0.3.0 is ``allowed_note_prefixes``,
because the note prefix is the legitimate point of variation: actproof
itself uses ``b"actproof:j"``, Quoruna uses ``b"quoruna/v1:"``, other
schemes that share the substrate use their own prefix. Everything else
is the same anchoring shape.

Future versions may introduce a ``SignerPolicy`` dataclass for richer
configuration. Such a change is a v0.4.0 design discussion, not a
v0.3.0 release blocker.

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

References
----------

This module is the structural ancestor of every other signer in
actproof. The validation policy is the security ancestor of every
on-chain commitment the library produces.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Final, FrozenSet, Optional, Sequence, Tuple, Union


__all__ = [
    "AlgorandSigner",
    "FORBIDDEN_METHOD_NAMES",
    "SignerValidationError",
    "ALGORAND_MIN_FEE_MICROALGOS",
    "ALGORAND_DEFAULT_MAX_FEE_MICROALGOS",
    "ALGORAND_MAX_NOTE_BYTES",
]


# ─────────────────────────────────────────────────────────────────
# CONSTANTS
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
transaction signing path. The list is conservative: if a method name
looks like it could lure a future developer into bypassing the
transaction-only discipline, it is here.
"""


ALGORAND_MIN_FEE_MICROALGOS: Final[int] = 1000
"""Algorand protocol minimum transaction fee, in microALGOs.

Defined in go-algorand/config/consensus.go as ``f_min``. Verified from
algorandfoundation/specs/dev/ledger.md.
"""


ALGORAND_DEFAULT_MAX_FEE_MICROALGOS: Final[int] = 1000
"""Default upper bound on transaction fee enforced by validation.

Equals the protocol minimum because anchoring transactions are not
priority traffic. Callers who need to anchor during network congestion
can pass a higher value via the constructor; reviewers can audit that
explicit decision.
"""


ALGORAND_MAX_NOTE_BYTES: Final[int] = 1024
"""Algorand protocol maximum size for the transaction note field, in bytes.

Defined in go-algorand/config/consensus.go as ``MaxTxnNoteBytes``.
Verified from algorandfoundation/specs/dev/ledger.md. The signer
rejects oversized notes explicitly (fail-closed before the KMS call)
rather than waiting for protocol-level rejection at submission time.
"""


_ACTPROOF_NOTE_PREFIX: Final[bytes] = b"actproof:j"
"""The canonical actproof ARC-2 note prefix.

Used as the default for ``allowed_note_prefixes`` when no explicit
value is passed to ``AlgorandSigner.__init__``. Other anchoring schemes
that share the actproof signer infrastructure should pass their own
prefix list explicitly.
"""


# ─────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────

class SignerValidationError(ValueError):
    """Raised by ``AlgorandSigner.validate_transaction`` on policy violation.

    Subclass of ``ValueError`` so callers can catch ``ValueError`` if
    they prefer unified handling, or ``SignerValidationError``
    specifically to distinguish signer-policy errors from other input-
    validation errors.
    """


# ─────────────────────────────────────────────────────────────────
# THE ABSTRACT BASE CLASS
# ─────────────────────────────────────────────────────────────────

class AlgorandSigner(ABC):
    """Abstract Algorand transaction signer for actproof.

    Concrete subclasses provide the cryptographic backend (mnemonic,
    KMS, HSM, etc.). This base class enforces structural and policy
    rules:

    Structural:

    1. The only signing-related method exposed on the public interface
       is ``sign_transaction``, which accepts a fully-built
       ``algosdk.transaction.PaymentTxn`` object.
    2. Subclasses cannot add raw-byte signing methods. Defining any
       method whose name appears in ``FORBIDDEN_METHOD_NAMES`` raises
       ``TypeError`` at the moment the subclass is defined (via
       ``__init_subclass__``). The check walks the full MRO so that
       mixins introducing forbidden names are also rejected.

    Policy (enforced by ``validate_transaction``):

    1. The transaction must be a ``PaymentTxn`` (not Transaction,
       not AssetTransferTxn, not ApplicationCallTxn, not
       KeyRegistrationTxn).
    2. ``txn.sender`` equals ``self.address``.
    3. ``txn.receiver`` equals ``self.address`` (self-payment).
    4. ``txn.amt`` equals 0.
    5. ``txn.note`` is bytes and starts with one of the allowed
       prefixes.
    6. ``txn.rekey_to`` is unset.
    7. ``txn.close_remainder_to`` is unset.
    8. ``txn.group`` is unset.
    9. ``txn.lease`` is unset.
    10. ``txn.fee`` is between ``ALGORAND_MIN_FEE_MICROALGOS`` and
        ``self._max_fee_microalgos`` (default 1000).

    All policy checks except ``allowed_note_prefixes`` and
    ``max_fee_microalgos`` are non-configurable. They are integrity
    invariants of an anchoring signer. Configuring them off would
    convert this signer into a general-purpose Algorand signing
    adapter, which it is not.

    Subclasses MUST also implement:

    * ``address`` (property) - the 58-character base32 Algorand
      address.
    * ``sign_transaction(txn)`` - call ``self.validate_transaction(txn)``
      then return a ``SignedTransaction``.

    Subclasses MUST call ``super().__init__(...)`` from their own
    ``__init__``. If they do not, ``validate_transaction`` will raise
    ``RuntimeError`` at the first call (the silent-fallback behaviour
    from earlier drafts is gone; subclass init bugs are now loud).

    Configurable policy (since v0.3.0):

    Args:
        allowed_note_prefixes: Sequence of byte prefixes acceptable for
            ``txn.note``. The default ``None`` resolves to
            ``[b"actproof:j"]`` (the actproof ARC-2 prefix). Pass an
            explicit list to support other anchoring schemes; for
            example, Quoruna uses ``[b"quoruna/v1:"]``. As a
            convenience a single ``bytes`` value is also accepted and
            internally wrapped in a one-element list.
        max_fee_microalgos: Upper bound on ``txn.fee``. Default
            ``1000`` (the Algorand protocol minimum). Callers who need
            to anchor during network congestion can pass a higher
            value; that decision is auditable in source.

    Raises:
        ValueError: If ``allowed_note_prefixes`` is an empty sequence
            or contains any empty prefix, or if ``max_fee_microalgos``
            is below ``ALGORAND_MIN_FEE_MICROALGOS``.
        TypeError: If any element of ``allowed_note_prefixes`` is not a
            ``bytes`` or ``bytearray``, or if ``max_fee_microalgos`` is
            not an ``int``.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Reject any subclass that exposes a forbidden method name,
        including methods inherited through mixins.

        Earlier drafts checked only ``cls.__dict__``, which let a
        mixin like ``class RawSigningMixin: def sign_raw(self, b): ...``
        slip through when used as ``class BadSigner(RawSigningMixin,
        AlgorandSigner)``. This implementation walks the full method
        resolution order (excluding ``AlgorandSigner``, ``ABC``, and
        ``object``) so that any forbidden name reachable on the class
        is caught at class-definition time.

        Raises:
            TypeError: If any forbidden method name is reachable on
                the subclass via its MRO.
        """
        super().__init_subclass__(**kwargs)

        ancestors_to_skip = {AlgorandSigner, ABC, object}
        forbidden_found: set = set()
        forbidden_sources: dict = {}
        for base in cls.__mro__:
            if base in ancestors_to_skip:
                continue
            base_dict = getattr(base, "__dict__", {})
            for name in FORBIDDEN_METHOD_NAMES:
                if name in base_dict:
                    forbidden_found.add(name)
                    forbidden_sources.setdefault(name, base.__name__)

        if forbidden_found:
            sources_repr = ", ".join(
                f"{name} (from {forbidden_sources[name]})"
                for name in sorted(forbidden_found)
            )
            raise TypeError(
                f"{cls.__name__} exposes forbidden method(s) "
                f"{sorted(forbidden_found)} via its MRO. Sources: "
                f"{sources_repr}. AlgorandSigner subclasses MUST NOT "
                f"expose any raw-byte signing surface, whether defined "
                f"directly or inherited from a mixin. The only signing "
                f"method allowed on this interface is "
                f"sign_transaction(txn) -> SignedTransaction. Full "
                f"forbidden list: {sorted(FORBIDDEN_METHOD_NAMES)}."
            )

    def __init__(
        self,
        *,
        allowed_note_prefixes: Optional[
            Union[Sequence[bytes], bytes, bytearray]
        ] = None,
        max_fee_microalgos: int = ALGORAND_DEFAULT_MAX_FEE_MICROALGOS,
    ) -> None:
        """Initialise the validation policy.

        Subclasses MUST call this from their own ``__init__`` (typically
        as ``super().__init__(...)``), forwarding the policy kwargs
        they want to expose. See the class docstring for argument
        semantics.

        Raises:
            ValueError: On invalid argument values.
            TypeError: On wrong argument types.
        """
        # Normalise allowed_note_prefixes.
        # Accept a single bytes value as a convenience; wrap into a
        # one-element list before iterating.
        if allowed_note_prefixes is None:
            allowed_note_prefixes = [_ACTPROOF_NOTE_PREFIX]
        elif isinstance(allowed_note_prefixes, (bytes, bytearray)):
            allowed_note_prefixes = [bytes(allowed_note_prefixes)]

        if not allowed_note_prefixes:
            raise ValueError(
                "allowed_note_prefixes must contain at least one prefix"
            )

        normalised: list = []
        for index, prefix in enumerate(allowed_note_prefixes):
            if not isinstance(prefix, (bytes, bytearray)):
                raise TypeError(
                    f"allowed_note_prefixes[{index}] must be bytes or "
                    f"bytearray, got {type(prefix).__name__}. To allow "
                    f"a single prefix you can pass the bytes value "
                    f"directly (e.g. allowed_note_prefixes=b'quoruna/v1:')."
                )
            prefix_bytes = bytes(prefix)
            if not prefix_bytes:
                raise ValueError(
                    f"allowed_note_prefixes[{index}] is empty; "
                    f"prefixes must be non-empty bytes"
                )
            normalised.append(prefix_bytes)

        # Validate max_fee_microalgos.
        # bool is a subclass of int in Python; reject explicitly so
        # the caller cannot pass True/False here by mistake.
        if isinstance(max_fee_microalgos, bool) or not isinstance(
            max_fee_microalgos, int
        ):
            raise TypeError(
                f"max_fee_microalgos must be int, got "
                f"{type(max_fee_microalgos).__name__}"
            )
        if max_fee_microalgos < ALGORAND_MIN_FEE_MICROALGOS:
            raise ValueError(
                f"max_fee_microalgos ({max_fee_microalgos}) must be "
                f">= Algorand protocol minimum "
                f"({ALGORAND_MIN_FEE_MICROALGOS})"
            )

        self._allowed_note_prefixes: Tuple[bytes, ...] = tuple(normalised)
        self._max_fee_microalgos: int = max_fee_microalgos

    @property
    @abstractmethod
    def address(self) -> str:
        """The 58-character base32 Algorand address this signer signs for.

        Implementations may cache lazily (first access triggers a key
        derivation or remote call; subsequent accesses return the
        cached value).
        """
        ...

    @abstractmethod
    def sign_transaction(self, txn: Any) -> Any:
        """Sign an Algorand payment transaction.

        Concrete implementations MUST call
        ``self.validate_transaction(txn)`` before invoking the
        underlying signing backend.

        Args:
            txn: An ``algosdk.transaction.PaymentTxn``, typically
                built by ``actproof.anchor.build_transaction``.

        Returns:
            An ``algosdk.transaction.SignedTransaction`` ready for
            submission to algod.

        Raises:
            SignerValidationError: If the transaction violates the
                signing policy.
            RuntimeError: If the underlying signing backend returns
                an error, or if the subclass failed to call
                ``super().__init__()``.
        """
        ...

    # ─────────────────────────────────────────────────────────────
    # DEFAULT VALIDATION (subclasses MUST call this before signing)
    # ─────────────────────────────────────────────────────────────

    def validate_transaction(self, txn: Any) -> None:
        """Validate an Algorand transaction against the configured policy.

        See the class docstring for the full list of checks. Subclasses
        should call this from inside ``sign_transaction`` before
        invoking the underlying signing backend; they can extend by
        overriding (call ``super().validate_transaction(txn)`` first,
        then add extra checks).

        Args:
            txn: The transaction to validate.

        Raises:
            SignerValidationError: On the first policy violation.
            RuntimeError: If the subclass failed to call
                ``super().__init__()`` (policy attributes are missing).
        """
        # Fail-closed check that the subclass properly initialised
        # the policy. Earlier drafts silently set defaults here; that
        # masked exactly the bug class we want to catch (a custom
        # subclass that forgot super().__init__() and is silently
        # using a different policy than the caller believed).
        # ChatGPT v0.3.0 review Finding B: check both required policy
        # attributes, not just one.
        missing_attrs = [
            name
            for name in ("_allowed_note_prefixes", "_max_fee_microalgos")
            if not hasattr(self, name)
        ]
        if missing_attrs:
            raise RuntimeError(
                f"{type(self).__name__}.validate_transaction was "
                f"called before AlgorandSigner.__init__ ran. Missing "
                f"policy attributes: {missing_attrs!r}. Every "
                f"subclass MUST call super().__init__(...) from its "
                f"own __init__ to set up the validation policy."
            )

        # Import algosdk types dynamically so the module is importable
        # even if py-algorand-sdk has a transitive problem.
        try:
            from algosdk.transaction import PaymentTxn
        except Exception as exc:  # noqa: BLE001
            raise SignerValidationError(
                f"py-algorand-sdk not importable: {exc}"
            ) from exc

        # Strict type check. The actproof anchoring shape is a
        # 0-ALGO self-payment with a tagged note. Other transaction
        # classes (AssetTransferTxn, ApplicationCallTxn,
        # KeyRegistrationTxn, AssetConfigTxn, AssetFreezeTxn) have
        # different semantics and are out of scope for this signer.
        if not isinstance(txn, PaymentTxn):
            raise SignerValidationError(
                f"Expected PaymentTxn, got {type(txn).__name__}. "
                f"actproof signers accept only payment transactions; "
                f"other transaction types must use a different signing "
                f"path."
            )

        # The sender must match this signer's address.
        # This check is the fundamental integrity invariant: a signer
        # only signs for itself.
        if getattr(txn, "sender", None) != self.address:
            raise SignerValidationError(
                f"Transaction sender {getattr(txn, 'sender', None)!r} "
                f"does not match signer address {self.address!r}. The "
                f"signer must own the sender's private key."
            )

        # Self-payment: receiver must equal sender.
        if getattr(txn, "receiver", None) != self.address:
            raise SignerValidationError(
                f"Transaction receiver "
                f"{getattr(txn, 'receiver', None)!r} does not equal "
                f"sender {self.address!r}. actproof anchoring is a "
                f"0-ALGO self-payment with a tagged note."
            )

        # Zero amount.
        amount = getattr(txn, "amt", None)
        if amount != 0:
            raise SignerValidationError(
                f"Transaction amount must be 0, got {amount!r}. "
                f"actproof anchoring transactions carry no value."
            )

        # No rekey. Documented attack vector: setting rekey_to on any
        # transaction from this account transfers signing authority to
        # the new address. The original key no longer controls the
        # account after confirmation.
        rekey_to = getattr(txn, "rekey_to", None)
        if rekey_to:
            raise SignerValidationError(
                f"Transaction rekey_to is set ({rekey_to!r}). actproof "
                f"signers never sign rekey-to transactions; this would "
                f"transfer signing authority of the account to a "
                f"different address."
            )

        # No close_remainder_to. Documented attack vector: drains all
        # remaining ALGO to a specified address and closes the
        # account.
        close_to = getattr(txn, "close_remainder_to", None)
        if close_to:
            raise SignerValidationError(
                f"Transaction close_remainder_to is set ({close_to!r}). "
                f"actproof signers never sign close-out transactions; "
                f"this would drain the account's remaining balance to "
                f"the specified address and close the account."
            )

        # No group. Grouped transactions enable sandwich attacks and
        # unintended side effects from co-grouped transactions; an
        # anchoring transaction has no business being part of a group.
        group = getattr(txn, "group", None)
        if group:
            raise SignerValidationError(
                f"Transaction group is set ({group!r}). actproof "
                f"signers never sign grouped transactions; anchoring "
                f"transactions are atomic in themselves and do not "
                f"belong to atomic groups."
            )

        # No lease. A lease is a 32-byte value that blocks other
        # transactions with the same sender+lease from confirming
        # during the validity window. Mostly a griefing vector, but
        # rejected here for the same defense-in-depth reason as the
        # other fields: an anchoring transaction has no legitimate use
        # for a lease.
        lease = getattr(txn, "lease", None)
        if lease:
            raise SignerValidationError(
                f"Transaction lease is set. actproof signers never "
                f"sign lease transactions."
            )

        # Fee bounded.
        fee = getattr(txn, "fee", None)
        if fee is None or not isinstance(fee, int) or isinstance(fee, bool):
            raise SignerValidationError(
                f"Transaction fee must be an int, got {fee!r} "
                f"({type(fee).__name__})."
            )
        if fee < ALGORAND_MIN_FEE_MICROALGOS:
            raise SignerValidationError(
                f"Transaction fee {fee} is below Algorand protocol "
                f"minimum {ALGORAND_MIN_FEE_MICROALGOS} microALGOs."
            )
        if fee > self._max_fee_microalgos:
            raise SignerValidationError(
                f"Transaction fee {fee} exceeds configured maximum "
                f"{self._max_fee_microalgos} microALGOs. If the "
                f"network is congested and you need to anchor at a "
                f"higher fee, construct the signer with "
                f"max_fee_microalgos=<higher>."
            )

        # Note must be bytes-like.
        note = getattr(txn, "note", None)
        if not isinstance(note, (bytes, bytearray)):
            raise SignerValidationError(
                f"Transaction note must be bytes, got "
                f"{type(note).__name__ if note is not None else 'None'}."
            )

        note_bytes = bytes(note)

        # Explicit size check: fail before KMS signs an oversized note
        # rather than waiting for protocol-level rejection at
        # submission time. ChatGPT v0.3.0 review Finding C.
        if len(note_bytes) > ALGORAND_MAX_NOTE_BYTES:
            raise SignerValidationError(
                f"Transaction note is {len(note_bytes)} bytes; "
                f"Algorand protocol maximum is "
                f"{ALGORAND_MAX_NOTE_BYTES} bytes."
            )

        # Note must start with at least one of the allowed prefixes.
        if not any(
            note_bytes.startswith(prefix)
            for prefix in self._allowed_note_prefixes
        ):
            allowed_repr = ", ".join(
                repr(p) for p in self._allowed_note_prefixes
            )
            raise SignerValidationError(
                f"Transaction note must start with one of the allowed "
                f"prefixes ({allowed_repr}). Got prefix "
                f"{note_bytes[:32]!r}. Pass allowed_note_prefixes at "
                f"construction to support additional prefixes."
            )
