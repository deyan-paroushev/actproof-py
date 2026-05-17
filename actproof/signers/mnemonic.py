# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
MnemonicSigner: Algorand signer that holds a mnemonic in process
memory.

**For testing only.**

The 25-word Algorand mnemonic encodes the full Ed25519 private key.
Once the mnemonic is in process memory, the private key is in process
memory. Anything that can read process memory (a debugger, a crash
dump, a core file, a kernel exploit, another process running as the
same user) can extract the key. Production anchoring keys belong in a
hardware security module: AWS CloudHSM, GCP KMS, Azure Key Vault,
HashiCorp Vault, YubiHSM, or similar.

This signer is appropriate for:

* Unit tests and CI smoke tests.
* Testnet experimentation during early development.
* Local proof-of-concept work.
* Documentation examples.

It is NOT appropriate for:

* Mainnet anchoring of compliance evidence.
* Any deployment where the signing key has material economic or legal
  consequences attached.

On construction, the signer emits a ``UserWarning`` to make the
testing-only stance loud and discoverable. Tests that legitimately use
the mnemonic signer should suppress the warning with
``warnings.simplefilter`` or ``warnings.catch_warnings``; the warning
is the signal, not the noise.

Configurable policy (since v0.3.0)
----------------------------------

The constructor accepts and forwards the validation-policy kwargs
defined on ``AlgorandSigner`` (``allowed_note_prefixes``,
``max_fee_microalgos``). Defaults match the strict actproof policy:
0-ALGO self-payment with an ``actproof:j`` note prefix, fee at the
Algorand minimum (1000 microALGOs), no rekey, no close, no group, no
lease.

Example
-------

::

    import warnings
    from actproof.signers import MnemonicSigner

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        signer = MnemonicSigner(
            "abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon"
        )

Custom policy example::

    quoruna_signer = MnemonicSigner(
        mnemonic_phrase,
        allowed_note_prefixes=b"quoruna/v1:",
    )
"""

from __future__ import annotations

import warnings
from typing import Any, Optional, Sequence, Union

from actproof.signers.interface import (
    ALGORAND_DEFAULT_MAX_FEE_MICROALGOS,
    AlgorandSigner,
    SignerValidationError,
)


__all__ = ["MnemonicSigner"]


_MNEMONIC_WARNING_MESSAGE = (
    "MnemonicSigner holds the Algorand private key in process memory "
    "and is for testing only. Do NOT use for production anchoring. "
    "Production keys belong in a hardware security module (AWS "
    "CloudHSM, GCP KMS, Azure Key Vault, HashiCorp Vault, YubiHSM, or "
    "similar)."
)


class MnemonicSigner(AlgorandSigner):
    """Algorand signer backed by an in-process mnemonic.

    Holds the derived private key in process memory. **Testing only;**
    see module docstring for the security caveats.

    The address is derived from the mnemonic at construction time.
    Both the private key and the address are cached for the lifetime
    of the signer instance; there is no remote call.

    Args:
        mnemonic_phrase: A 25-word Algorand mnemonic, words separated
            by single spaces. Extra whitespace is stripped.
        allowed_note_prefixes: See ``AlgorandSigner``. Default
            ``[b"actproof:j"]``. A single ``bytes`` value is also
            accepted.
        max_fee_microalgos: See ``AlgorandSigner``. Default ``1000``.

    Raises:
        ValueError: If the mnemonic is empty, not 25 words, or fails
            algosdk's checksum. Also raised if
            ``allowed_note_prefixes`` is empty or contains an empty
            prefix, or if ``max_fee_microalgos`` is below the protocol
            minimum.
        TypeError: If ``allowed_note_prefixes`` contains a non-bytes
            element, or if ``max_fee_microalgos`` is not an int.
        RuntimeError: If py-algorand-sdk is not importable.
    """

    def __init__(
        self,
        mnemonic_phrase: str,
        *,
        allowed_note_prefixes: Optional[
            Union[Sequence[bytes], bytes, bytearray]
        ] = None,
        max_fee_microalgos: int = ALGORAND_DEFAULT_MAX_FEE_MICROALGOS,
    ) -> None:
        # Initialise the policy attributes on AlgorandSigner first.
        # Any ValueError/TypeError on the policy kwargs is raised
        # before we touch the mnemonic, so an invalid policy doesn't
        # waste the checksum validation cycle.
        super().__init__(
            allowed_note_prefixes=allowed_note_prefixes,
            max_fee_microalgos=max_fee_microalgos,
        )

        try:
            from algosdk import account, mnemonic
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"py-algorand-sdk not importable: {exc}. "
                f"Install with: pip install 'py-algorand-sdk>=2.6.1'"
            ) from exc

        if not mnemonic_phrase or not mnemonic_phrase.strip():
            raise ValueError("Mnemonic phrase is empty")

        words = mnemonic_phrase.strip().split()
        if len(words) != 25:
            raise ValueError(
                f"Algorand mnemonics are 25 words; got {len(words)}"
            )

        try:
            self._private_key: str = mnemonic.to_private_key(" ".join(words))
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                f"Cannot derive private key from mnemonic: {exc}. "
                f"Check the mnemonic words and checksum word."
            ) from exc

        self._address: str = account.address_from_private_key(self._private_key)

        # Loud warning on every instantiation. This is the security
        # signal.
        warnings.warn(
            _MNEMONIC_WARNING_MESSAGE,
            category=UserWarning,
            stacklevel=2,
        )

    @property
    def address(self) -> str:
        """The signer's 58-character Algorand address."""
        return self._address

    def sign_transaction(self, txn: Any) -> Any:
        """Validate the transaction then sign it with the held private
        key.

        Args:
            txn: An ``algosdk.transaction.PaymentTxn`` to sign.

        Returns:
            An ``algosdk.transaction.SignedTransaction``.

        Raises:
            SignerValidationError: If the transaction violates the
                signing policy (see
                ``AlgorandSigner.validate_transaction``).
        """
        self.validate_transaction(txn)
        try:
            return txn.sign(self._private_key)
        except SignerValidationError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"algosdk transaction signing failed: {exc}"
            ) from exc
