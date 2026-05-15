# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
MnemonicSigner: Algorand signer that holds a mnemonic in process memory.

**For testing only.**

The 25-word Algorand mnemonic encodes the full Ed25519 private key. Once
the mnemonic is in process memory, the private key is in process memory.
Anything that can read process memory (a debugger, a crash dump, a core
file, a kernel exploit, another process running as the same user) can
extract the key. Production anchoring keys belong in a hardware security
module: AWS CloudHSM, GCP KMS, Azure Key Vault, HashiCorp Vault, YubiHSM,
or similar.

This signer is appropriate for:

* Unit tests and CI smoke tests.
* Testnet experimentation during early development.
* Local proof-of-concept work.
* Documentation examples.

It is NOT appropriate for:

* Mainnet anchoring of compliance evidence.
* Any deployment where the signing key has material economic or legal
  consequences attached.

On construction, the signer emits a ``UserWarning`` to make the testing-
only stance loud and discoverable. Tests that legitimately use the
mnemonic signer should suppress the warning with ``warnings.simplefilter``
or ``warnings.catch_warnings``; the warning is the signal, not the noise.

Example
-------

::

    import warnings
    from openproof.signers import MnemonicSigner

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        signer = MnemonicSigner(
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon"
        )
        # ... use signer for testnet anchoring
"""

from __future__ import annotations

import warnings
from typing import Any

from openproof.signers.interface import AlgorandSigner, SignerValidationError


__all__ = ["MnemonicSigner"]


_MNEMONIC_WARNING_MESSAGE = (
    "MnemonicSigner holds the Algorand private key in process memory and "
    "is for testing only. Do NOT use for production anchoring. Production "
    "keys belong in a hardware security module (AWS CloudHSM, GCP KMS, "
    "Azure Key Vault, HashiCorp Vault, YubiHSM, or similar)."
)


class MnemonicSigner(AlgorandSigner):
    """Algorand signer backed by an in-process mnemonic.

    Holds the derived private key in process memory. **Testing only;**
    see module docstring for the security caveats.

    The address is derived from the mnemonic at construction time. Both
    the private key and the address are cached for the lifetime of the
    signer instance; there is no remote call.

    Args:
        mnemonic_phrase: A 25-word Algorand mnemonic, words separated by
            single spaces. Extra whitespace is stripped.

    Raises:
        ValueError: If the mnemonic is empty, not 25 words, or fails
            algosdk's checksum.
        RuntimeError: If py-algorand-sdk is not importable.
    """

    def __init__(self, mnemonic_phrase: str) -> None:
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

        # Loud warning on every instantiation. This is the security signal.
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
        """Validate the transaction then sign it with the held private key.

        Args:
            txn: An ``algosdk.transaction.Transaction`` to sign.

        Returns:
            An ``algosdk.transaction.SignedTransaction``.

        Raises:
            SignerValidationError: If the transaction violates the signing
                policy (see ``AlgorandSigner.validate_transaction``).
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
