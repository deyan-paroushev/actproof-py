# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Signer implementations for actproof anchoring.

A signer holds an Algorand Ed25519 private key (or a reference to one
in external custody) and signs transactions built by
``actproof.anchor``. Every concrete signer subclasses
``AlgorandSigner`` so the contract ("transactions only, never raw
bytes") is structurally enforced.

What's in this package
----------------------

* ``AlgorandSigner`` (in ``interface.py``) - the abstract base class.
  Concrete signers MUST subclass it. ``__init_subclass__`` raises
  ``TypeError`` if a subclass exposes any method whose name suggests
  raw-byte signing, whether defined directly or inherited via a
  mixin (the full forbidden-name list is the module constant
  ``FORBIDDEN_METHOD_NAMES``).

* ``MnemonicSigner`` (in ``mnemonic.py``) - holds an Algorand
  mnemonic in process memory and signs locally. **Testing only.**
  Emits a loud ``UserWarning`` on construction. Production keys
  belong in an HSM-grade KMS.

* ``GoogleKMSSigner`` (in ``google_kms.py``) - production-grade
  signer for users who hold their Ed25519 key in Google Cloud KMS.
  KMS supports Ed25519 natively via the ``EC_SIGN_ED25519``
  algorithm; the private key never leaves the KMS service. For
  HSM-residency guarantees, use a key with protection level ``HSM``
  or ``HSM_SINGLE_TENANT``. Requires the optional ``[gcp]`` install
  extra (``pip install 'actproof[gcp]'``).

What's NOT in this package
--------------------------

AWS KMS does not support Ed25519 directly (only RSA and SEC ECC
curves P-256/P-384/P-521 plus secp256k1). AWS users with HSM-grade
requirements need either AWS CloudHSM (where Ed25519 is supported)
or an envelope-encryption pattern. Either path is out-of-scope here;
AWS users implement their own ``AlgorandSigner`` subclass against
their preferred backend.

Azure Key Vault and HashiCorp Vault similarly: write your own
subclass against their SDKs. The ABC's enforcement does the security
work regardless of backend.

Example
-------

::

    from actproof.signers import MnemonicSigner
    from actproof import anchor_manifest, AnchorMode

    signer = MnemonicSigner("...25 words separated by spaces...")
    record = anchor_manifest(
        manifest_hash,
        signer=signer,
        mode=AnchorMode.DEMO,  # testnet
    )

For production with GCP KMS::

    from actproof.signers import GoogleKMSSigner

    signer = GoogleKMSSigner(
        kms_resource_name=(
            "projects/my-project/locations/europe-west4/"
            "keyRings/anchoring/cryptoKeys/anchor-signer-v1/"
            "cryptoKeyVersions/1"
        ),
    )
"""

from __future__ import annotations

from actproof.signers.interface import (
    ALGORAND_DEFAULT_MAX_FEE_MICROALGOS,
    ALGORAND_MAX_NOTE_BYTES,
    ALGORAND_MIN_FEE_MICROALGOS,
    FORBIDDEN_METHOD_NAMES,
    AlgorandSigner,
    SignerValidationError,
)
from actproof.signers.mnemonic import MnemonicSigner

# Optional: GoogleKMSSigner requires google-cloud-kms. Import is
# best-effort; if the GCP libraries are not installed, expose a stub
# class that raises a clear RuntimeError on instantiation rather than
# silently substituting None. ChatGPT v0.3.0 review Finding 5: the
# previous None fallback caused
# ``TypeError: 'NoneType' object is not callable`` for library users,
# which is poor UX.
try:
    from actproof.signers.google_kms import GoogleKMSSigner
    _GOOGLE_KMS_AVAILABLE: bool = True
    _GOOGLE_KMS_ERROR: str | None = None
except Exception as exc:  # noqa: BLE001
    _GOOGLE_KMS_AVAILABLE = False
    _GOOGLE_KMS_ERROR = str(exc)

    class GoogleKMSSigner(AlgorandSigner):  # type: ignore[no-redef]
        """Stub raised when ``actproof[gcp]`` is not installed.

        Instantiating this stub fails fast with a clear installation
        hint. The real ``GoogleKMSSigner`` is imported from
        ``actproof.signers.google_kms`` when the optional dependencies
        are present.
        """

        def __init__(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError(
                "GoogleKMSSigner requires the optional GCP "
                "dependencies (google-cloud-kms, google-crc32c, "
                "cryptography). Install them with:\n\n"
                "    pip install 'actproof[gcp]'\n\n"
                f"Underlying import error: {_GOOGLE_KMS_ERROR}"
            )

        @property
        def address(self) -> str:  # pragma: no cover
            raise RuntimeError("GoogleKMSSigner stub has no address.")

        def sign_transaction(self, txn: object) -> object:  # pragma: no cover
            raise RuntimeError("GoogleKMSSigner stub cannot sign.")


__all__ = [
    "AlgorandSigner",
    "MnemonicSigner",
    "GoogleKMSSigner",
    "FORBIDDEN_METHOD_NAMES",
    "SignerValidationError",
    "ALGORAND_MIN_FEE_MICROALGOS",
    "ALGORAND_DEFAULT_MAX_FEE_MICROALGOS",
    "ALGORAND_MAX_NOTE_BYTES",
]
