# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
GoogleKMSSigner: Algorand signer backed by Google Cloud KMS.

The private Ed25519 key never leaves the GCP HSM. This signer holds a
reference to the key version resource path and uses the KMS client to:

1. Fetch the SPKI-PEM-encoded Ed25519 public key (once, lazily, on first
   ``address`` access).
2. Derive the 58-character Algorand address from the raw 32-byte public key.
3. Invoke ``asymmetric_sign`` for each transaction signature.

The key never exits KMS; the operator cannot extract it. This is the
defense-in-depth posture actproof recommends for production anchoring
of compliance evidence.

Optional dependency
-------------------

This module requires the ``[gcp]`` install extra::

    pip install 'actproof[gcp]'

which pulls in ``google-cloud-kms`` (the KMS client) and ``google-crc32c``
(integrity checking on KMS request/response). If those packages are not
installed, instantiating ``GoogleKMSSigner`` raises ``RuntimeError`` with
the installation command.

Other clouds (AWS, Azure, Vault)
--------------------------------

AWS KMS does NOT support Ed25519 directly (only RSA and SEC ECC curves
P-256/P-384/P-521 plus secp256k1). AWS users with HSM-grade requirements
need either AWS CloudHSM (where Ed25519 is supported) or an envelope-
encryption pattern. Either path is out-of-scope for actproof's bundled
signers; AWS users write their own ``AlgorandSigner`` subclass against
their preferred backend.

Azure Key Vault and HashiCorp Vault: write your own subclass against
their SDKs. The ``AlgorandSigner`` ABC's enforcement does the security
work regardless of backend.

Why ``data`` and not ``digest`` for Ed25519
-------------------------------------------

The KMS ``AsymmetricSignRequest`` has both a ``data`` field and a
``digest`` field. For RSA and ECDSA signing modes, callers typically
pre-hash and pass the digest. For Ed25519 in PureEdDSA mode, the
algorithm itself does the hashing as part of the signing operation, so
callers MUST pass the raw bytes via the ``data`` field. Passing
``digest`` for an Ed25519 key returns ``INVALID_ARGUMENT`` from KMS.
"""

from __future__ import annotations

import base64
import warnings
from typing import Any, Optional

from actproof.signers.interface import AlgorandSigner, SignerValidationError


__all__ = ["GoogleKMSSigner"]


# ─────────────────────────────────────────────────────────────────
# OPTIONAL IMPORTS: google-cloud-kms and google-crc32c
# ─────────────────────────────────────────────────────────────────

_INSTALL_HINT = (
    "Install with: pip install 'actproof[gcp]' "
    "(adds google-cloud-kms and google-crc32c)."
)

try:
    from google.cloud import kms_v1 as _kms_v1
    _KMS_AVAILABLE: bool = True
    _KMS_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    _KMS_AVAILABLE = False
    _KMS_ERROR = str(exc)
    _kms_v1 = None  # type: ignore[assignment,misc]

try:
    import google_crc32c as _google_crc32c
    _CRC_AVAILABLE: bool = True
    _CRC_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    _CRC_AVAILABLE = False
    _CRC_ERROR = str(exc)
    _google_crc32c = None  # type: ignore[assignment,misc]


# ─────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────

ALGORAND_SIGN_PREFIX: bytes = b"TX"
"""Algorand's canonical signing prefix. Every Ed25519 transaction signature
covers ``ALGORAND_SIGN_PREFIX + msgpack_encode(txn)``."""

ED25519_PUBKEY_LEN: int = 32
"""Ed25519 raw public key size in bytes."""


# ─────────────────────────────────────────────────────────────────
# THE SIGNER CLASS
# ─────────────────────────────────────────────────────────────────

class GoogleKMSSigner(AlgorandSigner):
    """Algorand signer backed by Google Cloud KMS Ed25519 keys.

    Args:
        kms_resource_name: Full resource path to the KMS Ed25519 key
            version. Example: ``projects/actproof-prod/locations/
            europe-west4/keyRings/anchoring/cryptoKeys/anchor-signer-v1/
            cryptoKeyVersions/1``.
        kms_client: Optional ``KeyManagementServiceClient`` for test
            injection. If ``None``, a default client is constructed using
            Application Default Credentials (set via
            ``gcloud auth application-default login`` for local dev, or
            via workload identity on GKE).

    Raises:
        RuntimeError: If ``google-cloud-kms`` or ``google-crc32c`` is not
            installed (the ``[gcp]`` extra is required).
    """

    def __init__(
        self,
        kms_resource_name: str,
        kms_client: Optional[Any] = None,
    ) -> None:
        if not _KMS_AVAILABLE:
            raise RuntimeError(
                f"google-cloud-kms is required for GoogleKMSSigner but is "
                f"not importable: {_KMS_ERROR}. {_INSTALL_HINT}"
            )
        if not _CRC_AVAILABLE:
            raise RuntimeError(
                f"google-crc32c is required for GoogleKMSSigner but is "
                f"not importable: {_CRC_ERROR}. {_INSTALL_HINT}"
            )

        if not kms_resource_name or "cryptoKeyVersions/" not in kms_resource_name:
            raise ValueError(
                f"kms_resource_name must be a full KMS key version path "
                f"(must contain 'cryptoKeyVersions/'), got "
                f"{kms_resource_name!r}"
            )

        self._kms_resource_name: str = kms_resource_name
        self._kms_client = kms_client or _kms_v1.KeyManagementServiceClient()
        self._cached_raw_pubkey: Optional[bytes] = None
        self._cached_address: Optional[str] = None

    # ─────────────────────────────────────────────────────────────
    # Public surface (the only methods the AlgorandSigner ABC allows)
    # ─────────────────────────────────────────────────────────────

    @property
    def address(self) -> str:
        """The 58-character Algorand address derived from the KMS key.

        First access triggers a KMS ``get_public_key`` call; subsequent
        accesses return the cached value.
        """
        if self._cached_address is None:
            raw_pubkey = self._fetch_raw_public_key()
            self._cached_address = _derive_algorand_address(raw_pubkey)
        return self._cached_address

    def sign_transaction(self, txn: Any) -> Any:
        """Sign an Algorand transaction via Google Cloud KMS.

        Validates the transaction (sender, receiver, amount, note prefix),
        computes the canonical bytes-to-sign, sends them to KMS as ``data``
        (not ``digest`` - Ed25519 hashes internally), validates the CRC32C
        integrity codes on both the request and the response, and assembles
        the ``SignedTransaction``.

        Args:
            txn: An ``algosdk.transaction.Transaction`` to sign.

        Returns:
            An ``algosdk.transaction.SignedTransaction``.

        Raises:
            SignerValidationError: If the transaction violates the signing
                policy.
            RuntimeError: If KMS returns an error or an integrity check
                fails.
        """
        self.validate_transaction(txn)
        bytes_to_sign = self._compute_bytes_to_sign(txn)
        raw_signature = self._kms_sign(bytes_to_sign)
        return _assemble_signed_transaction(txn, raw_signature)

    # ─────────────────────────────────────────────────────────────
    # Internal: bytes-to-sign computation
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _compute_bytes_to_sign(txn: Any) -> bytes:
        """Compute the canonical bytes that Ed25519 will sign.

        Per Algorand's signing rule::

            bytes_to_sign = b"TX" || msgpack_bytes(txn)

        ``algosdk.encoding.msgpack_encode`` returns a BASE64-ENCODED
        STRING, not raw msgpack bytes. We base64-decode to get the raw
        bytes, then prepend the TX prefix. This mirrors what algosdk's
        own ``Transaction.sign`` does internally.
        """
        try:
            from algosdk import encoding
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"py-algorand-sdk not importable: {exc}"
            ) from exc

        msgpack_b64 = encoding.msgpack_encode(txn)
        msgpack_bytes = base64.b64decode(msgpack_b64)
        return ALGORAND_SIGN_PREFIX + msgpack_bytes

    # ─────────────────────────────────────────────────────────────
    # Internal: KMS public key fetch
    # ─────────────────────────────────────────────────────────────

    def _fetch_raw_public_key(self) -> bytes:
        """Fetch the SPKI-PEM-encoded Ed25519 public key from KMS,
        validate the CRC32C, and extract the raw 32-byte public key.
        """
        if self._cached_raw_pubkey is not None:
            return self._cached_raw_pubkey

        try:
            response = self._kms_client.get_public_key(
                request={"name": self._kms_resource_name}
            )
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"KMS get_public_key failed for {self._kms_resource_name}: "
                f"{exc}"
            ) from exc

        # CRC32C integrity check on the response PEM bytes.
        pem = response.pem
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        if hasattr(response, "pem_crc32c") and response.pem_crc32c:
            computed = int(_google_crc32c.value(pem_bytes))
            expected = int(response.pem_crc32c)
            if computed != expected:
                raise RuntimeError(
                    f"KMS get_public_key response CRC32C mismatch: "
                    f"computed {computed}, expected {expected}. The "
                    f"response may have been corrupted in transit."
                )

        raw_pubkey = _extract_raw_ed25519_from_pem(pem_bytes)
        self._cached_raw_pubkey = raw_pubkey
        return raw_pubkey

    # ─────────────────────────────────────────────────────────────
    # Internal: KMS asymmetric_sign call
    # ─────────────────────────────────────────────────────────────

    def _kms_sign(self, bytes_to_sign: bytes) -> bytes:
        """Call KMS ``asymmetric_sign`` and return the raw 64-byte
        Ed25519 signature.

        Sends ``bytes_to_sign`` as ``data``, never as ``digest``.
        Validates the CRC32C integrity code on both the request and the
        response.
        """
        request_crc = int(_google_crc32c.value(bytes_to_sign))

        try:
            response = self._kms_client.asymmetric_sign(
                request={
                    "name": self._kms_resource_name,
                    "data": bytes_to_sign,
                    "data_crc32c": request_crc,
                }
            )
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"KMS asymmetric_sign failed for "
                f"{self._kms_resource_name}: {exc}"
            ) from exc

        # KMS confirms it received our request CRC matching.
        if hasattr(response, "verified_data_crc32c") and not response.verified_data_crc32c:
            raise RuntimeError(
                "KMS reports request data CRC32C did not match; request "
                "may have been corrupted in transit."
            )

        # We verify the response signature CRC.
        signature = response.signature
        if hasattr(response, "signature_crc32c") and response.signature_crc32c:
            computed = int(_google_crc32c.value(signature))
            expected = int(response.signature_crc32c)
            if computed != expected:
                raise RuntimeError(
                    f"KMS asymmetric_sign response signature CRC32C "
                    f"mismatch: computed {computed}, expected {expected}."
                )

        return signature


# ─────────────────────────────────────────────────────────────────
# HELPER: Derive Algorand address from raw Ed25519 public key
# ─────────────────────────────────────────────────────────────────

def _derive_algorand_address(raw_pubkey: bytes) -> str:
    """Derive the 58-character Algorand address from a raw Ed25519 public key.

    The Algorand address is base32(pubkey || checksum), where the checksum
    is the last 4 bytes of SHA-512/256(pubkey). algosdk has the helper.
    """
    if len(raw_pubkey) != ED25519_PUBKEY_LEN:
        raise ValueError(
            f"Expected {ED25519_PUBKEY_LEN}-byte Ed25519 public key, "
            f"got {len(raw_pubkey)} bytes"
        )

    try:
        from algosdk import encoding
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"py-algorand-sdk not importable: {exc}"
        ) from exc

    return encoding.encode_address(raw_pubkey)


# ─────────────────────────────────────────────────────────────────
# HELPER: Extract raw Ed25519 public key bytes from SPKI PEM
# ─────────────────────────────────────────────────────────────────

def _extract_raw_ed25519_from_pem(pem_bytes: bytes) -> bytes:
    """Parse an SPKI-PEM-encoded Ed25519 public key and return its 32-byte
    raw form.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_pem_public_key,
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"cryptography library not importable: {exc}"
        ) from exc

    pubkey = load_pem_public_key(pem_bytes)
    if not isinstance(pubkey, Ed25519PublicKey):
        raise RuntimeError(
            f"KMS returned a non-Ed25519 public key "
            f"({type(pubkey).__name__}); the key version may have the "
            f"wrong algorithm. Algorand requires Ed25519."
        )
    return pubkey.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )


# ─────────────────────────────────────────────────────────────────
# HELPER: Assemble a SignedTransaction from txn + raw signature
# ─────────────────────────────────────────────────────────────────

def _assemble_signed_transaction(txn: Any, raw_signature: bytes) -> Any:
    """Build an ``algosdk.transaction.SignedTransaction`` from the
    transaction and the 64-byte Ed25519 signature."""
    try:
        from algosdk.transaction import SignedTransaction
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"py-algorand-sdk not importable: {exc}"
        ) from exc

    # algosdk's SignedTransaction expects the signature as a base64 string.
    signature_b64 = base64.b64encode(raw_signature).decode("ascii")
    return SignedTransaction(txn, signature_b64)
