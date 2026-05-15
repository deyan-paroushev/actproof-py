# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Acquire RFC 3161 trusted timestamp tokens with QTSP failover.

A timestamp token is a TSA's signed assertion that a given hash existed at a
specific moment in time. For openproof, that hash is typically the
``manifest_hash`` of a commitment. The token plus the TSA's certificate
chain produce non-repudiable proof of existence: anyone who later receives
the receipt can verify the token's signature, extract the timestamp, and
confirm "this hash was already known by <date>" without needing to trust
either the issuer or the openproof platform.

This module owns the **acquisition** half: build an RFC 3161 TimeStampReq,
POST it to a TSA, parse the TimeStampResp, validate the response is
well-formed, extract metadata, return a typed ``TimestampToken``. The
**verification** half (validating the token's CMS signature against the
TSA's certificate chain end-to-end) lives in ``openproof.verify`` (v0.0.9).

QTSP failover chain
-------------------

``DEFAULT_TSA_CHAIN`` lists six TSAs in priority order:

1. **Sectigo Qualified** - `timestamp.sectigo.com/qualified`
2. **QuoVadis EU** - `ts.quovadisglobal.com/eu` (DigiCert eIDAS QTSP)
3. **Izenpe TSA** - `tsa.izenpe.com` (Basque government QTSP)
4. **Belgium TSA** - `tsa.belgium.be/connect` (Belgian government QTSP)
5. **DigiCert** - `timestamp.digicert.com` (public, high availability)
6. **freetsa.org** - `freetsa.org/tsr` (public, free, no SLA)

The first four are EU-qualified TSP candidates. Whether a given TSA holds
qualified status at any given moment depends on the EU Trusted List
(eIDAS Regulation 910/2014); openproof does not assert qualification, it
records which TSA actually returned the token. Verifiers can check current
qualified status against the EUTL themselves.

The four EU candidates are tried first because their tokens have stronger
legal weight in EU jurisdictions. The two public fallbacks exist because
free public TSAs are sometimes the only reachable option (corporate firewalls
blocking exotic endpoints, EU TSAs down for maintenance, etc.). A token from
DigiCert is still a valid RFC 3161 token; it just doesn't carry an eIDAS
qualified signature.

Counter-timestamping (acquiring a second token from a different TSA over
the same imprint, for defense against a single TSA failure or compromise)
is a v0.0.7+ concern; this module produces single tokens.

Acquisition flow
----------------

::

    from openproof.canonical import hash_canonical
    from openproof.manifest import manifest_to_dict
    from openproof.timestamp import acquire_timestamp_token

    manifest_dict = manifest_to_dict(my_manifest)
    imprint_bytes = hash_canonical(manifest_dict)  # 32 bytes

    result = acquire_timestamp_token(imprint_bytes)
    print(result.token.tsa_name)        # e.g. "QuoVadis EU"
    print(result.token.timestamp)        # ISO 8601 UTC
    print(result.attempts)               # which TSAs succeeded/failed

API
---

* ``acquire_timestamp_token(imprint, *, ...) -> AcquisitionResult``
* ``TimestampAuthority`` - one TSA endpoint description.
* ``TSAAttempt`` - record of one acquisition attempt (success or failure).
* ``AcquisitionResult`` - the bundle of (token, attempts) returned.
* ``TimestampError`` - raised when all TSAs in the chain fail.
* ``DEFAULT_TSA_CHAIN`` - the production failover chain.
* ``DEFAULT_TIMEOUT_SECONDS`` - default per-TSA timeout.
* ``SUPPORTED_HASH_ALGORITHMS`` - set of accepted ``hash_alg`` values.

Network usage
-------------

This module reaches out over HTTP(S) to TSA endpoints. In production
``acquire_timestamp_token`` is the first network-touching call in an
anchor workflow. Tests in this package mock the underlying ``tsp_client``
calls so the test suite does not require network access.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Sequence

import requests

from openproof.receipt import TimestampToken

try:
    from tsp_client import SigningSettings, TSPSigner, TSPVerifier
    from tsp_client.algorithms import DigestAlgorithm
    _TSP_CLIENT_AVAILABLE: bool = True
    _TSP_CLIENT_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    # tsp_client is a hard dependency in pyproject.toml, but transitive
    # version conflicts (e.g. cryptography vs pyOpenSSL) can make it fail
    # to import in some environments, sometimes with errors other than
    # ImportError (AttributeError from a removed C-binding symbol, for
    # example). Catch broadly so the rest of openproof remains usable;
    # defer failure to call time. Tests can still monkeypatch the
    # placeholder symbols below.
    _TSP_CLIENT_AVAILABLE = False
    _TSP_CLIENT_ERROR = str(exc)

    class _UnavailableTSPSigner:
        """Placeholder. Real ``TSPSigner`` is provided by tsp_client when
        available; in environments where the import fails, this stub stays
        in place. Tests can monkeypatch ``sign`` to swap in fakes."""
        def sign(self, message_digest: bytes, signing_settings: Any) -> bytes:
            raise TimestampError(
                f"tsp-client is required but cannot be imported: "
                f"{_TSP_CLIENT_ERROR}. "
                f"Install or repair with: pip install 'tsp-client==0.2.1'"
            )

    class _UnavailableTSPVerifier:
        def verify(self, token: bytes, message_digest: bytes) -> Any:
            raise TimestampError(
                f"tsp-client is required but cannot be imported: "
                f"{_TSP_CLIENT_ERROR}."
            )

    class _PlaceholderSigningSettings:
        """Placeholder settings constructor; accepts arbitrary kwargs."""
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    class _PlaceholderDigestAlgorithm:
        """Placeholder enum-like; values are string sentinels."""
        SHA224 = "SHA224"
        SHA256 = "SHA256"
        SHA384 = "SHA384"
        SHA512 = "SHA512"
        SHA3_224 = "SHA3_224"
        SHA3_256 = "SHA3_256"
        SHA3_384 = "SHA3_384"
        SHA3_512 = "SHA3_512"

    SigningSettings = _PlaceholderSigningSettings  # type: ignore[assignment,misc]
    TSPSigner = _UnavailableTSPSigner  # type: ignore[assignment,misc]
    TSPVerifier = _UnavailableTSPVerifier  # type: ignore[assignment,misc]
    DigestAlgorithm = _PlaceholderDigestAlgorithm  # type: ignore[assignment,misc]


logger = logging.getLogger(__name__)


__all__ = [
    "TimestampAuthority",
    "TSAAttempt",
    "AcquisitionResult",
    "TimestampError",
    "acquire_timestamp_token",
    "DEFAULT_TSA_CHAIN",
    "DEFAULT_TIMEOUT_SECONDS",
    "SUPPORTED_HASH_ALGORITHMS",
]


# ─────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT_SECONDS: float = 10.0
"""Default per-TSA timeout when acquiring a token."""

# Algorithm name → tsp_client DigestAlgorithm enum
_DIGEST_MAP: dict[str, DigestAlgorithm] = {
    "sha-256": DigestAlgorithm.SHA256,
    "sha-384": DigestAlgorithm.SHA384,
    "sha-512": DigestAlgorithm.SHA512,
    "sha-224": DigestAlgorithm.SHA224,
    "sha3-256": DigestAlgorithm.SHA3_256,
    "sha3-384": DigestAlgorithm.SHA3_384,
    "sha3-512": DigestAlgorithm.SHA3_512,
    "sha3-224": DigestAlgorithm.SHA3_224,
}

SUPPORTED_HASH_ALGORITHMS: frozenset[str] = frozenset(_DIGEST_MAP.keys())
"""Hash algorithm names accepted by ``acquire_timestamp_token``."""

# Expected digest length in bytes, per algorithm.
_EXPECTED_DIGEST_BYTES: dict[str, int] = {
    "sha-224": 28,
    "sha-256": 32,
    "sha-384": 48,
    "sha-512": 64,
    "sha3-224": 28,
    "sha3-256": 32,
    "sha3-384": 48,
    "sha3-512": 64,
}


# ─────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────

class TimestampError(RuntimeError):
    """Raised when all TSAs in the failover chain fail to produce a token.

    When ``raise_on_failure=False`` is passed to ``acquire_timestamp_token``,
    callers receive an ``AcquisitionResult`` with ``token=None`` instead of
    this exception, so they can inspect the attempts list and decide what to
    do (retry later, fall through to a different operational mode, etc.).
    """


# ─────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TimestampAuthority:
    """One TSA endpoint description.

    Attributes:
        name: Human-readable TSA name. Recorded in the returned
            ``TimestampToken.tsa_name`` for receipts.
        url: HTTP(S) endpoint URL. RFC 3161 TSAs commonly speak HTTP only
            (the protocol carries its own cryptographic protection via the
            TSToken's signature); this is normal.
        profile: Free-form profile tag describing what kind of TSA this is.
            Common values: ``"eu-qualified-candidate"`` for EU TSPs that
            *may* hold qualified status (verify against EUTL),
            ``"public"`` for free or fallback TSAs, ``"configured"`` for
            user-supplied endpoints.
    """
    name: str
    url: str
    profile: str = "public"


@dataclass(frozen=True)
class TSAAttempt:
    """Record of one attempt against a TSA. Returned in the attempts list
    regardless of success or failure, for diagnostics.

    Attributes:
        tsa_name: The TSA's name.
        tsa_url: The TSA's URL.
        profile: The TSA's profile tag.
        ok: ``True`` if a valid token was returned; ``False`` if any error.
        error: Error message text on failure, ``None`` on success.
        elapsed_seconds: Wall-clock time spent on this attempt.
    """
    tsa_name: str
    tsa_url: str
    profile: str
    ok: bool
    error: Optional[str] = None
    elapsed_seconds: Optional[float] = None


@dataclass(frozen=True)
class AcquisitionResult:
    """The return of ``acquire_timestamp_token``: token (or None) plus attempts.

    Attributes:
        token: The acquired ``TimestampToken``, or ``None`` if every TSA in
            the chain failed.
        attempts: Tuple of per-TSA ``TSAAttempt`` records, in the order
            they were tried.
    """
    token: Optional[TimestampToken]
    attempts: tuple[TSAAttempt, ...]

    @property
    def ok(self) -> bool:
        """``True`` if a token was acquired, ``False`` otherwise."""
        return self.token is not None


# ─────────────────────────────────────────────────────────────────
# DEFAULT TSA CHAIN
# ─────────────────────────────────────────────────────────────────

DEFAULT_TSA_CHAIN: tuple[TimestampAuthority, ...] = (
    # EU-qualified candidates first. Whether a given TSA holds qualified
    # status at any given moment depends on the EU Trusted List; verifiers
    # check EUTL separately. Listing as candidate means: probable QTSP, but
    # this module does not assert qualification.
    TimestampAuthority(
        name="Sectigo Qualified",
        url="http://timestamp.sectigo.com/qualified",
        profile="eu-qualified-candidate",
    ),
    TimestampAuthority(
        name="QuoVadis EU",
        url="http://ts.quovadisglobal.com/eu",
        profile="eu-qualified-candidate",
    ),
    TimestampAuthority(
        name="Izenpe TSA",
        url="http://tsa.izenpe.com",
        profile="eu-qualified-candidate",
    ),
    TimestampAuthority(
        name="Belgium TSA",
        url="http://tsa.belgium.be/connect",
        profile="eu-qualified-candidate",
    ),
    # Public high-availability fallbacks. Valid RFC 3161 tokens but no
    # eIDAS qualified signature.
    TimestampAuthority(
        name="DigiCert",
        url="http://timestamp.digicert.com",
        profile="public",
    ),
    TimestampAuthority(
        name="freetsa.org",
        url="https://freetsa.org/tsr",
        profile="public",
    ),
)


# ─────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────

def _utc_iso(value: Optional[datetime]) -> Optional[str]:
    """Convert a datetime to ISO 8601 UTC string with Z suffix."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_imprint(imprint: bytes, hash_alg: str) -> None:
    """Confirm the imprint bytes have the right length for hash_alg."""
    expected = _EXPECTED_DIGEST_BYTES.get(hash_alg)
    if expected is None:
        return  # unknown algorithm; let tsp_client complain
    if len(imprint) != expected:
        raise TimestampError(
            f"imprint length {len(imprint)} bytes does not match "
            f"{hash_alg} digest length {expected} bytes"
        )


def _digest_enum(hash_alg: str) -> DigestAlgorithm:
    """Map a hash_alg name to the tsp_client DigestAlgorithm enum."""
    try:
        return _DIGEST_MAP[hash_alg]
    except KeyError as exc:
        raise TimestampError(
            f"Unsupported hash algorithm {hash_alg!r}. "
            f"Supported: {sorted(SUPPORTED_HASH_ALGORITHMS)}"
        ) from exc


def _build_transport(timeout_seconds: float) -> Callable[..., requests.Response]:
    """Build a transport callable for tsp_client's SigningSettings.

    The transport is a function that takes a URL plus kwargs and returns a
    ``requests.Response``. We set sensible connect/read timeouts so a
    misbehaving TSA does not stall the whole chain.
    """
    connect_timeout = min(2.0, max(0.5, timeout_seconds / 2.0))
    read_timeout = max(1.0, timeout_seconds)

    def _transport(url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", (connect_timeout, read_timeout))
        return requests.post(url, **kwargs)

    return _transport


def _extract_token_metadata(
    token_bytes: bytes,
    verified: Any,
    imprint: bytes,
    hash_alg: str,
    tsa: TimestampAuthority,
) -> TimestampToken:
    """Build a ``TimestampToken`` from a TSPVerifier.verify result."""
    tst_info = getattr(verified, "tst_info", {}) or {}
    gen_time = tst_info.get("gen_time")
    policy_oid = tst_info.get("policy")

    return TimestampToken(
        tsa_url=tsa.url,
        tsa_name=tsa.name,
        token_b64=base64.b64encode(token_bytes).decode("ascii"),
        policy_oid=str(policy_oid) if policy_oid else None,
        hash_alg=hash_alg,
        imprint_hex=imprint.hex(),
        timestamp=_utc_iso(gen_time) or "",
    )


# ─────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────

def acquire_timestamp_token(
    imprint: bytes,
    *,
    hash_alg: str = "sha-256",
    chain: Optional[Sequence[TimestampAuthority]] = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    raise_on_failure: bool = True,
) -> AcquisitionResult:
    """Acquire an RFC 3161 timestamp token over ``imprint``.

    Iterates through ``chain`` in order. Each TSA is tried with the
    specified timeout. On the first success, returns immediately with
    the token plus the attempts so far. If all TSAs fail, either raises
    ``TimestampError`` (default) or returns an ``AcquisitionResult`` with
    ``token=None`` and the full attempts list.

    Args:
        imprint: The raw digest bytes to be timestamped. Typically the
            SHA-256 of a canonical manifest dict (32 bytes). The length
            must match the algorithm declared in ``hash_alg``.
        hash_alg: Name of the algorithm used to produce ``imprint``. Must
            be one of ``SUPPORTED_HASH_ALGORITHMS``. Default ``"sha-256"``.
        chain: Optional sequence of ``TimestampAuthority`` to try in order.
            Defaults to ``DEFAULT_TSA_CHAIN``.
        timeout_seconds: Per-TSA timeout. Default 10.0 seconds.
        raise_on_failure: If ``True`` (default), raise ``TimestampError``
            when no TSA succeeds. If ``False``, return ``AcquisitionResult``
            with ``token=None`` instead.

    Returns:
        ``AcquisitionResult`` with the token (or None) and per-TSA attempts.

    Raises:
        TimestampError: If ``imprint`` has the wrong length for ``hash_alg``,
            or if ``hash_alg`` is not supported, or if all TSAs fail and
            ``raise_on_failure=True``.
    """
    _validate_imprint(imprint, hash_alg)
    digest_alg = _digest_enum(hash_alg)

    if chain is None:
        chain = DEFAULT_TSA_CHAIN
    if not chain:
        raise TimestampError("Empty TSA chain: pass at least one TimestampAuthority")

    transport = _build_transport(timeout_seconds)
    signer = TSPSigner()
    verifier = TSPVerifier()

    attempts: list[TSAAttempt] = []

    for tsa in chain:
        started = time.monotonic()
        try:
            settings = SigningSettings(
                tsp_server=tsa.url,
                digest_algorithm=digest_alg,
                transport=transport,
            )
            token_bytes = signer.sign(message_digest=imprint, signing_settings=settings)
            verified = verifier.verify(token_bytes, message_digest=imprint)
            elapsed = time.monotonic() - started

            token = _extract_token_metadata(
                token_bytes=token_bytes,
                verified=verified,
                imprint=imprint,
                hash_alg=hash_alg,
                tsa=tsa,
            )

            attempts.append(
                TSAAttempt(
                    tsa_name=tsa.name,
                    tsa_url=tsa.url,
                    profile=tsa.profile,
                    ok=True,
                    error=None,
                    elapsed_seconds=elapsed,
                )
            )

            logger.info(
                "RFC 3161 timestamp acquired from %s in %.2fs",
                tsa.name, elapsed,
            )
            return AcquisitionResult(token=token, attempts=tuple(attempts))

        except Exception as exc:  # noqa: BLE001
            # Catch broadly because TSP errors come from many places:
            # tsp_client.exceptions, requests exceptions, ASN.1 parsing,
            # TSA returning HTTP 5xx, etc. Record and move to next TSA.
            elapsed = time.monotonic() - started
            attempts.append(
                TSAAttempt(
                    tsa_name=tsa.name,
                    tsa_url=tsa.url,
                    profile=tsa.profile,
                    ok=False,
                    error=str(exc),
                    elapsed_seconds=elapsed,
                )
            )
            logger.warning(
                "RFC 3161 timestamp attempt failed for %s: %s",
                tsa.url, exc,
            )

    # All TSAs failed.
    if raise_on_failure:
        attempt_summary = "; ".join(
            f"{a.tsa_name}: {a.error}" for a in attempts
        )
        raise TimestampError(
            f"All {len(attempts)} TSAs in the chain failed: {attempt_summary}"
        )

    return AcquisitionResult(token=None, attempts=tuple(attempts))
