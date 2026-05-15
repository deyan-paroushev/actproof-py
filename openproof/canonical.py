# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
RFC 8785 JSON Canonicalization Scheme (JCS) with optional compliance discipline.

This module is the foundation of every other operation in openproof. A canonical
manifest is what gets hashed; the hash is what gets anchored on the public ledger
and timestamped by the QTSP; the receipt that travels outside this library is
re-verifiable by anyone who recomputes the canonical bytes from the same input
and gets the same hash.

The wrapper pattern
-------------------

We do not implement RFC 8785 from scratch. We wrap the ``rfc8785`` package
maintained by Trail of Bits, which is audited and broadly used. Our wrapper
adds three things on top:

1. **Strict mode (default).** Reject inputs that would produce ambiguous,
   non-reproducible, or non-I-JSON canonical bytes. The restrictions are
   carried forward from the production canonicaliser in the Quoruna reference
   implementation (Quoruna-JCS-v1).

2. **Duplicate-key detection on JSON parse.** Python dicts silently swallow
   duplicates. When input arrives as JSON text from an external party, the
   ``canonicalize_from_json`` entry point uses ``object_pairs_hook`` to raise
   on duplicate keys before the dict is constructed.

3. **JSON-Path-style error locations.** Validation errors report where in the
   input the problem occurred (``$.evidence[2].sha256``), which matters when
   manifests have many fields.

Strict mode restrictions
------------------------

When ``strict=True`` (the default), the canonicaliser rejects:

* **Floating-point numbers.** Floats have representation-dependent canonical
  forms across platforms. Use scaled integers instead (``*_basis_points``
  for percentages, ``*_minor_units`` for currency, ``*_ppm`` for parts per
  million).
* **NaN and Infinity.** Not representable in JSON; would produce a
  canonical form that no other implementation could agree on.
* **Integers outside the I-JSON safe range** ([-(2^53 - 1), 2^53 - 1]).
  RFC 7493 (I-JSON) limits integers to this range because larger values are
  not reliably preserved across JSON implementations. If a larger value
  must be carried, encode it as a string.
* **Strings that cannot encode to UTF-8** (lone surrogate code points).

When ``strict=False``, the canonicaliser delegates directly to ``rfc8785.dumps``
without pre-validation. This mode produces pure RFC 8785 output and accepts
anything the underlying library accepts. Use this for general-purpose JCS work
where the strict restrictions are not appropriate.

Quick reference
---------------

::

    from openproof.canonical import canonicalize, hash_canonical_hex

    manifest = {
        "act_type_id": "op:eu.nis2.art20.management_body_approval.v1",
        "decision_date": "2026-05-14",
    }

    canonical_bytes = canonicalize(manifest)
    # b'{"act_type_id":"op:eu.nis2.art20.management_body_approval.v1",
    #    "decision_date":"2026-05-14"}'

    manifest_hash = hash_canonical_hex(manifest)
    # "a3f2c1...

API
---

``canonicalize(obj, *, strict=True) -> bytes``
    Primary entry point. Returns UTF-8 encoded bytes of the canonical
    representation.

``canonicalize_str(obj, *, strict=True) -> str``
    Same as ``canonicalize`` but returns a Python ``str`` instead of bytes.

``canonicalize_from_json(json_str, *, strict=True) -> bytes``
    Parse JSON text with duplicate-key detection, then canonicalise. Use this
    when input arrives as JSON from an external party.

``hash_canonical(obj, *, strict=True) -> bytes``
    Canonicalize and return the SHA-256 raw digest (32 bytes).

``hash_canonical_hex(obj, *, strict=True) -> str``
    Canonicalize and return the SHA-256 hex digest (64 lowercase hex chars).

References
----------

* RFC 8785: https://datatracker.ietf.org/doc/html/rfc8785
* RFC 7493 (I-JSON): https://datatracker.ietf.org/doc/html/rfc7493
* rfc8785 library: https://github.com/trailofbits/rfc8785.py
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

try:
    import rfc8785
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "rfc8785 is required. Install with: pip install 'rfc8785>=0.1.4'"
    ) from exc


__all__ = [
    "canonicalize",
    "canonicalize_str",
    "canonicalize_from_json",
    "hash_canonical",
    "hash_canonical_hex",
    "IJSON_MAX_SAFE_INT",
    "IJSON_MIN_SAFE_INT",
    "CanonicalizationError",
]


# ─────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────

# I-JSON safe integer range, per RFC 7493 section 2.2. Integers outside this
# range are not reliably preserved across JSON implementations and must be
# encoded as strings if their values are to survive a round trip.
IJSON_MAX_SAFE_INT: int = 2**53 - 1
IJSON_MIN_SAFE_INT: int = -(2**53 - 1)


# ─────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────

class CanonicalizationError(ValueError):
    """Raised when input violates a strict-mode canonicalisation restriction.

    Subclass of ``ValueError`` so callers can catch ``ValueError`` if they
    prefer to handle all input-validation errors uniformly, or
    ``CanonicalizationError`` specifically when they need to distinguish
    canonicalisation problems from other value errors.

    The error message includes a JSON-Path-style location (``$.foo.bar[2]``)
    indicating where in the input the problem occurred.
    """


# ─────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────

def canonicalize(obj: Any, *, strict: bool = True) -> bytes:
    """RFC 8785 canonicalise a JSON-serialisable Python object.

    Args:
        obj: The Python object to canonicalise. May be a dict, list, str,
            int, float (rejected if ``strict``), bool, or ``None``.
        strict: If ``True`` (default), enforce openproof discipline:
            no floats, no NaN/Infinity, integers in I-JSON safe range,
            strings that encode to UTF-8. If ``False``, delegate directly
            to ``rfc8785.dumps`` with no pre-validation.

    Returns:
        UTF-8 encoded bytes of the canonical JSON representation.

    Raises:
        CanonicalizationError: If ``strict=True`` and a restriction is
            violated.
        TypeError: If the input contains a type that JSON cannot represent.
        rfc8785.IntegerDomainError: If ``strict=False`` and an integer is
            outside the I-JSON safe range (raised by the underlying library).
    """
    if strict:
        _validate_strict(obj, "$")
    return rfc8785.dumps(obj)


def canonicalize_str(obj: Any, *, strict: bool = True) -> str:
    """RFC 8785 canonicalise to a Python ``str`` (UTF-8 decoded).

    Args:
        obj: The object to canonicalise. See ``canonicalize`` for details.
        strict: Whether to enforce strict mode. Default ``True``.

    Returns:
        The canonical representation as a ``str``.
    """
    return canonicalize(obj, strict=strict).decode("utf-8")


def canonicalize_from_json(json_str: str, *, strict: bool = True) -> bytes:
    """Parse JSON text with duplicate-key detection, then canonicalise.

    Use this entry point when input arrives as JSON text from an external
    party. Python's ``json.loads`` silently swallows duplicate keys
    (keeping the last value); this function uses ``object_pairs_hook`` to
    raise on duplicates before the dict is constructed.

    Args:
        json_str: The JSON text to parse and canonicalise.
        strict: Whether to enforce strict mode. Default ``True``.

    Returns:
        UTF-8 encoded bytes of the canonical JSON representation.

    Raises:
        CanonicalizationError: If duplicate keys are detected, or any
            other strict-mode restriction is violated downstream.
        json.JSONDecodeError: If the input is not valid JSON.
    """
    obj = json.loads(json_str, object_pairs_hook=_detect_duplicate_keys)
    return canonicalize(obj, strict=strict)


def hash_canonical(obj: Any, *, strict: bool = True) -> bytes:
    """Canonicalise and return the SHA-256 raw digest (32 bytes).

    Convenience for the most common operation: canonicalise a manifest and
    compute the hash that will be anchored on the public ledger.

    Args:
        obj: The object to canonicalise and hash.
        strict: Whether to enforce strict mode. Default ``True``.

    Returns:
        The 32-byte SHA-256 raw digest of the canonical bytes.
    """
    return hashlib.sha256(canonicalize(obj, strict=strict)).digest()


def hash_canonical_hex(obj: Any, *, strict: bool = True) -> str:
    """Canonicalise and return the SHA-256 hex digest.

    Args:
        obj: The object to canonicalise and hash.
        strict: Whether to enforce strict mode. Default ``True``.

    Returns:
        The 64-character lowercase hexadecimal SHA-256 digest.
    """
    return hash_canonical(obj, strict=strict).hex()


# ─────────────────────────────────────────────────────────────────
# INTERNAL: STRICT-MODE VALIDATION
# ─────────────────────────────────────────────────────────────────

def _validate_strict(node: Any, path: str) -> None:
    """Recursively validate ``node`` against strict-mode restrictions.

    Walks the tree depth-first. Raises ``CanonicalizationError`` on the
    first restriction violation, with a JSON-Path-style location.
    """
    # bool is a subclass of int in Python; check it first.
    if isinstance(node, bool):
        return

    if isinstance(node, float):
        if math.isnan(node):
            raise CanonicalizationError(
                f"NaN at {path}: not representable in canonical JSON. "
                f"Strict mode forbids NaN and Infinity."
            )
        if math.isinf(node):
            raise CanonicalizationError(
                f"Infinity at {path}: not representable in canonical JSON. "
                f"Strict mode forbids NaN and Infinity."
            )
        raise CanonicalizationError(
            f"Floating-point number {node} at {path}: not allowed in strict "
            f"mode. Floats have representation-dependent canonical forms across "
            f"platforms. Use scaled integers (e.g. *_basis_points for "
            f"percentages, *_minor_units for currency, *_ppm for parts per "
            f"million), or pass strict=False if you do not need cross-platform "
            f"reproducibility."
        )

    if isinstance(node, int):
        if node > IJSON_MAX_SAFE_INT or node < IJSON_MIN_SAFE_INT:
            raise CanonicalizationError(
                f"Integer {node} at {path} exceeds I-JSON safe range "
                f"[{IJSON_MIN_SAFE_INT}, {IJSON_MAX_SAFE_INT}] "
                f"(RFC 7493 section 2.2). Integers outside this range are not "
                f"reliably preserved across JSON implementations. Encode as a "
                f"string if a larger value must be carried, or pass strict=False."
            )
        return

    if isinstance(node, str):
        try:
            node.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise CanonicalizationError(
                f"String at {path} contains code points that cannot encode to "
                f"UTF-8 (typically lone surrogates): {exc}. Strict mode requires "
                f"all strings to be valid UTF-8."
            ) from exc
        return

    if node is None:
        return

    if isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(k, str):
                raise CanonicalizationError(
                    f"Non-string key at {path}: {type(k).__name__} {k!r}. "
                    f"JSON requires string keys."
                )
            try:
                k.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise CanonicalizationError(
                    f"Key {k!r} at {path} contains code points that cannot "
                    f"encode to UTF-8: {exc}."
                ) from exc
            _validate_strict(v, f"{path}.{k}")
        return

    if isinstance(node, list):
        for i, item in enumerate(node):
            _validate_strict(item, f"{path}[{i}]")
        return

    raise CanonicalizationError(
        f"Unsupported type at {path}: {type(node).__name__}. "
        f"openproof canonical accepts dict, list, str, int, bool, None."
    )


# ─────────────────────────────────────────────────────────────────
# INTERNAL: DUPLICATE KEY DETECTION
# ─────────────────────────────────────────────────────────────────

def _detect_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` for ``json.loads`` that detects duplicate keys.

    Python's default ``json.loads`` silently keeps the last value when keys
    repeat. RFC 8785 canonicalisation requires unique keys; if input arrived
    with duplicates and we silently swallowed them, two parties could compute
    different canonical bytes from textually identical inputs.

    Raises:
        CanonicalizationError: If any duplicate keys are present.
    """
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        seen: set[str] = set()
        duplicates: list[str] = []
        for k in keys:
            if k in seen:
                if k not in duplicates:
                    duplicates.append(k)
            else:
                seen.add(k)
        raise CanonicalizationError(
            f"Duplicate keys forbidden by RFC 8785. "
            f"Duplicates found: {sorted(duplicates)}"
        )
    return dict(pairs)
