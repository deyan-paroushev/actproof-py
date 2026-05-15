# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Tests for openproof.timestamp.

Mocks TSPSigner.sign and TSPVerifier.verify so tests do not hit the network.
Real-network tests live in a separate suite marked ``@pytest.mark.slow`` and
are not run by default.

Twelve test groups:

* TestDataClasses: construction and immutability for TimestampAuthority,
  TSAAttempt, AcquisitionResult.
* TestDefaultChain: composition of DEFAULT_TSA_CHAIN.
* TestSupportedAlgorithms: SUPPORTED_HASH_ALGORITHMS set.
* TestImprintValidation: length-vs-algorithm check.
* TestUnsupportedHashAlg: rejected with clear error.
* TestEmptyChain: rejected immediately.
* TestHappyPath: first TSA succeeds.
* TestFailover: first fails, second succeeds.
* TestAllFailRaising: TimestampError raised when all fail with raise_on_failure=True.
* TestAllFailNonRaising: AcquisitionResult with token=None when raise_on_failure=False.
* TestAttemptsList: attempts records have right fields.
* TestAcquisitionResultProperties: .ok property.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from typing import Any

import pytest

from openproof.receipt import TimestampToken
from openproof.timestamp import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TSA_CHAIN,
    SUPPORTED_HASH_ALGORITHMS,
    AcquisitionResult,
    TimestampAuthority,
    TimestampError,
    TSAAttempt,
    acquire_timestamp_token,
)


# ─────────────────────────────────────────────────────────────────
# Test fixtures: fake objects that look like TSPVerifier output
# ─────────────────────────────────────────────────────────────────

class _FakeVerifiedToken:
    """Stand-in for the object TSPVerifier.verify returns.

    The real one has a ``tst_info`` attribute (dict-like) with fields per
    RFC 3161 section 2.4.2: gen_time, policy, message_imprint, serial_number.
    """
    def __init__(
        self,
        gen_time: datetime = datetime(2026, 5, 14, 8, 23, 11, tzinfo=timezone.utc),
        policy: str = "2.16.756.5.14.7.4.8",
        serial_number: int = 123456789,
    ) -> None:
        self.tst_info: dict[str, Any] = {
            "gen_time": gen_time,
            "policy": policy,
            "serial_number": serial_number,
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
            },
        }


# A valid SHA-256 digest length is 32 bytes; use a constant for tests.
_VALID_IMPRINT = b"\x12" * 32


# ─────────────────────────────────────────────────────────────────
# Group 1: Data classes
# ─────────────────────────────────────────────────────────────────

class TestDataClasses:

    def test_timestamp_authority_constructs(self) -> None:
        tsa = TimestampAuthority(name="Test", url="http://x", profile="public")
        assert tsa.name == "Test"
        assert tsa.url == "http://x"
        assert tsa.profile == "public"

    def test_timestamp_authority_default_profile(self) -> None:
        tsa = TimestampAuthority(name="Test", url="http://x")
        assert tsa.profile == "public"

    def test_timestamp_authority_frozen(self) -> None:
        tsa = TimestampAuthority(name="X", url="http://x")
        with pytest.raises(FrozenInstanceError):
            tsa.name = "Y"  # type: ignore[misc]

    def test_tsa_attempt_constructs(self) -> None:
        a = TSAAttempt(
            tsa_name="X", tsa_url="http://x", profile="public", ok=True,
            error=None, elapsed_seconds=0.5,
        )
        assert a.ok is True
        assert a.elapsed_seconds == 0.5

    def test_tsa_attempt_frozen(self) -> None:
        a = TSAAttempt(
            tsa_name="X", tsa_url="http://x", profile="public", ok=True,
        )
        with pytest.raises(FrozenInstanceError):
            a.ok = False  # type: ignore[misc]

    def test_acquisition_result_constructs(self) -> None:
        token = TimestampToken(
            tsa_url="http://x", tsa_name="X", token_b64="ABC",
            policy_oid=None, hash_alg="sha-256",
            imprint_hex="a" * 64, timestamp="2026-05-14T12:00:00Z",
        )
        r = AcquisitionResult(token=token, attempts=())
        assert r.token is token

    def test_acquisition_result_frozen(self) -> None:
        r = AcquisitionResult(token=None, attempts=())
        with pytest.raises(FrozenInstanceError):
            r.token = None  # type: ignore[misc]


# ─────────────────────────────────────────────────────────────────
# Group 2: Default chain composition
# ─────────────────────────────────────────────────────────────────

class TestDefaultChain:

    def test_chain_is_non_empty(self) -> None:
        assert len(DEFAULT_TSA_CHAIN) > 0

    def test_chain_is_tuple(self) -> None:
        # Immutability of the public chain matters.
        assert isinstance(DEFAULT_TSA_CHAIN, tuple)

    def test_chain_starts_with_eu_qualified(self) -> None:
        # The first few entries should be EU-qualified candidates so they
        # are tried first and produce stronger legal weight.
        assert DEFAULT_TSA_CHAIN[0].profile == "eu-qualified-candidate"
        assert DEFAULT_TSA_CHAIN[1].profile == "eu-qualified-candidate"

    def test_chain_contains_public_fallbacks(self) -> None:
        profiles = [tsa.profile for tsa in DEFAULT_TSA_CHAIN]
        assert "public" in profiles

    def test_named_tsas_present(self) -> None:
        names = {tsa.name for tsa in DEFAULT_TSA_CHAIN}
        # Four core EU-qualified candidates per the design note.
        assert "Sectigo Qualified" in names
        assert "QuoVadis EU" in names
        assert "Izenpe TSA" in names
        assert "Belgium TSA" in names

    def test_default_timeout_is_reasonable(self) -> None:
        # 10 seconds is the documented default; if someone bumps it
        # accidentally to something silly, this catches it.
        assert 1.0 <= DEFAULT_TIMEOUT_SECONDS <= 60.0


# ─────────────────────────────────────────────────────────────────
# Group 3: Supported algorithms set
# ─────────────────────────────────────────────────────────────────

class TestSupportedAlgorithms:

    def test_sha256_supported(self) -> None:
        assert "sha-256" in SUPPORTED_HASH_ALGORITHMS

    def test_sha384_supported(self) -> None:
        assert "sha-384" in SUPPORTED_HASH_ALGORITHMS

    def test_sha512_supported(self) -> None:
        assert "sha-512" in SUPPORTED_HASH_ALGORITHMS

    def test_md5_not_supported(self) -> None:
        # MD5 is broken and should NOT be in the supported set.
        assert "md5" not in SUPPORTED_HASH_ALGORITHMS

    def test_sha1_not_supported(self) -> None:
        # SHA-1 is deprecated; we don't accept it.
        assert "sha-1" not in SUPPORTED_HASH_ALGORITHMS
        assert "sha1" not in SUPPORTED_HASH_ALGORITHMS


# ─────────────────────────────────────────────────────────────────
# Group 4: Imprint length validation
# ─────────────────────────────────────────────────────────────────

class TestImprintValidation:

    def test_sha256_requires_32_bytes(self) -> None:
        with pytest.raises(TimestampError, match="imprint length"):
            acquire_timestamp_token(b"\x00" * 16, hash_alg="sha-256")

    def test_sha256_rejects_too_long(self) -> None:
        with pytest.raises(TimestampError, match="imprint length"):
            acquire_timestamp_token(b"\x00" * 64, hash_alg="sha-256")

    def test_sha384_requires_48_bytes(self) -> None:
        with pytest.raises(TimestampError, match="imprint length"):
            acquire_timestamp_token(b"\x00" * 32, hash_alg="sha-384")

    def test_sha512_requires_64_bytes(self) -> None:
        with pytest.raises(TimestampError, match="imprint length"):
            acquire_timestamp_token(b"\x00" * 32, hash_alg="sha-512")


# ─────────────────────────────────────────────────────────────────
# Group 5: Unsupported hash algorithm
# ─────────────────────────────────────────────────────────────────

class TestUnsupportedHashAlg:

    def test_unknown_alg_rejected(self) -> None:
        with pytest.raises(TimestampError, match="Unsupported hash algorithm"):
            acquire_timestamp_token(_VALID_IMPRINT, hash_alg="md5")

    def test_garbage_alg_rejected(self) -> None:
        with pytest.raises(TimestampError, match="Unsupported hash algorithm"):
            acquire_timestamp_token(_VALID_IMPRINT, hash_alg="not-a-real-algorithm")


# ─────────────────────────────────────────────────────────────────
# Group 6: Empty chain
# ─────────────────────────────────────────────────────────────────

class TestEmptyChain:

    def test_empty_chain_rejected(self) -> None:
        with pytest.raises(TimestampError, match="Empty TSA chain"):
            acquire_timestamp_token(_VALID_IMPRINT, chain=[])


# ─────────────────────────────────────────────────────────────────
# Helpers for monkeypatching tsp_client
# ─────────────────────────────────────────────────────────────────

def _patch_sign_always_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """All sign() calls return fake token bytes."""
    monkeypatch.setattr(
        "openproof.timestamp.TSPSigner.sign",
        lambda self, message_digest, signing_settings: b"fake DER token bytes",
    )
    monkeypatch.setattr(
        "openproof.timestamp.TSPVerifier.verify",
        lambda self, token, message_digest: _FakeVerifiedToken(),
    )


def _patch_sign_always_fails(
    monkeypatch: pytest.MonkeyPatch, error: str = "TSA unreachable"
) -> None:
    """All sign() calls raise."""
    def _fail(self, message_digest, signing_settings):  # type: ignore[no-untyped-def]
        raise RuntimeError(error)

    monkeypatch.setattr("openproof.timestamp.TSPSigner.sign", _fail)


def _patch_sign_fails_then_succeeds(
    monkeypatch: pytest.MonkeyPatch, fail_count: int
) -> None:
    """The first ``fail_count`` sign() calls raise; subsequent ones succeed."""
    state = {"calls": 0}

    def _maybe_fail(self, message_digest, signing_settings):  # type: ignore[no-untyped-def]
        state["calls"] += 1
        if state["calls"] <= fail_count:
            raise RuntimeError(f"TSA #{state['calls']} unreachable")
        return b"fake DER token bytes"

    monkeypatch.setattr("openproof.timestamp.TSPSigner.sign", _maybe_fail)
    monkeypatch.setattr(
        "openproof.timestamp.TSPVerifier.verify",
        lambda self, token, message_digest: _FakeVerifiedToken(),
    )


# ─────────────────────────────────────────────────────────────────
# Group 7: Happy path
# ─────────────────────────────────────────────────────────────────

class TestHappyPath:

    def test_first_tsa_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_sign_always_succeeds(monkeypatch)
        result = acquire_timestamp_token(_VALID_IMPRINT)
        assert result.ok is True
        assert result.token is not None
        assert len(result.attempts) == 1
        assert result.attempts[0].ok is True

    def test_returned_token_has_correct_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_succeeds(monkeypatch)
        result = acquire_timestamp_token(_VALID_IMPRINT)
        token = result.token
        assert token is not None
        assert token.tsa_name == DEFAULT_TSA_CHAIN[0].name
        assert token.tsa_url == DEFAULT_TSA_CHAIN[0].url
        assert token.hash_alg == "sha-256"
        assert token.imprint_hex == _VALID_IMPRINT.hex()
        assert token.policy_oid == "2.16.756.5.14.7.4.8"
        assert token.timestamp == "2026-05-14T08:23:11Z"
        assert token.token_b64  # non-empty

    def test_token_b64_decodes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import base64
        _patch_sign_always_succeeds(monkeypatch)
        result = acquire_timestamp_token(_VALID_IMPRINT)
        # Roundtrip the base64.
        decoded = base64.b64decode(result.token.token_b64)
        assert decoded == b"fake DER token bytes"


# ─────────────────────────────────────────────────────────────────
# Group 8: Failover
# ─────────────────────────────────────────────────────────────────

class TestFailover:

    def test_first_fails_second_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_fails_then_succeeds(monkeypatch, fail_count=1)
        result = acquire_timestamp_token(_VALID_IMPRINT)
        assert result.ok is True
        assert len(result.attempts) == 2
        # First attempt failed; second succeeded.
        assert result.attempts[0].ok is False
        assert result.attempts[1].ok is True
        # The returned token's TSA name matches the second in the chain.
        assert result.token.tsa_name == DEFAULT_TSA_CHAIN[1].name

    def test_multiple_fails_eventually_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_fails_then_succeeds(monkeypatch, fail_count=3)
        result = acquire_timestamp_token(_VALID_IMPRINT)
        assert result.ok is True
        assert len(result.attempts) == 4
        # The first three failed.
        for i in range(3):
            assert result.attempts[i].ok is False
        assert result.attempts[3].ok is True


# ─────────────────────────────────────────────────────────────────
# Group 9: All fail, raising
# ─────────────────────────────────────────────────────────────────

class TestAllFailRaising:

    def test_all_fail_raises_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_fails(monkeypatch, error="custom error message")
        with pytest.raises(TimestampError) as exc_info:
            acquire_timestamp_token(_VALID_IMPRINT)
        # Error message should mention how many TSAs failed and include
        # the underlying error for diagnostics.
        assert "All" in str(exc_info.value)
        assert "TSAs in the chain failed" in str(exc_info.value)
        assert "custom error message" in str(exc_info.value)

    def test_short_custom_chain_all_fail(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_fails(monkeypatch)
        custom_chain = [
            TimestampAuthority("Test1", "http://x1", "test"),
            TimestampAuthority("Test2", "http://x2", "test"),
        ]
        with pytest.raises(TimestampError):
            acquire_timestamp_token(_VALID_IMPRINT, chain=custom_chain)


# ─────────────────────────────────────────────────────────────────
# Group 10: All fail, non-raising
# ─────────────────────────────────────────────────────────────────

class TestAllFailNonRaising:

    def test_all_fail_returns_result_with_no_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_fails(monkeypatch)
        result = acquire_timestamp_token(
            _VALID_IMPRINT, raise_on_failure=False,
        )
        assert result.ok is False
        assert result.token is None

    def test_all_fail_attempts_list_complete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_fails(monkeypatch)
        result = acquire_timestamp_token(
            _VALID_IMPRINT, raise_on_failure=False,
        )
        # Every TSA in the chain was tried and recorded.
        assert len(result.attempts) == len(DEFAULT_TSA_CHAIN)
        for attempt in result.attempts:
            assert attempt.ok is False

    def test_all_fail_short_chain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_fails(monkeypatch)
        custom_chain = [
            TimestampAuthority("OnlyOne", "http://one", "test"),
        ]
        result = acquire_timestamp_token(
            _VALID_IMPRINT, chain=custom_chain, raise_on_failure=False,
        )
        assert not result.ok
        assert len(result.attempts) == 1
        assert result.attempts[0].tsa_name == "OnlyOne"


# ─────────────────────────────────────────────────────────────────
# Group 11: Attempts list fields
# ─────────────────────────────────────────────────────────────────

class TestAttemptsList:

    def test_successful_attempt_has_no_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_succeeds(monkeypatch)
        result = acquire_timestamp_token(_VALID_IMPRINT)
        attempt = result.attempts[0]
        assert attempt.ok is True
        assert attempt.error is None

    def test_failed_attempt_has_error_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_fails(monkeypatch, error="my failure reason")
        result = acquire_timestamp_token(
            _VALID_IMPRINT, raise_on_failure=False,
        )
        for attempt in result.attempts:
            assert attempt.error is not None
            assert "my failure reason" in attempt.error

    def test_attempt_records_elapsed_seconds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_succeeds(monkeypatch)
        result = acquire_timestamp_token(_VALID_IMPRINT)
        attempt = result.attempts[0]
        assert attempt.elapsed_seconds is not None
        assert attempt.elapsed_seconds >= 0

    def test_attempt_preserves_tsa_metadata(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_sign_always_succeeds(monkeypatch)
        custom_chain = [
            TimestampAuthority(
                name="MyCustomTSA", url="http://my.tsa", profile="configured"
            ),
        ]
        result = acquire_timestamp_token(_VALID_IMPRINT, chain=custom_chain)
        assert result.attempts[0].tsa_name == "MyCustomTSA"
        assert result.attempts[0].tsa_url == "http://my.tsa"
        assert result.attempts[0].profile == "configured"


# ─────────────────────────────────────────────────────────────────
# Group 12: AcquisitionResult properties
# ─────────────────────────────────────────────────────────────────

class TestAcquisitionResultProperties:

    def test_ok_true_when_token_present(self) -> None:
        token = TimestampToken(
            tsa_url="http://x", tsa_name="X", token_b64="ABC",
            policy_oid=None, hash_alg="sha-256",
            imprint_hex="a" * 64, timestamp="2026-05-14T12:00:00Z",
        )
        r = AcquisitionResult(token=token, attempts=())
        assert r.ok is True

    def test_ok_false_when_token_none(self) -> None:
        r = AcquisitionResult(token=None, attempts=())
        assert r.ok is False
