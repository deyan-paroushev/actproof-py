# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Tests for actproof.canonical (RFC 8785 JCS with optional strict discipline).

Six test groups:

* TestRFC8785Basics: behaviors required by RFC 8785 itself (key sorting,
  number formatting, escaping, Unicode, empty structures, nesting).
* TestStrictModeRestrictions: enforces actproof's strict-mode discipline
  (no floats, no NaN/Infinity, I-JSON integer range, valid UTF-8, no
  duplicate keys when parsing JSON).
* TestNonStrictMode: confirms strict=False delegates to rfc8785 directly,
  accepting floats and not enforcing the strict restrictions.
* TestHelperFunctions: canonicalize_str, hash_canonical,
  hash_canonical_hex, canonicalize_from_json.
* TestErrorLocations: JSON-Path-style error locations report where in the
  input a restriction violation occurred.
* TestReproducibility: the same logical input always produces the same
  canonical bytes, regardless of insertion order.

Run with::

    pytest tests/test_canonical.py -v
"""

from __future__ import annotations

import hashlib
import json

import pytest

from actproof.canonical import (
    CanonicalizationError,
    IJSON_MAX_SAFE_INT,
    IJSON_MIN_SAFE_INT,
    canonicalize,
    canonicalize_from_json,
    canonicalize_str,
    hash_canonical,
    hash_canonical_hex,
)


# ─────────────────────────────────────────────────────────────────
# Group 1: RFC 8785 basics
# ─────────────────────────────────────────────────────────────────

class TestRFC8785Basics:
    """RFC 8785 canonicalization rules.

    These tests do not exercise strict-mode restrictions; they exercise the
    underlying RFC 8785 algorithm via our wrapper.
    """

    def test_object_keys_sorted_alphabetically(self) -> None:
        assert canonicalize_str({"c": 3, "a": 1, "b": 2}) == '{"a":1,"b":2,"c":3}'

    def test_object_keys_sorted_by_unicode_codepoint(self) -> None:
        # Per RFC 8785, sort is by UTF-16 code units, which for the BMP
        # equals Unicode code point order. Capital letters precede lowercase.
        assert canonicalize_str({"b": 1, "B": 2, "a": 3}) == '{"B":2,"a":3,"b":1}'

    def test_nested_keys_independently_sorted(self) -> None:
        # The sort applies recursively at each object level.
        result = canonicalize_str({"z": {"b": 1, "a": 2}, "a": {"d": 3, "c": 4}})
        assert result == '{"a":{"c":4,"d":3},"z":{"a":2,"b":1}}'

    def test_no_insignificant_whitespace(self) -> None:
        # RFC 8785 forbids whitespace between tokens.
        result = canonicalize_str({"a": 1, "b": [2, 3]})
        assert " " not in result
        assert "\t" not in result
        assert "\n" not in result

    def test_integers_no_leading_zero(self) -> None:
        assert canonicalize_str({"x": 0}) == '{"x":0}'

    def test_negative_integers(self) -> None:
        assert canonicalize_str({"x": -1}) == '{"x":-1}'

    def test_newline_escaped_as_backslash_n(self) -> None:
        assert canonicalize_str({"x": "\n"}) == r'{"x":"\n"}'

    def test_tab_escaped_as_backslash_t(self) -> None:
        assert canonicalize_str({"x": "\t"}) == r'{"x":"\t"}'

    def test_quote_escaped(self) -> None:
        assert canonicalize_str({"x": '"'}) == r'{"x":"\""}'

    def test_backslash_escaped(self) -> None:
        assert canonicalize_str({"x": "\\"}) == r'{"x":"\\"}'

    def test_empty_object(self) -> None:
        assert canonicalize_str({}) == "{}"

    def test_empty_array(self) -> None:
        assert canonicalize_str([]) == "[]"

    def test_object_with_null_value(self) -> None:
        assert canonicalize_str({"x": None}) == '{"x":null}'

    def test_object_with_empty_array_value(self) -> None:
        assert canonicalize_str({"x": []}) == '{"x":[]}'

    def test_object_with_empty_object_value(self) -> None:
        assert canonicalize_str({"x": {}}) == '{"x":{}}'

    def test_boolean_true(self) -> None:
        assert canonicalize_str({"x": True}) == '{"x":true}'

    def test_boolean_false(self) -> None:
        assert canonicalize_str({"x": False}) == '{"x":false}'

    def test_unicode_string_preserved(self) -> None:
        result = canonicalize_str({"name": "café"})
        # The character may be passed through literally or escaped as \u00e9;
        # both are RFC 8785 compliant. We just need the value to round-trip.
        parsed = json.loads(result)
        assert parsed == {"name": "café"}

    def test_emoji_string_preserved(self) -> None:
        result = canonicalize_str({"x": "🌍"})
        parsed = json.loads(result)
        assert parsed == {"x": "🌍"}

    def test_iso_8601_timestamp_preserved(self) -> None:
        result = canonicalize_str({"ts": "2026-05-14T08:23:11Z"})
        assert '"ts":"2026-05-14T08:23:11Z"' in result

    def test_nested_two_level(self) -> None:
        assert canonicalize_str({"a": {"b": 1}}) == '{"a":{"b":1}}'

    def test_nested_three_level_with_array(self) -> None:
        result = canonicalize_str({"a": {"b": {"c": [1, 2, 3]}}})
        assert result == '{"a":{"b":{"c":[1,2,3]}}}'

    def test_array_of_objects(self) -> None:
        result = canonicalize_str({"items": [{"id": 1}, {"id": 2}]})
        assert result == '{"items":[{"id":1},{"id":2}]}'

    def test_array_preserves_order(self) -> None:
        # Arrays are not re-sorted; their order is significant.
        assert canonicalize_str([3, 1, 2]) == "[3,1,2]"

    def test_returns_bytes_by_default(self) -> None:
        result = canonicalize({"x": 1})
        assert isinstance(result, bytes)
        assert result == b'{"x":1}'

    def test_returns_str_via_canonicalize_str(self) -> None:
        result = canonicalize_str({"x": 1})
        assert isinstance(result, str)
        assert result == '{"x":1}'


# ─────────────────────────────────────────────────────────────────
# Group 2: Strict-mode restrictions
# ─────────────────────────────────────────────────────────────────

class TestStrictModeRestrictions:
    """Restrictions enforced when strict=True (the default)."""

    def test_floats_rejected(self) -> None:
        with pytest.raises(CanonicalizationError, match="Floating-point"):
            canonicalize({"x": 1.5})

    def test_negative_float_rejected(self) -> None:
        with pytest.raises(CanonicalizationError, match="Floating-point"):
            canonicalize({"x": -0.1})

    def test_zero_float_rejected(self) -> None:
        # 0.0 is a float; reject like any other float for consistency.
        with pytest.raises(CanonicalizationError, match="Floating-point"):
            canonicalize({"x": 0.0})

    def test_nan_rejected(self) -> None:
        with pytest.raises(CanonicalizationError, match="NaN"):
            canonicalize({"x": float("nan")})

    def test_positive_infinity_rejected(self) -> None:
        with pytest.raises(CanonicalizationError, match="Infinity"):
            canonicalize({"x": float("inf")})

    def test_negative_infinity_rejected(self) -> None:
        with pytest.raises(CanonicalizationError, match="Infinity"):
            canonicalize({"x": float("-inf")})

    def test_ijson_max_safe_int_accepted(self) -> None:
        # 2^53 - 1 is the largest integer that round-trips through IEEE 754
        # double-precision; I-JSON allows it.
        result = canonicalize_str({"x": IJSON_MAX_SAFE_INT})
        assert result == '{"x":9007199254740991}'

    def test_ijson_min_safe_int_accepted(self) -> None:
        result = canonicalize_str({"x": IJSON_MIN_SAFE_INT})
        assert result == '{"x":-9007199254740991}'

    def test_oversized_positive_int_rejected(self) -> None:
        # 2^53 is one above the safe range.
        with pytest.raises(CanonicalizationError, match="I-JSON"):
            canonicalize({"x": 2**53})

    def test_oversized_negative_int_rejected(self) -> None:
        with pytest.raises(CanonicalizationError, match="I-JSON"):
            canonicalize({"x": -(2**53)})

    def test_very_large_int_rejected(self) -> None:
        with pytest.raises(CanonicalizationError, match="I-JSON"):
            canonicalize({"x": 10**100})

    def test_non_utf8_string_rejected(self) -> None:
        # Lone surrogate cannot encode to UTF-8.
        lone_surrogate = "\ud800"
        with pytest.raises(CanonicalizationError, match="UTF-8"):
            canonicalize({"x": lone_surrogate})

    def test_non_utf8_key_rejected(self) -> None:
        lone_surrogate = "\ud800"
        with pytest.raises(CanonicalizationError, match="UTF-8"):
            canonicalize({lone_surrogate: 1})

    def test_unsupported_type_rejected(self) -> None:
        # Tuples, sets, custom objects, etc. are not JSON-representable.
        with pytest.raises(CanonicalizationError, match="Unsupported type"):
            canonicalize({"x": {1, 2, 3}})  # set, not JSON

    def test_duplicate_keys_in_json_rejected(self) -> None:
        with pytest.raises(CanonicalizationError, match="Duplicate keys"):
            canonicalize_from_json('{"a":1,"a":2}')

    def test_duplicate_keys_listed_in_error(self) -> None:
        with pytest.raises(CanonicalizationError, match=r"\['a', 'b'\]"):
            canonicalize_from_json('{"a":1,"a":2,"b":3,"b":4}')

    def test_strict_mode_is_default(self) -> None:
        # If we don't pass strict, floats should be rejected.
        with pytest.raises(CanonicalizationError):
            canonicalize({"x": 1.5})


# ─────────────────────────────────────────────────────────────────
# Group 3: Non-strict mode
# ─────────────────────────────────────────────────────────────────

class TestNonStrictMode:
    """When strict=False, delegate directly to rfc8785 without pre-validation."""

    def test_floats_accepted_non_strict(self) -> None:
        # The rfc8785 library produces a canonical form for floats per ES6
        # ToString. We just need the operation to succeed.
        result = canonicalize({"x": 1.5}, strict=False)
        assert isinstance(result, bytes)
        # Parse the result back; the value should round-trip.
        parsed = json.loads(result.decode("utf-8"))
        assert parsed == {"x": 1.5}

    def test_non_strict_still_sorts_keys(self) -> None:
        # RFC 8785 key sorting still applies in non-strict mode.
        result = canonicalize_str({"c": 1, "a": 2, "b": 3}, strict=False)
        assert result == '{"a":2,"b":3,"c":1}'

    def test_non_strict_still_returns_utf8_bytes(self) -> None:
        result = canonicalize({"x": "hello"}, strict=False)
        assert isinstance(result, bytes)
        # Should be valid UTF-8.
        result.decode("utf-8")


# ─────────────────────────────────────────────────────────────────
# Group 4: Helper functions
# ─────────────────────────────────────────────────────────────────

class TestHelperFunctions:
    """canonicalize_str, hash_canonical, hash_canonical_hex, canonicalize_from_json."""

    def test_canonicalize_str_matches_decoded_bytes(self) -> None:
        obj = {"a": 1, "b": "two"}
        as_bytes = canonicalize(obj)
        as_str = canonicalize_str(obj)
        assert as_str == as_bytes.decode("utf-8")

    def test_hash_canonical_returns_32_bytes(self) -> None:
        result = hash_canonical({"x": 1})
        assert isinstance(result, bytes)
        assert len(result) == 32  # SHA-256 raw digest length

    def test_hash_canonical_matches_manual_sha256(self) -> None:
        obj = {"a": 1, "b": 2}
        expected = hashlib.sha256(canonicalize(obj)).digest()
        actual = hash_canonical(obj)
        assert actual == expected

    def test_hash_canonical_hex_returns_64_chars(self) -> None:
        result = hash_canonical_hex({"x": 1})
        assert isinstance(result, str)
        assert len(result) == 64
        # All lowercase hex.
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_canonical_hex_matches_hash_canonical(self) -> None:
        obj = {"x": "test"}
        assert hash_canonical_hex(obj) == hash_canonical(obj).hex()

    def test_canonicalize_from_json_round_trips(self) -> None:
        json_in = '{"b":2,"a":1}'  # not yet canonical: keys out of order
        result = canonicalize_from_json(json_in)
        # After canonicalization, keys are sorted.
        assert result == b'{"a":1,"b":2}'

    def test_canonicalize_from_json_strict_mode(self) -> None:
        # Float in source JSON should be rejected in strict mode.
        with pytest.raises(CanonicalizationError, match="Floating-point"):
            canonicalize_from_json('{"x":1.5}')

    def test_canonicalize_from_json_invalid_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            canonicalize_from_json('{"a":')


# ─────────────────────────────────────────────────────────────────
# Group 5: Error locations
# ─────────────────────────────────────────────────────────────────

class TestErrorLocations:
    """Verify JSON-Path-style error locations in CanonicalizationError messages."""

    def test_top_level_float_reports_root_path(self) -> None:
        with pytest.raises(CanonicalizationError, match=r"\$\.x"):
            canonicalize({"x": 1.5})

    def test_nested_float_reports_full_path(self) -> None:
        with pytest.raises(CanonicalizationError, match=r"\$\.a\.b"):
            canonicalize({"a": {"b": 1.5}})

    def test_array_index_in_path(self) -> None:
        with pytest.raises(CanonicalizationError, match=r"\$\.items\[2\]"):
            canonicalize({"items": [1, 2, 1.5]})

    def test_deeply_nested_path(self) -> None:
        bad = {"a": {"b": [{"c": {"d": 1.5}}]}}
        with pytest.raises(CanonicalizationError, match=r"\$\.a\.b\[0\]\.c\.d"):
            canonicalize(bad)


# ─────────────────────────────────────────────────────────────────
# Group 6: Reproducibility property
# ─────────────────────────────────────────────────────────────────

class TestReproducibility:
    """The same logical input must always produce the same canonical bytes."""

    def test_insertion_order_does_not_affect_output(self) -> None:
        a = {"x": 1, "y": 2, "z": 3}
        b = {"z": 3, "y": 2, "x": 1}
        c = {"y": 2, "x": 1, "z": 3}
        assert canonicalize(a) == canonicalize(b) == canonicalize(c)

    def test_nested_insertion_order_does_not_affect_output(self) -> None:
        a = {"a": {"x": 1, "y": 2}, "b": {"p": 3, "q": 4}}
        b = {"b": {"q": 4, "p": 3}, "a": {"y": 2, "x": 1}}
        assert canonicalize(a) == canonicalize(b)

    def test_hash_is_reproducible(self) -> None:
        a = {"act_type_id": "op:eu.nis2.art20.v1", "decision_date": "2026-05-14"}
        b = {"decision_date": "2026-05-14", "act_type_id": "op:eu.nis2.art20.v1"}
        assert hash_canonical(a) == hash_canonical(b)

    def test_separate_calls_produce_identical_bytes(self) -> None:
        obj = {"act_type_id": "op:test.v1", "decision_date": "2026-05-14"}
        results = [canonicalize(obj) for _ in range(10)]
        # All results must be identical.
        assert len(set(results)) == 1


# ─────────────────────────────────────────────────────────────────
# Group 7: I-JSON boundary parametrized tests
# ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "value, should_pass",
    [
        (0, True),
        (1, True),
        (-1, True),
        (100, True),
        (IJSON_MAX_SAFE_INT, True),
        (IJSON_MIN_SAFE_INT, True),
        (IJSON_MAX_SAFE_INT + 1, False),
        (IJSON_MIN_SAFE_INT - 1, False),
        (2**63, False),
        (-(2**63), False),
        (10**18, False),
    ],
)
def test_integer_boundary(value: int, should_pass: bool) -> None:
    """Each integer either passes strict mode or raises a clean error."""
    if should_pass:
        result = canonicalize_str({"x": value})
        assert f'"x":{value}' in result
    else:
        with pytest.raises(CanonicalizationError, match="I-JSON"):
            canonicalize({"x": value})


# ─────────────────────────────────────────────────────────────────
# Group 8: Manifest-shaped real-world examples
# ─────────────────────────────────────────────────────────────────

class TestRealisticManifests:
    """Sanity-check canonicalization on manifest shapes actproof actually uses."""

    def test_nis2_manifest_shape(self) -> None:
        manifest = {
            "act_type_id": "op:eu.nis2.art20.management_body_approval.v1",
            "issuer": {
                "org_name": "Sofia Tech Holdings AD",
                "authority_label": "Management Body",
            },
            "claim": {
                "approving_body_name": "Board of Directors",
                "decision_date": "2026-05-14",
                "approved_measures_summary": "Annual cybersecurity programme",
            },
            "evidence": [
                {
                    "label": "signed_resolution_or_minutes",
                    "filename_normalized": "minutes_2026-05-14.pdf",
                    "byte_size": 482991,
                    "mime_type": "application/pdf",
                    "sha256": "abc123" + "0" * 58,
                },
            ],
        }
        # Should canonicalise without error.
        result = canonicalize(manifest)
        assert isinstance(result, bytes)
        # Top-level keys should be sorted: act_type_id, claim, evidence, issuer.
        decoded = result.decode("utf-8")
        idx_act = decoded.index('"act_type_id"')
        idx_claim = decoded.index('"claim"')
        idx_evidence = decoded.index('"evidence"')
        idx_issuer = decoded.index('"issuer"')
        assert idx_act < idx_claim < idx_evidence < idx_issuer

    def test_eudr_manifest_with_scaled_amounts(self) -> None:
        # EUDR shipments include quantities. Use scaled integers, not floats.
        manifest = {
            "act_type_id": "op:eu.eudr.dds_preparation.v1",
            "operator_org_name": "Smart Organic AD",
            "operator_eori": "BG203456789",
            "product_commodity_codes": ["0901", "1801"],
            "quantity_kg_thousandths": 250_000_000,  # 250 tonnes in g/1000 = kg/1
        }
        result = canonicalize(manifest)
        # 250 million fits comfortably in I-JSON safe range.
        assert b'"quantity_kg_thousandths":250000000' in result

    def test_software_release_manifest(self) -> None:
        manifest = {
            "act_type_id": "op:actproof.software_release.v1",
            "release_tag": "v0.0.2",
            "released_at": "2026-05-14T16:00:00Z",
            "source_url": "https://github.com/deyan-paroushev/actproof-py",
            "git_commit": "a" * 40,
            "release_notes_sha256": "b" * 64,
        }
        result = canonicalize(manifest)
        # Verify the hash is deterministic across two calls.
        assert hash_canonical(manifest) == hash_canonical(manifest)
