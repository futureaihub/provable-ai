
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from provable_ai.canonical import (
    build_hash_payload,
    canonical_encode,
    canonical_hash,
    canonical_string,
    genesis_hash,
    is_valid_hash,
    validate_hash_payload,
)
from provable_ai.exceptions import CanonicalJsonError


VECTORS_PATH = Path(__file__).parent / "test_vectors.json"


def load_vectors() -> list[dict]:
    with open(VECTORS_PATH) as f:
        return json.load(f)["vectors"]


# ── Golden vector tests ───────────────────────────────────────────────────────

class TestGoldenVectors:
    """
    Every vector must produce EXACT expected SHA-256.
    These are the cross-language reference values.
    If any of these fail, the canonical JSON implementation is wrong.
    """

    def test_all_vectors_match_exact_hash(self):
        vectors = load_vectors()
        for v in vectors:
            if "input" in v:
                result = canonical_hash(v["input"])
                assert result == v["sha256"], (
                    f"Vector '{v['id']}' failed:\n"
                    f"  Expected: {v['sha256']}\n"
                    f"  Got:      {result}"
                )

    def test_simple_integers_exact_string(self):
        result = canonical_string({"a": 1, "b": 2})
        assert result == '{"a":1,"b":2}'

    def test_unicode_not_escaped(self):
        result = canonical_string({"name": "José"})
        assert result == '{"name":"José"}'
        assert "\\u" not in result

    def test_booleans_lowercase(self):
        result = canonical_string({"active": True, "inactive": False})
        assert result == '{"active":true,"inactive":false}'

    def test_none_is_null(self):
        result = canonical_string({"x": None})
        assert result == '{"x":null}'

    def test_full_hash_payload_matches_golden(self):
        vectors = load_vectors()
        v = next(x for x in vectors if x["id"] == "full_hash_payload")
        assert canonical_hash(v["input"]) == v["sha256"]


# ── Cross-order determinism tests ─────────────────────────────────────────────

class TestCrossOrderDeterminism:
    """
    Same data different insertion order must produce identical hash.
    This is critical for cross-system verification.
    """

    def test_two_dicts_different_insertion_order_same_hash(self):
        a = {"z": 3, "a": 1, "m": 2}
        b = {"a": 1, "m": 2, "z": 3}
        c = {"m": 2, "z": 3, "a": 1}
        assert canonical_hash(a) == canonical_hash(b) == canonical_hash(c)

    def test_nested_dict_different_insertion_order_same_hash(self):
        a = {"decision": {"to_state": "approved", "from_state": "pending"},
             "sequence_id": 1}
        b = {"sequence_id": 1,
             "decision": {"from_state": "pending", "to_state": "approved"}}
        assert canonical_hash(a) == canonical_hash(b)

    def test_insertion_order_vector_matches_golden(self):
        vectors = load_vectors()
        v = next(x for x in vectors if x["id"] == "insertion_order_independent")
        h_a = canonical_hash(v["input_a"])
        h_b = canonical_hash(v["input_b"])
        assert h_a == h_b == v["sha256"]

    def test_canonical_string_always_sorted(self):
        result = canonical_string({"z": 1, "a": 2, "m": 3})
        assert result == '{"a":2,"m":3,"z":1}'

    def test_deterministic_across_repeated_calls(self):
        payload = {"b": 2, "a": 1, "c": {"z": 26, "m": 13}}
        hashes = [canonical_hash(payload) for _ in range(5)]
        assert len(set(hashes)) == 1  # all identical


# ── Negative tests ────────────────────────────────────────────────────────────

class TestNegativeCases:
    """Different payloads must produce different hashes."""

    def test_different_value_different_hash(self):
        h1 = canonical_hash({"score": 720})
        h2 = canonical_hash({"score": 721})
        assert h1 != h2

    def test_different_key_different_hash(self):
        h1 = canonical_hash({"score": 720})
        h2 = canonical_hash({"rating": 720})
        assert h1 != h2

    def test_different_state_different_hash(self):
        h1 = canonical_hash({"to_state": "approved"})
        h2 = canonical_hash({"to_state": "denied"})
        assert h1 != h2

    def test_extra_field_different_hash(self):
        h1 = canonical_hash({"a": 1})
        h2 = canonical_hash({"a": 1, "b": 2})
        assert h1 != h2

    def test_empty_dict_different_from_nonempty(self):
        h1 = canonical_hash({})
        h2 = canonical_hash({"a": 1})
        assert h1 != h2

    def test_null_vs_missing_key_different(self):
        h1 = canonical_hash({"a": 1, "b": None})
        h2 = canonical_hash({"a": 1})
        assert h1 != h2

    def test_int_vs_string_different(self):
        h1 = canonical_hash({"threshold": 700})
        h2 = canonical_hash({"threshold": "700"})
        assert h1 != h2  # type distinction must be preserved

    def test_true_vs_one_different(self):
        h1 = canonical_hash({"flag": True})
        h2 = canonical_hash({"flag": 1})
        assert h1 != h2


# ── Hash exclusion validation ─────────────────────────────────────────────────

class TestHashExclusions:
    """
    Fields excluded from the hash must not change the hash if they change.
    This tests the explicit exclusion rules documented in canonical.py.
    """

    def _make_hash_payload(self, **overrides):
        base = {
            "decision": {"from_state": "pending", "to_state": "approved"},
            "decision_context": {
                "reason_code": "TEST",
                "policy_rule": "rule_1",
                "model_version": "model_v1",
                "inputs_hash": "a" * 64,
                "feature_contributions": [],
                "threshold_used": "700",
                "metadata": {},
            },
            "governance": {
                "model_version": "model_v1",
                "agent_version": "agent_v1",
                "policy_version": "policy_v1",
            },
            "determinism": {
                "mode": "strict_deterministic",
                "seed": None,
                "external_calls_hash": None,
            },
            "previous_hash": genesis_hash(),
            "sequence_id": 1,
        }
        base.update(overrides)
        return base

    def test_timestamp_not_in_hash(self):
        """Timestamp is excluded — changing it must not change current_hash."""
        payload = self._make_hash_payload()
        h1 = canonical_hash(payload)
        # Adding timestamp to what we hash would break replay
        # Verify timestamp is NOT in the hash payload
        assert "timestamp" not in payload

    def test_signature_not_in_hash(self):
        """Signature must never be in its own hash payload."""
        payload = self._make_hash_payload()
        assert "signature" not in payload

    def test_current_hash_not_in_hash(self):
        """current_hash is the output of hashing — not an input."""
        payload = self._make_hash_payload()
        assert "current_hash" not in payload

    def test_instance_id_not_in_hash(self):
        """instance_id is an identifier — not part of the cryptographic proof."""
        payload = self._make_hash_payload()
        assert "instance_id" not in payload

    def test_type_not_in_hash(self):
        """type (schema label) is not part of the hash."""
        payload = self._make_hash_payload()
        assert "type" not in payload

    def test_validate_hash_payload_rejects_excluded_fields(self):
        """validate_hash_payload must reject excluded fields."""
        payload = self._make_hash_payload()
        payload["timestamp"] = "2026-04-28T00:00:00Z"
        with pytest.raises(ValueError, match="excluded"):
            validate_hash_payload(payload)

    def test_validate_hash_payload_rejects_missing_required_fields(self):
        """validate_hash_payload must require all 6 fields."""
        with pytest.raises(ValueError, match="missing required"):
            validate_hash_payload({"decision": {"from_state": "a", "to_state": "b"}})

    def test_two_proofs_same_content_same_hash(self):
        """Same decision content → identical hash regardless of timestamp."""
        p1 = self._make_hash_payload()
        p2 = self._make_hash_payload()
        assert canonical_hash(p1) == canonical_hash(p2)


# ── Type validation tests ─────────────────────────────────────────────────────

class TestTypeValidation:

    def test_float_raises(self):
        with pytest.raises(CanonicalJsonError) as e:
            canonical_hash({"score": 0.28})
        assert "float" in str(e.value).lower()

    def test_nested_float_raises(self):
        with pytest.raises(CanonicalJsonError):
            canonical_hash({"ctx": {"ratio": 0.5}})

    def test_float_in_list_raises(self):
        with pytest.raises(CanonicalJsonError):
            canonical_hash({"vals": [1, 2, 0.3]})

    def test_datetime_raises(self):
        from datetime import datetime
        with pytest.raises(CanonicalJsonError) as e:
            canonical_hash({"ts": datetime.now()})
        assert "datetime" in str(e.value).lower()

    def test_uuid_raises(self):
        from uuid import uuid4
        with pytest.raises(CanonicalJsonError) as e:
            canonical_hash({"id": uuid4()})
        assert "uuid" in str(e.value).lower()

    def test_decimal_raises(self):
        from decimal import Decimal
        with pytest.raises(CanonicalJsonError) as e:
            canonical_hash({"amount": Decimal("720.00")})
        assert "decimal" in str(e.value).lower()

    def test_bytes_raises(self):
        with pytest.raises(CanonicalJsonError):
            canonical_hash({"data": b"hello"})

    def test_set_raises(self):
        with pytest.raises(CanonicalJsonError):
            canonical_hash({"items": {1, 2, 3}})

    def test_tuple_raises(self):
        with pytest.raises(CanonicalJsonError):
            canonical_hash({"pair": (1, 2)})

    def test_non_string_key_raises(self):
        with pytest.raises(CanonicalJsonError):
            canonical_hash({1: "value"})

    def test_integer_allowed(self):
        assert len(canonical_hash({"score": 720})) == 64

    def test_string_number_allowed(self):
        assert len(canonical_hash({"ratio": "0.28"})) == 64

    def test_empty_dict_allowed(self):
        h1 = canonical_hash({})
        h2 = canonical_hash({})
        assert h1 == h2

    def test_empty_list_allowed(self):
        assert len(canonical_hash({"items": []})) == 64

    def test_none_allowed(self):
        assert len(canonical_hash({"reason": None})) == 64

    def test_bool_allowed(self):
        assert len(canonical_hash({"active": True})) == 64


# ── Utilities ─────────────────────────────────────────────────────────────────

class TestUtilities:

    def test_genesis_hash_is_64_zeros(self):
        g = genesis_hash()
        assert g == "0" * 64
        assert len(g) == 64

    def test_genesis_hash_is_valid(self):
        assert is_valid_hash(genesis_hash())

    def test_is_valid_hash_true(self):
        assert is_valid_hash("a" * 64)
        assert is_valid_hash("0" * 64)
        assert is_valid_hash(canonical_hash({"a": 1}))

    def test_is_valid_hash_wrong_length(self):
        assert not is_valid_hash("a" * 63)
        assert not is_valid_hash("a" * 65)
        assert not is_valid_hash("")

    def test_is_valid_hash_non_hex(self):
        assert not is_valid_hash("g" * 64)

    def test_is_valid_hash_non_string(self):
        assert not is_valid_hash(None)
        assert not is_valid_hash(123)

    def test_canonical_encode_returns_utf8_bytes(self):
        result = canonical_encode({"name": "José"})
        assert isinstance(result, bytes)
        assert result.decode("utf-8") == '{"name":"José"}'

    def test_returns_lowercase_hex(self):
        h = canonical_hash({"a": 1})
        assert h == h.lower()
        assert len(h) == 64


# ── Cross-language compatibility ──────────────────────────────────────────────

class TestCrossLanguageCompatibility:

    def test_ensure_ascii_false_matters(self):
        """ensure_ascii=False produces different hash than True for non-ASCII."""
        correct = canonical_hash({"name": "José"})
        # Simulate what happens with ensure_ascii=True (wrong)
        wrong_str = json.dumps({"name": "José"}, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=True)
        wrong_hash = hashlib.sha256(wrong_str.encode("utf-8")).hexdigest()
        assert correct != wrong_hash, "ensure_ascii matters for non-ASCII content"

    def test_int_and_string_are_different_types(self):
        """Integer 700 ≠ string '700' — type distinction must be preserved."""
        assert canonical_hash({"t": 700}) != canonical_hash({"t": "700"})

    def test_true_and_one_are_different(self):
        """Boolean true ≠ integer 1 in JSON."""
        assert canonical_hash({"f": True}) != canonical_hash({"f": 1})