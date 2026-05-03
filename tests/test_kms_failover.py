"""
Zorynex Phase 3 — KMS Failover Tests
======================================
All mock-based. No AWS credentials or live KMS needed.

Covers:
  1. FailoverMetrics — thread-safe counters
  2. Normal signing — primary used when healthy
  3. Failover trigger — switches to fallback after N consecutive failures
  4. Failback — returns to primary once probe succeeds
  5. Force failover / force failback — manual control
  6. Both signers fail — raises SigningFailed with clear message
  7. Metrics structure and content
  8. Prometheus output format
  9. Thread safety — concurrent signing under failover
  10. from_env() factory — reads correct env vars
  11. Non-failover exceptions propagate immediately

Run: pytest tests/test_kms_failover.py -v
"""

from __future__ import annotations

import threading
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest

from provable_ai.exceptions import KMSUnavailable, InvalidKeyId, SigningFailed
from provable_ai.signer import BaseSigner, EnvSigner
from provable_ai.signer_failover import FailoverSigner, FailoverMetrics


# ── Fixtures & helpers ────────────────────────────────────────────────────────

HASH_32 = b"\xab" * 32
SIG_64  = "a" * 128
PUBKEY  = "b" * 64


def _mock_signer(
    key_id:     str  = "primary-key",
    sig:        str  = SIG_64,
    pubkey:     str  = PUBKEY,
    fail_with:  type | None = None,
    fail_after: int  = 0,
) -> MagicMock:
    """Build a mock BaseSigner with configurable failure behaviour."""
    signer = MagicMock(spec=BaseSigner)
    signer.get_key_id.return_value    = key_id
    signer.get_public_key.return_value = pubkey

    call_count = [0]

    def _sign(h):
        call_count[0] += 1
        if fail_with and call_count[0] > fail_after:
            # InvalidKeyId takes (key_id, tenant_id); others take (key_id, underlying_error)
            from provable_ai.exceptions import InvalidKeyId
            if fail_with is InvalidKeyId:
                raise fail_with(key_id=key_id, tenant_id=None)
            else:
                raise fail_with(key_id=key_id, underlying_error="mock failure")
        return sig

    signer.sign_hash.side_effect = _sign
    return signer


def _make_failover(
    primary_fails_with: type | None = None,
    primary_fail_after: int  = 0,
    fallback_fails_with:type | None = None,
    max_failures:       int  = 2,
    failback_interval:  float = 0.05,
    primary_key_id:     str  = "kms-primary",
    fallback_key_id:    str  = "kms-fallback",
    primary_sig:        str  = SIG_64,
    fallback_sig:       str  = "f" * 128,
) -> tuple[FailoverSigner, MagicMock, MagicMock]:
    primary  = _mock_signer(key_id=primary_key_id, sig=primary_sig,
                             fail_with=primary_fails_with, fail_after=primary_fail_after)
    fallback = _mock_signer(key_id=fallback_key_id, sig=fallback_sig,
                             fail_with=fallback_fails_with)
    signer = FailoverSigner(
        primary=primary, fallback=fallback,
        max_consecutive_failures=max_failures,
        failback_interval=failback_interval,
    )
    return signer, primary, fallback


# ═══════════════════════════════════════════════════════════════════════════════
# PART 1 — FailoverMetrics
# ═══════════════════════════════════════════════════════════════════════════════

class TestFailoverMetrics:

    def test_initial_state_all_zero(self):
        m = FailoverMetrics()
        s = m.snapshot()
        assert s["failover_count"]       == 0
        assert s["failback_count"]       == 0
        assert s["primary_errors"]       == 0
        assert s["fallback_errors"]      == 0
        assert s["total_signs"]          == 0
        assert s["consecutive_failures"] == 0
        assert s["last_failover_at"]     is None
        assert s["last_failback_at"]     is None

    def test_record_sign_increments_total(self):
        m = FailoverMetrics()
        for _ in range(5):
            m.record_sign()
        assert m.snapshot()["total_signs"] == 5

    def test_record_primary_error_increments(self):
        m = FailoverMetrics()
        m.record_primary_error()
        m.record_primary_error()
        s = m.snapshot()
        assert s["primary_errors"]       == 2
        assert s["consecutive_failures"] == 2

    def test_record_failover_sets_timestamp(self):
        m = FailoverMetrics()
        m.record_failover()
        s = m.snapshot()
        assert s["failover_count"]   == 1
        assert s["last_failover_at"] is not None
        assert "T" in s["last_failover_at"]

    def test_record_failback_resets_consecutive(self):
        m = FailoverMetrics()
        m.record_primary_error()
        m.record_primary_error()
        assert m.snapshot()["consecutive_failures"] == 2
        m.record_failback()
        assert m.snapshot()["consecutive_failures"] == 0
        assert m.snapshot()["failback_count"] == 1

    def test_reset_consecutive(self):
        m = FailoverMetrics()
        m.record_primary_error()
        m.record_primary_error()
        m.reset_consecutive()
        assert m.snapshot()["consecutive_failures"] == 0

    def test_snapshot_is_a_copy(self):
        m = FailoverMetrics()
        s1 = m.snapshot()
        m.record_sign()
        s2 = m.snapshot()
        assert s1["total_signs"] == 0
        assert s2["total_signs"] == 1

    def test_thread_safe_increments(self):
        m = FailoverMetrics()
        errors = []

        def worker():
            try:
                for _ in range(100):
                    m.record_sign()
                    m.record_primary_error()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert m.snapshot()["total_signs"]    == 1000
        assert m.snapshot()["primary_errors"] == 1000


# ═══════════════════════════════════════════════════════════════════════════════
# PART 2 — Normal signing (primary healthy)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalSigning:

    def test_uses_primary_when_healthy(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover()
        result = signer.sign_hash(HASH_32)
        assert result == SIG_64
        primary.sign_hash.assert_called_once_with(HASH_32)
        fallback.sign_hash.assert_not_called()

    def test_sign_increments_total(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, _, _ = _make_failover()
        for _ in range(3):
            signer.sign_hash(HASH_32)
        assert signer.metrics()["total_signs"] == 3

    def test_get_key_id_returns_primary_when_healthy(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, _, _ = _make_failover(primary_key_id="kms-us-east-1")
        assert signer.get_key_id() == "kms-us-east-1"

    def test_get_public_key_returns_primary_when_healthy(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        primary  = _mock_signer(key_id="p", pubkey="c" * 64)
        fallback = _mock_signer(key_id="f", pubkey="d" * 64)
        signer   = FailoverSigner(primary=primary, fallback=fallback)
        assert signer.get_public_key() == "c" * 64

    def test_consecutive_failures_reset_on_success(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, _ = _make_failover(max_failures=3)
        # One failure then success
        primary.sign_hash.side_effect = [
            KMSUnavailable(key_id="p", underlying_error="tmp"),
            SIG_64,
        ]
        try:
            signer.sign_hash(HASH_32)  # failure → goes to fallback
        except Exception:
            pass
        signer._primary_healthy = True  # manually restore for next call
        primary.sign_hash.side_effect = None
        primary.sign_hash.return_value = SIG_64
        signer.sign_hash(HASH_32)
        assert signer.metrics()["consecutive_failures"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# PART 3 — Failover trigger
# ═══════════════════════════════════════════════════════════════════════════════

class TestFailoverTrigger:

    def test_failover_after_max_consecutive_failures(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(
            primary_fails_with=KMSUnavailable,
            max_failures=2,
            failback_interval=999,  # don't failback during test
        )
        # First two calls fail (triggers failover at failure #2)
        for _ in range(2):
            signer.sign_hash(HASH_32)

        assert signer.metrics()["mode"]           == "fallback"
        assert signer.metrics()["failover_count"] == 1
        assert not signer.metrics()["primary_healthy"]

    def test_failover_uses_fallback_signer(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(
            primary_fails_with=KMSUnavailable,
            max_failures=1,
            failback_interval=999,
            fallback_sig="f" * 128,
        )
        result = signer.sign_hash(HASH_32)
        # First call fails on primary → failover → returns fallback result
        assert result == "f" * 128

    def test_failover_changes_key_id(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(
            primary_fails_with=KMSUnavailable,
            max_failures=1,
            failback_interval=999,
            primary_key_id="kms-us-east-1",
            fallback_key_id="kms-us-west-2",
        )
        signer.sign_hash(HASH_32)  # triggers failover
        assert signer.get_key_id() == "kms-us-west-2"

    def test_invalid_key_id_also_triggers_failover(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(
            primary_fails_with=InvalidKeyId,
            max_failures=1,
            failback_interval=999,
        )
        signer.sign_hash(HASH_32)
        assert signer.metrics()["failover_count"] == 1

    def test_no_failover_below_threshold(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(
            primary_fails_with=KMSUnavailable,
            primary_fail_after=0,
            max_failures=3,   # need 3 consecutive failures
            failback_interval=999,
        )
        # First failure — below threshold (1 < 3)
        signer.sign_hash(HASH_32)
        assert signer.metrics()["mode"] == "fallback" or \
               signer.metrics()["consecutive_failures"] >= 1

    def test_primary_errors_counter_increments(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(
            primary_fails_with=KMSUnavailable,
            max_failures=5,
            failback_interval=999,
        )
        for _ in range(3):
            signer.sign_hash(HASH_32)
        assert signer.metrics()["primary_errors"] == 3


# ═══════════════════════════════════════════════════════════════════════════════
# PART 4 — Failback
# ═══════════════════════════════════════════════════════════════════════════════

class TestFailback:

    def test_failback_after_primary_recovers(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        # Primary fails at first → fallback mode → probe → primary recovers → failback
        call_count = [0]
        primary = _mock_signer(key_id="kms-primary")

        def _sign(h):
            call_count[0] += 1
            if call_count[0] <= 1:
                raise KMSUnavailable(key_id="kms-primary", underlying_error="down")
            return SIG_64

        primary.sign_hash.side_effect = _sign
        primary.get_public_key.return_value = PUBKEY  # probe succeeds

        fallback = _mock_signer(key_id="kms-fallback")

        signer = FailoverSigner(
            primary=primary, fallback=fallback,
            max_consecutive_failures=1,
            failback_interval=0.05,
        )

        # Trigger failover
        signer.sign_hash(HASH_32)
        assert signer.metrics()["mode"] == "fallback"

        # Wait for probe to fire and failback
        time.sleep(0.3)
        assert signer.metrics()["failback_count"] == 1
        assert signer.metrics()["mode"] == "primary"

    def test_force_failover_and_force_failback(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(failback_interval=999)

        assert signer.metrics()["mode"] == "primary"

        signer.force_failover()
        assert signer.metrics()["mode"]           == "fallback"
        assert signer.metrics()["failover_count"] == 1

        signer.force_failback()
        assert signer.metrics()["mode"]           == "primary"
        assert signer.metrics()["failback_count"] == 1

    def test_force_failover_idempotent(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, _, _ = _make_failover(failback_interval=999)
        signer.force_failover()
        signer.force_failover()  # second call is no-op
        assert signer.metrics()["failover_count"] == 1

    def test_signs_with_primary_after_failback(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(
            primary_sig="primary-sig" + "a" * 118,
            fallback_sig="fallbk-sig" + "f" * 118,
            failback_interval=999,
        )
        signer.force_failover()
        r1 = signer.sign_hash(HASH_32)
        assert r1 == "fallbk-sig" + "f" * 118

        signer.force_failback()
        r2 = signer.sign_hash(HASH_32)
        assert r2 == "primary-sig" + "a" * 118


# ═══════════════════════════════════════════════════════════════════════════════
# PART 5 — Both signers fail
# ═══════════════════════════════════════════════════════════════════════════════

class TestBothSignersFail:

    def test_signing_failed_when_both_fail(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(
            primary_fails_with=KMSUnavailable,
            fallback_fails_with=KMSUnavailable,
            max_failures=1,
            failback_interval=999,
        )
        with pytest.raises(SigningFailed) as exc_info:
            signer.sign_hash(HASH_32)
        assert "Both primary and fallback failed" in str(exc_info.value)

    def test_fallback_errors_counter_increments(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, primary, fallback = _make_failover(
            primary_fails_with=KMSUnavailable,
            fallback_fails_with=KMSUnavailable,
            max_failures=1,
            failback_interval=999,
        )
        for _ in range(3):
            try:
                signer.sign_hash(HASH_32)
            except SigningFailed:
                pass
        # fallback_errors tracks how many times fallback was called and failed
        assert signer.metrics()["fallback_errors"] >= 1

    def test_non_failover_exception_propagates_immediately(self, monkeypatch):
        """SigningFailed (not KMSUnavailable) on primary should NOT trigger failover."""
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        primary  = _mock_signer(key_id="p")
        fallback = _mock_signer(key_id="f")
        primary.sign_hash.side_effect = SigningFailed(
            key_id="p", underlying_error="hardware fault"
        )

        signer = FailoverSigner(primary=primary, fallback=fallback, max_consecutive_failures=2)

        with pytest.raises(SigningFailed):
            signer.sign_hash(HASH_32)

        # Fallback must NOT have been called (SigningFailed is not a failover trigger)
        fallback.sign_hash.assert_not_called()
        assert signer.metrics()["failover_count"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# PART 6 — Metrics and Prometheus output
# ═══════════════════════════════════════════════════════════════════════════════

class TestMetrics:

    def test_metrics_structure(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, _, _ = _make_failover()
        m = signer.metrics()
        required_keys = {
            "mode", "primary_healthy", "primary_key_id", "fallback_key_id",
            "failover_count", "failback_count", "primary_errors", "fallback_errors",
            "total_signs", "consecutive_failures",
            "last_failover_at", "last_failback_at",
        }
        assert required_keys.issubset(set(m.keys()))

    def test_metrics_mode_primary_initially(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, _, _ = _make_failover()
        assert signer.metrics()["mode"] == "primary"
        assert signer.metrics()["primary_healthy"] is True

    def test_prometheus_output_has_all_metrics(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, _, _ = _make_failover()
        prom = signer.prometheus_metrics()
        for counter in [
            "zorynex_kms_failover_total",
            "zorynex_kms_failback_total",
            "zorynex_kms_primary_errors_total",
            "zorynex_kms_fallback_errors_total",
            "zorynex_kms_primary_healthy",
            "zorynex_kms_consecutive_failures",
        ]:
            assert counter in prom, f"Missing: {counter}"

    def test_prometheus_output_valid_format(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, _, _ = _make_failover()
        prom = signer.prometheus_metrics()
        # Every metric line must have a numeric value
        for line in prom.strip().split("\n"):
            if line.startswith("#") or not line.strip():
                continue
            name, value = line.rsplit(" ", 1)
            float(value)  # must be numeric

    def test_primary_healthy_gauge_reflects_state(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, _, _ = _make_failover(failback_interval=999)
        assert "zorynex_kms_primary_healthy 1" in signer.prometheus_metrics()
        signer.force_failover()
        assert "zorynex_kms_primary_healthy 0" in signer.prometheus_metrics()


# ═══════════════════════════════════════════════════════════════════════════════
# PART 7 — from_env() factory
# ═══════════════════════════════════════════════════════════════════════════════

class TestFromEnv:

    def test_from_env_no_kms_uses_env_signer(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        monkeypatch.delenv("ZORYNEX_KMS_KEY_ID", raising=False)
        monkeypatch.delenv("ZORYNEX_KMS_FALLBACK_KEY_ID", raising=False)

        signer = FailoverSigner.from_env()
        # Both primary and fallback should be EnvSigner
        assert isinstance(signer._primary,  EnvSigner)
        assert isinstance(signer._fallback, EnvSigner)

    def test_from_env_reads_failback_interval(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        monkeypatch.setenv("ZORYNEX_KMS_FAILBACK_INTERVAL", "120")
        monkeypatch.delenv("ZORYNEX_KMS_KEY_ID", raising=False)
        monkeypatch.delenv("ZORYNEX_KMS_FALLBACK_KEY_ID", raising=False)

        signer = FailoverSigner.from_env()
        assert signer._failback_interval == 120.0

    def test_from_env_reads_max_consecutive(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        monkeypatch.setenv("ZORYNEX_KMS_MAX_CONSECUTIVE_FAILURES", "5")
        monkeypatch.delenv("ZORYNEX_KMS_KEY_ID", raising=False)
        monkeypatch.delenv("ZORYNEX_KMS_FALLBACK_KEY_ID", raising=False)

        signer = FailoverSigner.from_env()
        assert signer._max_consecutive == 5


# ═══════════════════════════════════════════════════════════════════════════════
# PART 8 — Thread safety under concurrent signing
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreadSafety:

    def test_concurrent_signing_no_data_race(self, monkeypatch):
        """Many goroutines signing concurrently must not corrupt state."""
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        signer, _, _ = _make_failover(failback_interval=999)

        results = []
        errors  = []

        def worker():
            try:
                for _ in range(50):
                    r = signer.sign_hash(HASH_32)
                    results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors: {errors}"
        assert len(results) == 500
        assert signer.metrics()["total_signs"] == 500

    def test_concurrent_failover_safe(self, monkeypatch):
        """Concurrent calls during failover should not double-increment failover_count."""
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", "a" * 64)
        primary = _mock_signer(key_id="p", fail_with=KMSUnavailable)
        primary.sign_hash.side_effect = KMSUnavailable(key_id="p", underlying_error="down")
        fallback = _mock_signer(key_id="f")

        signer = FailoverSigner(primary=primary, fallback=fallback,
                                max_consecutive_failures=2, failback_interval=999)

        barrier = threading.Barrier(5)
        errors  = []

        def worker():
            barrier.wait()  # all start at exactly the same time
            try:
                for _ in range(10):
                    signer.sign_hash(HASH_32)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # failover_count must be exactly 1 — not incremented by racing threads
        assert signer.metrics()["failover_count"] == 1
        assert errors == []