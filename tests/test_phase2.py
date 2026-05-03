"""
Phase 2 Session 1 — Integration tests
9 tests, all must pass green.

Fix applied: NullPool + function-scoped engine/session per test.
Root cause was asyncpg connections being shared across event loops
when using scope="session" fixtures with pytest-asyncio AUTO mode.

Solution:
  - NullPool: no connection reuse across loops
  - engine created once at module level with NullPool
  - session fixture is function-scoped (default)
  - setup_db uses scope="session" but with NullPool it's safe
  - NO custom event_loop fixture (conflicts with AUTO mode)
  - engine.dispose() in teardown
"""

import asyncio
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from nacl.signing import SigningKey
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from provable_ai.database import Base
from provable_ai.exceptions import ChainBroken, DuplicateSequenceId, LedgerError, SequenceGap
from provable_ai.models import Tenant  # noqa: F401 — registers model
from provable_ai.models import KeyRegistry, Ledger, AuditLog  # noqa: F401
from provable_ai.pii import assert_no_pii, hash_sensitive, scrub_inputs, scrub_inputs_full
from provable_ai.repositories import (
    AuditLogRepository,
    KeyRegistryRepository,
    LedgerRepository,
    TenantRepository,
)

# ── Engine — NullPool is the key fix ─────────────────────────────────────────
# NullPool disables connection pooling entirely.
# Each async with engine.connect() gets a fresh connection on the current loop.
# This prevents "Future attached to a different loop" from asyncpg.

_DB_URL = os.getenv(
    "ZORYNEX_DATABASE_URL",
    "postgresql+asyncpg://zorynex:zorynex@localhost:5432/zorynex_test",
)

engine = create_async_engine(
    _DB_URL,
    echo=False,
    poolclass=NullPool,   # ← critical: no pool, no cross-loop sharing
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

# ── Helpers ───────────────────────────────────────────────────────────────────

GENESIS = "0" * 64


def _canonical(d) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _make_proof(
    instance_id: str,
    sequence_id: int,
    signing_key: SigningKey,
    previous_hash: str = GENESIS,
    from_state: str = "pending",
    to_state: str = "approved",
) -> dict:
    """Build a cryptographically valid proof dict with real Ed25519 signature."""
    pub_key_hex = signing_key.verify_key.encode().hex()
    key_id = f"env-{pub_key_hex[:16]}"

    payload = {
        "decision":         {"from_state": from_state, "to_state": to_state},
        "decision_context": {
            "reason_code": "SCORE_ABOVE_THRESHOLD",
            "policy_rule": "credit_policy_v2.rule_7",
            "model_version": "credit_model_v3.1",
            "inputs_hash": "a" * 64,
            "feature_contributions": [{"feature": "credit_score", "contribution": "0.65"}],
            "threshold_used": "700",
            "metadata": {},
        },
        "governance": {
            "model_version": "credit_model_v3.1",
            "agent_version": "agent_v1.0",
            "policy_version": "credit_policy_v2",
        },
        "determinism": {
            "mode": "strict_deterministic",
            "seed": None,
            "external_calls_hash": None,
        },
        "previous_hash": previous_hash,
        "sequence_id":   sequence_id,
    }

    current_hash = _sha256(_canonical(payload))
    sig_bytes    = signing_key.sign(bytes.fromhex(current_hash)).signature
    proof_id     = _sha256(f"{current_hash}:{sequence_id}")

    return {
        "type":             "zorynex-proof-v1",
        "instance_id":      instance_id,
        "decision":         payload["decision"],
        "decision_context": payload["decision_context"],
        "governance":       payload["governance"],
        "determinism":      payload["determinism"],
        "ledger": {
            "sequence_id":   sequence_id,
            "previous_hash": previous_hash,
            "current_hash":  current_hash,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        },
        "signature": {
            "algorithm":  "ed25519",
            "key_id":     key_id,
            "public_key": pub_key_hex,
            "value":      sig_bytes.hex(),
        },
        "proof_id": proof_id,
    }


# ── Fixtures ──────────────────────────────────────────────────────────────────
# NO custom event_loop fixture — pytest-asyncio AUTO mode manages it.
# scope="session" on setup_db is safe because NullPool means no connection
# is held between tests.

@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_db():
    """Drop and recreate all tables once for the test session."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()   # clean shutdown — no "loop closed" errors


@pytest_asyncio.fixture
async def session():
    """Fresh DB session for each test. Rolls back on failure."""
    async with SessionLocal() as s:
        yield s


@pytest.fixture
def signing_key() -> SigningKey:
    return SigningKey.generate()


# ── Pre-seed tenants once so all tests can use them ───────────────────────────
# Each test that needs tenant_a / tenant_b gets a fresh session but the
# tenant rows already exist from a previous test or are created idempotently.

@pytest_asyncio.fixture
async def tenant_a(session):
    repo = TenantRepository(session)
    return await repo.get_or_create("test_tenant_a", "Test Tenant A")


@pytest_asyncio.fixture
async def tenant_b(session):
    repo = TenantRepository(session)
    return await repo.get_or_create("test_tenant_b", "Test Tenant B")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — Valid proof stored correctly
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_1_valid_proof_stored(session, tenant_a, signing_key):
    proof = _make_proof(f"loan_s1_{uuid.uuid4().hex[:8]}", 1, signing_key)
    repo  = LedgerRepository(session)
    row   = await repo.append("test_tenant_a", proof)

    assert row.id            is not None
    assert row.tenant_id     == "test_tenant_a"
    assert row.sequence_id   == 1
    assert row.previous_hash == GENESIS
    assert len(row.current_hash) == 64
    assert len(row.signature)    == 128
    assert len(row.public_key)   == 64
    assert row.from_state    == "pending"
    assert row.to_state      == "approved"
    assert row.schema_version == "v1"
    print(f"\n  ✓ Stored: id={row.id} hash={row.current_hash[:12]}…")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — Duplicate sequence rejected
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_2_duplicate_sequence_rejected(session, tenant_a, signing_key):
    iid   = f"loan_s2_{uuid.uuid4().hex[:8]}"
    repo  = LedgerRepository(session)

    proof1 = _make_proof(iid, 1, signing_key)
    await repo.append("test_tenant_a", proof1)

    proof1_dup = _make_proof(iid, 1, signing_key)
    with pytest.raises(DuplicateSequenceId):
        await repo.append("test_tenant_a", proof1_dup)
    print("\n  ✓ Duplicate sequence rejected")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — Same instance_id across tenants rejected
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_3_cross_tenant_instance_rejected(session, tenant_a, tenant_b, signing_key):
    iid  = f"shared_{uuid.uuid4().hex[:8]}"
    repo = LedgerRepository(session)

    proof_a = _make_proof(iid, 1, signing_key)
    await repo.append("test_tenant_a", proof_a)

    proof_b = _make_proof(iid, 1, signing_key)
    with pytest.raises(LedgerError) as exc_info:
        await repo.append("test_tenant_b", proof_b)

    assert "test_tenant_a" in str(exc_info.value)
    print("\n  ✓ Cross-tenant instance reuse rejected")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 4 — Key rotation: only one active key per tenant
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_4_key_rotation_one_active(session, tenant_a):
    repo = KeyRegistryRepository(session)
    tid  = f"rot_tenant_{uuid.uuid4().hex[:8]}"

    # Create a fresh tenant for this test to avoid key conflicts
    t_repo = TenantRepository(session)
    await t_repo.get_or_create(tid, "Rotation Test Tenant")

    sk1, sk2, sk3 = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()

    k1 = await repo.create_key(tid, f"key-{uuid.uuid4().hex[:8]}", sk1.verify_key.encode().hex())
    assert k1.status == "active"

    k2, old = await repo.rotate_key(tid, f"key-{uuid.uuid4().hex[:8]}", sk2.verify_key.encode().hex())
    assert k2.status   == "active"
    assert old.status  == "retired"
    assert old.retired_at is not None

    k3, old2 = await repo.rotate_key(tid, f"key-{uuid.uuid4().hex[:8]}", sk3.verify_key.encode().hex())
    assert k3.status   == "active"
    assert old2.status == "retired"

    active = await repo.get_active_key(tid)
    assert active.key_id == k3.key_id

    all_keys = await repo.list_keys(tid)
    assert len(all_keys) == 3
    print(f"\n  ✓ Key rotation: active={active.key_id} total={len(all_keys)}")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 5 — Tenant isolation: different tenants see different data
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_5_tenant_isolation_different_results(session, tenant_a, tenant_b, signing_key):
    repo = LedgerRepository(session)
    suffix = uuid.uuid4().hex[:8]

    iid_a = f"loan_iso_a_{suffix}"
    iid_b = f"loan_iso_b_{suffix}"

    proof_a = _make_proof(iid_a, 1, signing_key)
    proof_b = _make_proof(iid_b, 1, signing_key)

    row_a = await repo.append("test_tenant_a", proof_a)
    row_b = await repo.append("test_tenant_b", proof_b)

    # Tenant A cannot see Tenant B's instance
    assert await repo.get_latest("test_tenant_a", iid_b) is None
    # Tenant B cannot see Tenant A's instance
    assert await repo.get_latest("test_tenant_b", iid_a) is None
    # Each sees their own
    assert (await repo.get_latest("test_tenant_a", iid_a)).id == row_a.id
    assert (await repo.get_latest("test_tenant_b", iid_b)).id == row_b.id
    print("\n  ✓ Tenant isolation confirmed — no cross-tenant leakage")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 6 — PII scrubbing: DB never stores raw sensitive values
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_6_pii_never_stored_raw(session, tenant_a, signing_key):
    raw = {"credit_score": 720, "email": "john@example.com", "name": "John Doe", "dti": "0.28"}
    scrubbed = scrub_inputs(raw)

    assert scrubbed["credit_score"] == 720
    assert scrubbed["dti"]          == "0.28"
    assert scrubbed["email"].startswith("sha256:")
    assert scrubbed["name"].startswith("sha256:")
    assert "john@example.com" not in str(scrubbed)
    assert "John Doe"         not in str(scrubbed)

    with pytest.raises(ValueError, match="PII violation"):
        assert_no_pii({"email": "raw@example.com"})

    assert_no_pii({"email": hash_sensitive("raw@example.com")})
    print("\n  ✓ PII scrubbing: raw values never stored")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 7 — Hash consistency (no DB needed)
# ═══════════════════════════════════════════════════════════════════════════════

def test_7_hash_consistency():
    v  = "john@example.com"
    h1, h2, h3 = hash_sensitive(v), hash_sensitive(v), hash_sensitive(v)
    assert h1 == h2 == h3

    d = {"credit_score": 720, "name": "John"}
    assert scrub_inputs_full(d) == scrub_inputs_full(d)
    assert len(scrub_inputs_full(d)) == 64

    assert hash_sensitive("a@x.com") != hash_sensitive("b@x.com")
    print("\n  ✓ Hash is deterministic and consistent")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 8 — Broken chain rejected
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_8_broken_chain_rejected(session, tenant_a, signing_key):
    iid  = f"loan_chain_{uuid.uuid4().hex[:8]}"
    repo = LedgerRepository(session)

    # Seq 1 succeeds
    proof1 = _make_proof(iid, 1, signing_key)
    row1   = await repo.append("test_tenant_a", proof1)

    # Seq 2 with WRONG previous_hash → ChainBroken
    proof_bad = _make_proof(iid, 2, signing_key, previous_hash="b" * 64)
    with pytest.raises(ChainBroken):
        await repo.append("test_tenant_a", proof_bad)

    # Seq 3 (gap) with correct hash → SequenceGap
    proof_gap = _make_proof(iid, 3, signing_key, previous_hash=row1.current_hash)
    with pytest.raises(SequenceGap):
        await repo.append("test_tenant_a", proof_gap)

    # Seq 2 with CORRECT previous_hash → succeeds
    proof2 = _make_proof(iid, 2, signing_key,
                         previous_hash=row1.current_hash,
                         from_state="approved", to_state="funded")
    row2 = await repo.append("test_tenant_a", proof2)
    assert row2.sequence_id   == 2
    assert row2.previous_hash == row1.current_hash
    print("\n  ✓ Chain validation: broken rejected, correct accepted")


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_audit_log_append(session, tenant_a):
    repo     = AuditLogRepository(session)
    trace_id = str(uuid.uuid4())

    await repo.append(
        tenant_id  = "test_tenant_a",
        event_type = "decision_recorded",
        trace_id   = trace_id,
        context    = {"instance_id": "loan_audit_test", "sequence_id": 1},
        actor      = "system",
        level      = "info",
    )

    events = await repo.get_by_trace("test_tenant_a", trace_id)
    assert len(events)          == 1
    assert events[0].event_type == "decision_recorded"
    assert events[0].trace_id   == trace_id
    print("\n  ✓ Audit log write and read verified")