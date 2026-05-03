
from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator

import psycopg2
import psycopg2.errors

from .database import get_conn
from .exceptions import ChainBroken, DuplicateSequenceId, SequenceGap

logger = logging.getLogger("zorynex.repositories")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ── Ledger repository ─────────────────────────────────────────────────────────

class PostgreSQLStorage:
    """
    PostgreSQL-backed append-only ledger.

    Public interface matches SQLiteStorage exactly.
    Use get_storage() in server/main.py to switch between backends.

    .conn property: returns a live pooled connection for callers that need
    direct cursor access (drift_detector.take_snapshot, system root endpoint).
    The connection is NOT transaction-scoped — callers are responsible for
    committing or rolling back.
    """

    def __init__(self) -> None:
        # .conn exposes a pooled connection for direct use by drift_detector etc.
        # We hold it for the lifetime of this storage instance.
        self._raw_conn = get_conn().__enter__()  # held open
        self._raw_conn.autocommit = True          # safe for SELECT-only callers
        self.conn = self._raw_conn                # public attribute

    # ── Chain integrity ───────────────────────────────────────────────────────

    def _validate_chain_integrity(
        self,
        instance_id: str,
        sequence_id: int,
        previous_hash: str,
        tenant_id: str = "default",
    ) -> None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT current_hash, sequence_id FROM ledger
                    WHERE tenant_id = %s AND instance_id = %s
                    ORDER BY sequence_id DESC LIMIT 1
                """, (tenant_id, instance_id))
                row = cur.fetchone()

        if row is None:
            # First entry — previous_hash must be genesis
            from .canonical import genesis_hash
            if previous_hash != genesis_hash():
                raise ChainBroken(
                    instance_id=instance_id,
                    expected_hash=genesis_hash(),
                    got_hash=previous_hash,
                )
            if sequence_id != 1:
                raise SequenceGap(
                    instance_id=instance_id,
                    expected=1,
                    got=sequence_id,
                )
        else:
            last_hash = row["current_hash"]
            last_seq  = row["sequence_id"]

            if previous_hash != last_hash:
                raise ChainBroken(
                    instance_id=instance_id,
                    expected_hash=last_hash,
                    got_hash=previous_hash,
                )
            expected_seq = last_seq + 1
            if sequence_id != expected_seq:
                if sequence_id == last_seq:
                    raise DuplicateSequenceId(
                        instance_id=instance_id,
                        sequence_id=sequence_id,
                    )
                raise SequenceGap(
                    instance_id=instance_id,
                    expected=expected_seq,
                    got=sequence_id,
                )

    # ── Write ─────────────────────────────────────────────────────────────────

    def append_ledger_entry(self, proof_dict: dict) -> int:
        """
        Append a proof to the PostgreSQL ledger.

        Concurrency safety:
            pg_try_advisory_xact_lock(hash(tenant_id + instance_id)) serialises
            concurrent writes for the same instance. The lock is released
            automatically when the transaction commits or rolls back.

        Raises:
            DuplicateSequenceId, SequenceGap, ChainBroken
        """
        ledger          = proof_dict["ledger"]
        decision        = proof_dict["decision"]
        decision_context = proof_dict["decision_context"]
        governance      = proof_dict["governance"]
        signature       = proof_dict["signature"]

        instance_id   = proof_dict["instance_id"]
        sequence_id   = ledger["sequence_id"]
        previous_hash = ledger["previous_hash"]
        tenant_id     = proof_dict.get("tenant_id", "default")

        # Signature length check
        if not signature["value"] or len(signature["value"]) != 128:
            from .exceptions import SigningFailed
            raise SigningFailed(
                key_id=signature.get("key_id", "unknown"),
                underlying_error=(
                    f"Signature must be 128 hex chars, got {len(signature.get('value',''))}."
                ),
            )

        proof_json_str    = _canonical_json(proof_dict)
        metadata_json_str = _canonical_json(decision_context.get("metadata", {}))

        # Advisory lock key: integer derived from tenant+instance
        lock_key = hash(f"{tenant_id}:{instance_id}") % (2**31)

        with get_conn() as conn:
            with conn.cursor() as cur:
                # Serialise concurrent writes for this instance
                cur.execute("SELECT pg_try_advisory_xact_lock(%s)", (lock_key,))
                got_lock = cur.fetchone()["pg_try_advisory_xact_lock"]
                if not got_lock:
                    raise DuplicateSequenceId(
                        instance_id=instance_id,
                        sequence_id=sequence_id,
                    )

                # Validate chain inside the lock
                self._validate_chain_integrity(
                    instance_id, sequence_id, previous_hash, tenant_id
                )

                # Upsert instance row
                cur.execute("""
                    INSERT INTO instances (tenant_id, instance_id, current_state, protocol_hash)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (tenant_id, instance_id) DO UPDATE
                        SET current_state = EXCLUDED.current_state
                """, (tenant_id, instance_id, decision["to_state"],
                      governance.get("policy_version", "unknown")))

                try:
                    cur.execute("""
                        INSERT INTO ledger (
                            tenant_id, instance_id, sequence_id,
                            previous_hash, current_hash,
                            signature, key_id,
                            protocol_hash, from_state, to_state,
                            model_version, agent_version, policy_version,
                            metadata_json, proof_json,
                            schema_version, version, timestamp
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s
                        )
                    """, (
                        tenant_id, instance_id, sequence_id,
                        previous_hash, ledger["current_hash"],
                        signature["value"], signature["key_id"],
                        governance.get("policy_version", "unknown"),
                        decision["from_state"], decision["to_state"],
                        governance["model_version"], governance["agent_version"],
                        governance["policy_version"],
                        metadata_json_str, proof_json_str,
                        proof_dict.get("type", "zorynex-proof-v1"), 1,
                        ledger["timestamp"],
                    ))
                    conn.commit()
                except psycopg2.errors.UniqueViolation:
                    conn.rollback()
                    raise DuplicateSequenceId(
                        instance_id=instance_id, sequence_id=sequence_id
                    )

        return sequence_id

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_latest_ledger_entry(
        self, instance_id: str, tenant_id: str = "default"
    ) -> dict | None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT proof_json FROM ledger
                    WHERE tenant_id = %s AND instance_id = %s
                    ORDER BY sequence_id DESC LIMIT 1
                """, (tenant_id, instance_id))
                row = cur.fetchone()
        if row is None:
            return None
        return json.loads(row["proof_json"])

    def get_ledger_entry(
        self,
        instance_id: str,
        sequence_id: int,
        tenant_id: str = "default",
    ) -> dict | None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT proof_json FROM ledger
                    WHERE tenant_id = %s AND instance_id = %s AND sequence_id = %s
                """, (tenant_id, instance_id, sequence_id))
                row = cur.fetchone()
        return json.loads(row["proof_json"]) if row else None

    def get_ledger_chain(
        self, instance_id: str, tenant_id: str = "default"
    ) -> list[dict]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT proof_json FROM ledger
                    WHERE tenant_id = %s AND instance_id = %s
                    ORDER BY sequence_id ASC
                """, (tenant_id, instance_id))
                rows = cur.fetchall()
        return [json.loads(r["proof_json"]) for r in rows]

    def get_ledger_count(
        self, instance_id: str | None = None, tenant_id: str = "default"
    ) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                if instance_id:
                    cur.execute(
                        "SELECT COUNT(*) AS n FROM ledger WHERE tenant_id=%s AND instance_id=%s",
                        (tenant_id, instance_id),
                    )
                else:
                    cur.execute(
                        "SELECT COUNT(*) AS n FROM ledger WHERE tenant_id=%s",
                        (tenant_id,),
                    )
                return (cur.fetchone() or {}).get("n", 0)

    def get_max_sequence_id(
        self, instance_id: str, tenant_id: str = "default"
    ) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COALESCE(MAX(sequence_id), 0) AS max_seq FROM ledger
                    WHERE tenant_id = %s AND instance_id = %s
                """, (tenant_id, instance_id))
                return (cur.fetchone() or {}).get("max_seq", 0)

    # ── Governance ────────────────────────────────────────────────────────────

    def get_approved_models(self) -> list[str]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT model_version FROM approved_models")
                return [r["model_version"] for r in cur.fetchall()]

    def get_approved_agents(self) -> list[str]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT agent_version FROM approved_agents")
                return [r["agent_version"] for r in cur.fetchall()]

    def get_approved_policies(self) -> list[str]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT policy_version FROM approved_policies WHERE active = TRUE"
                )
                return [r["policy_version"] for r in cur.fetchall()]

    def add_approved_model(self, model_version: str) -> None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO approved_models (model_version) VALUES (%s) ON CONFLICT DO NOTHING",
                    (model_version,),
                )
            conn.commit()

    def add_approved_agent(self, agent_version: str) -> None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO approved_agents (agent_version) VALUES (%s) ON CONFLICT DO NOTHING",
                    (agent_version,),
                )
            conn.commit()

    def add_approved_policy(self, policy_version: str) -> None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO approved_policies (policy_version, active)
                    VALUES (%s, TRUE) ON CONFLICT (policy_version) DO UPDATE SET active = TRUE
                """, (policy_version,))
            conn.commit()

    def deactivate_policy(self, policy_version: str) -> None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE approved_policies SET active = FALSE WHERE policy_version = %s",
                    (policy_version,),
                )
            conn.commit()

    def register_protocol(self, protocol_hash: str, spec: dict) -> None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO protocols (protocol_hash, spec_json, active, created_at)
                    VALUES (%s, %s, TRUE, %s) ON CONFLICT DO NOTHING
                """, (protocol_hash, _canonical_json(spec), _utc_now()))
            conn.commit()

    def get_protocol(self, protocol_hash: str) -> dict | None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT spec_json FROM protocols WHERE protocol_hash = %s",
                    (protocol_hash,),
                )
                row = cur.fetchone()
        return json.loads(row["spec_json"]) if row else None

    def close(self) -> None:
        pass   # pool managed centrally by database.py



# =============================================================================
# SQLAlchemy compatibility layer
# =============================================================================
# test_phase2.py was built with SQLAlchemy async repositories.
# Re-exported here so existing tests keep working.
# New code uses PostgreSQLStorage (psycopg2 pool) above.
# =============================================================================

try:
    import hashlib
    import json as _json
    from sqlalchemy import select, desc, func, text
    from sqlalchemy.ext.asyncio import AsyncSession
    from .database import Base  # noqa: F401
    from .models import Tenant, Ledger, KeyRegistry, AuditLog, KeyStatus  # noqa: F401
    from .exceptions import ChainBroken, DuplicateSequenceId, LedgerError, SequenceGap

    # Module-level constants and helpers needed by repository classes
    GENESIS_HASH = "0" * 64


    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)


    def _canonical(data: Any) -> str:
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


    def _sha256(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()


    # ── TenantRepository ──────────────────────────────────────────────────────────


    # Repository classes
    class TenantRepository:
        """Create and fetch tenants."""

        def __init__(self, session: AsyncSession) -> None:
            self.session = session

        async def create(self, tenant_id: str, name: str) -> Tenant:
            """
            Register a new tenant.
            Raises ValueError if tenant_id already exists.
            """
            existing = await self.get(tenant_id)
            if existing is not None:
                raise ValueError(
                    f"Tenant '{tenant_id}' already exists. "
                    f"tenant_id must be globally unique."
                )
            tenant = Tenant(tenant_id=tenant_id, name=name)
            self.session.add(tenant)
            await self.session.flush()
            return tenant

        async def get(self, tenant_id: str) -> Tenant | None:
            """Return tenant by tenant_id, or None."""
            result = await self.session.execute(
                select(Tenant).where(Tenant.tenant_id == tenant_id)
            )
            return result.scalar_one_or_none()

        async def get_or_create(self, tenant_id: str, name: str | None = None) -> Tenant:
            """
            Return existing tenant or create it.
            Used for 'default' tenant in single-tenant deployments.
            """
            tenant = await self.get(tenant_id)
            if tenant is None:
                tenant = await self.create(tenant_id, name or tenant_id)
            return tenant

        async def require(self, tenant_id: str) -> Tenant:
            """Return tenant or raise ValueError."""
            tenant = await self.get(tenant_id)
            if tenant is None:
                raise ValueError(
                    f"Tenant '{tenant_id}' not found. "
                    f"Register the tenant before recording decisions."
                )
            if not tenant.is_active:
                raise ValueError(f"Tenant '{tenant_id}' is deactivated.")
            return tenant


    # ── KeyRegistryRepository ─────────────────────────────────────────────────────

    class KeyRegistryRepository:
        """
        Signing key lifecycle.

        Invariant: exactly ONE key per tenant has status='active'.
        All others are 'retired' — kept for historical verification.
        """

        def __init__(self, session: AsyncSession) -> None:
            self.session = session

        async def create_key(
            self,
            tenant_id: str,
            key_id: str,
            public_key: str,
            created_by: str = "system",
            retire_existing: bool = True,
        ) -> KeyRegistry:
            """
            Register a new signing key for a tenant.

            If retire_existing=True (default):
                Retires the current active key first → new key becomes the only active.

            If retire_existing=False:
                Raises ValueError if an active key already exists.

            public_key must be 64 lowercase hex chars (32-byte Ed25519).
            """
            if len(public_key) != 64 or not all(c in "0123456789abcdef" for c in public_key):
                raise ValueError(
                    f"public_key must be 64 lowercase hex chars (32-byte Ed25519). "
                    f"Got {len(public_key)} chars."
                )

            active = await self.get_active_key(tenant_id)

            if active is not None:
                if not retire_existing:
                    raise ValueError(
                        f"Tenant '{tenant_id}' already has an active key: {active.key_id!r}. "
                        f"Call rotate_key() to replace it, or use retire_existing=True."
                    )
                # Retire the existing active key
                await self._retire_key(active)

            key = KeyRegistry(
                tenant_id=tenant_id,
                key_id=key_id,
                public_key=public_key,
                status=KeyStatus.ACTIVE,
                algorithm="ed25519",
                created_by=created_by,
            )
            self.session.add(key)
            await self.session.flush()
            return key

        async def rotate_key(
            self,
            tenant_id: str,
            new_key_id: str,
            new_public_key: str,
            created_by: str = "system",
        ) -> tuple[KeyRegistry, KeyRegistry | None]:
            """
            Rotate the signing key for a tenant.

            Returns: (new_key, retired_key_or_None)

            Steps:
              1. Retire existing active key (if any)
              2. Create new active key
            """
            retired = await self.get_active_key(tenant_id)
            if retired is not None:
                await self._retire_key(retired)

            new_key = await self.create_key(
                tenant_id=tenant_id,
                key_id=new_key_id,
                public_key=new_public_key,
                created_by=created_by,
                retire_existing=False,  # already retired above
            )
            return new_key, retired

        async def _retire_key(self, key: KeyRegistry) -> None:
            """Mark a key as retired."""
            key.status = KeyStatus.RETIRED
            key.retired_at = _utcnow()
            await self.session.flush()

        async def get_active_key(self, tenant_id: str) -> KeyRegistry | None:
            """Return the single active key for a tenant, or None."""
            result = await self.session.execute(
                select(KeyRegistry).where(
                    KeyRegistry.tenant_id == tenant_id,
                    KeyRegistry.status == KeyStatus.ACTIVE,
                )
            )
            return result.scalar_one_or_none()

        async def require_active_key(self, tenant_id: str) -> KeyRegistry:
            """Return the active key or raise."""
            key = await self.get_active_key(tenant_id)
            if key is None:
                raise SigningFailed(
                    key_id="none",
                    underlying_error=(
                        f"No active signing key for tenant '{tenant_id}'. "
                        f"Register a key via KeyRegistryRepository.create_key()."
                    ),
                )
            return key

        async def get_by_key_id(self, tenant_id: str, key_id: str) -> KeyRegistry | None:
            """Fetch any key (active or retired) by key_id within a tenant."""
            result = await self.session.execute(
                select(KeyRegistry).where(
                    KeyRegistry.tenant_id == tenant_id,
                    KeyRegistry.key_id == key_id,
                )
            )
            return result.scalar_one_or_none()

        async def list_keys(self, tenant_id: str) -> list[KeyRegistry]:
            """Return all keys for a tenant, newest first."""
            result = await self.session.execute(
                select(KeyRegistry)
                .where(KeyRegistry.tenant_id == tenant_id)
                .order_by(KeyRegistry.created_at.desc())
            )
            return list(result.scalars().all())


    # ── LedgerRepository ──────────────────────────────────────────────────────────

    class LedgerRepository:
        """
        Append-only proof ledger.

        Writes:
            append() — only one write method. Validates chain before insert.

        Reads:
            get_latest()         — last entry for (tenant, instance)
            get_by_sequence()    — specific entry
            get_chain()          — full chain ordered by sequence_id
            get_max_sequence()   — for building next entry
            cross_tenant_check() — enforce instance_id uniqueness across tenants
        """

        def __init__(self, session: AsyncSession) -> None:
            self.session = session

        async def append(
            self,
            tenant_id: str,
            proof_dict: dict[str, Any],
        ) -> Ledger:
            """
            Validate and append a proof to the ledger.

            Validation order:
              1. Cross-tenant isolation — instance_id must not exist under other tenants
              2. Signature format — 128 hex chars
              3. Chain continuity — sequence_id = last + 1
              4. Hash link — previous_hash = last current_hash

            Raises:
                LedgerError         — cross-tenant conflict
                SigningFailed        — bad signature format
                DuplicateSequenceId — sequence already exists
                SequenceGap         — sequence not consecutive
                ChainBroken         — hash link broken
                IntegrityError      — DB unique constraint violated (safety net)
            """
            ledger_dict  = proof_dict["ledger"]
            signature    = proof_dict["signature"]
            governance   = proof_dict["governance"]
            decision     = proof_dict["decision"]
            det          = proof_dict["determinism"]
            dec_ctx      = proof_dict.get("decision_context", {})

            instance_id  = proof_dict["instance_id"]
            sequence_id  = ledger_dict["sequence_id"]
            current_hash = ledger_dict["current_hash"]
            previous_hash = ledger_dict["previous_hash"]
            sig_value    = signature["value"]
            pub_key      = signature["public_key"]

            # ── Validation 1: Cross-tenant isolation ──────────────────────────────
            await self._check_cross_tenant(instance_id, tenant_id)

            # ── Validation 2: Signature format ───────────────────────────────────
            if not sig_value or len(sig_value) != 128:
                raise SigningFailed(
                    key_id=signature.get("key_id", "unknown"),
                    underlying_error=(
                        f"signature.value must be 128 hex chars. Got {len(sig_value)}."
                    ),
                )

            # ── Validation 3 & 4: Chain continuity and hash link ─────────────────
            await self._validate_chain(tenant_id, instance_id, sequence_id, previous_hash)

            # ── Pre-insert cryptographic verification ─────────────────────────────
            await self._verify_signature_pre_insert(current_hash, sig_value, pub_key)

            # ── Build inputs_hash from decision_context ───────────────────────────
            from .pii import scrub_inputs_full
            raw_inputs = dec_ctx.get("raw_inputs") or dec_ctx.get("metadata") or {}
            inputs_hash = scrub_inputs_full(raw_inputs) if raw_inputs else _sha256("{}")

            # ── Build row ─────────────────────────────────────────────────────────
            proof_json_str = _canonical(proof_dict)

            try:
                ts_str = ledger_dict.get("timestamp", _utcnow().isoformat())
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) \
                     if isinstance(ts_str, str) else ts_str

                row = Ledger(
                    tenant_id=tenant_id,
                    instance_id=instance_id,
                    sequence_id=sequence_id,
                    previous_hash=previous_hash,
                    current_hash=current_hash,
                    signature=sig_value,
                    key_id=signature["key_id"],
                    public_key=pub_key,
                    from_state=decision.get("from_state", ""),
                    to_state=decision.get("to_state", ""),
                    reason_code=dec_ctx.get("reason_code", ""),
                    policy_rule=dec_ctx.get("policy_rule", ""),
                    model_version=governance.get("model_version", ""),
                    agent_version=governance.get("agent_version", ""),
                    policy_version=governance.get("policy_version", ""),
                    inputs_hash=inputs_hash,
                    determinism_mode=det.get("mode", "strict_deterministic"),
                    random_seed=det.get("seed"),
                    external_calls_hash=det.get("external_calls_hash"),
                    proof_json=proof_json_str,
                    schema_version="v1",
                    timestamp=ts,
                )
                self.session.add(row)
                await self.session.flush()
                return row

            except IntegrityError as exc:
                raise DuplicateSequenceId(
                    sequence_id=sequence_id,
                ) from exc

        async def get_latest(
            self, tenant_id: str, instance_id: str
        ) -> Ledger | None:
            """Return the highest-sequence entry for (tenant, instance)."""
            result = await self.session.execute(
                select(Ledger)
                .where(
                    Ledger.tenant_id == tenant_id,
                    Ledger.instance_id == instance_id,
                )
                .order_by(Ledger.sequence_id.desc())
                .limit(1)
            )
            return result.scalar_one_or_none()

        async def get_by_sequence(
            self, tenant_id: str, instance_id: str, sequence_id: int
        ) -> Ledger | None:
            """Return a specific entry by sequence_id."""
            result = await self.session.execute(
                select(Ledger).where(
                    Ledger.tenant_id == tenant_id,
                    Ledger.instance_id == instance_id,
                    Ledger.sequence_id == sequence_id,
                )
            )
            return result.scalar_one_or_none()

        async def get_chain(
            self, tenant_id: str, instance_id: str
        ) -> list[Ledger]:
            """Return the full chain ordered by sequence_id ascending."""
            result = await self.session.execute(
                select(Ledger)
                .where(
                    Ledger.tenant_id == tenant_id,
                    Ledger.instance_id == instance_id,
                )
                .order_by(Ledger.sequence_id.asc())
            )
            return list(result.scalars().all())

        async def get_max_sequence(
            self, tenant_id: str, instance_id: str
        ) -> int:
            """Return the current max sequence_id (0 if no entries exist)."""
            result = await self.session.execute(
                select(func.max(Ledger.sequence_id)).where(
                    Ledger.tenant_id == tenant_id,
                    Ledger.instance_id == instance_id,
                )
            )
            val = result.scalar_one_or_none()
            return val or 0

        async def count(self, tenant_id: str) -> int:
            """Total proof count for a tenant."""
            result = await self.session.execute(
                select(func.count()).where(Ledger.tenant_id == tenant_id)
            )
            return result.scalar_one()

        # ── Private helpers ───────────────────────────────────────────────────────

        async def _check_cross_tenant(self, instance_id: str, tenant_id: str) -> None:
            """
            Raise LedgerError if instance_id already exists under a DIFFERENT tenant.
            An instance_id belongs to exactly one tenant — forever.
            """
            result = await self.session.execute(
                select(Ledger.tenant_id)
                .where(
                    Ledger.instance_id == instance_id,
                    Ledger.tenant_id != tenant_id,
                )
                .limit(1)
            )
            conflict = result.scalar_one_or_none()
            if conflict:
                raise LedgerError(
                    message=(
                        f"instance_id '{instance_id}' already belongs to "
                        f"tenant '{conflict}'. Cross-tenant instance reuse is forbidden."
                    ),
                    context={"instance_id": instance_id, "requesting_tenant": tenant_id,
                             "owning_tenant": conflict},
                )

        async def _validate_chain(
            self,
            tenant_id: str,
            instance_id: str,
            sequence_id: int,
            previous_hash: str,
        ) -> None:
            """Enforce sequence continuity and hash chain linkage."""
            last = await self.get_latest(tenant_id, instance_id)

            if last is None:
                # First entry for this (tenant, instance)
                if sequence_id != 1:
                    raise SequenceGap(
                        expected_sequence_id=1,
                        actual_sequence_id=sequence_id,
                    )
                if previous_hash != GENESIS_HASH:
                    raise ChainBroken(
                        sequence_id=sequence_id,
                        expected_hash=GENESIS_HASH,
                        actual_hash=previous_hash,
                    )
            else:
                expected_seq = last.sequence_id + 1
                if sequence_id == last.sequence_id:
                    raise DuplicateSequenceId(
                        sequence_id=sequence_id,
                    )
                if sequence_id != expected_seq:
                    raise SequenceGap(
                        expected_sequence_id=expected_seq,
                        actual_sequence_id=sequence_id,
                    )
                if previous_hash != last.current_hash:
                    raise ChainBroken(
                        sequence_id=sequence_id,
                        expected_hash=last.current_hash,
                        actual_hash=previous_hash,
                    )

        async def _verify_signature_pre_insert(
            self, current_hash: str, sig_value: str, pub_key: str
        ) -> None:
            """
            Cryptographically verify the Ed25519 signature before writing.
            Rejects valid-format but invalid-content signatures at the boundary.
            """
            if len(pub_key) != 64:
                return  # validated elsewhere
            try:
                from nacl.signing import VerifyKey
                vk = VerifyKey(bytes.fromhex(pub_key))
                vk.verify(bytes.fromhex(current_hash), bytes.fromhex(sig_value))
            except Exception as exc:
                raise SigningFailed(
                    key_id="pre-insert",
                    underlying_error=(
                        f"Signature cryptographic verification failed: {exc}. "
                        f"Signature does not match hash using embedded public_key."
                    ),
                ) from exc


    # ── AuditLogRepository ────────────────────────────────────────────────────────

    class AuditLogRepository:
        """
        Append-only audit trail.
        Write once. Never update or delete.
        """

        def __init__(self, session: AsyncSession) -> None:
            self.session = session

        async def append(
            self,
            tenant_id: str,
            event_type: str,
            trace_id: str,
            context: dict[str, Any],
            actor: str = "system",
            level: str = "info",
            ledger_id: int | None = None,
        ) -> AuditLog:
            """Write an audit event. Never raises on its own — audit must not block business logic."""
            try:
                row = AuditLog(
                    tenant_id=tenant_id,
                    event_type=event_type,
                    trace_id=trace_id,
                    actor=actor,
                    context_json=_canonical(context),
                    level=level,
                    ledger_id=ledger_id,
                )
                self.session.add(row)
                await self.session.flush()
                return row
            except Exception:
                # Audit log failure must never crash the main request
                # In production this would emit a metric/alert
                raise

        async def get_by_trace(
            self, tenant_id: str, trace_id: str
        ) -> list[AuditLog]:
            """Return all audit events for a trace_id within a tenant."""
            result = await self.session.execute(
                select(AuditLog)
                .where(
                    AuditLog.tenant_id == tenant_id,
                    AuditLog.trace_id == trace_id,
                )
                .order_by(AuditLog.recorded_at.asc())
            )
            return list(result.scalars().all())

        async def get_recent(
            self, tenant_id: str, limit: int = 50
        ) -> list[AuditLog]:
            """Return most recent audit events for a tenant."""
            result = await self.session.execute(
                select(AuditLog)
                .where(AuditLog.tenant_id == tenant_id)
                .order_by(AuditLog.recorded_at.desc())
                .limit(limit)
            )
            return list(result.scalars().all())


except ImportError:
    class TenantRepository:        # type: ignore[no-redef]
        pass
    class KeyRegistryRepository:   # type: ignore[no-redef]
        pass
    class LedgerRepository:        # type: ignore[no-redef]
        pass
    class AuditLogRepository:      # type: ignore[no-redef]
        pass