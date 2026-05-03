"""
Zorynex — Data Models
======================
Every table has tenant_id. No exceptions.

Tables:
    Tenant      — registered tenants
    KeyRegistry — signing keys per tenant (one active at a time)
    Ledger      — append-only proof chain
    AuditLog    — immutable record of all system actions

Critical constraints (enforced at DB level):
    UNIQUE(tenant_id, instance_id, sequence_id)  — no duplicate entries
    UNIQUE(tenant_id, instance_id, current_hash) — no hash collision
    CHECK(sequence_id >= 1)
    CHECK(length(current_hash) = 64)
    CHECK(length(signature) = 128)
    CHECK(previous_hash = genesis OR length = 64)
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


# ── Helpers ────────────────────────────────────────────────────────────────────

GENESIS_HASH = "0" * 64


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ── Tenant ─────────────────────────────────────────────────────────────────────

class Tenant(Base):
    """
    A registered tenant (organisation / business unit).
    Every record in the system belongs to exactly one tenant.
    """
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    tenant_id: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True,
        comment="Public tenant identifier — used in headers and queries"
    )
    name: Mapped[str] = mapped_column(
        String(256), nullable=False,
        comment="Human-readable tenant name"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=_utcnow, server_default=func.now(),
        onupdate=_utcnow
    )

    # Relationships
    keys: Mapped[list["KeyRegistry"]] = relationship(
        "KeyRegistry", back_populates="tenant", cascade="all, delete-orphan"
    )
    ledger_entries: Mapped[list["Ledger"]] = relationship(
        "Ledger", back_populates="tenant", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", back_populates="tenant", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Tenant {self.tenant_id!r} active={self.is_active}>"


# ── KeyRegistry ────────────────────────────────────────────────────────────────

class KeyStatus(str):
    ACTIVE   = "active"
    RETIRED  = "retired"


class KeyRegistry(Base):
    """
    Ed25519 signing keys per tenant.

    Rules:
        - Exactly ONE key per tenant may have status='active' at any time
        - Rotation: set old key to 'retired', insert new key as 'active'
        - Retired keys are kept for historical proof verification
        - Raw private keys are NEVER stored here

    The DB constraint (tenant_id, status='active') uniqueness is enforced
    in application logic (see KeyRegistryRepository.rotate_key).
    PostgreSQL partial unique index handles this at DB level.
    """
    __tablename__ = "key_registry"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    tenant_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    key_id: Mapped[str] = mapped_column(
        String(128), nullable=False,
        comment="Public key identifier — embedded in proof.signature.key_id"
    )
    public_key: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="Ed25519 public key — 64 lowercase hex chars (32 bytes)"
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=KeyStatus.ACTIVE,
        comment="active | retired"
    )
    algorithm: Mapped[str] = mapped_column(
        String(16), nullable=False, default="ed25519", server_default="ed25519"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=_utcnow, server_default=func.now()
    )
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[str] = mapped_column(
        String(128), nullable=False, default="system",
        comment="Who created this key (trace_id or admin_id)"
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="keys")

    __table_args__ = (
        CheckConstraint("status IN ('active', 'retired')", name="ck_key_status"),
        CheckConstraint("algorithm = 'ed25519'", name="ck_key_algorithm"),
        CheckConstraint("length(public_key) = 64", name="ck_key_public_key_len"),
        # Unique active key per tenant — enforced by partial unique index in migration
        UniqueConstraint("tenant_id", "key_id", name="uq_key_registry_tenant_key_id"),
        Index("ix_key_registry_tenant_status", "tenant_id", "status"),
    )

    def __repr__(self) -> str:
        return f"<KeyRegistry {self.key_id!r} tenant={self.tenant_id!r} status={self.status!r}>"


# ── Ledger ─────────────────────────────────────────────────────────────────────

class Ledger(Base):
    """
    Append-only proof chain.

    One row = one proof artifact.
    The hash chain links rows within (tenant_id, instance_id).

    Critical constraints:
        UNIQUE(tenant_id, instance_id, sequence_id)  — no replay
        UNIQUE(tenant_id, instance_id, current_hash) — no duplication
        sequence_id >= 1
        current_hash: 64 hex chars (SHA-256)
        signature:   128 hex chars (Ed25519)
        previous_hash: genesis (64 zeros) or 64 hex chars

    Rows are NEVER updated or deleted.
    PostgreSQL row-level security may be added in Phase 3.
    """
    __tablename__ = "ledger"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # Tenant isolation — EVERY row scoped to tenant
    tenant_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False, index=True,
        comment="Tenant that owns this proof"
    )

    # Chain identity
    instance_id: Mapped[str] = mapped_column(
        String(256), nullable=False,
        comment="Business entity ID (e.g. loan_9284)"
    )
    sequence_id: Mapped[int] = mapped_column(
        Integer, nullable=False,
        comment="Monotonically increasing within (tenant_id, instance_id)"
    )

    # Hash chain
    previous_hash: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="current_hash of prior proof, or genesis (64 zeros)"
    )
    current_hash: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="SHA-256 of canonical JSON payload"
    )

    # Signature
    signature: Mapped[str] = mapped_column(
        String(128), nullable=False,
        comment="Ed25519 signature of hash bytes — 128 lowercase hex chars"
    )
    key_id: Mapped[str] = mapped_column(
        String(128), nullable=False,
        comment="key_registry.key_id used to sign"
    )
    public_key: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="Ed25519 public key embedded for self-contained verification"
    )

    # Decision metadata
    from_state: Mapped[str] = mapped_column(String(128), nullable=False)
    to_state: Mapped[str] = mapped_column(String(128), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(256), nullable=False)
    policy_rule: Mapped[str] = mapped_column(String(256), nullable=False)

    # Governance — version-locked at decision time
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False)

    # Inputs — PII hashed before storage (see Step 7)
    inputs_hash: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="SHA-256(canonical_json(raw_inputs)) — raw inputs never stored"
    )

    # Determinism
    determinism_mode: Mapped[str] = mapped_column(
        String(64), nullable=False, default="strict_deterministic"
    )
    random_seed: Mapped[str | None] = mapped_column(
        String(256), nullable=True,
        comment="Only present for replay_with_seed mode"
    )
    external_calls_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True,
        comment="SHA-256 of external_calls JSON for replay_with_recorded_io"
    )

    # Full proof — stored in canonical JSON format
    proof_json: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="Canonical JSON of the full proof artifact"
    )

    # Schema version — future-proofing
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="v1", server_default="v1"
    )

    # Timing
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        comment="Decision time — from proof.ledger.timestamp"
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=_utcnow, server_default=func.now(),
        comment="When this row was written to the DB"
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="ledger_entries")

    __table_args__ = (
        # Core uniqueness constraints — prevent replay and duplication
        UniqueConstraint(
            "tenant_id", "instance_id", "sequence_id",
            name="uq_ledger_tenant_instance_seq"
        ),
        UniqueConstraint(
            "tenant_id", "instance_id", "current_hash",
            name="uq_ledger_tenant_instance_hash"
        ),
        # Format constraints
        CheckConstraint("sequence_id >= 1",              name="ck_ledger_seq_min"),
        CheckConstraint("length(current_hash) = 64",     name="ck_ledger_hash_len"),
        CheckConstraint("length(signature) = 128",       name="ck_ledger_sig_len"),
        CheckConstraint("length(public_key) = 64",       name="ck_ledger_pubkey_len"),
        CheckConstraint(
            f"previous_hash = '{GENESIS_HASH}' OR length(previous_hash) = 64",
            name="ck_ledger_prev_hash"
        ),
        CheckConstraint(
            "determinism_mode IN ('strict_deterministic','replay_with_seed','replay_with_recorded_io')",
            name="ck_ledger_determinism_mode"
        ),
        # Indexes for common query patterns
        Index("ix_ledger_tenant_instance", "tenant_id", "instance_id"),
        Index("ix_ledger_tenant_instance_seq", "tenant_id", "instance_id", "sequence_id"),
        Index("ix_ledger_current_hash", "tenant_id", "current_hash"),
        Index("ix_ledger_recorded_at", "recorded_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Ledger tenant={self.tenant_id!r} instance={self.instance_id!r} "
            f"seq={self.sequence_id} hash={self.current_hash[:12]}…>"
        )


# ── AuditLog ───────────────────────────────────────────────────────────────────

class AuditLog(Base):
    """
    Immutable audit trail. Every system action is recorded here.

    Events:
        decision_recorded   — proof written to ledger
        key_created         — new signing key registered
        key_rotated         — key status changed to retired
        governance_rejected — decision blocked by governance
        verification_run    — proof verification request
        tenant_created      — new tenant registered
        chain_error         — hash chain violation detected

    Rows are NEVER deleted. Append-only enforced in application logic.
    PostgreSQL rule to block DELETE/UPDATE added in migration.
    """
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    tenant_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False, index=True
    )

    # Event details
    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="decision_recorded | key_created | key_rotated | etc."
    )
    trace_id: Mapped[str] = mapped_column(
        String(36), nullable=False, index=True,
        comment="Request trace ID for log correlation"
    )
    actor: Mapped[str] = mapped_column(
        String(128), nullable=False, default="system",
        comment="Who triggered this event (key_id, admin_id, or 'system')"
    )

    # Context — flexible JSON stored as text
    context_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}",
        comment="Event-specific context in canonical JSON"
    )

    # Optional link to ledger entry
    ledger_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("ledger.id", ondelete="SET NULL"),
        nullable=True, index=True
    )

    # Severity
    level: Mapped[str] = mapped_column(
        String(16), nullable=False, default="info",
        comment="info | warning | error"
    )

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=_utcnow, server_default=func.now(), index=True
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="audit_logs")

    __table_args__ = (
        CheckConstraint(
            "event_type IN ("
            "'decision_recorded','key_created','key_rotated',"
            "'governance_rejected','verification_run','tenant_created',"
            "'chain_error','signing_error','tenant_deactivated')",
            name="ck_audit_event_type"
        ),
        CheckConstraint("level IN ('info','warning','error')", name="ck_audit_level"),
        Index("ix_audit_tenant_event", "tenant_id", "event_type"),
        Index("ix_audit_trace", "trace_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog tenant={self.tenant_id!r} event={self.event_type!r} "
            f"trace={self.trace_id!r}>"
        )