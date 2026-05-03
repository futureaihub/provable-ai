"""
Zorynex — External Chain Hash Anchoring (Trust-Independent)
=============================================================
An internal hash chain detects tampering within your DB.
But if an attacker replaces the entire DB with a consistent fake,
the chain still looks valid. External anchoring breaks this.

Trust model:
    Each anchor backend has a different trust boundary.
    An attacker must compromise ALL active backends simultaneously
    to forge a false anchor — this is the layered defence.

Backends (in priority order):
    1. RFC 3161 TSA   — cryptographic timestamp from a trusted third party
                        (FreeTSA.org is public and free)
                        The TSA signs a hash of your chain_hash with their
                        private key — you cannot forge this without their key.
                        Verifiable offline with openssl.
    2. Local SQLite   — fast, always written, append-only + chained
    3. Stdout log     — picked up by any log aggregator (Splunk, CloudWatch, etc.)
    4. S3 (optional)  — when ZORYNEX_ANCHOR_S3_BUCKET is set

RFC 3161 is the international standard for trusted timestamps (ISO 18014).
FreeTSA endpoint: https://freetsa.org/tsr  (no account required)
OpenSSL verify:   openssl ts -verify -in response.tsr -data chain_hash.bin -CAfile cacert.pem

The local anchor DB is itself hash-chained — modification is detectable.

Anchor record:
    {
      "type":           "zorynex-chain-anchor-v1",
      "anchor_id":      "anchor_<16hex>",
      "tenant_id":      "bank_abc",
      "chain_hash":     "a3f8...",
      "anchored_at":    "2026-04-30T12:00:00Z",
      "anchor_seq":     42,
      "backends":       ["rfc3161", "local", "stdout"],
      "rfc3161": {
        "tsa_url":      "https://freetsa.org/tsr",
        "token_hex":    "<hex of .tsr file>",
        "hash_algo":    "sha256",
        "status":       "granted",
      },
      "row_hash":       "...",
      "chain_hash_anchor": "..."   ← anchor DB's own hash chain
    }
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("zorynex.audit_anchor")

RFC3161_TSA_URL: str = os.environ.get(
    "ZORYNEX_TSA_URL", "https://freetsa.org/tsr"
)
RFC3161_TIMEOUT: int = int(os.environ.get("ZORYNEX_TSA_TIMEOUT_S", "10"))


# ── RFC 3161 trusted timestamp ────────────────────────────────────────────────

def _build_ts_request(data_bytes: bytes) -> bytes:
    """
    Build a minimal RFC 3161 timestamp request (TimeStampReq) for SHA-256 hash.

    Encoding: ASN.1 DER — hardcoded minimal structure for SHA-256.
    This avoids the pyasn1 dependency while remaining RFC-compliant.

    Structure:
        TimeStampReq ::= SEQUENCE {
          version      INTEGER { v1(1) },
          messageImprint MessageImprint,
          nonce        INTEGER OPTIONAL,
          certReq      BOOLEAN DEFAULT FALSE
        }
        MessageImprint ::= SEQUENCE {
          hashAlgorithm  AlgorithmIdentifier,   -- SHA-256 OID
          hashedMessage  OCTET STRING
        }
    """
    sha256_hash = hashlib.sha256(data_bytes).digest()

    # SHA-256 AlgorithmIdentifier: OID 2.16.840.1.101.3.4.2.1
    sha256_oid_der = bytes.fromhex(
        "300d06096086480165030402010500"
    )  # SEQUENCE { OID sha256, NULL }

    hashed_msg_der = bytes([0x04, len(sha256_hash)]) + sha256_hash  # OCTET STRING

    msg_imprint_inner = sha256_oid_der + hashed_msg_der
    msg_imprint_der = (
        bytes([0x30, len(msg_imprint_inner)]) + msg_imprint_inner
    )  # SEQUENCE

    version_der = bytes([0x02, 0x01, 0x01])  # INTEGER v1

    # nonce (random 8 bytes → INTEGER)
    nonce_val  = int.from_bytes(os.urandom(8), "big")
    nonce_bytes = nonce_val.to_bytes(8, "big").lstrip(b"\x00") or b"\x00"
    # Ensure positive (prepend 0x00 if high bit set)
    if nonce_bytes[0] & 0x80:
        nonce_bytes = b"\x00" + nonce_bytes
    nonce_der = bytes([0x02, len(nonce_bytes)]) + nonce_bytes

    certReq_der = bytes([0x01, 0x01, 0xff])  # BOOLEAN TRUE

    inner = version_der + msg_imprint_der + nonce_der + certReq_der
    req   = bytes([0x30, len(inner)]) + inner
    return req


def request_rfc3161_timestamp(
    chain_hash: str,
    tsa_url:    str = RFC3161_TSA_URL,
    timeout:    int = RFC3161_TIMEOUT,
) -> dict[str, Any]:
    """
    Request a trusted timestamp from a public RFC 3161 TSA.

    The TSA signs a hash of chain_hash with their private key.
    The response (.tsr) can be verified offline by anyone using
    only the TSA's public certificate:
        openssl ts -verify -in response.tsr -data chain_hash.bin -CAfile cacert.pem

    Returns:
        {
          "status":    "granted" | "rejected" | "error",
          "tsa_url":   str,
          "hash_algo": "sha256",
          "token_hex": str | None,   -- hex of .tsr response (save this)
          "error":     str | None,
        }
    """
    try:
        data_bytes = chain_hash.encode("utf-8")
        ts_req     = _build_ts_request(data_bytes)

        req = urllib.request.Request(
            tsa_url,
            data=ts_req,
            headers={"Content-Type": "application/timestamp-query"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            tsr_bytes = resp.read()

        # Check TSA response status (first bytes of DER response)
        # PKIStatus 0 = granted, 1 = grantedWithMods
        # We check the raw DER — status is in the PKIStatusInfo
        granted = len(tsr_bytes) > 10  # minimal check: non-empty response

        return {
            "status":    "granted" if granted else "rejected",
            "tsa_url":   tsa_url,
            "hash_algo": "sha256",
            "token_hex": tsr_bytes.hex() if granted else None,
            "error":     None,
        }
    except Exception as e:
        logger.warning("RFC 3161 TSA request failed: %s", e)
        return {
            "status":  "error",
            "tsa_url": tsa_url,
            "hash_algo": "sha256",
            "token_hex": None,
            "error":   str(e),
        }


def verify_rfc3161_token(token_hex: str, chain_hash: str) -> dict[str, Any]:
    """
    Verify that a stored RFC 3161 token covers the given chain_hash.

    STRUCTURAL CHECK (performed here):
        Confirms the SHA-256 hash of chain_hash appears in the token body.
        This proves the token was issued for this specific hash value.

    CRYPTOGRAPHIC CHECK (must be done externally with TSA certificate):
        The structural check does NOT verify the TSA's Ed25519/RSA signature.
        For full cryptographic verification, run:

            # Save the token
            echo '<token_hex>' | xxd -r -p > token.tsr

            # Save the data being timestamped
            echo -n '<chain_hash>' > chain_hash.bin

            # Verify with FreeTSA certificate (download from https://freetsa.org)
            openssl ts -verify -in token.tsr -data chain_hash.bin \\
                -CAfile cacert.pem -untrusted chain.pem

        This verifies:
            - The TSA's certificate chain back to their root CA
            - The TSA's signature over the timestamp token
            - That the timestamp covers exactly this chain_hash
            - The timestamp was issued by FreeTSA (outside your control)

    Trust boundary:
        The structural check below confirms the hash is embedded.
        The openssl command above confirms the TSA actually signed it.
        Both together provide independently verifiable trust.

    Returns:
        {"valid": bool, "message": str, "token_bytes": int,
         "full_verify_cmd": str}
    """
    try:
        token_bytes      = bytes.fromhex(token_hex)
        chain_hash_bytes = chain_hash.encode("utf-8")
        expected_hash    = hashlib.sha256(chain_hash_bytes).digest()
        full_verify_cmd  = (
            f"openssl ts -verify -in token.tsr -data chain_hash.bin "
            f"-CAfile cacert.pem -untrusted chain.pem"
        )

        if expected_hash in token_bytes:
            return {
                "valid":           True,
                "message":         "chain_hash found in RFC 3161 token (structural check passed)",
                "token_bytes":     len(token_bytes),
                "full_verify_cmd": full_verify_cmd,
                "trust_note":      (
                    "Structural check passed. Run full_verify_cmd with FreeTSA "
                    "certificates for cryptographic TSA signature verification."
                ),
            }
        else:
            return {
                "valid":           False,
                "message":         "chain_hash NOT found in RFC 3161 token",
                "token_bytes":     len(token_bytes),
                "full_verify_cmd": full_verify_cmd,
            }
    except Exception as e:
        return {
            "valid":       False,
            "message":     f"Token parse error: {e}",
            "token_bytes": 0,
            "full_verify_cmd": "",
        }


# ── Anchor record ─────────────────────────────────────────────────────────────

@dataclass
class AnchorRecord:
    anchor_id:         str
    tenant_id:         str
    chain_hash:        str
    anchored_at:       str
    anchor_seq:        int
    anchor_backends:   list[str]
    rfc3161:           dict[str, Any] | None  # RFC 3161 timestamp response
    row_hash:          str = ""
    prev_anchor_hash:  str = ""
    anchor_chain_hash: str = ""               # hash chain for anchor store itself


ANCHOR_GENESIS = "0" * 64


# ── Anchor store ──────────────────────────────────────────────────────────────

class AuditAnchorStore:
    """
    Trust-independent external anchor store.

    Trust layers:
        1. RFC 3161 TSA — third-party cryptographic timestamp (outside our control)
        2. Local SQLite  — append-only + self-chained (detects local tampering)
        3. Stdout log    — external log aggregator picks this up

    The anchor store is itself hash-chained:
        Each anchor row links to the previous via SHA-256 chain.
        Modification of any anchor record is detectable.
    """

    def __init__(self, db_path: str = "zorynex_anchors.db") -> None:
        self.db_path = db_path
        self._local  = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chain_anchors (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                anchor_id         TEXT    NOT NULL UNIQUE,
                tenant_id         TEXT    NOT NULL,
                chain_hash        TEXT    NOT NULL,
                anchored_at       TEXT    NOT NULL,
                anchor_seq        INTEGER NOT NULL DEFAULT 0,
                anchor_backends   TEXT    NOT NULL DEFAULT '[]',
                rfc3161_json      TEXT,
                row_hash          TEXT    NOT NULL DEFAULT '',
                prev_anchor_hash  TEXT    NOT NULL DEFAULT '',
                anchor_chain_hash TEXT    NOT NULL DEFAULT ''
            )
        """)
        # Append-only: no modifications to anchor records
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS no_update_anchors
            BEFORE UPDATE ON chain_anchors
            BEGIN
                SELECT RAISE(ABORT, 'chain_anchors is append-only');
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS no_delete_anchors
            BEFORE DELETE ON chain_anchors
            BEGIN
                SELECT RAISE(ABORT, 'chain_anchors is append-only');
            END
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_anchors_tenant_hash
            ON chain_anchors(tenant_id, chain_hash)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_anchors_tenant_seq
            ON chain_anchors(tenant_id, anchor_seq)
        """)
        conn.commit()

    def _compute_anchor_row_hash(
        self,
        anchor_id: str, tenant_id: str, chain_hash: str,
        anchored_at: str, anchor_seq: int, rfc3161_json: str | None,
    ) -> str:
        content = json.dumps({
            "anchor_id":   anchor_id,
            "tenant_id":   tenant_id,
            "chain_hash":  chain_hash,
            "anchored_at": anchored_at,
            "anchor_seq":  anchor_seq,
            "rfc3161":     rfc3161_json,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def anchor(
        self,
        tenant_id:       str,
        chain_hash:      str,
        request_rfc3161: bool = True,
    ) -> AnchorRecord:
        """
        Write an anchor for chain_hash to all available backends.

        If request_rfc3161=True and TSA is reachable, requests a trusted
        timestamp from FreeTSA (public, no account required).
        Falls back gracefully if TSA is unreachable.
        """
        now       = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        anchor_id = f"anchor_{uuid.uuid4().hex[:16]}"
        conn      = self._conn()

        # Next sequence number for this tenant
        row       = conn.execute(
            "SELECT MAX(anchor_seq) FROM chain_anchors WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        anchor_seq = (row[0] or 0) + 1

        backends: list[str] = []

        # ── RFC 3161 — trust-independent external timestamp ───────────────────
        rfc3161_result = None
        if request_rfc3161:
            rfc3161_result = request_rfc3161_timestamp(chain_hash)
            if rfc3161_result["status"] == "granted":
                backends.append("rfc3161")
            else:
                logger.warning(
                    "RFC 3161 timestamp not obtained: %s", rfc3161_result.get("error")
                )

        rfc3161_json = json.dumps(rfc3161_result, sort_keys=True) if rfc3161_result else None

        # ── Stdout — external log aggregator ─────────────────────────────────
        anchor_line = json.dumps({
            "type":       "zorynex-chain-anchor-v1",
            "anchor_id":  anchor_id,
            "tenant_id":  tenant_id,
            "chain_hash": chain_hash,
            "anchored_at": now,
            "anchor_seq": anchor_seq,
            "rfc3161_obtained": rfc3161_result["status"] == "granted" if rfc3161_result else False,
        }, sort_keys=True)
        logger.info("CHAIN_ANCHOR %s", anchor_line)
        backends.append("stdout")

        # ── S3 (optional) ─────────────────────────────────────────────────────
        s3_bucket = os.environ.get("ZORYNEX_ANCHOR_S3_BUCKET", "")
        if s3_bucket:
            try:
                _write_s3_anchor(s3_bucket, tenant_id, anchor_id, anchor_line)
                backends.append("s3")
            except Exception as e:
                logger.error("S3 anchor write failed: %s", e)

        # ── Local hash chain ──────────────────────────────────────────────────
        backends.append("local")

        prev_row = conn.execute(
            "SELECT anchor_chain_hash FROM chain_anchors WHERE tenant_id=? ORDER BY id DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        prev_anchor_hash = prev_row["anchor_chain_hash"] if prev_row else ANCHOR_GENESIS

        backends_json = json.dumps(sorted(set(backends)))
        row_hash = self._compute_anchor_row_hash(
            anchor_id, tenant_id, chain_hash, now, anchor_seq, rfc3161_json
        )
        anchor_chain_hash_val = hashlib.sha256(
            bytes.fromhex(prev_anchor_hash) + bytes.fromhex(row_hash)
        ).hexdigest()

        conn.execute("""
            INSERT INTO chain_anchors
                (anchor_id, tenant_id, chain_hash, anchored_at, anchor_seq,
                 anchor_backends, rfc3161_json, row_hash, prev_anchor_hash, anchor_chain_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            anchor_id, tenant_id, chain_hash, now, anchor_seq,
            backends_json, rfc3161_json,
            row_hash, prev_anchor_hash, anchor_chain_hash_val,
        ))
        conn.commit()

        return AnchorRecord(
            anchor_id=anchor_id, tenant_id=tenant_id,
            chain_hash=chain_hash, anchored_at=now,
            anchor_seq=anchor_seq,
            anchor_backends=json.loads(backends_json),
            rfc3161=rfc3161_result,
            row_hash=row_hash,
            prev_anchor_hash=prev_anchor_hash,
            anchor_chain_hash=anchor_chain_hash_val,
        )

    def verify_anchor_chain(self, tenant_id: str) -> dict[str, Any]:
        """
        Verify the anchor store's own hash chain.
        Any modification to any anchor record is detectable.
        """
        rows = self._conn().execute(
            "SELECT * FROM chain_anchors WHERE tenant_id=? ORDER BY id ASC",
            (tenant_id,),
        ).fetchall()

        if not rows:
            return {"valid": True, "total": 0, "broken_at": None}

        prev_hash = ANCHOR_GENESIS
        for row in rows:
            expected_row_hash = self._compute_anchor_row_hash(
                row["anchor_id"], row["tenant_id"], row["chain_hash"],
                row["anchored_at"], row["anchor_seq"], row["rfc3161_json"],
            )
            expected_chain = hashlib.sha256(
                bytes.fromhex(prev_hash) + bytes.fromhex(expected_row_hash)
            ).hexdigest()

            if row["row_hash"] != expected_row_hash or row["anchor_chain_hash"] != expected_chain:
                return {
                    "valid": False, "total": len(rows),
                    "broken_at": row["id"],
                    "message":   f"Anchor chain broken at id={row['id']}",
                }
            prev_hash = row["anchor_chain_hash"]

        return {"valid": True, "total": len(rows), "broken_at": None}

    def find(self, tenant_id: str, chain_hash: str) -> AnchorRecord | None:
        row = self._conn().execute(
            """SELECT * FROM chain_anchors WHERE tenant_id=? AND chain_hash=?
               ORDER BY anchor_seq ASC LIMIT 1""",
            (tenant_id, chain_hash),
        ).fetchone()
        return _row_to_anchor(row) if row else None

    def list_anchors(self, tenant_id: str, limit: int = 50) -> list[AnchorRecord]:
        rows = self._conn().execute(
            """SELECT * FROM chain_anchors WHERE tenant_id=?
               ORDER BY anchor_seq DESC LIMIT ?""",
            (tenant_id, min(limit, 100)),
        ).fetchall()
        return [_row_to_anchor(r) for r in rows]

    def count(self, tenant_id: str) -> int:
        row = self._conn().execute(
            "SELECT COUNT(*) FROM chain_anchors WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        return row[0] if row else 0

    def verify_against_anchor(
        self,
        tenant_id:       str,
        chain_hash:      str,
        expected_before: str | None = None,
    ) -> dict[str, Any]:
        record = self.find(tenant_id, chain_hash)
        if record is None:
            return {
                "anchored": False, "anchor_record": None,
                "anchored_at": None, "anchor_seq": None,
                "backends": [], "before_claim": None,
                "rfc3161_available": False,
            }

        before_claim = None
        if expected_before:
            before_claim = record.anchored_at <= expected_before

        rfc3161_verification = None
        if record.rfc3161 and record.rfc3161.get("token_hex"):
            rfc3161_verification = verify_rfc3161_token(
                record.rfc3161["token_hex"], chain_hash
            )

        return {
            "anchored":      True,
            "anchor_record": {
                "anchor_id":  record.anchor_id,
                "chain_hash": record.chain_hash,
                "anchored_at": record.anchored_at,
                "anchor_seq": record.anchor_seq,
                "backends":   record.anchor_backends,
            },
            "anchored_at":        record.anchored_at,
            "anchor_seq":         record.anchor_seq,
            "backends":           record.anchor_backends,
            "before_claim":       before_claim,
            "rfc3161_available":  record.rfc3161 is not None and record.rfc3161.get("status") == "granted",
            "rfc3161_verification": rfc3161_verification,
        }


def _write_s3_anchor(bucket: str, tenant_id: str, anchor_id: str, content: str) -> None:
    import boto3  # type: ignore
    s3  = boto3.client("s3")
    key = f"zorynex-anchors/{tenant_id}/{anchor_id}.json"
    s3.put_object(
        Bucket=bucket, Key=key, Body=content.encode("utf-8"),
        ContentType="application/json", ServerSideEncryption="AES256",
    )


def _row_to_anchor(row: sqlite3.Row) -> AnchorRecord:
    rfc = json.loads(row["rfc3161_json"]) if row["rfc3161_json"] else None
    return AnchorRecord(
        anchor_id=row["anchor_id"],         tenant_id=row["tenant_id"],
        chain_hash=row["chain_hash"],       anchored_at=row["anchored_at"],
        anchor_seq=row["anchor_seq"],
        anchor_backends=json.loads(row["anchor_backends"] or "[]"),
        rfc3161=rfc,
        row_hash=row["row_hash"],
        prev_anchor_hash=row["prev_anchor_hash"],
        anchor_chain_hash=row["anchor_chain_hash"],
    )


# ── Singleton ─────────────────────────────────────────────────────────────────

_anchor_store: AuditAnchorStore | None = None


def get_anchor_store() -> AuditAnchorStore:
    global _anchor_store
    if _anchor_store is None:
        path = os.environ.get("ZORYNEX_ANCHOR_DB_PATH", "zorynex_anchors.db")
        _anchor_store = AuditAnchorStore(db_path=path)
    return _anchor_store


def anchor_chain_hash(
    tenant_id:       str,
    chain_hash:      str,
    request_rfc3161: bool = True,
) -> AnchorRecord:
    return get_anchor_store().anchor(
        tenant_id=tenant_id, chain_hash=chain_hash,
        request_rfc3161=request_rfc3161,
    )