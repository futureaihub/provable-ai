#!/usr/bin/env python3
"""
Zorynex — Standalone Anchor Verifier
======================================
Verify that a chain_hash or system_root was anchored externally at a specific
time, with ZERO dependency on Zorynex infrastructure.

Dependencies: none for structural check / openssl for cryptographic check.

Usage:
    # Structural check: is this hash in the RFC 3161 token?
    python verify_anchor.py --hash <64-hex> --token <token.tsr>

    # Verify anchor store chain integrity (SQLite file)
    python verify_anchor.py --anchor-db zorynex_anchors.db --tenant bank_abc

    # Full cryptographic check (requires openssl + FreeTSA cert)
    python verify_anchor.py --hash <64-hex> --token <token.tsr> --ca cacert.pem

What this verifies:
    1. Structural: the chain_hash SHA-256 appears inside the RFC 3161 token bytes
       (proves the token was issued for this hash)
    2. Cryptographic: openssl ts -verify confirms the TSA's signature
       (proves FreeTSA actually signed this, not a forgery)
    3. Anchor chain: the local anchor DB is internally consistent
       (proves no anchor records were modified after writing)

Trust model:
    Structural check (this script)  — confirms hash is embedded
    Cryptographic check (openssl)   — confirms TSA signed it
    Both together                   — independently verifiable trust

FreeTSA certificates:
    https://www.freetsa.org/index_en.php
    curl -O https://www.freetsa.org/files/cacert.pem
    curl -O https://www.freetsa.org/files/tsa.crt
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any


# ── RFC 3161 structural check ─────────────────────────────────────────────────

def verify_rfc3161_structural(chain_hash: str, token_path: str) -> dict[str, Any]:
    """
    Structural check: confirm chain_hash SHA-256 is embedded in the token.

    Does NOT verify the TSA's cryptographic signature — use verify_rfc3161_full
    for that. The structural check is sufficient to confirm the token was issued
    for this specific hash value.
    """
    result: dict[str, Any] = {
        "valid":       False,
        "check_type":  "structural",
        "chain_hash":  chain_hash[:16] + "...",
        "token_path":  token_path,
        "failure":     None,
    }

    try:
        with open(token_path, "rb") as f:
            token_bytes = f.read()
        result["token_size_bytes"] = len(token_bytes)
    except OSError as e:
        result["failure"] = f"Cannot read token: {e}"
        return result

    expected_hash = hashlib.sha256(chain_hash.encode("utf-8")).digest()

    if expected_hash in token_bytes:
        result["valid"]   = True
        result["message"] = "chain_hash SHA-256 found in RFC 3161 token"
    else:
        result["failure"] = (
            "chain_hash SHA-256 NOT found in token bytes. "
            "Token was not issued for this chain_hash."
        )

    return result


def verify_rfc3161_full(
    chain_hash: str,
    token_path: str,
    ca_cert_path: str,
    tsa_cert_path: str | None = None,
) -> dict[str, Any]:
    """
    Full cryptographic verification using openssl.

    Confirms the TSA (FreeTSA) actually signed this timestamp.
    Requires openssl installed on the verifier's machine.

    openssl command:
        openssl ts -verify -in <token.tsr> -data <chain_hash.bin>
                   -CAfile <cacert.pem> [-untrusted <tsa.crt>]
    """
    result: dict[str, Any] = {
        "valid":      False,
        "check_type": "cryptographic",
        "chain_hash": chain_hash[:16] + "...",
        "failure":    None,
    }

    # Check openssl available
    if subprocess.run(["which", "openssl"], capture_output=True).returncode != 0:
        result["failure"] = (
            "openssl not found. Install openssl to run cryptographic verification."
        )
        return result

    with tempfile.TemporaryDirectory() as tmp:
        # Write chain_hash as raw bytes for openssl -data
        data_path = os.path.join(tmp, "chain_hash.bin")
        with open(data_path, "wb") as f:
            f.write(chain_hash.encode("utf-8"))

        cmd = [
            "openssl", "ts", "-verify",
            "-in", token_path,
            "-data", data_path,
            "-CAfile", ca_cert_path,
        ]
        if tsa_cert_path:
            cmd += ["-untrusted", tsa_cert_path]

        proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode == 0 and "Verification: OK" in proc.stdout:
        result["valid"]   = True
        result["message"] = "RFC 3161 signature cryptographically verified (TSA signature valid)"
        result["openssl_output"] = proc.stdout.strip()
    else:
        result["failure"]        = "openssl ts -verify failed"
        result["openssl_stdout"] = proc.stdout.strip()
        result["openssl_stderr"] = proc.stderr.strip()

    return result


# ── Anchor chain integrity ────────────────────────────────────────────────────

def verify_anchor_chain(db_path: str, tenant_id: str) -> dict[str, Any]:
    """
    Verify the anchor store's internal hash chain.

    Reads the zorynex_anchors.db SQLite file directly — no Zorynex code needed.
    Recomputes every chain link and reports the first broken row.
    """
    result: dict[str, Any] = {
        "valid": False, "total_rows": 0, "broken_at_id": None, "failure": None,
    }

    if not os.path.exists(db_path):
        result["failure"] = f"Anchor DB not found: {db_path}"
        return result

    GENESIS = "0" * 64

    def _compute_anchor_row_hash(row: dict) -> str:
        content = json.dumps({
            "anchor_id":   row["anchor_id"],
            "tenant_id":   row["tenant_id"],
            "chain_hash":  row["chain_hash"],
            "anchored_at": row["anchored_at"],
            "anchor_seq":  row["anchor_seq"],
            "rfc3161":     row["rfc3161_json"],
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM chain_anchors WHERE tenant_id=? ORDER BY id ASC",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    result["total_rows"] = len(rows)

    if not rows:
        result["valid"] = True
        result["message"] = "No anchors found for this tenant"
        return result

    prev_hash = GENESIS
    for row in rows:
        row_d = dict(row)
        expected_row_hash = _compute_anchor_row_hash(row_d)
        expected_chain    = hashlib.sha256(
            bytes.fromhex(prev_hash) + bytes.fromhex(expected_row_hash)
        ).hexdigest()

        if row_d["row_hash"] != expected_row_hash:
            result["broken_at_id"] = row_d["id"]
            result["failure"] = f"Row id={row_d['id']}: row_hash mismatch (content was modified)"
            return result

        if row_d["anchor_chain_hash"] != expected_chain:
            result["broken_at_id"] = row_d["id"]
            result["failure"] = f"Row id={row_d['id']}: chain broken (row was inserted or deleted)"
            return result

        prev_hash = row_d["anchor_chain_hash"]

    result["valid"]      = True
    result["final_hash"] = prev_hash
    result["message"]    = f"Anchor chain intact ({len(rows)} rows)"
    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Verify Zorynex anchor records")
    parser.add_argument("--hash",       help="chain_hash or system_root (64 hex chars)")
    parser.add_argument("--token",      help="RFC 3161 .tsr token file")
    parser.add_argument("--ca",         help="CA cert PEM for full cryptographic check")
    parser.add_argument("--tsa-cert",   help="TSA cert PEM (optional, for chain)")
    parser.add_argument("--anchor-db",  help="zorynex_anchors.db file path")
    parser.add_argument("--tenant",     default="default", help="tenant_id to check")
    parser.add_argument("--quiet",      action="store_true")
    args = parser.parse_args()

    exit_code = 0

    # Anchor chain integrity
    if args.anchor_db:
        result = verify_anchor_chain(args.anchor_db, args.tenant)
        if not args.quiet:
            status = "VALID" if result["valid"] else "INVALID"
            print(f"\nAnchor chain integrity: {status}")
            print(f"  tenant_id:   {args.tenant}")
            print(f"  total_rows:  {result['total_rows']}")
            if result.get("broken_at_id"):
                print(f"  broken_at:   id={result['broken_at_id']}")
            if result.get("failure"):
                print(f"  failure:     {result['failure']}")
            if result.get("message"):
                print(f"  message:     {result['message']}")
            print()
        if not result["valid"]:
            exit_code = 1

    # RFC 3161 token checks
    if args.hash and args.token:
        struct = verify_rfc3161_structural(args.hash, args.token)
        if not args.quiet:
            status = "VALID" if struct["valid"] else "INVALID"
            print(f"Structural check: {status}")
            print(f"  chain_hash:   {struct['chain_hash']}")
            print(f"  token_size:   {struct.get('token_size_bytes', '?')} bytes")
            if struct.get("failure"):
                print(f"  failure:      {struct['failure']}")
            print()
        if not struct["valid"]:
            exit_code = 1

        if args.ca:
            crypto = verify_rfc3161_full(args.hash, args.token, args.ca, args.tsa_cert)
            if not args.quiet:
                status = "VALID" if crypto["valid"] else "INVALID"
                print(f"Cryptographic check: {status}")
                if crypto.get("message"):
                    print(f"  {crypto['message']}")
                if crypto.get("failure"):
                    print(f"  failure: {crypto['failure']}")
                if crypto.get("openssl_stderr"):
                    print(f"  openssl: {crypto['openssl_stderr']}")
                print()
            if not crypto["valid"]:
                exit_code = 1

    if not args.anchor_db and not (args.hash and args.token):
        parser.print_help()
        return 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())