#!/usr/bin/env python3
"""
Zorynex CLI
============
Command-line interface for recording, verifying, and exporting
AI decision proofs.

Usage:
    python cli.py record --instance loan_001 --from pending --to approved ...
    python cli.py verify proof.json
    python cli.py chain-verify --instance loan_001
    python cli.py export --instance loan_001 --out proof_package.json
    python cli.py governance status
    python cli.py governance approve-model credit-model-v3.1
    python cli.py server         (start API server)
    python cli.py info           (show configuration)
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def _get_engine():
    from provable_ai.engine import GovernanceEngine
    from provable_ai.signer import get_signer
    from provable_ai.storage import SQLiteStorage
    db_path = os.environ.get("ZORYNEX_DB_PATH", "provable_ai.db")
    storage = SQLiteStorage(db_path=db_path)
    signer  = get_signer()
    return GovernanceEngine(storage=storage, signer=signer), storage


# ── record ────────────────────────────────────────────────────────────────────

def cmd_record(args: argparse.Namespace) -> int:
    engine, _ = _get_engine()
    raw_inputs = json.loads(args.inputs) if args.inputs else {}

    proof = engine.record_decision(
        instance_id     = args.instance,
        from_state      = args.from_state,
        to_state        = args.to_state,
        model_version   = args.model,
        agent_version   = args.agent,
        policy_version  = args.policy,
        reason_code     = args.reason or "CLI_DECISION",
        policy_rule     = args.rule or f"{args.policy}.default",
        raw_inputs      = raw_inputs,
        metadata        = json.loads(args.metadata) if args.metadata else {},
    )

    out = {
        "proof_id":     proof.proof_id,
        "instance_id":  proof.instance_id,
        "sequence_id":  proof.ledger.sequence_id,
        "current_hash": proof.ledger.current_hash,
        "to_state":     proof.decision.to_state,
    }
    print(json.dumps(out, indent=2))
    return 0


# ── verify ────────────────────────────────────────────────────────────────────

def cmd_verify(args: argparse.Namespace) -> int:
    from provable_ai.verifier import verify_proof

    with open(args.proof_file) as f:
        data = json.load(f)

    # Handle both single proof and proof package
    if data.get("type") == "provable-ai-proof-package":
        from provable_ai.verifier import verify_chain
        proofs = data.get("proofs", [])
        result = verify_chain(proofs)
        status = "VALID" if result.valid else "INVALID"
        print(f"\nChain verification: {status}")
        print(f"  steps:       {result.sequence_verified}")
        print(f"  final_state: {result.final_state}")
        if not result.valid:
            print(f"  failure:     {result.failure_reason}")
        return 0 if result.valid else 1
    else:
        result = verify_proof(data)
        status = "VALID" if result.valid else "INVALID"
        print(f"\nProof verification: {status}")
        print(f"  proof_id:    {data.get('proof_id', 'unknown')[:24]}...")
        print(f"  key_id:      {result.key_id}")
        print(f"  chain_intact:{result.chain_intact}")
        if not result.valid:
            print(f"  failure:     {result.failure_reason}")
        return 0 if result.valid else 1


# ── chain-verify ──────────────────────────────────────────────────────────────

def cmd_chain_verify(args: argparse.Namespace) -> int:
    import json as _json
    from provable_ai.verifier import verify_chain
    _, storage = _get_engine()

    chain = storage.get_ledger_chain(args.instance)
    if not chain:
        print(f"No ledger entries for instance: {args.instance}")
        return 1

    proof_dicts = [_json.loads(e["proof_json"]) for e in chain if e.get("proof_json") and e["proof_json"] != "{}"]
    result = verify_chain(proof_dicts)

    status = "VALID" if result.valid else "INVALID"
    print(f"\nChain verification [{args.instance}]: {status}")
    print(f"  steps:       {result.sequence_verified}")
    print(f"  final_state: {result.final_state}")
    print(f"  chain_intact:{result.chain_intact}")
    if not result.valid:
        print(f"  failure:     {result.failure_reason}")

    return 0 if result.valid else 1


# ── export ────────────────────────────────────────────────────────────────────

def cmd_export(args: argparse.Namespace) -> int:
    import json as _json
    _, storage = _get_engine()

    chain = storage.get_ledger_chain(args.instance)
    if not chain:
        print(f"No ledger entries for instance: {args.instance}")
        return 1

    proof_dicts = [
        _json.loads(e["proof_json"]) for e in chain
        if e.get("proof_json") and e["proof_json"] != "{}"
    ]

    package = {
        "type":         "provable-ai-proof-package",
        "instance_id":  args.instance,
        "chain_length": len(proof_dicts),
        "final_state":  proof_dicts[-1]["decision"]["to_state"] if proof_dicts else None,
        "chain_root":   chain[-1].get("current_hash", "") if chain else "",
        "proofs":       proof_dicts,
    }

    out_path = args.out or f"{args.instance}_proof.json"
    with open(out_path, "w") as f:
        _json.dump(package, f, indent=2)

    print(f"Proof package exported: {out_path}")
    print(f"  proofs:  {len(proof_dicts)}")
    return 0


# ── governance ────────────────────────────────────────────────────────────────

def cmd_governance(args: argparse.Namespace) -> int:
    _, storage = _get_engine()

    if args.governance_cmd == "status":
        print(f"\nGovernance status ({os.environ.get('ZORYNEX_DB_PATH', 'provable_ai.db')}):")
        print(f"\nApproved models:")
        for m in storage.get_approved_models():
            print(f"  + {m}")
        print(f"\nApproved agents:")
        for a in storage.get_approved_agents():
            print(f"  + {a}")
        print(f"\nApproved policies:")
        for p in storage.get_approved_policies():
            print(f"  + {p}")
        return 0

    elif args.governance_cmd == "approve-model":
        storage.add_approved_model(args.version)
        print(f"✓ Approved model: {args.version}")
        return 0

    elif args.governance_cmd == "approve-agent":
        storage.add_approved_agent(args.version)
        print(f"✓ Approved agent: {args.version}")
        return 0

    elif args.governance_cmd == "approve-policy":
        storage.add_approved_policy(args.version)
        print(f"✓ Approved policy: {args.version}")
        return 0

    else:
        print(f"Unknown governance command: {args.governance_cmd}")
        return 1


# ── server ────────────────────────────────────────────────────────────────────

def cmd_server(args: argparse.Namespace) -> int:
    import uvicorn
    host    = os.environ.get("ZORYNEX_HOST", "0.0.0.0")
    port    = int(os.environ.get("ZORYNEX_PORT", "8000"))
    workers = int(os.environ.get("ZORYNEX_WORKERS", "1"))
    reload  = args.reload

    print(f"Starting Zorynex server on {host}:{port} (workers={workers})")
    uvicorn.run(
        "server.main:app",
        host=host, port=port,
        workers=workers,
        reload=reload,
        log_level="info",
    )
    return 0


# ── info ──────────────────────────────────────────────────────────────────────

def cmd_info(args: argparse.Namespace) -> int:
    from provable_ai.signer import get_signer
    signer = get_signer()
    print(f"\nZorynex Configuration:")
    print(f"  DB path:      {os.environ.get('ZORYNEX_DB_PATH', 'provable_ai.db')}")
    print(f"  Key ID:       {signer.get_key_id()}")
    print(f"  Public key:   {signer.get_public_key()[:32]}...")
    print(f"  Backend:      {os.environ.get('ZORYNEX_BACKEND', 'sqlite')}")
    print(f"  Anchor RFC3161:{os.environ.get('ZORYNEX_ANCHOR_RFC3161', 'false')}")
    return 0


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zorynex",
        description="Zorynex — Provable AI Infrastructure CLI",
    )
    sub = p.add_subparsers(dest="command")

    # record
    rec = sub.add_parser("record", help="Record an AI decision")
    rec.add_argument("--instance",   required=True, help="Instance ID")
    rec.add_argument("--from",       dest="from_state", required=True)
    rec.add_argument("--to",         dest="to_state",   required=True)
    rec.add_argument("--model",      required=True, help="Model version")
    rec.add_argument("--agent",      required=True, help="Agent version")
    rec.add_argument("--policy",     required=True, help="Policy version")
    rec.add_argument("--reason",     default="",    help="Reason code")
    rec.add_argument("--rule",       default="",    help="Policy rule")
    rec.add_argument("--inputs",     default="{}",  help="Raw inputs JSON")
    rec.add_argument("--metadata",   default="{}",  help="Metadata JSON")

    # verify
    ver = sub.add_parser("verify", help="Verify a proof or proof package")
    ver.add_argument("proof_file", help="Path to proof.json or package.json")

    # chain-verify
    cv = sub.add_parser("chain-verify", help="Verify chain for an instance")
    cv.add_argument("--instance", required=True, help="Instance ID")

    # export
    exp = sub.add_parser("export", help="Export proof package")
    exp.add_argument("--instance", required=True, help="Instance ID")
    exp.add_argument("--out",      default=None,  help="Output file path")

    # governance
    gov = sub.add_parser("governance", help="Manage governance configuration")
    gov_sub = gov.add_subparsers(dest="governance_cmd")
    gov_sub.add_parser("status", help="Show current governance config")
    am = gov_sub.add_parser("approve-model",  help="Approve a model version")
    am.add_argument("version")
    aa = gov_sub.add_parser("approve-agent",  help="Approve an agent version")
    aa.add_argument("version")
    ap = gov_sub.add_parser("approve-policy", help="Approve a policy version")
    ap.add_argument("version")

    # server
    srv = sub.add_parser("server", help="Start the API server")
    srv.add_argument("--reload", action="store_true", help="Enable auto-reload")

    # info
    sub.add_parser("info", help="Show Zorynex configuration")

    return p


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "record":       cmd_record,
        "verify":       cmd_verify,
        "chain-verify": cmd_chain_verify,
        "export":       cmd_export,
        "governance":   cmd_governance,
        "server":       cmd_server,
        "info":         cmd_info,
    }

    fn = commands.get(args.command)
    if not fn:
        print(f"Unknown command: {args.command}")
        return 1

    try:
        return fn(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())