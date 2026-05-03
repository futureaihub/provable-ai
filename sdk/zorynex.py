"""
Zorynex Python SDK
====================
Single-file client. No external dependencies beyond the standard library.
Copy this file into your project and import it — no pip install needed.

Usage:
    from zorynex import ZorynexClient

    client = ZorynexClient(
        base_url = "http://127.0.0.1:8000",
        api_key  = "dev-key",
        tenant_id= "default",
    )

    # Quick: let the platform auto-resolve governance
    proof = client.record_decision(
        instance_id = "loan-001",
        from_state  = "pending",
        to_state    = "approved",
        raw_inputs  = {"credit_score": "742"},
    )
    print(proof["proof_id"])

    # Full: explicit governance
    proof = client.record_decision(
        instance_id    = "loan-001",
        from_state     = "pending",
        to_state       = "approved",
        model_version  = "credit-model-v3.1",
        agent_version  = "underwriter-v1.0",
        policy_version = "credit-policy-v2",
        reason_code    = "SCORE_ABOVE_THRESHOLD",
        raw_inputs     = {"credit_score": "742"},
    )
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class ZorynexError(Exception):
    def __init__(self, status_code: int, detail: Any) -> None:
        self.status_code = status_code
        self.detail      = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class ZorynexClient:
    """
    Thin HTTP client for the Zorynex Provable AI API.

    All methods return the parsed JSON response as a dict.
    Raises ZorynexError on HTTP 4xx/5xx.
    """

    def __init__(
        self,
        base_url:  str = "http://127.0.0.1:8000",
        api_key:   str = "dev-key",
        tenant_id: str = "default",
        timeout:   float = 30.0,
    ) -> None:
        self._base    = base_url.rstrip("/")
        self._headers = {
            "X-API-Key":    api_key,
            "X-Tenant-Id":  tenant_id,
            "Content-Type": "application/json",
        }
        self._timeout = timeout

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url  = self._base + path
        data = json.dumps(body).encode() if body is not None else None
        req  = urllib.request.Request(url, data=data, headers=self._headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read())
            except Exception:
                detail = e.reason
            raise ZorynexError(e.code, detail)

    def _get(self, path: str) -> dict:
        return self._request("GET", path)

    def _post(self, path: str, body: dict) -> dict:
        return self._request("POST", path, body)

    # ── Quickstart ────────────────────────────────────────────────────────────

    def bootstrap(self) -> dict:
        """
        Seed a complete demo environment in one call.
        Approves a model/agent/policy, compiles a protocol, creates an instance.
        Returns the instance_id and next-step payload.
        """
        return self._post("/demo/bootstrap", {})

    # ── Governance ────────────────────────────────────────────────────────────

    def approve_model(self, name: str, version: str) -> dict:
        """Approve a model version for use in decisions."""
        return self._post("/governance/model", {"name": name, "version": version})

    def approve_agent(self, name: str, version: str) -> dict:
        """Approve an agent version for use in decisions."""
        return self._post("/governance/agent", {"name": name, "version": version})

    def approve_policy(self, name: str, version: str) -> dict:
        """Approve a policy version for use in decisions."""
        return self._post("/governance/policy", {"name": name, "version": version})

    def governance_status(self) -> dict:
        """Return all approved models, agents, and policies."""
        return self._get("/governance/status")

    # ── Protocol + instance ───────────────────────────────────────────────────

    def compile_protocol(
        self,
        states:        list[str],
        initial_state: str,
        transitions:   list[dict] | None = None,
        metadata:      dict | None = None,
    ) -> dict:
        """Define a workflow protocol. Returns {protocol_hash}."""
        return self._post("/protocol/compile", {
            "states":        states,
            "initial_state": initial_state,
            "transitions":   transitions or [],
            "metadata":      metadata    or {},
        })

    def create_instance(
        self,
        instance_id:   str,
        protocol_hash: str | None = None,
    ) -> dict:
        """Create a workflow instance. Returns {instance_id, initial_state}."""
        body: dict = {"instance_id": instance_id}
        if protocol_hash:
            body["protocol_hash"] = protocol_hash
        return self._post("/instance/create", body)

    # ── Decisions ─────────────────────────────────────────────────────────────

    def record_decision(
        self,
        instance_id:    str,
        from_state:     str,
        to_state:       str,
        raw_inputs:     dict | None = None,
        # Optional — auto-resolved if omitted
        model_version:  str | None = None,
        agent_version:  str | None = None,
        policy_version: str | None = None,
        reason_code:    str | None = None,
        policy_rule:    str | None = None,
        # Optional extras
        feature_contributions: list[dict] | None = None,
        threshold_used:        str | None = None,
        metadata:              dict | None = None,
    ) -> dict:
        """
        Record an AI decision as a cryptographic proof.

        Minimal usage (governance auto-resolved):
            client.record_decision("loan-001", "pending", "approved",
                                   raw_inputs={"credit_score": "742"})

        Full usage (all fields explicit):
            client.record_decision("loan-001", "pending", "approved",
                                   model_version="credit-model-v3.1",
                                   agent_version="underwriter-v1.0",
                                   policy_version="credit-policy-v2",
                                   reason_code="SCORE_ABOVE_THRESHOLD",
                                   raw_inputs={"credit_score": "742"})

        Returns: {proof_id, sequence_id, instance_id, current_hash, proof_url}
        """
        body: dict = {
            "instance_id": instance_id,
            "from_state":  from_state,
            "to_state":    to_state,
            "raw_inputs":  raw_inputs or {},
        }
        if model_version:            body["model_version"]  = model_version
        if agent_version:            body["agent_version"]  = agent_version
        if policy_version:           body["policy_version"] = policy_version
        if reason_code:              body["reason_code"]    = reason_code
        if policy_rule:              body["policy_rule"]    = policy_rule
        if feature_contributions:    body["feature_contributions"] = feature_contributions
        if threshold_used:           body["threshold_used"] = threshold_used
        if metadata:                 body["metadata"]       = metadata

        return self._post("/decision", body)

    # ── Proofs ────────────────────────────────────────────────────────────────

    def get_proof(self, instance_id: str, sequence_id: int | None = None,
                  verbose: bool = False) -> dict:
        """Get a proof by instance_id. Add verbose=True for full canonical payload."""
        path = f"/proof/{instance_id}"
        params = []
        if sequence_id: params.append(f"sequence_id={sequence_id}")
        if verbose:     params.append("verbose=true")
        if params: path += "?" + "&".join(params)
        return self._get(path)

    def get_chain(self, instance_id: str, full: bool = False) -> dict:
        """Get chain summary. Add full=True for all entries."""
        path = f"/chain/{instance_id}"
        if full: path += "?full=true"
        return self._get(path)

    def export_proof(self, instance_id: str, inline: bool = True) -> dict:
        """Export a complete verifiable proof package."""
        path = f"/proof/export/{instance_id}"
        if inline: path += "?inline=true"
        return self._get(path)

    # ── Verification ──────────────────────────────────────────────────────────

    def verify_proof(self, proof_dict: dict) -> dict:
        """Verify a single proof dict. Returns {valid, ...}."""
        return self._post("/verify", proof_dict)

    def verify_package(self, package: dict) -> dict:
        """
        Verify a complete exported proof package.
        Returns {verified, checks, instance_id, final_state, ...}.
        """
        return self._post("/verify-package", package)

    # ── Audit ─────────────────────────────────────────────────────────────────

    def chain_verify(self) -> dict:
        """Verify the integrity of the full proof ledger for this tenant."""
        return self._get("/audit/chain-verify")

    def compliance_pack(self) -> dict:
        """Export the compliance JSON (SR 11-7 / EU AI Act / CFPB)."""
        return self._get("/audit/compliance")

    # ── Health ────────────────────────────────────────────────────────────────

    def health(self) -> dict:
        """Check if the server is alive. No auth required."""
        return self._request("GET", "/health")

    def ready(self) -> dict:
        """Check if the server is ready (DB + signer available). No auth required."""
        return self._request("GET", "/ready")