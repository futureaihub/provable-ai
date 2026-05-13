# Zorynex — Auditor Verification Guide

**Audience:** Auditors, regulators, compliance teams, and legal counsel verifying AI decisions.

**Key property:** You can verify every proof with zero access to the originating system — no server, no database, no trust required.

---

## How auditor verification works — end to end

You receive one file. You run one command. That is the entire process.

```
Step 1   You receive proof_loan9284.json from the operator
         (sent by email, secure share, or any file transfer)

Step 2   pip install pynacl
         (one-time — standard cryptography library, nothing Zorynex-specific)

Step 3   python verify/verify_package.py proof_loan9284.json
```

Output:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ZORYNEX · PROOF VERIFICATION REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✓  [PASS]  Package structure valid
             Proof package schema and required fields confirmed

  ✓  [PASS]  Package untampered
             SHA-256 of ledger matches stored package hash

  ✓  [PASS]  Chain valid
             Hash chain linkage verified across all decisions

  ✓  [PASS]  Original signer verified
             Ed25519 signature over instance root confirmed

────────────────────────────────────────────────────────────────
  Instance      loan-application-9284
  Final state   approved
  Chain length  3 decisions
  Signed by     env-58c9d4aa2634ed9a
  Tamper status CLEAN
────────────────────────────────────────────────────────────────

  FINAL VERDICT:  ✓  VALID EVIDENCE
```

No Zorynex account. No API key. No network connection at verification time. The proof either verifies cryptographically or it does not — there is no middle ground.

The verifier script (`verify/verify_package.py`) is a single Python file available from the public GitHub repository. The source code is readable — you can confirm exactly what it checks before running it.

---

## Option 1: Browser verifier (no terminal required)

If the operator's Zorynex deployment is running, they will provide a link:

```
http://[their-server-address]/verify-ui
```

1. Open the link in any browser
2. Drag and drop the `.json` proof package file
3. Four checks run entirely in your browser — the file never leaves your device
4. Download a PDF verification report for your records

**Note:** This requires the operator's server to be running. For permanent offline verification that works without any server, use the CLI method above.

---

## Option 2: Command line (recommended for formal verification)

```bash
pip install pynacl
```

```bash
# Primary verifier
python verify/verify_package.py proof_package.json

# With full decision chain table
python verify/verify_package.py proof_package.json --verbose

# Machine-readable JSON output (for integrations)
python verify/verify_package.py proof_package.json --json

# Legacy individual verifiers
python verify/verify_signature.py proof_package.json
python verify/verify_batch.py     batch_export.json
```

---

## Option 3: API

If the operator provides API access:

```bash
curl -X POST https://[server]/verify-package \
  -H "X-API-Key: [your-audit-key]" \
  -H "Content-Type: application/json" \
  -d @proof_package.json
```

Response:
```json
{
  "verified":      true,
  "instance_id":   "loan-application-9284",
  "final_state":   "approved",
  "proof_count":   3,
  "chain_length":  3,
  "proof_fingerprint": "b7ee4d91b9fcde28...",
  "model_version": "credit-model-v3.1",
  "policy_version":"credit-policy-v2",
  "signing_key":   "env-58c9d4aa2634ed9a",
  "checks": [
    {"name": "Package structure valid", "passed": true, "detail": "3 proofs in package"},
    {"name": "Package untampered",      "passed": true, "detail": "SHA-256 matches"},
    {"name": "Chain valid",             "passed": true, "detail": "sequence 1→3"},
    {"name": "Signature valid",         "passed": true, "detail": "Ed25519 key: env-58c9..."}
  ]
}
```

---

## What the checks prove

| Check | What failure means |
|---|---|
| **Package structure** | File is corrupted or not a Zorynex proof |
| **Package untampered** | Any field in any decision was modified after export |
| **Chain valid** | A decision was inserted, deleted, or reordered |
| **Signature valid** | The file was not signed by the claimed AI system |

A tampered proof fails immediately:
```
  ✓  [PASS]  Package structure valid
  ✗  [FAIL]  Package untampered
             Hash mismatch — content was modified after export.
             stored:   6358d2d4ee79...
             computed: a1b2c3d4...

  FINAL VERDICT:  ✗  VERIFICATION FAILED
```

---

## Reading the proof metadata

Each decision in the proof contains:

| Field | Description |
|---|---|
| `instance_id` | The entity this decision belongs to (loan, account, claim) |
| `sequence_id` | Position in the chain — gaps indicate tampering |
| `from_state` / `to_state` | The state transition that occurred |
| `model_version` | Which AI model made this decision |
| `agent_version` | Which agent orchestrated the decision |
| `policy_version` | Which policy governed the decision |
| `reason_code` | Machine-readable reason (e.g. `SCORE_ABOVE_THRESHOLD`) |
| `feature_contributions` | Model explanation captured at execution time |
| `threshold_used` | Decision threshold at the time of execution |
| `inputs_hash` | SHA-256 of raw inputs — request the original values from the operator if needed |
| `timestamp` | UTC timestamp of the decision |
| `current_hash` | SHA-256 of this proof's content |
| `previous_hash` | Links to the prior proof in the chain |
| `chain_length` | Total number of decisions in this proof package |
| `proof_fingerprint` | Deterministic package identity — independently verifiable |

---

## Compliance exports

For structured regulatory submissions, request from the operator:

```
GET /audit/compliance    # SR 11-7 / EU AI Act / CFPB compliance pack
GET /audit/export        # Full batch export with Merkle root
GET /audit/report        # PDF audit report
```

---

## Frequently asked questions

**What is `proof_fingerprint` and how do I verify it?**

`proof_fingerprint` is a cryptographically deterministic identity for the proof package — reproducible by anyone with access to the package fields.

**Formula:**
```
proof_fingerprint = SHA256(instance_root + ":" + chain_length)
```

Both `instance_root` and `chain_length` are embedded in the package. To verify independently:

```python
import hashlib, json

pkg           = json.load(open("proof.json"))
instance_root = pkg["proof"]["instance_root"]
chain_length  = pkg["chain_length"]
expected      = hashlib.sha256(f"{instance_root}:{chain_length}".encode()).hexdigest()

assert expected == pkg["proof_fingerprint"]
print("✓ Fingerprint confirmed:", expected[:16] + "...")
```

This is separate from the Ed25519 signature check. The fingerprint confirms proof identity — you have the right package. The signature confirms proof integrity — the package has not been modified. Both checks should pass.

**What does `chain_length` tell me?**

`chain_length` is the number of decisions in the proof package ledger. If you requested proof for an instance with 5 recorded decisions and `chain_length` is 3, two entries are missing. Always verify `chain_length` matches your expected decision count before accepting a proof as complete evidence.

**Does the operator need to keep their server running for me to verify?**

No — for CLI verification. You verify the file offline with `python verify/verify_package.py proof.json`. No server. No network. No access to the operator's systems.

The browser verifier at `/verify-ui` does require the operator's server to be running. For formal independent verification that works permanently without any server dependency, use the CLI.

**Can the operator alter a proof after I receive it?**

No. The `package_hash` covers the entire ledger serialization. Any modification — even a single character — produces a different hash. The CLI and browser verifiers both check this.

**Can the operator generate a fake proof?**

Only with access to the Ed25519 private key. The signing key identity (`env-58c9d4aa...`) is embedded in every proof and in the `public_key` field of the package. If you have the expected public key on record, you can verify the signature independently without relying on the operator's word.

**What if I don't have PyNaCl installed?**

Use the browser verifier at `/verify-ui` — it uses the browser's built-in Web Crypto API and requires no installation. Or install pynacl once: `pip install pynacl`.

**What does RFC 3161 anchoring prove?**

If RFC 3161 timestamps are enabled, each proof is submitted to an independent timestamp authority (FreeTSA) at the time of execution. This proves the decision existed at or before the timestamp — even if the operator's infrastructure is later compromised or altered.

---

See also: [dev.md](dev.md) for technical integration details.
