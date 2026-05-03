# Zorynex — Auditor Verification Guide

**Audience:** Auditors, regulators, compliance teams, and legal counsel verifying AI decisions.

**Key property:** You can verify every proof with zero access to the originating system — no server, no database, no trust required.

---

## What you receive

A **proof package** (JSON file) containing:
- Every AI decision for an account, loan, or case
- The cryptographic hash chain linking them in sequence
- Ed25519 signatures proving each decision's authenticity
- Optional RFC 3161 timestamps proving when decisions occurred

---

## Option 1: Browser verifier (recommended — no installation)

Open the link sent with your proof package:

```
http://[server-address]/verify-ui
```

1. Drag and drop the `.json` proof package file
2. Four checks run in your browser — no data leaves your device
3. Review the results and download a PDF verification report

**What it verifies:**
- ✓ Package structure valid
- ✓ Package untampered (SHA-256 of full ledger)
- ✓ Chain valid (per-proof hashes + linkage)
- ✓ Signature valid (Ed25519 over instance root)

---

## Option 2: Command line (one dependency)

```bash
pip install pynacl    # Ed25519 verification — one package
```

```bash
# Primary verifier (recommended)
python verify/verify_package.py proof_package.json

# Legacy individual verifiers
python verify/verify_signature.py proof_package.json
python verify/verify_batch.py     batch_export.json
```

Output:
```
  ✓ Package structure valid  (3 proofs in package)
  ✓ Package untampered       (SHA-256 of full ledger matches package_hash)
  ✓ Chain valid              (3 proofs, sequence 1→3)
  ✓ Signature valid          (Ed25519  key: env-58c9d4aa2634ed9a)

  RESULT:  VERIFIED ✓
  Instance:    loan-application-9284
  Final state: funded
  Chain:       3 decisions  (sequence 1→3)
  Signed by:   env-58c9d4aa2634ed9a
```

Additional options:
```bash
python verify/verify_package.py proof.json --verbose   # full decision chain table
python verify/verify_package.py proof.json --json      # machine-readable output
```

---

## Option 3: API

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
  "final_state":   "funded",
  "proof_count":   3,
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
  ✓ Package structure valid
  ✗ Package untampered
       Hash mismatch — content was modified after export.
       stored:   6358d2d4ee79...
       computed: a1b2c3d4...

  RESULT:  VERIFICATION FAILED ✗
```

---

## Reading the proof metadata

Each decision contains:

| Field | Description |
|---|---|
| `instance_id` | The entity this decision belongs to (loan, account, claim) |
| `sequence_id` | Position in the chain — gaps indicate tampering |
| `from_state` / `to_state` | The state transition that occurred |
| `model_version` | Which AI model made this decision |
| `agent_version` | Which agent orchestrated the decision |
| `policy_version` | Which policy governed the decision |
| `reason_code` | Machine-readable reason (e.g. `SCORE_ABOVE_THRESHOLD`) |
| `inputs_hash` | SHA-256 of raw inputs — request the preimage from the operator |
| `timestamp` | UTC timestamp of the decision |
| `current_hash` | SHA-256 of this proof's content |
| `previous_hash` | Links to the prior proof in the chain |

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

**Can the operator alter a proof after I receive it?**
No. The `package_hash` covers the entire ledger serialization. Any modification — even a single character — produces a different hash. The browser and CLI verifiers both check this.

**Can the operator generate a fake proof?**
Only with access to the Ed25519 private key. The signing key identity (`env-58c9d4aa...`) is embedded in every proof and in the `public_key` field of the package. If you have the expected public key, you can verify the signature independently.

**What if I don't have PyNaCl installed?**
Use the browser verifier at `/verify-ui` — it uses the browser's built-in Web Crypto API and requires no installation.

**What does RFC 3161 anchoring prove?**
If RFC 3161 timestamps are enabled, each proof is submitted to an independent timestamp authority (FreeTSA). This proves the decision existed at or before the timestamp — even if your infrastructure is later compromised.

---

See also: [dev.md](dev.md) for technical integration details.