# Zorynex — Independent Verification Kit

Three standalone scripts. Zero Zorynex infrastructure required.
An auditor, regulator, or external party can verify proofs on any machine.

## Requirements

```bash
pip install pynacl          # Ed25519 signature verification
# openssl                   # for full RFC 3161 cryptographic check (system package)
```

---

## 1. Verify a proof signature

```bash
python verify_signature.py proof.json
python verify_signature.py proof.json --public-key <64-hex-public-key>
```

What it checks:
- Recomputes SHA-256 hash from canonical proof content
- Verifies Ed25519 signature over that hash
- Exits 0 if valid, 1 if invalid

---

## 2. Verify a batch export

```bash
# Full batch
python verify_batch.py batch_export.json

# Single proof membership (without revealing other proofs)
python verify_batch.py batch_export.json --proof-id <proof_id_hex>

# Pre-computed inclusion proof
python verify_batch.py --inclusion-proof inclusion_proof.json
```

What it checks:
- Recomputes Merkle root from all proof_ids in the batch
- Verifies Ed25519 signature over the Merkle root
- (Optional) Inclusion proof: proves one proof is in the tree

---

## 3. Verify anchor records

```bash
# Verify the anchor store chain is intact
python verify_anchor.py --anchor-db zorynex_anchors.db --tenant bank_abc

# Structural RFC 3161 check (no openssl needed)
python verify_anchor.py --hash <64-hex-chain-hash> --token anchor.tsr

# Full cryptographic RFC 3161 check (requires openssl + FreeTSA cert)
curl -O https://www.freetsa.org/files/cacert.pem
python verify_anchor.py \
    --hash <64-hex-chain-hash> \
    --token anchor.tsr \
    --ca cacert.pem
```

What it checks:
- Structural: confirms the chain_hash is embedded in the RFC 3161 token
- Cryptographic: runs `openssl ts -verify` to confirm TSA signature
- Chain: walks every anchor row and recomputes the hash chain

---

## Trust model

| Check | What it proves | Who controls it |
|---|---|---|
| `verify_signature.py` | Proof content was not modified after signing | Zorynex (your key) |
| `verify_batch.py` | Batch was not modified after export | Zorynex (your key) |
| `verify_anchor.py` structural | Token was issued for this hash | FreeTSA (external) |
| `verify_anchor.py` cryptographic | FreeTSA actually signed this | FreeTSA (external) |

The RFC 3161 timestamp is the only check outside Zorynex's control boundary.
An attacker who compromises all Zorynex infrastructure cannot forge a FreeTSA
signature on an old or fabricated chain_hash.

---

## Exit codes

- `0` — verification passed
- `1` — verification failed or error