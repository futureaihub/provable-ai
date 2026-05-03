/**
 * Zorynex TypeScript Verifier
 * ============================
 * Pure verification logic. No DOM. No framework. No network calls.
 * Works in browser (ESM) and Node.js 18+.
 *
 * Install:  npm install
 * Build:    npx tsc
 * Use:      import { verifyProof, verifyChain } from "./dist/verifier.js";
 *
 * Verification steps (in order):
 *   1. Structure     — required fields present, types correct
 *   2. Hash          — recompute SHA-256, compare with ledger.current_hash
 *   3. Signature     — Ed25519 valid against embedded public_key
 *   4. Chain         — previous_hash links to prior proof
 *   5. Sequence      — sequence_ids consecutive
 *   6. Proof ID      — deterministic ID correct
 *
 * Canonical JSON rules match Python exactly:
 *   json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)
 */

import * as ed from "@noble/ed25519";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface VerificationResult {
  valid: boolean;
  chain_intact: boolean;
  sequence_verified: number;
  final_state: string | null;
  key_id: string | null;
  verified_at: string;
  governance_recorded: GovernanceInfo | null;
  governance_verified: false;
  replay_result: ReplayInfo | null;
  failure_reason: FailureReason | null;
}

export interface GovernanceInfo {
  model_version: string;
  agent_version: string;
  policy_version: string;
  determinism_mode: string;
}

export interface ReplayInfo {
  mode_valid: boolean;
  seed_captured: boolean;
  external_calls_recorded: number;
  full_replay_executed: false;
  determinism_mode: string;
}

export interface FailureReason {
  type: string;
  message: string;
  sequence_id: number;
  expected?: string;
  stored?: string;
  key_id?: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const GENESIS_HASH = "0".repeat(64);

const REQUIRED_TOP_FIELDS = [
  "type", "instance_id", "decision", "decision_context",
  "governance", "determinism", "ledger", "signature",
] as const;

const REQUIRED_LEDGER_FIELDS = [
  "sequence_id", "previous_hash", "current_hash", "timestamp",
] as const;

const REQUIRED_SIGNATURE_FIELDS = [
  "algorithm", "key_id", "public_key", "value",
] as const;

// ── Canonical JSON ────────────────────────────────────────────────────────────
// Matches Python: json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)

export function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite number in payload");
    if (!Number.isInteger(value)) throw new Error(`Float ${value} not allowed — use string or integer`);
    return String(value);
  }
  if (typeof value === "string") {
    // JSON.stringify escapes non-ASCII as \uXXXX.
    // Python ensure_ascii=False keeps them as UTF-8.
    // Unescape to match.
    return JSON.stringify(value).replace(
      /\\u([0-9a-fA-F]{4})/g,
      (_, hex) => String.fromCodePoint(parseInt(hex, 16))
    );
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return "{" + Object.keys(obj).sort()
      .map(k => canonicalJson(k) + ":" + canonicalJson(obj[k]))
      .join(",") + "}";
  }
  throw new Error(`Unsupported type: ${typeof value}`);
}

// ── SHA-256 via WebCrypto ─────────────────────────────────────────────────────

async function sha256Hex(data: Uint8Array<ArrayBuffer>): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256HexStr(s: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(s));
}

// ── Hex utilities ─────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0) throw new Error(`Odd hex length: ${hex.length}`);
  const bytes = new Uint8Array(hex.length / 2) as Uint8Array<ArrayBuffer>;
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function isValidHex(s: unknown, expectedLen?: number): s is string {
  if (typeof s !== "string" || s.length === 0) return false;
  if (expectedLen !== undefined && s.length !== expectedLen) return false;
  return /^[0-9a-fA-F]+$/.test(s);
}

// ── Ed25519 ───────────────────────────────────────────────────────────────────
// Uses @noble/ed25519 — auditable 5KB pure-JS implementation.
// API: verifyAsync(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array)

async function verifyEd25519(
  publicKeyHex: string,
  messageBytes: Uint8Array,
  signatureHex: string
): Promise<boolean> {
  return ed.verifyAsync(
    hexToBytes(signatureHex),
    messageBytes,
    hexToBytes(publicKeyHex)
  );
}

// ── Hash payload ──────────────────────────────────────────────────────────────
// Matches Python build_hash_payload() exactly.
// INCLUDED:  decision, decision_context, governance, determinism,
//            previous_hash, sequence_id
// EXCLUDED:  timestamp, current_hash, signature, public_key, key_id,
//            type, instance_id, proof_id, tenant_id

function buildHashPayload(proof: Record<string, unknown>): Record<string, unknown> {
  const ledger = proof["ledger"] as Record<string, unknown>;
  return {
    decision:         proof["decision"],
    decision_context: proof["decision_context"],
    determinism:      proof["determinism"],
    governance:       proof["governance"],
    previous_hash:    ledger["previous_hash"],
    sequence_id:      ledger["sequence_id"],
  };
}

// ── proof_id ──────────────────────────────────────────────────────────────────
// Locked cross-language formula:
//   proof_id = sha256(f"{current_hash}:{sequence_id}".encode("utf-8")).hexdigest()

export async function computeProofId(currentHash: string, sequenceId: number): Promise<string> {
  return sha256HexStr(`${currentHash}:${sequenceId}`);
}

// ── Structure validation ──────────────────────────────────────────────────────

function validateStructure(proof: unknown): string | null {
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
    return "Proof must be a JSON object";
  }
  const p = proof as Record<string, unknown>;

  for (const f of REQUIRED_TOP_FIELDS) {
    if (!(f in p)) return `Missing required field: "${f}"`;
  }

  if (p["type"] !== "zorynex-proof-v1") {
    return `type must be "zorynex-proof-v1", got "${p["type"]}"`;
  }

  const ledger = p["ledger"];
  if (!ledger || typeof ledger !== "object" || Array.isArray(ledger)) {
    return "ledger must be an object";
  }
  const l = ledger as Record<string, unknown>;
  for (const f of REQUIRED_LEDGER_FIELDS) {
    if (!(f in l)) return `Missing ledger field: "${f}"`;
  }

  const signature = p["signature"];
  if (!signature || typeof signature !== "object" || Array.isArray(signature)) {
    return "signature must be an object";
  }
  const s = signature as Record<string, unknown>;
  for (const f of REQUIRED_SIGNATURE_FIELDS) {
    if (!(f in s)) return `Missing signature field: "${f}"`;
  }

  if (!isValidHex(s["public_key"], 64)) {
    return "signature.public_key must be 64 lowercase hex chars (32-byte Ed25519 public key)";
  }
  if (!isValidHex(s["value"], 128)) {
    return "signature.value must be 128 lowercase hex chars (64-byte Ed25519 signature)";
  }
  if (!isValidHex(l["current_hash"], 64)) {
    return "ledger.current_hash must be 64 hex chars";
  }
  if (typeof l["sequence_id"] !== "number" || !Number.isInteger(l["sequence_id"]) || l["sequence_id"] < 1) {
    return "ledger.sequence_id must be integer >= 1";
  }

  return null;
}

// ── Failure helper ────────────────────────────────────────────────────────────

function fail(
  type: string,
  message: string,
  sequenceId: number,
  verifiedAt: string,
  extra: Partial<FailureReason> = {},
  keyId: string | null = null
): VerificationResult {
  return {
    valid: false,
    chain_intact: false,
    sequence_verified: sequenceId,
    final_state: null,
    key_id: keyId,
    verified_at: verifiedAt,
    governance_recorded: null,
    governance_verified: false,
    replay_result: null,
    failure_reason: { type, message, sequence_id: sequenceId, ...extra },
  };
}

// ── verifyProof ───────────────────────────────────────────────────────────────

/**
 * Verify a single proof artifact.
 *
 * Works completely offline. No network. No server. No trust.
 * The public_key embedded in proof.signature enables self-contained verification.
 *
 * @param proofInput          Parsed proof.json object
 * @param expectedPreviousHash If verifying within a chain — the prior proof's current_hash
 * @param expectedSequenceId  If verifying within a chain — the expected sequence number
 */
export async function verifyProof(
  proofInput: unknown,
  expectedPreviousHash: string | null = null,
  expectedSequenceId: number | null = null
): Promise<VerificationResult> {
  const verifiedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  let keyId: string | null = null;
  let seqId = 0;
  let finalState: string | null = null;

  // ── Step 1: Structure ───────────────────────────────────────────────────
  const structErr = validateStructure(proofInput);
  if (structErr) {
    return fail("SchemaValidationError", structErr, 0, verifiedAt);
  }

  const proof   = proofInput as Record<string, unknown>;
  const ledger  = proof["ledger"]    as Record<string, unknown>;
  const sigObj  = proof["signature"] as Record<string, unknown>;
  const decision = proof["decision"] as Record<string, unknown>;

  keyId      = String(sigObj["key_id"]);
  seqId      = Number(ledger["sequence_id"]);
  finalState = String(decision["to_state"]);

  // ── Step 2: Hash ─────────────────────────────────────────────────────────
  const payload     = buildHashPayload(proof);
  const canonical   = canonicalJson(payload);
  const recomputed  = await sha256Hex(new TextEncoder().encode(canonical));
  const storedHash  = String(ledger["current_hash"]).toLowerCase();

  if (recomputed !== storedHash) {
    return fail("HashMismatch",
      `Recomputed hash '${recomputed.slice(0, 16)}...' does not match stored hash '${storedHash.slice(0, 16)}...'. Payload was modified after signing.`,
      seqId, verifiedAt,
      { expected: recomputed, stored: storedHash },
      keyId
    );
  }

  // ── Step 3: Signature ─────────────────────────────────────────────────────
  const hashBytes  = hexToBytes(storedHash);
  const pubKeyHex  = String(sigObj["public_key"]).toLowerCase();
  const sigHex     = String(sigObj["value"]).toLowerCase();

  let sigValid: boolean;
  try {
    sigValid = await verifyEd25519(pubKeyHex, hashBytes, sigHex);
  } catch (e) {
    return fail("SignatureError",
      `Ed25519 verification threw: ${e instanceof Error ? e.message : String(e)}`,
      seqId, verifiedAt, { key_id: keyId }, keyId
    );
  }

  if (!sigValid) {
    return fail("SignatureMismatch",
      `Ed25519 signature invalid for key '${keyId}'. Signature does not verify against embedded public_key.`,
      seqId, verifiedAt, { key_id: keyId }, keyId
    );
  }

  // ── Step 4: Chain ─────────────────────────────────────────────────────────
  const prevHash = String(ledger["previous_hash"]).toLowerCase();

  if (expectedPreviousHash !== null) {
    if (prevHash !== expectedPreviousHash.toLowerCase()) {
      return fail("ChainBroken",
        `Hash chain broken at sequence_id=${seqId}. previous_hash does not match prior proof's current_hash.`,
        seqId, verifiedAt,
        { expected: expectedPreviousHash, stored: prevHash },
        keyId
      );
    }
  } else if (seqId === 1 && prevHash !== GENESIS_HASH) {
    return fail("ChainBroken",
      `First proof (sequence_id=1) must have previous_hash = genesis hash (64 zeros).`,
      seqId, verifiedAt,
      { expected: GENESIS_HASH, stored: prevHash },
      keyId
    );
  }

  // ── Step 5: Sequence ──────────────────────────────────────────────────────
  if (expectedSequenceId !== null && seqId !== expectedSequenceId) {
    return fail("SequenceGap",
      `Expected sequence_id=${expectedSequenceId}, got ${seqId}.`,
      seqId, verifiedAt,
      { expected: String(expectedSequenceId), stored: String(seqId) },
      keyId
    );
  }

  // ── Step 6: proof_id ──────────────────────────────────────────────────────
  const proofIdField = proof["proof_id"];
  if (proofIdField) {
    const expectedId = await computeProofId(storedHash, seqId);
    if (String(proofIdField).toLowerCase() !== expectedId) {
      return fail("ProofIdMismatch",
        `proof_id does not match expected '${expectedId.slice(0, 16)}...'.`,
        seqId, verifiedAt,
        { expected: expectedId, stored: String(proofIdField) },
        keyId
      );
    }
  }

  // ── All checks passed ─────────────────────────────────────────────────────
  const governance  = proof["governance"]  as Record<string, unknown>;
  const determinism = proof["determinism"] as Record<string, unknown>;

  return {
    valid: true,
    chain_intact: true,
    sequence_verified: seqId,
    final_state: finalState,
    key_id: keyId,
    verified_at: verifiedAt,
    governance_recorded: {
      model_version:    String(governance["model_version"]),
      agent_version:    String(governance["agent_version"]),
      policy_version:   String(governance["policy_version"]),
      determinism_mode: String(determinism["mode"]),
    },
    governance_verified: false,
    replay_result: {
      mode_valid:               true,
      seed_captured:            determinism["seed"] != null,
      external_calls_recorded:  determinism["external_calls_hash"] ? 1 : 0,
      full_replay_executed:     false,
      determinism_mode:         String(determinism["mode"]),
    },
    failure_reason: null,
  };
}

// ── verifyChain ───────────────────────────────────────────────────────────────

/**
 * Verify a complete chain of proofs.
 * Each proof is verified individually AND hash chain links are validated.
 *
 * @param proofs Array of proof.json objects — oldest first (sequence_id ascending)
 */
export async function verifyChain(proofs: unknown[]): Promise<VerificationResult> {
  const verifiedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  if (!Array.isArray(proofs) || proofs.length === 0) {
    return fail("EmptyChain", "No proofs provided", 0, verifiedAt);
  }

  let lastHash = GENESIS_HASH;

  for (let i = 0; i < proofs.length; i++) {
    const result = await verifyProof(proofs[i], lastHash, i + 1);
    if (!result.valid) return result;

    const p = proofs[i] as Record<string, unknown>;
    const l = p["ledger"] as Record<string, unknown>;
    lastHash = String(l["current_hash"]).toLowerCase();
  }

  // Build final result from last proof
  const last     = proofs[proofs.length - 1] as Record<string, unknown>;
  const lastLedger  = last["ledger"]    as Record<string, unknown>;
  const lastSig     = last["signature"] as Record<string, unknown>;
  const lastDec     = last["decision"]  as Record<string, unknown>;
  const lastGov     = last["governance"]  as Record<string, unknown>;
  const lastDet     = last["determinism"] as Record<string, unknown>;

  return {
    valid: true,
    chain_intact: true,
    sequence_verified: proofs.length,
    final_state: String(lastDec["to_state"]),
    key_id: String(lastSig["key_id"]),
    verified_at: verifiedAt,
    governance_recorded: {
      model_version:    String(lastGov["model_version"]),
      agent_version:    String(lastGov["agent_version"]),
      policy_version:   String(lastGov["policy_version"]),
      determinism_mode: String(lastDet["mode"]),
    },
    governance_verified: false,
    replay_result: {
      mode_valid:              true,
      seed_captured:           lastDet["seed"] != null,
      external_calls_recorded: lastDet["external_calls_hash"] ? 1 : 0,
      full_replay_executed:    false,
      determinism_mode:        String(lastDet["mode"]),
    },
    failure_reason: null,
  };
}