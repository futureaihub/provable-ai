/**
 * Zorynex TypeScript SDK
 * ========================
 * Single-file client. Copy into your project — no npm install needed.
 * Works in Node.js (18+), Deno, Bun, and modern browsers.
 *
 * Usage:
 *   import { ZorynexClient } from './zorynex';
 *
 *   const client = new ZorynexClient({
 *     baseUrl:  'http://127.0.0.1:8000',
 *     apiKey:   'dev-key',
 *     tenantId: 'default',
 *   });
 *
 *   // Simple: governance auto-resolved
 *   const proof = await client.recordDecision({
 *     instanceId: 'loan-001',
 *     fromState:  'pending',
 *     toState:    'approved',
 *     rawInputs:  { credit_score: '742' },
 *   });
 *   console.log(proof.proofId);
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ZorynexConfig {
  baseUrl:  string;
  apiKey:   string;
  tenantId: string;
  timeout?: number;   // ms, default 30000
}

export interface DecisionRequest {
  instanceId:    string;
  fromState:     string;
  toState:       string;
  rawInputs?:    Record<string, string>;
  // Optional — auto-resolved from approved lists if omitted
  modelVersion?:  string;
  agentVersion?:  string;
  policyVersion?: string;
  reasonCode?:    string;
  policyRule?:    string;
  featureContributions?: Array<{ feature: string; contribution: string }>;
  thresholdUsed?: string;
  metadata?:      Record<string, string>;
}

export interface DecisionResponse {
  proofId:     string;
  sequenceId:  number;
  instanceId:  string;
  currentHash: string;
  proofUrl:    string;
  traceId:     string;
}

export interface VerifyPackageResponse {
  verified:      boolean;
  instanceId:    string | null;
  finalState:    string | null;
  proofCount:    number;
  modelVersion:  string | null;
  policyVersion: string | null;
  signingKey:    string | null;
  checks: Array<{
    name:    string;
    passed:  boolean;
    detail:  string | null;
    failure: string | null;
  }>;
  traceId: string;
}

export class ZorynexError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly detail: unknown,
  ) {
    super(`HTTP ${statusCode}: ${JSON.stringify(detail)}`);
    this.name = 'ZorynexError';
  }
}

// ── Client ────────────────────────────────────────────────────────────────────

export class ZorynexClient {
  private readonly base:    string;
  private readonly headers: Record<string, string>;
  private readonly timeout: number;

  constructor(config: ZorynexConfig) {
    this.base    = config.baseUrl.replace(/\/$/, '');
    this.timeout = config.timeout ?? 30_000;
    this.headers = {
      'X-API-Key':    config.apiKey,
      'X-Tenant-Id':  config.tenantId,
      'Content-Type': 'application/json',
    };
  }

  // ── HTTP helpers ────────────────────────────────────────────────────────────

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(`${this.base}${path}`, {
        method,
        headers: this.headers,
        body:    body !== undefined ? JSON.stringify(body) : undefined,
        signal:  controller.signal,
      });

      const data = await resp.json();
      if (!resp.ok) throw new ZorynexError(resp.status, data);
      return data as T;
    } finally {
      clearTimeout(timer);
    }
  }

  private get<T>(path: string) { return this.request<T>('GET', path); }
  private post<T>(path: string, body: unknown) { return this.request<T>('POST', path, body); }

  // ── Quickstart ──────────────────────────────────────────────────────────────

  /** Bootstrap a complete demo environment in one call. */
  bootstrap() {
    return this.post<Record<string, unknown>>('/demo/bootstrap', {});
  }

  // ── Governance ──────────────────────────────────────────────────────────────

  approveModel(name: string, version: string) {
    return this.post('/governance/model', { name, version });
  }

  approveAgent(name: string, version: string) {
    return this.post('/governance/agent', { name, version });
  }

  approvePolicy(name: string, version: string) {
    return this.post('/governance/policy', { name, version });
  }

  governanceStatus() {
    return this.get('/governance/status');
  }

  // ── Protocol + instance ─────────────────────────────────────────────────────

  compileProtocol(params: {
    states:       string[];
    initialState: string;
    transitions?: Array<{ from_state: string; to_state: string }>;
    metadata?:    Record<string, string>;
  }) {
    return this.post<{ protocol_hash: string }>('/protocol/compile', {
      states:        params.states,
      initial_state: params.initialState,
      transitions:   params.transitions ?? [],
      metadata:      params.metadata    ?? {},
    });
  }

  createInstance(instanceId: string, protocolHash?: string) {
    return this.post<{ instance_id: string; initial_state: string }>(
      '/instance/create',
      { instance_id: instanceId, ...(protocolHash ? { protocol_hash: protocolHash } : {}) },
    );
  }

  // ── Decisions ───────────────────────────────────────────────────────────────

  /**
   * Record an AI decision as a cryptographic proof.
   *
   * Minimal usage (governance auto-resolved):
   *   await client.recordDecision({
   *     instanceId: 'loan-001', fromState: 'pending', toState: 'approved',
   *     rawInputs: { credit_score: '742' }
   *   });
   */
  recordDecision(req: DecisionRequest): Promise<DecisionResponse> {
    const body: Record<string, unknown> = {
      instance_id: req.instanceId,
      from_state:  req.fromState,
      to_state:    req.toState,
      raw_inputs:  req.rawInputs ?? {},
    };
    if (req.modelVersion)          body['model_version']          = req.modelVersion;
    if (req.agentVersion)          body['agent_version']          = req.agentVersion;
    if (req.policyVersion)         body['policy_version']         = req.policyVersion;
    if (req.reasonCode)            body['reason_code']            = req.reasonCode;
    if (req.policyRule)            body['policy_rule']            = req.policyRule;
    if (req.featureContributions)  body['feature_contributions']  = req.featureContributions;
    if (req.thresholdUsed)         body['threshold_used']         = req.thresholdUsed;
    if (req.metadata)              body['metadata']               = req.metadata;

    return this.post<DecisionResponse>('/decision', body);
  }

  // ── Proofs ──────────────────────────────────────────────────────────────────

  getProof(instanceId: string, opts: { sequenceId?: number; verbose?: boolean } = {}) {
    const params = new URLSearchParams();
    if (opts.sequenceId) params.set('sequence_id', String(opts.sequenceId));
    if (opts.verbose)    params.set('verbose', 'true');
    const qs = params.toString();
    return this.get(`/proof/${instanceId}${qs ? '?' + qs : ''}`);
  }

  getChain(instanceId: string, full = false) {
    return this.get(`/chain/${instanceId}${full ? '?full=true' : ''}`);
  }

  exportProof(instanceId: string, inline = true) {
    return this.get(`/proof/export/${instanceId}${inline ? '?inline=true' : ''}`);
  }

  // ── Verification ────────────────────────────────────────────────────────────

  verifyProof(proofDict: Record<string, unknown>) {
    return this.post('/verify', proofDict);
  }

  verifyPackage(pkg: Record<string, unknown>): Promise<VerifyPackageResponse> {
    return this.post<VerifyPackageResponse>('/verify-package', pkg);
  }

  // ── Audit ────────────────────────────────────────────────────────────────────

  chainVerify() { return this.get('/audit/chain-verify'); }
  compliancePack() { return this.get('/audit/compliance'); }

  // ── Health ────────────────────────────────────────────────────────────────────

  health() { return this.get('/health'); }
  ready()  { return this.get('/ready'); }
}