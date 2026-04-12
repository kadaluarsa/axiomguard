export class Guard {
  constructor(config: {
    cpUrl: string;
    apiKey: string;
    tenantId: string;
    agentId?: string;
    verifyingKeyHex?: string;
    timeout?: number;
  });
  check(
    tool: string,
    args: Record<string, unknown>,
    options?: { sessionId?: string; agentId?: string },
  ): Promise<GuardResult>;
}

export class GuardResult {
  decision: string;
  reason: string;
  riskScore: number;
  token: string | null;
  tool: string;
  agentId: string;
  sessionId: string;
  get allowed(): boolean;
}

export function computeHash(argsObj: Record<string, unknown>): string;
export function verifyToken(
  tokenStr: string,
  verifyingKeyHex: string,
): VerifyResult;
export function verifyTokenWithChecks(
  tokenStr: string,
  verifyingKeyHex: string,
  options?: {
    expectedTool?: string;
    expectedAgentId?: string;
    expectedArgs?: Record<string, unknown>;
    maxRisk?: number;
  },
): VerifyResult;

export interface Claims {
  tool: string;
  args_hash: string;
  session_id: string;
  tenant_id: string;
  agent_id: string;
  decision: string;
  iat: number;
  exp: number;
  jti: string;
  risk_score: number;
}

export interface VerifyResult {
  valid: boolean;
  claims: Claims | null;
  error: string | null;
}
