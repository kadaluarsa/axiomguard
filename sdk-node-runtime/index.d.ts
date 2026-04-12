export interface GuardParams {
  cpUrl: string;
  apiKey: string;
  tenantId: string;
  agentId: string;
  timeout?: number;
}

export declare class Guard {
  constructor(params: GuardParams);
  check(tool: string, args: any, options?: { sessionId?: string; agentId?: string }): Promise<{
    decision: string;
    reason?: string;
    riskScore?: number;
    token?: string;
    tool: string;
    agentId?: string;
    sessionId?: string;
    allowed?: boolean;
  }>;
}

export interface RuntimeGuardParams extends GuardParams {
  flushIntervalMs?: number;
  refreshPolicyMs?: number;
}

export declare class RuntimeGuard {
  constructor(params: RuntimeGuardParams);
  start(): void;
  stop(): void;
  check(tool: string, args: any, options?: { sessionId?: string; agentId?: string }): Promise<any>;
}
