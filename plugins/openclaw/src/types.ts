/** AxiomGuard OpenClaw Plugin — internal types */

/** Mapping from an OpenClaw tool name to an AxiomGuard category. */
export interface ToolMapping {
  category: string;
  riskMultiplier: number;
  block?: boolean;
  requireApproval?: boolean;
}

/** Per-session cumulative risk state. */
export interface SessionState {
  sessionId: string;
  risk: number;
  entries: Array<{
    category: string;
    riskScore: number;
    decision: string;
    ts: number;
  }>;
  lastActivity: number;
}

/** Plugin configuration after validation and defaults applied. */
export interface AxiomGuardPluginConfig {
  enabled: true;
  cpUrl: string;
  apiKey: string;
  tenantId: string;
  agentId: string;
  sessionRiskLimit: number;
  failOpen: boolean;
  requireApprovalCategories: string[];
  blockedTools: string[];
  blockedCategories: string[];
  toolOverrides: Record<string, Partial<ToolMapping>>;
  timeout: number;
  auditFlushIntervalMs: number;
}

/** Disabled config — plugin self-disables with zero overhead. */
export interface DisabledConfig {
  enabled: false;
}

/** Final validated config is either enabled or disabled. */
export type ValidatedConfig = AxiomGuardPluginConfig | DisabledConfig;

/** Dependencies injected into the hook handler for testability. */
export interface HookDeps {
  config: AxiomGuardPluginConfig;
  runtimeGuard: {
    check: (
      tool: string,
      args: unknown,
      options?: { sessionId?: string; agentId?: string },
    ) => Promise<{
      decision?: string;
      reason?: string;
      riskScore?: number;
      allowed?: boolean;
    }>;
  };
  sessionTracker: {
    getRisk: (sessionId: string) => number;
    record: (
      sessionId: string,
      entry: { category: string; riskScore: number; decision: string },
    ) => void;
  };
  resolveToolMapping: (
    toolName: string,
    overrides?: Record<string, Partial<ToolMapping>>,
  ) => ToolMapping;
}

/** OpenClaw hook context passed to before_tool_call. */
export interface ToolCallContext {
  tool: string;
  args: Record<string, unknown>;
  sessionId?: string;
  agentId?: string;
}

/** Hook response returned to OpenClaw. */
export interface HookResponse {
  block?: boolean;
  requireApproval?: boolean;
  reason?: string;
}
