/** AxiomGuard OpenClaw Plugin v2 — types matching real OpenClaw plugin API */

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

// ---------------------------------------------------------------------------
// Real OpenClaw hook shapes (matching openclaw/openclaw src/plugins/types.ts)
// ---------------------------------------------------------------------------

/** Hook input — what OpenClaw passes to before_tool_call. */
export interface ToolCallInput {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
}

/** Hook context — separate second parameter with agent/session info. */
export interface ToolCallContext {
  toolName: string;
  agentId: string;
  sessionKey: string;
}

/** Hook result — what before_tool_call returns to OpenClaw. */
export interface ToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
  requireApproval?: {
    id?: string;
    title: string;
    description: string;
    severity?: "info" | "warning" | "critical";
    pluginId?: string;
  };
}

// ---------------------------------------------------------------------------
// Plugin config — supports standalone and managed modes
// ---------------------------------------------------------------------------

/** Raw config as it arrives from OpenClaw (all optional). */
export interface AxiomGuardPluginConfig {
  // General
  enabled?: boolean;
  failOpen?: boolean;

  // Standalone mode (default when cpUrl absent)
  blockedTools?: string[];
  blockedCategories?: string[];
  requireApprovalCategories?: string[];
  sessionRiskLimit?: number;
  toolOverrides?: Record<string, Partial<ToolMapping>>;

  // Managed mode (requires cpUrl + apiKey + tenantId)
  cpUrl?: string;
  apiKey?: string;
  tenantId?: string;
  agentId?: string;
  timeout?: number;
  auditFlushIntervalMs?: number;
}

/** Validated config after applying defaults. */
export interface ValidatedConfig {
  enabled: true;
  failOpen: boolean;
  blockedTools: string[];
  blockedCategories: string[];
  requireApprovalCategories: string[];
  sessionRiskLimit: number;
  toolOverrides: Record<string, Partial<ToolMapping>>;
  // Managed mode fields (absent in standalone)
  cpUrl?: string;
  apiKey?: string;
  tenantId?: string;
  agentId?: string;
  timeout?: number;
  auditFlushIntervalMs?: number;
}

/** Disabled config — plugin self-disables. */
export interface DisabledConfig {
  enabled: false;
}

export type ResolvedConfig = ValidatedConfig | DisabledConfig;

// ---------------------------------------------------------------------------
// Dependency injection for hook handler (testability)
// ---------------------------------------------------------------------------

export interface HookDeps {
  config: ValidatedConfig;
  runtimeGuard?: {
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
  evaluateLocal: (
    input: ToolCallInput,
    config: ValidatedConfig,
    sessionRisk: number,
    mapping: ToolMapping,
  ) => ToolCallResult | undefined;
}

// ---------------------------------------------------------------------------
// OpenClaw config schema (for plugin registration)
// ---------------------------------------------------------------------------

export interface OpenClawPluginConfigSchema {
  safeParse?: (value: unknown) => {
    success: boolean;
    data?: unknown;
    error?: { issues?: Array<{ message: string; path?: string[] }> };
  };
  jsonSchema?: Record<string, unknown>;
}
