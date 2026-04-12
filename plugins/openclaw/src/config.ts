import type {
  AxiomGuardPluginConfig,
  DisabledConfig,
  ValidatedConfig,
  ToolMapping,
} from "./types.js";

interface RawConfig {
  cpUrl?: string;
  apiKey?: string;
  tenantId?: string;
  agentId?: string;
  enabled?: boolean;
  sessionRiskLimit?: number;
  failOpen?: boolean;
  requireApprovalCategories?: string[];
  blockedTools?: string[];
  blockedCategories?: string[];
  toolOverrides?: Record<string, Partial<ToolMapping>>;
  timeout?: number;
  auditFlushIntervalMs?: number;
}

/**
 * Validate raw plugin config and apply defaults.
 *
 * Returns a disabled config when `enabled: false` or when required fields
 * are missing — the plugin self-disables with zero overhead.
 */
export function createConfig(raw: RawConfig): ValidatedConfig {
  // Explicit disable
  if (raw.enabled === false) {
    return Object.freeze({ enabled: false });
  }

  // Required fields
  if (!raw.cpUrl || !raw.apiKey || !raw.tenantId) {
    return Object.freeze({ enabled: false });
  }

  const config: AxiomGuardPluginConfig = {
    enabled: true,
    cpUrl: raw.cpUrl,
    apiKey: raw.apiKey,
    tenantId: raw.tenantId,
    agentId: raw.agentId ?? "openclaw-default",
    sessionRiskLimit: raw.sessionRiskLimit ?? 0.8,
    failOpen: raw.failOpen ?? true,
    requireApprovalCategories: raw.requireApprovalCategories ?? [],
    blockedTools: raw.blockedTools ?? [],
    blockedCategories: raw.blockedCategories ?? [],
    toolOverrides: raw.toolOverrides ?? {},
    timeout: raw.timeout ?? 5000,
    auditFlushIntervalMs: raw.auditFlushIntervalMs ?? 30000,
  };

  return Object.freeze(config);
}
