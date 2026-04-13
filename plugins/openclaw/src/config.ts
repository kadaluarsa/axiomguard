import type {
  AxiomGuardPluginConfig,
  DisabledConfig,
  ResolvedConfig,
  ValidatedConfig,
  OpenClawPluginConfigSchema,
} from "./types.js";

/**
 * Validate raw plugin config and apply defaults.
 *
 * Two modes:
 * - **Standalone** (default): No cpUrl required. Plugin runs with local-only decisions.
 * - **Managed**: cpUrl + apiKey + tenantId required. Connects to AxiomGuard control plane.
 *
 * Returns a disabled config when `enabled: false` or when managed mode
 * has missing required fields.
 */
export function createConfig(raw: AxiomGuardPluginConfig): ResolvedConfig {
  if (raw.enabled === false) {
    return Object.freeze({ enabled: false });
  }

  const isManaged = Boolean(raw.cpUrl);

  // Managed mode requires additional fields
  if (isManaged && (!raw.apiKey || !raw.tenantId)) {
    return Object.freeze({ enabled: false });
  }

  const config: ValidatedConfig = {
    enabled: true,
    failOpen: raw.failOpen ?? true,
    blockedTools: raw.blockedTools ?? [],
    blockedCategories: raw.blockedCategories ?? [],
    requireApprovalCategories: raw.requireApprovalCategories ?? [],
    sessionRiskLimit: raw.sessionRiskLimit ?? 0.8,
    toolOverrides: raw.toolOverrides ?? {},
  };

  // Managed mode fields
  if (isManaged) {
    config.cpUrl = raw.cpUrl;
    config.apiKey = raw.apiKey;
    config.tenantId = raw.tenantId;
    config.agentId = raw.agentId ?? "openclaw-default";
    config.timeout = raw.timeout ?? 5000;
    config.auditFlushIntervalMs = raw.auditFlushIntervalMs ?? 30000;
  }

  return Object.freeze(config);
}

/**
 * Build an OpenClaw-compatible config schema for plugin registration.
 *
 * Provides safeParse for runtime validation and jsonSchema for the config UI.
 */
export function buildConfigSchema(): OpenClawPluginConfigSchema {
  return {
    safeParse: (value: unknown) => {
      if (value === null || value === undefined || typeof value !== "object") {
        return {
          success: false,
          error: { issues: [{ message: "Config must be an object" }] },
        };
      }

      const raw = value as AxiomGuardPluginConfig;
      const config = createConfig(raw);

      if (!config.enabled) {
        return {
          success: false,
          error: { issues: [{ message: "Plugin disabled: missing required fields for managed mode, or explicitly disabled" }] },
        };
      }

      return { success: true, data: config };
    },
    jsonSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        enabled: {
          type: "boolean",
          description: "Enable or disable the plugin",
          default: true,
        },
        failOpen: {
          type: "boolean",
          description: "Allow tools when control plane is unreachable",
          default: true,
        },
        blockedTools: {
          type: "array",
          items: { type: "string" },
          description: "Tool names to always block",
          default: [],
        },
        blockedCategories: {
          type: "array",
          items: { type: "string" },
          description: "Tool categories to always block",
          default: [],
        },
        requireApprovalCategories: {
          type: "array",
          items: { type: "string" },
          description: "Tool categories that require human approval",
          default: [],
        },
        sessionRiskLimit: {
          type: "number",
          minimum: 0,
          maximum: 1,
          description: "Cumulative session risk threshold (0-1)",
          default: 0.8,
        },
        toolOverrides: {
          type: "object",
          description: "Per-tool overrides for category, risk, block, requireApproval",
          additionalProperties: {
            type: "object",
            properties: {
              category: { type: "string" },
              riskMultiplier: { type: "number", minimum: 0, maximum: 1 },
              block: { type: "boolean" },
              requireApproval: { type: "boolean" },
            },
          },
        },
        cpUrl: {
          type: "string",
          description: "AxiomGuard control plane URL (enables managed mode)",
        },
        apiKey: {
          type: "string",
          description: "API key for control plane authentication",
        },
        tenantId: {
          type: "string",
          description: "Tenant ID for multi-tenant control plane",
        },
        agentId: {
          type: "string",
          description: "Agent identifier (default: openclaw-default)",
        },
        timeout: {
          type: "number",
          description: "Control plane request timeout in ms",
          default: 5000,
        },
        auditFlushIntervalMs: {
          type: "number",
          description: "Audit flush interval in ms (managed mode)",
          default: 30000,
        },
      },
    },
  };
}
