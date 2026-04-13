import type { ToolMapping } from "./types.js";

/** Default mapping from OpenClaw tool names to AxiomGuard categories. */
const DEFAULT_MAP: Record<string, ToolMapping> = {
  // Execution (high risk)
  bash: { category: "exec", riskMultiplier: 1.0 },
  exec: { category: "exec", riskMultiplier: 1.0 },
  spawn: { category: "exec", riskMultiplier: 1.0 },
  shell: { category: "exec", riskMultiplier: 1.0 },
  terminal: { category: "exec", riskMultiplier: 1.0 },

  // File write operations
  fs_write: { category: "file_write", riskMultiplier: 0.6 },
  fs_delete: { category: "file_write", riskMultiplier: 0.7 },
  fs_move: { category: "file_write", riskMultiplier: 0.5 },

  // File read
  fs_read: { category: "file_read", riskMultiplier: 0.3 },

  // Network
  "web-search": { category: "http", riskMultiplier: 0.4 },
  "web-fetch": { category: "http", riskMultiplier: 0.4 },

  // Browser
  browser: { category: "browser", riskMultiplier: 0.5 },

  // Automation
  cron: { category: "automation", riskMultiplier: 0.7 },

  // System management
  gateway: { category: "system", riskMultiplier: 0.7 },
  nodes: { category: "system", riskMultiplier: 0.7 },

  // Session management
  sessions: { category: "sessions", riskMultiplier: 0.4 },
  subagents: { category: "sessions", riskMultiplier: 0.4 },

  // Secrets
  secrets: { category: "secrets", riskMultiplier: 0.8 },
};

/** Risk multiplier for MCP bridge tools (mcp-* prefix). */
const MCP_RISK: ToolMapping = { category: "mcp", riskMultiplier: 0.5 };

/** Fallback for unrecognized tools. */
const UNKNOWN: ToolMapping = { category: "unknown", riskMultiplier: 0.8 };

/**
 * Resolve an OpenClaw tool name to an AxiomGuard category mapping.
 *
 * Checks user overrides first, then the default map, then pattern matches
 * MCP tools (mcp-*), then falls back to `unknown`.
 */
export function resolveToolMapping(
  toolName: string,
  overrides?: Record<string, Partial<ToolMapping>>,
): ToolMapping {
  // User overrides take highest priority
  const userOverride = overrides?.[toolName];
  if (userOverride) {
    return applyOverride(DEFAULT_MAP[toolName] ?? UNKNOWN, userOverride);
  }

  // Exact match in default map
  const base = DEFAULT_MAP[toolName];
  if (base) return { ...base };

  // Pattern match: MCP bridge tools
  if (toolName.startsWith("mcp-")) {
    return { ...MCP_RISK };
  }

  // Fallback
  return { ...UNKNOWN };
}

function applyOverride(base: ToolMapping, override: Partial<ToolMapping>): ToolMapping {
  return {
    category: override.category ?? base.category,
    riskMultiplier: override.riskMultiplier ?? base.riskMultiplier,
    block: override.block,
    requireApproval: override.requireApproval,
  };
}

/** Return all default mappings (for tests and introspection). */
export function getDefaultMap(): Readonly<Record<string, ToolMapping>> {
  return DEFAULT_MAP;
}
