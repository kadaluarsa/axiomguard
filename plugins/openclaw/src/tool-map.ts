import type { ToolMapping } from "./types.js";

/** Default mapping from OpenClaw tool names to AxiomGuard categories. */
const DEFAULT_MAP: Record<string, ToolMapping> = {
  // Execution
  exec: { category: "exec", riskMultiplier: 1.0 },
  process: { category: "exec", riskMultiplier: 1.0 },
  code_execution: { category: "exec", riskMultiplier: 1.0 },

  // File operations
  write: { category: "file_write", riskMultiplier: 0.6 },
  edit: { category: "file_write", riskMultiplier: 0.6 },
  apply_patch: { category: "file_write", riskMultiplier: 0.6 },

  // File read
  read: { category: "file_read", riskMultiplier: 0.3 },

  // Network
  web_search: { category: "http", riskMultiplier: 0.4 },
  web_fetch: { category: "http", riskMultiplier: 0.4 },
  x_search: { category: "http", riskMultiplier: 0.4 },

  // Browser
  browser: { category: "browser", riskMultiplier: 0.5 },

  // Messaging
  message: { category: "message", riskMultiplier: 0.2 },

  // Automation
  cron: { category: "automation", riskMultiplier: 0.7 },
  gateway: { category: "automation", riskMultiplier: 0.7 },

  // Media generation
  image_generate: { category: "media_gen", riskMultiplier: 0.3 },
  music_generate: { category: "media_gen", riskMultiplier: 0.3 },
  video_generate: { category: "media_gen", riskMultiplier: 0.3 },
  tts: { category: "media_gen", riskMultiplier: 0.3 },

  // Session management
  sessions_create: { category: "sessions", riskMultiplier: 0.4 },
  sessions_list: { category: "sessions", riskMultiplier: 0.4 },
  sessions_delete: { category: "sessions", riskMultiplier: 0.4 },
  subagents: { category: "sessions", riskMultiplier: 0.4 },
  session_status: { category: "sessions", riskMultiplier: 0.4 },

  // Memory
  memory_search: { category: "memory", riskMultiplier: 0.2 },
  memory_get: { category: "memory", riskMultiplier: 0.2 },

  // System
  image: { category: "system", riskMultiplier: 0.3 },
  canvas: { category: "system", riskMultiplier: 0.3 },
  nodes: { category: "system", riskMultiplier: 0.3 },
};

const UNKNOWN: ToolMapping = { category: "unknown", riskMultiplier: 0.8 };

/**
 * Resolve an OpenClaw tool name to an AxiomGuard category mapping.
 *
 * Checks user overrides first, then the default map, then falls back to
 * `unknown` with a high risk multiplier.
 */
export function resolveToolMapping(
  toolName: string,
  overrides?: Record<string, Partial<ToolMapping>>,
): ToolMapping {
  const base = DEFAULT_MAP[toolName] ?? { ...UNKNOWN };
  const userOverride = overrides?.[toolName];

  if (!userOverride) return base;

  return {
    category: userOverride.category ?? base.category,
    riskMultiplier: userOverride.riskMultiplier ?? base.riskMultiplier,
    block: userOverride.block,
    requireApproval: userOverride.requireApproval,
  };
}

/** Return all default mappings (useful for tests and introspection). */
export function getDefaultMap(): Readonly<Record<string, ToolMapping>> {
  return DEFAULT_MAP;
}
