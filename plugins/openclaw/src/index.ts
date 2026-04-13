import { definePluginEntry, type OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import { RuntimeGuard } from "@axiomguard/sdk-node-runtime";
import { buildConfigSchema, createConfig } from "./config.js";
import { resolveToolMapping } from "./tool-map.js";
import { SessionTracker } from "./session-tracker.js";
import { evaluateLocal } from "./standalone.js";
import { createHandler } from "./hook.js";

const plugin: { id: string; name: string; description: string; configSchema: ReturnType<typeof buildConfigSchema>; register: (api: OpenClawPluginApi) => void } = definePluginEntry({
  id: "axiomguard",
  name: "AxiomGuard Security Plugin",
  description: "Security guardrails for OpenClaw agents — block risky tools, track session risk, enforce approval policies",
  configSchema: buildConfigSchema(),
  register(api: OpenClawPluginApi) {
    const config = createConfig(api.config as Record<string, unknown>);
    if (!config.enabled) return;

    // Managed mode: start RuntimeGuard for control plane communication
    let runtimeGuard;
    if (config.cpUrl) {
      runtimeGuard = new RuntimeGuard({
        cpUrl: config.cpUrl,
        apiKey: config.apiKey!,
        tenantId: config.tenantId!,
        agentId: config.agentId!,
        timeout: config.timeout,
        flushIntervalMs: config.auditFlushIntervalMs,
      });
      runtimeGuard.start();
    }

    const sessionTracker = new SessionTracker();

    api.on("before_tool_call", createHandler({
      config,
      runtimeGuard,
      sessionTracker,
      resolveToolMapping,
      evaluateLocal,
    }));
  },
});

export default plugin;

// Re-export internals for programmatic use / testing
export { createConfig, buildConfigSchema } from "./config.js";
export { resolveToolMapping, getDefaultMap } from "./tool-map.js";
export { SessionTracker } from "./session-tracker.js";
export { evaluateLocal } from "./standalone.js";
export { createHandler } from "./hook.js";
