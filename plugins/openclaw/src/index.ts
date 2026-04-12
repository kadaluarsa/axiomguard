import { definePluginEntry } from "./openclaw.js";
import { RuntimeGuard } from "@axiomguard/sdk-node-runtime";
import { createConfig } from "./config.js";
import { resolveToolMapping } from "./tool-map.js";
import { SessionTracker } from "./session-tracker.js";
import { createHandler } from "./hook.js";

export default definePluginEntry({
  id: "axiomguard",
  name: "AxiomGuard Security Plugin",
  register(api, pluginConfig) {
    const config = createConfig(pluginConfig as Parameters<typeof createConfig>[0]);
    if (!config.enabled) return; // zero overhead when disabled

    const runtimeGuard = new RuntimeGuard({
      cpUrl: config.cpUrl,
      apiKey: config.apiKey,
      tenantId: config.tenantId,
      agentId: config.agentId,
      timeout: config.timeout,
      flushIntervalMs: config.auditFlushIntervalMs,
    });
    runtimeGuard.start();

    const sessionTracker = new SessionTracker();

    api.registerHook(
      "before_tool_call",
      createHandler({ config, runtimeGuard, sessionTracker, resolveToolMapping }),
    );

    api.registerHook("on_unload", () => {
      runtimeGuard.stop();
      sessionTracker.destroy();
    });
  },
});

// Re-export internals for programmatic use / testing
export { createConfig } from "./config.js";
export { resolveToolMapping, getDefaultMap } from "./tool-map.js";
export { SessionTracker } from "./session-tracker.js";
export { createHandler } from "./hook.js";
