/**
 * Type declarations for the OpenClaw plugin SDK.
 *
 * These types mirror the real OpenClaw API from:
 *   openclaw/openclaw — src/plugin-sdk/plugin-entry.ts, src/plugins/types.ts
 *
 * At runtime, the real SDK is resolved from the OpenClaw host installation.
 * This file provides types for development and compilation.
 */

declare module "openclaw/plugin-sdk/plugin-entry" {
  import type { OpenClawPluginConfigSchema } from "./types.js";

  interface OpenClawPluginApi {
    /** Resolved plugin configuration from openclaw.json. */
    config: Record<string, unknown>;
    /** Register a lifecycle hook handler. */
    on(
      event: "before_tool_call",
      handler: (
        input: import("./types.js").ToolCallInput,
        ctx: import("./types.js").ToolCallContext,
      ) => Promise<import("./types.js").ToolCallResult | void>,
    ): void;
    on(event: string, handler: (...args: unknown[]) => Promise<unknown>): void;
    /** Register an agent tool. */
    registerTool(
      name: string,
      factory: unknown,
    ): void;
    /** Register a slash command. */
    registerCommand(definition: unknown): void;
    /** Register a background service. */
    registerService(service: unknown): void;
  }

  interface DefinedPluginEntry {
    id: string;
    name: string;
    description: string;
    configSchema: OpenClawPluginConfigSchema;
    register: (api: OpenClawPluginApi) => void;
  }

  function definePluginEntry(options: {
    id: string;
    name: string;
    description: string;
    kind?: string;
    configSchema?: OpenClawPluginConfigSchema;
    register: (api: OpenClawPluginApi) => void;
  }): DefinedPluginEntry;

  export { definePluginEntry, type OpenClawPluginApi, type DefinedPluginEntry };
}
