/**
 * Type stubs for the OpenClaw plugin SDK.
 *
 * These types represent the OpenClaw plugin API that host applications provide.
 * The actual implementation lives in the OpenClaw gateway runtime.
 */

declare function definePluginEntry(entry: {
  id: string;
  name: string;
  register: (api: OpenClawPluginAPI, config: Record<string, unknown>) => void;
}): void;

export { definePluginEntry };

interface OpenClawPluginAPI {
  registerHook(
    event: "before_tool_call",
    handler: (context: import("./types").ToolCallContext) => import("./types").HookResponse,
  ): void;
  registerHook(event: "on_unload", handler: () => void): void;
  registerHook(event: string, handler: (...args: unknown[]) => unknown): void;
  registerTool(
    name: string,
    handler: (args: Record<string, unknown>) => Promise<unknown>,
  ): void;
}

export type { OpenClawPluginAPI };
