import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { createHandler } from "../src/hook.js";
import { resolveToolMapping } from "../src/tool-map.js";
import { evaluateLocal } from "../src/standalone.js";
import { SessionTracker } from "../src/session-tracker.js";
import { createConfig } from "../src/config.js";
import type { HookDeps, ValidatedConfig } from "../src/types.js";

function startMockCP(port: number): Promise<{
  server: Server;
  requests: Array<{ url: string; body: unknown }>;
}> {
  const requests: Array<{ url: string; body: unknown }> = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
    req.on("end", () => {
      requests.push({ url: req.url ?? "/", body: body ? JSON.parse(body) : null });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: "Allow", allowed: true }));
    });
  });
  return new Promise((resolve) => {
    server.listen(port, () => resolve({ server, requests }));
  });
}

describe("Integration: before_tool_call (standalone mode)", () => {
  it("allows safe tools with no config", async () => {
    const config = createConfig({}) as ValidatedConfig;
    const tracker = new SessionTracker();
    const handler = createHandler({ config, sessionTracker: tracker, resolveToolMapping, evaluateLocal });

    const result = await handler(
      { toolName: "fs_read", params: { path: "/etc/hosts" } },
      { toolName: "fs_read", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result, undefined);
  });

  it("blocks tools in blocked list", async () => {
    const config = createConfig({ blockedTools: ["bash"] }) as ValidatedConfig;
    const tracker = new SessionTracker();
    const handler = createHandler({ config, sessionTracker: tracker, resolveToolMapping, evaluateLocal });

    const result = await handler(
      { toolName: "bash", params: { cmd: "rm -rf /" } },
      { toolName: "bash", agentId: "main", sessionKey: "s2" },
    );
    assert.equal(result!.block, true);
  });

  it("accumulates session risk across multiple calls", async () => {
    const config = createConfig({ sessionRiskLimit: 0.8 }) as ValidatedConfig;
    const tracker = new SessionTracker();
    const handler = createHandler({ config, sessionTracker: tracker, resolveToolMapping, evaluateLocal });

    let result = await handler({ toolName: "fs_read", params: {} }, { toolName: "fs_read", agentId: "main", sessionKey: "s3" });
    assert.equal(result, undefined);

    result = await handler({ toolName: "fs_read", params: {} }, { toolName: "fs_read", agentId: "main", sessionKey: "s3" });
    assert.equal(result, undefined);

    // Session risk: 0.3 * 2 = 0.6. Next fs_read (0.3) → 0.9 >= 0.8 → blocked
    result = await handler({ toolName: "fs_read", params: {} }, { toolName: "fs_read", agentId: "main", sessionKey: "s3" });
    assert.equal(result!.block, true);
  });

  it("returns requireApproval object with proper fields", async () => {
    const config = createConfig({ sessionRiskLimit: 1.0, requireApprovalCategories: ["secrets"] }) as ValidatedConfig;
    const tracker = new SessionTracker();
    const handler = createHandler({ config, sessionTracker: tracker, resolveToolMapping, evaluateLocal });

    const result = await handler(
      { toolName: "secrets", params: {} },
      { toolName: "secrets", agentId: "main", sessionKey: "s4" },
    );
    assert.ok(result!.requireApproval);
    assert.ok(result!.requireApproval!.title);
    assert.ok(result!.requireApproval!.description);
    assert.ok(result!.requireApproval!.id);
  });
});

describe("Integration: before_tool_call (managed mode + mock CP)", () => {
  let mockCP: { server: Server; requests: Array<{ url: string; body: unknown }> };

  beforeEach(async () => {
    mockCP = await startMockCP(9876);
  });

  afterEach(() => {
    mockCP.server.close();
  });

  it("allows when CP responds Allow", async () => {
    const config = createConfig({
      cpUrl: "http://localhost:9876",
      apiKey: "test-key",
      tenantId: "tenant-1",
    }) as ValidatedConfig;

    const tracker = new SessionTracker();
    const handler = createHandler({
      config,
      sessionTracker: tracker,
      resolveToolMapping,
      evaluateLocal,
      runtimeGuard: {
        check: async (tool, args, options) => {
          await fetch("http://localhost:9876/v1/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ tool, args, ...options }),
          });
          return { decision: "Allow", allowed: true };
        },
      },
    });

    const result = await handler(
      { toolName: "fs_read", params: { path: "/tmp" } },
      { toolName: "fs_read", agentId: "main", sessionKey: "int-s1" },
    );
    assert.equal(result, undefined);

    // Give fetch time to complete
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(mockCP.requests.some((r) => r.url.includes("/check")));
  });

  it("blocks when CP responds Block", async () => {
    const config = createConfig({
      cpUrl: "http://localhost:9876",
      apiKey: "test-key",
      tenantId: "tenant-1",
    }) as ValidatedConfig;

    const tracker = new SessionTracker();
    const handler = createHandler({
      config,
      sessionTracker: tracker,
      resolveToolMapping,
      evaluateLocal,
      runtimeGuard: {
        check: async () => ({ decision: "Block", reason: "Policy denied" }),
      },
    });

    const result = await handler(
      { toolName: "fs_read", params: {} },
      { toolName: "fs_read", agentId: "main", sessionKey: "int-s2" },
    );
    assert.equal(result!.block, true);
    assert.equal(result!.blockReason, "Policy denied");
  });
});
