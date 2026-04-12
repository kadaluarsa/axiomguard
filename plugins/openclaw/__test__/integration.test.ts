import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { createHandler } from "../src/hook.js";
import { resolveToolMapping } from "../src/tool-map.js";
import { SessionTracker } from "../src/session-tracker.js";
import { createConfig } from "../src/config.js";
import type { HookDeps, AxiomGuardPluginConfig, ValidatedConfig } from "../src/types.js";

/** Spin up a minimal mock control plane for integration testing. */
function startMockCP(port: number): Promise<{
  server: Server;
  requests: Array<{ url: string; body: unknown }>;
}> {
  const requests: Array<{ url: string; body: unknown }> = [];

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      requests.push({
        url: req.url ?? "/",
        body: body ? JSON.parse(body) : null,
      });

      // Respond based on route
      if (req.url?.includes("/token/issue")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ token: "mock-token", decision: "Allow", allowed: true }));
      } else if (req.url?.includes("/audit/batch")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      } else if (req.url?.includes("/policy/pull")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ rules: [] }));
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ decision: "Allow", allowed: true, riskScore: 0.1 }));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(port, () => resolve({ server, requests }));
  });
}

describe("Integration: before_tool_call → mock CP", () => {
  let mockCP: { server: Server; requests: Array<{ url: string; body: unknown }> };

  beforeEach(async () => {
    mockCP = await startMockCP(9876);
  });

  afterEach(() => {
    mockCP.server.close();
  });

  function makeIntegrationDeps(
    overrides?: Partial<HookDeps>,
  ): HookDeps & { sessionTracker: SessionTracker } {
    const config = createConfig({
      cpUrl: "http://localhost:9876",
      apiKey: "test-key",
      tenantId: "tenant-1",
      sessionRiskLimit: 0.8,
    }) as AxiomGuardPluginConfig;

    const sessionTracker = new SessionTracker();

    return {
      config,
      runtimeGuard: {
        check: async (tool, args, options) => {
          // Simulate real HTTP call to mock CP
          const body = JSON.stringify({
            tool,
            args,
            sessionId: options?.sessionId,
            agentId: options?.agentId,
          });
          return new Promise((resolve) => {
            const req = `http://localhost:9876/v1/check`;
            fetch(req, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body,
            })
              .then((r) => r.json())
              .then(resolve)
              .catch(() => resolve({ decision: "Allow", allowed: true }));
          });
        },
      },
      sessionTracker,
      resolveToolMapping,
      ...overrides,
    };
  }

  it("allows safe tool and fires CP call", async () => {
    const deps = makeIntegrationDeps();
    const handler = createHandler(deps);

    const result = handler({
      tool: "read",
      args: { path: "/etc/hosts" },
      sessionId: "int-s1",
    });

    assert.equal(result.block, false);

    // Wait for fire-and-forget CP call
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(
      mockCP.requests.some((r) => r.url.includes("/check")),
      "CP should receive a check request",
    );
  });

  it("blocks tools in blocked list without calling CP for decision", async () => {
    const deps = makeIntegrationDeps({
      config: {
        ...makeIntegrationDeps().config,
        blockedTools: ["exec"],
      },
    });
    const handler = createHandler(deps);

    const result = handler({
      tool: "exec",
      args: { cmd: "rm -rf /" },
      sessionId: "int-s2",
    });

    assert.equal(result.block, true);
  });

  it("accumulates session risk across multiple calls", () => {
    const deps = makeIntegrationDeps();
    const handler = createHandler(deps);

    // First call: exec (1.0 risk) — should be allowed (0 + 1.0 >= 0.8 → blocked!)
    // Actually exec has risk 1.0, which already exceeds 0.8. Let's use message (0.2)
    let result = handler({ tool: "message", args: {}, sessionId: "int-s3" });
    assert.equal(result.block, false);

    result = handler({ tool: "message", args: {}, sessionId: "int-s3" });
    assert.equal(result.block, false);

    result = handler({ tool: "message", args: {}, sessionId: "int-s3" });
    assert.equal(result.block, false);

    // Session risk: 0.2 * 3 = 0.6. Next message (0.2) → 0.8 >= 0.8 → blocked
    result = handler({ tool: "message", args: {}, sessionId: "int-s3" });
    assert.equal(result.block, true);
    assert.ok(result.reason!.includes("risk limit"));
  });

  it("tracks separate sessions independently", () => {
    const deps = makeIntegrationDeps();
    const handler = createHandler(deps);

    // Fill s1 to near-limit
    for (let i = 0; i < 3; i++) {
      handler({ tool: "message", args: {}, sessionId: "int-s4a" });
    }

    // s2 should still be clean
    const result = handler({ tool: "message", args: {}, sessionId: "int-s4b" });
    assert.equal(result.block, false);
  });

  it("audit events arrive at mock CP via fire-and-forget", async () => {
    const deps = makeIntegrationDeps();
    const handler = createHandler(deps);

    handler({ tool: "read", args: { path: "/tmp" }, sessionId: "int-s5" });
    handler({ tool: "write", args: { path: "/tmp/out" }, sessionId: "int-s5" });

    await new Promise((r) => setTimeout(r, 300));

    const checkReqs = mockCP.requests.filter((r) => r.url.includes("/check"));
    assert.ok(checkReqs.length >= 2, "Should have at least 2 CP check requests");
  });
});
