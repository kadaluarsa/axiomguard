import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHandler } from "../src/hook.js";
import { resolveToolMapping } from "../src/tool-map.js";
import type { HookDeps, AxiomGuardPluginConfig } from "../src/types.js";

function makeConfig(
  overrides?: Partial<AxiomGuardPluginConfig>,
): AxiomGuardPluginConfig {
  return {
    enabled: true,
    cpUrl: "https://cp.example.com",
    apiKey: "test-key",
    tenantId: "tenant-1",
    agentId: "agent-1",
    sessionRiskLimit: 0.8,
    failOpen: true,
    requireApprovalCategories: [],
    blockedTools: [],
    blockedCategories: [],
    toolOverrides: {},
    timeout: 5000,
    auditFlushIntervalMs: 30000,
    ...overrides,
  };
}

function makeDeps(overrides?: Partial<HookDeps>): HookDeps {
  const tracker = {
    _sessions: new Map<string, number>(),
    getRisk(sessionId: string) {
      return this._sessions.get(sessionId) ?? 0;
    },
    record(
      sessionId: string,
      entry: { category: string; riskScore: number; decision: string },
    ) {
      const current = this._sessions.get(sessionId) ?? 0;
      this._sessions.set(sessionId, Math.min(1.0, current + entry.riskScore));
    },
  };

  return {
    config: makeConfig(),
    runtimeGuard: {
      check: async () => ({ decision: "Allow", allowed: true }),
    },
    sessionTracker: tracker,
    resolveToolMapping,
    ...overrides,
  };
}

describe("createHandler / before_tool_call", () => {
  it("allows safe tools", () => {
    const handler = createHandler(makeDeps());
    const result = handler({ tool: "read", args: { path: "/tmp/file" }, sessionId: "s1" });
    assert.equal(result.block, false);
    assert.equal(result.requireApproval, undefined);
  });

  it("blocks tools in blockedTools list", () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({ blockedTools: ["exec"] }),
    }));
    const result = handler({ tool: "exec", args: { cmd: "rm -rf /" }, sessionId: "s1" });
    assert.equal(result.block, true);
    assert.ok(result.reason!.includes("blocked"));
  });

  it("blocks tools with block override in toolOverrides", () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({
        toolOverrides: { read: { block: true } },
      }),
    }));
    const result = handler({ tool: "read", args: {}, sessionId: "s1" });
    assert.equal(result.block, true);
  });

  it("blocks tools in blockedCategories", () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({ blockedCategories: ["exec"] }),
    }));
    const result = handler({ tool: "exec", args: {}, sessionId: "s1" });
    assert.equal(result.block, true);
    assert.ok(result.reason!.includes("Category"));
  });

  it("requires approval for requireApprovalCategories", () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({ requireApprovalCategories: ["http"], sessionRiskLimit: 1.0 }),
    }));
    const result = handler({ tool: "web_search", args: {}, sessionId: "s1" });
    assert.equal(result.requireApproval, true);
    assert.equal(result.block, undefined);
    assert.ok(result.reason!.includes("requires approval"));
  });

  it("requires approval for tools with requireApproval override", () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({
        toolOverrides: { read: { requireApproval: true } },
      }),
    }));
    const result = handler({ tool: "read", args: {}, sessionId: "s1" });
    assert.equal(result.requireApproval, true);
  });

  it("blocks when session risk exceeds limit", () => {
    // Pre-load session risk to 0.7, then exec (1.0) should push over 0.8
    const tracker = {
      _sessions: new Map<string, number>([["s1", 0.7]]),
      getRisk(sessionId: string) {
        return this._sessions.get(sessionId) ?? 0;
      },
      record(
        sessionId: string,
        entry: { category: string; riskScore: number; decision: string },
      ) {
        const current = this._sessions.get(sessionId) ?? 0;
        this._sessions.set(sessionId, Math.min(1.0, current + entry.riskScore));
      },
    };

    const handler = createHandler(makeDeps({ sessionTracker: tracker }));
    const result = handler({ tool: "exec", args: {}, sessionId: "s1" });
    assert.equal(result.block, true);
    assert.ok(result.reason!.includes("risk limit"));
  });

  it("allows when session risk is below limit", () => {
    // Pre-load session risk to 0.3, then message (0.2) = 0.5, well under 0.8
    const tracker = {
      _sessions: new Map<string, number>([["s1", 0.3]]),
      getRisk(sessionId: string) {
        return this._sessions.get(sessionId) ?? 0;
      },
      record(
        sessionId: string,
        entry: { category: string; riskScore: number; decision: string },
      ) {
        const current = this._sessions.get(sessionId) ?? 0;
        this._sessions.set(sessionId, Math.min(1.0, current + entry.riskScore));
      },
    };

    const handler = createHandler(makeDeps({ sessionTracker: tracker }));
    const result = handler({ tool: "message", args: {}, sessionId: "s1" });
    assert.equal(result.block, false);
  });

  it("uses 'default' sessionId when not provided", () => {
    const tracker = {
      _sessions: new Map<string, number>(),
      getRisk(sessionId: string) {
        return this._sessions.get(sessionId) ?? 0;
      },
      record(
        sessionId: string,
        entry: { category: string; riskScore: number; decision: string },
      ) {
        const current = this._sessions.get(sessionId) ?? 0;
        this._sessions.set(sessionId, Math.min(1.0, current + entry.riskScore));
      },
    };

    const handler = createHandler(makeDeps({ sessionTracker: tracker }));
    handler({ tool: "read", args: {} }); // no sessionId
    assert.equal(tracker._sessions.has("default"), true);
  });

  it("fire-and-forget does not block even when CP fails", async () => {
    let callCount = 0;
    const handler = createHandler(makeDeps({
      runtimeGuard: {
        check: async () => {
          callCount++;
          throw new Error("CP unreachable");
        },
      },
    }));

    // Should return immediately, not throw
    const result = handler({ tool: "read", args: {}, sessionId: "s1" });
    assert.equal(result.block, false);

    // Give microtask queue a chance
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(callCount, 1); // CP was called
  });

  it("updates session tracker on each call", () => {
    const tracker = {
      _sessions: new Map<string, number>(),
      getRisk(sessionId: string) {
        return this._sessions.get(sessionId) ?? 0;
      },
      record(
        sessionId: string,
        entry: { category: string; riskScore: number; decision: string },
      ) {
        const current = this._sessions.get(sessionId) ?? 0;
        this._sessions.set(sessionId, Math.min(1.0, current + entry.riskScore));
      },
    };

    const handler = createHandler(makeDeps({ sessionTracker: tracker }));
    handler({ tool: "exec", args: {}, sessionId: "s1" });
    assert.equal(tracker.getRisk("s1"), 1.0); // exec = 1.0 risk
  });

  it("blocks unknown tools with high risk when session is near limit", () => {
    const tracker = {
      _sessions: new Map<string, number>([["s1", 0.3]]),
      getRisk(sessionId: string) {
        return this._sessions.get(sessionId) ?? 0;
      },
      record(
        sessionId: string,
        entry: { category: string; riskScore: number; decision: string },
      ) {
        const current = this._sessions.get(sessionId) ?? 0;
        this._sessions.set(sessionId, Math.min(1.0, current + entry.riskScore));
      },
    };

    const handler = createHandler(makeDeps({ sessionTracker: tracker }));
    // unknown tool has 0.8 risk multiplier, 0.3 + 0.8 = 1.1 >= 0.8 limit
    const result = handler({ tool: "weird_custom_tool", args: {}, sessionId: "s1" });
    assert.equal(result.block, true);
  });
});
