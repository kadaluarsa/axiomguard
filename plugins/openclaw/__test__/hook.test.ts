import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHandler } from "../src/hook.js";
import { resolveToolMapping } from "../src/tool-map.js";
import { evaluateLocal } from "../src/standalone.js";
import type { HookDeps, ValidatedConfig, ToolCallResult } from "../src/types.js";

function makeConfig(overrides?: Partial<ValidatedConfig>): ValidatedConfig {
  return {
    enabled: true,
    failOpen: true,
    blockedTools: [],
    blockedCategories: [],
    requireApprovalCategories: [],
    sessionRiskLimit: 0.8,
    toolOverrides: {},
    ...overrides,
  };
}

function makeDeps(overrides?: Partial<HookDeps>): HookDeps {
  return {
    config: makeConfig(),
    runtimeGuard: undefined,
    sessionTracker: {
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
    },
    resolveToolMapping,
    evaluateLocal,
    ...overrides,
  };
}

describe("createHandler / before_tool_call", () => {
  it("allows safe tools (standalone mode)", async () => {
    const handler = createHandler(makeDeps());
    const result = await handler(
      { toolName: "fs_read", params: { path: "/tmp/file" } },
      { toolName: "fs_read", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result, undefined);
  });

  it("blocks tools in blockedTools list", async () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({ blockedTools: ["bash"] }),
    }));
    const result = await handler(
      { toolName: "bash", params: { cmd: "rm -rf /" } },
      { toolName: "bash", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result!.block, true);
    assert.ok(result!.blockReason!.includes("blocked"));
  });

  it("blocks tools with block override in toolOverrides", async () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({ toolOverrides: { fs_read: { block: true } } }),
    }));
    const result = await handler(
      { toolName: "fs_read", params: {} },
      { toolName: "fs_read", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result!.block, true);
  });

  it("blocks tools in blockedCategories", async () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({ blockedCategories: ["exec"] }),
    }));
    const result = await handler(
      { toolName: "bash", params: {} },
      { toolName: "bash", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result!.block, true);
    assert.ok(result!.blockReason!.includes("Category"));
  });

  it("returns requireApproval object for approval categories", async () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({ sessionRiskLimit: 1.0, requireApprovalCategories: ["http"] }),
    }));
    const result = await handler(
      { toolName: "web-search", params: {} },
      { toolName: "web-search", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result!.block, undefined);
    assert.ok(result!.requireApproval);
    assert.ok(result!.requireApproval!.title);
    assert.ok(result!.requireApproval!.description);
    assert.equal(result!.requireApproval!.severity, "warning");
  });

  it("blocks when session risk exceeds limit", async () => {
    const tracker = {
      _sessions: new Map<string, number>([["s1", 0.7]]),
      getRisk(sessionId: string) { return this._sessions.get(sessionId) ?? 0; },
      record(sessionId: string, entry: { category: string; riskScore: number; decision: string }) {
        const current = this._sessions.get(sessionId) ?? 0;
        this._sessions.set(sessionId, Math.min(1.0, current + entry.riskScore));
      },
    };
    const handler = createHandler(makeDeps({ sessionTracker: tracker }));
    const result = await handler(
      { toolName: "bash", params: {} },
      { toolName: "bash", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result!.block, true);
    assert.ok(result!.blockReason!.includes("risk limit"));
  });

  it("allows when session risk is below limit", async () => {
    const tracker = {
      _sessions: new Map<string, number>([["s1", 0.3]]),
      getRisk(sessionId: string) { return this._sessions.get(sessionId) ?? 0; },
      record(sessionId: string, entry: { category: string; riskScore: number; decision: string }) {
        const current = this._sessions.get(sessionId) ?? 0;
        this._sessions.set(sessionId, Math.min(1.0, current + entry.riskScore));
      },
    };
    const handler = createHandler(makeDeps({ sessionTracker: tracker }));
    const result = await handler(
      { toolName: "fs_read", params: {} },
      { toolName: "fs_read", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result, undefined);
  });

  it("updates session tracker on each call", async () => {
    const tracker = {
      _sessions: new Map<string, number>(),
      getRisk(sessionId: string) { return this._sessions.get(sessionId) ?? 0; },
      record(sessionId: string, entry: { category: string; riskScore: number; decision: string }) {
        const current = this._sessions.get(sessionId) ?? 0;
        this._sessions.set(sessionId, Math.min(1.0, current + entry.riskScore));
      },
    };
    const handler = createHandler(makeDeps({ sessionTracker: tracker }));
    await handler(
      { toolName: "bash", params: {} },
      { toolName: "bash", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(tracker.getRisk("s1"), 1.0); // exec = 1.0 risk
  });

  // --- Managed mode tests ---

  it("in managed mode, blocks when CP returns Block", async () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({
        cpUrl: "https://cp.example.com",
        apiKey: "key",
        tenantId: "t1",
      }),
      runtimeGuard: {
        check: async () => ({ decision: "Block", reason: "Policy violation" }),
      },
    }));
    const result = await handler(
      { toolName: "fs_read", params: {} },
      { toolName: "fs_read", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result!.block, true);
    assert.equal(result!.blockReason, "Policy violation");
  });

  it("in managed mode, allows when CP returns Allow", async () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({
        cpUrl: "https://cp.example.com",
        apiKey: "key",
        tenantId: "t1",
      }),
      runtimeGuard: {
        check: async () => ({ decision: "Allow", allowed: true }),
      },
    }));
    const result = await handler(
      { toolName: "fs_read", params: {} },
      { toolName: "fs_read", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result, undefined);
  });

  it("in managed mode, fail-open allows when CP throws", async () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({
        cpUrl: "https://cp.example.com",
        apiKey: "key",
        tenantId: "t1",
        failOpen: true,
      }),
      runtimeGuard: {
        check: async () => { throw new Error("unreachable"); },
      },
    }));
    const result = await handler(
      { toolName: "fs_read", params: {} },
      { toolName: "fs_read", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result, undefined);
  });

  it("in managed mode, fail-closed blocks when CP throws", async () => {
    const handler = createHandler(makeDeps({
      config: makeConfig({
        cpUrl: "https://cp.example.com",
        apiKey: "key",
        tenantId: "t1",
        failOpen: false,
      }),
      runtimeGuard: {
        check: async () => { throw new Error("unreachable"); },
      },
    }));
    const result = await handler(
      { toolName: "fs_read", params: {} },
      { toolName: "fs_read", agentId: "main", sessionKey: "s1" },
    );
    assert.equal(result!.block, true);
    assert.ok(result!.blockReason!.includes("unreachable"));
  });
});
