import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createConfig, buildConfigSchema } from "../src/config.js";

describe("createConfig", () => {
  // --- Standalone mode ---

  it("returns enabled config in standalone mode (no cpUrl)", () => {
    const config = createConfig({});
    assert.equal(config.enabled, true);
    if (!config.enabled) return;
    assert.equal(config.cpUrl, undefined);
    assert.equal(config.apiKey, undefined);
  });

  it("applies defaults in standalone mode", () => {
    const config = createConfig({});
    if (!config.enabled) return;
    assert.equal(config.failOpen, true);
    assert.equal(config.sessionRiskLimit, 0.8);
    assert.deepEqual(config.blockedTools, []);
    assert.deepEqual(config.blockedCategories, []);
    assert.deepEqual(config.requireApprovalCategories, []);
    assert.deepEqual(config.toolOverrides, {});
  });

  it("accepts standalone config options", () => {
    const config = createConfig({
      blockedTools: ["bash"],
      blockedCategories: ["exec"],
      requireApprovalCategories: ["secrets"],
      sessionRiskLimit: 0.5,
    });
    if (!config.enabled) return;
    assert.deepEqual(config.blockedTools, ["bash"]);
    assert.deepEqual(config.blockedCategories, ["exec"]);
    assert.deepEqual(config.requireApprovalCategories, ["secrets"]);
    assert.equal(config.sessionRiskLimit, 0.5);
  });

  // --- Managed mode ---

  it("returns enabled config in managed mode with all required fields", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
      tenantId: "tenant-1",
    });
    assert.equal(config.enabled, true);
    if (!config.enabled) return;
    assert.equal(config.cpUrl, "https://cp.example.com");
    assert.equal(config.apiKey, "key-123");
    assert.equal(config.tenantId, "tenant-1");
    assert.equal(config.agentId, "openclaw-default");
    assert.equal(config.timeout, 5000);
    assert.equal(config.auditFlushIntervalMs, 30000);
  });

  it("applies custom values in managed mode", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
      tenantId: "tenant-1",
      agentId: "my-agent",
      timeout: 10000,
      auditFlushIntervalMs: 60000,
    });
    if (!config.enabled) return;
    assert.equal(config.agentId, "my-agent");
    assert.equal(config.timeout, 10000);
    assert.equal(config.auditFlushIntervalMs, 60000);
  });

  // --- Disabled cases ---

  it("self-disables when enabled is false", () => {
    const config = createConfig({ enabled: false });
    assert.equal(config.enabled, false);
  });

  it("self-disables when managed mode missing apiKey", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      tenantId: "tenant-1",
    });
    assert.equal(config.enabled, false);
  });

  it("self-disables when managed mode missing tenantId", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
    });
    assert.equal(config.enabled, false);
  });

  // --- General ---

  it("returns a frozen object", () => {
    const config = createConfig({});
    assert.equal(Object.isFrozen(config), true);
  });

  it("handles toolOverrides", () => {
    const config = createConfig({
      toolOverrides: { bash: { category: "custom", riskMultiplier: 0.1 } },
    });
    if (!config.enabled) return;
    assert.deepEqual(config.toolOverrides, {
      bash: { category: "custom", riskMultiplier: 0.1 },
    });
  });
});

describe("buildConfigSchema", () => {
  it("returns an object with safeParse and jsonSchema", () => {
    const schema = buildConfigSchema();
    assert.equal(typeof schema.safeParse, "function");
    assert.ok(schema.jsonSchema);
  });

  it("safeParse accepts valid standalone config", () => {
    const schema = buildConfigSchema();
    const result = schema.safeParse!({ sessionRiskLimit: 0.5 });
    assert.equal(result.success, true);
  });

  it("safeParse rejects non-object input", () => {
    const schema = buildConfigSchema();
    const result = schema.safeParse!("not an object");
    assert.equal(result.success, false);
  });

  it("safeParse rejects disabled config", () => {
    const schema = buildConfigSchema();
    const result = schema.safeParse!({ enabled: false });
    assert.equal(result.success, false);
  });

  it("jsonSchema has expected properties", () => {
    const schema = buildConfigSchema();
    const props = (schema.jsonSchema as Record<string, unknown>).properties as Record<string, unknown>;
    assert.ok(props.enabled);
    assert.ok(props.blockedTools);
    assert.ok(props.cpUrl);
    assert.ok(props.sessionRiskLimit);
  });
});
