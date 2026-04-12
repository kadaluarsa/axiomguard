import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createConfig } from "../src/config.js";

describe("createConfig", () => {
  it("returns enabled config with all required fields", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
      tenantId: "tenant-1",
    });
    assert.equal(config.enabled, true);
    if (!config.enabled) return; // type narrow
    assert.equal(config.cpUrl, "https://cp.example.com");
    assert.equal(config.apiKey, "key-123");
    assert.equal(config.tenantId, "tenant-1");
  });

  it("applies defaults for optional fields", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
      tenantId: "tenant-1",
    });
    if (!config.enabled) return;
    assert.equal(config.agentId, "openclaw-default");
    assert.equal(config.sessionRiskLimit, 0.8);
    assert.equal(config.failOpen, true);
    assert.deepEqual(config.requireApprovalCategories, []);
    assert.deepEqual(config.blockedTools, []);
    assert.deepEqual(config.blockedCategories, []);
    assert.deepEqual(config.toolOverrides, {});
    assert.equal(config.timeout, 5000);
    assert.equal(config.auditFlushIntervalMs, 30000);
  });

  it("applies custom values for optional fields", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
      tenantId: "tenant-1",
      agentId: "my-agent",
      sessionRiskLimit: 0.5,
      failOpen: false,
      requireApprovalCategories: ["exec"],
      blockedTools: ["rm"],
      blockedCategories: ["automation"],
      timeout: 10000,
      auditFlushIntervalMs: 60000,
    });
    if (!config.enabled) return;
    assert.equal(config.agentId, "my-agent");
    assert.equal(config.sessionRiskLimit, 0.5);
    assert.equal(config.failOpen, false);
    assert.deepEqual(config.requireApprovalCategories, ["exec"]);
    assert.deepEqual(config.blockedTools, ["rm"]);
    assert.deepEqual(config.blockedCategories, ["automation"]);
    assert.equal(config.timeout, 10000);
    assert.equal(config.auditFlushIntervalMs, 60000);
  });

  it("self-disables when enabled is false", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
      tenantId: "tenant-1",
      enabled: false,
    });
    assert.equal(config.enabled, false);
  });

  it("self-disables when cpUrl is missing", () => {
    const config = createConfig({
      apiKey: "key-123",
      tenantId: "tenant-1",
    });
    assert.equal(config.enabled, false);
  });

  it("self-disables when apiKey is missing", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      tenantId: "tenant-1",
    });
    assert.equal(config.enabled, false);
  });

  it("self-disables when tenantId is missing", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
    });
    assert.equal(config.enabled, false);
  });

  it("self-disables when all required fields are missing", () => {
    const config = createConfig({});
    assert.equal(config.enabled, false);
  });

  it("returns a frozen object", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
      tenantId: "tenant-1",
    });
    assert.equal(Object.isFrozen(config), true);
  });

  it("handles toolOverrides", () => {
    const config = createConfig({
      cpUrl: "https://cp.example.com",
      apiKey: "key-123",
      tenantId: "tenant-1",
      toolOverrides: {
        exec: { category: "custom", riskMultiplier: 0.1 },
      },
    });
    if (!config.enabled) return;
    assert.deepEqual(config.toolOverrides, {
      exec: { category: "custom", riskMultiplier: 0.1 },
    });
  });
});
