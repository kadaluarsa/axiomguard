import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluateLocal } from "../src/standalone.js";
import type { ToolCallInput, ValidatedConfig, ToolMapping } from "../src/types.js";

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

function makeInput(toolName: string): ToolCallInput {
  return { toolName, params: {} };
}

describe("evaluateLocal", () => {
  it("returns undefined for safe tools", () => {
    const result = evaluateLocal(
      makeInput("fs_read"),
      makeConfig(),
      0,
      { category: "file_read", riskMultiplier: 0.3 },
    );
    assert.equal(result, undefined);
  });

  it("blocks tools in blockedTools list", () => {
    const result = evaluateLocal(
      makeInput("bash"),
      makeConfig({ blockedTools: ["bash"] }),
      0,
      { category: "exec", riskMultiplier: 1.0 },
    );
    assert.equal(result!.block, true);
    assert.ok(result!.blockReason!.includes("bash"));
  });

  it("blocks tools with block override in mapping", () => {
    const result = evaluateLocal(
      makeInput("fs_read"),
      makeConfig(),
      0,
      { category: "file_read", riskMultiplier: 0.3, block: true },
    );
    assert.equal(result!.block, true);
  });

  it("blocks tools in blockedCategories", () => {
    const result = evaluateLocal(
      makeInput("bash"),
      makeConfig({ blockedCategories: ["exec"] }),
      0,
      { category: "exec", riskMultiplier: 1.0 },
    );
    assert.equal(result!.block, true);
    assert.ok(result!.blockReason!.includes("Category"));
  });

  it("blocks when session risk exceeds limit", () => {
    const result = evaluateLocal(
      makeInput("bash"),
      makeConfig({ sessionRiskLimit: 0.8 }),
      0.7,
      { category: "exec", riskMultiplier: 1.0 },
    );
    assert.equal(result!.block, true);
    assert.ok(result!.blockReason!.includes("risk limit"));
  });

  it("allows when session risk is below limit", () => {
    const result = evaluateLocal(
      makeInput("fs_read"),
      makeConfig({ sessionRiskLimit: 0.8 }),
      0.3,
      { category: "file_read", riskMultiplier: 0.3 },
    );
    assert.equal(result, undefined);
  });

  it("returns requireApproval object for requireApprovalCategories", () => {
    const result = evaluateLocal(
      makeInput("secrets"),
      makeConfig({ sessionRiskLimit: 1.0, requireApprovalCategories: ["secrets"] }),
      0,
      { category: "secrets", riskMultiplier: 0.8 },
    );
    assert.equal(result!.block, undefined);
    assert.ok(result!.requireApproval);
    assert.equal(result!.requireApproval!.title, "Approval required: secrets");
    assert.equal(result!.requireApproval!.severity, "warning");
    assert.ok(result!.requireApproval!.id);
  });

  it("returns requireApproval for tools with requireApproval override", () => {
    const result = evaluateLocal(
      makeInput("fs_read"),
      makeConfig({ sessionRiskLimit: 1.0 }),
      0,
      { category: "file_read", riskMultiplier: 0.3, requireApproval: true },
    );
    assert.ok(result!.requireApproval);
  });

  it("requireApproval object has all required fields", () => {
    const result = evaluateLocal(
      makeInput("secrets"),
      makeConfig({ sessionRiskLimit: 1.0, requireApprovalCategories: ["secrets"] }),
      0,
      { category: "secrets", riskMultiplier: 0.8 },
    );
    const ra = result!.requireApproval!;
    assert.ok(ra.id);
    assert.ok(ra.title);
    assert.ok(ra.description);
    assert.ok(ra.severity);
  });

  it("blocked takes precedence over requireApproval", () => {
    const result = evaluateLocal(
      makeInput("bash"),
      makeConfig({ blockedTools: ["bash"], requireApprovalCategories: ["exec"] }),
      0,
      { category: "exec", riskMultiplier: 1.0 },
    );
    assert.equal(result!.block, true);
    assert.equal(result!.requireApproval, undefined);
  });
});
