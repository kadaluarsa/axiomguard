import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveToolMapping, getDefaultMap } from "../src/tool-map.js";

describe("resolveToolMapping", () => {
  it("resolves known exec tools", () => {
    for (const tool of ["bash", "exec", "spawn", "shell", "terminal"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "exec");
      assert.equal(m.riskMultiplier, 1.0);
    }
  });

  it("resolves known file_write tools", () => {
    const m = resolveToolMapping("fs_write");
    assert.equal(m.category, "file_write");
    assert.equal(m.riskMultiplier, 0.6);
  });

  it("resolves known file_read tools", () => {
    const m = resolveToolMapping("fs_read");
    assert.equal(m.category, "file_read");
    assert.equal(m.riskMultiplier, 0.3);
  });

  it("resolves known http tools", () => {
    for (const tool of ["web-search", "web-fetch"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "http");
      assert.equal(m.riskMultiplier, 0.4);
    }
  });

  it("resolves known browser tool", () => {
    const m = resolveToolMapping("browser");
    assert.equal(m.category, "browser");
    assert.equal(m.riskMultiplier, 0.5);
  });

  it("resolves known automation tool", () => {
    const m = resolveToolMapping("cron");
    assert.equal(m.category, "automation");
    assert.equal(m.riskMultiplier, 0.7);
  });

  it("resolves known system tools", () => {
    for (const tool of ["gateway", "nodes"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "system");
      assert.equal(m.riskMultiplier, 0.7);
    }
  });

  it("resolves known sessions tools", () => {
    for (const tool of ["sessions", "subagents"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "sessions");
      assert.equal(m.riskMultiplier, 0.4);
    }
  });

  it("resolves secrets tool", () => {
    const m = resolveToolMapping("secrets");
    assert.equal(m.category, "secrets");
    assert.equal(m.riskMultiplier, 0.8);
  });

  it("resolves mcp-* tools by pattern", () => {
    for (const tool of ["mcp-weather", "mcp-github", "mcp-custom-tool"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "mcp");
      assert.equal(m.riskMultiplier, 0.5);
    }
  });

  it("returns unknown for unmapped tools", () => {
    const m = resolveToolMapping("totally_unknown_tool");
    assert.equal(m.category, "unknown");
    assert.equal(m.riskMultiplier, 0.8);
  });

  it("applies user overrides for category", () => {
    const m = resolveToolMapping("bash", {
      bash: { category: "custom_exec" },
    });
    assert.equal(m.category, "custom_exec");
    assert.equal(m.riskMultiplier, 1.0); // preserved from base
  });

  it("applies user overrides for riskMultiplier", () => {
    const m = resolveToolMapping("fs_read", {
      fs_read: { riskMultiplier: 0.9 },
    });
    assert.equal(m.category, "file_read");
    assert.equal(m.riskMultiplier, 0.9);
  });

  it("applies user overrides for block and requireApproval", () => {
    const m = resolveToolMapping("fs_read", {
      fs_read: { block: true, requireApproval: true },
    });
    assert.equal(m.block, true);
    assert.equal(m.requireApproval, true);
  });

  it("applies overrides for unmapped tools", () => {
    const m = resolveToolMapping("custom_tool", {
      custom_tool: { category: "my_category", riskMultiplier: 0.1 },
    });
    assert.equal(m.category, "my_category");
    assert.equal(m.riskMultiplier, 0.1);
  });

  it("does not mutate default map", () => {
    resolveToolMapping("bash", { bash: { category: "hacked" } });
    const after = getDefaultMap();
    assert.equal(after.bash.category, "exec");
  });
});
