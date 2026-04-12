import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveToolMapping, getDefaultMap } from "../src/tool-map.js";

describe("resolveToolMapping", () => {
  it("resolves known exec tools", () => {
    for (const tool of ["exec", "process", "code_execution"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "exec");
      assert.equal(m.riskMultiplier, 1.0);
    }
  });

  it("resolves known file_write tools", () => {
    for (const tool of ["write", "edit", "apply_patch"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "file_write");
      assert.equal(m.riskMultiplier, 0.6);
    }
  });

  it("resolves known file_read tools", () => {
    const m = resolveToolMapping("read");
    assert.equal(m.category, "file_read");
    assert.equal(m.riskMultiplier, 0.3);
  });

  it("resolves known http tools", () => {
    for (const tool of ["web_search", "web_fetch", "x_search"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "http");
      assert.equal(m.riskMultiplier, 0.4);
    }
  });

  it("resolves known browser tools", () => {
    const m = resolveToolMapping("browser");
    assert.equal(m.category, "browser");
    assert.equal(m.riskMultiplier, 0.5);
  });

  it("resolves known message tools", () => {
    const m = resolveToolMapping("message");
    assert.equal(m.category, "message");
    assert.equal(m.riskMultiplier, 0.2);
  });

  it("resolves known automation tools", () => {
    for (const tool of ["cron", "gateway"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "automation");
      assert.equal(m.riskMultiplier, 0.7);
    }
  });

  it("resolves known media_gen tools", () => {
    for (const tool of ["image_generate", "music_generate", "video_generate", "tts"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "media_gen");
      assert.equal(m.riskMultiplier, 0.3);
    }
  });

  it("resolves known sessions tools", () => {
    for (const tool of ["sessions_create", "sessions_list", "sessions_delete", "subagents", "session_status"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "sessions");
      assert.equal(m.riskMultiplier, 0.4);
    }
  });

  it("resolves known memory tools", () => {
    for (const tool of ["memory_search", "memory_get"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "memory");
      assert.equal(m.riskMultiplier, 0.2);
    }
  });

  it("resolves known system tools", () => {
    for (const tool of ["image", "canvas", "nodes"]) {
      const m = resolveToolMapping(tool);
      assert.equal(m.category, "system");
      assert.equal(m.riskMultiplier, 0.3);
    }
  });

  it("returns unknown for unmapped tools", () => {
    const m = resolveToolMapping("totally_unknown_tool");
    assert.equal(m.category, "unknown");
    assert.equal(m.riskMultiplier, 0.8);
  });

  it("applies user overrides for category", () => {
    const m = resolveToolMapping("exec", {
      exec: { category: "custom_exec" },
    });
    assert.equal(m.category, "custom_exec");
    assert.equal(m.riskMultiplier, 1.0); // preserved from base
  });

  it("applies user overrides for riskMultiplier", () => {
    const m = resolveToolMapping("read", {
      read: { riskMultiplier: 0.9 },
    });
    assert.equal(m.category, "file_read"); // preserved from base
    assert.equal(m.riskMultiplier, 0.9);
  });

  it("applies user overrides for block and requireApproval", () => {
    const m = resolveToolMapping("message", {
      message: { block: true, requireApproval: true },
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
    const before = { ...getDefaultMap() };
    resolveToolMapping("exec", { exec: { category: "hacked" } });
    const after = getDefaultMap();
    assert.equal(after.exec.category, "exec");
    assert.deepEqual(Object.keys(before).sort(), Object.keys(after).sort());
  });
});
