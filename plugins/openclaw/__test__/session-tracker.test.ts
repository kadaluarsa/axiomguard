import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { SessionTracker } from "../src/session-tracker.js";

describe("SessionTracker", () => {
  it("returns 0 risk for unknown session", () => {
    const tracker = new SessionTracker();
    assert.equal(tracker.getRisk("unknown"), 0);
  });

  it("returns undefined for unknown session state", () => {
    const tracker = new SessionTracker();
    assert.equal(tracker.get("unknown"), undefined);
  });

  it("accumulates risk across records", () => {
    const tracker = new SessionTracker();
    tracker.record("s1", { category: "exec", riskScore: 0.3, decision: "allow" });
    assert.equal(tracker.getRisk("s1"), 0.3);

    tracker.record("s1", { category: "exec", riskScore: 0.4, decision: "allow" });
    assert.equal(tracker.getRisk("s1"), 0.7);
  });

  it("caps risk at 1.0", () => {
    const tracker = new SessionTracker();
    tracker.record("s1", { category: "exec", riskScore: 0.8, decision: "allow" });
    tracker.record("s1", { category: "exec", riskScore: 0.5, decision: "allow" });
    assert.equal(tracker.getRisk("s1"), 1.0);
  });

  it("tracks entries in session state", () => {
    const tracker = new SessionTracker();
    tracker.record("s1", { category: "exec", riskScore: 0.3, decision: "allow" });
    tracker.record("s1", { category: "http", riskScore: 0.2, decision: "block" });

    const state = tracker.get("s1");
    assert.equal(state!.entries.length, 2);
    assert.equal(state!.entries[0].category, "exec");
    assert.equal(state!.entries[1].category, "http");
    assert.equal(state!.entries[1].decision, "block");
  });

  it("tracks independent sessions separately", () => {
    const tracker = new SessionTracker();
    tracker.record("s1", { category: "exec", riskScore: 0.5, decision: "allow" });
    tracker.record("s2", { category: "http", riskScore: 0.3, decision: "allow" });

    assert.equal(tracker.getRisk("s1"), 0.5);
    assert.equal(tracker.getRisk("s2"), 0.3);
    assert.equal(tracker.size, 2);
  });

  it("evicts stale sessions", () => {
    const tracker = new SessionTracker({ evictionMs: 50 });
    tracker.record("s1", { category: "exec", riskScore: 0.3, decision: "allow" });

    // s1 is fresh
    assert.equal(tracker.size, 1);

    // Wait for eviction threshold
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        tracker.evict();
        assert.equal(tracker.size, 0);
        assert.equal(tracker.getRisk("s1"), 0);
        resolve();
      }, 80);
    });
  });

  it("does not evict fresh sessions", () => {
    const tracker = new SessionTracker({ evictionMs: 5000 });
    tracker.record("s1", { category: "exec", riskScore: 0.3, decision: "allow" });
    tracker.evict();
    assert.equal(tracker.size, 1);
  });

  it("respects maxSessions limit", () => {
    const tracker = new SessionTracker({ maxSessions: 2 });
    tracker.record("s1", { category: "exec", riskScore: 0.1, decision: "allow" });
    tracker.record("s2", { category: "exec", riskScore: 0.1, decision: "allow" });
    // At capacity — new session should be dropped (all are fresh, no eviction)
    tracker.record("s3", { category: "exec", riskScore: 0.1, decision: "allow" });
    assert.equal(tracker.size, 2);
    assert.equal(tracker.getRisk("s3"), 0); // never recorded
  });

  it("evicts stale sessions to make room for new ones", () => {
    const tracker = new SessionTracker({ maxSessions: 2, evictionMs: 50 });

    return new Promise<void>((resolve) => {
      tracker.record("s1", { category: "exec", riskScore: 0.1, decision: "allow" });
      tracker.record("s2", { category: "exec", riskScore: 0.1, decision: "allow" });

      setTimeout(() => {
        // s1 and s2 are stale now, eviction will clear them
        tracker.record("s3", { category: "exec", riskScore: 0.2, decision: "allow" });
        assert.equal(tracker.size, 1);
        assert.equal(tracker.getRisk("s3"), 0.2);
        resolve();
      }, 80);
    });
  });

  it("destroy clears all sessions", () => {
    const tracker = new SessionTracker();
    tracker.record("s1", { category: "exec", riskScore: 0.3, decision: "allow" });
    tracker.record("s2", { category: "exec", riskScore: 0.3, decision: "allow" });
    assert.equal(tracker.size, 2);

    tracker.destroy();
    assert.equal(tracker.size, 0);
    assert.equal(tracker.getRisk("s1"), 0);
  });

  it("updates lastActivity on each record", () => {
    const tracker = new SessionTracker();
    tracker.record("s1", { category: "exec", riskScore: 0.1, decision: "allow" });
    const t1 = tracker.get("s1")!.lastActivity;

    return new Promise<void>((resolve) => {
      setTimeout(() => {
        tracker.record("s1", { category: "exec", riskScore: 0.1, decision: "allow" });
        const t2 = tracker.get("s1")!.lastActivity;
        assert.ok(t2 > t1, "lastActivity should be updated");
        resolve();
      }, 20);
    });
  });
});
