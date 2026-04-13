import type {
  HookDeps,
  ToolCallInput,
  ToolCallContext,
  ToolCallResult,
} from "./types.js";

/**
 * Create an async `before_tool_call` handler wired to AxiomGuard.
 *
 * Flow:
 *  1. Local evaluation (standalone + managed)
 *  2. If standalone mode → return local decision
 *  3. If managed mode → await control plane, merge decisions
 *
 * Hooks in OpenClaw are async, so we can properly await the CP call.
 */
export function createHandler(deps: HookDeps) {
  const { config, runtimeGuard, sessionTracker, resolveToolMapping, evaluateLocal } = deps;

  return async function beforeToolCall(
    input: ToolCallInput,
    ctx: ToolCallContext,
  ): Promise<ToolCallResult | void> {
    const mapping = resolveToolMapping(input.toolName, config.toolOverrides);
    const sessionRisk = sessionTracker.getRisk(ctx.sessionKey);

    // Local evaluation (works in both modes)
    const localResult = evaluateLocal(input, config, sessionRisk, mapping);

    // If local check blocks, return immediately (no CP call needed)
    if (localResult?.block) {
      sessionTracker.record(ctx.sessionKey, {
        category: mapping.category,
        riskScore: mapping.riskMultiplier,
        decision: "block",
      });
      return localResult;
    }

    // Standalone mode: return local decision only
    if (!config.cpUrl || !runtimeGuard) {
      sessionTracker.record(ctx.sessionKey, {
        category: mapping.category,
        riskScore: mapping.riskMultiplier,
        decision: localResult?.requireApproval ? "requireApproval" : "allow",
      });
      return localResult;
    }

    // Managed mode: await control plane decision
    try {
      const cpResult = await runtimeGuard.check(
        mapping.category,
        input.params,
        { sessionId: ctx.sessionKey, agentId: ctx.agentId },
      );

      sessionTracker.record(ctx.sessionKey, {
        category: mapping.category,
        riskScore: mapping.riskMultiplier,
        decision: cpResult.decision === "Block" ? "block" : "allow",
      });

      // CP says block — that overrides everything
      if (cpResult.decision === "Block") {
        return {
          block: true,
          blockReason: cpResult.reason ?? "Blocked by AxiomGuard control plane",
        };
      }

      // CP allows — local requireApproval still applies
      return localResult;
    } catch {
      // CP unreachable
      sessionTracker.record(ctx.sessionKey, {
        category: mapping.category,
        riskScore: mapping.riskMultiplier,
        decision: "allow",
      });

      if (!config.failOpen) {
        return {
          block: true,
          blockReason: "AxiomGuard control plane unreachable",
        };
      }

      // Fail-open: return local decision
      return localResult;
    }
  };
}
