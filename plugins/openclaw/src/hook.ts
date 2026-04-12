import type { HookDeps, ToolCallContext, HookResponse } from "./types.js";

/**
 * Create a `before_tool_call` handler wired to AxiomGuard.
 *
 * Decision flow (all synchronous for sub-ms response):
 *  1. Resolve tool → AG category + risk multiplier
 *  2. Check explicit tool block list
 *  3. Check category block list
 *  4. Check session cumulative risk >= limit
 *  5. Check requireApproval categories
 *  6. Allow
 *
 * After the synchronous decision, a fire-and-forget call to the control plane
 * records the event and may update the risk score for future calls.
 */
export function createHandler(deps: HookDeps) {
  const { config, runtimeGuard, sessionTracker, resolveToolMapping } = deps;

  return function beforeToolCall(context: ToolCallContext): HookResponse {
    const sessionId = context.sessionId ?? "default";
    const mapping = resolveToolMapping(context.tool, config.toolOverrides);

    // 1. Explicit tool-level block
    if (mapping.block || config.blockedTools.includes(context.tool)) {
      fireAndForget(context, mapping, sessionId, "block");
      return { block: true, reason: `Tool "${context.tool}" is blocked` };
    }

    // 2. Category-level block
    if (config.blockedCategories.includes(mapping.category)) {
      fireAndForget(context, mapping, sessionId, "block");
      return {
        block: true,
        reason: `Category "${mapping.category}" is blocked`,
      };
    }

    // 3. Session risk exceeded
    const sessionRisk = sessionTracker.getRisk(sessionId);
    const accumulatedRisk = sessionRisk + mapping.riskMultiplier;
    if (accumulatedRisk >= config.sessionRiskLimit) {
      fireAndForget(context, mapping, sessionId, "block");
      return {
        block: true,
        reason: `Session risk limit exceeded (${accumulatedRisk.toFixed(2)} >= ${config.sessionRiskLimit})`,
      };
    }

    // 4. Require approval
    if (
      mapping.requireApproval ||
      config.requireApprovalCategories.includes(mapping.category)
    ) {
      fireAndForget(context, mapping, sessionId, "requireApproval");
      return {
        requireApproval: true,
        reason: `Category "${mapping.category}" requires approval`,
      };
    }

    // 5. Allow
    fireAndForget(context, mapping, sessionId, "allow");
    return { block: false };
  };

  function fireAndForget(
    context: ToolCallContext,
    mapping: { category: string; riskMultiplier: number },
    sessionId: string,
    decision: string,
  ): void {
    // Update local session tracker immediately
    sessionTracker.record(sessionId, {
      category: mapping.category,
      riskScore: mapping.riskMultiplier,
      decision,
    });

    // Async CP call — intentionally not awaited
    runtimeGuard
      .check(context.tool, context.args, {
        sessionId,
        agentId: context.agentId,
      })
      .catch(() => {
        // Swallow — fire-and-forget. Local decisions already made.
      });
  }
}
