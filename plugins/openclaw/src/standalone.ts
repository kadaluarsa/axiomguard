import type { ToolCallInput, ToolCallResult, ValidatedConfig, ToolMapping } from "./types.js";

/**
 * Pure local risk evaluator — no network calls, no side effects.
 *
 * Decision flow:
 *  1. Check blockedTools → { block: true }
 *  2. Check blockedCategories → { block: true }
 *  3. Check session risk >= sessionRiskLimit → { block: true }
 *  4. Check requireApprovalCategories → { requireApproval: { ... } }
 *  5. Return undefined (allow)
 *
 * Used as the primary decision engine in standalone mode,
 * and as the first-pass filter in managed mode.
 */
export function evaluateLocal(
  input: ToolCallInput,
  config: ValidatedConfig,
  sessionRisk: number,
  mapping: ToolMapping,
): ToolCallResult | undefined {
  // 1. Explicit tool-level block
  if (mapping.block || config.blockedTools.includes(input.toolName)) {
    return {
      block: true,
      blockReason: `Tool "${input.toolName}" is blocked`,
    };
  }

  // 2. Category-level block
  if (config.blockedCategories.includes(mapping.category)) {
    return {
      block: true,
      blockReason: `Category "${mapping.category}" is blocked`,
    };
  }

  // 3. Session risk exceeded
  const accumulatedRisk = sessionRisk + mapping.riskMultiplier;
  if (accumulatedRisk >= config.sessionRiskLimit) {
    return {
      block: true,
      blockReason: `Session risk limit exceeded (${accumulatedRisk.toFixed(2)} >= ${config.sessionRiskLimit})`,
    };
  }

  // 4. Require approval
  if (
    mapping.requireApproval ||
    config.requireApprovalCategories.includes(mapping.category)
  ) {
    return {
      requireApproval: {
        id: `ag-${input.toolName}-${Date.now()}`,
        title: `Approval required: ${input.toolName}`,
        description: `Tool "${input.toolName}" (category: ${mapping.category}) requires human approval before execution.`,
        severity: "warning",
      },
    };
  }

  // 5. Allow
  return undefined;
}
