export const PLAN_MODE_DIRECTIVE =
  "Plan mode is active. Produce or update an explicit execution plan before execution, call out blockers, validation, evidence, and next steps, and do not claim completion until the plan is validated.";

export function buildPlanModeIntent(
  text: string,
  planMode: boolean,
): string {
  const trimmed = text.trim();
  if (!planMode || trimmed.length === 0) {
    return trimmed;
  }
  if (trimmed.startsWith(PLAN_MODE_DIRECTIVE)) {
    return trimmed;
  }
  return `${PLAN_MODE_DIRECTIVE}\n\nOperator request:\n${trimmed}`;
}

export function planModePlaceholder(defaultPlaceholder?: string): string {
  return (
    defaultPlaceholder ||
    "Ask for an execution plan, review strategy, or plan update before running work."
  );
}

export function planModeStatusCopy(): string {
  return "Plan mode keeps the plan drawer in focus and turns each submission into a plan-first operator request.";
}
