export const WORKFLOW_SANDBOX_RESOURCE_LIMITS_SCHEMA_VERSION =
  "ioi.workflow.sandbox-resource-limits.v1" as const;

export type WorkflowSandboxResourceStatus = "ready" | "needs_review" | "blocked";

export interface WorkflowSandboxResourceDefaults {
  maxTimeoutMs: number;
  maxMemoryMb: number;
  maxOutputKb: number;
  network: "deny" | "allow";
  currentBoundary: "pre_execution_policy" | "container_namespace";
}

export interface WorkflowSandboxResourcePlan {
  id: string;
  label: string;
  command: string;
  requestedTimeoutMs?: number | null;
  requestedMemoryMb?: number | null;
  requestedOutputKb?: number | null;
  requestedNetwork?: "deny" | "allow" | null;
  arbitraryShell?: boolean | null;
  receiptRequired?: boolean | null;
}

export interface WorkflowSandboxResourceLimitRow {
  id: string;
  label: string;
  commandPreview: string;
  status: WorkflowSandboxResourceStatus;
  effectiveLimits: {
    timeoutMs: number;
    memoryMb: number;
    outputKb: number;
    network: "deny" | "allow";
  };
  boundary: {
    current: WorkflowSandboxResourceDefaults["currentBoundary"];
    containerNamespaceRequired: boolean;
  };
  policyRefs: string[];
  blockReason: string | null;
}

export interface WorkflowSandboxResourceLimitPanel {
  schemaVersion: typeof WORKFLOW_SANDBOX_RESOURCE_LIMITS_SCHEMA_VERSION;
  status: "ready" | "needs_review" | "blocked";
  defaultLimits: WorkflowSandboxResourceDefaults;
  rowCount: number;
  readyCount: number;
  needsReviewCount: number;
  blockedCount: number;
  rows: WorkflowSandboxResourceLimitRow[];
}

export function buildWorkflowSandboxResourceLimitPanel(input: {
  defaults: WorkflowSandboxResourceDefaults;
  plans: readonly WorkflowSandboxResourcePlan[];
}): WorkflowSandboxResourceLimitPanel {
  const rows = normalizePlans(input.plans).map((plan) => resourceLimitRow(plan, input.defaults));
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const needsReviewCount = rows.filter((row) => row.status === "needs_review").length;
  const readyCount = rows.filter((row) => row.status === "ready").length;
  return {
    schemaVersion: WORKFLOW_SANDBOX_RESOURCE_LIMITS_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : needsReviewCount > 0 ? "needs_review" : "ready",
    defaultLimits: input.defaults,
    rowCount: rows.length,
    readyCount,
    needsReviewCount,
    blockedCount,
    rows,
  };
}

function resourceLimitRow(
  plan: WorkflowSandboxResourcePlan,
  defaults: WorkflowSandboxResourceDefaults,
): WorkflowSandboxResourceLimitRow {
  const effectiveLimits = {
    timeoutMs: plan.requestedTimeoutMs ?? defaults.maxTimeoutMs,
    memoryMb: plan.requestedMemoryMb ?? defaults.maxMemoryMb,
    outputKb: plan.requestedOutputKb ?? defaults.maxOutputKb,
    network: plan.requestedNetwork ?? defaults.network,
  };
  const policyRefs = [
    "policy:sandbox_resource.plan_only",
    "policy:sandbox_resource.receipt_required",
    "policy:sandbox_resource.timeout_limit",
    "policy:sandbox_resource.memory_limit",
    "policy:sandbox_resource.output_limit",
    "policy:sandbox_resource.network_default_deny",
  ];

  if (effectiveLimits.timeoutMs > defaults.maxTimeoutMs) {
    policyRefs.push("policy:sandbox_resource.block.timeout_exceeded");
  }
  if (effectiveLimits.memoryMb > defaults.maxMemoryMb) {
    policyRefs.push("policy:sandbox_resource.block.memory_exceeded");
  }
  if (effectiveLimits.outputKb > defaults.maxOutputKb) {
    policyRefs.push("policy:sandbox_resource.block.output_exceeded");
  }
  if (effectiveLimits.network !== "deny" || networkShapedCommand(plan.command)) {
    policyRefs.push("policy:sandbox_resource.block.network");
  }
  if (plan.arbitraryShell && defaults.currentBoundary !== "container_namespace") {
    policyRefs.push("policy:sandbox_resource.review.linux_namespace_missing");
  }
  if (plan.receiptRequired === false) {
    policyRefs.push("policy:sandbox_resource.block.receipt_not_required");
  }

  const blockReason = blockReasonForPolicy(policyRefs);
  const status = blockReason
    ? "blocked"
    : policyRefs.some((policyRef) => policyRef.includes(".review."))
      ? "needs_review"
      : "ready";

  return {
    id: safeId(plan.id),
    label: plan.label,
    commandPreview: plan.command.slice(0, 160),
    status,
    effectiveLimits,
    boundary: {
      current: defaults.currentBoundary,
      containerNamespaceRequired: !!plan.arbitraryShell,
    },
    policyRefs,
    blockReason,
  };
}

function blockReasonForPolicy(policyRefs: readonly string[]): string | null {
  if (policyRefs.includes("policy:sandbox_resource.block.network")) {
    return "Network access is denied for sandboxed command plans.";
  }
  if (policyRefs.includes("policy:sandbox_resource.block.timeout_exceeded")) {
    return "Requested timeout exceeds the sandbox limit.";
  }
  if (policyRefs.includes("policy:sandbox_resource.block.memory_exceeded")) {
    return "Requested memory exceeds the sandbox limit.";
  }
  if (policyRefs.includes("policy:sandbox_resource.block.output_exceeded")) {
    return "Requested output capture exceeds the sandbox limit.";
  }
  if (policyRefs.includes("policy:sandbox_resource.block.receipt_not_required")) {
    return "Sandboxed command plans must require execution receipts.";
  }
  return null;
}

function networkShapedCommand(command: string): boolean {
  return /\b(curl|wget|ssh|scp|nc|ncat|telnet)\b|https?:\/\//i.test(command);
}

function normalizePlans(plans: readonly WorkflowSandboxResourcePlan[] | undefined): WorkflowSandboxResourcePlan[] {
  return Array.isArray(plans) ? plans.filter(Boolean) : [];
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "plan"
  );
}
