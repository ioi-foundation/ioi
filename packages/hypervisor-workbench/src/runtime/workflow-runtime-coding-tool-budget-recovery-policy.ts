import type { Node, WorkflowProject } from "../types/graph";

export const WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION =
  "ioi.workflow.coding-tool-budget-recovery-policy.v1" as const;

export interface WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor {
  schemaVersion: typeof WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION;
  source: "react_flow_coding_tool_pack" | "runtime_event" | string;
  approvalScope: string;
  operatorRole: string;
  retryLimit: number;
  ttlMs: number;
  requiresApproval: boolean;
  allowOverride: boolean;
  targetNodeIds: string[];
  sourceNodeIds: string[];
}

export function workflowCodingToolBudgetRecoveryPolicyFromWorkflow(
  workflow: Pick<WorkflowProject, "nodes">,
  fallbackTargetNodeIds: readonly string[],
): WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor {
  const fallbackTargets = uniqueStrings(fallbackTargetNodeIds);
  const targetNodes = workflow.nodes.filter((node) =>
    fallbackTargets.includes(node.id),
  );
  const codingToolNodes = targetNodes.filter(workflowNodeIsMutatingCodingTool);
  const configured = codingToolNodes
    .map((node) => ({
      node,
      toolPack: toolPackForNode(node),
    }))
    .filter(
      (entry): entry is { node: Node; toolPack: Record<string, unknown> } =>
        Boolean(entry.toolPack),
    );
  const source = configured.find((entry) =>
    toolPackHasRecoveryPolicy(entry.toolPack),
  ) ?? configured[0];
  const pack = source?.toolPack ?? {};
  const configuredTargetNodeIds = stringArrayOption(
    valueAtPath(pack, "budgetRecoveryTargetNodeIds"),
    valueAtPath(pack, "budget_recovery_target_node_ids"),
    valueAtPath(pack, "recoveryPolicy.targetNodeIds"),
    valueAtPath(pack, "recovery_policy.target_node_ids"),
  );

  return normalizeWorkflowCodingToolBudgetRecoveryPolicy(
    {
      source: "react_flow_coding_tool_pack",
      approvalScope:
        stringOption(
          valueAtPath(pack, "budgetRecoveryApprovalScope"),
          valueAtPath(pack, "budget_recovery_approval_scope"),
          valueAtPath(pack, "recoveryPolicy.approvalScope"),
          valueAtPath(pack, "recovery_policy.approval_scope"),
        ) ?? "target_nodes",
      operatorRole:
        stringOption(
          valueAtPath(pack, "budgetRecoveryOperatorRole"),
          valueAtPath(pack, "budget_recovery_operator_role"),
          valueAtPath(pack, "recoveryPolicy.operatorRole"),
          valueAtPath(pack, "recovery_policy.operator_role"),
        ) ?? "operator",
      retryLimit:
        numberOption(
          valueAtPath(pack, "budgetRecoveryRetryLimit"),
          valueAtPath(pack, "budget_recovery_retry_limit"),
          valueAtPath(pack, "recoveryPolicy.retryLimit"),
          valueAtPath(pack, "recovery_policy.retry_limit"),
        ) ?? 1,
      ttlMs:
        numberOption(
          valueAtPath(pack, "budgetRecoveryTtlMs"),
          valueAtPath(pack, "budget_recovery_ttl_ms"),
          valueAtPath(pack, "recoveryPolicy.ttlMs"),
          valueAtPath(pack, "recovery_policy.ttl_ms"),
        ) ?? 900_000,
      requiresApproval:
        booleanOption(
          valueAtPath(pack, "budgetRecoveryRequiresApproval"),
          valueAtPath(pack, "budget_recovery_requires_approval"),
          valueAtPath(pack, "recoveryPolicy.requiresApproval"),
          valueAtPath(pack, "recovery_policy.requires_approval"),
        ) ?? true,
      allowOverride:
        booleanOption(
          valueAtPath(pack, "budgetRecoveryAllowOverride"),
          valueAtPath(pack, "budget_recovery_allow_override"),
          valueAtPath(pack, "recoveryPolicy.allowOverride"),
          valueAtPath(pack, "recovery_policy.allow_override"),
        ) ?? true,
      targetNodeIds: configuredTargetNodeIds.length > 0
        ? configuredTargetNodeIds
        : fallbackTargets,
      sourceNodeIds: uniqueStrings([
        ...configured.map((entry) => entry.node.id),
        ...(source ? [source.node.id] : []),
      ]),
    },
    fallbackTargets,
  );
}

export function workflowCodingToolBudgetRecoveryPolicyFromUnknown(
  value: unknown,
  fallbackTargetNodeIds: readonly string[] = [],
): WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor | null {
  const direct = recordFromUnknown(value);
  const candidate =
    direct &&
    stringOption(valueAtPath(direct, "schemaVersion"), valueAtPath(direct, "schema_version")) ===
      WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION
      ? direct
      : recordField(direct, "recoveryPolicy", "recovery_policy") ??
        recordField(
          direct,
          "codingToolBudgetRecoveryPolicy",
          "coding_tool_budget_recovery_policy",
        ) ??
        recordField(
          recordField(direct, "preflight"),
          "recoveryPolicy",
          "recovery_policy",
        ) ??
        recordField(
          recordField(direct, "approvalManifest", "approval_manifest"),
          "recoveryPolicy",
          "recovery_policy",
        );
  if (!candidate) return null;
  return normalizeWorkflowCodingToolBudgetRecoveryPolicy(
    candidate,
    fallbackTargetNodeIds,
  );
}

export function normalizeWorkflowCodingToolBudgetRecoveryPolicy(
  value: unknown,
  fallbackTargetNodeIds: readonly string[] = [],
): WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor {
  const record = recordFromUnknown(value) ?? {};
  const fallbackTargets = uniqueStrings(fallbackTargetNodeIds);
  const targetNodeIds = stringArrayOption(
    valueAtPath(record, "targetNodeIds"),
    valueAtPath(record, "target_node_ids"),
  );
  const sourceNodeIds = stringArrayOption(
    valueAtPath(record, "sourceNodeIds"),
    valueAtPath(record, "source_node_ids"),
  );

  return {
    schemaVersion: WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION,
    source: stringOption(valueAtPath(record, "source")) ?? "runtime_event",
    approvalScope:
      stringOption(
        valueAtPath(record, "approvalScope"),
        valueAtPath(record, "approval_scope"),
      ) ?? "target_nodes",
    operatorRole:
      stringOption(
        valueAtPath(record, "operatorRole"),
        valueAtPath(record, "operator_role"),
      ) ?? "operator",
    retryLimit:
      Math.max(
        0,
        Math.trunc(
          numberOption(
            valueAtPath(record, "retryLimit"),
            valueAtPath(record, "retry_limit"),
          ) ?? 1,
        ),
      ),
    ttlMs:
      Math.max(
        0,
        Math.trunc(
          numberOption(valueAtPath(record, "ttlMs"), valueAtPath(record, "ttl_ms")) ??
            900_000,
        ),
      ),
    requiresApproval:
      booleanOption(
        valueAtPath(record, "requiresApproval"),
        valueAtPath(record, "requires_approval"),
      ) ?? true,
    allowOverride:
      booleanOption(
        valueAtPath(record, "allowOverride"),
        valueAtPath(record, "allow_override"),
      ) ?? true,
    targetNodeIds: uniqueStrings(
      (targetNodeIds.length > 0 ? targetNodeIds : fallbackTargets).filter(Boolean),
    ),
    sourceNodeIds: uniqueStrings(sourceNodeIds),
  };
}

function workflowNodeIsMutatingCodingTool(node: Node): boolean {
  if (node.type !== "plugin_tool") return false;
  const binding = node.config?.logic?.toolBinding;
  if (binding?.bindingKind !== "coding_tool_pack") return false;
  const sideEffectClass = String(binding.sideEffectClass ?? "none");
  return !["none", "read"].includes(sideEffectClass);
}

function toolPackForNode(node: Node): Record<string, unknown> | null {
  const toolPack = node.config?.logic?.toolBinding?.toolPack;
  return recordFromUnknown(toolPack);
}

function toolPackHasRecoveryPolicy(toolPack: Record<string, unknown>): boolean {
  return [
    "budgetRecoveryApprovalScope",
    "budget_recovery_approval_scope",
    "budgetRecoveryTargetNodeIds",
    "budget_recovery_target_node_ids",
    "budgetRecoveryRetryLimit",
    "budget_recovery_retry_limit",
    "budgetRecoveryTtlMs",
    "budget_recovery_ttl_ms",
    "budgetRecoveryOperatorRole",
    "budget_recovery_operator_role",
    "budgetRecoveryAllowOverride",
    "budget_recovery_allow_override",
    "recoveryPolicy",
    "recovery_policy",
  ].some((key) => key in toolPack);
}

function recordField(
  source: unknown,
  ...keys: string[]
): Record<string, unknown> | null {
  const record = recordFromUnknown(source);
  if (!record) return null;
  for (const key of keys) {
    const nested = recordFromUnknown(record[key]);
    if (nested) return nested;
  }
  return null;
}

function recordFromUnknown(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function valueAtPath(source: unknown, path: string): unknown {
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    return undefined;
  }
  return path.split(".").reduce<unknown>((current, segment) => {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }
    return (current as Record<string, unknown>)[segment];
  }, source);
}

function stringOption(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value !== "string") continue;
    const trimmed = value.trim();
    if (trimmed) return trimmed;
  }
  return null;
}

function numberOption(...values: unknown[]): number | null {
  for (const value of values) {
    const parsed =
      typeof value === "number"
        ? value
        : typeof value === "string" && value.trim()
          ? Number(value)
          : null;
    if (typeof parsed === "number" && Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function booleanOption(...values: unknown[]): boolean | null {
  for (const value of values) {
    if (typeof value === "boolean") return value;
  }
  return null;
}

function stringArrayOption(...values: unknown[]): string[] {
  for (const value of values) {
    if (Array.isArray(value)) {
      return uniqueStrings(
        value
          .map((item) => (typeof item === "string" ? item.trim() : ""))
          .filter(Boolean),
      );
    }
    if (typeof value === "string" && value.trim()) {
      return uniqueStrings(
        value
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
      );
    }
  }
  return [];
}

function uniqueStrings(values: readonly string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}
