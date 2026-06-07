import type { RuntimeDiagnosticsRepairAction } from "./workflow-runtime-control-nodes";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

export type WorkflowRuntimeDiagnosticsRepairAction = RuntimeDiagnosticsRepairAction;

export interface WorkflowRuntimeDiagnosticsRepairActionDescriptor {
  id: string;
  decisionId: string;
  action: WorkflowRuntimeDiagnosticsRepairAction;
  label: string;
  summary: string | null;
  status: string;
  executable: boolean;
  requiresApproval: boolean;
  approvalGranted: boolean;
  allowConflicts: boolean;
  restoreConflictPolicy: string | null;
  threadId: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventId: string;
  rollbackRefs: string[];
  workspaceSnapshotRefs: string[];
  policyDecisionRefs: string[];
  receiptRefs: string[];
}

const DIAGNOSTICS_REPAIR_ACTION_LABELS: Record<
  WorkflowRuntimeDiagnosticsRepairAction,
  string
> = {
  repair_retry: "Retry repair",
  restore_preview: "Preview restore",
  restore_apply: "Apply restore",
  operator_override: "Override",
};

export function diagnosticsRepairActionsForEvents(
  events: readonly WorkflowRuntimeThreadEventLike[],
  latestEvent: WorkflowRuntimeThreadEventLike,
): WorkflowRuntimeDiagnosticsRepairActionDescriptor[] {
  const descriptors = new Map<
    WorkflowRuntimeDiagnosticsRepairAction,
    WorkflowRuntimeDiagnosticsRepairActionDescriptor
  >();

  for (const event of events) {
    const payload = event.payload ?? {};
    for (const { decision, policy } of diagnosticsRepairDecisionRecords(payload)) {
      const action = diagnosticsRepairActionFromValue(
        stringField(decision, "action"),
      );
      if (!action) continue;
      const status = stringField(decision, "status") ?? "available";
      const policyDecisionRefs = uniqueStrings([
        ...event.policyDecisionRefs,
        ...stringArrayField(policy, "decision_refs"),
        stringField(policy, "policy_id") ?? "",
      ]);
      const decisionId =
        stringField(decision, "decision_id") ??
        stringField(decision, "id") ??
        matchingDiagnosticsRepairDecisionRef(policyDecisionRefs, action) ??
        action;
      const restoreConflictPolicy =
        stringField(decision, "restore_conflict_policy") ??
        stringField(policy, "restore_conflict_policy");
      const requiresApproval =
        booleanField(decision, "requires_approval") ??
        status === "requires_approval";
      const allowConflicts =
        booleanField(decision, "allow_conflicts") ??
        booleanField(decision, "override_conflicts") ??
        restoreConflictPolicy === "allow_override";
      const workflowNodeId =
        stringField(decision, "workflow_node_id") ??
        `runtime.run-inspector.diagnostics-repair.${slug(action)}`;
      descriptors.set(action, {
        id: `diagnostics-repair:${event.threadId}:${decisionId}:${action}`,
        decisionId,
        action,
        label: DIAGNOSTICS_REPAIR_ACTION_LABELS[action],
        summary:
          stringField(decision, "summary") ?? stringField(decision, "message"),
        status,
        executable: diagnosticsRepairDecisionIsExecutable(status),
        requiresApproval,
        approvalGranted:
          requiresApproval ||
          action === "restore_apply" ||
          action === "operator_override",
        allowConflicts,
        restoreConflictPolicy,
        threadId:
          stringField(decision, "thread_id") ??
          stringField(policy, "thread_id") ??
          event.threadId,
        workflowGraphId:
          stringField(decision, "workflow_graph_id") ??
          event.workflowGraphId ??
          latestEvent.workflowGraphId,
        workflowNodeId,
        eventId: event.id,
        rollbackRefs: uniqueStrings([
          ...event.rollbackRefs,
          ...stringArrayField(decision, "rollback_refs"),
          ...stringArrayField(policy, "rollback_refs"),
        ]),
        workspaceSnapshotRefs: uniqueStrings([
          ...stringArrayField(decision, "workspace_snapshot_refs"),
          ...stringArrayField(policy, "workspace_snapshot_refs"),
        ]),
        policyDecisionRefs,
        receiptRefs: event.receiptRefs,
      });
    }
  }

  const order: WorkflowRuntimeDiagnosticsRepairAction[] = [
    "repair_retry",
    "restore_preview",
    "restore_apply",
    "operator_override",
  ];
  return order.flatMap((action) => {
    const descriptor = descriptors.get(action);
    return descriptor ? [descriptor] : [];
  });
}

function diagnosticsRepairDecisionRecords(
  payload: Record<string, unknown>,
): Array<{
  decision: Record<string, unknown>;
  policy: Record<string, unknown> | null;
}> {
  const policies = uniqueRecords([
    recordField(payload, "repair_policy"),
    recordField(payload, "diagnostics_repair_policy"),
    recordField(
      recordField(payload, "diagnostics_repair_context"),
      "repair_policy",
    ),
    recordField(recordField(payload, "result"), "repair_policy"),
  ]);
  const records: Array<{
    decision: Record<string, unknown>;
    policy: Record<string, unknown> | null;
  }> = [];

  for (const policy of policies) {
    for (const decision of arrayField(policy, "decisions")) {
      const record = objectField(decision);
      if (record) records.push({ decision: record, policy });
    }
  }

  for (const decision of [
    ...arrayField(payload, "repair_decisions"),
    ...arrayField(payload, "decisions"),
  ]) {
    const record = objectField(decision);
    if (record) records.push({ decision: record, policy: policies[0] ?? null });
  }

  return records;
}

function uniqueRecords(
  records: Array<Record<string, unknown> | null>,
): Record<string, unknown>[] {
  return records.filter(
    (record, index): record is Record<string, unknown> =>
      Boolean(record) && records.indexOf(record) === index,
  );
}

function diagnosticsRepairActionFromValue(
  value: string | null,
): WorkflowRuntimeDiagnosticsRepairAction | null {
  const normalized = value?.trim().toLowerCase().replace(/-/g, "_") ?? "";
  switch (normalized) {
    case "retry":
    case "repair_retry":
      return "repair_retry";
    case "preview_restore":
    case "restore_preview":
      return "restore_preview";
    case "apply_restore":
    case "restore_apply":
      return "restore_apply";
    case "override":
    case "operator_override":
      return "operator_override";
    default:
      return null;
  }
}

function diagnosticsRepairDecisionIsExecutable(status: string): boolean {
  const normalizedStatus = status.trim().toLowerCase();
  return (
    !normalizedStatus ||
    normalizedStatus === "available" ||
    normalizedStatus === "requires_approval"
  );
}

function matchingDiagnosticsRepairDecisionRef(
  policyDecisionRefs: readonly string[],
  action: WorkflowRuntimeDiagnosticsRepairAction,
): string | null {
  const actionSlug = action.replace(/_/g, "-");
  return (
    policyDecisionRefs.find(
      (ref) => ref.includes(action) || ref.includes(actionSlug),
    ) ?? null
  );
}

function uniqueStrings(values: readonly string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function objectField(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringField(value: unknown, key: string): string | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate = objectValue[key];
  return typeof candidate === "string" && candidate.trim() ? candidate : null;
}

function booleanField(value: unknown, key: string): boolean | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate = objectValue[key];
  if (typeof candidate === "boolean") return candidate;
  if (typeof candidate !== "string") return null;
  const normalized = candidate.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return null;
}

function arrayField(value: unknown, key: string): unknown[] {
  const objectValue = objectField(value);
  if (!objectValue) return [];
  const candidate = objectValue[key];
  return Array.isArray(candidate) ? candidate : [];
}

function recordField(
  value: unknown,
  key: string,
): Record<string, unknown> | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate = objectValue[key];
  return objectField(candidate);
}

function stringArrayField(value: unknown, key: string): string[] {
  return arrayField(value, key).filter(
    (candidate): candidate is string =>
      typeof candidate === "string" && Boolean(candidate.trim()),
  );
}

function slug(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || "unknown";
}
