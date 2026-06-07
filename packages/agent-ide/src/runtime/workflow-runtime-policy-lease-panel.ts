import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import {
  workflowRuntimeEventId,
  workflowRuntimeEventKind,
} from "./workflow-runtime-event-identity";

export const WORKFLOW_RUNTIME_POLICY_LEASE_PANEL_SCHEMA_VERSION =
  "ioi.workflow.policy-lease-panel.v1" as const;

export type WorkflowRuntimePolicyLeaseStatus =
  | "pending"
  | "active"
  | "denied"
  | "revoked"
  | "expired";

export interface WorkflowRuntimePolicyLeasePanelOptions {
  threadId?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  now?: string | null;
}

export interface WorkflowRuntimePolicyLeaseRow {
  approvalId: string;
  leaseId: string | null;
  status: WorkflowRuntimePolicyLeaseStatus;
  scope: string | null;
  action: string | null;
  policyHash: string | null;
  ttlMs: number | null;
  expiresAt: string | null;
  expectedReceiptRefs: string[];
  authorityScopeRequirements: string[];
  requestEventId: string | null;
  decisionEventId: string | null;
  revokeEventId: string | null;
  latestEventId: string | null;
  latestSeq: number | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  threadId: string | null;
  turnId: string | null;
  revokeEndpoint: string | null;
  revokable: boolean;
  executable: boolean;
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowRuntimePolicyLeasePanel {
  schemaVersion: typeof WORKFLOW_RUNTIME_POLICY_LEASE_PANEL_SCHEMA_VERSION;
  status: "empty" | "pending" | "active" | "blocked" | "revoked";
  rows: WorkflowRuntimePolicyLeaseRow[];
  pendingCount: number;
  activeCount: number;
  deniedCount: number;
  revokedCount: number;
  expiredCount: number;
  eventIds: string[];
  threadIds: string[];
  workflowGraphIds: string[];
  workflowNodeIds: string[];
}

type RuntimeEventInput = WorkflowRuntimeThreadEventLike | Record<string, unknown>;

export function buildWorkflowRuntimePolicyLeasePanel(
  events: readonly RuntimeEventInput[],
  options: WorkflowRuntimePolicyLeasePanelOptions = {},
): WorkflowRuntimePolicyLeasePanel {
  const threadFilter = cleanString(options.threadId);
  const graphFilter = cleanString(options.workflowGraphId);
  const nodeFilter = cleanString(options.workflowNodeId);
  const nowMs = Date.parse(cleanString(options.now) ?? new Date().toISOString());
  const sortedEvents = [...events]
    .filter((event) => {
      const threadId = eventThreadId(event);
      const graphId = eventWorkflowGraphId(event);
      const nodeId = eventWorkflowNodeId(event);
      return (
        (!threadFilter || !threadId || threadId === threadFilter) &&
        (!graphFilter || !graphId || graphId === graphFilter) &&
        (!nodeFilter || !nodeId || nodeId === nodeFilter)
      );
    })
    .sort((left, right) => eventSeq(left) - eventSeq(right));

  const rowsByApprovalId = new Map<string, WorkflowRuntimePolicyLeaseRow>();
  for (const event of sortedEvents) {
    const kind = eventKind(event);
    if (
      kind !== "approval.required" &&
      kind !== "approval.approved" &&
      kind !== "approval.rejected" &&
      kind !== "approval.revoked"
    ) {
      continue;
    }
    const payload = eventPayload(event);
    const approvalId =
      stringField(event, "approval_id") ??
      stringField(payload, "approval_id");
    if (!approvalId) continue;
    const lease = objectField(payload, "approval_lease");
    const current = rowsByApprovalId.get(approvalId);
    const next = rowForPolicyLeaseEvent({
      current,
      event,
      payload,
      lease,
      approvalId,
      kind,
      nowMs,
    });
    rowsByApprovalId.set(approvalId, next);
  }

  const rows = Array.from(rowsByApprovalId.values()).sort((left, right) => {
    return (left.latestSeq ?? 0) - (right.latestSeq ?? 0);
  });
  const pendingCount = rows.filter((row) => row.status === "pending").length;
  const activeCount = rows.filter((row) => row.status === "active").length;
  const deniedCount = rows.filter((row) => row.status === "denied").length;
  const revokedCount = rows.filter((row) => row.status === "revoked").length;
  const expiredCount = rows.filter((row) => row.status === "expired").length;
  const status =
    rows.length === 0
      ? "empty"
      : activeCount > 0
        ? "active"
        : pendingCount > 0
          ? "pending"
          : revokedCount > 0
            ? "revoked"
            : "blocked";

  return {
    schemaVersion: WORKFLOW_RUNTIME_POLICY_LEASE_PANEL_SCHEMA_VERSION,
    status,
    rows,
    pendingCount,
    activeCount,
    deniedCount,
    revokedCount,
    expiredCount,
    eventIds: uniqueStrings(rows.flatMap((row) =>
      [row.requestEventId, row.decisionEventId, row.revokeEventId, row.latestEventId],
    )),
    threadIds: uniqueStrings(rows.map((row) => row.threadId)),
    workflowGraphIds: uniqueStrings(rows.map((row) => row.workflowGraphId)),
    workflowNodeIds: uniqueStrings(rows.map((row) => row.workflowNodeId)),
  };
}

function rowForPolicyLeaseEvent({
  current,
  event,
  payload,
  lease,
  approvalId,
  kind,
  nowMs,
}: {
  current?: WorkflowRuntimePolicyLeaseRow;
  event: RuntimeEventInput;
  payload: Record<string, unknown>;
  lease: Record<string, unknown>;
  approvalId: string;
  kind: string;
  nowMs: number;
}): WorkflowRuntimePolicyLeaseRow {
  const status = policyLeaseStatusForEvent(kind, payload, lease, nowMs);
  const eventId = eventIdForRuntimeEvent(event);
  const receiptRefs = uniqueStrings([
    ...(current?.receiptRefs ?? []),
    ...arrayField(event, "receipt_refs"),
  ]);
  const policyDecisionRefs = uniqueStrings([
    ...(current?.policyDecisionRefs ?? []),
    ...arrayField(event, "policy_decision_refs"),
  ]);

  return {
    approvalId,
    leaseId:
      stringField(lease, "lease_id") ??
      stringField(payload, "lease_id") ??
      current?.leaseId ??
      null,
    status,
    scope: stringField(lease, "scope") ?? stringField(payload, "scope") ?? current?.scope ?? null,
    action: stringField(lease, "action") ?? stringField(payload, "action") ?? current?.action ?? null,
    policyHash:
      stringField(lease, "policy_hash") ??
      stringField(payload, "policy_hash") ??
      current?.policyHash ??
      null,
    ttlMs:
      numberField(lease, "ttl_ms") ??
      numberField(payload, "ttl_ms") ??
      current?.ttlMs ??
      null,
    expiresAt:
      stringField(lease, "expires_at") ??
      stringField(payload, "expires_at") ??
      current?.expiresAt ??
      null,
    expectedReceiptRefs: uniqueStrings([
      ...(current?.expectedReceiptRefs ?? []),
      ...arrayField(lease, "expected_receipt_refs"),
      ...arrayField(payload, "expected_receipt_refs"),
    ]),
    authorityScopeRequirements: uniqueStrings([
      ...(current?.authorityScopeRequirements ?? []),
      ...arrayField(lease, "authority_scope_requirements"),
      ...arrayField(payload, "authority_scope_requirements"),
    ]),
    requestEventId:
      kind === "approval.required"
        ? eventId
        : stringField(payload, "approval_request_event_id") ??
          current?.requestEventId ??
          null,
    decisionEventId:
      kind === "approval.approved" || kind === "approval.rejected"
        ? eventId
        : stringField(payload, "approval_decision_event_id") ??
          current?.decisionEventId ??
          null,
    revokeEventId: kind === "approval.revoked" ? eventId : current?.revokeEventId ?? null,
    latestEventId: eventId,
    latestSeq: eventSeq(event),
    workflowGraphId: eventWorkflowGraphId(event) ?? current?.workflowGraphId ?? null,
    workflowNodeId: eventWorkflowNodeId(event) ?? current?.workflowNodeId ?? null,
    threadId: eventThreadId(event) ?? current?.threadId ?? null,
    turnId: eventTurnId(event) ?? current?.turnId ?? null,
    revokeEndpoint:
      stringField(lease, "revoke_endpoint") ??
      stringField(payload, "revoke_endpoint") ??
      current?.revokeEndpoint ??
      null,
    revokable: status === "pending" || status === "active",
    executable: status === "active",
    receiptRefs,
    policyDecisionRefs,
  };
}

function policyLeaseStatusForEvent(
  kind: string,
  payload: Record<string, unknown>,
  lease: Record<string, unknown>,
  nowMs: number,
): WorkflowRuntimePolicyLeaseStatus {
  if (kind === "approval.revoked") return "revoked";
  if (kind === "approval.rejected") return "denied";
  if (kind === "approval.required") return "pending";
  const explicit = cleanString(
    stringField(lease, "status") ??
      stringField(payload, "lease_status") ??
      stringField(payload, "status"),
  );
  const expiresAt = stringField(lease, "expires_at") ??
    stringField(payload, "expires_at");
  const expiresMs = expiresAt ? Date.parse(expiresAt) : Number.NaN;
  if (Number.isFinite(expiresMs) && expiresMs <= nowMs) return "expired";
  if (explicit === "active" || explicit === "approved") return "active";
  return "active";
}

function eventPayload(event: RuntimeEventInput): Record<string, unknown> {
  const record = event as Record<string, unknown>;
  return objectValue(record.payload_summary) ?? objectValue(record.payload) ?? {};
}

function objectField(record: Record<string, unknown>, ...keys: string[]): Record<string, unknown> {
  for (const key of keys) {
    const object = objectValue(record[key]);
    if (object) return object;
  }
  return {};
}

function objectValue(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function stringField(record: unknown, ...keys: string[]): string | null {
  const object = objectValue(record);
  if (!object) return null;
  for (const key of keys) {
    const value = object[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
  return null;
}

function numberField(record: unknown, ...keys: string[]): number | null {
  const object = objectValue(record);
  if (!object) return null;
  for (const key of keys) {
    const value = object[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim()) {
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
  }
  return null;
}

function arrayField(record: unknown, ...keys: string[]): string[] {
  const object = objectValue(record);
  if (!object) return [];
  for (const key of keys) {
    const value = object[key];
    if (Array.isArray(value)) {
      return value
        .map((item) => cleanString(item))
        .filter((item): item is string => Boolean(item));
    }
  }
  return [];
}

function eventIdForRuntimeEvent(event: RuntimeEventInput): string | null {
  return workflowRuntimeEventId(event);
}

function eventKind(event: RuntimeEventInput): string {
  return workflowRuntimeEventKind(event) ?? "";
}

function eventSeq(event: RuntimeEventInput): number {
  return numberField(event, "seq") ?? 0;
}

function eventThreadId(event: RuntimeEventInput): string | null {
  return stringField(event, "thread_id");
}

function eventTurnId(event: RuntimeEventInput): string | null {
  return stringField(event, "turn_id");
}

function eventWorkflowGraphId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflow_graph_id");
}

function eventWorkflowNodeId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflow_node_id");
}

function cleanString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(values.map((value) => cleanString(value)).filter((value): value is string => Boolean(value))),
  );
}
