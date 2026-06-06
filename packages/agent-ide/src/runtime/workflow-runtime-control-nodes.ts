import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-thread-fork-control.v1" as const;
export const RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID = "runtime.thread-fork" as const;
export const RUNTIME_THREAD_FORK_COMPONENT_KIND = "thread_fork" as const;
export const RUNTIME_THREAD_FORK_SOURCE = "react_flow" as const;
export const RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND = "OperatorControl.Fork" as const;
export const RUNTIME_THREAD_FORK_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.thread-fork.v1" as const;
export const WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-operator-interrupt-control.v1" as const;
export const RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID =
  "runtime.operator-interrupt" as const;
export const RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND = "operator_control" as const;
export const RUNTIME_OPERATOR_INTERRUPT_SOURCE = "react_flow" as const;
export const RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND =
  "OperatorControl.Interrupt" as const;
export const RUNTIME_OPERATOR_INTERRUPT_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.operator-control.v1" as const;
export const WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-operator-steer-control.v1" as const;
export const RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID =
  "runtime.operator-steer" as const;
export const RUNTIME_OPERATOR_STEER_COMPONENT_KIND = "operator_control" as const;
export const RUNTIME_OPERATOR_STEER_SOURCE = "react_flow" as const;
export const RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND =
  "OperatorControl.Steer" as const;
export const RUNTIME_OPERATOR_STEER_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.operator-control.v1" as const;
export const WORKFLOW_RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-thread-mode-control.v1" as const;
export const RUNTIME_THREAD_MODE_WORKFLOW_NODE_ID =
  "runtime.thread-mode" as const;
export const RUNTIME_THREAD_MODE_COMPONENT_KIND = "runtime_mode" as const;
export const RUNTIME_THREAD_MODE_SOURCE = "react_flow" as const;
export const RUNTIME_THREAD_MODE_SOURCE_EVENT_KIND =
  "OperatorControl.Mode" as const;
export const RUNTIME_THREAD_MODE_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.thread-mode-control.v1" as const;
export const WORKFLOW_RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-workspace-trust-acknowledgement-control.v1" as const;
export const RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_WORKFLOW_NODE_ID =
  "runtime.workspace-trust" as const;
export const RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_COMPONENT_KIND =
  "workspace_trust" as const;
export const RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_SOURCE =
  "react_flow" as const;
export const RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_SOURCE_EVENT_KIND =
  "WorkspaceTrust.Acknowledged" as const;
export const RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.workspace-trust-acknowledgement.v1" as const;
export const WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-context-compact-control.v1" as const;
export const RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID =
  "runtime.context-compact" as const;
export const RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND = "context_compaction" as const;
export const RUNTIME_CONTEXT_COMPACT_SOURCE = "react_flow" as const;
export const RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND =
  "OperatorControl.Compact" as const;
export const RUNTIME_CONTEXT_COMPACT_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.context-compaction.v1" as const;
export const WORKFLOW_RUNTIME_APPROVAL_REQUEST_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-approval-request-control.v1" as const;
export const RUNTIME_APPROVAL_REQUEST_WORKFLOW_NODE_ID =
  "runtime.approval.context-pressure" as const;
export const RUNTIME_APPROVAL_REQUEST_COMPONENT_KIND = "approval_gate" as const;
export const RUNTIME_APPROVAL_REQUEST_SOURCE = "react_flow" as const;
export const RUNTIME_APPROVAL_REQUEST_SOURCE_EVENT_KIND =
  "OperatorApproval.Request" as const;
export const RUNTIME_APPROVAL_REQUEST_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.approval-request.v1" as const;
export const WORKFLOW_RUNTIME_ROLLBACK_SNAPSHOT_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-rollback-snapshot-control.v1" as const;
export const RUNTIME_ROLLBACK_SNAPSHOT_WORKFLOW_NODE_ID =
  "runtime.rollback-snapshot" as const;
export const RUNTIME_ROLLBACK_SNAPSHOT_COMPONENT_KIND =
  "workspace_snapshot" as const;
export const RUNTIME_ROLLBACK_SNAPSHOT_SOURCE = "react_flow" as const;
export const RUNTIME_ROLLBACK_SNAPSHOT_SOURCE_EVENT_KIND =
  "WorkspaceSnapshot.List" as const;
export const RUNTIME_ROLLBACK_SNAPSHOT_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.workspace-snapshot.v1" as const;
export const WORKFLOW_RUNTIME_RESTORE_GATE_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-restore-gate-control.v1" as const;
export const RUNTIME_RESTORE_GATE_WORKFLOW_NODE_ID = "runtime.restore-gate" as const;
export const RUNTIME_RESTORE_GATE_COMPONENT_KIND = "restore_gate" as const;
export const RUNTIME_RESTORE_GATE_SOURCE = "react_flow" as const;
export const RUNTIME_RESTORE_GATE_SOURCE_EVENT_KIND =
  "WorkspaceRestore.Gate" as const;
export const RUNTIME_RESTORE_GATE_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.workspace-restore-gate.v1" as const;
export const WORKFLOW_RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-diagnostics-repair-control.v1" as const;
export const RUNTIME_DIAGNOSTICS_REPAIR_WORKFLOW_NODE_ID =
  "runtime.diagnostics-repair" as const;
export const RUNTIME_DIAGNOSTICS_REPAIR_COMPONENT_KIND =
  "lsp_diagnostics_repair" as const;
export const RUNTIME_DIAGNOSTICS_REPAIR_SOURCE = "react_flow" as const;
export const RUNTIME_DIAGNOSTICS_REPAIR_SOURCE_EVENT_KIND =
  "LspDiagnostics.RepairDecisionExecuted" as const;
export const RUNTIME_DIAGNOSTICS_REPAIR_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.diagnostics-repair-decision-execution.v1" as const;

export interface RuntimeThreadForkControlRequestBody {
  reason: string;
  source: typeof RUNTIME_THREAD_FORK_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_THREAD_FORK_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_THREAD_FORK_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeThreadForkControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_thread_fork";
  nodeId: string | null;
  threadId: string;
  endpoint: string;
  body: RuntimeThreadForkControlRequestBody;
}

export interface RuntimeThreadForkControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  input?: unknown;
  reason?: string | null;
  reasonField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeThreadForkWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export interface RuntimeOperatorInterruptControlRequestBody {
  reason: string;
  source: typeof RUNTIME_OPERATOR_INTERRUPT_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_OPERATOR_INTERRUPT_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeOperatorInterruptControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_operator_interrupt";
  nodeId: string | null;
  threadId: string;
  turnId: string;
  endpoint: string;
  body: RuntimeOperatorInterruptControlRequestBody;
}

export interface RuntimeOperatorInterruptControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  input?: unknown;
  reason?: string | null;
  reasonField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeOperatorInterruptWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export interface RuntimeOperatorSteerControlRequestBody {
  guidance: string;
  source: typeof RUNTIME_OPERATOR_STEER_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_OPERATOR_STEER_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_OPERATOR_STEER_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeOperatorSteerControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_operator_steer";
  nodeId: string | null;
  threadId: string;
  turnId: string;
  endpoint: string;
  body: RuntimeOperatorSteerControlRequestBody;
}

export interface RuntimeOperatorSteerControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  input?: unknown;
  guidance?: string | null;
  guidanceField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeOperatorSteerWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export type RuntimeThreadModeMode = "plan" | "review" | "agent" | "yolo" | "custom";
export type RuntimeThreadModeApprovalMode =
  | "suggest"
  | "auto_local"
  | "never_prompt"
  | "human_required"
  | "policy_required";

export interface RuntimeThreadModeControlRequestBody {
  mode: RuntimeThreadModeMode;
  interactionMode: RuntimeThreadModeMode;
  interaction_mode: RuntimeThreadModeMode;
  approvalMode: RuntimeThreadModeApprovalMode;
  approval_mode: RuntimeThreadModeApprovalMode;
  trustProfile: string;
  trust_profile: string;
  workspaceTrustWorkflowNodeId: string;
  workspace_trust_workflow_node_id: string;
  requestWarningAcknowledgement: boolean;
  request_warning_acknowledgement: boolean;
  source: typeof RUNTIME_THREAD_MODE_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_THREAD_MODE_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_THREAD_MODE_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_THREAD_MODE_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeThreadModeControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_thread_mode";
  nodeId: string | null;
  threadId: string;
  mode: RuntimeThreadModeMode;
  approvalMode: RuntimeThreadModeApprovalMode;
  endpoint: string;
  body: RuntimeThreadModeControlRequestBody;
}

export interface RuntimeThreadModeControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  input?: unknown;
  mode?: string | null;
  modeField?: string | null;
  approvalMode?: string | null;
  approvalModeField?: string | null;
  trustProfile?: string | null;
  trustProfileField?: string | null;
  workspaceTrustWorkflowNodeId?: string | null;
  workspaceTrustWorkflowNodeIdField?: string | null;
  requestWarningAcknowledgement?: boolean | null;
  requestWarningAcknowledgementField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeThreadModeWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export interface RuntimeContextCompactControlRequestBody {
  reason: string;
  scope: string;
  turnId: string | null;
  source: typeof RUNTIME_CONTEXT_COMPACT_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_CONTEXT_COMPACT_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeContextCompactControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_context_compact";
  nodeId: string | null;
  threadId: string;
  turnId: string | null;
  endpoint: string;
  body: RuntimeContextCompactControlRequestBody;
}

export interface RuntimeContextCompactControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  input?: unknown;
  reason?: string | null;
  reasonField?: string | null;
  scope?: string | null;
  scopeField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeContextCompactWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export interface RuntimeApprovalRequestControlRequestBody {
  approvalId: string;
  approval_id: string;
  reason: string;
  scope: string;
  turnId: string | null;
  turn_id: string | null;
  pressure: number | null;
  pressureStatus: string | null;
  pressure_status: string | null;
  alertId: string | null;
  alert_id: string | null;
  sourceEventId: string | null;
  source_event_id: string | null;
  receiptRefs: string[];
  receipt_refs: string[];
  policyDecisionRefs: string[];
  policy_decision_refs: string[];
  source: typeof RUNTIME_APPROVAL_REQUEST_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_APPROVAL_REQUEST_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_APPROVAL_REQUEST_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_APPROVAL_REQUEST_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeApprovalRequestControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_APPROVAL_REQUEST_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_approval_request";
  nodeId: string | null;
  threadId: string;
  turnId: string | null;
  endpoint: string;
  body: RuntimeApprovalRequestControlRequestBody;
}

export interface RuntimeApprovalRequestControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  input?: unknown;
  approvalId?: string | null;
  approvalIdField?: string | null;
  reason?: string | null;
  reasonField?: string | null;
  scope?: string | null;
  scopeField?: string | null;
  pressure?: number | null;
  pressureField?: string | null;
  pressureStatus?: string | null;
  pressureStatusField?: string | null;
  alertId?: string | null;
  alertIdField?: string | null;
  sourceEventId?: string | null;
  sourceEventIdField?: string | null;
  receiptRefs?: string[] | null;
  receiptRefsField?: string | null;
  policyDecisionRefs?: string[] | null;
  policyDecisionRefsField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeApprovalRequestWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export interface RuntimeWorkspaceTrustAcknowledgementControlRequestBody {
  warning_id: string;
  reason: string;
  source_event_id: string | null;
  source: typeof RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_SOURCE;
  actor: string;
  workflow_graph_id: string | null;
  workflow_node_id: string;
  event_kind: typeof RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeWorkspaceTrustAcknowledgementControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_workspace_trust_acknowledgement";
  nodeId: string | null;
  threadId: string;
  warningId: string;
  endpoint: string;
  body: RuntimeWorkspaceTrustAcknowledgementControlRequestBody;
}

export interface RuntimeWorkspaceTrustAcknowledgementControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  warningId?: string | null;
  warningIdField?: string | null;
  sourceEventId?: string | null;
  sourceEventIdField?: string | null;
  input?: unknown;
  reason?: string | null;
  reasonField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeRollbackSnapshotControlRequestBody {
  source: typeof RUNTIME_ROLLBACK_SNAPSHOT_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_ROLLBACK_SNAPSHOT_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_ROLLBACK_SNAPSHOT_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_ROLLBACK_SNAPSHOT_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeRollbackSnapshotControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_ROLLBACK_SNAPSHOT_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_rollback_snapshot";
  nodeId: string | null;
  threadId: string;
  endpoint: string;
  body: RuntimeRollbackSnapshotControlRequestBody;
}

export interface RuntimeRollbackSnapshotControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  input?: unknown;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeRollbackSnapshotWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export type RuntimeRestoreGateMode = "preview" | "apply";
export type RuntimeRestoreGateConflictPolicy = "block" | "allow_override";

export interface RuntimeRestoreGateControlRequestBody {
  snapshotId: string;
  snapshot_id: string;
  mode: RuntimeRestoreGateMode;
  conflictPolicy: RuntimeRestoreGateConflictPolicy;
  conflict_policy: RuntimeRestoreGateConflictPolicy;
  approvalGranted: boolean;
  approval_granted: boolean;
  allowConflicts: boolean;
  allow_conflicts: boolean;
  source: typeof RUNTIME_RESTORE_GATE_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_RESTORE_GATE_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_RESTORE_GATE_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_RESTORE_GATE_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeRestoreGateControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_RESTORE_GATE_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_restore_gate";
  nodeId: string | null;
  threadId: string;
  snapshotId: string;
  mode: RuntimeRestoreGateMode;
  endpoint: string;
  body: RuntimeRestoreGateControlRequestBody;
}

export interface RuntimeRestoreGateControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  snapshotId?: string | null;
  snapshotIdField?: string | null;
  input?: unknown;
  mode?: string | null;
  modeField?: string | null;
  conflictPolicy?: string | null;
  conflictPolicyField?: string | null;
  approvalGranted?: boolean | null;
  approvalGrantedField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeRestoreGateWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export type RuntimeDiagnosticsRepairAction =
  | "repair_retry"
  | "restore_preview"
  | "restore_apply"
  | "operator_override";

export interface RuntimeDiagnosticsRepairControlRequestBody {
  decisionId: string;
  decision_id: string;
  action: RuntimeDiagnosticsRepairAction;
  message: string | null;
  approvalGranted: boolean;
  approval_granted: boolean;
  approved: boolean;
  confirm: boolean;
  operatorOverrideApproved: boolean;
  operator_override_approved: boolean;
  allowConflicts: boolean;
  allow_conflicts: boolean;
  overrideConflicts: boolean;
  override_conflicts: boolean;
  source: typeof RUNTIME_DIAGNOSTICS_REPAIR_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_DIAGNOSTICS_REPAIR_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_DIAGNOSTICS_REPAIR_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_DIAGNOSTICS_REPAIR_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeDiagnosticsRepairControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_diagnostics_repair";
  nodeId: string | null;
  threadId: string;
  decisionId: string;
  action: RuntimeDiagnosticsRepairAction;
  endpoint: string;
  body: RuntimeDiagnosticsRepairControlRequestBody;
}

export interface RuntimeDiagnosticsRepairControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  decisionId?: string | null;
  decisionIdField?: string | null;
  input?: unknown;
  action?: string | null;
  actionField?: string | null;
  message?: string | null;
  messageField?: string | null;
  approvalGranted?: boolean | null;
  approvalGrantedField?: string | null;
  allowConflicts?: boolean | null;
  allowConflictsField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeDiagnosticsRepairWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

type RuntimeControlTurnIdMode = "none" | "required" | "optional";

interface RuntimeControlRequestEnvelope<
  SchemaVersion extends string,
  NodeType extends string,
  Source extends string,
  EventKind extends string,
  ComponentKind extends string,
  PayloadSchemaVersion extends string,
> {
  schemaVersion: SchemaVersion;
  nodeType: NodeType;
  nodeId: string | null;
  threadId: string;
  turnId: string | null;
  endpoint: string;
  metadata: {
    source: Source;
    actor: string;
    workflowGraphId: string | null;
    workflowNodeId: string;
    eventKind: EventKind;
    componentKind: ComponentKind;
    payloadSchemaVersion: PayloadSchemaVersion;
  };
}

interface RuntimeControlRequestEnvelopeConfig<
  SchemaVersion extends string,
  NodeType extends string,
  Source extends string,
  EventKind extends string,
  ComponentKind extends string,
  PayloadSchemaVersion extends string,
> {
  schemaVersion: SchemaVersion;
  nodeType: NodeType;
  source: Source;
  eventKind: EventKind;
  componentKind: ComponentKind;
  payloadSchemaVersion: PayloadSchemaVersion;
  defaultWorkflowNodeId: string;
  defaultEndpoint: string;
  turnIdMode: RuntimeControlTurnIdMode;
}

interface RuntimeControlRequestEnvelopeInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  input?: unknown;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export function createRuntimeThreadForkControlRequest(
  params: RuntimeThreadForkControlRequestInput,
): RuntimeThreadForkControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_thread_fork",
      source: RUNTIME_THREAD_FORK_SOURCE,
      eventKind: RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_THREAD_FORK_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_THREAD_FORK_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/fork",
      turnIdMode: "none",
    },
    params,
  );
  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "Fork thread from React Flow workflow control.";

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    endpoint: envelope.endpoint,
    body: {
      reason,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeOperatorInterruptControlRequest(
  params: RuntimeOperatorInterruptControlRequestInput,
): RuntimeOperatorInterruptControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_operator_interrupt",
      source: RUNTIME_OPERATOR_INTERRUPT_SOURCE,
      eventKind: RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_OPERATOR_INTERRUPT_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/turns/{turnId}/interrupt",
      turnIdMode: "required",
    },
    params,
  );
  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "Interrupt turn from React Flow workflow control.";

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    turnId: requiredTurnId(envelope),
    endpoint: envelope.endpoint,
    body: {
      reason,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeOperatorSteerControlRequest(
  params: RuntimeOperatorSteerControlRequestInput,
): RuntimeOperatorSteerControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_operator_steer",
      source: RUNTIME_OPERATOR_STEER_SOURCE,
      eventKind: RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_OPERATOR_STEER_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_OPERATOR_STEER_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/turns/{turnId}/steer",
      turnIdMode: "required",
    },
    params,
  );
  const guidance =
    stringAtPath(params.input, params.guidanceField ?? "") ??
    cleanString(params.guidance) ??
    "Steer turn from React Flow workflow control.";

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    turnId: requiredTurnId(envelope),
    endpoint: envelope.endpoint,
    body: {
      guidance,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeThreadModeControlRequest(
  params: RuntimeThreadModeControlRequestInput,
): RuntimeThreadModeControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_thread_mode",
      source: RUNTIME_THREAD_MODE_SOURCE,
      eventKind: RUNTIME_THREAD_MODE_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_THREAD_MODE_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_THREAD_MODE_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_THREAD_MODE_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/mode",
      turnIdMode: "none",
    },
    params,
  );
  const mode = runtimeThreadModeMode(
    stringAtPath(params.input, params.modeField ?? "mode") ??
      stringAtPath(params.input, "thread_mode") ??
      cleanString(params.mode),
  );
  const approvalMode = runtimeThreadModeApprovalMode(
    stringAtPath(params.input, params.approvalModeField ?? "approvalMode") ??
      stringAtPath(params.input, "approval_mode") ??
      cleanString(params.approvalMode),
    approvalModeForRuntimeThreadMode(mode),
  );
  const trustProfile =
    stringAtPath(params.input, params.trustProfileField ?? "trustProfile") ??
    stringAtPath(params.input, "trust_profile") ??
    cleanString(params.trustProfile) ??
    "local_private";
  const workspaceTrustWorkflowNodeId =
    stringAtPath(
      params.input,
      params.workspaceTrustWorkflowNodeIdField ?? "workspaceTrustWorkflowNodeId",
    ) ??
    stringAtPath(params.input, "workspace_trust_workflow_node_id") ??
    cleanString(params.workspaceTrustWorkflowNodeId) ??
    `${envelope.metadata.workflowNodeId}.workspace-trust`;
  const requestWarningAcknowledgement =
    booleanAtPath(
      params.input,
      params.requestWarningAcknowledgementField ??
        "requestWarningAcknowledgement",
    ) ??
    booleanAtPath(params.input, "request_warning_acknowledgement") ??
    params.requestWarningAcknowledgement ??
    true;

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    mode,
    approvalMode,
    endpoint: envelope.endpoint,
    body: {
      mode,
      interactionMode: mode,
      interaction_mode: mode,
      approvalMode,
      approval_mode: approvalMode,
      trustProfile,
      trust_profile: trustProfile,
      workspaceTrustWorkflowNodeId,
      workspace_trust_workflow_node_id: workspaceTrustWorkflowNodeId,
      requestWarningAcknowledgement,
      request_warning_acknowledgement: requestWarningAcknowledgement,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeContextCompactControlRequest(
  params: RuntimeContextCompactControlRequestInput,
): RuntimeContextCompactControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_context_compact",
      source: RUNTIME_CONTEXT_COMPACT_SOURCE,
      eventKind: RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_CONTEXT_COMPACT_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/compact",
      turnIdMode: "optional",
    },
    params,
  );
  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "Compact thread context from React Flow workflow control.";
  const scope =
    stringAtPath(params.input, params.scopeField ?? "") ??
    cleanString(params.scope) ??
    "thread";

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    turnId: envelope.turnId,
    endpoint: envelope.endpoint,
    body: {
      reason,
      scope,
      turnId: envelope.turnId,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeApprovalRequestControlRequest(
  params: RuntimeApprovalRequestControlRequestInput,
): RuntimeApprovalRequestControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_APPROVAL_REQUEST_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_approval_request",
      source: RUNTIME_APPROVAL_REQUEST_SOURCE,
      eventKind: RUNTIME_APPROVAL_REQUEST_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_APPROVAL_REQUEST_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_APPROVAL_REQUEST_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_APPROVAL_REQUEST_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/approvals",
      turnIdMode: "optional",
    },
    params,
  );
  const approvalId =
    stringAtPath(params.input, params.approvalIdField ?? "approvalId") ??
    stringAtPath(params.input, "approval_id") ??
    cleanString(params.approvalId) ??
    `approval-${envelope.threadId}-${envelope.turnId ?? "thread"}`;
  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "Request operator approval from React Flow workflow control.";
  const scope =
    stringAtPath(params.input, params.scopeField ?? "") ??
    cleanString(params.scope) ??
    "thread";
  const pressure =
    numberAtPath(params.input, params.pressureField ?? "pressure") ??
    params.pressure ??
    null;
  const pressureStatus =
    stringAtPath(params.input, params.pressureStatusField ?? "pressureStatus") ??
    stringAtPath(params.input, "pressure_status") ??
    cleanString(params.pressureStatus);
  const alertId =
    stringAtPath(params.input, params.alertIdField ?? "alertId") ??
    stringAtPath(params.input, "alert_id") ??
    cleanString(params.alertId);
  const sourceEventId =
    stringAtPath(params.input, params.sourceEventIdField ?? "sourceEventId") ??
    stringAtPath(params.input, "source_event_id") ??
    cleanString(params.sourceEventId);
  const receiptRefs = uniqueStringArray([
    ...stringArrayAtPath(params.input, params.receiptRefsField ?? "receiptRefs"),
    ...stringArrayAtPath(params.input, "receipt_refs"),
    ...(params.receiptRefs ?? []),
  ]);
  const policyDecisionRefs = uniqueStringArray([
    ...stringArrayAtPath(
      params.input,
      params.policyDecisionRefsField ?? "policyDecisionRefs",
    ),
    ...stringArrayAtPath(params.input, "policy_decision_refs"),
    ...(params.policyDecisionRefs ?? []),
  ]);

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    turnId: envelope.turnId,
    endpoint: envelope.endpoint,
    body: {
      approvalId,
      approval_id: approvalId,
      reason,
      scope,
      turnId: envelope.turnId,
      turn_id: envelope.turnId,
      pressure,
      pressureStatus,
      pressure_status: pressureStatus,
      alertId,
      alert_id: alertId,
      sourceEventId,
      source_event_id: sourceEventId,
      receiptRefs,
      receipt_refs: receiptRefs,
      policyDecisionRefs,
      policy_decision_refs: policyDecisionRefs,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeWorkspaceTrustAcknowledgementControlRequest(
  params: RuntimeWorkspaceTrustAcknowledgementControlRequestInput,
): RuntimeWorkspaceTrustAcknowledgementControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error(
      "runtime_workspace_trust_acknowledgement nodes need a threadId input before dispatch.",
    );
  }
  const warningId =
    cleanString(params.warningId) ??
    stringAtPath(params.input, params.warningIdField ?? "warningId") ??
    stringAtPath(params.input, "warning_id");
  if (!warningId) {
    throw new Error(
      "runtime_workspace_trust_acknowledgement nodes need a warningId input before dispatch.",
    );
  }
  const endpointTemplate =
    cleanString(params.endpoint) ??
    "/v1/threads/{threadId}/workspace-trust/{warningId}/acknowledge";
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_WORKFLOW_NODE_ID;
  const sourceEventId =
    stringAtPath(params.input, params.sourceEventIdField ?? "sourceEventId") ??
    stringAtPath(params.input, "source_event_id") ??
    cleanString(params.sourceEventId);
  const reason =
    stringAtPath(params.input, params.reasonField ?? "reason") ??
    cleanString(params.reason) ??
    "Acknowledge workspace trust warning from React Flow run inspector.";

  return {
    schemaVersion:
      WORKFLOW_RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_workspace_trust_acknowledgement",
    nodeId: cleanString(params.nodeId),
    threadId,
    warningId,
    endpoint: endpointFromTemplate(endpointTemplate, { threadId, warningId }),
    body: {
      warning_id: warningId,
      reason,
      source_event_id: sourceEventId,
      source: RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_SOURCE,
      actor: cleanString(params.actor) ?? "operator",
      workflow_graph_id: cleanString(params.workflowGraphId),
      workflow_node_id: workflowNodeId,
      event_kind: RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_COMPONENT_KIND,
      payload_schema_version:
        RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_PAYLOAD_SCHEMA_VERSION,
    },
  };
}

export function createRuntimeRollbackSnapshotControlRequest(
  params: RuntimeRollbackSnapshotControlRequestInput,
): RuntimeRollbackSnapshotControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_ROLLBACK_SNAPSHOT_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_rollback_snapshot",
      source: RUNTIME_ROLLBACK_SNAPSHOT_SOURCE,
      eventKind: RUNTIME_ROLLBACK_SNAPSHOT_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_ROLLBACK_SNAPSHOT_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_ROLLBACK_SNAPSHOT_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_ROLLBACK_SNAPSHOT_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/snapshots",
      turnIdMode: "none",
    },
    params,
  );

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    endpoint: envelope.endpoint,
    body: {
      ...envelope.metadata,
    },
  };
}

export function createRuntimeRestoreGateControlRequest(
  params: RuntimeRestoreGateControlRequestInput,
): RuntimeRestoreGateControlRequest {
  const mode = runtimeRestoreGateMode(
    stringAtPath(params.input, params.modeField ?? "") ?? cleanString(params.mode),
  );
  const endpointTemplate =
    cleanString(params.endpoint) ??
    "/v1/threads/{threadId}/snapshots/{snapshotId}/restore-{mode}";
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_RESTORE_GATE_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_restore_gate",
      source: RUNTIME_RESTORE_GATE_SOURCE,
      eventKind: RUNTIME_RESTORE_GATE_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_RESTORE_GATE_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_RESTORE_GATE_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_RESTORE_GATE_WORKFLOW_NODE_ID,
      defaultEndpoint: endpointTemplate,
      turnIdMode: "none",
    },
    {
      ...params,
      endpoint: endpointTemplate,
    },
  );
  const snapshotId =
    cleanString(params.snapshotId) ??
    stringAtPath(params.input, params.snapshotIdField ?? "snapshotId") ??
    stringAtPath(params.input, "snapshot_id");
  if (!snapshotId) {
    throw new Error(
      "runtime_restore_gate nodes need a snapshotId input before dispatch.",
    );
  }
  const conflictPolicy = runtimeRestoreGateConflictPolicy(
    stringAtPath(params.input, params.conflictPolicyField ?? "") ??
      cleanString(params.conflictPolicy),
  );
  const approvalGranted =
    booleanAtPath(params.input, params.approvalGrantedField ?? "") ??
    params.approvalGranted ??
    false;
  const allowConflicts = conflictPolicy === "allow_override";

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    snapshotId,
    mode,
    endpoint: endpointFromTemplate(endpointTemplate, {
      threadId: envelope.threadId,
      snapshotId,
      mode,
    }),
    body: {
      snapshotId,
      snapshot_id: snapshotId,
      mode,
      conflictPolicy,
      conflict_policy: conflictPolicy,
      approvalGranted,
      approval_granted: approvalGranted,
      allowConflicts,
      allow_conflicts: allowConflicts,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeDiagnosticsRepairControlRequest(
  params: RuntimeDiagnosticsRepairControlRequestInput,
): RuntimeDiagnosticsRepairControlRequest {
  const action = runtimeDiagnosticsRepairAction(
    stringAtPath(params.input, params.actionField ?? "") ??
      cleanString(params.action),
  );
  const decisionId =
    cleanString(params.decisionId) ??
    stringAtPath(params.input, params.decisionIdField ?? "decisionId") ??
    stringAtPath(params.input, "decision_id") ??
    action;
  const endpointTemplate =
    cleanString(params.endpoint) ??
    "/v1/threads/{threadId}/diagnostics/repair-decisions/{decisionId}/execute";
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_diagnostics_repair",
      source: RUNTIME_DIAGNOSTICS_REPAIR_SOURCE,
      eventKind: RUNTIME_DIAGNOSTICS_REPAIR_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_DIAGNOSTICS_REPAIR_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_DIAGNOSTICS_REPAIR_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_DIAGNOSTICS_REPAIR_WORKFLOW_NODE_ID,
      defaultEndpoint: endpointTemplate,
      turnIdMode: "none",
    },
    {
      ...params,
      endpoint: endpointTemplate,
    },
  );
  const message =
    stringAtPath(params.input, params.messageField ?? "") ??
    cleanString(params.message);
  const approvalGranted =
    booleanAtPath(params.input, params.approvalGrantedField ?? "") ??
    params.approvalGranted ??
    false;
  const allowConflicts =
    booleanAtPath(params.input, params.allowConflictsField ?? "") ??
    params.allowConflicts ??
    false;

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    decisionId,
    action,
    endpoint: endpointFromTemplate(endpointTemplate, {
      threadId: envelope.threadId,
      decisionId,
    }),
    body: {
      decisionId,
      decision_id: decisionId,
      action,
      message,
      approvalGranted,
      approval_granted: approvalGranted,
      approved: approvalGranted,
      confirm: approvalGranted,
      operatorOverrideApproved: approvalGranted,
      operator_override_approved: approvalGranted,
      allowConflicts,
      allow_conflicts: allowConflicts,
      overrideConflicts: allowConflicts,
      override_conflicts: allowConflicts,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeThreadForkControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeThreadForkWorkflowNodeOptions = {},
): RuntimeThreadForkControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_thread_fork");
  return createRuntimeThreadForkControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeThreadForkThreadId),
    threadIdField: cleanString(logic.runtimeThreadForkThreadIdField) ?? "threadId",
    reason: cleanString(logic.runtimeThreadForkReason),
    reasonField: cleanString(logic.runtimeThreadForkReasonField),
    endpoint: cleanString(logic.runtimeThreadForkEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeThreadForkWorkflowNodeId) ??
      RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(options, logic, "runtimeThreadForkActor"),
  });
}

export function createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeOperatorInterruptWorkflowNodeOptions = {},
): RuntimeOperatorInterruptControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_operator_interrupt");
  return createRuntimeOperatorInterruptControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeOperatorInterruptThreadId),
    threadIdField:
      cleanString(logic.runtimeOperatorInterruptThreadIdField) ?? "threadId",
    turnId: cleanString(logic.runtimeOperatorInterruptTurnId),
    turnIdField: cleanString(logic.runtimeOperatorInterruptTurnIdField) ?? "turnId",
    reason: cleanString(logic.runtimeOperatorInterruptReason),
    reasonField: cleanString(logic.runtimeOperatorInterruptReasonField),
    endpoint: cleanString(logic.runtimeOperatorInterruptEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeOperatorInterruptWorkflowNodeId) ??
      RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(
      options,
      logic,
      "runtimeOperatorInterruptActor",
    ),
  });
}

export function createRuntimeOperatorSteerControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeOperatorSteerWorkflowNodeOptions = {},
): RuntimeOperatorSteerControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_operator_steer");
  return createRuntimeOperatorSteerControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeOperatorSteerThreadId),
    threadIdField: cleanString(logic.runtimeOperatorSteerThreadIdField) ?? "threadId",
    turnId: cleanString(logic.runtimeOperatorSteerTurnId),
    turnIdField: cleanString(logic.runtimeOperatorSteerTurnIdField) ?? "turnId",
    guidance: cleanString(logic.runtimeOperatorSteerGuidance),
    guidanceField: cleanString(logic.runtimeOperatorSteerGuidanceField),
    endpoint: cleanString(logic.runtimeOperatorSteerEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeOperatorSteerWorkflowNodeId) ??
      RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(options, logic, "runtimeOperatorSteerActor"),
  });
}

export function createRuntimeContextCompactControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeContextCompactWorkflowNodeOptions = {},
): RuntimeContextCompactControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_context_compact");
  return createRuntimeContextCompactControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeContextCompactThreadId),
    threadIdField: cleanString(logic.runtimeContextCompactThreadIdField) ?? "threadId",
    turnId: cleanString(logic.runtimeContextCompactTurnId),
    turnIdField: cleanString(logic.runtimeContextCompactTurnIdField) ?? "turnId",
    reason: cleanString(logic.runtimeContextCompactReason),
    reasonField: cleanString(logic.runtimeContextCompactReasonField),
    scope: cleanString(logic.runtimeContextCompactScope),
    scopeField: cleanString(logic.runtimeContextCompactScopeField),
    endpoint: cleanString(logic.runtimeContextCompactEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeContextCompactWorkflowNodeId) ??
      RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(
      options,
      logic,
      "runtimeContextCompactActor",
    ),
  });
}

export function createRuntimeThreadModeControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeThreadModeWorkflowNodeOptions = {},
): RuntimeThreadModeControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_thread_mode");
  return createRuntimeThreadModeControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeThreadModeThreadId),
    threadIdField: cleanString(logic.runtimeThreadModeThreadIdField) ?? "threadId",
    mode: cleanString(logic.runtimeThreadModeMode),
    modeField: cleanString(logic.runtimeThreadModeModeField) ?? "mode",
    approvalMode: cleanString(logic.runtimeThreadModeApprovalMode),
    approvalModeField:
      cleanString(logic.runtimeThreadModeApprovalModeField) ?? "approvalMode",
    trustProfile: cleanString(logic.runtimeThreadModeTrustProfile),
    trustProfileField:
      cleanString(logic.runtimeThreadModeTrustProfileField) ?? "trustProfile",
    workspaceTrustWorkflowNodeId: cleanString(
      logic.runtimeThreadModeWorkspaceTrustWorkflowNodeId,
    ),
    workspaceTrustWorkflowNodeIdField:
      cleanString(logic.runtimeThreadModeWorkspaceTrustWorkflowNodeIdField) ??
      "workspaceTrustWorkflowNodeId",
    requestWarningAcknowledgement:
      typeof logic.runtimeThreadModeRequestWarningAcknowledgement === "boolean"
        ? logic.runtimeThreadModeRequestWarningAcknowledgement
        : null,
    requestWarningAcknowledgementField: cleanString(
      logic.runtimeThreadModeRequestWarningAcknowledgementField,
    ),
    endpoint: cleanString(logic.runtimeThreadModeEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeThreadModeWorkflowNodeId) ??
      RUNTIME_THREAD_MODE_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(options, logic, "runtimeThreadModeActor"),
  });
}

export function createRuntimeApprovalRequestControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeApprovalRequestWorkflowNodeOptions = {},
): RuntimeApprovalRequestControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_approval_request");
  return createRuntimeApprovalRequestControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeApprovalRequestThreadId),
    threadIdField: cleanString(logic.runtimeApprovalRequestThreadIdField) ?? "threadId",
    turnId: cleanString(logic.runtimeApprovalRequestTurnId),
    turnIdField: cleanString(logic.runtimeApprovalRequestTurnIdField) ?? "turnId",
    approvalId: cleanString(logic.runtimeApprovalRequestApprovalId),
    approvalIdField:
      cleanString(logic.runtimeApprovalRequestApprovalIdField) ?? "approvalId",
    reason: cleanString(logic.runtimeApprovalRequestReason),
    reasonField: cleanString(logic.runtimeApprovalRequestReasonField) ?? "reason",
    scope: cleanString(logic.runtimeApprovalRequestScope),
    scopeField: cleanString(logic.runtimeApprovalRequestScopeField) ?? "scope",
    pressureField:
      cleanString(logic.runtimeApprovalRequestPressureField) ?? "pressure",
    pressureStatus: cleanString(logic.runtimeApprovalRequestPressureStatus),
    pressureStatusField:
      cleanString(logic.runtimeApprovalRequestPressureStatusField) ??
      "pressureStatus",
    alertId: cleanString(logic.runtimeApprovalRequestAlertId),
    alertIdField: cleanString(logic.runtimeApprovalRequestAlertIdField) ?? "alertId",
    sourceEventId: cleanString(logic.runtimeApprovalRequestSourceEventId),
    sourceEventIdField:
      cleanString(logic.runtimeApprovalRequestSourceEventIdField) ??
      "sourceEventId",
    receiptRefsField:
      cleanString(logic.runtimeApprovalRequestReceiptRefsField) ?? "receiptRefs",
    policyDecisionRefsField:
      cleanString(logic.runtimeApprovalRequestPolicyDecisionRefsField) ??
      "policyDecisionRefs",
    endpoint: cleanString(logic.runtimeApprovalRequestEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeApprovalRequestWorkflowNodeId) ??
      RUNTIME_APPROVAL_REQUEST_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(
      options,
      logic,
      "runtimeApprovalRequestActor",
    ),
  });
}

export function createRuntimeRollbackSnapshotControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeRollbackSnapshotWorkflowNodeOptions = {},
): RuntimeRollbackSnapshotControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_rollback_snapshot");
  return createRuntimeRollbackSnapshotControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeRollbackSnapshotThreadId),
    threadIdField:
      cleanString(logic.runtimeRollbackSnapshotThreadIdField) ?? "threadId",
    endpoint: cleanString(logic.runtimeRollbackSnapshotEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeRollbackSnapshotWorkflowNodeId) ??
      RUNTIME_ROLLBACK_SNAPSHOT_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(
      options,
      logic,
      "runtimeRollbackSnapshotActor",
    ),
  });
}

export function createRuntimeRestoreGateControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeRestoreGateWorkflowNodeOptions = {},
): RuntimeRestoreGateControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_restore_gate");
  return createRuntimeRestoreGateControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeRestoreGateThreadId),
    threadIdField: cleanString(logic.runtimeRestoreGateThreadIdField) ?? "threadId",
    snapshotId: cleanString(logic.runtimeRestoreGateSnapshotId),
    snapshotIdField:
      cleanString(logic.runtimeRestoreGateSnapshotIdField) ?? "snapshotId",
    mode: cleanString(logic.runtimeRestoreGateMode),
    modeField: cleanString(logic.runtimeRestoreGateModeField),
    conflictPolicy: cleanString(logic.runtimeRestoreGateConflictPolicy),
    conflictPolicyField: cleanString(logic.runtimeRestoreGateConflictPolicyField),
    approvalGranted:
      typeof logic.runtimeRestoreGateApprovalGranted === "boolean"
        ? logic.runtimeRestoreGateApprovalGranted
        : null,
    approvalGrantedField: cleanString(logic.runtimeRestoreGateApprovalGrantedField),
    endpoint: cleanString(logic.runtimeRestoreGateEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeRestoreGateWorkflowNodeId) ??
      RUNTIME_RESTORE_GATE_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(options, logic, "runtimeRestoreGateActor"),
  });
}

export function createRuntimeDiagnosticsRepairControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeDiagnosticsRepairWorkflowNodeOptions = {},
): RuntimeDiagnosticsRepairControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_diagnostics_repair");
  return createRuntimeDiagnosticsRepairControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeDiagnosticsRepairThreadId),
    threadIdField:
      cleanString(logic.runtimeDiagnosticsRepairThreadIdField) ?? "threadId",
    decisionId: cleanString(logic.runtimeDiagnosticsRepairDecisionId),
    decisionIdField:
      cleanString(logic.runtimeDiagnosticsRepairDecisionIdField) ?? "decisionId",
    action: cleanString(logic.runtimeDiagnosticsRepairAction),
    actionField: cleanString(logic.runtimeDiagnosticsRepairActionField),
    message: cleanString(logic.runtimeDiagnosticsRepairMessage),
    messageField: cleanString(logic.runtimeDiagnosticsRepairMessageField),
    approvalGranted:
      typeof logic.runtimeDiagnosticsRepairApprovalGranted === "boolean"
        ? logic.runtimeDiagnosticsRepairApprovalGranted
        : null,
    approvalGrantedField: cleanString(
      logic.runtimeDiagnosticsRepairApprovalGrantedField,
    ),
    allowConflicts:
      typeof logic.runtimeDiagnosticsRepairAllowConflicts === "boolean"
        ? logic.runtimeDiagnosticsRepairAllowConflicts
        : null,
    allowConflictsField: cleanString(
      logic.runtimeDiagnosticsRepairAllowConflictsField,
    ),
    endpoint: cleanString(logic.runtimeDiagnosticsRepairEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeDiagnosticsRepairWorkflowNodeId) ??
      RUNTIME_DIAGNOSTICS_REPAIR_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(
      options,
      logic,
      "runtimeDiagnosticsRepairActor",
    ),
  });
}

function runtimeControlWorkflowNodeLogic(
  node: Pick<Node, "type" | "config">,
  expectedType: string,
): NodeLogic {
  if (node.type !== expectedType) {
    throw new Error(`Expected ${expectedType} node, received ${node.type}.`);
  }
  return node.config?.logic ?? {};
}

function runtimeControlWorkflowActor(
  options: { actor?: string | null },
  logic: NodeLogic,
  actorKey: keyof NodeLogic,
): string {
  return cleanString(options.actor) ?? cleanString(logic[actorKey]) ?? "operator";
}

function createRuntimeControlRequestEnvelope<
  SchemaVersion extends string,
  NodeType extends string,
  Source extends string,
  EventKind extends string,
  ComponentKind extends string,
  PayloadSchemaVersion extends string,
>(
  config: RuntimeControlRequestEnvelopeConfig<
    SchemaVersion,
    NodeType,
    Source,
    EventKind,
    ComponentKind,
    PayloadSchemaVersion
  >,
  params: RuntimeControlRequestEnvelopeInput,
): RuntimeControlRequestEnvelope<
  SchemaVersion,
  NodeType,
  Source,
  EventKind,
  ComponentKind,
  PayloadSchemaVersion
> {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error(`${config.nodeType} nodes need a threadId input before dispatch.`);
  }

  const turnId =
    config.turnIdMode === "none"
      ? null
      : cleanString(params.turnId) ??
        stringAtPath(params.input, params.turnIdField ?? "turnId") ??
        stringAtPath(params.input, "turn_id");
  if (config.turnIdMode === "required" && !turnId) {
    throw new Error(`${config.nodeType} nodes need a turnId input before dispatch.`);
  }

  const endpointTemplate = cleanString(params.endpoint) ?? config.defaultEndpoint;
  const endpointValues: Record<string, string> = { threadId };
  if (config.turnIdMode !== "none") {
    endpointValues.turnId = turnId ?? "";
  }

  return {
    schemaVersion: config.schemaVersion,
    nodeType: config.nodeType,
    nodeId: cleanString(params.nodeId),
    threadId,
    turnId,
    endpoint: endpointFromTemplate(endpointTemplate, endpointValues),
    metadata: {
      source: config.source,
      actor: cleanString(params.actor) ?? "operator",
      workflowGraphId: cleanString(params.workflowGraphId),
      workflowNodeId:
        cleanString(params.workflowNodeId) ?? config.defaultWorkflowNodeId,
      eventKind: config.eventKind,
      componentKind: config.componentKind,
      payloadSchemaVersion: config.payloadSchemaVersion,
    },
  };
}

function requiredTurnId(
  envelope: RuntimeControlRequestEnvelope<
    string,
    string,
    string,
    string,
    string,
    string
  >,
): string {
  if (!envelope.turnId) {
    throw new Error(`${envelope.nodeType} nodes need a turnId input before dispatch.`);
  }
  return envelope.turnId;
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : null;
}

function stringAtPath(value: unknown, path: string | null | undefined): string | null {
  const normalizedPath = cleanString(path);
  if (!normalizedPath) return null;
  const found = valueAtPath(value, normalizedPath);
  return cleanString(found);
}

function numberAtPath(value: unknown, path: string | null | undefined): number | null {
  const normalizedPath = cleanString(path);
  if (!normalizedPath) return null;
  const found = valueAtPath(value, normalizedPath);
  return typeof found === "number" && Number.isFinite(found) ? found : null;
}

function stringArrayAtPath(
  value: unknown,
  path: string | null | undefined,
): string[] {
  const normalizedPath = cleanString(path);
  if (!normalizedPath) return [];
  return uniqueStringArray(valueAtPath(value, normalizedPath));
}

function uniqueStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(value.map((item) => cleanString(item)).filter(Boolean) as string[]),
  );
}

function booleanAtPath(
  value: unknown,
  path: string | null | undefined,
): boolean | null {
  const normalizedPath = cleanString(path);
  if (!normalizedPath) return null;
  const found = valueAtPath(value, normalizedPath);
  return typeof found === "boolean" ? found : null;
}

function runtimeRestoreGateMode(
  value: string | null,
): RuntimeRestoreGateMode {
  return value === "apply" ? "apply" : "preview";
}

function runtimeRestoreGateConflictPolicy(
  value: string | null,
): RuntimeRestoreGateConflictPolicy {
  return value === "allow_override" ? "allow_override" : "block";
}

function runtimeDiagnosticsRepairAction(
  value: string | null,
): RuntimeDiagnosticsRepairAction {
  const normalized = (value ?? "repair_retry")
    .trim()
    .toLowerCase()
    .replace(/[-.]/g, "_");
  switch (normalized) {
    case "restore_preview":
    case "preview":
    case "preview_restore":
      return "restore_preview";
    case "restore_apply":
    case "apply":
    case "apply_restore":
      return "restore_apply";
    case "operator_override":
    case "override":
      return "operator_override";
    default:
      return "repair_retry";
  }
}

function runtimeThreadModeMode(value: string | null): RuntimeThreadModeMode {
  const normalized = (value ?? "agent").trim().toLowerCase().replace(/[-.]/g, "_");
  switch (normalized) {
    case "plan":
    case "planning":
    case "read_only":
    case "readonly":
      return "plan";
    case "review":
    case "review_mode":
    case "human_review":
    case "approval_review":
      return "review";
    case "yolo":
    case "auto":
    case "auto_local":
    case "never_prompt":
      return "yolo";
    case "custom":
    case "dry_run":
    case "handoff":
    case "learn":
      return "custom";
    default:
      return "agent";
  }
}

function runtimeThreadModeApprovalMode(
  value: string | null,
  fallback: RuntimeThreadModeApprovalMode,
): RuntimeThreadModeApprovalMode {
  const normalized = value?.trim().toLowerCase().replace(/[-.]/g, "_");
  switch (normalized) {
    case "auto_local":
    case "never_prompt":
    case "human_required":
    case "policy_required":
      return normalized;
    case "suggest":
      return "suggest";
    default:
      return fallback;
  }
}

function approvalModeForRuntimeThreadMode(
  mode: RuntimeThreadModeMode,
): RuntimeThreadModeApprovalMode {
  switch (mode) {
    case "plan":
    case "review":
      return "human_required";
    case "yolo":
      return "never_prompt";
    default:
      return "suggest";
  }
}

function endpointFromTemplate(
  template: string,
  values: Record<string, string>,
): string {
  return Object.entries(values).reduce(
    (current, [key, value]) =>
      current.replace(new RegExp(`\\{${key}\\}`, "g"), encodeURIComponent(value)),
    template,
  );
}

function valueAtPath(value: unknown, path: string): unknown {
  let current = value;
  for (const segment of path.split(".").filter(Boolean)) {
    if (current === null || current === undefined) return undefined;
    if (segment === "[]") {
      current = Array.isArray(current) ? current[0] : undefined;
      continue;
    }
    if (typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}
