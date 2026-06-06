import assert from "node:assert/strict";
import test from "node:test";
import { makeWorkflowNode } from "./workflow-node-registry";
import {
  RUNTIME_APPROVAL_REQUEST_COMPONENT_KIND,
  RUNTIME_APPROVAL_REQUEST_SOURCE_EVENT_KIND,
  RUNTIME_APPROVAL_REQUEST_WORKFLOW_NODE_ID,
  RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND,
  RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND,
  RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
  RUNTIME_DIAGNOSTICS_REPAIR_COMPONENT_KIND,
  RUNTIME_DIAGNOSTICS_REPAIR_SOURCE_EVENT_KIND,
  RUNTIME_DIAGNOSTICS_REPAIR_WORKFLOW_NODE_ID,
  RUNTIME_RESTORE_GATE_COMPONENT_KIND,
  RUNTIME_RESTORE_GATE_SOURCE_EVENT_KIND,
  RUNTIME_RESTORE_GATE_WORKFLOW_NODE_ID,
  RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND,
  RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND,
  RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID,
  RUNTIME_OPERATOR_STEER_COMPONENT_KIND,
  RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND,
  RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID,
  RUNTIME_THREAD_MODE_COMPONENT_KIND,
  RUNTIME_THREAD_MODE_SOURCE_EVENT_KIND,
  RUNTIME_THREAD_MODE_WORKFLOW_NODE_ID,
  RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_COMPONENT_KIND,
  RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_SOURCE_EVENT_KIND,
  RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_WORKFLOW_NODE_ID,
  RUNTIME_ROLLBACK_SNAPSHOT_COMPONENT_KIND,
  RUNTIME_ROLLBACK_SNAPSHOT_SOURCE_EVENT_KIND,
  RUNTIME_ROLLBACK_SNAPSHOT_WORKFLOW_NODE_ID,
  RUNTIME_THREAD_FORK_COMPONENT_KIND,
  RUNTIME_THREAD_FORK_SOURCE,
  RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND,
  RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID,
  WORKFLOW_RUNTIME_APPROVAL_REQUEST_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_RESTORE_GATE_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_ROLLBACK_SNAPSHOT_CONTROL_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION,
  createRuntimeApprovalRequestControlRequestFromWorkflowNode,
  createRuntimeContextCompactControlRequestFromWorkflowNode,
  createRuntimeDiagnosticsRepairControlRequestFromWorkflowNode,
  createRuntimeOperatorInterruptControlRequestFromWorkflowNode,
  createRuntimeOperatorSteerControlRequestFromWorkflowNode,
  createRuntimeThreadModeControlRequestFromWorkflowNode,
  createRuntimeWorkspaceTrustAcknowledgementControlRequest,
  createRuntimeRestoreGateControlRequestFromWorkflowNode,
  createRuntimeRollbackSnapshotControlRequestFromWorkflowNode,
  createRuntimeThreadForkControlRequestFromWorkflowNode,
} from "./workflow-runtime-control-nodes";

test("runtime_thread_fork workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "fork-control",
    "runtime_thread_fork",
    "Fork control",
    100,
    120,
  );
  const request = createRuntimeThreadForkControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      reason: "branch for live React Flow validation",
    },
    { workflowGraphId: "workflow.react-flow.thread-fork-proof" },
  );

  assert.equal(request.schemaVersion, WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION);
  assert.equal(request.nodeType, "runtime_thread_fork");
  assert.equal(request.nodeId, "fork-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.endpoint, "/v1/threads/thread-react-flow-1/fork");
  assert.equal(request.body.reason, "branch for live React Flow validation");
  assert.equal(request.body.source, RUNTIME_THREAD_FORK_SOURCE);
  assert.equal(request.body.actor, "operator");
  assert.equal(request.body.workflowGraphId, "workflow.react-flow.thread-fork-proof");
  assert.equal(request.body.workflowNodeId, RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_THREAD_FORK_COMPONENT_KIND);
});

test("runtime_thread_fork helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "fork-control-configured",
    "runtime_thread_fork",
    "Fork control",
    100,
    120,
    {
      runtimeThreadForkEndpoint: "/runtime/{threadId}/fork",
      runtimeThreadForkThreadIdField: "runtime.threadId",
      runtimeThreadForkReasonField: "operator.reason",
      runtimeThreadForkWorkflowNodeId: "runtime.thread-fork",
      runtimeThreadForkActor: "workflow-author",
    },
  );
  const request = createRuntimeThreadForkControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space" },
      operator: { reason: "split the live branch" },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.endpoint, "/runtime/thread%20with%20space/fork");
  assert.equal(request.body.reason, "split the live branch");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});

test("runtime control workflow helpers share graph identity envelope metadata", () => {
  const graphId = "workflow.react-flow.shared-control-envelope";
  const actor = "workflow-operator";
  const requests = [
    createRuntimeThreadForkControlRequestFromWorkflowNode(
      makeWorkflowNode("fork-shared", "runtime_thread_fork", "Fork", 0, 0),
      { threadId: "thread-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
      makeWorkflowNode(
        "interrupt-shared",
        "runtime_operator_interrupt",
        "Interrupt",
        0,
        0,
      ),
      { threadId: "thread-shared", turnId: "turn-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeOperatorSteerControlRequestFromWorkflowNode(
      makeWorkflowNode("steer-shared", "runtime_operator_steer", "Steer", 0, 0),
      { threadId: "thread-shared", turnId: "turn-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeThreadModeControlRequestFromWorkflowNode(
      makeWorkflowNode("mode-shared", "runtime_thread_mode", "Mode", 0, 0),
      { threadId: "thread-shared", mode: "review" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeContextCompactControlRequestFromWorkflowNode(
      makeWorkflowNode(
        "compact-shared",
        "runtime_context_compact",
        "Compact",
        0,
        0,
      ),
      { threadId: "thread-shared", turnId: "turn-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeApprovalRequestControlRequestFromWorkflowNode(
      makeWorkflowNode(
        "approval-request-shared",
        "runtime_approval_request",
        "Approval",
        0,
        0,
      ),
      { threadId: "thread-shared", turnId: "turn-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeRollbackSnapshotControlRequestFromWorkflowNode(
      makeWorkflowNode(
        "snapshot-shared",
        "runtime_rollback_snapshot",
        "Snapshot",
        0,
        0,
      ),
      { threadId: "thread-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeRestoreGateControlRequestFromWorkflowNode(
      makeWorkflowNode("restore-shared", "runtime_restore_gate", "Restore", 0, 0),
      { threadId: "thread-shared", snapshotId: "snapshot-shared" },
      { workflowGraphId: graphId, actor },
    ),
    createRuntimeDiagnosticsRepairControlRequestFromWorkflowNode(
      makeWorkflowNode(
        "repair-shared",
        "runtime_diagnostics_repair",
        "Repair",
        0,
        0,
      ),
      {
        threadId: "thread-shared",
        decisionId: "repair_retry",
        action: "repair_retry",
      },
      { workflowGraphId: graphId, actor },
    ),
  ];

  assert.deepEqual(
    requests.map((request) => ({
      source: request.body.source,
      actor: request.body.actor,
      graphId: request.body.workflowGraphId,
      nodeId: request.body.workflowNodeId,
      threadId: request.threadId,
    })),
    [
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_THREAD_MODE_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_APPROVAL_REQUEST_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_ROLLBACK_SNAPSHOT_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_RESTORE_GATE_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
      {
        source: "react_flow",
        actor,
        graphId,
        nodeId: RUNTIME_DIAGNOSTICS_REPAIR_WORKFLOW_NODE_ID,
        threadId: "thread-shared",
      },
    ],
  );
});

test("runtime_thread_mode workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "mode-control",
    "runtime_thread_mode",
    "Mode control",
    100,
    120,
  );
  const request = createRuntimeThreadModeControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      mode: "yolo",
      approvalMode: "never_prompt",
      trustProfile: "canvas_claimed_trusted",
    },
    { workflowGraphId: "workflow.react-flow.thread-mode-proof" },
  );

  assert.equal(request.schemaVersion, WORKFLOW_RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION);
  assert.equal(request.nodeType, "runtime_thread_mode");
  assert.equal(request.nodeId, "mode-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.mode, "yolo");
  assert.equal(request.approvalMode, "never_prompt");
  assert.equal(request.endpoint, "/v1/threads/thread-react-flow-1/mode");
  assert.equal(request.body.mode, "yolo");
  assert.equal(request.body.approval_mode, "never_prompt");
  assert.equal(request.body.trust_profile, "canvas_claimed_trusted");
  assert.equal(
    request.body.workspace_trust_workflow_node_id,
    "runtime.thread-mode.workspace-trust",
  );
  assert.equal(request.body.request_warning_acknowledgement, true);
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.workflowGraphId, "workflow.react-flow.thread-mode-proof");
  assert.equal(request.body.workflowNodeId, RUNTIME_THREAD_MODE_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_THREAD_MODE_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_THREAD_MODE_COMPONENT_KIND);
});

test("runtime_thread_mode helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "mode-control-configured",
    "runtime_thread_mode",
    "Mode control",
    100,
    120,
    {
      runtimeThreadModeEndpoint: "/runtime/{threadId}/mode",
      runtimeThreadModeThreadIdField: "runtime.threadId",
      runtimeThreadModeModeField: "operator.mode",
      runtimeThreadModeApprovalModeField: "operator.approval",
      runtimeThreadModeTrustProfile: "canvas_local_override",
      runtimeThreadModeWorkspaceTrustWorkflowNodeId:
        "runtime.mode.trust-warning",
      runtimeThreadModeRequestWarningAcknowledgement: false,
      runtimeThreadModeWorkflowNodeId: "runtime.mode-control",
      runtimeThreadModeActor: "workflow-author",
    },
  );
  const request = createRuntimeThreadModeControlRequestFromWorkflowNode(node, {
    runtime: { threadId: "thread with space" },
    operator: { mode: "review", approval: "policy_required" },
  });

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.endpoint, "/runtime/thread%20with%20space/mode");
  assert.equal(request.body.mode, "review");
  assert.equal(request.body.approvalMode, "policy_required");
  assert.equal(request.body.trustProfile, "canvas_local_override");
  assert.equal(
    request.body.workspaceTrustWorkflowNodeId,
    "runtime.mode.trust-warning",
  );
  assert.equal(request.body.requestWarningAcknowledgement, false);
  assert.equal(request.body.workflowNodeId, "runtime.mode-control");
  assert.equal(request.body.actor, "workflow-author");
});

test("workspace trust acknowledgement builds a daemon receipt request", () => {
  const request = createRuntimeWorkspaceTrustAcknowledgementControlRequest({
    nodeId: "workspace-trust-action",
    threadId: "thread-react-flow-1",
    warningId: "workspace_trust_123",
    sourceEventId: "event-workspace-trust",
    reason: "operator reviewed dirty workspace warning",
    endpoint: "/v1/threads/{threadId}/workspace-trust/{warningId}/acknowledge",
    workflowGraphId: "workflow.react-flow.thread-mode-proof",
    workflowNodeId: "runtime.thread-mode.workspace-trust",
  });

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_workspace_trust_acknowledgement");
  assert.equal(request.endpoint, "/v1/threads/thread-react-flow-1/workspace-trust/workspace_trust_123/acknowledge");
  assert.equal(request.body.warning_id, "workspace_trust_123");
  assert.equal(request.body.source_event_id, "event-workspace-trust");
  assert.equal(request.body.reason, "operator reviewed dirty workspace warning");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.workflow_graph_id, "workflow.react-flow.thread-mode-proof");
  assert.equal(request.body.workflow_node_id, "runtime.thread-mode.workspace-trust");
  assert.equal(
    request.body.event_kind,
    RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_SOURCE_EVENT_KIND,
  );
  assert.equal(
    request.body.component_kind,
    RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_COMPONENT_KIND,
  );
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "warningId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "sourceEventId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "workflowGraphId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "workflowNodeId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "eventKind"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "componentKind"), false);
  assert.equal(
    RUNTIME_WORKSPACE_TRUST_ACKNOWLEDGEMENT_WORKFLOW_NODE_ID,
    "runtime.workspace-trust",
  );
});

test("runtime_context_compact workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "compact-control",
    "runtime_context_compact",
    "Compact control",
    100,
    120,
  );
  const request = createRuntimeContextCompactControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      turnId: "turn-react-flow-1",
      reason: "reduce stale context",
      scope: "thread",
    },
    { workflowGraphId: "workflow.react-flow.context-compact-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_context_compact");
  assert.equal(request.nodeId, "compact-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.turnId, "turn-react-flow-1");
  assert.equal(request.endpoint, "/v1/threads/thread-react-flow-1/compact");
  assert.equal(request.body.reason, "reduce stale context");
  assert.equal(request.body.scope, "thread");
  assert.equal(request.body.turnId, "turn-react-flow-1");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.context-compact-proof",
  );
  assert.equal(request.body.workflowNodeId, RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND);
});

test("runtime_context_compact helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "compact-control-configured",
    "runtime_context_compact",
    "Compact control",
    100,
    120,
    {
      runtimeContextCompactEndpoint: "/runtime/{threadId}/compact/{turnId}",
      runtimeContextCompactThreadIdField: "runtime.threadId",
      runtimeContextCompactTurnIdField: "runtime.turnId",
      runtimeContextCompactReasonField: "operator.reason",
      runtimeContextCompactScopeField: "operator.scope",
      runtimeContextCompactWorkflowNodeId: "runtime.context-compact",
      runtimeContextCompactActor: "workflow-author",
    },
  );
  const request = createRuntimeContextCompactControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space", turnId: "turn/with/slash" },
      operator: { reason: "summarize stale context", scope: "thread" },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.turnId, "turn/with/slash");
  assert.equal(
    request.endpoint,
    "/runtime/thread%20with%20space/compact/turn%2Fwith%2Fslash",
  );
  assert.equal(request.body.reason, "summarize stale context");
  assert.equal(request.body.scope, "thread");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});

test("runtime_approval_request workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "approval-request-control",
    "runtime_approval_request",
    "Approval request",
    100,
    120,
  );
  const request = createRuntimeApprovalRequestControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      turnId: "turn-react-flow-1",
      approvalId: "approval-context-pressure",
      reason: "continue through high context pressure",
      scope: "subagent_aggregate",
      pressure: 0.91,
      pressureStatus: "high",
      alertId: "event-context-alert",
      sourceEventId: "event-context-pressure",
      receiptRefs: ["receipt-context-alert"],
      policyDecisionRefs: ["policy-context-alert-compact"],
    },
    { workflowGraphId: "workflow.react-flow.approval-request-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_APPROVAL_REQUEST_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_approval_request");
  assert.equal(request.nodeId, "approval-request-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.turnId, "turn-react-flow-1");
  assert.equal(request.endpoint, "/v1/threads/thread-react-flow-1/approvals");
  assert.equal(request.body.approvalId, "approval-context-pressure");
  assert.equal(request.body.approval_id, "approval-context-pressure");
  assert.equal(request.body.reason, "continue through high context pressure");
  assert.equal(request.body.scope, "subagent_aggregate");
  assert.equal(request.body.turnId, "turn-react-flow-1");
  assert.equal(request.body.pressure, 0.91);
  assert.equal(request.body.pressureStatus, "high");
  assert.equal(request.body.alertId, "event-context-alert");
  assert.equal(request.body.sourceEventId, "event-context-pressure");
  assert.deepEqual(request.body.receiptRefs, ["receipt-context-alert"]);
  assert.deepEqual(request.body.policyDecisionRefs, ["policy-context-alert-compact"]);
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.approval-request-proof",
  );
  assert.equal(request.body.workflowNodeId, RUNTIME_APPROVAL_REQUEST_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_APPROVAL_REQUEST_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_APPROVAL_REQUEST_COMPONENT_KIND);
});

test("runtime_approval_request helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "approval-request-configured",
    "runtime_approval_request",
    "Approval request",
    100,
    120,
    {
      runtimeApprovalRequestEndpoint: "/runtime/{threadId}/approval",
      runtimeApprovalRequestThreadIdField: "runtime.threadId",
      runtimeApprovalRequestTurnIdField: "runtime.turnId",
      runtimeApprovalRequestApprovalIdField: "approval.id",
      runtimeApprovalRequestReasonField: "approval.reason",
      runtimeApprovalRequestScopeField: "approval.scope",
      runtimeApprovalRequestPressureField: "approval.pressure",
      runtimeApprovalRequestPressureStatusField: "approval.pressureStatus",
      runtimeApprovalRequestAlertIdField: "approval.alertId",
      runtimeApprovalRequestSourceEventIdField: "approval.sourceEventId",
      runtimeApprovalRequestWorkflowNodeId: "runtime.approval.context-pressure",
      runtimeApprovalRequestActor: "workflow-author",
    },
  );
  const request = createRuntimeApprovalRequestControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space", turnId: "turn/with/slash" },
      approval: {
        id: "approval configured",
        reason: "manual continuation gate",
        scope: "turn",
        pressure: 0.88,
        pressureStatus: "high",
        alertId: "alert-configured",
        sourceEventId: "usage-delta-configured",
      },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.turnId, "turn/with/slash");
  assert.equal(request.endpoint, "/runtime/thread%20with%20space/approval");
  assert.equal(request.body.approvalId, "approval configured");
  assert.equal(request.body.reason, "manual continuation gate");
  assert.equal(request.body.scope, "turn");
  assert.equal(request.body.pressure, 0.88);
  assert.equal(request.body.pressureStatus, "high");
  assert.equal(request.body.alertId, "alert-configured");
  assert.equal(request.body.sourceEventId, "usage-delta-configured");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});

test("runtime_rollback_snapshot workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "snapshot-control",
    "runtime_rollback_snapshot",
    "Snapshot control",
    100,
    120,
  );
  const request = createRuntimeRollbackSnapshotControlRequestFromWorkflowNode(
    node,
    { threadId: "thread-react-flow-1" },
    { workflowGraphId: "workflow.react-flow.rollback-snapshot-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_ROLLBACK_SNAPSHOT_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_rollback_snapshot");
  assert.equal(request.nodeId, "snapshot-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.endpoint, "/v1/threads/thread-react-flow-1/snapshots");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.rollback-snapshot-proof",
  );
  assert.equal(
    request.body.workflowNodeId,
    RUNTIME_ROLLBACK_SNAPSHOT_WORKFLOW_NODE_ID,
  );
  assert.equal(
    request.body.eventKind,
    RUNTIME_ROLLBACK_SNAPSHOT_SOURCE_EVENT_KIND,
  );
  assert.equal(request.body.componentKind, RUNTIME_ROLLBACK_SNAPSHOT_COMPONENT_KIND);
});

test("runtime_rollback_snapshot helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "snapshot-control-configured",
    "runtime_rollback_snapshot",
    "Snapshot control",
    100,
    120,
    {
      runtimeRollbackSnapshotEndpoint: "/runtime/{threadId}/snapshots",
      runtimeRollbackSnapshotThreadIdField: "runtime.threadId",
      runtimeRollbackSnapshotWorkflowNodeId: "runtime.rollback-snapshot",
      runtimeRollbackSnapshotActor: "workflow-author",
    },
  );
  const request = createRuntimeRollbackSnapshotControlRequestFromWorkflowNode(
    node,
    { runtime: { threadId: "thread with space" } },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.endpoint, "/runtime/thread%20with%20space/snapshots");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});

test("runtime_restore_gate workflow node builds a React Flow preview daemon request", () => {
  const node = makeWorkflowNode(
    "restore-control",
    "runtime_restore_gate",
    "Restore control",
    100,
    120,
  );
  const request = createRuntimeRestoreGateControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      snapshotId: "snapshot-react-flow-1",
    },
    { workflowGraphId: "workflow.react-flow.restore-gate-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_RESTORE_GATE_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_restore_gate");
  assert.equal(request.nodeId, "restore-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.snapshotId, "snapshot-react-flow-1");
  assert.equal(request.mode, "preview");
  assert.equal(
    request.endpoint,
    "/v1/threads/thread-react-flow-1/snapshots/snapshot-react-flow-1/restore-preview",
  );
  assert.equal(request.body.snapshot_id, "snapshot-react-flow-1");
  assert.equal(request.body.conflictPolicy, "block");
  assert.equal(request.body.approvalGranted, false);
  assert.equal(request.body.allowConflicts, false);
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.restore-gate-proof",
  );
  assert.equal(request.body.workflowNodeId, RUNTIME_RESTORE_GATE_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_RESTORE_GATE_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_RESTORE_GATE_COMPONENT_KIND);
});

test("runtime_restore_gate helper supports apply mode, approval, and configurable fields", () => {
  const node = makeWorkflowNode(
    "restore-control-configured",
    "runtime_restore_gate",
    "Restore control",
    100,
    120,
    {
      runtimeRestoreGateEndpoint:
        "/runtime/{threadId}/snapshots/{snapshotId}/{mode}",
      runtimeRestoreGateThreadIdField: "runtime.threadId",
      runtimeRestoreGateSnapshotIdField: "runtime.snapshot.id",
      runtimeRestoreGateModeField: "restore.mode",
      runtimeRestoreGateConflictPolicyField: "restore.conflictPolicy",
      runtimeRestoreGateApprovalGrantedField: "restore.approved",
      runtimeRestoreGateWorkflowNodeId: "runtime.restore-gate",
      runtimeRestoreGateActor: "workflow-author",
    },
  );
  const request = createRuntimeRestoreGateControlRequestFromWorkflowNode(
    node,
    {
      runtime: {
        threadId: "thread with space",
        snapshot: { id: "snapshot/with/slash" },
      },
      restore: {
        mode: "apply",
        conflictPolicy: "allow_override",
        approved: true,
      },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.snapshotId, "snapshot/with/slash");
  assert.equal(request.mode, "apply");
  assert.equal(
    request.endpoint,
    "/runtime/thread%20with%20space/snapshots/snapshot%2Fwith%2Fslash/apply",
  );
  assert.equal(request.body.conflict_policy, "allow_override");
  assert.equal(request.body.approval_granted, true);
  assert.equal(request.body.allow_conflicts, true);
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});

test("runtime_diagnostics_repair workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "repair-control",
    "runtime_diagnostics_repair",
    "Repair control",
    100,
    120,
  );
  const request = createRuntimeDiagnosticsRepairControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      decisionId: "restore_preview",
      action: "restore_preview",
      message: "Preview rollback from diagnostics repair.",
    },
    { workflowGraphId: "workflow.react-flow.diagnostics-repair-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_diagnostics_repair");
  assert.equal(request.nodeId, "repair-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.decisionId, "restore_preview");
  assert.equal(request.action, "restore_preview");
  assert.equal(
    request.endpoint,
    "/v1/threads/thread-react-flow-1/diagnostics/repair-decisions/restore_preview/execute",
  );
  assert.equal(request.body.decision_id, "restore_preview");
  assert.equal(request.body.action, "restore_preview");
  assert.equal(request.body.message, "Preview rollback from diagnostics repair.");
  assert.equal(request.body.approvalGranted, false);
  assert.equal(request.body.operatorOverrideApproved, false);
  assert.equal(request.body.allowConflicts, false);
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.diagnostics-repair-proof",
  );
  assert.equal(
    request.body.workflowNodeId,
    RUNTIME_DIAGNOSTICS_REPAIR_WORKFLOW_NODE_ID,
  );
  assert.equal(
    request.body.eventKind,
    RUNTIME_DIAGNOSTICS_REPAIR_SOURCE_EVENT_KIND,
  );
  assert.equal(
    request.body.componentKind,
    RUNTIME_DIAGNOSTICS_REPAIR_COMPONENT_KIND,
  );
});

test("runtime_diagnostics_repair helper supports approval, conflicts, and configurable fields", () => {
  const node = makeWorkflowNode(
    "repair-control-configured",
    "runtime_diagnostics_repair",
    "Repair control",
    100,
    120,
    {
      runtimeDiagnosticsRepairEndpoint:
        "/runtime/{threadId}/diagnostics/{decisionId}/execute",
      runtimeDiagnosticsRepairThreadIdField: "runtime.threadId",
      runtimeDiagnosticsRepairDecisionIdField: "diagnostics.decision.id",
      runtimeDiagnosticsRepairActionField: "diagnostics.decision.action",
      runtimeDiagnosticsRepairMessageField: "diagnostics.message",
      runtimeDiagnosticsRepairApprovalGrantedField: "diagnostics.approved",
      runtimeDiagnosticsRepairAllowConflictsField: "diagnostics.allowConflicts",
      runtimeDiagnosticsRepairWorkflowNodeId: "runtime.diagnostics-repair",
      runtimeDiagnosticsRepairActor: "workflow-author",
    },
  );
  const request = createRuntimeDiagnosticsRepairControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space" },
      diagnostics: {
        decision: { id: "operator/override", action: "override" },
        message: "Continue after review.",
        approved: true,
        allowConflicts: true,
      },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.decisionId, "operator/override");
  assert.equal(request.action, "operator_override");
  assert.equal(
    request.endpoint,
    "/runtime/thread%20with%20space/diagnostics/operator%2Foverride/execute",
  );
  assert.equal(request.body.approval_granted, true);
  assert.equal(request.body.operator_override_approved, true);
  assert.equal(request.body.allow_conflicts, true);
  assert.equal(request.body.override_conflicts, true);
  assert.equal(request.body.message, "Continue after review.");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});

test("runtime_operator_steer workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "steer-control",
    "runtime_operator_steer",
    "Steer control",
    100,
    120,
  );
  const request = createRuntimeOperatorSteerControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      turnId: "turn-react-flow-1",
      guidance: "focus on the failing assertion",
    },
    { workflowGraphId: "workflow.react-flow.operator-steer-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_operator_steer");
  assert.equal(request.nodeId, "steer-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.turnId, "turn-react-flow-1");
  assert.equal(
    request.endpoint,
    "/v1/threads/thread-react-flow-1/turns/turn-react-flow-1/steer",
  );
  assert.equal(request.body.guidance, "focus on the failing assertion");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.operator-steer-proof",
  );
  assert.equal(request.body.workflowNodeId, RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_OPERATOR_STEER_COMPONENT_KIND);
});

test("runtime_operator_steer helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "steer-control-configured",
    "runtime_operator_steer",
    "Steer control",
    100,
    120,
    {
      runtimeOperatorSteerEndpoint: "/runtime/{threadId}/turns/{turnId}/steer",
      runtimeOperatorSteerThreadIdField: "runtime.threadId",
      runtimeOperatorSteerTurnIdField: "runtime.turnId",
      runtimeOperatorSteerGuidanceField: "operator.guidance",
      runtimeOperatorSteerWorkflowNodeId: "runtime.operator-steer",
      runtimeOperatorSteerActor: "workflow-author",
    },
  );
  const request = createRuntimeOperatorSteerControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space", turnId: "turn/with/slash" },
      operator: { guidance: "keep the proof scoped" },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.turnId, "turn/with/slash");
  assert.equal(
    request.endpoint,
    "/runtime/thread%20with%20space/turns/turn%2Fwith%2Fslash/steer",
  );
  assert.equal(request.body.guidance, "keep the proof scoped");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});

test("runtime_operator_interrupt workflow node builds a React Flow daemon request", () => {
  const node = makeWorkflowNode(
    "interrupt-control",
    "runtime_operator_interrupt",
    "Interrupt control",
    100,
    120,
  );
  const request = createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
    node,
    {
      threadId: "thread-react-flow-1",
      turnId: "turn-react-flow-1",
      reason: "pause live validation from workflow",
    },
    { workflowGraphId: "workflow.react-flow.operator-interrupt-proof" },
  );

  assert.equal(
    request.schemaVersion,
    WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION,
  );
  assert.equal(request.nodeType, "runtime_operator_interrupt");
  assert.equal(request.nodeId, "interrupt-control");
  assert.equal(request.threadId, "thread-react-flow-1");
  assert.equal(request.turnId, "turn-react-flow-1");
  assert.equal(
    request.endpoint,
    "/v1/threads/thread-react-flow-1/turns/turn-react-flow-1/interrupt",
  );
  assert.equal(request.body.reason, "pause live validation from workflow");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.actor, "operator");
  assert.equal(
    request.body.workflowGraphId,
    "workflow.react-flow.operator-interrupt-proof",
  );
  assert.equal(request.body.workflowNodeId, RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID);
  assert.equal(request.body.eventKind, RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND);
  assert.equal(request.body.componentKind, RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND);
});

test("runtime_operator_interrupt helper supports configurable fields from node logic", () => {
  const node = makeWorkflowNode(
    "interrupt-control-configured",
    "runtime_operator_interrupt",
    "Interrupt control",
    100,
    120,
    {
      runtimeOperatorInterruptEndpoint:
        "/runtime/{threadId}/turns/{turnId}/interrupt",
      runtimeOperatorInterruptThreadIdField: "runtime.threadId",
      runtimeOperatorInterruptTurnIdField: "runtime.turnId",
      runtimeOperatorInterruptReasonField: "operator.reason",
      runtimeOperatorInterruptWorkflowNodeId: "runtime.operator-interrupt",
      runtimeOperatorInterruptActor: "workflow-author",
    },
  );
  const request = createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
    node,
    {
      runtime: { threadId: "thread with space", turnId: "turn/with/slash" },
      operator: { reason: "pause the active turn" },
    },
  );

  assert.equal(request.threadId, "thread with space");
  assert.equal(request.turnId, "turn/with/slash");
  assert.equal(
    request.endpoint,
    "/runtime/thread%20with%20space/turns/turn%2Fwith%2Fslash/interrupt",
  );
  assert.equal(request.body.reason, "pause the active turn");
  assert.equal(request.body.actor, "workflow-author");
  assert.equal(request.body.source, "react_flow");
});
