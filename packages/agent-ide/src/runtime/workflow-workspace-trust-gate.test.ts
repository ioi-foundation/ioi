import assert from "node:assert/strict";
import test from "node:test";
import type { WorkflowProject } from "../types/graph";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { workflowWorkspaceTrustGateReadiness } from "./workflow-workspace-trust-gate";

const baseEvent = (
  overrides: Partial<WorkflowRuntimeThreadEventLike>,
): WorkflowRuntimeThreadEventLike => ({
  id: "event",
  cursor: "cursor",
  seq: 1,
  threadId: "thread",
  turnId: null,
  type: "runtime_step",
  eventKind: "runtime.step",
  sourceEventKind: "Runtime.Step",
  status: "completed",
  componentKind: "workspace_trust",
  workflowNodeId: "runtime.thread-mode.workspace-trust",
  workflowGraphId: "workflow",
  payloadSchemaVersion: "test",
  receiptRefs: [],
  artifactRefs: [],
  policyDecisionRefs: [],
  rollbackRefs: [],
  payload: {},
  ...overrides,
});

const workflow = (
  overrides: Partial<WorkflowProject> = {},
): WorkflowProject =>
  ({
    version: "1",
    metadata: {
      id: "workflow",
      name: "Workflow",
      slug: "workflow",
      workflowKind: "agent_workflow",
      executionMode: "mock",
    },
    global_config: {
      env: "test",
      requiredCapabilities: {},
      policy: { maxBudget: 1, maxSteps: 4, timeoutMs: 1_000 },
      contract: { developerBond: 1, adjudicationRubric: "test" },
      meta: { name: "Workflow", description: "Workflow" },
    },
    nodes: [
      {
        id: "source",
        type: "source",
        name: "Source",
        x: 0,
        y: 0,
        config: { logic: {} },
      },
      {
        id: "thread-mode",
        type: "runtime_thread_mode",
        name: "Review mode",
        x: 120,
        y: 0,
        config: {
          logic: {
            runtimeThreadModeMode: "review",
            runtimeThreadModeApprovalMode: "human_required",
            runtimeThreadModeWorkflowNodeId: "runtime.thread-mode",
            runtimeThreadModeWorkspaceTrustWorkflowNodeId:
              "runtime.thread-mode.workspace-trust",
            runtimeThreadModeRequestWarningAcknowledgement: true,
          },
        },
      },
      {
        id: "trust-gate",
        type: "runtime_workspace_trust_gate",
        name: "Trust gate",
        x: 240,
        y: 0,
        config: {
          logic: {
            runtimeWorkspaceTrustGateModeNodeId: "thread-mode",
            runtimeWorkspaceTrustGateWarningWorkflowNodeId:
              "runtime.thread-mode.workspace-trust",
            runtimeWorkspaceTrustGateStatusField:
              "runtimeWorkspaceTrustGate.status",
          },
        },
      },
      {
        id: "output",
        type: "output",
        name: "Output",
        x: 360,
        y: 0,
        config: { logic: {} },
      },
    ],
    edges: [
      {
        id: "mode-to-gate",
        from: "thread-mode",
        to: "trust-gate",
      },
    ],
    ...overrides,
  }) as WorkflowProject;

test("workspace trust gate blocks risky runtime mode until daemon warning exists", () => {
  const readiness = workflowWorkspaceTrustGateReadiness(workflow(), []);
  assert.equal(readiness.status, "blocked");
  assert.deepEqual(
    readiness.issues.map((issue) => issue.code),
    ["workspace_trust_warning_not_emitted"],
  );
});

test("workspace trust gate requires acknowledgement after daemon warning", () => {
  const warning = baseEvent({
    id: "warning-1",
    type: "workspace_trust_warning",
    eventKind: "workspace.trust_warning",
    sourceEventKind: "WorkspaceTrust.Warning",
    payload: {
      warningId: "warning-1",
      mode: "review",
      approvalMode: "human_required",
    },
    receiptRefs: ["receipt:warning"],
  });
  const readiness = workflowWorkspaceTrustGateReadiness(workflow(), [warning]);
  assert.equal(readiness.status, "blocked");
  assert.equal(readiness.requirements[0]?.warningId, "warning-1");
  assert.deepEqual(
    readiness.issues.map((issue) => issue.code),
    ["workspace_trust_acknowledgement_missing"],
  );
});

test("workspace trust gate passes when acknowledgement receipt is in daemon history", () => {
  const warning = baseEvent({
    id: "warning-1",
    type: "workspace_trust_warning",
    eventKind: "workspace.trust_warning",
    sourceEventKind: "WorkspaceTrust.Warning",
    payload: { warningId: "warning-1" },
    receiptRefs: ["receipt:warning"],
  });
  const acknowledgement = baseEvent({
    id: "ack-1",
    seq: 2,
    type: "workspace_trust_acknowledged",
    eventKind: "workspace.trust_acknowledged",
    sourceEventKind: "WorkspaceTrust.Acknowledged",
    payload: {
      warningId: "warning-1",
      sourceEventId: "warning-1",
    },
    receiptRefs: ["receipt:ack"],
  });
  const readiness = workflowWorkspaceTrustGateReadiness(workflow(), [
    warning,
    acknowledgement,
  ]);
  assert.equal(readiness.status, "passed");
  assert.deepEqual(readiness.issues, []);
  assert.deepEqual(readiness.requirements[0]?.receiptRefs, [
    "receipt:warning",
    "receipt:ack",
  ]);
});

test("workspace trust gate ignores canvas-local pass state without daemon receipt", () => {
  const localOnly = workflow({
    nodes: workflow().nodes.map((node) =>
      node.id === "trust-gate"
        ? ({
            ...node,
            config: {
              kind: node.type,
              law: node.config?.law ?? {},
              logic: {
                ...(node.config?.logic ?? {}),
                runtimeWorkspaceTrustGate: { status: "passed" },
              },
            },
          } as typeof node)
        : node,
    ),
  });
  const readiness = workflowWorkspaceTrustGateReadiness(localOnly, []);
  assert.equal(readiness.status, "blocked");
  assert.equal(readiness.issues[0]?.code, "workspace_trust_warning_not_emitted");
});

test("workspace trust gate reports missing gate for risky thread mode", () => {
  const missingGate = workflow({
    nodes: workflow().nodes.filter((node) => node.id !== "trust-gate"),
    edges: [],
  });
  const readiness = workflowWorkspaceTrustGateReadiness(missingGate, []);
  assert.equal(readiness.status, "blocked");
  assert.equal(readiness.issues[0]?.code, "missing_workspace_trust_gate");
});
