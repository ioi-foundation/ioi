import assert from "node:assert/strict";
import test from "node:test";
import type {
  WorkflowProject,
  WorkflowRunResult,
  WorkflowRunStatus,
  WorkflowRunSummary,
  WorkflowStreamEvent,
} from "../types/graph";
import { workflowRunHistoryModel } from "./workflow-run-history-model";
import {
  createLiveWorkflowRunTelemetryHydration,
  mergeWorkflowRuntimeThreadEvents,
} from "./workflow-runtime-live-telemetry";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

const workflow = {
  version: "1",
  nodes: [
    {
      id: "model",
      type: "model_call",
      name: "Model",
      x: 0,
      y: 0,
    },
    {
      id: "output",
      type: "output",
      name: "Output",
      x: 0,
      y: 0,
    },
  ],
  edges: [],
  global_config: {
    env: "test",
    modelBindings: {},
    requiredCapabilities: {},
    policy: {
      maxBudget: 1,
      maxSteps: 4,
      timeoutMs: 1_000,
    },
    contract: {
      developerBond: 1,
      adjudicationRubric: "test",
    },
    meta: {
      name: "Test workflow",
      description: "Test workflow",
    },
  },
  metadata: {
    id: "workflow",
    name: "Workflow",
    slug: "workflow",
    workflowKind: "agent_workflow",
    executionMode: "mock",
  },
} as unknown as WorkflowProject;

function runSummary(
  id: string,
  status: WorkflowRunStatus,
  summary: string,
  startedAtMs = 1_000,
): WorkflowRunSummary {
  return {
    id,
    status,
    startedAtMs,
    finishedAtMs: startedAtMs + 100,
    nodeCount: 2,
    checkpointCount: id === "run-a" ? 1 : 2,
    summary,
  };
}

function event(id: string, runId = "run-a"): WorkflowStreamEvent {
  return {
    id,
    runId,
    threadId: "thread",
    sequence: Number(id.replace(/\D/g, "")) || 1,
    kind: "node_succeeded",
    createdAtMs: 1_100,
    nodeId: "model",
    status: "success",
    message: `event ${id}`,
  };
}

function runtimeThreadEvent(
  id: string,
  seq: number,
  overrides: Partial<WorkflowRuntimeThreadEventLike> = {},
): WorkflowRuntimeThreadEventLike {
  return {
    id,
    cursor: `events_thread:${seq}`,
    seq,
    threadId: "thread",
    turnId: "turn-a",
    type: "runtime_step",
    eventKind: "runtime.step",
    sourceEventKind: "KernelEvent::RuntimeStep",
    status: "completed",
    createdAt: `2026-05-12T00:00:0${seq}.000Z`,
    componentKind: null,
    workflowNodeId: null,
    workflowGraphId: "workflow",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

function runResult(
  id: string,
  status: WorkflowRunStatus,
  output: unknown,
): WorkflowRunResult {
  return {
    summary: runSummary(id, status, `${id} summary`),
    thread: {
      id: "thread",
      workflowPath: "workflow.json",
      status,
      createdAtMs: 900,
    },
    finalState: {
      threadId: "thread",
      checkpointId: `${id}-checkpoint`,
      runId: id,
      stepIndex: 1,
      values: { result: output },
      nodeOutputs: { model: output },
      completedNodeIds: ["model"],
      blockedNodeIds: [],
      interruptedNodeIds: [],
      activeNodeIds: [],
      branchDecisions: {},
      pendingWrites: [],
    },
    nodeRuns: [
      {
        nodeId: "model",
        nodeType: "model_call",
        status: status === "failed" ? "error" : "success",
        startedAtMs: 1_000,
        finishedAtMs: 1_100,
        attempt: 1,
        input: { prompt: "hello" },
        output,
      },
    ],
    checkpoints: [
      {
        id: `${id}-checkpoint`,
        threadId: "thread",
        runId: id,
        createdAtMs: 1_100,
        stepIndex: 1,
        status,
        summary: `${id} checkpoint`,
      },
    ],
    events: [event(`${id}-event`, id)],
    verificationEvidence: [],
    completionRequirements: [],
  };
}

const runs = [
  runSummary("run-a", "passed", "Generate final answer"),
  runSummary("run-b", "failed", "Tool call failed", 2_000),
  runSummary("run-c", "blocked", "Policy blocked", 3_000),
];

test("workflow run history model filters runs by status and search", () => {
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: null,
    compareRunResult: null,
    selectedRunId: "run-b",
    compareRunId: "run-a",
    runEvents: [],
    searchQuery: " tool ",
    statusFilter: "failed",
  });

  assert.equal(model.normalizedSearch, "tool");
  assert.deepEqual(model.runStatuses, ["blocked", "failed", "passed"]);
  assert.equal(model.statusCounts.failed, 1);
  assert.deepEqual(
    model.visibleRows.map((row) => [row.run.id, row.selected, row.compare]),
    [["run-b", true, false]],
  );
});

test("workflow run history model binds selected run, timeline, and comparison", () => {
  const target = runResult("run-a", "passed", { answer: "new" });
  const baseline = runResult("run-b", "failed", { answer: "old" });
  const fallbackEvents = [event("fallback")];
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: baseline,
    selectedRunId: "run-a",
    compareRunId: "run-b",
    runEvents: fallbackEvents,
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.selectedRun?.summary.id, "run-a");
  assert.equal(model.defaultCompareRun?.id, "run-b");
  assert.equal(model.timelineEvents[0]?.runId, "run-a");
  assert.equal(model.comparison?.baselineRunId, "run-b");
  assert.equal(model.comparison?.targetRunId, "run-a");
  assert.equal(model.comparison?.changedNodes[0]?.nodeId, "model");
});

test("workflow run history model exposes model invocation traces and searches prompt evidence", () => {
  const target = runResult("run-a", "passed", {
    response: "sports answer",
    modelInvocation: {
      mode: "live_mounted_model",
      modelRef: "reasoning",
      modelId: "demo-mounted-model",
      promptHash: "sha256:prompt",
      responseHash: "sha256:response",
      prompt: {
        user: "what's the latest sports news?",
      },
      trace: [
        { phase: "input", summary: "Collected workflow input." },
        { phase: "binding", summary: "Resolved mounted model binding." },
        {
          phase: "prompt",
          summary: "Assembled prompt envelope.",
          promptHash: "sha256:prompt",
        },
        {
          phase: "model",
          summary: "Invoked mounted runtime.",
          responseHash: "sha256:response",
        },
      ],
    },
  });
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    searchQuery: "sports",
    statusFilter: "all",
  });

  assert.equal(model.modelInvocationTraces.length, 1);
  assert.equal(model.modelInvocationTraces[0]?.mode, "live_mounted_model");
  assert.equal(model.modelInvocationTraces[0]?.modelId, "demo-mounted-model");
  assert.equal(model.modelInvocationTraces[0]?.trace.length, 4);
  assert.deepEqual(
    model.modelInvocationTraces[0]?.trace.map((step) => step.phase),
    ["input", "binding", "prompt", "model"],
  );
  assert.deepEqual(
    model.visibleRows.map((row) => row.run.id),
    ["run-a"],
  );
});

test("workflow run history model projects canonical runtime thread events", () => {
  const target = runResult("run-a", "passed", { answer: "new" });
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    runtimeThreadEvents: [
      runtimeThreadEvent("event-1", 1, {
        type: "reasoning_delta",
        eventKind: "reasoning.delta",
        sourceEventKind: "KernelEvent::AgentThought",
        workflowNodeId: "runtime.reasoning",
        componentKind: "reasoning_delta",
        status: "running",
      }),
      runtimeThreadEvent("event-2", 2, {
        type: "tool_completed",
        eventKind: "tool.completed",
        sourceEventKind: "KernelEvent::AgentActionResult",
        workflowNodeId: "runtime.tool-result",
        componentKind: "tool_result",
        toolName: "shell",
        receiptRefs: ["receipt-tool"],
        artifactRefs: ["artifact-tool"],
      }),
    ],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.runtimeEventProjection.eventCount, 2);
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes.map((node) => node.id),
    ["runtime.reasoning", "runtime.tool-result"],
  );
  assert.equal(
    model.runtimeEventProjection.reactFlowNodes[1]?.data.latestCursor,
    "events_thread:2",
  );
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes[1]?.data.receiptRefs,
    ["receipt-tool"],
  );
  assert.equal(
    model.runtimeEventProjection.reactFlowEdges[0]?.source,
    "runtime.reasoning",
  );
  assert.equal(model.timelineEvents[0]?.runId, "run-a");
});

test("workflow run history model exposes computer-use prompt pipelines", () => {
  const target = runResult("run-a", "passed", {
    answer: "browser prompt inspected",
  });
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    runtimeThreadEvents: [
      runtimeThreadEvent("computer-use-environment", 1, {
        eventKind: "computer_use.environment_selected",
        sourceEventKind: "ComputerUse.EnvironmentSelected",
        status: "completed",
        componentKind: "computer_use_harness",
        workflowNodeId: "computer-use.select-environment",
        payloadSchemaVersion: "ioi.computer-use.harness.v1",
        receiptRefs: ["receipt-computer-use-environment"],
        payload: {
          summary: "Computer-use environment selected",
          computer_use_step: "select_environment",
          computer_use_lane: "native_browser",
          computer_use_session_mode: "owned_hermetic_browser",
          computer_use_lease_id: "lease-browser",
          computer_use_controlled_relaunch_launch_ref:
            "controlled_relaunch_run_a",
          controlled_relaunch_launch_receipt: {
            launch_ref: "controlled_relaunch_run_a",
            status: "launched",
            approval_ref: "approval-controlled-browser-launch",
            process_ref: "process:native_browser:run-a",
            profile_dir_ref: "profile:controlled_relaunch:run-a",
            endpoint_ref: "cdp_endpoint_run_a",
          },
          environment_selection_receipt: {
            risk_posture: "read_only_probe",
            authority_required: "computer_use.native_browser.read",
          },
          lease: {
            lease_id: "lease-browser",
            lane: "native_browser",
            session_mode: "owned_hermetic_browser",
            retention_mode: "local_redacted_artifacts",
          },
        },
      }),
      runtimeThreadEvent("computer-use-observation", 2, {
        eventKind: "computer_use.observation",
        sourceEventKind: "ComputerUse.Observation",
        status: "completed",
        componentKind: "computer_use_harness",
        workflowNodeId: "computer-use.observe",
        payloadSchemaVersion: "ioi.computer-use.harness.v1",
        artifactRefs: ["computer-use-trace.json"],
        payload: {
          computer_use_step: "observe",
          computer_use_observation_ref: "observation-browser",
          computer_use_target_index_ref: "target-index-browser",
          observation_bundle: {
            observation_ref: "observation-browser",
            target_index_ref: "target-index-browser",
            screenshot_ref: "artifact:run-a:screenshot",
            som_ref: "artifact:run-a:som-overlay",
            detected_patterns: ["form", "toolbar"],
          },
          target_index: {
            target_index_ref: "target-index-browser",
            coordinate_space_id: "viewport-run-a",
            targets: [
              {
                target_ref: "target-page",
                label: "Page body",
                role: "document",
                som_id: 1,
                confidence: 0.91,
                available_actions: ["inspect"],
                bounds: {
                  coordinate_space_id: "viewport-run-a",
                  x: 0,
                  y: 0,
                  width: 1024,
                  height: 768,
                },
              },
            ],
          },
        },
      }),
      runtimeThreadEvent("computer-use-proposal", 3, {
        eventKind: "computer_use.action_proposed",
        sourceEventKind: "ComputerUse.ActionProposed",
        status: "waiting_for_policy",
        componentKind: "computer_use_harness",
        workflowNodeId: "computer-use.action-proposal",
        payloadSchemaVersion: "ioi.computer-use.harness.v1",
        policyDecisionRefs: ["policy-read-only"],
        payload: {
          computer_use_step: "propose_action",
          computer_use_proposal_ref: "proposal-inspect",
          computer_use_target_ref: "target-page",
          computer_use_policy_decision_ref: "policy-read-only",
          action_proposal: {
            proposal_ref: "proposal-inspect",
            target_ref: "target-page",
            policy_decision_ref: "policy-read-only",
          },
          policy_decision_receipt: {
            policy_decision_ref: "policy-read-only",
            outcome: "approved_for_read_only_probe",
            authority_scope: "computer_use.native_browser.read",
            approval_ref: null,
            external_effect: false,
            fail_closed: false,
          },
        },
      }),
      runtimeThreadEvent("computer-use-action", 4, {
        eventKind: "computer_use.action_executed",
        sourceEventKind: "ComputerUse.ActionExecuted",
        status: "completed",
        componentKind: "computer_use_harness",
        workflowNodeId: "computer-use.execute-action",
        payloadSchemaVersion: "ioi.computer-use.harness.v1",
        payload: {
          computer_use_step: "execute_action",
          computer_use_action_ref: "action-click",
          computer_use_proposal_ref: "proposal-inspect",
          computer_action: {
            action_ref: "action-click",
            action_kind: "click",
            target_ref: "target-page",
          },
          action_receipt: {
            receipt_ref: "receipt-action-click",
            action_ref: "action-click",
            adapter_id: "ioi.visual_gui.local_executor",
            status: "completed",
            verification_ref: "verification-inspect",
          },
          computer_use_execution_result: {
            status: "completed",
            executor_ref: "visual-gui-executor-run-a",
            adapter_id: "ioi.visual_gui.local_executor",
            provider_id: "fixture",
            preflight_receipt: { status: "captured" },
            execution_receipt: { provider_id: "fixture" },
            after: { requires_reobserve: true },
          },
        },
      }),
      runtimeThreadEvent("computer-use-verification", 5, {
        eventKind: "computer_use.verification",
        sourceEventKind: "ComputerUse.Verification",
        status: "completed",
        componentKind: "computer_use_harness",
        workflowNodeId: "computer-use.verify",
        payloadSchemaVersion: "ioi.computer-use.harness.v1",
        payload: {
          computer_use_step: "verify_postcondition",
          computer_use_verification_ref: "verification-inspect",
          verification_receipt: {
            verification_ref: "verification-inspect",
            status: "passed",
          },
        },
      }),
      runtimeThreadEvent("computer-use-commit-gate", 6, {
        eventKind: "computer_use.commit_gate",
        sourceEventKind: "ComputerUse.CommitGate",
        status: "completed",
        componentKind: "computer_use_harness",
        workflowNodeId: "computer-use.commit-gate",
        payloadSchemaVersion: "ioi.computer-use.harness.v1",
        payload: {
          computer_use_step: "commit_or_handoff",
          computer_use_action_ref: "action-inspect",
          computer_use_commit_gate_ref: "commit-gate-inspect",
          outcome_contract: {
            outcome_ref: "outcome-inspect",
            external_effect_policy: "confirmation_required",
          },
          commit_gate: {
            commit_gate_ref: "commit-gate-inspect",
            status: "not_required",
          },
        },
      }),
    ],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.runtimeEventProjection.eventCount, 6);
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes.map((node) => node.data.label),
    [
      "Computer use: select environment",
      "Computer use: observe",
      "Computer use: propose action",
      "Computer use: execute action",
      "Computer use: verify",
      "Computer use: commit gate",
    ],
  );
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes.map((node) => node.data.computerUse?.step),
    [
      "select_environment",
      "observe",
      "propose_action",
      "execute_action",
      "verify_postcondition",
      "commit_or_handoff",
    ],
  );
  assert.equal(
    model.runtimeEventProjection.nodes[0]?.computerUse?.lane,
    "native_browser",
  );
  assert.equal(
    model.runtimeEventProjection.nodes[1]?.computerUse?.targetIndexRef,
    "target-index-browser",
  );
  assert.equal(
    model.computerUseWorkbench?.screenRef,
    "artifact:run-a:screenshot",
  );
  assert.equal(
    model.computerUseWorkbench?.controlledRelaunchLaunchRef,
    "controlled_relaunch_run_a",
  );
  assert.equal(
    model.computerUseWorkbench?.controlledRelaunchLaunchStatus,
    "launched",
  );
  assert.equal(
    model.computerUseWorkbench?.controlledRelaunchEndpointRef,
    "cdp_endpoint_run_a",
  );
  assert.equal(model.computerUseWorkbench?.somRef, "artifact:run-a:som-overlay");
  assert.deepEqual(
    model.computerUseWorkbench?.artifactPreviews.map((artifact) => [
      artifact.artifactRef,
      artifact.previewKind,
      artifact.fetchPath,
    ]),
    [
      [
        "artifact:run-a:screenshot",
        "runtime_artifact",
        "/v1/runs/run-a/artifacts/artifact%3Arun-a%3Ascreenshot",
      ],
      [
        "artifact:run-a:som-overlay",
        "runtime_artifact",
        "/v1/runs/run-a/artifacts/artifact%3Arun-a%3Asom-overlay",
      ],
      [
        "computer-use-trace.json",
        "runtime_artifact",
        "/v1/runs/run-a/artifacts/computer-use-trace.json",
      ],
    ],
  );
  assert.equal(model.computerUseWorkbench?.coordinateSpaceId, "viewport-run-a");
  assert.deepEqual(model.computerUseWorkbench?.overlayViewport, {
    coordinateSpaceId: "viewport-run-a",
    width: 1024,
    height: 768,
  });
  assert.equal(model.computerUseWorkbench?.targetCount, 1);
  assert.equal(model.computerUseWorkbench?.affordanceCount, 0);
  assert.deepEqual(model.computerUseWorkbench?.detectedPatterns, [
    "form",
    "toolbar",
  ]);
  assert.deepEqual(model.computerUseWorkbench?.visualTargetSummaries[0], {
    targetRef: "target-page",
    label: "Page body",
    role: "document",
    somId: 1,
    confidence: 0.91,
    bounds: {
      x: 0,
      y: 0,
      width: 1024,
      height: 768,
      coordinateSpaceId: "viewport-run-a",
    },
    boundsSummary: "viewport-run-a · 0,0 1024x768",
    availableActions: ["inspect"],
  });
  assert.equal(
    model.runtimeEventProjection.nodes[2]?.computerUse?.policyDecisionRef,
    "policy-read-only",
  );
  assert.equal(
    model.computerUseWorkbench?.policyOutcome,
    "approved_for_read_only_probe",
  );
  assert.equal(
    model.computerUseWorkbench?.policyAuthorityScope,
    "computer_use.native_browser.read",
  );
  assert.equal(model.computerUseWorkbench?.policyExternalEffect, false);
  assert.equal(model.computerUseWorkbench?.policyFailClosed, false);
  assert.equal(model.computerUseWorkbench?.executionStatus, "completed");
  assert.equal(
    model.computerUseWorkbench?.executionAdapterId,
    "ioi.visual_gui.local_executor",
  );
  assert.equal(model.computerUseWorkbench?.executionProviderId, "fixture");
  assert.equal(model.computerUseWorkbench?.executionPreflightStatus, "captured");
  assert.equal(model.computerUseWorkbench?.executionRequiresReobserve, true);
  assert.equal(
    model.runtimeEventProjection.nodes[3]?.computerUse?.executionProviderId,
    "fixture",
  );
  assert.equal(
    model.runtimeEventProjection.nodes[4]?.computerUse?.verificationStatus,
    "passed",
  );
  assert.equal(
    model.runtimeEventProjection.nodes[5]?.computerUse?.commitGateStatus,
    "not_required",
  );
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowEdges.map((edge) => [
      edge.source,
      edge.target,
    ]),
    [
      ["computer-use.select-environment", "computer-use.observe"],
      ["computer-use.observe", "computer-use.action-proposal"],
      ["computer-use.action-proposal", "computer-use.execute-action"],
      ["computer-use.execute-action", "computer-use.verify"],
      ["computer-use.verify", "computer-use.commit-gate"],
    ],
  );
});

test("workflow run history model exposes computer-use scorecard summaries", () => {
  const target = runResult("run-a", "passed", {
    evidenceAssessment: {
      computerUseTriLaneScorecard: {
        status: "passed",
        headline: "Computer-use tri-lane retained gate passed.",
        summaryRows: [
          {
            id: "lane:native_browser",
            lane: "native_browser",
            label: "Native Browser",
            status: "passed",
            sessionMode: "owned_hermetic_browser",
            actionKind: "inspect",
            modelPromptTrace: "present",
            runtimeEvents: 18,
            projectedNodes: 11,
            targets: 3,
            affordances: 4,
            policy: "approved_for_read_only_probe",
            verification: "passed",
            cleanup: "completed",
            proofPath: "/tmp/native-browser-proof.json",
            blockers: [],
          },
          {
            id: "lane:visual_gui",
            lane: "visual_gui",
            label: "Visual GUI",
            status: "passed",
            sessionMode: "local_gui",
            actionKind: "click",
            modelPromptTrace: "present",
            runtimeEvents: 20,
            projectedNodes: 12,
            targets: 5,
            affordances: 6,
            policy: "approval-visual-gui-run-button",
            verification: "passed",
            cleanup: "completed",
            proofPath: "/tmp/visual-gui-proof.json",
            blockers: [],
          },
          {
            id: "lane:sandboxed_hosted",
            lane: "sandboxed_hosted",
            label: "Sandboxed Hosted",
            status: "passed",
            sessionMode: "local_sandbox",
            actionKind: "inspect",
            modelPromptTrace: "not_required",
            runtimeEvents: 16,
            projectedNodes: 10,
            targets: 2,
            affordances: 3,
            policy: "fail_closed",
            verification: "passed",
            cleanup: "completed",
            proofPath: "/tmp/sandboxed-proof.json",
            blockers: [],
          },
        ],
        blockers: [],
        externalDeferrals: [
          {
            id: "hosted_provider_backends",
            status: "external_provider_deferral",
            reason: "Provider credentials are selected outside this run.",
          },
        ],
      },
    },
  });
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.computerUseScorecard?.status, "passed");
  assert.equal(
    model.computerUseScorecard?.headline,
    "Computer-use tri-lane retained gate passed.",
  );
  assert.deepEqual(
    model.computerUseScorecard?.summaryRows.map((row) => [
      row.lane,
      row.status,
      row.runtimeEvents,
      row.targets,
      row.affordances,
    ]),
    [
      ["native_browser", "passed", 18, 3, 4],
      ["visual_gui", "passed", 20, 5, 6],
      ["sandboxed_hosted", "passed", 16, 2, 3],
    ],
  );
  assert.deepEqual(model.computerUseScorecard?.proofPaths, [
    "/tmp/native-browser-proof.json",
    "/tmp/visual-gui-proof.json",
    "/tmp/sandboxed-proof.json",
  ]);
  assert.equal(
    model.computerUseScorecard?.externalDeferrals[0]?.id,
    "hosted_provider_backends",
  );
});

test("workflow run history model projects the replayable runtime policy stack", () => {
  const target = runResult("run-a", "passed", { answer: "new" });
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    runtimeThreadEvents: [
      runtimeThreadEvent("trust-warning", 1, {
        type: "workspace_trust_warning",
        eventKind: "workspace.trust_warning",
        sourceEventKind: "WorkspaceTrust.Warning",
        workflowNodeId: "runtime.thread-mode.workspace-trust",
        componentKind: "workspace_trust",
        status: "warning",
        receiptRefs: ["receipt-trust"],
        payload: { warning_id: "warning-1" },
      }),
      runtimeThreadEvent("trust-ack", 2, {
        type: "workspace_trust_acknowledged",
        eventKind: "workspace.trust_acknowledged",
        sourceEventKind: "WorkspaceTrust.Acknowledged",
        workflowNodeId: "runtime.thread-mode.workspace-trust",
        componentKind: "workspace_trust",
        receiptRefs: ["receipt-trust-ack"],
        payload: { warning_id: "warning-1" },
      }),
      runtimeThreadEvent("approval-required", 3, {
        type: "approval_required",
        eventKind: "approval.required",
        sourceEventKind: "OperatorApproval.Request",
        workflowNodeId: "workflow.coding.file.apply_patch",
        componentKind: "approval_gate",
        approvalId: "approval-1",
        receiptRefs: ["receipt-approval"],
        payload: { approval_id: "approval-1" },
      }),
      runtimeThreadEvent("approval-approved", 4, {
        type: "approval_decision",
        eventKind: "approval.approved",
        sourceEventKind: "OperatorApproval.Approve",
        workflowNodeId: "workflow.coding.file.apply_patch",
        componentKind: "approval_gate",
        approvalId: "approval-1",
        status: "approved",
        receiptRefs: ["receipt-approval-approved"],
        payload: { approval_id: "approval-1", decision: "approve" },
      }),
      runtimeThreadEvent("tool-completed", 5, {
        type: "tool_completed",
        eventKind: "tool.completed",
        sourceEventKind: "CodingTool.FileApplyPatch",
        workflowNodeId: "workflow.coding.file.apply_patch",
        componentKind: "coding_tool",
        toolCallId: "tool-call-1",
        receiptRefs: ["receipt-tool"],
        payload: {
          approval_id: "approval-1",
          approval_satisfied: true,
          approval_decision_event_id: "approval-approved",
        },
      }),
    ],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.runtimePolicyStack.status, "completed");
  assert.deepEqual(
    model.runtimePolicyStack.stages.map((stage) => [stage.kind, stage.status]),
    [
      ["workspace_trust_warning", "completed"],
      ["workspace_trust_acknowledgement", "completed"],
      ["approval_requirement", "completed"],
      ["approval_decision", "completed"],
      ["approved_retry", "completed"],
    ],
  );
  assert.deepEqual(model.runtimePolicyStack.receiptRefs, [
    "receipt-trust",
    "receipt-trust-ack",
    "receipt-approval",
    "receipt-approval-approved",
    "receipt-tool",
  ]);
});

test("workflow run history model projects workflow edit proposal policy stack", () => {
  const target = runResult("run-a", "passed", { answer: "new" });
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    runtimeThreadEvents: [
      runtimeThreadEvent("proposal", 1, {
        type: "workflow_edit_proposed",
        eventKind: "workflow.edit_proposed",
        sourceEventKind: "WorkflowEdit.Proposed",
        workflowNodeId: "runtime.workflow-edit-proposal.proposal-a",
        componentKind: "workflow_edit_proposal",
        approvalId: "approval-a",
        receiptRefs: ["receipt-proposal"],
        payload: {
          proposal_id: "proposal-a",
          approval_id: "approval-a",
          target_workflow_node_ids: ["model"],
        },
      }),
      runtimeThreadEvent("approval-required", 2, {
        type: "approval_required",
        eventKind: "approval.required",
        sourceEventKind: "OperatorApproval.Request",
        workflowNodeId: "runtime.workflow-edit-proposal.proposal-a",
        componentKind: "approval_gate",
        approvalId: "approval-a",
        receiptRefs: ["receipt-approval"],
        payload: { approval_id: "approval-a" },
      }),
      runtimeThreadEvent("approval-approved", 3, {
        type: "approval_decision",
        eventKind: "approval.approved",
        sourceEventKind: "OperatorApproval.Approve",
        workflowNodeId: "runtime.workflow-edit-proposal.proposal-a",
        componentKind: "approval_gate",
        approvalId: "approval-a",
        status: "approved",
        receiptRefs: ["receipt-approved"],
        payload: { approval_id: "approval-a", decision: "approve" },
      }),
      runtimeThreadEvent("apply", 4, {
        type: "workflow_edit_applied",
        eventKind: "workflow.edit_applied",
        sourceEventKind: "WorkflowEdit.Applied",
        workflowNodeId: "runtime.workflow-edit-proposal.proposal-a",
        componentKind: "workflow_edit_proposal",
        approvalId: "approval-a",
        receiptRefs: ["receipt-apply"],
        payload: {
          proposal_id: "proposal-a",
          proposal_event_id: "proposal",
          approval_id: "approval-a",
          mutation_executed: true,
        },
      }),
    ],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.runtimeEditProposalPolicyStack.status, "completed");
  assert.equal(model.runtimeEditProposalPolicyStack.proposalId, "proposal-a");
  assert.equal(model.runtimeEditProposalPolicyStack.mutationExecuted, true);
  assert.deepEqual(
    model.runtimeEditProposalPolicyStack.stages.map((stage) => [
      stage.kind,
      stage.status,
    ]),
    [
      ["proposal_created", "completed"],
      ["approval_requirement", "completed"],
      ["approval_decision", "completed"],
      ["proposal_apply", "completed"],
    ],
  );
});

test("workflow run history model hydrates live telemetry for an in-flight run", () => {
  const liveRun = createLiveWorkflowRunTelemetryHydration({
    workflow,
    thread: {
      id: "thread-live",
      workflowPath: "workflow.json",
      status: "queued",
      createdAtMs: 950,
      input: { prompt: "stream tokens" },
    },
    startedAtMs: 1_000,
  });
  const events = mergeWorkflowRuntimeThreadEvents(
    [
      runtimeThreadEvent("usage-1", 1, {
        threadId: "thread-live",
        type: "usage_delta",
        eventKind: "usage.delta",
        sourceEventKind: "RuntimeUsageTelemetry.Delta",
        workflowNodeId: "runtime.usage-telemetry",
        componentKind: "usage_telemetry",
        status: "running",
        payload: {
          total_tokens: 128,
          input_tokens: 80,
          output_tokens: 48,
          estimated_cost_usd: 0.000128,
          context_pressure: 0.42,
          context_pressure_status: "nominal",
        },
      }),
    ],
    [
      runtimeThreadEvent("usage-1", 1, {
        threadId: "thread-live",
        type: "usage_delta",
        eventKind: "usage.delta",
        sourceEventKind: "RuntimeUsageTelemetry.Delta",
        workflowNodeId: "runtime.usage-telemetry",
        componentKind: "usage_telemetry",
        status: "running",
        payload: {
          total_tokens: 128,
          input_tokens: 80,
          output_tokens: 48,
          estimated_cost_usd: 0.000128,
          context_pressure: 0.42,
          context_pressure_status: "nominal",
        },
      }),
      runtimeThreadEvent("context-2", 2, {
        threadId: "thread-live",
        type: "context_pressure_delta",
        eventKind: "context.pressure_delta",
        sourceEventKind: "RuntimeContextPressure.Delta",
        workflowNodeId: "runtime.context-budget",
        componentKind: "context_pressure",
        status: "running",
        payload: {
          usage_total_tokens: 192,
          usage_cost_estimate_usd: 0.000192,
          usage_context_pressure: 0.74,
          usage_context_pressure_status: "elevated",
        },
      }),
      runtimeThreadEvent("context-alert-3", 3, {
        threadId: "thread-live",
        type: "context_pressure_alert",
        eventKind: "context.pressure_alert",
        sourceEventKind: "RuntimeContextPressure.Alert",
        workflowNodeId: "runtime.context-pressure-alert",
        componentKind: "context_pressure_alert",
        status: "warning",
        payload: {
          alert_level: "warn",
          scope: "turn",
          pressure: 0.74,
          pressure_status: "elevated",
          actions: [
            {
              action: "delegate_summary",
              label: "Delegate summary",
              executable: true,
              workflowNodeId: "runtime.subagent.delegate-summary",
            },
            {
              action: "compact",
              label: "Compact context",
              executable: true,
              workflowNodeId: "runtime.context-compact",
            },
          ],
        },
      }),
    ],
  );

  const model = workflowRunHistoryModel({
    workflow,
    runs: [liveRun.summary],
    lastRunResult: liveRun,
    compareRunResult: null,
    selectedRunId: liveRun.summary.id,
    compareRunId: null,
    runEvents: [],
    runtimeThreadEvents: events,
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.selectedRun?.summary.status, "running");
  assert.equal(model.timelineEvents[0]?.threadId, "thread-live");
  assert.equal(model.runtimeEventProjection.eventCount, 3);
  assert.equal(model.runtimeTelemetrySummary.status, "elevated");
  assert.equal(model.runtimeTelemetrySummary.totalTokens, 192);
  assert.equal(model.runtimeTelemetrySummary.contextPressureStatus, "elevated");
  assert.equal(model.runtimeTelemetrySummary.usageEventCount, 1);
  assert.equal(model.runtimeTelemetrySummary.contextPressureEventCount, 1);
  assert.equal(model.runtimeTelemetrySummary.contextPressureAlertCount, 1);
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes.map((node) => [
      node.id,
      node.data.nodeKind,
      node.data.status,
    ]),
    [
      ["runtime.usage-telemetry", "runtime_usage_meter", "running"],
      ["runtime.context-budget", "runtime_context_budget", "running"],
      ["runtime.context-pressure-alert", "hook_policy", "warning"],
    ],
  );
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes[2]?.data.contextPressureActions.map(
      (action) => [action.action, action.workflowNodeId, action.executable],
    ),
    [
      ["delegate_summary", "runtime.subagent.delegate-summary", true],
      ["compact", "runtime.context-compact", true],
    ],
  );
});

test("workflow run history model projects TUI control state for run inspector", () => {
  const target = {
    ...runResult("run-a", "passed", { answer: "new" }),
    tuiControlState: {
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      surface: "tui",
      thread_id: "thread",
      current_turn_id: "turn-a",
      last_cursor: "events_thread:9",
      mode_status: {
        mode: "agent",
        approval_mode: "suggest",
        trust_profile: "local_private",
      },
      approval_rows: [
        {
          approval_id: "approval-a",
          status: "pending",
          workflow_node_id: "runtime.approval.approval-a",
        },
      ],
      approval_decisions: [
        {
          approval_id: "approval-a",
          decision: "reject",
          status: "rejected",
          receipt_refs: ["receipt-approval-rejected"],
          policy_decision_refs: ["policy-approval-allow"],
        },
      ],
      command_history: [
        {
          id: "command-events",
          command: "events",
          raw_input: "/events 0",
          status: "applied",
          sequence: 1,
        },
      ],
      validation_errors: [
        {
          id: "error-steer",
          command: "steer",
          raw_input: "/steer",
          message: "/steer requires guidance text",
          sequence: 2,
        },
      ],
    },
  } as unknown as WorkflowRunResult;

  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.tuiControlStateProjection.threadId, "thread");
  assert.equal(model.tuiControlStateProjection.currentTurnId, "turn-a");
  assert.equal(model.tuiControlStateProjection.commandCount, 1);
  assert.equal(model.tuiControlStateProjection.validationErrorCount, 1);
  assert.equal(model.tuiControlStateProjection.approvalCount, 1);
  assert.equal(model.tuiControlStateProjection.approvalDecisionCount, 1);
  assert.deepEqual(
    model.tuiControlStateProjection.rows.map((row) => [
      row.rowKind,
      row.command,
      row.status,
    ]),
    [
      ["summary", null, "current"],
      ["mode_status", null, "current"],
      ["approval", null, "pending"],
      ["approval_decision", "reject", "rejected"],
      ["command", "events", "applied"],
      ["validation_error", "steer", "validation_error"],
    ],
  );
  assert.deepEqual(
    model.tuiControlStateProjection.rows[3]?.receiptRefs,
    ["receipt-approval-rejected"],
  );
});

test("workflow run history model exposes source-filtered TUI coding-tool budget evidence", () => {
  const target = {
    ...runResult("run-a", "blocked", { answer: "budget blocked" }),
    tuiControlState: {
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      surface: "tui",
      thread_id: "thread-budget",
      workflow_graph_id: "workflow",
      current_turn_id: "turn-budget",
      last_cursor: "events_thread:12",
      last_event_id: "event-budget",
      coding_tool_rows: [
        {
          id: "budget-row",
          status: "blocked",
          command: "events",
          raw_input: "/events",
          event_id: "event-budget",
          cursor: "events_thread:12",
          thread_id: "thread-budget",
          turn_id: "turn-budget",
          workflow_graph_id: "workflow",
          workflow_node_id: "workflow.coding.file.apply_patch",
          tool_name: "file.apply_patch",
          tool_call_id: "tool-call-budget",
          reason: "coding_tool_budget_exceeded",
          budget_status: "exceeded",
          context_budget_status: "blocked",
          budget_usage_telemetry: {
            total_tokens: 720,
            estimated_cost_usd: 0.0042,
            context_pressure: 0.72,
          },
          context_budget: {
            mode: "block",
            policy_decision_id: "policy-budget",
            checks: [{ field: "total_tokens" }],
            violations: [{ field: "total_tokens" }],
          },
          mutation_blocked: true,
          receipt_refs: ["receipt-budget"],
          policy_decision_refs: ["policy-budget"],
        },
      ],
      command_history: [
        {
          id: "command-events",
          command: "events",
          raw_input: "/events 0",
          status: "applied",
          sequence: 1,
        },
      ],
    },
  } as unknown as WorkflowRunResult;

  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    searchQuery: "",
    statusFilter: "all",
    sourceFilter: "tui_coding_tool_rows",
  });

  assert.equal(model.runtimeTelemetrySummary.status, "blocked");
  assert.equal(model.runtimeTelemetrySummary.codingToolBudgetRowCount, 1);
  assert.ok(
    model.runtimeTelemetrySummary.sourceKinds.includes("tui_coding_tool_rows"),
  );
  assert.equal(model.runtimeTelemetrySourceFilter, "tui_coding_tool_rows");
  assert.deepEqual(
    model.runtimeTelemetrySourceFilters.map((source) => [
      source.sourceKind,
      source.count,
      source.active,
      source.blocksMutation,
    ]),
    [["tui_coding_tool_rows", 1, true, true]],
  );
  assert.deepEqual(
    model.visibleTuiControlStateRows.map((row) => [row.rowKind, row.eventId]),
    [["coding_tool_budget", "event-budget"]],
  );
  assert.equal(model.runtimeCodingToolBudgetEvidence?.rowCount, 1);
  assert.equal(model.runtimeCodingToolBudgetEvidence?.mutationBlocked, true);
  assert.deepEqual(model.runtimeCodingToolBudgetEvidence?.eventIds, [
    "event-budget",
  ]);
  assert.deepEqual(model.runtimeCodingToolBudgetEvidence?.toolNames, [
    "file.apply_patch",
  ]);
  assert.deepEqual(model.runtimeCodingToolBudgetEvidence?.toolCallIds, [
    "tool-call-budget",
  ]);
  assert.deepEqual(model.runtimeCodingToolBudgetEvidence?.budgetStatuses, [
    "exceeded",
  ]);
  assert.deepEqual(
    model.runtimeCodingToolBudgetEvidence?.contextBudgetStatuses,
    ["blocked"],
  );
  assert.equal(model.runtimeCodingToolBudgetEvidence?.totalTokens, 720);
  assert.equal(model.runtimeCodingToolBudgetEvidence?.contextPressure, 0.72);
  assert.deepEqual(model.runtimeCodingToolBudgetEvidence?.policyDecisionRefs, [
    "policy-budget",
  ]);
});

test("workflow run history model replays daemon-owned coding budget preflight blocks", () => {
  const target = {
    ...runResult("run-a", "blocked", { answer: "budget blocked" }),
    runtimeThreadEvents: [
      runtimeThreadEvent("event-workflow-run-preflight-blocked", 1, {
        type: "policy_blocked",
        eventKind: "policy.blocked",
        sourceEventKind: "WorkflowRunCodingToolBudgetPreflightBlocked",
        status: "blocked",
        componentKind: "coding_tool",
        workflowNodeId: "runtime.coding-tool-budget-preflight",
        payloadSchemaVersion: "ioi.workflow.coding-tool-budget-preflight.v1",
        receiptRefs: ["receipt-workflow-run-budget"],
        policyDecisionRefs: ["policy-workflow-run-budget"],
        payload: {
          reason: "coding_tool_budget_preflight_blocked",
          status: "blocked",
          contextBudgetStatus: "blocked",
          mutationBlocked: true,
        },
      }),
    ],
    tuiControlState: {
      schemaVersion: "ioi.workflow.runtime-tui-control-state.v1",
      surface: "workflow_run",
      threadId: "thread",
      workflowGraphId: "workflow",
      lastCursor: "workflow_run_policy:run-a:1",
      lastEventId: "event-workflow-run-preflight-blocked",
      codingToolRows: [
        {
          id: "workflow-run-coding-tool-budget-preflight-run-a",
          status: "blocked",
          eventId: "event-workflow-run-preflight-blocked",
          workflowNodeId: "runtime.coding-tool-budget-preflight",
          reason: "coding_tool_budget_preflight_blocked",
          budgetStatus: "exceeded",
          contextBudgetStatus: "blocked",
          mutationBlocked: true,
          receiptRefs: ["receipt-workflow-run-budget"],
          policyDecisionRefs: ["policy-workflow-run-budget"],
        },
      ],
    },
  } as unknown as WorkflowRunResult;

  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    searchQuery: "",
    statusFilter: "all",
    sourceFilter: "all",
  });

  assert.equal(model.runtimeEventProjection.nodes[0]?.nodeKind, "plugin_tool");
  assert.equal(
    model.runtimeEventProjection.nodes[0]?.codingToolBudgetReason,
    "coding_tool_budget_preflight_blocked",
  );
  assert.equal(model.runtimeTelemetrySummary.status, "blocked");
  assert.equal(model.runtimeCodingToolBudgetEvidence?.mutationBlocked, true);
  assert.deepEqual(model.runtimeCodingToolBudgetEvidence?.eventIds, [
    "event-workflow-run-preflight-blocked",
  ]);
  assert.deepEqual(model.runtimeCodingToolBudgetEvidence?.receiptRefs, [
    "receipt-workflow-run-budget",
  ]);
});

test("workflow run history model replays coding budget recovery chains", () => {
  const target = {
    ...runResult("run-a", "passed", { answer: "retried" }),
    runtimeThreadEvents: [
      runtimeThreadEvent("event-workflow-run-preflight-blocked", 1, {
        type: "policy_blocked",
        eventKind: "policy.blocked",
        sourceEventKind: "WorkflowRunCodingToolBudgetPreflightBlocked",
        status: "blocked",
        componentKind: "coding_tool",
        workflowNodeId: "runtime.coding-tool-budget-preflight",
        payloadSchemaVersion: "ioi.workflow.coding-tool-budget-preflight.v1",
        receiptRefs: ["receipt-workflow-run-budget"],
        policyDecisionRefs: ["policy-workflow-run-budget"],
        payload: {
          reason: "coding_tool_budget_preflight_blocked",
          status: "blocked",
          contextBudgetStatus: "blocked",
          mutationBlocked: true,
        },
      }),
      runtimeThreadEvent("event-approval-required", 2, {
        type: "approval_required",
        eventKind: "approval.required",
        sourceEventKind: "OperatorApproval.Request",
        status: "waiting_for_approval",
        componentKind: "approval_gate",
        workflowNodeId: "runtime.coding-tool-budget-preflight",
        approvalId: "approval-budget",
        payloadSchemaVersion: "ioi.runtime.approval-request.v1",
        receiptRefs: ["receipt-approval-required"],
        policyDecisionRefs: ["policy-approval-required"],
        payload: {
          reason: "coding_tool_budget_preflight_blocked",
          approvalId: "approval-budget",
          sourceEventId: "event-workflow-run-preflight-blocked",
        },
      }),
      runtimeThreadEvent("event-approval-approved", 3, {
        type: "approval_decision",
        eventKind: "approval.approved",
        sourceEventKind: "OperatorApproval.Approve",
        status: "approved",
        componentKind: "approval_gate",
        workflowNodeId: "runtime.coding-tool-budget-preflight",
        approvalId: "approval-budget",
        payloadSchemaVersion: "ioi.runtime.approval-decision.v1",
        receiptRefs: ["receipt-approval-approved"],
        policyDecisionRefs: ["policy-approval-approved"],
        payload: {
          decision: "approve",
          approvalId: "approval-budget",
        },
      }),
      runtimeThreadEvent("event-retry-completed", 4, {
        type: "tool_completed",
        eventKind: "workflow.run.retry_completed",
        sourceEventKind: "WorkflowRunCodingToolBudgetApprovedRetry",
        status: "completed",
        componentKind: "coding_tool",
        workflowNodeId: "runtime.coding-tool-budget-preflight",
        approvalId: "approval-budget",
        payloadSchemaVersion: "ioi.workflow.coding-tool-budget-recovery.v1",
        receiptRefs: ["receipt-retry"],
        policyDecisionRefs: ["policy-retry"],
        payload: {
          approvalId: "approval-budget",
          approvalSatisfied: true,
          approvalDecisionEventId: "event-approval-approved",
        },
      }),
    ],
  } as unknown as WorkflowRunResult;

  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    searchQuery: "",
    statusFilter: "all",
    sourceFilter: "all",
  });

  assert.equal(model.runtimePolicyStack.status, "completed");
  assert.deepEqual(
    model.runtimePolicyStack.stages.map((stage) => [stage.kind, stage.status]),
    [
      ["workspace_trust_warning", "not_required"],
      ["workspace_trust_acknowledgement", "not_required"],
      ["approval_requirement", "completed"],
      ["approval_decision", "completed"],
      ["approved_retry", "completed"],
    ],
  );
  assert.deepEqual(
    model.runtimeEventProjection.nodes[0]?.codingToolBudgetRecoveryActions.map(
      (action) => [action.action, action.status, action.executable],
    ),
    [
      ["review_receipt", "completed", false],
      ["request_approval", "completed", false],
      ["approve_override", "completed", false],
      ["reject_override", "blocked", false],
      ["retry_approved", "completed", false],
    ],
  );
});

test("workflow run history model falls back to ambient events without selected run", () => {
  const fallbackEvents = [event("fallback")];
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: runResult("run-a", "passed", "new"),
    compareRunResult: null,
    selectedRunId: "missing",
    compareRunId: null,
    runEvents: fallbackEvents,
    searchQuery: "zzz",
    statusFilter: "all",
  });

  assert.equal(model.selectedRun, null);
  assert.equal(model.comparison, null);
  assert.equal(model.timelineEvents, fallbackEvents);
  assert.equal(model.filteredRuns.length, 0);
});

test("workflow run history model projects interrupts and harness attempts", () => {
  const selected = {
    ...runResult("run-a", "interrupted", "needs input"),
    interrupt: {
      id: "interrupt",
      runId: "run-a",
      threadId: "thread",
      nodeId: "model",
      status: "pending",
      createdAtMs: 1_200,
      prompt: "Approve?",
      allowedOutcomes: ["approve"],
      response: {
        binding: {
          bindingKind: "tool",
          ref: "tool:write",
          sideEffectClass: "write",
        },
      },
    },
    harnessAttempts: [
      {
        attemptId: "attempt",
        harnessWorkflowId: "harness",
        harnessActivationId: "activation",
        harnessHash: "hash",
        workflowNodeId: "model",
        componentId: "component",
        componentKind: "planner",
        executionMode: "live",
        readiness: "live_ready",
        attemptIndex: 1,
        status: "succeeded",
        startedAtMs: 1_000,
        durationMs: 100,
        receiptIds: ["receipt"],
        evidenceRefs: ["evidence"],
        replay: {
          deterministicEnvelope: true,
          capturesInput: true,
          capturesOutput: true,
          capturesPolicyDecision: true,
          fixtureRef: "fixture",
          determinism: "deterministic",
          redactionPolicy: "none",
        },
      },
    ],
    harnessShadowComparisons: [
      {
        liveAttemptId: "live",
        shadowAttemptId: "shadow",
        workflowNodeId: "model",
        componentKind: "planner",
        divergence: "matched",
        blocking: false,
        summary: "matched",
        evidenceRefs: ["evidence"],
      },
    ],
  } as unknown as WorkflowRunResult;

  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: selected,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.interrupt?.prompt, "Approve?");
  assert.equal(model.interruptPreview?.binding?.ref, "tool:write");
  assert.equal(model.harnessAttempts[0]?.attemptId, "attempt");
  assert.equal(model.harnessComparisons[0]?.divergence, "matched");
});
