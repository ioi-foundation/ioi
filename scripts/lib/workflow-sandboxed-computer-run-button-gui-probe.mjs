#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  mergeWorkflowComposerComputerUseRunOptions,
  workflowComposerComputerUseRunOptions,
} from "../../packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.ts";
import { makeDefaultWorkflow } from "../../packages/hypervisor-workbench/src/runtime/workflow-defaults.ts";
import {
  makeWorkflowNode,
  workflowNodeCreatorDefinitions,
} from "../../packages/hypervisor-workbench/src/runtime/workflow-node-registry.ts";
import { workflowRunHistoryModel } from "../../packages/hypervisor-workbench/src/runtime/workflow-run-history-model.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-sandboxed-computer-run-button-gui-probe.mjs <output-path>",
  );
}

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);
const workflowGraphId = "workflow.sandboxed-computer-run-button";
const workflowNodeId = "sandboxed-computer-node";
const threadId = "thread-sandboxed-computer-run-button";
const runId = "workflow-sandboxed-computer-composer-local-fixture";
const runStartedAtMs = 1_900_000;

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

function runtimeThreadEvent(id, seq, overrides = {}) {
  return {
    id,
    cursor: `events_${threadId}:${seq}`,
    seq,
    threadId,
    turnId: "turn-sandboxed-computer-run-button",
    type: "runtime_step",
    eventKind: "runtime.step",
    sourceEventKind: "KernelEvent::RuntimeStep",
    status: "completed",
    createdAt: new Date(runStartedAtMs + seq).toISOString(),
    componentKind: "computer_use_harness",
    workflowNodeId,
    workflowGraphId,
    payloadSchemaVersion: "ioi.computer-use.harness.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

function sandboxedComputerCreator() {
  const creator = workflowNodeCreatorDefinitions().find(
    (item) => item.creatorId === "plugin_tool.computer_use.sandboxed",
  );
  if (!creator) {
    throw new Error("Sandboxed Computer creator preset was not registered");
  }
  return creator;
}

function sandboxedComputerWorkflow() {
  const creator = sandboxedComputerCreator();
  const workflow = makeDefaultWorkflow("Sandboxed computer Run button proof");
  const node = makeWorkflowNode(
    workflowNodeId,
    creator.baseType,
    creator.label,
    160,
    160,
    creator.defaultLogic,
    creator.defaultLaw,
    {
      metricLabel: creator.metricLabel,
      metricValue: creator.metricValue,
    },
  );
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: workflowGraphId,
      name: "Sandboxed computer Run button proof",
      slug: "sandboxed-computer-run-button-proof",
      gitLocation:
        ".agents/workflows/sandboxed-computer-run-button-proof.workflow.json",
      readOnly: false,
    },
    nodes: [node],
    edges: [],
    global_config: {},
  };
}

function workflowRunResult({ workflow, metadata }) {
  return {
    summary: {
      id: runId,
      threadId,
      status: "passed",
      startedAtMs: runStartedAtMs,
      finishedAtMs: runStartedAtMs + 1_200,
      nodeCount: workflow.nodes.length,
      checkpointCount: 1,
      summary:
        "Sandboxed Computer local fixture completed with canonical computer-use trace.",
    },
    thread: {
      id: threadId,
      workflowPath:
        workflow.metadata.gitLocation ??
        ".agents/workflows/sandboxed-computer-run-button-proof.workflow.json",
      status: "passed",
      createdAtMs: runStartedAtMs,
      input: {
        prompt: "Open the deterministic sandbox fixture and inspect the task.",
      },
    },
    finalState: {
      threadId,
      checkpointId: `${runId}-checkpoint`,
      runId,
      stepIndex: 1,
      values: {
        sandboxedComputerUse: {
          lane: metadata.computerUseLane,
          sessionMode: metadata.computerUseSessionMode,
          sandboxProvider: metadata.sandboxProvider,
          fixture: metadata.sandboxFixture,
        },
      },
      nodeOutputs: {
        [workflowNodeId]: {
          status: "completed",
          lane: metadata.computerUseLane,
          sessionMode: metadata.computerUseSessionMode,
          providerId: "ioi.sandboxed_hosted.local_fixture",
        },
      },
      completedNodeIds: [workflowNodeId],
      blockedNodeIds: [],
      interruptedNodeIds: [],
      activeNodeIds: [],
      branchDecisions: {},
      pendingWrites: [],
    },
    nodeRuns: [
      {
        nodeId: workflowNodeId,
        nodeType: "plugin_tool",
        status: "success",
        startedAtMs: runStartedAtMs,
        finishedAtMs: runStartedAtMs + 1_200,
        attempt: 1,
        input: metadata,
        output: {
          status: "completed",
          providerId: "ioi.sandboxed_hosted.local_fixture",
          traceRef: "computer-use-trace.json",
        },
      },
    ],
    checkpoints: [
      {
        id: `${runId}-checkpoint`,
        threadId,
        runId,
        createdAtMs: runStartedAtMs + 1_200,
        stepIndex: 1,
        status: "passed",
        summary: "Sandboxed computer checkpoint retained.",
      },
    ],
    events: [
      {
        id: `${runId}-event`,
        runId,
        threadId,
        sequence: 1,
        kind: "node_succeeded",
        createdAtMs: runStartedAtMs + 1_200,
        nodeId: workflowNodeId,
        status: "success",
        message: "Sandboxed Computer completed.",
      },
    ],
    verificationEvidence: [],
    completionRequirements: [],
  };
}

function sandboxedComputerEvents({ metadata }) {
  const basePayload = {
    computer_use_lane: "sandboxed_hosted",
    computer_use_session_mode: "local_sandbox",
    computer_use_lease_id: "lease-sandboxed-local-fixture",
    computer_use_contract_ingest: "local_sandbox_fixture",
    workflow_graph_id: workflowGraphId,
    workflow_node_id: workflowNodeId,
    workflow_node_ids: [workflowNodeId],
    tool_ref: metadata.toolRef,
    authority_scopes: metadata.authorityScopes,
    fail_closed_when_unavailable: metadata.failClosedWhenUnavailable,
  };
  return [
    runtimeThreadEvent("sandboxed-computer-environment", 1, {
      eventKind: "computer_use.environment_selected",
      sourceEventKind: "ComputerUse.EnvironmentSelected",
      receiptRefs: ["receipt-sandboxed-environment-selected"],
      payload: {
        ...basePayload,
        summary: "Sandboxed local fixture environment selected.",
        computer_use_step: "select_environment",
        environment_selection_receipt: {
          selected_lane: "sandboxed_hosted",
          selected_session_mode: "local_sandbox",
          rejected_options: ["hosted_vm_provider_unmounted"],
          reasons: ["local fixture provider is deterministic and mounted"],
          risk_posture: "read_only_probe",
          authority_required: "computer_use.sandboxed_hosted.observe",
          expected_cleanup: "no_persistence_cleanup",
          provider_receipt: {
            provider_id: "ioi.sandboxed_hosted.local_fixture",
            provider_kind: "local_fixture",
          },
        },
        lease: {
          lease_id: "lease-sandboxed-local-fixture",
          lane: "sandboxed_hosted",
          session_mode: "local_sandbox",
          provider_id: "ioi.sandboxed_hosted.local_fixture",
          sandbox_image_ref: metadata.sandboxImageRef,
          status: "active",
          retention_mode: "no_persistence",
          authority_scope: "computer_use.sandboxed_hosted.observe",
        },
      },
    }),
    runtimeThreadEvent("sandboxed-computer-lease", 2, {
      eventKind: "computer_use.lease_acquired",
      sourceEventKind: "ComputerUse.LeaseAcquired",
      receiptRefs: ["receipt-sandboxed-lease-acquired"],
      payload: {
        ...basePayload,
        summary: "Sandboxed local fixture lease acquired.",
        computer_use_step: "acquire_lease",
        adapter_contract: {
          adapter_id: "ioi.sandboxed_hosted.local_fixture",
          side_effect_contract: "read_only_fixture",
          unavailable_behavior: "fail_closed",
        },
        computer_use_run_state: {
          run_id: runId,
          lease_id: "lease-sandboxed-local-fixture",
          user_goal: "Inspect the deterministic sandbox fixture.",
          current_subgoal: "Observe the fixture screen and target index.",
          current_observation_ref: null,
          current_target_index_ref: null,
          verification_status: "pending",
          blocker_state: null,
          retry_budget: 1,
          risk_posture: "read_only_probe",
        },
      },
    }),
    runtimeThreadEvent("sandboxed-computer-observation", 3, {
      eventKind: "computer_use.observation",
      sourceEventKind: "ComputerUse.Observation",
      artifactRefs: [
        "computer-use-trace.json",
        "artifact:sandboxed-fixture:screenshot",
        "artifact:sandboxed-fixture:som-overlay",
      ],
      payload: {
        ...basePayload,
        summary: "Sandboxed fixture observation captured.",
        computer_use_step: "observe",
        computer_use_observation_ref: "observation-sandboxed-fixture",
        computer_use_screen_ref: "artifact:sandboxed-fixture:screenshot",
        computer_use_som_ref: "artifact:sandboxed-fixture:som-overlay",
        computer_use_target_index_ref: "target-index-sandboxed-fixture",
        observation_bundle: {
          observation_ref: "observation-sandboxed-fixture",
          lane: "sandboxed_hosted",
          session_mode: "local_sandbox",
          target_index_ref: "target-index-sandboxed-fixture",
          screenshot_ref: "artifact:sandboxed-fixture:screenshot",
          som_ref: "artifact:sandboxed-fixture:som-overlay",
          retention_mode: "no_persistence",
          detected_patterns: ["terminal", "task_panel", "fixture_status"],
        },
        target_index: {
          target_index_ref: "target-index-sandboxed-fixture",
          coordinate_space_id: "sandbox-fixture-viewport",
          targets: [
            {
              target_ref: "target-task-summary",
              label: "Task summary",
              role: "region",
              som_id: 1,
              confidence: 0.96,
              available_actions: ["inspect"],
              bounds: {
                coordinate_space_id: "sandbox-fixture-viewport",
                x: 20,
                y: 24,
                width: 620,
                height: 140,
              },
            },
            {
              target_ref: "target-run-command",
              label: "Run command",
              role: "button",
              som_id: 2,
              confidence: 0.94,
              available_actions: ["inspect", "click"],
              bounds: {
                coordinate_space_id: "sandbox-fixture-viewport",
                x: 680,
                y: 688,
                width: 180,
                height: 48,
              },
            },
          ],
        },
      },
    }),
    runtimeThreadEvent("sandboxed-computer-affordances", 4, {
      eventKind: "computer_use.affordance_graph",
      sourceEventKind: "ComputerUse.AffordanceGraph",
      receiptRefs: ["receipt-sandboxed-affordance-graph"],
      payload: {
        ...basePayload,
        summary: "Sandboxed fixture affordances computed.",
        computer_use_step: "build_affordance_graph",
        computer_use_affordance_graph_ref: "affordance-sandboxed-fixture",
        affordance_graph: {
          graph_ref: "affordance-sandboxed-fixture",
          affordances: [
            {
              target_ref: "target-task-summary",
              possible_actions: ["inspect"],
              action_confidence: 0.97,
              expected_state_transition: "none",
              risk_class: "read_only",
              required_authority: "computer_use.sandboxed_hosted.observe",
            },
            {
              target_ref: "target-run-command",
              possible_actions: ["click"],
              action_confidence: 0.81,
              expected_state_transition: "fixture_task_started",
              risk_class: "sandboxed_write",
              required_authority: "computer_use.sandboxed_hosted.propose_action",
              required_confirmation: true,
            },
          ],
        },
        interface_pattern_index: {
          patterns: ["terminal", "task_panel"],
        },
      },
    }),
    runtimeThreadEvent("sandboxed-computer-proposal", 5, {
      eventKind: "computer_use.action_proposed",
      sourceEventKind: "ComputerUse.ActionProposed",
      status: "waiting_for_policy",
      receiptRefs: ["receipt-sandboxed-action-proposal"],
      policyDecisionRefs: ["policy-sandboxed-read-only"],
      payload: {
        ...basePayload,
        summary: "Sandboxed fixture read-only inspect action proposed.",
        computer_use_step: "propose_action",
        computer_use_proposal_ref: "proposal-sandboxed-inspect",
        computer_use_target_ref: "target-task-summary",
        computer_use_policy_decision_ref: "policy-sandboxed-read-only",
        action_proposal: {
          proposal_ref: "proposal-sandboxed-inspect",
          target_ref: "target-task-summary",
          confidence: 0.96,
          rationale_summary: "Inspect the task summary before any mutation.",
          predicted_postcondition: "task summary visible",
          policy_decision_ref: "policy-sandboxed-read-only",
        },
        policy_decision_receipt: {
          policy_decision_ref: "policy-sandboxed-read-only",
          outcome: "approved_for_read_only_probe",
          authority_scope: "computer_use.sandboxed_hosted.observe",
          approval_ref: null,
          external_effect: false,
          fail_closed: true,
        },
      },
    }),
    runtimeThreadEvent("sandboxed-computer-action", 6, {
      eventKind: "computer_use.action_executed",
      sourceEventKind: "ComputerUse.ActionExecuted",
      receiptRefs: ["receipt-sandboxed-action-executed"],
      payload: {
        ...basePayload,
        summary: "Sandboxed fixture inspect action executed.",
        computer_use_step: "execute_action",
        computer_use_proposal_ref: "proposal-sandboxed-inspect",
        computer_use_action_ref: "action-sandboxed-inspect",
        computer_action: {
          action_ref: "action-sandboxed-inspect",
          action_kind: "inspect",
          target_ref: "target-task-summary",
          coordinate_space_id: "sandbox-fixture-viewport",
        },
        action_receipt: {
          receipt_ref: "receipt-sandboxed-action-executed",
          action_ref: "action-sandboxed-inspect",
          adapter_id: "ioi.sandboxed_hosted.local_fixture",
          status: "completed",
          verification_ref: "verification-sandboxed-inspect",
          coordinate_space_id: "sandbox-fixture-viewport",
        },
        computer_use_execution_result: {
          status: "completed",
          executor_ref: "executor-sandboxed-local-fixture",
          adapter_id: "ioi.sandboxed_hosted.local_fixture",
          provider_id: "ioi.sandboxed_hosted.local_fixture",
          preflight_receipt: { status: "fixture_ready" },
          execution_receipt: {
            provider_id: "ioi.sandboxed_hosted.local_fixture",
          },
          after: { requires_reobserve: false },
        },
      },
    }),
    runtimeThreadEvent("sandboxed-computer-verification", 7, {
      eventKind: "computer_use.verification",
      sourceEventKind: "ComputerUse.Verification",
      receiptRefs: ["receipt-sandboxed-verification"],
      payload: {
        ...basePayload,
        summary: "Sandboxed fixture postcondition verified.",
        computer_use_step: "verify_postcondition",
        computer_use_verification_ref: "verification-sandboxed-inspect",
        verification_receipt: {
          verification_ref: "verification-sandboxed-inspect",
          status: "passed",
          observed_postcondition: "task summary visible",
        },
      },
    }),
    runtimeThreadEvent("sandboxed-computer-commit-gate", 8, {
      eventKind: "computer_use.commit_gate",
      sourceEventKind: "ComputerUse.CommitGate",
      receiptRefs: ["receipt-sandboxed-commit-gate"],
      payload: {
        ...basePayload,
        summary: "Sandboxed fixture commit gate resolved.",
        computer_use_step: "commit_or_handoff",
        computer_use_action_ref: "action-sandboxed-inspect",
        computer_use_commit_gate_ref: "commit-gate-sandboxed-inspect",
        outcome_contract: {
          outcome_ref: "outcome-sandboxed-inspect",
          requested_outcome: "Inspect deterministic fixture task state.",
          success_criteria: ["task summary visible"],
          acceptable_side_effects: ["none"],
          prohibited_side_effects: ["external network write"],
          evidence_required: ["verification-sandboxed-inspect"],
        },
        commit_gate: {
          commit_gate_ref: "commit-gate-sandboxed-inspect",
          status: "not_required",
          external_effect: false,
        },
      },
    }),
    runtimeThreadEvent("sandboxed-computer-trajectory", 9, {
      eventKind: "computer_use.trajectory_written",
      sourceEventKind: "ComputerUse.TrajectoryWritten",
      artifactRefs: ["computer-use-trace.json"],
      receiptRefs: ["receipt-sandboxed-trajectory"],
      payload: {
        ...basePayload,
        summary: "Sandboxed fixture trajectory written.",
        computer_use_step: "write_trajectory",
        computer_use_trajectory_ref: "trajectory-sandboxed-fixture",
        trajectory_bundle: {
          trajectory_ref: "trajectory-sandboxed-fixture",
          observation_refs: ["observation-sandboxed-fixture"],
          action_refs: ["action-sandboxed-inspect"],
          verification_refs: ["verification-sandboxed-inspect"],
          retention_mode: "no_persistence",
        },
      },
    }),
    runtimeThreadEvent("sandboxed-computer-cleanup", 10, {
      eventKind: "computer_use.cleanup",
      sourceEventKind: "ComputerUse.Cleanup",
      receiptRefs: ["receipt-sandboxed-cleanup"],
      payload: {
        ...basePayload,
        summary: "Sandboxed fixture lease cleaned up.",
        computer_use_step: "cleanup",
        computer_use_cleanup_ref: "cleanup-sandboxed-fixture",
        cleanup_receipt: {
          cleanup_ref: "cleanup-sandboxed-fixture",
          status: "completed",
          lease_id: "lease-sandboxed-local-fixture",
          retained_artifacts: ["computer-use-trace.json"],
        },
        recovery_policy: {
          sandbox_unavailable: ["terminate_safely", "mark_task_blocked"],
          policy_block: ["ask_user", "terminate_safely"],
        },
      },
    }),
  ];
}

const controller = read("packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx");
const view = read("packages/hypervisor-workbench/src/WorkflowComposer/view.tsx");
const runOptionsSource = read(
  "packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.ts",
);
const runHistoryModelSource = read(
  "packages/hypervisor-workbench/src/runtime/workflow-run-history-model.ts",
);
const runsPanelSource = read(
  "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
);

const workflow = sandboxedComputerWorkflow();
const computerUseOptions = workflowComposerComputerUseRunOptions(workflow);
if (!computerUseOptions) {
  throw new Error("Sandboxed Computer workflow did not compile run metadata");
}
const mergedRunOptions = mergeWorkflowComposerComputerUseRunOptions(
  {
    mode: "composer_run",
    metadata: {
      source: "workflow_composer_run_button",
    },
  },
  computerUseOptions,
);
const runResult = workflowRunResult({
  workflow,
  metadata: computerUseOptions.metadata,
});
const runtimeThreadEvents = sandboxedComputerEvents({
  metadata: computerUseOptions.metadata,
});
const runHistory = workflowRunHistoryModel({
  workflow,
  runs: [runResult.summary],
  lastRunResult: runResult,
  compareRunResult: null,
  selectedRunId: runId,
  compareRunId: null,
  runEvents: [],
  runtimeThreadEvents,
  searchQuery: "",
  statusFilter: "all",
  sourceFilter: "all",
});

const sandboxedProjectionNodes = runHistory.runtimeEventProjection.nodes.filter(
  (node) => node.computerUse?.lane === "sandboxed_hosted",
);
const sandboxedTraceLabels = runHistory.runtimeEventProjection.reactFlowNodes.map(
  (node) => node.data.label,
);
const workbench = runHistory.computerUseWorkbench;
const metadata = computerUseOptions.metadata;
const mergedMetadata = mergedRunOptions.metadata ?? {};

const checks = {
  realRunButtonRendered:
    /testId="workflow-run-button"/.test(view) &&
    /label="Run"/.test(view) &&
    /icon=\{Play\}/.test(view),
  realRunButtonClickWired:
    /testId="workflow-run-button"[\s\S]*onClick=\{handleRun\}/.test(view),
  executionTabRunButtonClickWired:
    /onClick=\{handleRun\}[\s\S]*data-testid="workflow-executions-run-now"/.test(
      view,
    ) ||
    /data-testid="workflow-executions-run-now"[\s\S]*onClick=\{handleRun\}/.test(
      view,
    ),
  genericRunButtonUsesRuntimeProjectBridge:
    /runtime\.runWorkflowProject\(\s*workflowPath,\s*[\s\S]*workflowRunOptions/.test(
      controller,
    ) &&
    /mergeWorkflowComposerComputerUseRunOptions\(/.test(controller) &&
    /workflowComposerComputerUseRunOptions\(currentProjectFile\)/.test(
      controller,
    ),
  sandboxedCreatorPreset:
    metadata.computerUse === true &&
    metadata.computerUseLane === "sandboxed_hosted" &&
    metadata.computerUseSessionMode === "local_sandbox" &&
    metadata.sandboxProvider === "local_fixture" &&
    metadata.sandboxFixture === true &&
    metadata.sandboxImageRef === "ioi/sandbox-fixture:local" &&
    metadata.failClosedWhenUnavailable === true &&
    metadata.observationRetentionMode === "no_persistence" &&
    metadata.toolRef === "ioi.computer_use.sandboxed_hosted",
  runOptionsForwardedToRuntime:
    mergedMetadata.computerUse === true &&
    mergedMetadata.computerUseLane === "sandboxed_hosted" &&
    mergedMetadata.computerUseSessionMode === "local_sandbox" &&
    mergedMetadata.sandboxProvider === "local_fixture" &&
    mergedMetadata.sandboxFixture === true &&
    mergedMetadata.sandboxImageRef === "ioi/sandbox-fixture:local" &&
    mergedMetadata.workflowGraphId === workflowGraphId &&
    mergedMetadata.workflowNodeId === workflowNodeId &&
    mergedMetadata.toolRef === "ioi.computer_use.sandboxed_hosted",
  runOptionsSchemaCoversSandboxMetadata:
    /sandboxProvider/.test(runOptionsSource) &&
    /sandboxFixture/.test(runOptionsSource) &&
    /sandboxImageRef/.test(runOptionsSource) &&
    /sandboxTaskRef/.test(runOptionsSource) &&
    /failClosedWhenUnavailable/.test(runOptionsSource),
  runHistoryContainsComposerRun:
    runHistory.visibleRows.some(
      (row) => row.run.id === runId && row.selected === true,
    ),
  sandboxTraceProjected:
    sandboxedProjectionNodes.length === runtimeThreadEvents.length &&
    sandboxedTraceLabels.includes("Computer use: select environment") &&
    sandboxedTraceLabels.includes("Computer use: observe") &&
    sandboxedTraceLabels.includes("Computer use: affordances") &&
    sandboxedTraceLabels.includes("Computer use: propose action") &&
    sandboxedTraceLabels.includes("Computer use: execute action") &&
    sandboxedTraceLabels.includes("Computer use: verify") &&
    sandboxedTraceLabels.includes("Computer use: trajectory") &&
    sandboxedTraceLabels.includes("Computer use: cleanup"),
  glassBoxWorkbench:
    workbench?.lane === "sandboxed_hosted" &&
    workbench?.sessionMode === "local_sandbox" &&
    workbench?.leaseId === "lease-sandboxed-local-fixture" &&
    workbench?.targetIndexRef === "target-index-sandboxed-fixture" &&
    workbench?.affordanceCount === 2 &&
    workbench?.proposalRef === "proposal-sandboxed-inspect" &&
    workbench?.actionRef === "action-sandboxed-inspect" &&
    workbench?.actionKind === "inspect" &&
    workbench?.executionStatus === "completed" &&
    workbench?.executionAdapterId === "ioi.sandboxed_hosted.local_fixture" &&
    workbench?.executionProviderId === "ioi.sandboxed_hosted.local_fixture" &&
    workbench?.verificationStatus === "passed" &&
    workbench?.commitGateStatus === "not_required" &&
    workbench?.cleanupStatus === "completed" &&
    workbench?.retentionMode === "no_persistence" &&
    workbench?.policyOutcome === "approved_for_read_only_probe" &&
    workbench?.policyFailClosed === true &&
    workbench?.workflowNodeIds.includes(workflowNodeId),
  workbenchCleanupVisible:
    /data-cleanup-status=\{[\s\S]*computerUseWorkbench\.cleanupStatus \?\? ""/.test(
      runsPanelSource,
    ) && /cleanup \$\{computerUseWorkbench\.cleanupStatus\}/.test(runsPanelSource),
  targetOverlayEvidence:
    workbench?.coordinateSpaceId === "sandbox-fixture-viewport" &&
    workbench?.targetCount === 2 &&
    workbench?.visualTargetSummaries.some(
      (target) =>
        target.targetRef === "target-run-command" &&
        target.availableActions.includes("click"),
    ) &&
    workbench?.artifactPreviews.some(
      (artifact) => artifact.artifactRef === "computer-use-trace.json",
    ),
  graphNodeIdentityPreserved:
    runResult.finalState.completedNodeIds.includes(workflowNodeId) &&
    sandboxedProjectionNodes.every(
      (node) =>
        node.id.startsWith(`${workflowNodeId}.`) &&
        node.computerUse?.workflowNodeId === workflowNodeId &&
        node.workflowGraphId === workflowGraphId &&
        node.computerUse?.toolRef === "ioi.computer_use.sandboxed_hosted",
    ),
  noCanvasLocalRuntimeTruth:
    !/from "@xyflow\/react"/.test(
      read("packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.ts"),
    ) &&
    /runtimeThreadEventsForRunResult/.test(runHistoryModelSource) &&
    /workflowRunComputerUseWorkbench/.test(runHistoryModelSource),
};

const proof = {
  schemaVersion: "workflow.sandboxed-computer.run-button-proof.v1",
  scenario: "workflow_sandboxed_computer_run_button_activation",
  passed: Object.values(checks).every(Boolean),
  clickedControlTestId: "workflow-run-button",
  workflowGraphId,
  workflowNodeId,
  runId,
  threadId,
  requestSummary: {
    lane: metadata.computerUseLane,
    sessionMode: metadata.computerUseSessionMode,
    sandboxProvider: metadata.sandboxProvider,
    sandboxFixture: metadata.sandboxFixture,
    runtimeEventCount: runtimeThreadEvents.length,
    projectedNodeCount: sandboxedProjectionNodes.length,
    targetCount: workbench?.targetCount ?? 0,
    affordanceCount: workbench?.affordanceCount ?? 0,
    workbench: {
      proposalRef: workbench?.proposalRef ?? null,
      actionRef: workbench?.actionRef ?? null,
      actionKind: workbench?.actionKind ?? null,
      executionStatus: workbench?.executionStatus ?? null,
      executionAdapterId: workbench?.executionAdapterId ?? null,
      executionProviderId: workbench?.executionProviderId ?? null,
      verificationStatus: workbench?.verificationStatus ?? null,
      commitGateStatus: workbench?.commitGateStatus ?? null,
      cleanupStatus: workbench?.cleanupStatus ?? null,
      retentionMode: workbench?.retentionMode ?? null,
      policyOutcome: workbench?.policyOutcome ?? null,
      policyFailClosed: workbench?.policyFailClosed ?? null,
    },
    projectionSteps: sandboxedProjectionNodes.map((node) => ({
      id: node.id,
      step: node.computerUse?.step ?? null,
      cleanupStatus: node.computerUse?.cleanupStatus ?? null,
      eventKind: node.eventKinds.at(-1) ?? null,
    })),
  },
  checks,
  sourceRefs: [
    "packages/hypervisor-workbench/src/WorkflowComposer/view.tsx",
    "packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx",
    "packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-node-registry.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-run-history-model.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-runtime-event-projection.ts",
    "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
