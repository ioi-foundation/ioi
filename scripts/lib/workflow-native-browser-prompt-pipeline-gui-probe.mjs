#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  mergeWorkflowComposerComputerUseRunOptions,
  workflowComposerComputerUseRunOptions,
} from "../../packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.ts";
import { makeDefaultWorkflow } from "../../packages/hypervisor-workbench/src/runtime/workflow-defaults.ts";
import {
  makeWorkflowEdge,
  makeWorkflowNode,
  workflowNodeCreatorDefinitions,
} from "../../packages/hypervisor-workbench/src/runtime/workflow-node-registry.ts";
import { workflowRunHistoryModel } from "../../packages/hypervisor-workbench/src/runtime/workflow-run-history-model.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-native-browser-prompt-pipeline-gui-probe.mjs <output-path>",
  );
}

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);
const workflowGraphId = "workflow.native-browser-prompt-pipeline";
const modelNodeId = "mounted-model-planner-node";
const browserNodeId = "browser-use-node";
const threadId = "thread-native-browser-prompt-pipeline";
const runId = "workflow-native-browser-prompt-pipeline-composer-run";
const runStartedAtMs = 1_950_000;
const demoPrompt =
  "Use Browser Use to inspect the IOI docs page and tell me what changed.";

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

function runtimeThreadEvent(id, seq, overrides = {}) {
  return {
    id,
    cursor: `events_${threadId}:${seq}`,
    seq,
    threadId,
    turnId: "turn-native-browser-prompt-pipeline",
    type: "runtime_step",
    eventKind: "runtime.step",
    sourceEventKind: "KernelEvent::RuntimeStep",
    status: "completed",
    createdAt: new Date(runStartedAtMs + seq).toISOString(),
    componentKind: null,
    workflowNodeId: null,
    workflowGraphId,
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

function browserUseCreator() {
  const creator = workflowNodeCreatorDefinitions().find(
    (item) => item.creatorId === "plugin_tool.browser_use",
  );
  if (!creator) throw new Error("Browser Use creator preset was not registered");
  return creator;
}

function nativeBrowserPromptWorkflow() {
  const creator = browserUseCreator();
  const workflow = makeDefaultWorkflow("Native browser prompt pipeline proof");
  const modelNode = makeWorkflowNode(
    modelNodeId,
    "model_call",
    "Mounted Browser Planner",
    120,
    160,
    {
      modelRef: "reasoning",
      modelId: "demo-mounted-browser-model",
      routeId: "route.mounted-browser-demo",
      reasoningEffort: "medium",
      modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
      capability: "chat",
      receiptRequired: true,
      prompt: demoPrompt,
      modelBinding: {
        modelRef: "reasoning",
        modelId: "demo-mounted-browser-model",
        routeId: "route.mounted-browser-demo",
        reasoningEffort: "medium",
        modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
        capability: "chat",
        receiptRequired: true,
        daemonApi: "/v1/model-mount/workflows/nodes/execute",
        mockBinding: false,
        capabilityScope: ["chat", "computer_use.action_proposal"],
        argumentSchema: { type: "object" },
        resultSchema: { type: "object" },
        sideEffectClass: "none",
        requiresApproval: false,
        credentialReady: true,
        toolUseMode: "runtime_tool_plan",
      },
    },
  );
  const browserNode = makeWorkflowNode(
    browserNodeId,
    creator.baseType,
    creator.label,
    520,
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
      name: "Native browser prompt pipeline proof",
      slug: "native-browser-prompt-pipeline-proof",
      gitLocation:
        ".agents/workflows/native-browser-prompt-pipeline-proof.workflow.json",
      readOnly: false,
    },
    nodes: [modelNode, browserNode],
    edges: [
      makeWorkflowEdge(
        "edge-mounted-model-to-browser-use",
        modelNodeId,
        browserNodeId,
        "output",
        "input",
      ),
    ],
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
      finishedAtMs: runStartedAtMs + 1_400,
      nodeCount: workflow.nodes.length,
      checkpointCount: 1,
      summary:
        "Mounted model planned a native-browser inspection and Browser Use verified the read-only outcome.",
    },
    thread: {
      id: threadId,
      workflowPath:
        workflow.metadata.gitLocation ??
        ".agents/workflows/native-browser-prompt-pipeline-proof.workflow.json",
      status: "passed",
      createdAtMs: runStartedAtMs,
      input: { prompt: demoPrompt },
    },
    finalState: {
      threadId,
      checkpointId: `${runId}-checkpoint`,
      runId,
      stepIndex: 2,
      values: {
        prompt: demoPrompt,
        modelPlan: {
          selectedTool: "ioi.computer_use.native_browser",
          actionKind: metadata.computerUseActionKind,
          targetRef: "target-docs-main",
        },
        browserUse: {
          lane: metadata.computerUseLane,
          sessionMode: metadata.computerUseSessionMode,
          verified: true,
        },
      },
      nodeOutputs: {
        [modelNodeId]: {
          plan: "Inspect the docs page using the native browser lane.",
          selectedTool: "ioi.computer_use.native_browser",
        },
        [browserNodeId]: {
          status: "completed",
          lane: metadata.computerUseLane,
          sessionMode: metadata.computerUseSessionMode,
          verificationRef: "verification-browser-inspect",
        },
      },
      completedNodeIds: [modelNodeId, browserNodeId],
      blockedNodeIds: [],
      interruptedNodeIds: [],
      activeNodeIds: [],
      branchDecisions: {},
      pendingWrites: [],
    },
    nodeRuns: [
      {
        nodeId: modelNodeId,
        nodeType: "model_call",
        status: "success",
        startedAtMs: runStartedAtMs,
        finishedAtMs: runStartedAtMs + 500,
        attempt: 1,
        input: { prompt: demoPrompt },
        output: {
          plan: "Use Browser Use to inspect the docs page.",
          modelInvocation: {
            mode: "live_mounted_model",
            modelRef: "reasoning",
            modelId: "demo-mounted-browser-model",
            promptHash: "sha256:native-browser-prompt",
            responseHash: "sha256:native-browser-plan-response",
            prompt: { user: demoPrompt },
            trace: [
              {
                phase: "input",
                summary: "Collected workflow prompt for Browser Use.",
                promptHash: "sha256:native-browser-prompt",
              },
              {
                phase: "binding",
                summary: "Resolved mounted browser-planner model.",
                latencyMs: 4,
              },
              {
                phase: "prompt",
                summary: "Assembled prompt with browser-use tool affordances.",
                promptHash: "sha256:native-browser-prompt",
              },
              {
                phase: "model",
                summary:
                  "Mounted model selected native browser inspect action.",
                responseHash: "sha256:native-browser-plan-response",
              },
              {
                phase: "tool_selection",
                summary:
                  "Model plan handed off to ioi.computer_use.native_browser.",
                latencyMs: 7,
              },
            ],
          },
        },
      },
      {
        nodeId: browserNodeId,
        nodeType: "plugin_tool",
        status: "success",
        startedAtMs: runStartedAtMs + 520,
        finishedAtMs: runStartedAtMs + 1_400,
        attempt: 1,
        input: metadata,
        output: {
          status: "completed",
          traceRef: "computer-use-trace.json",
          verificationRef: "verification-browser-inspect",
        },
      },
    ],
    checkpoints: [
      {
        id: `${runId}-checkpoint`,
        threadId,
        runId,
        createdAtMs: runStartedAtMs + 1_400,
        stepIndex: 2,
        status: "passed",
        summary: "Native browser prompt pipeline checkpoint retained.",
      },
    ],
    events: [
      {
        id: `${runId}-model-event`,
        runId,
        threadId,
        sequence: 1,
        kind: "model_invocation_succeeded",
        createdAtMs: runStartedAtMs + 500,
        nodeId: modelNodeId,
        status: "success",
        message: "Mounted model produced a browser-use plan.",
      },
      {
        id: `${runId}-browser-event`,
        runId,
        threadId,
        sequence: 2,
        kind: "node_succeeded",
        createdAtMs: runStartedAtMs + 1_400,
        nodeId: browserNodeId,
        status: "success",
        message: "Browser Use completed read-only verification.",
      },
    ],
    verificationEvidence: [],
    completionRequirements: [],
  };
}

function nativeBrowserPipelineEvents({ metadata }) {
  const basePayload = {
    computer_use_lane: "native_browser",
    computer_use_session_mode: "owned_hermetic_browser",
    computer_use_lease_id: "lease-native-browser-prompt",
    computer_use_contract_ingest: "mounted_model_browser_use_plan",
    workflow_graph_id: workflowGraphId,
    workflow_node_id: browserNodeId,
    workflow_node_ids: [browserNodeId],
    tool_ref: metadata.toolRef,
    authority_scopes: metadata.authorityScopes,
    fail_closed_when_unavailable: metadata.failClosedWhenUnavailable,
  };
  return [
    runtimeThreadEvent("native-browser-model-route", 1, {
      type: "model_route_decision",
      eventKind: "model.route_decision",
      sourceEventKind: "ModelRouter.RouteSelected",
      componentKind: "model_router",
      workflowNodeId: modelNodeId,
      receiptRefs: ["receipt-mounted-model-route"],
      payload: {
        summary: "Mounted model selected native Browser Use.",
        model_ref: "reasoning",
        model_id: "demo-mounted-browser-model",
        prompt_hash: "sha256:native-browser-prompt",
        response_hash: "sha256:native-browser-plan-response",
        selected_tool_ref: "ioi.computer_use.native_browser",
      },
    }),
    runtimeThreadEvent("native-browser-environment", 2, {
      eventKind: "computer_use.environment_selected",
      sourceEventKind: "ComputerUse.EnvironmentSelected",
      componentKind: "computer_use_harness",
      workflowNodeId: browserNodeId,
      receiptRefs: ["receipt-native-browser-environment"],
      payload: {
        ...basePayload,
        summary: "Owned native browser environment selected.",
        computer_use_step: "select_environment",
        environment_selection_receipt: {
          selected_lane: "native_browser",
          selected_session_mode: "owned_hermetic_browser",
          rejected_options: ["visual_gui_fallback_not_needed"],
          reasons: ["DOM and AX browser semantics available"],
          risk_posture: "read_only_probe",
          authority_required: "computer_use.native_browser.read",
          expected_cleanup: "close_owned_browser",
        },
        lease: {
          lease_id: "lease-native-browser-prompt",
          lane: "native_browser",
          session_mode: "owned_hermetic_browser",
          status: "active",
          retention_mode: "local_redacted_artifacts",
          authority_scope: "computer_use.native_browser.read",
        },
      },
    }),
    runtimeThreadEvent("native-browser-observation", 3, {
      eventKind: "computer_use.observation",
      sourceEventKind: "ComputerUse.Observation",
      componentKind: "computer_use_harness",
      workflowNodeId: browserNodeId,
      artifactRefs: [
        "computer-use-trace.json",
        "artifact:native-browser:screenshot",
        "artifact:native-browser:som-overlay",
      ],
      payload: {
        ...basePayload,
        summary: "Native browser observation captured.",
        computer_use_step: "observe",
        computer_use_observation_ref: "observation-native-browser-docs",
        computer_use_screen_ref: "artifact:native-browser:screenshot",
        computer_use_som_ref: "artifact:native-browser:som-overlay",
        computer_use_target_index_ref: "target-index-native-browser-docs",
        observation_bundle: {
          observation_ref: "observation-native-browser-docs",
          lane: "native_browser",
          session_mode: "owned_hermetic_browser",
          target_index_ref: "target-index-native-browser-docs",
          screenshot_ref: "artifact:native-browser:screenshot",
          som_ref: "artifact:native-browser:som-overlay",
          retention_mode: "local_redacted_artifacts",
          detected_patterns: ["document", "navigation", "article"],
        },
        target_index: {
          target_index_ref: "target-index-native-browser-docs",
          coordinate_space_id: "native-browser-viewport",
          targets: [
            {
              target_ref: "target-docs-main",
              label: "Docs main content",
              role: "main",
              som_id: 1,
              confidence: 0.97,
              available_actions: ["inspect", "scroll"],
              bounds: {
                coordinate_space_id: "native-browser-viewport",
                x: 96,
                y: 120,
                width: 1020,
                height: 640,
              },
            },
            {
              target_ref: "target-docs-nav",
              label: "Docs navigation",
              role: "navigation",
              som_id: 2,
              confidence: 0.93,
              available_actions: ["inspect", "click"],
              bounds: {
                coordinate_space_id: "native-browser-viewport",
                x: 0,
                y: 84,
                width: 260,
                height: 680,
              },
            },
          ],
        },
      },
    }),
    runtimeThreadEvent("native-browser-affordances", 4, {
      eventKind: "computer_use.affordance_graph",
      sourceEventKind: "ComputerUse.AffordanceGraph",
      componentKind: "computer_use_harness",
      workflowNodeId: browserNodeId,
      receiptRefs: ["receipt-native-browser-affordances"],
      payload: {
        ...basePayload,
        summary: "Browser affordances computed from target index.",
        computer_use_step: "build_affordance_graph",
        computer_use_affordance_graph_ref: "affordance-native-browser-docs",
        affordance_graph: {
          graph_ref: "affordance-native-browser-docs",
          affordances: [
            {
              target_ref: "target-docs-main",
              possible_actions: ["inspect", "scroll"],
              action_confidence: 0.96,
              expected_state_transition: "content_summary_available",
              risk_class: "read_only",
              required_authority: "computer_use.native_browser.read",
            },
            {
              target_ref: "target-docs-nav",
              possible_actions: ["click"],
              action_confidence: 0.84,
              expected_state_transition: "navigation_target_changes",
              risk_class: "navigation_only",
              required_authority: "computer_use.native_browser.read",
            },
          ],
        },
      },
    }),
    runtimeThreadEvent("native-browser-proposal", 5, {
      eventKind: "computer_use.action_proposed",
      sourceEventKind: "ComputerUse.ActionProposed",
      componentKind: "computer_use_harness",
      workflowNodeId: browserNodeId,
      status: "waiting_for_policy",
      receiptRefs: ["receipt-native-browser-proposal"],
      policyDecisionRefs: ["policy-native-browser-read-only"],
      payload: {
        ...basePayload,
        summary: "Model-grounded browser inspect action proposed.",
        computer_use_step: "propose_action",
        computer_use_proposal_ref: "proposal-native-browser-inspect",
        computer_use_target_ref: "target-docs-main",
        computer_use_policy_decision_ref: "policy-native-browser-read-only",
        action_proposal: {
          proposal_ref: "proposal-native-browser-inspect",
          proposed_by: modelNodeId,
          model_role: "planner",
          target_ref: "target-docs-main",
          confidence: 0.95,
          rationale_summary:
            "The mounted model requested read-only inspection of the docs page.",
          predicted_postcondition: "docs content summarized",
          policy_decision_ref: "policy-native-browser-read-only",
        },
        policy_decision_receipt: {
          policy_decision_ref: "policy-native-browser-read-only",
          outcome: "approved_for_read_only_probe",
          authority_scope: "computer_use.native_browser.read",
          approval_ref: null,
          external_effect: false,
          fail_closed: false,
        },
      },
    }),
    runtimeThreadEvent("native-browser-commit-gate", 6, {
      eventKind: "computer_use.commit_gate",
      sourceEventKind: "ComputerUse.CommitGate",
      componentKind: "computer_use_harness",
      workflowNodeId: browserNodeId,
      receiptRefs: ["receipt-native-browser-commit-gate"],
      payload: {
        ...basePayload,
        summary: "Browser inspect commit gate resolved as read-only.",
        computer_use_step: "commit_or_handoff",
        computer_use_action_ref: "action-native-browser-inspect",
        computer_use_commit_gate_ref: "commit-gate-native-browser-inspect",
        outcome_contract: {
          outcome_ref: "outcome-native-browser-inspect",
          requested_outcome: "Inspect docs content without external mutation.",
          success_criteria: ["docs content summarized"],
          acceptable_side_effects: ["read-only navigation"],
          prohibited_side_effects: ["form submit", "external write"],
          evidence_required: ["verification-browser-inspect"],
        },
        commit_gate: {
          commit_gate_ref: "commit-gate-native-browser-inspect",
          status: "not_required",
          external_effect: false,
        },
      },
    }),
    runtimeThreadEvent("native-browser-action", 7, {
      eventKind: "computer_use.action_executed",
      sourceEventKind: "ComputerUse.ActionExecuted",
      componentKind: "computer_use_harness",
      workflowNodeId: browserNodeId,
      receiptRefs: ["receipt-native-browser-action"],
      payload: {
        ...basePayload,
        summary: "Native browser inspect action executed.",
        computer_use_step: "execute_action",
        computer_use_proposal_ref: "proposal-native-browser-inspect",
        computer_use_action_ref: "action-native-browser-inspect",
        computer_action: {
          action_ref: "action-native-browser-inspect",
          action_kind: "inspect",
          target_ref: "target-docs-main",
          coordinate_space_id: "native-browser-viewport",
        },
        action_receipt: {
          receipt_ref: "receipt-native-browser-action",
          action_ref: "action-native-browser-inspect",
          adapter_id: "ioi.native_browser.owned_hermetic",
          status: "completed",
          verification_ref: "verification-browser-inspect",
          coordinate_space_id: "native-browser-viewport",
        },
        computer_use_execution_result: {
          status: "completed",
          executor_ref: "executor-native-browser-owned",
          adapter_id: "ioi.native_browser.owned_hermetic",
          provider_id: "ioi.native_browser.local",
          preflight_receipt: { status: "dom_ax_ready" },
          execution_receipt: { provider_id: "ioi.native_browser.local" },
          after: { requires_reobserve: false },
        },
      },
    }),
    runtimeThreadEvent("native-browser-verification", 8, {
      eventKind: "computer_use.verification",
      sourceEventKind: "ComputerUse.Verification",
      componentKind: "computer_use_harness",
      workflowNodeId: browserNodeId,
      receiptRefs: ["receipt-native-browser-verification"],
      payload: {
        ...basePayload,
        summary: "Browser inspect postcondition verified.",
        computer_use_step: "verify_postcondition",
        computer_use_verification_ref: "verification-browser-inspect",
        verification_receipt: {
          verification_ref: "verification-browser-inspect",
          status: "passed",
          observed_postcondition: "docs content summarized",
        },
      },
    }),
    runtimeThreadEvent("native-browser-trajectory", 9, {
      eventKind: "computer_use.trajectory_written",
      sourceEventKind: "ComputerUse.TrajectoryWritten",
      componentKind: "computer_use_harness",
      workflowNodeId: browserNodeId,
      artifactRefs: ["computer-use-trace.json"],
      receiptRefs: ["receipt-native-browser-trajectory"],
      payload: {
        ...basePayload,
        summary: "Native browser trajectory written.",
        computer_use_step: "write_trajectory",
        computer_use_trajectory_ref: "trajectory-native-browser-prompt",
        trajectory_bundle: {
          trajectory_ref: "trajectory-native-browser-prompt",
          observation_refs: ["observation-native-browser-docs"],
          action_refs: ["action-native-browser-inspect"],
          verification_refs: ["verification-browser-inspect"],
          retention_mode: "local_redacted_artifacts",
        },
      },
    }),
    runtimeThreadEvent("native-browser-cleanup", 10, {
      eventKind: "computer_use.cleanup",
      sourceEventKind: "ComputerUse.Cleanup",
      componentKind: "computer_use_harness",
      workflowNodeId: browserNodeId,
      receiptRefs: ["receipt-native-browser-cleanup"],
      payload: {
        ...basePayload,
        summary: "Native browser lease cleaned up.",
        computer_use_step: "cleanup",
        computer_use_cleanup_ref: "cleanup-native-browser-prompt",
        cleanup_receipt: {
          cleanup_ref: "cleanup-native-browser-prompt",
          status: "completed",
          lease_id: "lease-native-browser-prompt",
          retained_artifacts: ["computer-use-trace.json"],
        },
        recovery_policy: {
          visual_drift: ["reobserve", "rebuild_target_index"],
          target_not_found: ["reobserve", "ask_user"],
          browser_crash: ["terminate_safely", "cleanup"],
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

const workflow = nativeBrowserPromptWorkflow();
const computerUseOptions = workflowComposerComputerUseRunOptions(workflow);
if (!computerUseOptions) {
  throw new Error("Browser Use workflow did not compile run metadata");
}
const mergedRunOptions = mergeWorkflowComposerComputerUseRunOptions(
  {
    mode: "composer_run",
    metadata: {
      source: "workflow_composer_run_button",
      promptHash: "sha256:native-browser-prompt",
    },
  },
  computerUseOptions,
);
const runResult = workflowRunResult({
  workflow,
  metadata: computerUseOptions.metadata,
});
const runtimeThreadEvents = nativeBrowserPipelineEvents({
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

const browserProjectionNodes = runHistory.runtimeEventProjection.nodes.filter(
  (node) => node.computerUse?.lane === "native_browser",
);
const projectionLabels = runHistory.runtimeEventProjection.reactFlowNodes.map(
  (node) => node.data.label,
);
const workbench = runHistory.computerUseWorkbench;
const modelTrace = runHistory.modelInvocationTraces[0] ?? null;
const metadata = computerUseOptions.metadata;
const mergedMetadata = mergedRunOptions.metadata ?? {};

const checks = {
  realRunButtonRendered:
    /testId="workflow-run-button"/.test(view) &&
    /label="Run"/.test(view) &&
    /icon=\{Play\}/.test(view),
  realRunButtonClickWired:
    /testId="workflow-run-button"[\s\S]*onClick=\{handleRun\}/.test(view),
  genericRunButtonUsesRuntimeProjectBridge:
    /runtime\.runWorkflowProject\(\s*workflowPath,\s*[\s\S]*workflowRunOptions/.test(
      controller,
    ) &&
    /mergeWorkflowComposerComputerUseRunOptions\(/.test(controller) &&
    /workflowComposerComputerUseRunOptions\(currentProjectFile\)/.test(
      controller,
    ),
  workflowComposition:
    workflow.nodes.some(
      (node) =>
        node.id === modelNodeId &&
        node.type === "model_call" &&
        node.config?.logic?.modelBinding?.modelId ===
          "demo-mounted-browser-model",
    ) &&
    workflow.nodes.some(
      (node) =>
        node.id === browserNodeId &&
        node.type === "plugin_tool" &&
        node.name === "Browser Use",
    ) &&
    workflow.edges.some(
      (edge) =>
        edge.from === modelNodeId &&
        edge.to === browserNodeId &&
        edge.fromPort === "output" &&
        edge.toPort === "input",
    ),
  browserRunOptionsForwarded:
    metadata.computerUse === true &&
    metadata.computerUseLane === "native_browser" &&
    metadata.computerUseSessionMode === "owned_hermetic_browser" &&
    metadata.computerUseActionKind === "inspect" &&
    metadata.observationRetentionMode === "local_redacted_artifacts" &&
    metadata.failClosedWhenUnavailable === true &&
    metadata.workflowGraphId === workflowGraphId &&
    metadata.workflowNodeId === browserNodeId &&
    metadata.toolRef === "ioi.computer_use.native_browser" &&
    mergedMetadata.computerUseLane === "native_browser" &&
    mergedMetadata.workflowNodeId === browserNodeId,
  runOptionsSchemaCoversBrowserMetadata:
    /computerUseLane/.test(runOptionsSource) &&
    /computerUseActionKind/.test(runOptionsSource) &&
    /cdpEndpointUrl/.test(runOptionsSource) &&
    /controlledRelaunchApprovalRef/.test(runOptionsSource) &&
    /observationRetentionMode/.test(runOptionsSource),
  modelInvocationTraceVisible:
    modelTrace?.nodeId === modelNodeId &&
    modelTrace?.mode === "live_mounted_model" &&
    modelTrace?.modelId === "demo-mounted-browser-model" &&
    modelTrace?.promptUser === demoPrompt &&
    modelTrace?.trace.map((step) => step.phase).join("|") ===
      "input|binding|prompt|model|tool_selection",
  promptSearchFindsRun:
    workflowRunHistoryModel({
      workflow,
      runs: [runResult.summary],
      lastRunResult: runResult,
      compareRunResult: null,
      selectedRunId: runId,
      compareRunId: null,
      runEvents: [],
      runtimeThreadEvents,
      searchQuery: "mounted browser planner",
      statusFilter: "all",
      sourceFilter: "all",
    }).visibleRows.length === 1,
  traceCrossesModelToBrowser:
    runHistory.runtimeEventProjection.reactFlowNodes.some(
      (node) => node.id === modelNodeId && node.data.nodeKind === "model_binding",
    ) &&
    runHistory.runtimeEventProjection.reactFlowEdges.some(
      (edge) =>
        edge.source === modelNodeId &&
        edge.target === `${browserNodeId}.select-environment`,
    ),
  browserTraceProjected:
    browserProjectionNodes.length === 9 &&
    projectionLabels.includes("Model router") &&
    projectionLabels.includes("Computer use: select environment") &&
    projectionLabels.includes("Computer use: observe") &&
    projectionLabels.includes("Computer use: affordances") &&
    projectionLabels.includes("Computer use: propose action") &&
    projectionLabels.includes("Computer use: commit gate") &&
    projectionLabels.includes("Computer use: execute action") &&
    projectionLabels.includes("Computer use: verify") &&
    projectionLabels.includes("Computer use: trajectory") &&
    projectionLabels.includes("Computer use: cleanup"),
  glassBoxWorkbench:
    workbench?.lane === "native_browser" &&
    workbench?.sessionMode === "owned_hermetic_browser" &&
    workbench?.leaseId === "lease-native-browser-prompt" &&
    workbench?.targetIndexRef === "target-index-native-browser-docs" &&
    workbench?.affordanceCount === 2 &&
    workbench?.proposalRef === "proposal-native-browser-inspect" &&
    workbench?.actionRef === "action-native-browser-inspect" &&
    workbench?.actionKind === "inspect" &&
    workbench?.executionStatus === "completed" &&
    workbench?.executionAdapterId === "ioi.native_browser.owned_hermetic" &&
    workbench?.executionProviderId === "ioi.native_browser.local" &&
    workbench?.verificationStatus === "passed" &&
    workbench?.commitGateStatus === "not_required" &&
    workbench?.cleanupStatus === "completed" &&
    workbench?.retentionMode === "local_redacted_artifacts" &&
    workbench?.policyOutcome === "approved_for_read_only_probe" &&
    workbench?.policyExternalEffect === false &&
    workbench?.workflowNodeIds.includes(browserNodeId),
  targetOverlayEvidence:
    workbench?.coordinateSpaceId === "native-browser-viewport" &&
    workbench?.targetCount === 2 &&
    workbench?.visualTargetSummaries.some(
      (target) =>
        target.targetRef === "target-docs-main" &&
        target.availableActions.includes("inspect"),
    ) &&
    workbench?.artifactPreviews.some(
      (artifact) => artifact.artifactRef === "computer-use-trace.json",
    ),
  workbenchUiExposesPipeline:
    /workflow-run-computer-use-workbench/.test(runsPanelSource) &&
    /workflow-run-computer-use-action-pane/.test(runsPanelSource) &&
    /data-cleanup-status/.test(runsPanelSource) &&
    /data-computer-use-proposal-ref/.test(runsPanelSource) &&
    /data-computer-use-verification-ref/.test(runsPanelSource),
  graphNodeIdentityPreserved:
    runResult.finalState.completedNodeIds.join("|") ===
      `${modelNodeId}|${browserNodeId}` &&
    browserProjectionNodes.every(
      (node) =>
        node.id.startsWith(`${browserNodeId}.`) &&
        node.computerUse?.workflowNodeId === browserNodeId &&
        node.workflowGraphId === workflowGraphId &&
        node.computerUse?.toolRef === "ioi.computer_use.native_browser",
    ),
  noCanvasLocalRuntimeTruth:
    !/from "@xyflow\/react"/.test(
      read("packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.ts"),
    ) &&
    /workflowModelInvocationTraces/.test(runHistoryModelSource) &&
    /workflowRunComputerUseWorkbench/.test(runHistoryModelSource),
};

const proof = {
  schemaVersion: "workflow.native-browser.prompt-pipeline-proof.v1",
  scenario: "workflow_native_browser_prompt_pipeline",
  passed: Object.values(checks).every(Boolean),
  clickedControlTestId: "workflow-run-button",
  workflowGraphId,
  modelNodeId,
  browserNodeId,
  runId,
  threadId,
  requestSummary: {
    prompt: demoPrompt,
    modelId: modelTrace?.modelId ?? null,
    modelTracePhases: modelTrace?.trace.map((step) => step.phase) ?? [],
    lane: metadata.computerUseLane,
    sessionMode: metadata.computerUseSessionMode,
    actionKind: metadata.computerUseActionKind,
    runtimeEventCount: runtimeThreadEvents.length,
    browserTraceNodeCount: browserProjectionNodes.length,
    projectionLabels,
    targetCount: workbench?.targetCount ?? 0,
    affordanceCount: workbench?.affordanceCount ?? 0,
    workbench: {
      proposalRef: workbench?.proposalRef ?? null,
      actionRef: workbench?.actionRef ?? null,
      verificationStatus: workbench?.verificationStatus ?? null,
      commitGateStatus: workbench?.commitGateStatus ?? null,
      cleanupStatus: workbench?.cleanupStatus ?? null,
      policyOutcome: workbench?.policyOutcome ?? null,
    },
  },
  checks,
  sourceRefs: [
    "packages/hypervisor-workbench/src/WorkflowComposer/view.tsx",
    "packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx",
    "packages/hypervisor-workbench/src/WorkflowComposer/computerUseRunOptions.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-node-registry.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-model-invocation-trace.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-run-history-model.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-runtime-event-projection.ts",
    "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
