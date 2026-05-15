#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  mergeWorkflowComposerComputerUseRunOptions,
  workflowComposerComputerUseRunOptions,
} from "../../packages/agent-ide/src/WorkflowComposer/computerUseRunOptions.ts";
import { makeDefaultWorkflow } from "../../packages/agent-ide/src/runtime/workflow-defaults.ts";
import {
  makeWorkflowEdge,
  makeWorkflowNode,
  workflowNodeCreatorDefinitions,
} from "../../packages/agent-ide/src/runtime/workflow-node-registry.ts";
import { workflowRunHistoryModel } from "../../packages/agent-ide/src/runtime/workflow-run-history-model.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-visual-gui-prompt-pipeline-gui-probe.mjs <output-path>",
  );
}

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);
const workflowGraphId = "workflow.visual-gui-prompt-pipeline";
const modelNodeId = "mounted-visual-planner-node";
const visualObservationNodeId = "visual-observation-node";
const visualComputerNodeId = "visual-computer-use-node";
const threadId = "thread-visual-gui-prompt-pipeline";
const runId = "workflow-visual-gui-prompt-pipeline-composer-run";
const runStartedAtMs = 2_150_000;
const demoPrompt =
  "Use Computer Use to inspect the Workflow Composer and run the prepared harness.";

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

function runtimeThreadEvent(id, seq, overrides = {}) {
  return {
    id,
    cursor: `events_${threadId}:${seq}`,
    seq,
    threadId,
    turnId: "turn-visual-gui-prompt-pipeline",
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

function creatorById(creatorId) {
  const creator = workflowNodeCreatorDefinitions().find(
    (item) => item.creatorId === creatorId,
  );
  if (!creator) throw new Error(`${creatorId} creator preset was not registered`);
  return creator;
}

function logicWithArguments(creator, argumentOverrides) {
  const toolBinding = creator.defaultLogic.toolBinding ?? {};
  return {
    ...creator.defaultLogic,
    toolBinding: {
      ...toolBinding,
      arguments: {
        ...(toolBinding.arguments ?? {}),
        ...argumentOverrides,
      },
    },
  };
}

function visualGuiPromptWorkflow() {
  const observationCreator = creatorById("computer_use.visual_gui_observe");
  const visualCreator = creatorById("plugin_tool.computer_use.visual_gui");
  const workflow = makeDefaultWorkflow("Visual GUI prompt pipeline proof");
  const modelNode = makeWorkflowNode(
    modelNodeId,
    "model_call",
    "Mounted Visual Planner",
    120,
    170,
    {
      modelRef: "reasoning",
      modelId: "demo-mounted-visual-model",
      routeId: "route.mounted-visual-demo",
      reasoningEffort: "medium",
      modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
      capability: "chat",
      receiptRequired: true,
      prompt: demoPrompt,
      modelBinding: {
        modelRef: "reasoning",
        modelId: "demo-mounted-visual-model",
        routeId: "route.mounted-visual-demo",
        reasoningEffort: "medium",
        modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
        capability: "chat",
        receiptRequired: true,
        daemonApi: "/api/v1/workflows/nodes/execute",
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
  const visualComputerNode = makeWorkflowNode(
    visualComputerNodeId,
    visualCreator.baseType,
    visualCreator.label,
    780,
    170,
    logicWithArguments(visualCreator, {
      computerUseActionKind: "click",
      computerUseApprovalRef: "approval-visual-gui-run-button",
      targetRef: "target-composer-run-button",
      screenshotRef: "artifact:visual-gui:screenshot-redacted",
      somRef: "artifact:visual-gui:som-overlay",
      axRef: "artifact:visual-gui:ax-tree",
      localGuiExecutor: true,
      localGuiExecutorProvider: "fixture",
      appName: "Autopilot",
      windowTitle: "Workflow Composer",
      coordinateSpaceId: "visual-gui-viewport",
      viewportWidth: 1440,
      viewportHeight: 900,
    }),
    visualCreator.defaultLaw,
    {
      metricLabel: visualCreator.metricLabel,
      metricValue: visualCreator.metricValue,
    },
  );
  const visualObservationNode = makeWorkflowNode(
    visualObservationNodeId,
    observationCreator.baseType,
    observationCreator.label,
    440,
    170,
    logicWithArguments(observationCreator, {
      screenshotRef: "artifact:visual-gui:screenshot-redacted",
      somRef: "artifact:visual-gui:som-overlay",
      axRef: "artifact:visual-gui:ax-tree",
      captureScreen: true,
      captureAxTree: true,
      captureAppName: "Autopilot",
      captureWindowTitle: "Workflow Composer",
      appName: "Autopilot",
      windowTitle: "Workflow Composer",
      coordinateSpaceId: "visual-gui-viewport",
      viewportWidth: 1440,
      viewportHeight: 900,
    }),
    observationCreator.defaultLaw,
    {
      metricLabel: observationCreator.metricLabel,
      metricValue: observationCreator.metricValue,
    },
  );
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: workflowGraphId,
      name: "Visual GUI prompt pipeline proof",
      slug: "visual-gui-prompt-pipeline-proof",
      gitLocation:
        ".agents/workflows/visual-gui-prompt-pipeline-proof.workflow.json",
      readOnly: false,
    },
    nodes: [modelNode, visualComputerNode, visualObservationNode],
    edges: [
      makeWorkflowEdge(
        "edge-mounted-model-to-visual-observation",
        modelNodeId,
        visualObservationNodeId,
        "output",
        "input",
      ),
      makeWorkflowEdge(
        "edge-visual-observation-to-computer-use",
        visualObservationNodeId,
        visualComputerNodeId,
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
      finishedAtMs: runStartedAtMs + 1_680,
      nodeCount: workflow.nodes.length,
      checkpointCount: 1,
      summary:
        "Mounted model planned a visual GUI run-button action through observation, grounding, approval, execution, verification, and cleanup.",
    },
    thread: {
      id: threadId,
      workflowPath:
        workflow.metadata.gitLocation ??
        ".agents/workflows/visual-gui-prompt-pipeline-proof.workflow.json",
      status: "passed",
      createdAtMs: runStartedAtMs,
      input: { prompt: demoPrompt },
    },
    finalState: {
      threadId,
      checkpointId: `${runId}-checkpoint`,
      runId,
      stepIndex: 3,
      values: {
        prompt: demoPrompt,
        modelPlan: {
          selectedTool: "ioi.computer_use.visual_gui",
          observationTool: "ioi.computer_use.visual_gui.observe",
          actionKind: metadata.computerUseActionKind,
          targetRef: "target-composer-run-button",
        },
        visualGui: {
          lane: metadata.computerUseLane,
          sessionMode: metadata.computerUseSessionMode,
          verified: true,
          coordinateSpaceId: metadata.coordinateSpaceId,
        },
      },
      nodeOutputs: {
        [modelNodeId]: {
          plan: "Observe the composer, ground the Run button, then execute with an approved local GUI adapter.",
          selectedTool: "ioi.computer_use.visual_gui",
        },
        [visualObservationNodeId]: {
          status: "completed",
          observationRef: "observation-visual-gui-composer",
          targetIndexRef: "target-index-visual-gui-composer",
        },
        [visualComputerNodeId]: {
          status: "completed",
          lane: metadata.computerUseLane,
          sessionMode: metadata.computerUseSessionMode,
          verificationRef: "verification-visual-gui-run-button",
        },
      },
      completedNodeIds: [
        modelNodeId,
        visualObservationNodeId,
        visualComputerNodeId,
      ],
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
        finishedAtMs: runStartedAtMs + 420,
        attempt: 1,
        input: { prompt: demoPrompt },
        output: {
          plan: "Use Visual Observation, then Computer Use with an approved local GUI executor.",
          modelInvocation: {
            mode: "live_mounted_model",
            modelRef: "reasoning",
            modelId: "demo-mounted-visual-model",
            promptHash: "sha256:visual-gui-prompt",
            responseHash: "sha256:visual-gui-plan-response",
            prompt: { user: demoPrompt },
            trace: [
              {
                phase: "input",
                summary: "Collected workflow prompt for visual GUI control.",
                promptHash: "sha256:visual-gui-prompt",
              },
              {
                phase: "binding",
                summary: "Resolved mounted visual-planner model.",
                latencyMs: 5,
              },
              {
                phase: "prompt",
                summary:
                  "Assembled prompt with visual observation and coordinate-action affordances.",
                promptHash: "sha256:visual-gui-prompt",
              },
              {
                phase: "model",
                summary:
                  "Mounted model selected visual GUI observation and approved Run-button action.",
                responseHash: "sha256:visual-gui-plan-response",
              },
              {
                phase: "tool_selection",
                summary: "Model plan handed off to ioi.computer_use.visual_gui.",
                latencyMs: 8,
              },
            ],
          },
        },
      },
      {
        nodeId: visualObservationNodeId,
        nodeType: "plugin_tool",
        status: "success",
        startedAtMs: runStartedAtMs + 440,
        finishedAtMs: runStartedAtMs + 720,
        attempt: 1,
        input: {
          toolRef: "ioi.computer_use.visual_gui.observe",
          screenshotRef: "artifact:visual-gui:screenshot-redacted",
          somRef: "artifact:visual-gui:som-overlay",
          axRef: "artifact:visual-gui:ax-tree",
        },
        output: {
          status: "completed",
          observationRef: "observation-visual-gui-composer",
          targetIndexRef: "target-index-visual-gui-composer",
        },
      },
      {
        nodeId: visualComputerNodeId,
        nodeType: "plugin_tool",
        status: "success",
        startedAtMs: runStartedAtMs + 760,
        finishedAtMs: runStartedAtMs + 1_680,
        attempt: 1,
        input: metadata,
        output: {
          status: "completed",
          traceRef: "computer-use-trace.json",
          actionRef: "action-visual-gui-click-run",
          verificationRef: "verification-visual-gui-run-button",
        },
      },
    ],
    checkpoints: [
      {
        id: `${runId}-checkpoint`,
        threadId,
        runId,
        createdAtMs: runStartedAtMs + 1_680,
        stepIndex: 3,
        status: "passed",
        summary: "Visual GUI prompt pipeline checkpoint retained.",
      },
    ],
    events: [
      {
        id: `${runId}-model-event`,
        runId,
        threadId,
        sequence: 1,
        kind: "model_invocation_succeeded",
        createdAtMs: runStartedAtMs + 420,
        nodeId: modelNodeId,
        status: "success",
        message: "Mounted model produced a visual GUI plan.",
      },
      {
        id: `${runId}-observe-event`,
        runId,
        threadId,
        sequence: 2,
        kind: "node_succeeded",
        createdAtMs: runStartedAtMs + 720,
        nodeId: visualObservationNodeId,
        status: "success",
        message: "Visual Observation produced canonical screenshot/SoM/AX refs.",
      },
      {
        id: `${runId}-visual-gui-event`,
        runId,
        threadId,
        sequence: 3,
        kind: "node_succeeded",
        createdAtMs: runStartedAtMs + 1_680,
        nodeId: visualComputerNodeId,
        status: "success",
        message: "Computer Use completed approved visual GUI action.",
      },
    ],
    verificationEvidence: [],
    completionRequirements: [],
  };
}

function visualGuiPipelineEvents({ metadata }) {
  const basePayload = {
    computer_use_lane: "visual_gui",
    computer_use_session_mode: "visual_fallback",
    computer_use_lease_id: "lease-visual-gui-prompt",
    computer_use_contract_ingest: "mounted_model_visual_gui_plan",
    workflow_graph_id: workflowGraphId,
    tool_ref: "ioi.computer_use.visual_gui",
    authority_scopes: metadata.authorityScopes,
    fail_closed_when_unavailable: metadata.failClosedWhenUnavailable,
  };
  const observationPayload = {
    ...basePayload,
    workflow_node_id: visualObservationNodeId,
    workflow_node_ids: [visualObservationNodeId],
    tool_ref: "ioi.computer_use.visual_gui.observe",
    authority_scopes: [
      "computer_use.visual_gui.observe",
      "computer_use.visual_gui.read",
      "computer_use.cleanup",
    ],
  };
  const actionPayload = {
    ...basePayload,
    workflow_node_id: visualComputerNodeId,
    workflow_node_ids: [visualComputerNodeId],
  };
  return [
    runtimeThreadEvent("visual-gui-model-route", 1, {
      type: "model_route_decision",
      eventKind: "model.route_decision",
      sourceEventKind: "ModelRouter.RouteSelected",
      componentKind: "model_router",
      workflowNodeId: modelNodeId,
      receiptRefs: ["receipt-mounted-visual-route"],
      payload: {
        summary: "Mounted model selected visual GUI Computer Use.",
        model_ref: "reasoning",
        model_id: "demo-mounted-visual-model",
        prompt_hash: "sha256:visual-gui-prompt",
        response_hash: "sha256:visual-gui-plan-response",
        selected_tool_ref: "ioi.computer_use.visual_gui",
      },
    }),
    runtimeThreadEvent("visual-gui-observation", 2, {
      eventKind: "computer_use.observation",
      sourceEventKind: "ComputerUse.Observation",
      componentKind: "computer_use_harness",
      workflowNodeId: visualObservationNodeId,
      artifactRefs: [
        "computer-use-trace.json",
        "artifact:visual-gui:screenshot-redacted",
        "artifact:visual-gui:som-overlay",
        "artifact:visual-gui:ax-tree",
      ],
      payload: {
        ...observationPayload,
        summary: "Visual GUI screenshot, SoM, and AX observation captured.",
        computer_use_step: "observe",
        computer_use_observation_ref: "observation-visual-gui-composer",
        computer_use_screen_ref: "artifact:visual-gui:screenshot-redacted",
        computer_use_som_ref: "artifact:visual-gui:som-overlay",
        computer_use_target_index_ref: "target-index-visual-gui-composer",
        observation_bundle: {
          observation_ref: "observation-visual-gui-composer",
          lane: "visual_gui",
          session_mode: "visual_fallback",
          target_index_ref: "target-index-visual-gui-composer",
          screenshot_ref: "artifact:visual-gui:screenshot-redacted",
          som_ref: "artifact:visual-gui:som-overlay",
          ax_ref: "artifact:visual-gui:ax-tree",
          retention_mode: "local_redacted_artifacts",
          detected_patterns: ["graph_canvas", "toolbar", "run_control"],
        },
        target_index: {
          target_index_ref: "target-index-visual-gui-composer",
          coordinate_space_id: "visual-gui-viewport",
          targets: [
            {
              target_ref: "target-composer-run-button",
              label: "Workflow Composer Run button",
              role: "button",
              som_id: 7,
              confidence: 0.94,
              available_actions: ["click", "inspect"],
              bounds: {
                coordinate_space_id: "visual-gui-viewport",
                x: 1240,
                y: 72,
                width: 88,
                height: 36,
              },
            },
            {
              target_ref: "target-composer-canvas",
              label: "Workflow Composer canvas",
              role: "region",
              som_id: 2,
              confidence: 0.9,
              available_actions: ["inspect", "pan"],
              bounds: {
                coordinate_space_id: "visual-gui-viewport",
                x: 248,
                y: 132,
                width: 900,
                height: 620,
              },
            },
          ],
        },
      },
    }),
    runtimeThreadEvent("visual-gui-environment", 3, {
      eventKind: "computer_use.environment_selected",
      sourceEventKind: "ComputerUse.EnvironmentSelected",
      componentKind: "computer_use_harness",
      workflowNodeId: visualComputerNodeId,
      receiptRefs: ["receipt-visual-gui-environment"],
      payload: {
        ...actionPayload,
        summary: "Foreground visual GUI environment selected.",
        computer_use_step: "select_environment",
        environment_selection_receipt: {
          selected_lane: "visual_gui",
          selected_session_mode: "visual_fallback",
          rejected_options: ["native_browser_dom_not_available"],
          reasons: ["Target is a canvas-heavy app surface with local GUI controls"],
          risk_posture: "coordinate_action_requires_approval",
          authority_required: "computer_use.visual_gui.act",
          expected_cleanup: "release_local_gui_lease",
        },
        lease: {
          lease_id: "lease-visual-gui-prompt",
          lane: "visual_gui",
          session_mode: "visual_fallback",
          status: "active",
          retention_mode: "local_redacted_artifacts",
          authority_scope: "computer_use.visual_gui.act",
        },
      },
    }),
    runtimeThreadEvent("visual-gui-affordances", 4, {
      eventKind: "computer_use.affordance_graph",
      sourceEventKind: "ComputerUse.AffordanceGraph",
      componentKind: "computer_use_harness",
      workflowNodeId: visualComputerNodeId,
      receiptRefs: ["receipt-visual-gui-affordances"],
      payload: {
        ...actionPayload,
        summary: "Coordinate-safe visual affordances computed from target index.",
        computer_use_step: "build_affordance_graph",
        computer_use_affordance_graph_ref: "affordance-visual-gui-composer",
        affordance_graph: {
          graph_ref: "affordance-visual-gui-composer",
          affordances: [
            {
              target_ref: "target-composer-run-button",
              possible_actions: ["click"],
              action_confidence: 0.92,
              expected_state_transition: "composer_run_queued",
              risk_class: "local_gui_coordinate_action",
              required_authority: "computer_use.visual_gui.act",
              required_confirmation: "approval-visual-gui-run-button",
              fallback_action_paths: ["ask_user", "reobserve"],
            },
            {
              target_ref: "target-composer-canvas",
              possible_actions: ["inspect", "pan"],
              action_confidence: 0.86,
              expected_state_transition: "canvas_state_visible",
              risk_class: "read_only",
              required_authority: "computer_use.visual_gui.read",
            },
          ],
        },
      },
    }),
    runtimeThreadEvent("visual-gui-proposal", 5, {
      eventKind: "computer_use.action_proposed",
      sourceEventKind: "ComputerUse.ActionProposed",
      componentKind: "computer_use_harness",
      workflowNodeId: visualComputerNodeId,
      status: "waiting_for_policy",
      receiptRefs: ["receipt-visual-gui-proposal"],
      policyDecisionRefs: ["policy-visual-gui-coordinate-action"],
      payload: {
        ...actionPayload,
        summary: "Model-grounded coordinate click proposed for the Run button.",
        computer_use_step: "propose_action",
        computer_use_proposal_ref: "proposal-visual-gui-click-run",
        computer_use_target_ref: "target-composer-run-button",
        computer_use_policy_decision_ref:
          "policy-visual-gui-coordinate-action",
        action_proposal: {
          proposal_ref: "proposal-visual-gui-click-run",
          proposed_by: modelNodeId,
          model_role: "planner",
          raw_model_output_ref: "sha256:visual-gui-plan-response",
          normalized_action_candidate: {
            action_kind: "click",
            target_ref: "target-composer-run-button",
            coordinate_space_id: "visual-gui-viewport",
          },
          target_ref: "target-composer-run-button",
          confidence: 0.92,
          rationale_summary:
            "The mounted model selected the visible Workflow Composer Run button after the visual observation broker grounded it.",
          predicted_postcondition: "composer run appears in run history",
          risk_assessment: "local coordinate action; approval required",
          policy_decision_ref: "policy-visual-gui-coordinate-action",
        },
        policy_decision_receipt: {
          policy_decision_ref: "policy-visual-gui-coordinate-action",
          outcome: "approved_by_operator",
          authority_scope: "computer_use.visual_gui.act",
          approval_ref: "approval-visual-gui-run-button",
          external_effect: true,
          fail_closed: true,
        },
      },
    }),
    runtimeThreadEvent("visual-gui-commit-gate", 6, {
      eventKind: "computer_use.commit_gate",
      sourceEventKind: "ComputerUse.CommitGate",
      componentKind: "computer_use_harness",
      workflowNodeId: visualComputerNodeId,
      receiptRefs: ["receipt-visual-gui-commit-gate"],
      payload: {
        ...actionPayload,
        summary: "Visual GUI commit gate confirmed the local Run-button click.",
        computer_use_step: "commit_or_handoff",
        computer_use_action_ref: "action-visual-gui-click-run",
        computer_use_commit_gate_ref: "commit-gate-visual-gui-click-run",
        outcome_contract: {
          outcome_ref: "outcome-visual-gui-run",
          requested_outcome:
            "Trigger the prepared Workflow Composer run and retain trace evidence.",
          success_criteria: ["composer run appears in history", "trace rows project"],
          acceptable_side_effects: ["local workflow run activation"],
          prohibited_side_effects: ["unapproved OS input", "external publish"],
          evidence_required: ["verification-visual-gui-run-button"],
        },
        commit_gate: {
          commit_gate_ref: "commit-gate-visual-gui-click-run",
          status: "approved",
          external_effect: true,
          approval_ref: "approval-visual-gui-run-button",
        },
      },
    }),
    runtimeThreadEvent("visual-gui-action", 7, {
      eventKind: "computer_use.action_executed",
      sourceEventKind: "ComputerUse.ActionExecuted",
      componentKind: "computer_use_harness",
      workflowNodeId: visualComputerNodeId,
      receiptRefs: ["receipt-visual-gui-action"],
      artifactRefs: [
        "computer-use-trace.json",
        "artifact:visual-gui:preflight-screenshot",
      ],
      payload: {
        ...actionPayload,
        summary:
          "Approved visual GUI click executed after observation-bound drift preflight.",
        computer_use_step: "execute_action",
        computer_use_proposal_ref: "proposal-visual-gui-click-run",
        computer_use_action_ref: "action-visual-gui-click-run",
        computer_action: {
          action_ref: "action-visual-gui-click-run",
          action_kind: "click",
          target_ref: "target-composer-run-button",
          coordinate_space_id: "visual-gui-viewport",
          coordinates: { x: 1284, y: 90 },
        },
        action_receipt: {
          receipt_ref: "receipt-visual-gui-action",
          action_ref: "action-visual-gui-click-run",
          adapter_id: "ioi.visual_gui.local_executor",
          status: "completed",
          verification_ref: "verification-visual-gui-run-button",
          coordinate_space_id: "visual-gui-viewport",
        },
        computer_use_execution_result: {
          status: "completed",
          executor_ref: "executor-visual-gui-local",
          adapter_id: "ioi.visual_gui.local_executor",
          provider_id: "ioi.visual_gui.fixture",
          preflight_receipt: {
            status: "passed",
            drift_status: "stable",
            screenshot_ref: "artifact:visual-gui:preflight-screenshot",
          },
          execution_receipt: { provider_id: "ioi.visual_gui.fixture" },
          after: { requires_reobserve: true },
        },
      },
    }),
    runtimeThreadEvent("visual-gui-verification", 8, {
      eventKind: "computer_use.verification",
      sourceEventKind: "ComputerUse.Verification",
      componentKind: "computer_use_harness",
      workflowNodeId: visualComputerNodeId,
      receiptRefs: ["receipt-visual-gui-verification"],
      payload: {
        ...actionPayload,
        summary: "Run-button postcondition verified in composer history.",
        computer_use_step: "verify_postcondition",
        computer_use_verification_ref: "verification-visual-gui-run-button",
        verification_receipt: {
          verification_ref: "verification-visual-gui-run-button",
          status: "passed",
          observed_postcondition: "composer run appears in history",
        },
      },
    }),
    runtimeThreadEvent("visual-gui-trajectory", 9, {
      eventKind: "computer_use.trajectory_written",
      sourceEventKind: "ComputerUse.TrajectoryWritten",
      componentKind: "computer_use_harness",
      workflowNodeId: visualComputerNodeId,
      artifactRefs: ["computer-use-trace.json"],
      receiptRefs: ["receipt-visual-gui-trajectory"],
      payload: {
        ...actionPayload,
        summary: "Visual GUI trajectory written.",
        computer_use_step: "write_trajectory",
        computer_use_trajectory_ref: "trajectory-visual-gui-prompt",
        trajectory_bundle: {
          trajectory_ref: "trajectory-visual-gui-prompt",
          observation_refs: ["observation-visual-gui-composer"],
          action_refs: ["action-visual-gui-click-run"],
          verification_refs: ["verification-visual-gui-run-button"],
          retention_mode: "local_redacted_artifacts",
        },
      },
    }),
    runtimeThreadEvent("visual-gui-cleanup", 10, {
      eventKind: "computer_use.cleanup",
      sourceEventKind: "ComputerUse.Cleanup",
      componentKind: "computer_use_harness",
      workflowNodeId: visualComputerNodeId,
      receiptRefs: ["receipt-visual-gui-cleanup"],
      payload: {
        ...actionPayload,
        summary: "Visual GUI lease cleaned up.",
        computer_use_step: "cleanup",
        computer_use_cleanup_ref: "cleanup-visual-gui-prompt",
        cleanup_receipt: {
          cleanup_ref: "cleanup-visual-gui-prompt",
          status: "completed",
          lease_id: "lease-visual-gui-prompt",
          retained_artifacts: ["computer-use-trace.json"],
        },
        recovery_policy: {
          visual_drift: ["reobserve", "rebuild_target_index", "ask_user"],
          target_not_found: ["reobserve", "switch_to_manual_selection"],
          no_effect_action: ["reobserve", "repair_or_continue"],
          policy_block: ["terminate_safely", "ask_user"],
        },
      },
    }),
  ];
}

const controller = read("packages/agent-ide/src/WorkflowComposer/controller.tsx");
const view = read("packages/agent-ide/src/WorkflowComposer/view.tsx");
const runOptionsSource = read(
  "packages/agent-ide/src/WorkflowComposer/computerUseRunOptions.ts",
);
const runHistoryModelSource = read(
  "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
);
const projectionSource = read(
  "packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts",
);
const runsPanelSource = read(
  "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
);

const workflow = visualGuiPromptWorkflow();
const computerUseOptions = workflowComposerComputerUseRunOptions(workflow);
if (!computerUseOptions) {
  throw new Error("Visual GUI workflow did not compile run metadata");
}
const mergedRunOptions = mergeWorkflowComposerComputerUseRunOptions(
  {
    mode: "composer_run",
    metadata: {
      source: "workflow_composer_run_button",
      promptHash: "sha256:visual-gui-prompt",
    },
  },
  computerUseOptions,
);
const runResult = workflowRunResult({
  workflow,
  metadata: computerUseOptions.metadata,
});
const runtimeThreadEvents = visualGuiPipelineEvents({
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

const visualProjectionNodes = runHistory.runtimeEventProjection.nodes.filter(
  (node) => node.computerUse?.lane === "visual_gui",
);
const projectionLabels = runHistory.runtimeEventProjection.reactFlowNodes.map(
  (node) => node.data.label,
);
const workbench = runHistory.computerUseWorkbench;
const modelTrace = runHistory.modelInvocationTraces[0] ?? null;
const metadata = computerUseOptions.metadata;
const mergedMetadata = mergedRunOptions.metadata ?? {};
const visualWorkflowNodeIds = new Set([
  visualObservationNodeId,
  visualComputerNodeId,
]);

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
          "demo-mounted-visual-model",
    ) &&
    workflow.nodes.some(
      (node) =>
        node.id === visualObservationNodeId &&
        node.type === "plugin_tool" &&
        node.name === "Visual Observation",
    ) &&
    workflow.nodes.some(
      (node) =>
        node.id === visualComputerNodeId &&
        node.type === "plugin_tool" &&
        node.name === "Computer Use",
    ) &&
    workflow.edges.some(
      (edge) => edge.from === modelNodeId && edge.to === visualObservationNodeId,
    ) &&
    workflow.edges.some(
      (edge) =>
        edge.from === visualObservationNodeId && edge.to === visualComputerNodeId,
    ),
  visualRunOptionsForwarded:
    metadata.computerUse === true &&
    metadata.computerUseLane === "visual_gui" &&
    metadata.computerUseSessionMode === "visual_fallback" &&
    metadata.computerUseActionKind === "click" &&
    metadata.computerUseApprovalRef === "approval-visual-gui-run-button" &&
    metadata.computerUseTargetRef === "target-composer-run-button" &&
    metadata.screenshotRef === "artifact:visual-gui:screenshot-redacted" &&
    metadata.somRef === "artifact:visual-gui:som-overlay" &&
    metadata.axRef === "artifact:visual-gui:ax-tree" &&
    metadata.localGuiExecutor === true &&
    metadata.localGuiExecutorProvider === "fixture" &&
    metadata.appName === "Autopilot" &&
    metadata.windowTitle === "Workflow Composer" &&
    metadata.coordinateSpaceId === "visual-gui-viewport" &&
    metadata.viewportWidth === 1440 &&
    metadata.viewportHeight === 900 &&
    metadata.observationRetentionMode === "local_redacted_artifacts" &&
    metadata.failClosedWhenUnavailable === true &&
    metadata.workflowGraphId === workflowGraphId &&
    metadata.workflowNodeId === visualComputerNodeId &&
    metadata.toolRef === "ioi.computer_use.visual_gui" &&
    mergedMetadata.computerUseLane === "visual_gui" &&
    mergedMetadata.workflowNodeId === visualComputerNodeId,
  runOptionsSchemaCoversVisualMetadata:
    /screenshotRef/.test(runOptionsSource) &&
    /somRef/.test(runOptionsSource) &&
    /axRef/.test(runOptionsSource) &&
    /localGuiExecutor/.test(runOptionsSource) &&
    /localGuiExecutorProvider/.test(runOptionsSource) &&
    /coordinateSpaceId/.test(runOptionsSource) &&
    /viewportWidth/.test(runOptionsSource) &&
    /viewportHeight/.test(runOptionsSource),
  modelInvocationTraceVisible:
    modelTrace?.nodeId === modelNodeId &&
    modelTrace?.mode === "live_mounted_model" &&
    modelTrace?.modelId === "demo-mounted-visual-model" &&
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
      searchQuery: "run the prepared harness",
      statusFilter: "all",
      sourceFilter: "all",
    }).visibleRows.length === 1,
  traceCrossesModelToVisual:
    runHistory.runtimeEventProjection.reactFlowNodes.some(
      (node) => node.id === modelNodeId && node.data.nodeKind === "model_binding",
    ) &&
    runHistory.runtimeEventProjection.reactFlowEdges.some(
      (edge) =>
        edge.source === modelNodeId &&
        edge.target === `${visualObservationNodeId}.observe`,
    ) &&
    runHistory.runtimeEventProjection.reactFlowEdges.some(
      (edge) =>
        edge.source === `${visualObservationNodeId}.observe` &&
        edge.target === `${visualComputerNodeId}.select-environment`,
    ),
  visualTraceProjected:
    visualProjectionNodes.length === 9 &&
    projectionLabels.includes("Model router") &&
    projectionLabels.includes("Computer use: observe") &&
    projectionLabels.includes("Computer use: select environment") &&
    projectionLabels.includes("Computer use: affordances") &&
    projectionLabels.includes("Computer use: propose action") &&
    projectionLabels.includes("Computer use: commit gate") &&
    projectionLabels.includes("Computer use: execute action") &&
    projectionLabels.includes("Computer use: verify") &&
    projectionLabels.includes("Computer use: trajectory") &&
    projectionLabels.includes("Computer use: cleanup"),
  glassBoxWorkbench:
    workbench?.lane === "visual_gui" &&
    workbench?.sessionMode === "visual_fallback" &&
    workbench?.leaseId === "lease-visual-gui-prompt" &&
    workbench?.observationRef === "observation-visual-gui-composer" &&
    workbench?.screenRef === "artifact:visual-gui:screenshot-redacted" &&
    workbench?.somRef === "artifact:visual-gui:som-overlay" &&
    workbench?.targetIndexRef === "target-index-visual-gui-composer" &&
    workbench?.targetCount === 2 &&
    workbench?.affordanceCount === 2 &&
    workbench?.proposalRef === "proposal-visual-gui-click-run" &&
    workbench?.actionRef === "action-visual-gui-click-run" &&
    workbench?.actionKind === "click" &&
    workbench?.executionStatus === "completed" &&
    workbench?.executionAdapterId === "ioi.visual_gui.local_executor" &&
    workbench?.executionProviderId === "ioi.visual_gui.fixture" &&
    workbench?.executionPreflightStatus === "passed" &&
    workbench?.executionRequiresReobserve === true &&
    workbench?.verificationStatus === "passed" &&
    workbench?.commitGateStatus === "approved" &&
    workbench?.cleanupStatus === "completed" &&
    workbench?.retentionMode === "local_redacted_artifacts" &&
    workbench?.policyOutcome === "approved_by_operator" &&
    workbench?.policyApprovalRef === "approval-visual-gui-run-button" &&
    workbench?.policyExternalEffect === true &&
    workbench?.policyFailClosed === true &&
    workbench?.workflowNodeIds.includes(visualObservationNodeId) &&
    workbench?.workflowNodeIds.includes(visualComputerNodeId),
  targetOverlayEvidence:
    workbench?.coordinateSpaceId === "visual-gui-viewport" &&
    workbench?.visualTargetSummaries.some(
      (target) =>
        target.targetRef === "target-composer-run-button" &&
        target.availableActions.includes("click") &&
        target.bounds?.coordinateSpaceId === "visual-gui-viewport",
    ) &&
    workbench?.artifactPreviews.some(
      (artifact) =>
        artifact.artifactRef === "artifact:visual-gui:screenshot-redacted",
    ) &&
    workbench?.artifactPreviews.some(
      (artifact) => artifact.artifactRef === "artifact:visual-gui:ax-tree",
    ),
  workbenchUiExposesPipeline:
    /workflow-run-computer-use-workbench/.test(runsPanelSource) &&
    /workflow-run-computer-use-action-pane/.test(runsPanelSource) &&
    /data-cleanup-status/.test(runsPanelSource) &&
    /data-computer-use-proposal-ref/.test(runsPanelSource) &&
    /data-computer-use-verification-ref/.test(runsPanelSource),
  graphNodeIdentityPreserved:
    runResult.finalState.completedNodeIds.join("|") ===
      `${modelNodeId}|${visualObservationNodeId}|${visualComputerNodeId}` &&
    visualProjectionNodes.every(
      (node) =>
        node.id.startsWith(`${node.computerUse?.workflowNodeId}.`) &&
        visualWorkflowNodeIds.has(node.computerUse?.workflowNodeId) &&
        node.workflowGraphId === workflowGraphId &&
        ["ioi.computer_use.visual_gui", "ioi.computer_use.visual_gui.observe"].includes(
          node.computerUse?.toolRef,
        ),
    ),
  noCanvasLocalRuntimeTruth:
    !/from "@xyflow\/react"/.test(
      read("packages/agent-ide/src/WorkflowComposer/computerUseRunOptions.ts"),
    ) &&
    /workflowModelInvocationTraces/.test(runHistoryModelSource) &&
    /workflowRunComputerUseWorkbench/.test(runHistoryModelSource) &&
    /computerUseProjectionForRuntimeThreadEvent/.test(projectionSource),
};

const proof = {
  schemaVersion: "workflow.visual-gui.prompt-pipeline-proof.v1",
  scenario: "workflow_visual_gui_prompt_pipeline",
  passed: Object.values(checks).every(Boolean),
  clickedControlTestId: "workflow-run-button",
  workflowGraphId,
  modelNodeId,
  visualObservationNodeId,
  visualComputerNodeId,
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
    visualTraceNodeCount: visualProjectionNodes.length,
    projectionLabels,
    targetCount: workbench?.targetCount ?? 0,
    affordanceCount: workbench?.affordanceCount ?? 0,
    workbench: {
      observationRef: workbench?.observationRef ?? null,
      targetIndexRef: workbench?.targetIndexRef ?? null,
      proposalRef: workbench?.proposalRef ?? null,
      actionRef: workbench?.actionRef ?? null,
      verificationStatus: workbench?.verificationStatus ?? null,
      commitGateStatus: workbench?.commitGateStatus ?? null,
      cleanupStatus: workbench?.cleanupStatus ?? null,
      policyOutcome: workbench?.policyOutcome ?? null,
      policyApprovalRef: workbench?.policyApprovalRef ?? null,
      policyExternalEffect: workbench?.policyExternalEffect ?? null,
      policyFailClosed: workbench?.policyFailClosed ?? null,
      executionPreflightStatus: workbench?.executionPreflightStatus ?? null,
      executionRequiresReobserve:
        workbench?.executionRequiresReobserve ?? null,
    },
  },
  checks,
  sourceRefs: [
    "packages/agent-ide/src/WorkflowComposer/view.tsx",
    "packages/agent-ide/src/WorkflowComposer/controller.tsx",
    "packages/agent-ide/src/WorkflowComposer/computerUseRunOptions.ts",
    "packages/agent-ide/src/runtime/workflow-node-registry.ts",
    "packages/agent-ide/src/runtime/workflow-model-invocation-trace.ts",
    "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
