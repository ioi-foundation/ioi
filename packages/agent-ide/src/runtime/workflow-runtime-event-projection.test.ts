import assert from "node:assert/strict";
import test from "node:test";
import {
  WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
  projectRuntimeTuiControlStateToWorkflowProjection,
  projectRuntimeThreadEventsToWorkflowNodes,
  projectRuntimeThreadEventsToWorkflowProjection,
  workflowNodeIdForRuntimeThreadEvent,
  type WorkflowRuntimeThreadEventLike,
} from "./workflow-runtime-event-projection";

function event(
  id: string,
  seq: number,
  overrides: Partial<WorkflowRuntimeThreadEventLike> = {},
): WorkflowRuntimeThreadEventLike {
  return {
    id,
    cursor: `events_thread:test:${seq}`,
    seq,
    threadId: "thread-test",
    turnId: "turn-test",
    type: "runtime_step",
    eventKind: "runtime.step",
    sourceEventKind: "KernelEvent::RuntimeStep",
    status: "completed",
    createdAt: `2026-05-12T00:00:0${seq}.000Z`,
    componentKind: null,
    workflowNodeId: null,
    workflowGraphId: "workflow-test",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

test("projects Thread.events runtime events into stable React Flow nodes and edges", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-3", 3, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "KernelEvent::ToolCompleted",
      workflowNodeId: "runtime.tool-result",
      componentKind: "tool_result",
      toolName: "shell",
      receiptRefs: ["receipt-tool"],
    }),
    event("event-1", 1, {
      type: "reasoning_delta",
      eventKind: "reasoning.delta",
      sourceEventKind: "KernelEvent::ReasoningDelta",
      workflowNodeId: "runtime.reasoning",
      componentKind: "reasoning_delta",
      status: "running",
      payload: { summary: "Thinking through the patch." },
    }),
    event("event-2", 2, {
      type: "model_route_decision",
      eventKind: "model.route_decision",
      sourceEventKind: "KernelEvent::ModelRouteDecision",
    }),
  ]);

  assert.equal(
    projection.schemaVersion,
    WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION,
  );
  assert.deepEqual(
    projection.reactFlowNodes.map((node) => node.id),
    ["runtime.reasoning", "runtime.model-router", "runtime.tool-result"],
  );
  assert.equal(projection.reactFlowNodes[0]?.data.nodeKind, "task_state");
  assert.equal(projection.reactFlowNodes[0]?.data.status, "running");
  assert.equal(projection.reactFlowNodes[0]?.data.summary, "Thinking through the patch.");
  assert.equal(projection.reactFlowNodes[1]?.data.nodeKind, "model_binding");
  assert.equal(projection.reactFlowNodes[1]?.data.componentKind, "model_router");
  assert.equal(projection.reactFlowNodes[2]?.data.nodeKind, "plugin_tool");
  assert.deepEqual(projection.reactFlowNodes[2]?.data.receiptRefs, ["receipt-tool"]);
  assert.deepEqual(
    projection.reactFlowEdges.map((edge) => [edge.source, edge.target]),
    [
      ["runtime.reasoning", "runtime.model-router"],
      ["runtime.model-router", "runtime.tool-result"],
    ],
  );
  assert.equal(projection.latestEventId, "event-3");
  assert.equal(projection.latestCursor, "events_thread:test:3");
});

test("projects computer-use lifecycle events as glass-box harness rows", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("computer-use-environment", 1, {
      eventKind: "computer_use.environment_selected",
      sourceEventKind: "ComputerUse.EnvironmentSelected",
      status: "completed",
      componentKind: "computer_use_harness",
      workflowNodeId: "browser-use-node",
      workflowGraphId: "workflow.browser-use-demo",
      payloadSchemaVersion: "ioi.computer-use.harness.v1",
      receiptRefs: ["receipt-computer-use-environment"],
      payload: {
        summary: "Computer-use environment selected",
        computer_use_step: "select_environment",
        computer_use_lane: "native_browser",
        computer_use_session_mode: "owned_hermetic_browser",
        computer_use_lease_id: "lease-browser",
        workflowGraphId: "workflow.browser-use-demo",
        workflowNodeId: "browser-use-node",
        workflowNodeIds: ["browser-use-node"],
        toolRef: "ioi.computer_use.native_browser",
        authorityScopes: ["computer_use.native_browser.read"],
        failClosedWhenUnavailable: true,
        environment_selection_receipt: {
          receipt_ref: "receipt-computer-use-environment",
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
    event("computer-use-observe", 2, {
      eventKind: "computer_use.observation",
      sourceEventKind: "ComputerUse.Observation",
      status: "completed",
      componentKind: "computer_use_harness",
      workflowNodeId: "computer-use.observe",
      payloadSchemaVersion: "ioi.computer-use.harness.v1",
      artifactRefs: ["computer-use-trace.json"],
      payload: {
        computer_use_step: "observe",
        computer_use_lane: "native_browser",
        computer_use_session_mode: "owned_hermetic_browser",
        computer_use_lease_id: "lease-browser",
        computer_use_observation_ref: "observation-browser",
        computer_use_target_index_ref: "target-index-browser",
        observation_bundle: {
          observation_ref: "observation-browser",
          target_index_ref: "target-index-browser",
          screenshot_ref: "artifact:browser:screenshot",
          som_ref: "artifact:browser:som",
          retention_mode: "local_redacted_artifacts",
          detected_patterns: ["form", "toolbar"],
        },
        target_index: {
          target_index_ref: "target-index-browser",
          coordinate_space_id: "viewport-browser",
          targets: [
            {
              target_ref: "target-page",
              label: "Page",
              role: "document",
              som_id: 1,
              confidence: 0.96,
              available_actions: ["inspect"],
              bounds: {
                coordinate_space_id: "viewport-browser",
                x: 0,
                y: 0,
                width: 1280,
                height: 720,
              },
            },
            { target_ref: "target-submit" },
          ],
        },
      },
    }),
    event("computer-use-propose", 3, {
      eventKind: "computer_use.action_proposed",
      sourceEventKind: "ComputerUse.ActionProposed",
      status: "waiting_for_policy",
      componentKind: "computer_use_harness",
      workflowNodeId: "computer-use.action-proposal",
      payloadSchemaVersion: "ioi.computer-use.harness.v1",
      policyDecisionRefs: ["policy-read-only"],
      payload: {
        computer_use_step: "propose_action",
        computer_use_lane: "native_browser",
        computer_use_session_mode: "owned_hermetic_browser",
        computer_use_lease_id: "lease-browser",
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
    event("computer-use-execute", 4, {
      eventKind: "computer_use.action_executed",
      sourceEventKind: "ComputerUse.ActionExecuted",
      status: "completed",
      componentKind: "computer_use_harness",
      workflowNodeId: "computer-use.execute-action",
      payloadSchemaVersion: "ioi.computer-use.harness.v1",
      receiptRefs: ["receipt-action"],
      payload: {
        computer_use_step: "execute_action",
        computer_use_action_ref: "action-inspect",
        computer_use_proposal_ref: "proposal-inspect",
        computer_action: {
          action_ref: "action-inspect",
          action_kind: "inspect",
          target_ref: "target-page",
        },
        action_receipt: {
          receipt_ref: "receipt-action",
          action_ref: "action-inspect",
          status: "completed",
          verification_ref: "verification-inspect",
        },
      },
    }),
    event("computer-use-commit-gate", 5, {
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
  ]);

  assert.deepEqual(
    projection.reactFlowNodes.map((node) => node.id),
    [
      "browser-use-node",
      "computer-use.observe",
      "computer-use.action-proposal",
      "computer-use.execute-action",
      "computer-use.commit-gate",
    ],
  );
  assert.equal(projection.nodes[0]?.nodeKind, "gui_harness_validation");
  assert.equal(projection.nodes[0]?.componentKind, "computer_use_harness");
  assert.equal(projection.nodes[0]?.label, "Computer use: select environment");
  assert.equal(projection.nodes[0]?.computerUse?.lane, "native_browser");
  assert.equal(
    projection.nodes[0]?.computerUse?.sessionMode,
    "owned_hermetic_browser",
  );
  assert.equal(projection.nodes[0]?.computerUse?.leaseId, "lease-browser");
  assert.equal(
    projection.nodes[0]?.computerUse?.workflowGraphId,
    "workflow.browser-use-demo",
  );
  assert.equal(
    projection.nodes[0]?.computerUse?.workflowNodeId,
    "browser-use-node",
  );
  assert.deepEqual(projection.nodes[0]?.computerUse?.workflowNodeIds, [
    "browser-use-node",
  ]);
  assert.equal(
    projection.nodes[0]?.computerUse?.toolRef,
    "ioi.computer_use.native_browser",
  );
  assert.deepEqual(projection.nodes[0]?.computerUse?.authorityScopes, [
    "computer_use.native_browser.read",
  ]);
  assert.equal(
    projection.nodes[0]?.computerUse?.failClosedWhenUnavailable,
    true,
  );
  assert.equal(projection.nodes[0]?.computerUse?.riskPosture, "read_only_probe");
  assert.equal(
    projection.nodes[0]?.computerUse?.authorityRequired,
    "computer_use.native_browser.read",
  );
  assert.equal(projection.nodes[0]?.computerUse?.retentionMode, "local_redacted_artifacts");
  assert.equal(projection.nodes[1]?.label, "Computer use: observe");
  assert.equal(projection.nodes[1]?.computerUse?.observationRef, "observation-browser");
  assert.equal(projection.nodes[1]?.computerUse?.screenRef, "artifact:browser:screenshot");
  assert.equal(projection.nodes[1]?.computerUse?.somRef, "artifact:browser:som");
  assert.equal(projection.nodes[1]?.computerUse?.coordinateSpaceId, "viewport-browser");
  assert.equal(projection.nodes[1]?.computerUse?.targetIndexRef, "target-index-browser");
  assert.equal(projection.nodes[1]?.computerUse?.targetCount, 2);
  assert.deepEqual(projection.nodes[1]?.computerUse?.visualTargetRefs, [
    "target-page",
    "target-submit",
  ]);
  assert.deepEqual(projection.nodes[1]?.computerUse?.visualTargetSummaries[0], {
    targetRef: "target-page",
    label: "Page",
    role: "document",
    somId: 1,
    confidence: 0.96,
    bounds: {
      x: 0,
      y: 0,
      width: 1280,
      height: 720,
      coordinateSpaceId: "viewport-browser",
    },
    boundsSummary: "viewport-browser · 0,0 1280x720",
    availableActions: ["inspect"],
  });
  assert.deepEqual(projection.nodes[1]?.computerUse?.detectedPatterns, [
    "form",
    "toolbar",
  ]);
  assert.equal(projection.nodes[2]?.status, "waiting");
  assert.equal(projection.nodes[2]?.label, "Computer use: propose action");
  assert.equal(projection.nodes[2]?.computerUse?.proposalRef, "proposal-inspect");
  assert.equal(projection.nodes[2]?.computerUse?.policyDecisionRef, "policy-read-only");
  assert.equal(projection.nodes[2]?.computerUse?.policyOutcome, "approved_for_read_only_probe");
  assert.equal(projection.nodes[2]?.computerUse?.policyAuthorityScope, "computer_use.native_browser.read");
  assert.equal(projection.nodes[2]?.computerUse?.policyExternalEffect, false);
  assert.equal(projection.nodes[2]?.computerUse?.policyFailClosed, false);
  assert.equal(projection.nodes[3]?.label, "Computer use: execute action");
  assert.equal(projection.nodes[3]?.computerUse?.actionKind, "inspect");
  assert.equal(projection.nodes[3]?.computerUse?.actionReceiptRef, "receipt-action");
  assert.equal(projection.nodes[3]?.computerUse?.verificationRef, "verification-inspect");
  assert.equal(projection.nodes[4]?.label, "Computer use: commit gate");
  assert.equal(projection.nodes[4]?.computerUse?.commitGateRef, "commit-gate-inspect");
  assert.equal(projection.nodes[4]?.computerUse?.commitGateStatus, "not_required");
  assert.equal(projection.nodes[4]?.computerUse?.outcomeRef, "outcome-inspect");
});

test("projects browser discovery receipts as glass-box computer-use rows", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("computer-use-browser-discovery", 1, {
      type: "computer_use_browser_discovery",
      eventKind: "computer_use.browser_discovery",
      sourceEventKind: "ComputerUse.BrowserDiscovery",
      status: "completed",
      componentKind: "computer_use_harness",
      workflowNodeId: "browser-discovery-node",
      workflowGraphId: "workflow.browser-discovery",
      payloadSchemaVersion: "ioi.computer-use.harness.v1",
      receiptRefs: [
        "receipt-computer-use-trace",
        "receipt-browser-discovery",
      ],
      artifactRefs: ["computer-use-browser-discovery.json"],
      payload: {
        summary: "Browser discovery receipt emitted",
        computer_use_step: "discover_browser",
        computer_use_lane: "native_browser",
        computer_use_session_mode: "discovery_only",
        computer_use_lease_id: "lease-browser-discovery",
        computer_use_browser_discovery_ref: "browser-discovery-1",
        workflowGraphId: "workflow.browser-discovery",
        workflowNodeId: "browser-discovery-node",
        workflowNodeIds: ["browser-discovery-node"],
        toolRef: "ioi.computer_use.browser_discovery",
        authorityScopes: ["computer_use.browser_discovery.read"],
        failClosedWhenUnavailable: true,
        browser_discovery_report: {
          receipt_ref: "receipt-browser-discovery",
          discovery_ref: "browser-discovery-1",
          browser_process_count: 2,
          cdp_endpoint_count: 1,
          default_profile_remote_debugging_blockers: [
            { browser_family: "chrome" },
          ],
          safety: {
            read_only: true,
            attached: false,
            launched: false,
            raw_command_lines_redacted: true,
          },
        },
        lease: {
          lease_id: "lease-browser-discovery",
          lane: "native_browser",
          session_mode: "discovery_only",
          retention_mode: "prompt_visible_summary_only",
        },
      },
    }),
  ]);

  assert.equal(projection.nodes.length, 1);
  assert.equal(projection.nodes[0]?.label, "Computer use: browser discovery");
  assert.equal(projection.nodes[0]?.computerUse?.browserDiscoveryRef, "browser-discovery-1");
  assert.equal(projection.nodes[0]?.computerUse?.browserProcessCount, 2);
  assert.equal(projection.nodes[0]?.computerUse?.cdpEndpointCount, 1);
  assert.equal(projection.nodes[0]?.computerUse?.defaultProfileBlockerCount, 1);
  assert.equal(
    projection.nodes[0]?.summary,
    "Browser discovery receipt emitted",
  );
});

test("projects bridge-derived proposal-only computer-use gates without executed actions", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("bridge-observation", 1, {
      type: "computer_use_observation",
      eventKind: "computer_use.observation",
      sourceEventKind: "ComputerUse.Observation",
      status: "completed",
      componentKind: null,
      workflowNodeId: null,
      workflowGraphId: "workflow.bridge-browser",
      payloadSchemaVersion: "ioi.computer-use.harness.v1",
      artifactRefs: ["computer-use-trace.json"],
      payload: {
        computer_use_step: "observe",
        computer_use_lane: "native_browser",
        computer_use_session_mode: "runtime_service_bridge",
        computer_use_lease_id: "lease-bridge",
        observation_bundle: {
          observation_ref: "observation-bridge",
          target_index_ref: "target-index-bridge",
          retention_mode: "local_redacted_artifacts",
        },
        target_index: {
          target_index_ref: "target-index-bridge",
          targets: [{ target_ref: "target-bridge-submit" }],
        },
      },
    }),
    event("bridge-affordances", 2, {
      type: "computer_use_affordance_graph",
      eventKind: "computer_use.affordance_graph",
      sourceEventKind: "ComputerUse.AffordanceGraph",
      status: "completed",
      componentKind: null,
      workflowNodeId: null,
      workflowGraphId: "workflow.bridge-browser",
      payloadSchemaVersion: "ioi.computer-use.harness.v1",
      artifactRefs: ["computer-use-trace.json"],
      payload: {
        computer_use_step: "build_affordance_graph",
        computer_use_lane: "native_browser",
        computer_use_session_mode: "runtime_service_bridge",
        computer_use_lease_id: "lease-bridge",
        affordance_graph: {
          graph_ref: "affordance-bridge",
          affordances: [
            {
              target_ref: "target-bridge-submit",
              possible_actions: ["click"],
              requires_confirmation: true,
            },
          ],
        },
      },
    }),
    event("bridge-proposal", 3, {
      type: "computer_use_action_proposed",
      eventKind: "computer_use.action_proposed",
      sourceEventKind: "ComputerUse.ActionProposed",
      status: "waiting_for_policy",
      componentKind: null,
      workflowNodeId: null,
      workflowGraphId: "workflow.bridge-browser",
      payloadSchemaVersion: "ioi.computer-use.harness.v1",
      artifactRefs: ["computer-use-trace.json"],
      payload: {
        computer_use_step: "propose_action",
        computer_use_lane: "native_browser",
        computer_use_session_mode: "runtime_service_bridge",
        computer_use_lease_id: "lease-bridge",
        action_proposal: {
          proposal_ref: "proposal-bridge-click",
          target_ref: "target-bridge-submit",
          policy_decision_ref: "policy-bridge-confirmation",
        },
        policy_gate: {
          policy_decision_ref: "policy-bridge-confirmation",
          decision: "requires_confirmation",
        },
      },
    }),
    event("bridge-commit-gate", 4, {
      type: "computer_use_commit_gate",
      eventKind: "computer_use.commit_gate",
      sourceEventKind: "ComputerUse.CommitGate",
      status: "waiting_for_confirmation",
      componentKind: null,
      workflowNodeId: null,
      workflowGraphId: "workflow.bridge-browser",
      payloadSchemaVersion: "ioi.computer-use.harness.v1",
      artifactRefs: ["computer-use-trace.json"],
      payload: {
        computer_use_step: "commit_or_handoff",
        computer_use_lane: "native_browser",
        computer_use_session_mode: "runtime_service_bridge",
        computer_use_lease_id: "lease-bridge",
        outcome_contract: {
          outcome_ref: "outcome-bridge-submit",
          external_effect_policy: "confirmation_required",
        },
        commit_gate: {
          commit_gate_ref: "commit-gate-bridge-submit",
          status: "requires_confirmation_before_execution",
          final_action_ref: null,
          user_confirmation_required: true,
        },
        human_handoff_state: {
          handoff_ref: "handoff-bridge-confirmation",
          reason: "external_effect_confirmation",
        },
      },
    }),
  ]);

  assert.deepEqual(
    projection.reactFlowNodes.map((node) => node.id),
    [
      "computer-use.observe",
      "computer-use.build-affordance-graph",
      "computer-use.propose-action",
      "computer-use.commit-or-handoff",
    ],
  );
  assert.deepEqual(
    projection.reactFlowNodes.map((node) => node.data.componentKind),
    [
      "computer_use_harness",
      "computer_use_harness",
      "computer_use_harness",
      "computer_use_harness",
    ],
  );
  assert.equal(projection.nodes[0]?.computerUse?.observationRef, "observation-bridge");
  assert.equal(projection.nodes[0]?.computerUse?.targetCount, 1);
  assert.equal(projection.nodes[1]?.computerUse?.affordanceGraphRef, "affordance-bridge");
  assert.equal(projection.nodes[1]?.computerUse?.affordanceCount, 1);
  assert.equal(projection.nodes[2]?.status, "waiting");
  assert.equal(projection.nodes[2]?.label, "Computer use: propose action");
  assert.equal(projection.nodes[2]?.computerUse?.proposalRef, "proposal-bridge-click");
  assert.equal(projection.nodes[2]?.computerUse?.actionRef, null);
  assert.equal(
    projection.nodes[2]?.computerUse?.policyDecisionRef,
    "policy-bridge-confirmation",
  );
  assert.equal(projection.nodes[3]?.status, "waiting");
  assert.equal(projection.nodes[3]?.label, "Computer use: commit gate");
  assert.equal(
    projection.nodes[3]?.computerUse?.commitGateRef,
    "commit-gate-bridge-submit",
  );
  assert.equal(
    projection.nodes[3]?.computerUse?.commitGateStatus,
    "requires_confirmation_before_execution",
  );
  assert.equal(projection.nodes[3]?.computerUse?.actionRef, null);
  assert.equal(projection.nodes[3]?.computerUse?.outcomeRef, "outcome-bridge-submit");
  assert.equal(
    projection.nodes[3]?.computerUse?.humanHandoffRef,
    "handoff-bridge-confirmation",
  );
  assert.deepEqual(
    projection.reactFlowEdges.map((edge) => [edge.source, edge.target]),
    [
      ["computer-use.observe", "computer-use.build-affordance-graph"],
      ["computer-use.build-affordance-graph", "computer-use.propose-action"],
      ["computer-use.propose-action", "computer-use.commit-or-handoff"],
    ],
  );
});

test("projects unavailable computer-use lanes as blocked recovery evidence", () => {
  const unavailable = event("computer-use-unavailable", 1, {
    eventKind: "computer_use.environment_unavailable",
    sourceEventKind: "ComputerUse.EnvironmentUnavailable",
    status: "blocked",
    componentKind: null,
    workflowNodeId: null,
    payloadSchemaVersion: "ioi.computer-use.harness.v1",
    payload: {
      computer_use_step: "acquire_lease",
      computer_use_lane: "sandboxed_hosted",
      computer_use_session_mode: "hosted_sandbox",
      computer_use_lease_id: "lease-hosted-unavailable",
      computer_use_blocker: "adapter_unavailable",
      recovery_policy: {
        policy_id: "computer-use-recovery:run:sandboxed_hosted",
        failure_class: "environment",
        allowed_actions: ["terminate_safely", "switch_to_browser_lane"],
      },
    },
  });

  const projection = projectRuntimeThreadEventsToWorkflowProjection([unavailable]);

  assert.equal(
    workflowNodeIdForRuntimeThreadEvent(unavailable),
    "computer-use.acquire-lease",
  );
  assert.equal(projection.nodes[0]?.nodeKind, "gui_harness_validation");
  assert.equal(projection.nodes[0]?.componentKind, "computer_use_harness");
  assert.equal(projection.nodes[0]?.status, "blocked");
  assert.equal(projection.nodes[0]?.label, "Computer use unavailable");
  assert.equal(projection.nodes[0]?.computerUse?.lane, "sandboxed_hosted");
  assert.equal(projection.nodes[0]?.computerUse?.sessionMode, "hosted_sandbox");
  assert.equal(projection.nodes[0]?.computerUse?.blocker, "adapter_unavailable");
  assert.deepEqual(projection.nodes[0]?.computerUse?.recoveryPolicy, {
    policy_id: "computer-use-recovery:run:sandboxed_hosted",
    failure_class: "environment",
    allowed_actions: ["terminate_safely", "switch_to_browser_lane"],
  });
});

test("projects workspace trust warnings as workspace trust gate React Flow rows", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-workspace-trust", 1, {
      type: "workspace_trust_warning",
      eventKind: "workspace.trust_warning",
      sourceEventKind: "WorkspaceTrust.Warning",
      status: "warning",
      workflowNodeId: "runtime.thread-mode.yolo.workspace-trust",
      componentKind: "workspace_trust",
      payloadSchemaVersion: "ioi.runtime.workspace-trust-warning.v1",
      receiptRefs: ["receipt-workspace-trust"],
      policyDecisionRefs: ["policy-workspace-trust-yolo"],
      payload: {
        warning_id: "workspace_trust_test",
        mode: "yolo",
        approval_mode: "never_prompt",
        severity: "high",
        message: "YOLO mode can run without further prompts.",
      },
    }),
  ]);

  assert.equal(projection.nodes[0]?.nodeKind, "runtime_workspace_trust_gate");
  assert.equal(projection.nodes[0]?.componentKind, "workspace_trust");
  assert.equal(projection.nodes[0]?.label, "Workspace trust warning");
  assert.equal(projection.nodes[0]?.status, "warning");
  assert.equal(
    projection.nodes[0]?.workflowNodeId,
    "runtime.thread-mode.yolo.workspace-trust",
  );
  assert.deepEqual(projection.nodes[0]?.receiptRefs, ["receipt-workspace-trust"]);
  assert.deepEqual(projection.nodes[0]?.workspaceTrustActions[0], {
    id: "workspace-trust:thread-test:workspace_trust_test:acknowledge",
    action: "acknowledge",
    label: "Acknowledge warning",
    summary: "YOLO mode can run without further prompts.",
    status: "available",
    executable: true,
    warningId: "workspace_trust_test",
    severity: "high",
    mode: "yolo",
    approvalMode: "never_prompt",
    threadId: "thread-test",
    workflowGraphId: "workflow-test",
    workflowNodeId: "runtime.thread-mode.yolo.workspace-trust",
    eventId: "event-workspace-trust",
    sourceEventId: "event-workspace-trust",
    receiptRefs: ["receipt-workspace-trust"],
    policyDecisionRefs: ["policy-workspace-trust-yolo"],
  });
});

test("projects workspace trust acknowledgements as completed hook-policy rows", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-workspace-trust", 1, {
      type: "workspace_trust_warning",
      eventKind: "workspace.trust_warning",
      sourceEventKind: "WorkspaceTrust.Warning",
      status: "warning",
      workflowNodeId: "runtime.thread-mode.yolo.workspace-trust",
      componentKind: "workspace_trust",
      payloadSchemaVersion: "ioi.runtime.workspace-trust-warning.v1",
      receiptRefs: ["receipt-workspace-trust"],
      policyDecisionRefs: ["policy-workspace-trust-yolo"],
      payload: {
        warning_id: "workspace_trust_test",
        mode: "yolo",
        approval_mode: "never_prompt",
        severity: "high",
      },
    }),
    event("event-workspace-trust-ack", 2, {
      type: "workspace_trust_acknowledged",
      eventKind: "workspace.trust_acknowledged",
      sourceEventKind: "WorkspaceTrust.Acknowledged",
      status: "completed",
      workflowNodeId: "runtime.thread-mode.yolo.workspace-trust",
      componentKind: "workspace_trust",
      payloadSchemaVersion: "ioi.runtime.workspace-trust-acknowledgement.v1",
      receiptRefs: ["receipt-workspace-trust-ack"],
      policyDecisionRefs: ["policy-workspace-trust-ack"],
      payload: {
        warning_id: "workspace_trust_test",
        source_event_id: "event-workspace-trust",
        status: "acknowledged",
      },
    }),
  ]);

  assert.equal(projection.nodes[0]?.label, "Workspace trust acknowledged");
  assert.equal(projection.nodes[0]?.status, "completed");
  assert.equal(projection.nodes[0]?.workspaceTrustActions[0]?.status, "acknowledged");
  assert.equal(projection.nodes[0]?.workspaceTrustActions[0]?.executable, false);
  assert.deepEqual(projection.nodes[0]?.workspaceTrustActions[0]?.receiptRefs, [
    "receipt-workspace-trust",
    "receipt-workspace-trust-ack",
  ]);
});

test("projects workflow edit proposals as proposal React Flow rows", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-workflow-edit-proposed", 1, {
      type: "workflow_edit_proposed",
      eventKind: "workflow.edit_proposed",
      sourceEventKind: "WorkflowEdit.Proposed",
      status: "waiting_for_approval",
      workflowNodeId: "runtime.workflow-edit-proposal.proposal-a",
      componentKind: "workflow_edit_proposal",
      approvalId: "approval-a",
      payloadSchemaVersion: "ioi.runtime.workflow-edit-proposal.v1",
      receiptRefs: ["receipt-proposal"],
      policyDecisionRefs: ["policy-proposal"],
      payload: {
        proposal_id: "proposal-a",
        approval_id: "approval-a",
        summary: "Proposal-only workflow edit staged for approval.",
      },
    }),
    event("event-workflow-edit-applied", 2, {
      type: "workflow_edit_applied",
      eventKind: "workflow.edit_applied",
      sourceEventKind: "WorkflowEdit.Applied",
      status: "completed",
      workflowNodeId: "runtime.workflow-edit-proposal.proposal-a",
      componentKind: "workflow_edit_proposal",
      approvalId: "approval-a",
      payloadSchemaVersion: "ioi.runtime.workflow-edit-apply.v1",
      receiptRefs: ["receipt-apply"],
      policyDecisionRefs: ["policy-apply"],
      payload: {
        proposal_id: "proposal-a",
        mutation_executed: true,
      },
    }),
  ]);

  assert.equal(projection.nodes[0]?.nodeKind, "proposal");
  assert.equal(projection.nodes[0]?.componentKind, "workflow_edit_proposal");
  assert.equal(projection.nodes[0]?.label, "Workflow edit applied");
  assert.equal(projection.nodes[0]?.status, "completed");
  assert.equal(
    projection.nodes[0]?.workflowNodeId,
    "runtime.workflow-edit-proposal.proposal-a",
  );
  assert.deepEqual(projection.nodes[0]?.eventIds, [
    "event-workflow-edit-proposed",
    "event-workflow-edit-applied",
  ]);
  assert.deepEqual(projection.nodes[0]?.receiptRefs, [
    "receipt-proposal",
    "receipt-apply",
  ]);
});

test("projects coding tool events as receipt-backed React Flow rows", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-coding-status", 1, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.WorkspaceStatus",
      workflowNodeId: "runtime.coding-tool.workspace.status",
      componentKind: "coding_tool",
      toolName: "workspace.status",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-status"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Workspace status inspected 1 changed file(s).",
      },
    }),
    event("event-coding-patch", 2, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.FileApplyPatch",
      workflowNodeId: "runtime.coding-tool.file.apply-patch",
      componentKind: "coding_tool",
      toolName: "file.apply_patch",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-patch"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Patch applied to README.md.",
      },
    }),
    event("event-workspace-snapshot", 3, {
      type: "runtime_step",
      eventKind: "workspace.snapshot.created",
      sourceEventKind: "WorkspaceSnapshot.Created",
      workflowNodeId: "runtime.workspace-snapshot",
      componentKind: "workspace_snapshot",
      payloadSchemaVersion: "ioi.runtime.workspace-snapshot.v1",
      receiptRefs: ["receipt-workspace-snapshot"],
      artifactRefs: ["artifact-workspace-snapshot"],
      rollbackRefs: ["workspace_snapshot_123"],
      payload: {
        summary: "Workspace snapshot recorded 1 changed file(s) for coding_tool_123.",
      },
    }),
    event("event-restore-preview", 4, {
      type: "runtime_step",
      eventKind: "workspace.restore.previewed",
      sourceEventKind: "WorkspaceRestore.Previewed",
      workflowNodeId: "runtime.restore-gate",
      componentKind: "restore_gate",
      payloadSchemaVersion: "ioi.runtime.workspace-restore-preview.v1",
      receiptRefs: ["receipt-restore-preview"],
      artifactRefs: ["artifact-restore-preview"],
      rollbackRefs: ["workspace_snapshot_123"],
      payload: {
        summary: "Restore preview ready for 1 file(s) from workspace_snapshot_123.",
      },
    }),
    event("event-restore-apply", 5, {
      type: "runtime_step",
      eventKind: "workspace.restore.applied",
      sourceEventKind: "WorkspaceRestore.Applied",
      workflowNodeId: "runtime.restore-apply",
      componentKind: "restore_gate",
      payloadSchemaVersion: "ioi.runtime.workspace-restore-apply.v1",
      receiptRefs: ["receipt-restore-apply"],
      artifactRefs: ["artifact-restore-apply"],
      rollbackRefs: ["workspace_snapshot_123"],
      payload: {
        summary: "Restore apply restored 1 file(s) from workspace_snapshot_123.",
      },
    }),
    event("event-coding-test", 6, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.TestRun",
      workflowNodeId: "runtime.coding-tool.test.run",
      componentKind: "coding_tool",
      toolName: "test.run",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-test"],
      artifactRefs: ["artifact-coding-test-output"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Test run passed with exit code 0.",
      },
    }),
    event("event-coding-diagnostics", 7, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.LspDiagnostics",
      workflowNodeId: "runtime.coding-tool.lsp.diagnostics",
      componentKind: "coding_tool",
      toolName: "lsp.diagnostics",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-diagnostics"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Diagnostics findings with 1 finding(s).",
      },
    }),
    event("event-diagnostics-injected", 8, {
      type: "runtime_step",
      eventKind: "lsp.diagnostics.injected",
      sourceEventKind: "LspDiagnostics.Injected",
      workflowNodeId: "runtime.lsp-diagnostics.injected",
      componentKind: "lsp_diagnostics",
      payloadSchemaVersion: "ioi.runtime.lsp-diagnostics-injection.v1",
      receiptRefs: ["receipt-lsp-diagnostics-injected"],
      payload: {
        summary: "Injected 1 post-edit diagnostic finding(s).",
      },
    }),
    event("event-coding-retrieve", 9, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.ToolRetrieveResult",
      workflowNodeId: "runtime.coding-tool.tool.retrieve-result",
      componentKind: "coding_tool",
      toolName: "tool.retrieve_result",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-retrieve"],
      artifactRefs: ["artifact-coding-test-output"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Retrieved tool result coding_tool_123.",
      },
    }),
  ]);

  const node = projection.nodes[0];
  assert.equal(node?.workflowNodeId, "runtime.coding-tool.workspace.status");
  assert.equal(node?.nodeKind, "plugin_tool");
  assert.equal(node?.componentKind, "coding_tool");
  assert.equal(node?.label, "Coding tool: workspace.status");
  assert.equal(node?.toolName, "workspace.status");
  assert.equal(node?.latestPayloadSchemaVersion, "ioi.runtime.coding-tool-result.v1");
  assert.deepEqual(node?.receiptRefs, ["receipt-coding-status"]);
  assert.equal(node?.summary, "Workspace status inspected 1 changed file(s).");
  const patchNode = projection.nodes[1];
  assert.equal(patchNode?.workflowNodeId, "runtime.coding-tool.file.apply-patch");
  assert.equal(patchNode?.label, "Coding tool: file.apply_patch");
  assert.equal(patchNode?.toolName, "file.apply_patch");
  assert.deepEqual(patchNode?.receiptRefs, ["receipt-coding-patch"]);
  assert.equal(patchNode?.summary, "Patch applied to README.md.");
  const snapshotNode = projection.nodes[2];
  assert.equal(snapshotNode?.workflowNodeId, "runtime.workspace-snapshot");
  assert.equal(snapshotNode?.nodeKind, "quality_ledger");
  assert.equal(snapshotNode?.componentKind, "workspace_snapshot");
  assert.equal(snapshotNode?.label, "Workspace snapshot");
  assert.deepEqual(snapshotNode?.receiptRefs, ["receipt-workspace-snapshot"]);
  assert.deepEqual(snapshotNode?.artifactRefs, ["artifact-workspace-snapshot"]);
  assert.deepEqual(snapshotNode?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(
    snapshotNode?.summary,
    "Workspace snapshot recorded 1 changed file(s) for coding_tool_123.",
  );
  const restoreNode = projection.nodes[3];
  assert.equal(restoreNode?.workflowNodeId, "runtime.restore-gate");
  assert.equal(restoreNode?.nodeKind, "hook_policy");
  assert.equal(restoreNode?.componentKind, "restore_gate");
  assert.equal(restoreNode?.label, "Restore preview");
  assert.deepEqual(restoreNode?.receiptRefs, ["receipt-restore-preview"]);
  assert.deepEqual(restoreNode?.artifactRefs, ["artifact-restore-preview"]);
  assert.deepEqual(restoreNode?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(
    restoreNode?.summary,
    "Restore preview ready for 1 file(s) from workspace_snapshot_123.",
  );
  const restoreApplyNode = projection.nodes[4];
  assert.equal(restoreApplyNode?.workflowNodeId, "runtime.restore-apply");
  assert.equal(restoreApplyNode?.nodeKind, "hook_policy");
  assert.equal(restoreApplyNode?.componentKind, "restore_gate");
  assert.equal(restoreApplyNode?.label, "Restore apply");
  assert.deepEqual(restoreApplyNode?.receiptRefs, ["receipt-restore-apply"]);
  assert.deepEqual(restoreApplyNode?.artifactRefs, ["artifact-restore-apply"]);
  assert.deepEqual(restoreApplyNode?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(
    restoreApplyNode?.summary,
    "Restore apply restored 1 file(s) from workspace_snapshot_123.",
  );
  const testNode = projection.nodes[5];
  assert.equal(testNode?.workflowNodeId, "runtime.coding-tool.test.run");
  assert.equal(testNode?.label, "Coding tool: test.run");
  assert.equal(testNode?.toolName, "test.run");
  assert.deepEqual(testNode?.receiptRefs, ["receipt-coding-test"]);
  assert.deepEqual(testNode?.artifactRefs, ["artifact-coding-test-output"]);
  assert.equal(testNode?.summary, "Test run passed with exit code 0.");
  const diagnosticsNode = projection.nodes[6];
  assert.equal(diagnosticsNode?.workflowNodeId, "runtime.coding-tool.lsp.diagnostics");
  assert.equal(diagnosticsNode?.label, "Coding tool: lsp.diagnostics");
  assert.deepEqual(diagnosticsNode?.receiptRefs, ["receipt-coding-diagnostics"]);
  const injectedNode = projection.nodes[7];
  assert.equal(injectedNode?.workflowNodeId, "runtime.lsp-diagnostics.injected");
  assert.equal(injectedNode?.label, "Diagnostics injected");
  assert.deepEqual(injectedNode?.receiptRefs, ["receipt-lsp-diagnostics-injected"]);
  assert.equal(injectedNode?.summary, "Injected 1 post-edit diagnostic finding(s).");
  const retrieveNode = projection.nodes[8];
  assert.equal(retrieveNode?.workflowNodeId, "runtime.coding-tool.tool.retrieve-result");
  assert.equal(retrieveNode?.label, "Coding tool: tool.retrieve_result");
  assert.deepEqual(retrieveNode?.artifactRefs, ["artifact-coding-test-output"]);
});

test("projects coding tool budget blocks as policy-addressable React Flow rows", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-coding-budget-blocked", 1, {
      type: "policy_blocked",
      eventKind: "policy.blocked",
      sourceEventKind: "CodingTool.FileApplyPatch",
      status: "blocked",
      workflowNodeId: "workflow.coding.file.apply_patch.summary-budget",
      workflowGraphId: "workflow.react-flow.coding-tool-summary-budget",
      componentKind: "coding_tool",
      toolName: "file.apply_patch",
      toolCallId: "coding_tool_summary_budget_blocked",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: [
        "receipt_coding_tool_file_apply_patch_budget",
        "receipt_context_budget_thread_budget",
      ],
      policyDecisionRefs: ["policy_context_budget_thread_budget_blocked"],
      payload: {
        event_kind: "CodingToolBudgetBlocked",
        tool_name: "file.apply_patch",
        tool_call_id: "coding_tool_summary_budget_blocked",
        status: "blocked",
        summary:
          "file.apply_patch blocked because the workflow coding-tool budget was exceeded.",
        budget_status: "exceeded",
        context_budget_status: "blocked",
        result_summary: {
          status: "blocked",
          reason: "coding_tool_budget_exceeded",
        },
        result: {
          status: "blocked",
          budget_status: "exceeded",
          context_budget_status: "blocked",
        },
        error: {
          code: "coding_tool_budget_exceeded",
          details: {
            reason: "coding_tool_budget_exceeded",
          },
        },
        context_budget: {
          status: "blocked",
          mode: "block",
          policy_decision_id: "policy_context_budget_thread_budget_blocked",
          receipt_refs: ["receipt_context_budget_thread_budget"],
          policy_decision_refs: ["policy_context_budget_thread_budget_blocked"],
          checks: [
            { id: "total_tokens", severity: "violation", actual: 720, limit: 100 },
            { id: "estimated_cost_usd", severity: "ok", actual: 0.0042, limit: 1 },
            { id: "context_pressure", severity: "ok", actual: 0.72, limit: 1 },
          ],
          violations: [
            { id: "total_tokens", severity: "violation", actual: 720, limit: 100 },
          ],
          usage_summary: {
            total_tokens: 720,
            estimated_cost_usd: 0.0042,
            context_pressure: 0.72,
          },
        },
        budget_usage_telemetry: {
          total_tokens: 720,
          estimated_cost_usd: 0.0042,
          context_pressure: 0.72,
        },
      },
    }),
  ]);

  const node = projection.nodes[0];
  assert.equal(node?.workflowNodeId, "workflow.coding.file.apply_patch.summary-budget");
  assert.equal(node?.workflowGraphId, "workflow.react-flow.coding-tool-summary-budget");
  assert.equal(node?.nodeKind, "plugin_tool");
  assert.equal(node?.componentKind, "coding_tool");
  assert.equal(node?.label, "Coding tool budget: file.apply_patch");
  assert.equal(node?.status, "blocked");
  assert.equal(node?.toolName, "file.apply_patch");
  assert.equal(node?.toolCallId, "coding_tool_summary_budget_blocked");
  assert.equal(node?.codingToolBudgetStatus, "exceeded");
  assert.equal(node?.codingToolBudgetReason, "coding_tool_budget_exceeded");
  assert.equal(node?.codingToolContextBudgetStatus, "blocked");
  assert.equal(node?.codingToolBudgetMode, "block");
  assert.equal(
    node?.codingToolBudgetDecisionId,
    "policy_context_budget_thread_budget_blocked",
  );
  assert.equal(node?.codingToolBudgetCheckCount, 3);
  assert.equal(node?.codingToolBudgetViolationCount, 1);
  assert.equal(node?.codingToolMutationBlocked, true);
  assert.deepEqual(
    node?.codingToolBudgetChecks.map((check) =>
      typeof check === "object" && check !== null
        ? (check as { id?: unknown }).id
        : null,
    ),
    ["total_tokens", "estimated_cost_usd", "context_pressure"],
  );
  assert.equal(node?.codingToolBudgetUsageTelemetry?.total_tokens, 720);
  assert.deepEqual(node?.policyDecisionRefs, [
    "policy_context_budget_thread_budget_blocked",
  ]);
  assert.equal(
    node?.reactFlowNode.data.codingToolBudgetViolationCount,
    1,
  );
});

test("projects workflow-run coding budget preflight blocks as coding-tool policy events", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-workflow-run-preflight-blocked", 1, {
      type: "policy_blocked",
      eventKind: "policy.blocked",
      sourceEventKind: "WorkflowRunCodingToolBudgetPreflightBlocked",
      status: "blocked",
      componentKind: "coding_tool",
      workflowNodeId: "runtime.coding-tool-budget-preflight",
      workflowGraphId: "workflow.react-flow.coding-tool-preflight",
      payloadSchemaVersion: "ioi.workflow.coding-tool-budget-preflight.v1",
      receiptRefs: ["receipt_workflow_run_coding_tool_budget_preflight"],
      policyDecisionRefs: [
        "policy_workflow_run_coding_tool_budget_preflight_blocked",
      ],
      payload: {
        eventKind: "WorkflowRunCodingToolBudgetPreflightBlocked",
        reason: "coding_tool_budget_preflight_blocked",
        runId: "run-budget-preflight",
        status: "blocked",
        summary: "Workflow run blocked by coding-tool budget preflight.",
        budgetStatus: "warning",
        contextBudgetStatus: "blocked",
        mutationBlocked: true,
        recoveryPolicy: {
          schemaVersion: "ioi.workflow.coding-tool-budget-recovery-policy.v1",
          approvalScope: "target_nodes",
          operatorRole: "operator",
          retryLimit: 1,
          ttlMs: 900000,
          targetNodeIds: ["runtime.coding-tool-budget-preflight"],
        },
        result: {
          status: "blocked",
          mutationBlocked: true,
        },
      },
    }),
  ]);

  const node = projection.nodes[0];
  assert.equal(node?.workflowNodeId, "runtime.coding-tool-budget-preflight");
  assert.equal(node?.nodeKind, "plugin_tool");
  assert.equal(node?.componentKind, "coding_tool");
  assert.equal(node?.label, "Coding tool budget: blocked");
  assert.equal(node?.status, "blocked");
  assert.equal(
    node?.codingToolBudgetReason,
    "coding_tool_budget_preflight_blocked",
  );
  assert.equal(node?.codingToolBudgetStatus, "warning");
  assert.equal(node?.codingToolContextBudgetStatus, "blocked");
  assert.equal(node?.codingToolMutationBlocked, true);
  assert.deepEqual(node?.receiptRefs, [
    "receipt_workflow_run_coding_tool_budget_preflight",
  ]);
  assert.deepEqual(
    node?.codingToolBudgetRecoveryActions.map((action) => [
      action.action,
      action.status,
      action.executable,
    ]),
    [
      ["review_receipt", "available", false],
      ["request_approval", "available", true],
      ["approve_override", "waiting", false],
      ["reject_override", "waiting", false],
      ["retry_approved", "waiting", false],
    ],
  );
  assert.equal(
    node?.codingToolBudgetRecoveryActions[1]?.schemaVersion,
    "ioi.workflow.coding-tool-budget-recovery.v1",
  );
  assert.equal(
    node?.codingToolBudgetRecoveryActions[1]?.eventId,
    "event-workflow-run-preflight-blocked",
  );
  assert.equal(
    node?.codingToolBudgetRecoveryActions[1]?.runId,
    "run-budget-preflight",
  );
  assert.equal(
    node?.codingToolBudgetRecoveryActions[1]?.recoveryPolicy?.approvalScope,
    "target_nodes",
  );
});

test("projects coding budget recovery approval and retry actions", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-workflow-run-preflight-blocked", 1, {
      type: "policy_blocked",
      eventKind: "policy.blocked",
      sourceEventKind: "WorkflowRunCodingToolBudgetPreflightBlocked",
      status: "blocked",
      componentKind: "coding_tool",
      workflowNodeId: "runtime.coding-tool-budget-preflight",
      workflowGraphId: "workflow.react-flow.coding-tool-preflight",
      payloadSchemaVersion: "ioi.workflow.coding-tool-budget-preflight.v1",
      receiptRefs: ["receipt-preflight"],
      policyDecisionRefs: ["policy-preflight"],
      payload: {
        reason: "coding_tool_budget_preflight_blocked",
        status: "blocked",
        contextBudgetStatus: "blocked",
        mutationBlocked: true,
        recoveryPolicy: {
          schemaVersion: "ioi.workflow.coding-tool-budget-recovery-policy.v1",
          source: "react_flow_coding_tool_pack",
          approvalScope: "target_nodes",
          operatorRole: "budget_operator",
          retryLimit: 2,
          ttlMs: 300000,
          requiresApproval: true,
          allowOverride: true,
          targetNodeIds: ["node-write"],
          sourceNodeIds: ["node-write"],
        },
        targetNodeIds: ["node-write"],
      },
    }),
    event("event-approval-required", 2, {
      type: "approval_required",
      eventKind: "approval.required",
      sourceEventKind: "OperatorApproval.Request",
      status: "waiting_for_approval",
      componentKind: "approval_gate",
      workflowNodeId: "runtime.coding-tool-budget-preflight",
      workflowGraphId: "workflow.react-flow.coding-tool-preflight",
      approvalId: "approval-budget",
      payloadSchemaVersion: "ioi.runtime.approval-request.v1",
      receiptRefs: ["receipt-approval-request"],
      policyDecisionRefs: ["policy-approval-request"],
      payload: {
        reason: "coding_tool_budget_preflight_blocked",
        sourceEventId: "event-workflow-run-preflight-blocked",
        approvalId: "approval-budget",
        targetNodeIds: ["node-write"],
      },
    }),
    event("event-approval-approved", 3, {
      type: "approval_decision",
      eventKind: "approval.approved",
      sourceEventKind: "OperatorApproval.Approve",
      status: "approved",
      componentKind: "approval_gate",
      workflowNodeId: "runtime.coding-tool-budget-preflight",
      workflowGraphId: "workflow.react-flow.coding-tool-preflight",
      approvalId: "approval-budget",
      payloadSchemaVersion: "ioi.runtime.approval-decision.v1",
      receiptRefs: ["receipt-approval-approved"],
      policyDecisionRefs: ["policy-approval-approved"],
      payload: {
        decision: "approve",
        approvalId: "approval-budget",
        approvalRequestEventId: "event-approval-required",
        targetNodeIds: ["node-write"],
      },
    }),
    event("event-retry-completed", 4, {
      type: "tool_completed",
      eventKind: "workflow.run.retry_completed",
      sourceEventKind: "WorkflowRunCodingToolBudgetApprovedRetry",
      status: "completed",
      componentKind: "coding_tool",
      workflowNodeId: "runtime.coding-tool-budget-preflight",
      workflowGraphId: "workflow.react-flow.coding-tool-preflight",
      approvalId: "approval-budget",
      payloadSchemaVersion: "ioi.workflow.coding-tool-budget-recovery.v1",
      receiptRefs: ["receipt-retry"],
      policyDecisionRefs: ["policy-retry"],
      payload: {
        approvalId: "approval-budget",
        approvalSatisfied: true,
        approvalDecisionEventId: "event-approval-approved",
        targetNodeIds: ["node-write"],
      },
    }),
  ]);

  const node = projection.nodes[0];
  assert.deepEqual(
    node?.codingToolBudgetRecoveryActions.map((action) => [
      action.action,
      action.status,
      action.executable,
    ]),
    [
      ["review_receipt", "completed", false],
      ["request_approval", "completed", false],
      ["approve_override", "completed", false],
      ["reject_override", "blocked", false],
      ["retry_approved", "completed", false],
    ],
  );
  assert.equal(
    node?.codingToolBudgetRecoveryActions[4]?.approvalDecisionEventId,
    "event-approval-approved",
  );
  assert.deepEqual(node?.codingToolBudgetRecoveryActions[4]?.targetNodeIds, [
    "node-write",
  ]);
  assert.equal(
    node?.codingToolBudgetRecoveryActions[4]?.recoveryPolicy?.operatorRole,
    "budget_operator",
  );
  assert.equal(
    node?.codingToolBudgetRecoveryActions[4]?.recoveryPolicy?.retryLimit,
    2,
  );
  assert.deepEqual(node?.codingToolBudgetRecoveryActions[4]?.receiptRefs, [
    "receipt-preflight",
    "receipt-approval-request",
    "receipt-approval-approved",
    "receipt-retry",
  ]);
});

test("projects approval and policy events without workflow node ids", () => {
  const approval = event("event-approval", 1, {
    type: "approval_required",
    eventKind: "approval.required",
    sourceEventKind: "KernelEvent::ApprovalRequired",
    approvalId: "approval-123",
    status: "waiting_for_input",
  });
  const policy = event("event-policy", 2, {
    type: "policy_blocked",
    eventKind: "policy.blocked",
    sourceEventKind: "KernelEvent::PolicyBlocked",
    status: "blocked",
    policyDecisionRefs: ["policy-deny"],
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([approval, policy]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(approval), "runtime.approval.approval-123");
  assert.equal(nodes[0]?.nodeKind, "human_gate");
  assert.equal(nodes[0]?.status, "waiting");
  assert.equal(nodes[1]?.workflowNodeId, "runtime.policy");
  assert.equal(nodes[1]?.nodeKind, "hook_policy");
  assert.equal(nodes[1]?.status, "blocked");
  assert.deepEqual(nodes[1]?.policyDecisionRefs, ["policy-deny"]);
});

test("projects approval decisions as human-gate React Flow rows", () => {
  const approval = event("event-approval", 1, {
    type: "approval_required",
    eventKind: "approval.required",
    sourceEventKind: "OperatorApproval.Request",
    componentKind: "approval_gate",
    workflowNodeId: "workflow.coding.file.apply_patch",
    approvalId: "approval-123",
    status: "waiting_for_input",
    receiptRefs: ["receipt-approval-required"],
    policyDecisionRefs: ["policy-approval-required"],
  });
  const decision = event("event-approval-approved", 2, {
    type: "approval_decision",
    eventKind: "approval.approved",
    sourceEventKind: "OperatorApproval.Approve",
    componentKind: "approval_gate",
    workflowNodeId: "workflow.coding.file.apply_patch",
    approvalId: "approval-123",
    status: "approved",
    receiptRefs: ["receipt-approval-approved"],
    policyDecisionRefs: ["policy-approval-approved"],
    payloadSchemaVersion: "ioi.runtime.approval-decision.v1",
    payload: {
      approval_id: "approval-123",
      decision: "approve",
      approval_request_event_id: "event-approval",
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([approval, decision]);

  assert.equal(nodes.length, 1);
  assert.equal(nodes[0]?.nodeKind, "human_gate");
  assert.equal(nodes[0]?.componentKind, "approval_gate");
  assert.equal(nodes[0]?.label, "Approval approved");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.eventIds, ["event-approval", "event-approval-approved"]);
  assert.deepEqual(nodes[0]?.receiptRefs, [
    "receipt-approval-required",
    "receipt-approval-approved",
  ]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, [
    "policy-approval-required",
    "policy-approval-approved",
  ]);
});

test("projects diagnostics blocking gates as workflow-addressable policy nodes", () => {
  const gate = event("event-diagnostics-gate", 6, {
    type: "policy_blocked",
    eventKind: "policy.blocked",
    sourceEventKind: "LspDiagnostics.BlockingGate",
    status: "blocked",
    workflowNodeId: "runtime.lsp-diagnostics.blocking-gate",
    componentKind: "lsp_diagnostics_gate",
    payloadSchemaVersion: "ioi.runtime.lsp-diagnostics-blocking-gate.v1",
    receiptRefs: ["receipt-lsp-diagnostics-gate"],
    policyDecisionRefs: [
      "policy-lsp-diagnostics-gate",
      "policy-lsp-diagnostics-gate-decision-repair-retry",
      "policy-lsp-diagnostics-gate-decision-restore-preview",
      "policy-lsp-diagnostics-gate-decision-restore-apply",
      "policy-lsp-diagnostics-gate-decision-operator-override",
    ],
    rollbackRefs: ["workspace_snapshot_123"],
    payload: {
      summary: "Blocking diagnostics gate paused model continuation after 1 finding(s).",
      reason: "post_edit_diagnostics_findings",
      repair_policy: {
        restoreConflictPolicy: "allow_override",
        restore_conflict_policy: "allow_override",
        workspaceSnapshotRefs: ["workspace_snapshot_123"],
        workspace_snapshot_refs: ["workspace_snapshot_123"],
        decisions: [
          {
            decisionId: "policy-lsp-diagnostics-gate-decision-repair-retry",
            decision_id: "policy-lsp-diagnostics-gate-decision-repair-retry",
            action: "repair_retry",
            status: "available",
            summary: "Retry with diagnostics context.",
          },
          {
            decisionId: "policy-lsp-diagnostics-gate-decision-restore-preview",
            decision_id: "policy-lsp-diagnostics-gate-decision-restore-preview",
            action: "restore_preview",
            status: "available",
          },
          {
            decisionId: "policy-lsp-diagnostics-gate-decision-restore-apply",
            decision_id: "policy-lsp-diagnostics-gate-decision-restore-apply",
            action: "restore_apply",
            status: "requires_approval",
            requiresApproval: true,
            requires_approval: true,
          },
          {
            decisionId: "policy-lsp-diagnostics-gate-decision-operator-override",
            decision_id: "policy-lsp-diagnostics-gate-decision-operator-override",
            action: "operator_override",
            status: "requires_approval",
            requiresApproval: true,
            requires_approval: true,
          },
        ],
      },
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([gate]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(gate), "runtime.lsp-diagnostics.blocking-gate");
  assert.equal(nodes[0]?.nodeKind, "hook_policy");
  assert.equal(nodes[0]?.componentKind, "lsp_diagnostics_gate");
  assert.equal(nodes[0]?.label, "Diagnostics blocking gate");
  assert.equal(nodes[0]?.status, "blocked");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-lsp-diagnostics-gate"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, [
    "policy-lsp-diagnostics-gate",
    "policy-lsp-diagnostics-gate-decision-repair-retry",
    "policy-lsp-diagnostics-gate-decision-restore-preview",
    "policy-lsp-diagnostics-gate-decision-restore-apply",
    "policy-lsp-diagnostics-gate-decision-operator-override",
  ]);
  assert.deepEqual(nodes[0]?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(nodes[0]?.latestPayloadSchemaVersion, "ioi.runtime.lsp-diagnostics-blocking-gate.v1");
  assert.equal(nodes[0]?.diagnosticsRepairActions.length, 4);
  assert.deepEqual(
    nodes[0]?.diagnosticsRepairActions.map((action) => action.action),
    ["repair_retry", "restore_preview", "restore_apply", "operator_override"],
  );
  assert.deepEqual(nodes[0]?.diagnosticsRepairActions[0], {
    id:
      "diagnostics-repair:thread-test:policy-lsp-diagnostics-gate-decision-repair-retry:repair_retry",
    decisionId: "policy-lsp-diagnostics-gate-decision-repair-retry",
    action: "repair_retry",
    label: "Retry repair",
    summary: "Retry with diagnostics context.",
    status: "available",
    executable: true,
    requiresApproval: false,
    approvalGranted: false,
    allowConflicts: true,
    restoreConflictPolicy: "allow_override",
    threadId: "thread-test",
    workflowGraphId: "workflow-test",
    workflowNodeId: "runtime.run-inspector.diagnostics-repair.repair-retry",
    eventId: "event-diagnostics-gate",
    rollbackRefs: ["workspace_snapshot_123"],
    workspaceSnapshotRefs: ["workspace_snapshot_123"],
    policyDecisionRefs: [
      "policy-lsp-diagnostics-gate",
      "policy-lsp-diagnostics-gate-decision-repair-retry",
      "policy-lsp-diagnostics-gate-decision-restore-preview",
      "policy-lsp-diagnostics-gate-decision-restore-apply",
      "policy-lsp-diagnostics-gate-decision-operator-override",
    ],
    receiptRefs: ["receipt-lsp-diagnostics-gate"],
  });
  assert.equal(nodes[0]?.diagnosticsRepairActions[2]?.requiresApproval, true);
  assert.equal(nodes[0]?.diagnosticsRepairActions[2]?.approvalGranted, true);
  assert.equal(nodes[0]?.diagnosticsRepairActions[2]?.allowConflicts, true);
});

test("projects diagnostics repair decisions as workflow-addressable policy nodes", () => {
  const repairDecision = event("event-diagnostics-repair-decision", 7, {
    type: "runtime_step",
    eventKind: "diagnostics.repair_decision.executed",
    sourceEventKind: "LspDiagnostics.RepairDecisionExecuted",
    status: "completed",
    workflowNodeId: "workflow.diagnostics.repair.restore-preview.decision",
    componentKind: "lsp_diagnostics_repair",
    payloadSchemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
    receiptRefs: ["receipt-lsp-diagnostics-repair"],
    policyDecisionRefs: [
      "policy-lsp-diagnostics-gate",
      "policy-lsp-diagnostics-gate-decision-restore-preview",
    ],
    rollbackRefs: ["workspace_snapshot_123"],
    payload: {
      summary: "Diagnostics repair decision restore_preview executed for workspace_snapshot_123.",
      action: "restore_preview",
      snapshot_id: "workspace_snapshot_123",
      restore_preview_event_id: "event-restore-preview",
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([repairDecision]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(repairDecision), "workflow.diagnostics.repair.restore-preview.decision");
  assert.equal(nodes[0]?.nodeKind, "hook_policy");
  assert.equal(nodes[0]?.componentKind, "lsp_diagnostics_repair");
  assert.equal(nodes[0]?.label, "Diagnostics repair decision");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-lsp-diagnostics-repair"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, [
    "policy-lsp-diagnostics-gate",
    "policy-lsp-diagnostics-gate-decision-restore-preview",
  ]);
  assert.deepEqual(nodes[0]?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(nodes[0]?.latestPayloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
});

test("projects diagnostics repair retry executions as workflow-addressable policy nodes", () => {
  const repairRetry = event("event-diagnostics-repair-retry", 8, {
    type: "runtime_step",
    eventKind: "diagnostics.repair_retry.created",
    sourceEventKind: "LspDiagnostics.RepairRetryTurnCreated",
    status: "completed",
    workflowNodeId: "workflow.diagnostics.repair.retry",
    componentKind: "lsp_diagnostics_repair_retry",
    payloadSchemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
    receiptRefs: ["receipt-lsp-diagnostics-repair-retry"],
    policyDecisionRefs: [
      "policy-lsp-diagnostics-gate",
      "policy-lsp-diagnostics-gate-decision-repair-retry",
    ],
    rollbackRefs: ["workspace_snapshot_123"],
    payload: {
      summary: "Diagnostics repair retry created turn turn_123.",
      action: "repair_retry",
      retry_turn_id: "turn_123",
      repair_prompt_injected: true,
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([repairRetry]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(repairRetry), "workflow.diagnostics.repair.retry");
  assert.equal(nodes[0]?.nodeKind, "hook_policy");
  assert.equal(nodes[0]?.componentKind, "lsp_diagnostics_repair_retry");
  assert.equal(nodes[0]?.label, "Diagnostics repair retry");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-lsp-diagnostics-repair-retry"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, [
    "policy-lsp-diagnostics-gate",
    "policy-lsp-diagnostics-gate-decision-repair-retry",
  ]);
  assert.deepEqual(nodes[0]?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(nodes[0]?.latestPayloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
});

test("projects diagnostics operator overrides as workflow-addressable policy nodes", () => {
  const operatorOverride = event("event-diagnostics-operator-override", 9, {
    type: "runtime_step",
    eventKind: "diagnostics.operator_override.executed",
    sourceEventKind: "LspDiagnostics.OperatorOverrideExecuted",
    status: "completed",
    workflowNodeId: "workflow.diagnostics.repair.operator-override",
    componentKind: "lsp_diagnostics_operator_override",
    payloadSchemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
    receiptRefs: ["receipt-lsp-diagnostics-operator-override"],
    policyDecisionRefs: [
      "policy-lsp-diagnostics-gate",
      "policy-lsp-diagnostics-gate-decision-operator-override",
    ],
    rollbackRefs: ["workspace_snapshot_123"],
    payload: {
      summary: "Diagnostics operator override granted.",
      action: "operator_override",
      approval_required: true,
      approval_satisfied: true,
      continuation_allowed: true,
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([operatorOverride]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(operatorOverride), "workflow.diagnostics.repair.operator-override");
  assert.equal(nodes[0]?.nodeKind, "hook_policy");
  assert.equal(nodes[0]?.componentKind, "lsp_diagnostics_operator_override");
  assert.equal(nodes[0]?.label, "Diagnostics operator override");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-lsp-diagnostics-operator-override"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, [
    "policy-lsp-diagnostics-gate",
    "policy-lsp-diagnostics-gate-decision-operator-override",
  ]);
  assert.deepEqual(nodes[0]?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(nodes[0]?.latestPayloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
});

test("projects operator interrupt events into the runtime control node", () => {
  const interrupt = event("event-interrupt", 4, {
    type: "turn_interrupted",
    eventKind: "turn.interrupted",
    sourceEventKind: "OperatorControl.Interrupt",
    status: "interrupted",
    componentKind: "operator_control",
    workflowNodeId: "runtime.operator-interrupt",
    receiptRefs: ["receipt-interrupt"],
    policyDecisionRefs: ["policy-interrupt-allow"],
    payloadSchemaVersion: "ioi.runtime.operator-control.v1",
    payload: { reason: "operator paused live validation" },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([interrupt]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(interrupt), "runtime.operator-interrupt");
  assert.equal(nodes[0]?.nodeKind, "runtime_operator_interrupt");
  assert.equal(nodes[0]?.componentKind, "operator_control");
  assert.equal(nodes[0]?.label, "Turn interrupted");
  assert.equal(nodes[0]?.status, "interrupted");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-interrupt"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, ["policy-interrupt-allow"]);
  assert.deepEqual(nodes[0]?.tuiDeepLink, {
    schemaVersion: WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    command: "ioi agent tui",
    args: [
      "agent",
      "tui",
      "--thread-id",
      "thread-test",
      "--since-seq",
      "4",
    ],
    reopenCommand: "ioi agent tui --thread-id thread-test --since-seq 4",
    threadId: "thread-test",
    turnId: "turn-test",
    workflowGraphId: "workflow-test",
    workflowNodeId: "runtime.operator-interrupt",
    eventId: "event-interrupt",
    eventKind: "turn.interrupted",
    componentKind: "operator_control",
    seq: 4,
    cursor: "events_thread:test:4",
    sinceSeq: 4,
    lastEventId: "event-interrupt",
  });
  assert.equal(
    nodes[0]?.reactFlowNode.data.tuiDeepLink.eventId,
    "event-interrupt",
  );
});

test("projects thread fork events into the runtime fork node", () => {
  const fork = event("event-fork", 4, {
    type: "thread_forked",
    eventKind: "thread.forked",
    sourceEventKind: "OperatorControl.Fork",
    status: "completed",
    componentKind: "thread_fork",
    workflowNodeId: "runtime.thread-fork",
    receiptRefs: ["receipt-fork"],
    policyDecisionRefs: ["policy-fork-allow"],
    payloadSchemaVersion: "ioi.runtime.thread-fork.v1",
    payload: { fork_thread_id: "thread-fork" },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([fork]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(fork), "runtime.thread-fork");
  assert.equal(nodes[0]?.nodeKind, "runtime_thread_fork");
  assert.equal(nodes[0]?.componentKind, "thread_fork");
  assert.equal(nodes[0]?.label, "Thread forked");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-fork"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, ["policy-fork-allow"]);
});

test("projects operator steer events into the runtime control node", () => {
  const steer = event("event-steer", 5, {
    type: "turn_steered",
    eventKind: "turn.steered",
    sourceEventKind: "OperatorControl.Steer",
    status: "completed",
    componentKind: "operator_control",
    workflowNodeId: "runtime.operator-steer",
    receiptRefs: ["receipt-steer"],
    policyDecisionRefs: ["policy-steer-allow"],
    payloadSchemaVersion: "ioi.runtime.operator-control.v1",
    payload: { guidance: "focus on the failing assertion" },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([steer]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(steer), "runtime.operator-steer");
  assert.equal(nodes[0]?.nodeKind, "runtime_operator_steer");
  assert.equal(nodes[0]?.componentKind, "operator_control");
  assert.equal(nodes[0]?.label, "Turn steered");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-steer"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, ["policy-steer-allow"]);
});

test("projects context compact events into the runtime compaction node", () => {
  const compact = event("event-compact", 6, {
    type: "context_compacted",
    eventKind: "context.compacted",
    sourceEventKind: "OperatorControl.Compact",
    status: "completed",
    componentKind: "context_compaction",
    workflowNodeId: "runtime.context-compact",
    receiptRefs: ["receipt-compact"],
    policyDecisionRefs: ["policy-compact-allow"],
    payloadSchemaVersion: "ioi.runtime.context-compaction.v1",
    payload: { reason: "reduce stale context" },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([compact]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(compact), "runtime.context-compact");
  assert.equal(nodes[0]?.nodeKind, "runtime_context_compact");
  assert.equal(nodes[0]?.componentKind, "context_compaction");
  assert.equal(nodes[0]?.label, "Context compacted");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-compact"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, ["policy-compact-allow"]);
});

test("projects compaction policy events into the runtime policy node", () => {
  const policy = event("event-compaction-policy", 7, {
    type: "compaction_policy_evaluated",
    eventKind: "compaction_policy.evaluated",
    sourceEventKind: "RuntimeCompactionPolicy.Evaluate",
    status: "completed",
    componentKind: "compaction_policy",
    workflowNodeId: "runtime.compaction-policy",
    receiptRefs: ["receipt-compaction-policy"],
    policyDecisionRefs: ["policy-compaction-compact"],
    payloadSchemaVersion: "ioi.runtime.compaction-policy.v1",
    payload: { action: "compact", budget_status: "blocked" },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([policy]);

  assert.equal(
    workflowNodeIdForRuntimeThreadEvent(policy),
    "runtime.compaction-policy",
  );
  assert.equal(nodes[0]?.nodeKind, "runtime_compaction_policy");
  assert.equal(nodes[0]?.componentKind, "compaction_policy");
  assert.equal(nodes[0]?.label, "Compaction policy");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-compaction-policy"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, ["policy-compaction-compact"]);
});

test("projects streaming usage and context-pressure deltas into runtime telemetry nodes", () => {
  const usageDelta = event("event-usage-delta", 8, {
    type: "usage_delta",
    eventKind: "usage.delta",
    sourceEventKind: "RuntimeUsageTelemetry.Delta",
    status: "running",
    componentKind: "usage_telemetry",
    workflowNodeId: "runtime.usage-telemetry",
    payloadSchemaVersion: "ioi.runtime.usage-delta.v1",
    payload: {
      stage: "completion_streamed",
      total_tokens: 1280,
      estimated_cost_usd: 0.00128,
      context_pressure: 0.01,
      context_pressure_status: "nominal",
      summary: "Usage delta 2/2: 1280 tokens, context 0.01.",
    },
  });
  const contextPressure = event("event-context-pressure", 9, {
    type: "context_pressure_delta",
    eventKind: "context.pressure_delta",
    sourceEventKind: "RuntimeContextPressure.Delta",
    status: "running",
    componentKind: "context_pressure",
    workflowNodeId: "runtime.context-budget",
    payloadSchemaVersion: "ioi.runtime.context-pressure-delta.v1",
    payload: {
      usage_context_pressure: 0.01,
      usage_context_pressure_status: "nominal",
      summary: "Context pressure delta 2/2: nominal at 0.01.",
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([
    usageDelta,
    contextPressure,
  ]);

  assert.equal(
    workflowNodeIdForRuntimeThreadEvent(usageDelta),
    "runtime.usage-telemetry",
  );
  assert.equal(
    workflowNodeIdForRuntimeThreadEvent(contextPressure),
    "runtime.context-budget",
  );
  assert.equal(nodes[0]?.nodeKind, "runtime_usage_meter");
  assert.equal(nodes[0]?.componentKind, "usage_telemetry");
  assert.equal(nodes[0]?.label, "Usage telemetry");
  assert.equal(nodes[0]?.status, "running");
  assert.equal(nodes[1]?.nodeKind, "runtime_context_budget");
  assert.equal(nodes[1]?.componentKind, "context_pressure");
  assert.equal(nodes[1]?.label, "Context pressure");
  assert.equal(nodes[1]?.status, "running");
});

test("projects context-pressure alerts into action rows", () => {
  const alert = event("event-context-alert", 10, {
    type: "context_pressure_alert",
    eventKind: "context.pressure_alert",
    sourceEventKind: "RuntimeContextPressure.Alert",
    status: "blocked",
    componentKind: "context_pressure_alert",
    workflowNodeId: "runtime.context-pressure-alert",
    payloadSchemaVersion: "ioi.runtime.context-pressure-alert.v1",
    receiptRefs: ["receipt-context-alert"],
    policyDecisionRefs: ["policy-context-alert-compact"],
    payload: {
      alert_id: "alert-context-pressure-high",
      alert_level: "blocked",
      scope: "subagent_aggregate",
      pressure: 0.91,
      pressure_status: "high",
      source_event_id: "event-context-pressure",
      summary: "Context pressure blocked subagent aggregate at 0.91.",
      actions: [
        {
          action: "compact",
          label: "Compact context",
          status: "available",
          executable: true,
          workflowNodeId: "runtime.context-compact",
          summary: "Compact aggregate context.",
        },
        {
          action: "request_approval",
          label: "Request approval",
          status: "available",
          executable: true,
          workflowNodeId: "runtime.approval.context-pressure",
        },
        {
          action: "delegate_summary",
          label: "Delegate summary",
          status: "recommended",
          executable: true,
          workflowNodeId: "runtime.subagent.delegate-summary",
        },
        {
          action: "stop",
          label: "Stop turn",
          status: "available",
          executable: true,
          workflowNodeId: "runtime.operator-interrupt",
        },
      ],
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([alert]);

  assert.equal(
    workflowNodeIdForRuntimeThreadEvent(alert),
    "runtime.context-pressure-alert",
  );
  assert.equal(nodes[0]?.nodeKind, "hook_policy");
  assert.equal(nodes[0]?.componentKind, "context_pressure_alert");
  assert.equal(nodes[0]?.label, "Context pressure alert");
  assert.equal(nodes[0]?.status, "blocked");
  assert.deepEqual(
    nodes[0]?.contextPressureActions.map((action) => [
      action.action,
      action.workflowNodeId,
      action.executable,
      action.scope,
      action.pressureStatus,
      action.sourceEventId,
    ]),
    [
      [
        "compact",
        "runtime.context-compact",
        true,
        "subagent_aggregate",
        "high",
        "event-context-pressure",
      ],
      [
        "request_approval",
        "runtime.approval.context-pressure",
        true,
        "subagent_aggregate",
        "high",
        "event-context-pressure",
      ],
      [
        "delegate_summary",
        "runtime.subagent.delegate-summary",
        true,
        "subagent_aggregate",
        "high",
        "event-context-pressure",
      ],
      [
        "stop",
        "runtime.operator-interrupt",
        true,
        "subagent_aggregate",
        "high",
        "event-context-pressure",
      ],
    ],
  );
});

test("projects TUI control state into React Flow run-inspector rows", () => {
  const projection = projectRuntimeTuiControlStateToWorkflowProjection({
    schema_version: "ioi.agent-cli.tui-control-state.v1",
    surface: "tui",
    thread_id: "thread-test",
    workflow_graph_id: "workflow-subagent-fanout",
    current_turn_id: "turn-test",
    last_cursor: "events_thread:test:8",
    last_event_id: "event-steer",
    mode_status: {
      mode: "agent",
      approval_mode: "suggest",
      trust_profile: "local_private",
      thread_status: "active",
      current_turn_status: "waiting_for_approval",
      requested_model: "auto",
      selected_model: "local:auto",
      model_route_id: "route.local-first",
      reasoning_effort: "high",
      workflow_node_id: "runtime.model-router",
    },
    approval_rows: [
      {
        id: "approval-row",
        approval_id: "approval-123",
        status: "pending",
        message: "Confirm shell execution",
        workflow_node_id: "runtime.approval.approval-123",
        receipt_refs: ["receipt-approval-request"],
        policy_decision_refs: ["policy-approval-required"],
        sequence: 5,
      },
    ],
    approval_decisions: [
      {
        id: "approval-decision",
        approval_id: "approval-123",
        decision: "approve",
        status: "approved",
        event_id: "event-approval-approved",
        workflow_node_id: "runtime.approval.approval-123",
        receipt_refs: ["receipt-approval-approved"],
        policy_decision_refs: ["policy-approval-allow"],
        sequence: 6,
      },
    ],
    workspace_trust_rows: [
      {
        id: "workspace-trust-row",
        warning_id: "workspace-trust-123",
        status: "warning",
        severity: "high",
        message: "YOLO mode can run without further prompts.",
        mode: "yolo",
        approval_mode: "never_prompt",
        trust_profile: "local_private",
        dirty: true,
        warning_reasons: [
          "thread_yolo_mode_never_prompts",
          "dirty_worktree",
        ],
        workflow_graph_id: "workflow-subagent-fanout",
        workflow_node_id: "runtime.thread-mode.yolo.workspace-trust",
        event_id: "event-workspace-trust",
        receipt_refs: ["receipt-workspace-trust"],
        policy_decision_refs: ["policy-workspace-trust-yolo"],
        sequence: 7,
      },
    ],
    job_rows: [
      {
        id: "job-row",
        job_id: "job-run-test",
        run_id: "run-test",
        thread_id: "thread-test",
        turn_id: "turn-test",
        status: "completed",
        progress_percent: "100",
        queue_name: "local-agentgres",
        workflow_node_id: "runtime.runtime-job",
      },
    ],
    run_lifecycle_rows: [
      {
        id: "run-lifecycle-row",
        job_id: "job-run-test",
        run_id: "run-test",
        thread_id: "thread-test",
        turn_id: "turn-test",
        status: "completed",
        progress_percent: "100",
        workflow_node_id: "runtime.runtime-job",
      },
    ],
    mcp_rows: [
      {
        id: "mcp-server-row",
        row_kind: "mcp_server",
        status: "completed",
        label: "MCP server search",
        command: "mcp",
        raw_input: "/mcp status",
        mcp_server_id: "search",
        message: "search · 2 tools",
        workflow_node_id: "runtime.mcp-manager",
        receipt_refs: ["receipt-mcp-status"],
        policy_decision_refs: ["policy-mcp-read"],
      },
      {
        id: "mcp-tool-row",
        row_kind: "mcp_tool",
        status: "completed",
        label: "MCP tool search.query",
        command: "mcp",
        raw_input: "/mcp tools",
        mcp_server_id: "search",
        mcp_tool_name: "query",
        workflow_node_id: "runtime.mcp-tool.search.query",
        receipt_refs: ["receipt-mcp-status"],
      },
      {
        id: "mcp-resource-row",
        row_kind: "mcp_resource",
        status: "completed",
        label: "MCP resource search-context",
        command: "mcp",
        raw_input: "/mcp resources",
        mcp_server_id: "search",
        mcp_resource_uri: "ioi://fixture/search-context",
        workflow_node_id: "runtime.mcp-resource.search.ioi_fixture_search-context",
        receipt_refs: ["receipt-mcp-status"],
      },
      {
        id: "mcp-prompt-row",
        row_kind: "mcp_prompt",
        status: "completed",
        label: "MCP prompt search-brief",
        command: "mcp",
        raw_input: "/mcp prompts",
        mcp_server_id: "search",
        mcp_prompt_name: "search-brief",
        workflow_node_id: "runtime.mcp-prompt.search.search-brief",
        receipt_refs: ["receipt-mcp-status"],
      },
      {
        id: "mcp-invoke-row",
        row_kind: "mcp_tool",
        status: "completed",
        label: "MCP invocation search.query",
        command: "mcp",
        raw_input: "/mcp invoke",
        mcp_server_id: "search",
        mcp_tool_name: "query",
        mcp_tool_call_id: "mcp-call-search-query",
        mcp_operation: "invoke",
        workflow_node_id: "runtime.mcp-tool.search.query",
        receipt_refs: ["receipt-mcp-invoke"],
      },
    ],
    memory_rows: [
      {
        id: "memory-status-row",
        row_kind: "memory_status",
        status: "completed",
        label: "Memory status",
        command: "memory",
        raw_input: "/memory status",
        memory_scope: "thread",
        memory_operation: "status",
        workflow_node_id: "runtime.memory-manager",
        receipt_refs: ["receipt-memory-status"],
      },
      {
        id: "memory-policy-row",
        row_kind: "memory_policy",
        status: "completed",
        label: "Memory policy",
        command: "memory",
        raw_input: "/memory policy",
        memory_scope: "thread",
        memory_operation: "policy",
        workflow_node_id: "runtime.memory-manager.policy",
        policy_decision_refs: ["policy-memory-read"],
      },
      {
        id: "memory-record-row",
        row_kind: "memory_record",
        status: "completed",
        label: "Memory record",
        command: "memory",
        raw_input: "/memory show",
        memory_record_id: "memory-123",
        memory_scope: "thread",
        memory_key: "conversation",
        memory_operation: "read",
        workflow_node_id: "runtime.memory",
      },
      {
        id: "memory-write-row",
        row_kind: "memory_record",
        status: "completed",
        label: "Memory write",
        command: "memory",
        raw_input: "/memory remember",
        memory_record_id: "memory-456",
        memory_scope: "thread",
        memory_key: "conversation",
        memory_operation: "write",
        workflow_node_id: "runtime.memory.write",
        receipt_refs: ["receipt-memory-write"],
      },
    ],
    usage_status: {
      scope: "thread",
      status: "nominal",
      usage_total_tokens: "4321",
      usage_input_tokens: "3000",
      usage_output_tokens: "1321",
      usage_cost_estimate_usd: "0.004321",
      usage_context_pressure: "0.0338",
      usage_context_pressure_status: "nominal",
      usage_run_count: "1",
      usage_subagent_count: "1",
      workflow_node_id: "runtime.usage-telemetry",
    },
    subagent_rows: [
      {
        id: "subagent-row",
        row_kind: "subagent",
        status: "completed",
        label: "Subagent",
        command: "subagent",
        raw_input: "/subagent spawn",
        subagent_id: "agent-subagent-1",
        subagent_role: "explore",
        subagent_operation: "spawn",
        subagent_lifecycle_status: "completed",
        subagent_output_contract_status: "passed",
        subagent_cancellation_inheritance: "propagate",
        subagent_merge_policy: "evidence_only",
        subagent_tool_pack: "coding",
        budget_status: {
          status: "within_budget",
          usage: {
            cumulative_total_tokens: 324,
            cumulative_cost_estimate_usd: 0.000324,
          },
        },
        subagent_run_id: "run-subagent-1",
        subagent_child_thread_id: "thread-child-1",
        subagent_restart_count: "1",
        subagent_input_count: "2",
        subagent_assignment_count: "1",
        workflow_graph_id: "workflow-subagent-fanout",
        workflow_node_id: "runtime.subagent.spawn.explore",
        receipt_refs: ["receipt-subagent-spawn"],
      },
    ],
    command_history: [
      {
        id: "tui-command-1",
        command: "events",
        raw_input: "/events 0",
        status: "applied",
        sequence: 1,
        cursor: "events_thread:test:4",
      },
      {
        id: "tui-command-2",
        command: "steer",
        raw_input: "/steer keep it focused",
        status: "applied",
        sequence: 2,
        turn_id: "turn-test",
        event_id: "event-steer",
      },
    ],
    validation_errors: [
      {
        id: "tui-error-1",
        command: "steer",
        raw_input: "/steer",
        message: "/steer requires guidance text",
        sequence: 3,
      },
    ],
  });

  assert.equal(
    projection.schemaVersion,
    WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
  );
  assert.equal(projection.sourceSchemaVersion, "ioi.agent-cli.tui-control-state.v1");
  assert.equal(projection.threadId, "thread-test");
  assert.equal(projection.workflowGraphId, "workflow-subagent-fanout");
  assert.equal(projection.currentTurnId, "turn-test");
  assert.equal(projection.lastCursor, "events_thread:test:8");
  assert.equal(projection.commandCount, 2);
  assert.equal(projection.validationErrorCount, 1);
  assert.equal(projection.approvalCount, 1);
  assert.equal(projection.approvalDecisionCount, 1);
  assert.equal(projection.workspaceTrustWarningCount, 1);
  assert.equal(projection.jobCount, 1);
  assert.equal(projection.runLifecycleCount, 1);
  assert.equal(projection.mcpRowCount, 5);
  assert.equal(projection.memoryRowCount, 4);
  assert.equal(projection.usageRowCount, 1);
  assert.equal(projection.subagentRowCount, 1);
  assert.equal(projection.subagentChildSubflowCount, 1);
  assert.equal(projection.rowCount, 23);
  assert.deepEqual(
    projection.rows.map((row) => [row.rowKind, row.command, row.status]),
    [
      ["summary", null, "current"],
      ["mode_status", null, "current"],
      ["model_route", "model", "current"],
      ["thinking", "thinking", "current"],
      ["workspace_trust_warning", "mode", "warning"],
      ["mcp_server", "mcp", "completed"],
      ["mcp_tool", "mcp", "completed"],
      ["mcp_resource", "mcp", "completed"],
      ["mcp_prompt", "mcp", "completed"],
      ["mcp_tool", "mcp", "completed"],
      ["memory_status", "memory", "completed"],
      ["memory_policy", "memory", "completed"],
      ["memory_record", "memory", "completed"],
      ["memory_record", "memory", "completed"],
      ["subagent", "subagent", "completed"],
      ["approval", null, "pending"],
      ["approval_decision", "approve", "approved"],
      ["job", "jobs", "completed"],
      ["run_lifecycle", "run", "completed"],
      ["usage_status", "usage", "current"],
      ["command", "events", "applied"],
      ["command", "steer", "applied"],
      ["validation_error", "steer", "validation_error"],
    ],
  );
  assert.equal(
    projection.rows[16]?.receiptRefs[0],
    "receipt-approval-approved",
  );
  assert.equal(
    projection.rows[21]?.reactFlowNodeId,
    "runtime.tui-control-state.command.steer",
  );
  assert.equal(projection.rows[2]?.modelId, "auto");
  assert.equal(projection.rows[3]?.reasoningEffort, "high");
  assert.equal(projection.rows[4]?.workspaceTrustWarningId, "workspace-trust-123");
  assert.equal(projection.rows[4]?.workspaceTrustSeverity, "high");
  assert.equal(projection.rows[4]?.workspaceTrustDirty, true);
  assert.equal(
    projection.rows[4]?.reactFlowNodeId,
    "runtime.thread-mode.yolo.workspace-trust",
  );
  assert.equal(projection.rows[5]?.mcpServerId, "search");
  assert.equal(projection.rows[6]?.mcpToolName, "query");
  assert.equal(projection.rows[6]?.reactFlowNodeId, "runtime.mcp-tool.search.query");
  assert.equal(projection.rows[7]?.mcpResourceUri, "ioi://fixture/search-context");
  assert.equal(projection.rows[8]?.mcpPromptName, "search-brief");
  assert.equal(projection.rows[9]?.mcpOperation, "invoke");
  assert.equal(projection.rows[9]?.mcpToolCallId, "mcp-call-search-query");
  assert.equal(projection.rows[10]?.memoryOperation, "status");
  assert.equal(projection.rows[12]?.memoryRecordId, "memory-123");
  assert.equal(projection.rows[12]?.memoryKey, "conversation");
  assert.equal(projection.rows[13]?.memoryOperation, "write");
  assert.equal(projection.rows[13]?.reactFlowNodeId, "runtime.memory.write");
  assert.equal(projection.rows[14]?.subagentId, "agent-subagent-1");
  assert.equal(projection.rows[14]?.subagentRole, "explore");
  assert.equal(projection.rows[14]?.subagentOutputContractStatus, "passed");
  assert.equal(projection.rows[14]?.subagentBudgetStatus, "within_budget");
  assert.equal(projection.rows[14]?.subagentTokenEstimate, 324);
  assert.equal(projection.rows[14]?.subagentCostEstimateUsd, 0.000324);
  assert.equal(projection.rows[14]?.subagentRestartCount, 1);
  assert.equal(projection.rows[14]?.workflowGraphId, "workflow-subagent-fanout");
  assert.equal(projection.rows[14]?.reactFlowNodeId, "runtime.subagent.spawn.explore");
  assert.equal(projection.rows[19]?.usageTotalTokens, 4321);
  assert.equal(projection.rows[19]?.usageCostEstimateUsd, 0.004321);
  assert.equal(projection.rows[19]?.usageSubagentCount, 1);
  assert.equal(projection.rows[19]?.reactFlowNodeId, "runtime.usage-telemetry");
  assert.equal(projection.subagentChildSubflows[0]?.workflowGraphId, "workflow-subagent-fanout");
  assert.equal(projection.subagentChildSubflows[0]?.parentReactFlowNodeId, "runtime.subagent.spawn.explore");
  assert.equal(projection.subagentChildSubflows[0]?.childThreadId, "thread-child-1");
  assert.equal(projection.subagentChildSubflows[0]?.childRunId, "run-subagent-1");
  assert.equal(projection.subagentChildSubflows[0]?.subagentBudgetStatus, "within_budget");
  assert.equal(projection.subagentChildSubflows[0]?.subagentTokenEstimate, 324);
  assert.equal(
    projection.subagentChildSubflows[0]?.childReactFlowNodeId,
    "runtime.subagent-subflow.agent-subagent-1",
  );
  assert.equal(
    projection.subagentChildSubflows[0]?.childRunReactFlowNodeId,
    "runtime.subagent-subflow.agent-subagent-1.run.run-subagent-1",
  );
  assert.equal(projection.subagentChildSubflowReactFlowNodes.length, 2);
  assert.equal(projection.subagentChildSubflowReactFlowEdges.length, 2);
  assert.equal(
    projection.subagentChildSubflowReactFlowNodes[0]?.parentId,
    "runtime.subagent.spawn.explore",
  );
  assert.equal(
    projection.subagentChildSubflowReactFlowNodes[1]?.parentId,
    "runtime.subagent-subflow.agent-subagent-1",
  );
  assert.equal(projection.rows[17]?.jobId, "job-run-test");
  assert.equal(projection.rows[18]?.runId, "run-test");
  assert.equal(projection.rows[22]?.message, "/steer requires guidance text");
});

test("projects TUI cost and context controls to usage, budget, and compaction nodes", () => {
  const projection = projectRuntimeTuiControlStateToWorkflowProjection({
    schema_version: "ioi.agent-cli.tui-control-state.v1",
    surface: "tui",
    thread_id: "thread-cost-context",
    current_turn_id: "turn-cost-context",
    cost_rows: [
      {
        id: "cost-row",
        row_kind: "cost_status",
        scope: "thread",
        usage_total_tokens: "1234",
        usage_input_tokens: "1000",
        usage_output_tokens: "234",
        usage_cost_estimate_usd: "0.01234",
        usage_context_pressure: "0.42",
        usage_context_pressure_status: "elevated",
        usage_run_count: "1",
        usage_subagent_count: "0",
        workflow_node_id: "runtime.usage-telemetry",
      },
    ],
    context_rows: [
      {
        id: "context-budget-row",
        row_kind: "context_budget",
        status: "warn",
        context_budget_status: "warn",
        context_budget_mode: "simulate",
        context_budget_decision_id: "policy_context_budget_thread_warn",
        usage_total_tokens: "1234",
        usage_cost_estimate_usd: "0.01234",
        usage_context_pressure: "0.42",
        usage_context_pressure_status: "elevated",
        workflow_node_id: "runtime.context-budget",
        receipt_refs: ["receipt_context_budget_thread"],
        policy_decision_refs: ["policy_context_budget_thread_warn"],
      },
      {
        id: "compaction-policy-row",
        row_kind: "compaction_policy",
        status: "warn",
        context_budget_status: "warn",
        compaction_policy_status: "warn",
        compaction_policy_action: "warn",
        compaction_policy_decision_id: "policy_compaction_thread_warn",
        compaction_executed: "false",
        workflow_node_id: "runtime.compaction-policy",
        receipt_refs: ["receipt_compaction_policy_thread"],
        policy_decision_refs: ["policy_compaction_thread_warn"],
      },
    ],
  });

  assert.equal(projection.costRowCount, 1);
  assert.equal(projection.contextRowCount, 2);
  assert.ok(
    projection.rows.some(
      (row) =>
        row.rowKind === "cost_status" &&
        row.command === "cost" &&
        row.usageTotalTokens === 1234 &&
        row.reactFlowNodeId === "runtime.usage-telemetry",
    ),
  );
  assert.ok(
    projection.rows.some(
      (row) =>
        row.rowKind === "context_budget" &&
        row.contextBudgetStatus === "warn" &&
        row.contextBudgetDecisionId === "policy_context_budget_thread_warn" &&
        row.reactFlowNodeId === "runtime.context-budget",
    ),
  );
  assert.ok(
    projection.rows.some(
      (row) =>
        row.rowKind === "compaction_policy" &&
        row.compactionPolicyAction === "warn" &&
        row.compactionPolicyDecisionId === "policy_compaction_thread_warn" &&
        row.compactionExecuted === false &&
        row.reactFlowNodeId === "runtime.compaction-policy",
    ),
  );
});

test("projects TUI coding-tool budget rows into inspector controls", () => {
  const projection = projectRuntimeTuiControlStateToWorkflowProjection({
    schema_version: "ioi.agent-cli.tui-control-state.v1",
    surface: "tui",
    thread_id: "thread-coding-tool-budget",
    workflow_graph_id: "workflow.react-flow.coding-tool-summary-budget",
    current_turn_id: "turn-coding-tool-budget",
    last_cursor: "events_thread:budget:3",
    last_event_id: "event-coding-budget-blocked",
    coding_tool_rows: [
      {
        id: "coding-tool-budget-row",
        row_kind: "coding_tool_budget",
        status: "blocked",
        tool_name: "file.apply_patch",
        tool_call_id: "coding_tool_summary_budget_blocked",
        workflow_graph_id: "workflow.react-flow.coding-tool-summary-budget",
        workflow_node_id: "workflow.coding.file.apply_patch.summary-budget",
        event_id: "event-coding-budget-blocked",
        receipt_refs: [
          "receipt_coding_tool_file_apply_patch_budget",
          "receipt_context_budget_thread_budget",
        ],
        policy_decision_refs: ["policy_context_budget_thread_budget_blocked"],
        budget_status: "exceeded",
        context_budget_status: "blocked",
        mutation_blocked: true,
        result_summary: {
          status: "blocked",
          reason: "coding_tool_budget_exceeded",
        },
        context_budget: {
          status: "blocked",
          mode: "block",
          policy_decision_id: "policy_context_budget_thread_budget_blocked",
          checks: [
            { id: "total_tokens", severity: "violation", actual: 720, limit: 100 },
          ],
          violations: [
            { id: "total_tokens", severity: "violation", actual: 720, limit: 100 },
          ],
          usage_summary: {
            total_tokens: 720,
            estimated_cost_usd: 0.0042,
            context_pressure: 0.72,
          },
        },
      },
    ],
  });

  assert.equal(projection.codingToolBudgetRowCount, 1);
  assert.equal(projection.rowCount, 2);
  const row = projection.rows.find(
    (candidate) => candidate.rowKind === "coding_tool_budget",
  );
  assert.ok(row);
  assert.equal(row.label, "Coding tool budget: file.apply_patch");
  assert.equal(row.status, "blocked");
  assert.equal(row.toolName, "file.apply_patch");
  assert.equal(row.toolCallId, "coding_tool_summary_budget_blocked");
  assert.equal(row.codingToolBudgetStatus, "exceeded");
  assert.equal(row.codingToolBudgetReason, "coding_tool_budget_exceeded");
  assert.equal(row.codingToolContextBudgetStatus, "blocked");
  assert.equal(row.codingToolBudgetMode, "block");
  assert.equal(
    row.codingToolBudgetDecisionId,
    "policy_context_budget_thread_budget_blocked",
  );
  assert.equal(row.codingToolBudgetCheckCount, 1);
  assert.equal(row.codingToolBudgetViolationCount, 1);
  assert.equal(row.codingToolBudgetUsageTotalTokens, 720);
  assert.equal(row.codingToolBudgetUsageCostEstimateUsd, 0.0042);
  assert.equal(row.codingToolBudgetUsageContextPressure, 0.72);
  assert.equal(row.codingToolMutationBlocked, true);
  assert.equal(
    row.reactFlowNodeId,
    "workflow.coding.file.apply_patch.summary-budget",
  );
  assert.deepEqual(row.policyDecisionRefs, [
    "policy_context_budget_thread_budget_blocked",
  ]);
});

test("projects TUI coding-tool success rows into inspector controls", () => {
  const projection = projectRuntimeTuiControlStateToWorkflowProjection({
    schema_version: "ioi.agent-cli.tui-control-state.v1",
    surface: "tui",
    thread_id: "thread-coding-tool-terminal",
    workflow_graph_id: "workflow.react-flow.terminal-coding-tools",
    current_turn_id: "turn-coding-tool-terminal",
    last_cursor: "events_thread:terminal:8",
    last_event_id: "event-coding-retrieve",
    coding_tool_rows: [
      {
        id: "coding-tool-status-row",
        row_kind: "coding_tool",
        status: "completed",
        command: "status",
        raw_input: "/status",
        tool_name: "workspace.status",
        tool_call_id: "coding_tool_status",
        workflow_node_id: "runtime.coding-tool.workspace.status",
        event_id: "event-coding-status",
        receipt_refs: ["receipt_coding_tool_status"],
        shell_fallback_used: false,
        mutation_blocked: false,
      },
      {
        id: "coding-tool-patch-dry-run-row",
        row_kind: "coding_tool",
        status: "completed",
        command: "patch-dry-run",
        raw_input: "/patch-dry-run README.md",
        tool_name: "file.apply_patch",
        tool_call_id: "coding_tool_patch_dry_run",
        workflow_node_id: "runtime.coding-tool.file.apply-patch",
        event_id: "event-coding-patch-dry-run",
        receipt_refs: ["receipt_coding_tool_patch"],
        dry_run: true,
        shell_fallback_used: "false",
        mutation_blocked: false,
      },
      {
        id: "coding-tool-test-row",
        row_kind: "coding_tool",
        status: "completed",
        command: "test",
        raw_input: "/test sample.test.mjs",
        tool_name: "test.run",
        tool_call_id: "coding_tool_test",
        workflow_node_id: "runtime.coding-tool.test.run",
        event_id: "event-coding-test",
        receipt_refs: ["receipt_coding_tool_test"],
        artifact_refs: ["artifact_test_output"],
        rollback_refs: ["workspace_snapshot_test"],
        shell_fallback_used: false,
        mutation_blocked: false,
      },
    ],
  });

  assert.equal(projection.codingToolRowCount, 3);
  assert.equal(projection.codingToolBudgetRowCount, 0);
  assert.equal(projection.rowCount, 4);
  const statusRow = projection.rows.find(
    (candidate) => candidate.toolName === "workspace.status",
  );
  assert.ok(statusRow);
  assert.equal(statusRow.rowKind, "coding_tool");
  assert.equal(statusRow.command, "status");
  assert.equal(statusRow.reactFlowNodeId, "runtime.coding-tool.workspace.status");
  assert.equal(statusRow.codingToolShellFallbackUsed, false);
  assert.deepEqual(statusRow.receiptRefs, ["receipt_coding_tool_status"]);
  const dryRunRow = projection.rows.find(
    (candidate) => candidate.toolCallId === "coding_tool_patch_dry_run",
  );
  assert.ok(dryRunRow);
  assert.equal(dryRunRow.command, "patch-dry-run");
  assert.equal(dryRunRow.rawInput, "/patch-dry-run README.md");
  assert.equal(dryRunRow.codingToolDryRun, true);
  assert.equal(dryRunRow.codingToolMutationBlocked, false);
  const testRow = projection.rows.find(
    (candidate) => candidate.toolName === "test.run",
  );
  assert.ok(testRow);
  assert.deepEqual(testRow.artifactRefs, ["artifact_test_output"]);
  assert.deepEqual(testRow.rollbackRefs, ["workspace_snapshot_test"]);
  assert.equal(testRow.reactFlowNodeId, "runtime.coding-tool.test.run");
});
