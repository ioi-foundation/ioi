import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeThreadControlSurface } from "./runtime-thread-control-surface.mjs";

function createStore() {
  const agent = {
    id: "agent_1",
    cwd: "/tmp/runtime-thread-control-test",
    runtimeProfile: "runtime_service",
    runtimeSessionId: "session_1",
    runtimeControls: {
      mode: "agent",
      approvalMode: "suggest",
      model: {
        id: "auto",
        routeId: "route.local-first",
        workflowNodeId: "runtime.model-router",
      },
    },
  };
  const store = {
    agents: new Map([[agent.id, agent]]),
    events: [],
    routeRequests: [],
    writes: [],
    agentForThread(threadId) {
      assert.equal(threadId, "thread_1");
      return this.agents.get(agent.id);
    },
    appendRuntimeEvent(record) {
      const event = {
        ...record,
        event_id: `evt_${this.events.length + 1}`,
        seq: this.events.length + 1,
      };
      this.events.push(event);
      return event;
    },
    resolveModelRoute(input, context) {
      this.routeRequests.push({ input, context });
      return {
        requestedModelId: input.model.id,
        selectedModel: "local-model",
        routeId: input.model.route_id,
        endpointId: "endpoint_1",
        providerId: "provider_1",
        receiptId: "receipt_route_1",
        decision: {
          requested_model: input.model.id,
          selected_model: "local-model",
          route_id: input.model.route_id,
          endpoint_id: "endpoint_1",
          provider_id: "provider_1",
          reasoning_effort: input.model.reasoning_effort ?? null,
          workflow_graph_id: context.workflowGraphId,
          workflow_node_id: context.workflowNodeId,
        },
      };
    },
    threadForAgent(record) {
      return {
        thread_id: "thread_1",
        agent_id: record.id,
        runtime_controls: record.runtimeControls,
      };
    },
    writeAgent(record, operationKind) {
      this.writes.push({ record, operationKind });
    },
  };
  return store;
}

function createSurface(plannerCalls = [], { threadControlStateUpdate = null } = {}) {
  return createRuntimeThreadControlSurface({
    contextPolicyRunner: {
      planThreadControlAgentStateUpdate(request = {}) {
        plannerCalls.push(request);
        const agent = {
          ...request.agent,
          runtimeControls: request.controls,
          updatedAt: request.updated_at,
        };
        if (request.model_route) {
          agent.modelId = request.model_route.selected_model;
          agent.requestedModelId = request.model_route.requested_model_id;
          agent.modelRouteId = request.model_route.route_id;
          agent.modelRouteEndpointId = request.model_route.endpoint_id;
          agent.modelRouteProviderId = request.model_route.provider_id;
          agent.modelRouteReceiptId = request.model_route.receipt_id;
          agent.modelRouteDecision = request.model_route.decision;
        }
        return {
          status: "planned",
          operation_kind: `thread.${request.control_kind}`,
          updated_at: request.updated_at,
          agent,
          ...threadControlStateUpdate,
        };
      },
    },
    nowIso: () => "2026-06-04T12:00:00.000Z",
    workspaceTrustState: {
      appendWorkspaceTrustWarningEvent(store, input) {
        if (input.controls.mode !== "review" && input.controls.mode !== "yolo") return null;
        return store.appendRuntimeEvent({
          event_stream_id: `stream_${input.threadId}`,
          thread_id: input.threadId,
          turn_id: "",
          item_id: `${input.threadId}:workspace-trust-warning`,
          idempotency_key: `${input.threadId}:workspace-trust-warning`,
          source: input.source,
          source_event_kind: "WorkspaceTrust.Warning",
          event_kind: "workspace.trust_warning",
          status: "warning",
          actor: "policy",
          created_at: input.now,
          workspace_root: input.agent.cwd,
          workflow_graph_id: input.workflowGraphId,
          workflow_node_id: "runtime.thread-mode.workspace-trust",
          component_kind: "workspace_trust",
          payload_schema_version: "ioi.workspace-trust-warning.test.v1",
          payload_summary: {
            warning_id: "workspace_trust_warning_1",
            mode: input.controls.mode,
            approval_mode: input.controls.approvalMode,
          },
          receipt_refs: ["receipt_workspace_trust_warning_1"],
          policy_decision_refs: ["policy_workspace_trust_warning_1"],
          artifact_refs: [],
          rollback_refs: [],
          redaction_profile: "internal",
          fixture_profile: "runtime-thread-control-test",
        });
      },
      acknowledgeWorkspaceTrustWarning(store, threadId, warningId, request = {}) {
        return {
          ...store.threadForAgent(store.agentForThread(threadId)),
          workspace_trust_acknowledgement: {
            warning_id: warningId,
            acknowledged_by: request.actor ?? "operator",
          },
        };
      },
    },
  });
}

function assertNoRetiredDetailAliases(details) {
  for (const key of ["threadId", "controlKind", "operationKind", "expectedOperationKind"]) {
    assert.equal(Object.hasOwn(details, key), false);
  }
}

test("thread control surface updates mode controls through Rust planner and emits workspace trust warning", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createSurface(plannerCalls);

  const result = surface.updateThreadMode(store, "thread_1", {
    mode: "review",
    actor: "operator_1",
    source: "agent_studio",
    workflow_graph_id: "graph_1",
  });

  assert.equal(result.control.schema_version, "ioi.runtime.thread-controls.v1");
  assert.equal(result.control.control_kind, "mode");
  assert.equal(result.control.mode, "review");
  assert.equal(result.control.approval_mode, "human_required");
  assert.equal(result.control.workspace_trust_warning.warning_id, "workspace_trust_warning_1");
  assert.equal(result.event.event_kind, "thread.mode_updated");
  assert.equal(result.event.payload_schema_version, "ioi.runtime.thread-mode-control.v1");
  assert.equal(result.event.source_event_kind, "OperatorControl.Mode");
  assert.equal(store.events[1].event_kind, "workspace.trust_warning");
  assert.equal(store.agents.get("agent_1").runtimeControls.mode, "review");
  assert.equal(store.writes[0].operationKind, "thread.mode");
  assert.equal(plannerCalls.length, 1);
  assert.equal(plannerCalls[0].control_kind, "mode");
  assert.equal(plannerCalls[0].thread_id, "thread_1");
  assert.equal(plannerCalls[0].event_id, "evt_1");
  assert.equal(plannerCalls[0].workspace_trust_warning_event_id, "evt_2");
  assert.equal(plannerCalls[0].controls.mode, "review");
});

test("thread control surface updates model controls through route selection and Rust planner", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createSurface(plannerCalls);

  const result = surface.updateThreadThinking(store, "thread_1", {
    thinking: "off",
    model: {
      id: "auto",
      route_id: "route.local-first",
      privacy: "local_private",
    },
    workflow_node_id: "runtime.model-router.custom",
    workflow_graph_id: "graph_1",
  });

  assert.equal(result.control.control_kind, "thinking");
  assert.equal(result.control.model.selectedModel, "local-model");
  assert.equal(result.control.model.reasoningEffort, "none");
  assert.equal(result.control.model.privacy, "local_private");
  assert.equal(result.control.model.allow_hosted_fallback, null);
  assert.equal(Object.hasOwn(result.control.model, "allowHostedFallback"), false);
  assert.equal(result.event.event_kind, "model.route_decision");
  assert.equal(result.event.source_event_kind, "OperatorControl.Thinking");
  assert.equal(result.event.payload_schema_version, "ioi.runtime.model-route-control.v1");
  assert.deepEqual(result.event.receipt_refs, ["receipt_route_1"]);
  assert.equal(store.routeRequests[0].input.model.route_id, "route.local-first");
  assert.equal(Object.hasOwn(store.routeRequests[0].input.model, "routeId"), false);
  assert.equal(store.routeRequests[0].context.evidenceRefs[0], "runtime_thread_thinking_control");
  assert.equal(store.agents.get("agent_1").modelRouteReceiptId, "receipt_route_1");
  assert.equal(store.writes[0].operationKind, "thread.thinking");
  assert.equal(plannerCalls.length, 1);
  assert.equal(plannerCalls[0].control_kind, "thinking");
  assert.equal(plannerCalls[0].model_route.receipt_id, "receipt_route_1");
  assert.equal(plannerCalls[0].model_route.route_id, "route.local-first");
  assert.equal(Object.hasOwn(plannerCalls[0].model_route, "receiptId"), false);
  assert.equal(Object.hasOwn(plannerCalls[0].model_route, "routeId"), false);
  assert.equal(plannerCalls[0].controls.model.selectedModel, "local-model");
});

test("thread control surface ignores retired request identity aliases", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createSurface(plannerCalls);

  const modeResult = surface.updateThreadMode(store, "thread_1", {
    mode: "review",
    interactionMode: "yolo",
    approvalMode: "never",
    requestedBy: "operator_retired",
    workflowGraphId: "graph_retired",
    workflowNodeId: "node_retired",
    idempotencyKey: "thread_control_idempotency_retired",
  });

  assert.equal(modeResult.event.payload.mode, "review");
  assert.equal(modeResult.event.payload.approval_mode, "human_required");
  assert.equal(modeResult.event.payload.requested_by, "operator");
  assert.equal(modeResult.event.workflow_graph_id, null);
  assert.equal(modeResult.event.workflow_node_id, "runtime.thread-mode");
  assert.match(modeResult.event.idempotency_key, /^thread:thread_1:control\.mode:/);
  assert.equal(store.events[1].workflow_graph_id, null);
  assert.equal(store.events[1].payload_summary.approval_mode, "human_required");
  assert.equal(plannerCalls[0].controls.mode, "review");
  assert.equal(plannerCalls[0].controls.approvalMode, "human_required");

  const modelResult = surface.updateThreadThinking(store, "thread_1", {
    thinking: "off",
    model: {
      id: "auto",
      route_id: "route.local-first",
    },
    workflowGraphId: "graph_model_retired",
    workflowNodeId: "node_model_retired",
    idempotencyKey: "thread_thinking_idempotency_retired",
  });

  assert.equal(store.routeRequests[0].context.workflowGraphId, null);
  assert.equal(store.routeRequests[0].context.workflowNodeId, "runtime.model-router");
  assert.equal(modelResult.event.workflow_graph_id, null);
  assert.equal(modelResult.event.workflow_node_id, "runtime.model-router");
  assert.match(modelResult.event.idempotency_key, /^thread:thread_1:control\.thinking:/);
});

test("thread control surface accepts canonical idempotency key", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createSurface(plannerCalls);

  const result = surface.updateThreadMode(store, "thread_1", {
    mode: "review",
    idempotency_key: "thread_control_idempotency_canonical",
  });

  assert.equal(result.event.idempotency_key, "thread_control_idempotency_canonical");
});

test("thread control surface fails closed without Rust-planned operation kind", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createSurface(plannerCalls, {
    threadControlStateUpdate: {
      operation_kind: null,
    },
  });

  assert.throws(
    () =>
      surface.updateThreadMode(store, "thread_1", {
        mode: "review",
        actor: "operator_1",
        source: "agent_studio",
      }),
    (error) => {
      assert.equal(error.code, "thread_control_state_update_operation_kind_missing");
      assert.equal(error.details.thread_id, "thread_1");
      assert.equal(error.details.control_kind, "mode");
      assert.equal(error.details.operation_kind, "thread.mode");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.writes.length, 0);
  assert.equal(store.agents.get("agent_1").runtimeControls.mode, "agent");
  assert.equal(plannerCalls.length, 1);
});

test("thread control surface rejects unexpected Rust-planned operation kind with canonical details", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createSurface(plannerCalls, {
    threadControlStateUpdate: {
      operation_kind: "thread.memory_status",
    },
  });

  assert.throws(
    () =>
      surface.updateThreadMode(store, "thread_1", {
        mode: "review",
        actor: "operator_1",
        source: "agent_studio",
      }),
    (error) => {
      assert.equal(error.code, "thread_control_state_update_operation_kind_mismatch");
      assert.equal(error.details.thread_id, "thread_1");
      assert.equal(error.details.control_kind, "mode");
      assert.equal(error.details.expected_operation_kind, "thread.mode");
      assert.equal(error.details.operation_kind, "thread.memory_status");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.writes.length, 0);
  assert.equal(store.agents.get("agent_1").runtimeControls.mode, "agent");
  assert.equal(plannerCalls.length, 1);
});

test("thread control surface delegates workspace trust acknowledgement", () => {
  const store = createStore();
  const surface = createSurface();

  const result = surface.acknowledgeWorkspaceTrustWarning(
    store,
    "thread_1",
    "workspace_trust_warning_1",
    { actor: "operator_1" },
  );

  assert.equal(result.workspace_trust_acknowledgement.warning_id, "workspace_trust_warning_1");
  assert.equal(result.workspace_trust_acknowledgement.acknowledged_by, "operator_1");
});
