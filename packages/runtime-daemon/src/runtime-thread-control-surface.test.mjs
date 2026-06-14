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
        requested_model_id: input.model.id,
        selected_model: "local-model",
        route_id: input.model.route_id,
        endpoint_id: "endpoint_1",
        provider_id: "provider_1",
        receipt_id: "receipt_route_1",
        decision: {
          requested_model: input.model.id,
          selected_model: "local-model",
          route_id: input.model.route_id,
          endpoint_id: "endpoint_1",
          provider_id: "provider_1",
          reasoning_effort: input.model.reasoning_effort ?? null,
          workflow_graph_id: context.workflow_graph_id,
          workflow_node_id: context.workflow_node_id,
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
      this.agents.set(record.id, record);
      return {
        source: "rust_agentgres_runtime_agent_state_commit_protocol",
        agent_id: record.id,
        operation_kind: operationKind,
        commit_hash: `commit_${operationKind}`,
      };
    },
  };
  return store;
}

function createSurface(plannerCalls = [], { threadControlStateUpdate = null } = {}) {
  return createRuntimeThreadControlSurface({
    contextPolicyCore: {
      planThreadControlAgentStateUpdate(request = {}) {
        plannerCalls.push(request);
        const receiptRefs =
          request.receipt_refs?.length > 0
            ? request.receipt_refs
            : [`receipt_thread_control_${request.control_kind}`];
        const agent = {
          ...request.agent,
          runtimeControls: request.controls,
          updatedAt: request.updated_at,
          receipt_refs: receiptRefs,
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
          receipt_refs: receiptRefs,
          control: {
            control_kind: request.control_kind,
            event_id: request.event_id,
            receipt_refs: receiptRefs,
          },
          agent,
          ...threadControlStateUpdate,
        };
      },
    },
    nowIso: () => "2026-06-04T12:00:00.000Z",
    workspaceTrustState: {
      appendWorkspaceTrustWarningEvent(store, input) {
        if (input.controls.mode !== "review" && input.controls.mode !== "yolo") return null;
        const event = store.appendRuntimeEvent({
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
        return {
          workspace_trust_warning: event.payload_summary,
          workspace_trust_warning_event: event,
          event,
        };
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
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "requestedControlKind",
    "threadId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details, key), false);
  }
}

function assertThreadControlRustCoreRequired(error, { threadId = "thread_1", controlKind } = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_thread_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.thread_control");
  assert.equal(error.details.operation, "thread_control");
  assert.equal(error.details.operation_kind, "thread_control");
  assert.equal(error.details.thread_id, threadId);
  assert.equal(error.details.requested_control_kind, controlKind);
  assert.deepEqual(error.details.evidence_refs, [
    "runtime_thread_control_js_facade_retired",
    "runtime_thread_mode_control_js_facade_retired",
    "runtime_thread_model_control_js_facade_retired",
    "runtime_thread_thinking_control_js_facade_retired",
    "runtime_thread_control_event_js_facade_retired",
    "rust_daemon_core_thread_control_required",
    "agentgres_thread_control_truth_required",
  ]);
  assertNoRetiredDetailAliases(error.details);
}

function assertNoThreadControlMutation(store, plannerCalls) {
  assert.deepEqual(store.events, []);
  assert.deepEqual(store.routeRequests, []);
  assert.deepEqual(store.writes, []);
  assert.equal(store.agents.get("agent_1").runtimeControls.mode, "agent");
  assert.deepEqual(plannerCalls, []);
}

test("thread control mode/model/thinking facades delegate to Rust planner and Agentgres-backed write", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createSurface(plannerCalls);

  const mode = surface.updateThreadMode(store, "thread_1", {
    mode: "review",
    actor: "operator_1",
    source: "agent_studio",
    workflow_graph_id: "graph_1",
  });

  assert.equal(mode.operation_kind, "thread.mode");
  assert.equal(mode.agent.runtimeControls.mode, "review");
  assert.equal(Object.hasOwn(mode.agent.runtimeControls, "schemaVersion"), false);
  assert.deepEqual(mode.receipt_refs, ["receipt_thread_control_mode"]);
  assert.equal(mode.commit.operation_kind, "thread.mode");

  const model = surface.updateThreadModel(store, "thread_1", {
    model: { id: "auto", route_id: "route.local-first" },
    workflow_node_id: "runtime.model-router.custom",
  });

  assert.equal(model.operation_kind, "thread.model");
  assert.equal(model.agent.modelId, "local-model");
  assert.deepEqual(model.receipt_refs, ["receipt_route_1"]);

  const thinking = surface.updateThreadThinking(store, "thread_1", {
    thinking: "off",
    model: {
      id: "auto",
      route_id: "route.local-first",
      privacy: "local_private",
    },
    workflow_node_id: "runtime.model-router.custom",
    workflow_graph_id: "graph_1",
  });

  assert.equal(thinking.operation_kind, "thread.thinking");
  assert.equal(thinking.agent.runtimeControls.model.reasoning_effort, "none");
  assert.equal(store.events.length, 1);
  assert.equal(mode.workspace_trust_warning_event.event_kind, "workspace.trust_warning");
  assert.equal(store.writes.length, 3);
  assert.equal(plannerCalls.length, 3);
  assert.equal(plannerCalls[0].control_kind, "mode");
  assert.equal(plannerCalls[0].model_route, null);
  assert.equal(plannerCalls[0].receipt_refs.length, 0);
  assert.equal(plannerCalls[1].model_route.selected_model, "local-model");
  assert.equal(plannerCalls[1].model_route.route_id, "route.local-first");
  for (const field of ["selectedModel", "requestedModelId", "routeId"]) {
    assert.equal(Object.hasOwn(plannerCalls[1].model_route, field), false);
  }
  assert.deepEqual(plannerCalls[1].receipt_refs, ["receipt_route_1"]);
  assert.equal(store.routeRequests.length, 2);
  assert.equal(store.routeRequests[0].context.workflow_node_id, "runtime.model-router.custom");
  assert.equal(store.routeRequests[1].context.workflow_graph_id, "graph_1");
});

test("thread runtime-control facade fails closed before lookup without Rust planner", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createRuntimeThreadControlSurface({
    contextPolicyCore: null,
    runtimeError: ({ message, code, status, details }) => {
      const error = new Error(message);
      error.code = code;
      error.status = status;
      error.details = details;
      return error;
    },
  });

  assert.throws(
    () => surface.updateThreadRuntimeControls(store, "thread_1", {
      control: "mode",
      mode: "review",
      workflowGraphId: "graph_retired",
      workflowNodeId: "node_retired",
      idempotencyKey: "thread_control_idempotency_retired",
    }),
    (error) => {
      assertThreadControlRustCoreRequired(error, { controlKind: "mode" });
      return true;
    },
  );

  assertNoThreadControlMutation(store, plannerCalls);
});

test("thread mode fails closed before lookup when workspace trust Rust planner is missing", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createRuntimeThreadControlSurface({
    contextPolicyCore: {
      planThreadControlAgentStateUpdate(request = {}) {
        plannerCalls.push(request);
        return {};
      },
    },
    runtimeError: ({ message, code, status, details }) => {
      const error = new Error(message);
      error.code = code;
      error.status = status;
      error.details = details;
      return error;
    },
  });

  assert.throws(
    () => surface.updateThreadMode(store, "thread_1", {
      mode: "review",
      workflow_graph_id: "graph_1",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_workspace_trust_control_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.workspace_trust_control");
      assert.equal(error.details.operation, "workspace_trust_control");
      assert.equal(error.details.thread_id, "thread_1");
      return true;
    },
  );

  assertNoThreadControlMutation(store, plannerCalls);
});

test("direct thread runtime-control event facade stays retired before JS event append", () => {
  const store = createStore();
  const plannerCalls = [];
  const surface = createSurface(plannerCalls);

  assert.throws(
    () => surface.appendThreadRuntimeControlEvent(store, {
      agent: { id: "agent_1", cwd: "/tmp/runtime-thread-control-test" },
      threadId: "thread_1",
      controlKind: "thinking",
      controls: {
        model: {
          id: "auto",
          routeId: "route.local-first",
          workflowNodeId: "runtime.model-router.retired",
        },
      },
      request: { idempotency_key: "canonical" },
      source: "agent_studio",
      requestedBy: "operator",
      workflowGraphId: "graph_1",
      modelRoute: { receiptId: "receipt_route_1" },
      now: "2026-06-04T12:00:00.000Z",
    }),
    (error) => {
      assertThreadControlRustCoreRequired(error, { controlKind: "thinking" });
      return true;
    },
  );

  assertNoThreadControlMutation(store, plannerCalls);
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
