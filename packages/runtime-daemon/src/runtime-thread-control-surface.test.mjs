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
        routeId: input.model.routeId,
        endpointId: "endpoint_1",
        providerId: "provider_1",
        receiptId: "receipt_route_1",
        decision: {
          requestedModel: input.model.id,
          selectedModel: "local-model",
          routeId: input.model.routeId,
          endpointId: "endpoint_1",
          providerId: "provider_1",
          reasoningEffort: input.model.reasoningEffort ?? null,
          workflowGraphId: context.workflowGraphId,
          workflowNodeId: context.workflowNodeId,
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

function createSurface() {
  return createRuntimeThreadControlSurface({
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

test("thread control surface updates mode controls and emits workspace trust warning", () => {
  const store = createStore();
  const surface = createSurface();

  const result = surface.updateThreadMode(store, "thread_1", {
    mode: "review",
    actor: "operator_1",
    source: "agent_studio",
    workflowGraphId: "graph_1",
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
});

test("thread control surface updates model controls through route selection", () => {
  const store = createStore();
  const surface = createSurface();

  const result = surface.updateThreadThinking(store, "thread_1", {
    thinking: "off",
    model: {
      id: "auto",
      routeId: "route.local-first",
      privacy: "local_private",
    },
    workflowNodeId: "runtime.model-router.custom",
    workflowGraphId: "graph_1",
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
  assert.equal(store.routeRequests[0].context.evidenceRefs[0], "runtime_thread_thinking_control");
  assert.equal(store.agents.get("agent_1").modelRouteReceiptId, "receipt_route_1");
  assert.equal(store.writes[0].operationKind, "thread.thinking");
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
