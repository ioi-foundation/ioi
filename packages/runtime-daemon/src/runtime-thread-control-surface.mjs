import {
  RUNTIME_MODEL_ROUTE_CONTROL_SCHEMA_VERSION,
  RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
  RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import { runtimeError } from "./runtime-http-utils.mjs";
import {
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";
import {
  approvalModeForThreadMode,
  normalizeThreadApprovalMode,
  normalizeThreadInteractionMode,
  normalizedAgentRuntimeControls,
  threadRuntimeControlKind,
  threadRuntimeControlModelInput,
} from "./threads/thread-runtime-controls.mjs";
import { createWorkspaceTrustState } from "./threads/workspace-trust-state.mjs";

export function createRuntimeThreadControlSurface({
  approvalModeForThreadMode: approvalModeForThreadModeDep = approvalModeForThreadMode,
  contextPolicyCore: contextPolicyCoreDep = null,
  eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
  normalizeThreadApprovalMode: normalizeThreadApprovalModeDep = normalizeThreadApprovalMode,
  normalizeThreadInteractionMode: normalizeThreadInteractionModeDep = normalizeThreadInteractionMode,
  normalizedAgentRuntimeControls: normalizedAgentRuntimeControlsDep = normalizedAgentRuntimeControls,
  nowIso = () => new Date().toISOString(),
  optionalString: optionalStringDep = optionalString,
  runtimeError: runtimeErrorDep = runtimeError,
  safeId: safeIdDep = safeId,
  threadRuntimeControlKind: threadRuntimeControlKindDep = threadRuntimeControlKind,
  threadRuntimeControlModelInput: threadRuntimeControlModelInputDep = threadRuntimeControlModelInput,
  workspaceTrustState,
  runtimeThreadControlsSchemaVersion = RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
  runtimeThreadModeControlSchemaVersion = RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION,
  runtimeModelRouteControlSchemaVersion = RUNTIME_MODEL_ROUTE_CONTROL_SCHEMA_VERSION,
} = {}) {
  const trustState = workspaceTrustState ?? createWorkspaceTrustState({
    eventStreamIdForThread: eventStreamIdForThreadDep,
    runtimeError: runtimeErrorDep,
    contextPolicyCore: contextPolicyCoreDep,
    nowIso,
  });

  return {
    updateThreadMode(store, threadId, request = {}) {
      return applyRustThreadControlStateUpdate(store, threadId, "mode", request);
    },
    updateThreadModel(store, threadId, request = {}) {
      return applyRustThreadControlStateUpdate(store, threadId, "model", request);
    },
    updateThreadThinking(store, threadId, request = {}) {
      return applyRustThreadControlStateUpdate(store, threadId, "thinking", request);
    },
    updateThreadRuntimeControls(store, threadId, request = {}) {
      const controlKind = threadRuntimeControlKindDep(request);
      return applyRustThreadControlStateUpdate(store, threadId, controlKind, request);
    },
    appendThreadRuntimeControlEvent(store, {
      agent,
      threadId,
      controlKind,
      controls,
      request,
      source,
      requestedBy,
      workflowGraphId,
      modelRoute,
      now,
    }) {
      void store;
      void agent;
      void controls;
      void request;
      void source;
      void requestedBy;
      void workflowGraphId;
      void modelRoute;
      void now;
      throwThreadControlRustCoreRequired({ threadId, controlKind });
    },
    appendWorkspaceTrustWarningEvent(store, input) {
      return trustState.appendWorkspaceTrustWarningEvent(store, input);
    },
    acknowledgeWorkspaceTrustWarning(store, threadId, warningId, request = {}) {
      return trustState.acknowledgeWorkspaceTrustWarning(store, threadId, warningId, request);
    },
  };

  function applyRustThreadControlStateUpdate(store, threadId, controlKind, request = {}) {
    const planner = contextPolicyCoreDep?.planThreadControlAgentStateUpdate;
    if (typeof planner !== "function") {
      throwThreadControlRustCoreRequired({ threadId, controlKind });
    }
    if (
      controlKind === "mode" &&
      !workspaceTrustState &&
      typeof contextPolicyCoreDep?.planWorkspaceTrustControlStateUpdate !== "function"
    ) {
      throwWorkspaceTrustRustCoreRequired({ threadId });
    }
    const agent = objectRecord(store.agentForThread?.(threadId));
    if (!agent) {
      throw runtimeErrorDep({
        status: 404,
        code: "thread_control_agent_not_found",
        message: "Thread runtime control requires a canonical agent projection.",
        details: { thread_id: threadId },
      });
    }

    const now = optionalStringDep(request.updated_at) ?? nowIso();
    const controls = nextThreadRuntimeControls(store, agent, controlKind, request, now);
    const modelRoute = controls.model_route ?? null;
    const { model_route: _modelRoute, ...controlsForRust } = controls;
    const eventStreamId = eventStreamIdForThreadDep(threadId);
    const eventId =
      optionalStringDep(request.event_id) ??
      `thread_control_${safeIdDep(threadId)}_${controlKind}_${safeIdDep(now)}`;
    const stateUpdate = planner.call(contextPolicyCoreDep, {
      thread_id: threadId,
      state_dir: optionalStringDep(store?.stateDir) ?? null,
      event_stream_id: eventStreamId,
      agent,
      control_kind: controlKind,
      controls: controlsForRust,
      event_id: eventId,
      created_at: now,
      updated_at: now,
      model_route: modelRoute,
      receipt_refs: threadControlReceiptRefs(controls),
      policy_decision_refs: [],
    });
    const record = objectRecord(stateUpdate?.record) ?? objectRecord(stateUpdate) ?? {};
    const plannedAgent = objectRecord(record.agent);
    if (!plannedAgent) {
      throw runtimeErrorDep({
        status: 502,
        code: "thread_control_rust_agent_update_missing",
        message: "Rust thread-control planner did not return an agent state projection.",
        details: {
          operation_kind: record.operation_kind ?? `thread.${controlKind}`,
          thread_id: threadId,
        },
      });
    }
    const operationKind = optionalStringDep(record.operation_kind) ?? `thread.${controlKind}`;
    const commit = store.writeAgent(plannedAgent, operationKind);
    const result = {
      ...record,
      commit,
      source: stateUpdate?.source ?? record.source ?? "rust_thread_control_api",
      backend: stateUpdate?.backend ?? record.backend ?? "rust_policy",
    };
    if (controlKind === "mode") {
      const workspaceTrust = trustState.appendWorkspaceTrustWarningEvent(store, {
        agent: plannedAgent,
        threadId,
        controls: controlsForRust,
        request,
        source: request.source,
        requestedBy: request.actor,
        workflowGraphId: request.workflow_graph_id,
        modeEvent: objectRecord(record.control),
        now,
      });
      if (workspaceTrust?.workspace_trust_warning) {
        result.workspace_trust_warning = workspaceTrust.workspace_trust_warning;
      }
      if (workspaceTrust?.workspace_trust_warning_event) {
        result.workspace_trust_warning_event = workspaceTrust.workspace_trust_warning_event;
      }
      if (workspaceTrust?.event) {
        result.workspace_trust_event = workspaceTrust.event;
      }
    }
    return result;
  }

  function nextThreadRuntimeControls(store, agent, controlKind, request, now) {
    const current = normalizedAgentRuntimeControlsDep(agent);
    if (controlKind === "mode") {
      const mode = normalizeThreadInteractionModeDep(
        request.mode ?? request.interaction_mode ?? current.mode,
      );
      const approvalMode = normalizeThreadApprovalModeDep(
        request.approval_mode,
        approvalModeForThreadModeDep(mode),
      );
      return {
        ...current,
        mode,
        approval_mode: approvalMode,
        model: {
          ...(objectRecord(current.model) ?? {}),
        },
      };
    }

    const { model, workflowNodeId: workflow_node_id } = threadRuntimeControlModelInputDep(
      request,
      current,
      agent,
    );
    const workflow_graph_id =
      optionalStringDep(model.workflow_graph_id) ??
      optionalStringDep(current.model?.workflow_graph_id) ??
      null;
    const modelRoute = store.resolveModelRoute(
      { model },
      {
        evidence_refs: ["runtime_thread_control_model_route"],
        workflow_graph_id,
        workflow_node_id,
        workflow_node_type: "Model Router",
      },
    );
    const canonicalModelRoute = threadControlAgentStateUpdateModelRoute(modelRoute, model);
    return {
      ...current,
      model: {
        ...(objectRecord(current.model) ?? {}),
        ...model,
        selected_model: canonicalModelRoute.selected_model,
        endpoint_id: canonicalModelRoute.endpoint_id,
        provider_id: canonicalModelRoute.provider_id,
        receipt_id: canonicalModelRoute.receipt_id,
        workflow_graph_id: canonicalModelRoute.workflow_graph_id ?? workflow_graph_id,
        workflow_node_id: canonicalModelRoute.workflow_node_id ?? workflow_node_id,
        updated_at: now,
      },
      model_route: canonicalModelRoute,
    };
  }

  function threadControlAgentStateUpdateModelRoute(modelRoute = {}, model = {}) {
    const decision = objectRecord(modelRoute.decision) ?? {};
    return {
      requested_model_id:
        optionalStringDep(modelRoute.requested_model_id) ??
        optionalStringDep(model.id) ??
        "auto",
      selected_model:
        optionalStringDep(modelRoute.selected_model) ??
        optionalStringDep(model.id) ??
        "auto",
      route_id:
        optionalStringDep(modelRoute.route_id) ??
        optionalStringDep(model.route_id) ??
        "route.local-first",
      endpoint_id:
        optionalStringDep(modelRoute.endpoint_id) ??
        null,
      provider_id:
        optionalStringDep(modelRoute.provider_id) ??
        null,
      receipt_id:
        optionalStringDep(modelRoute.receipt_id) ??
        null,
      workflow_graph_id:
        optionalStringDep(decision.workflow_graph_id) ??
        optionalStringDep(model.workflow_graph_id) ??
        null,
      workflow_node_id:
        optionalStringDep(decision.workflow_node_id) ??
        optionalStringDep(model.workflow_node_id) ??
        "runtime.model-router",
      decision,
    };
  }

  function threadControlReceiptRefs(controls = {}) {
    const refs = [];
    const modelReceipt = optionalStringDep(controls.model?.receipt_id);
    const routeReceipt = optionalStringDep(controls.model_route?.receipt_id);
    if (modelReceipt) refs.push(modelReceipt);
    if (routeReceipt) refs.push(routeReceipt);
    return [...new Set(refs)];
  }

  function throwThreadControlRustCoreRequired({ threadId = null, controlKind = null } = {}) {
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_thread_control_rust_core_required",
      message: "Thread runtime control requires direct Rust daemon-core admission and projection.",
      details: {
        rust_core_boundary: "runtime.thread_control",
        operation: "thread_control",
        operation_kind: "thread_control",
        requested_control_kind: controlKind ?? null,
        thread_id: threadId,
        evidence_refs: [
          "runtime_thread_control_js_facade_retired",
          "runtime_thread_mode_control_js_facade_retired",
          "runtime_thread_model_control_js_facade_retired",
          "runtime_thread_thinking_control_js_facade_retired",
          "runtime_thread_control_event_js_facade_retired",
          "rust_daemon_core_thread_control_required",
          "agentgres_thread_control_truth_required",
        ],
      },
    });
  }

  function throwWorkspaceTrustRustCoreRequired({ threadId = null } = {}) {
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_workspace_trust_control_rust_core_required",
      message: "Workspace trust control requires direct Rust daemon-core admission and projection.",
      details: {
        rust_core_boundary: "runtime.workspace_trust_control",
        operation: "workspace_trust_control",
        operation_kind: "workspace_trust_control",
        thread_id: threadId,
        evidence_refs: [
          "runtime_workspace_trust_control_rust_planner_required",
          "runtime_workspace_trust_event_admission_rust_required",
          "agentgres_workspace_trust_truth_required",
        ],
      },
    });
  }
}
