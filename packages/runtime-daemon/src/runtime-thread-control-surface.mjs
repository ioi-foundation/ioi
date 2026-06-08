import {
  RUNTIME_MODEL_ROUTE_CONTROL_SCHEMA_VERSION,
  RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
  RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION,
  WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION,
  WORKSPACE_TRUST_WARNING_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import {
  eventStreamIdForThread,
  fixtureProfileForAgent,
  runtimeSessionIdForAgent,
} from "./runtime-identifiers.mjs";
import { createContextPolicyRunnerFromEnv } from "./runtime-context-policy-runner.mjs";
import { runtimeError } from "./runtime-http-utils.mjs";
import {
  operatorControlSource,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";
import { workspaceTrustWarningRecordForMode } from "./repository-context.mjs";
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
  contextPolicyRunner: contextPolicyRunnerDep = createContextPolicyRunnerFromEnv(),
  eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
  fixtureProfileForAgent: fixtureProfileForAgentDep = fixtureProfileForAgent,
  normalizeThreadApprovalMode: normalizeThreadApprovalModeDep = normalizeThreadApprovalMode,
  normalizeThreadInteractionMode: normalizeThreadInteractionModeDep = normalizeThreadInteractionMode,
  normalizedAgentRuntimeControls: normalizedAgentRuntimeControlsDep = normalizedAgentRuntimeControls,
  nowIso = () => new Date().toISOString(),
  operatorControlSource: operatorControlSourceDep = operatorControlSource,
  optionalString: optionalStringDep = optionalString,
  runtimeError: runtimeErrorDep = runtimeError,
  runtimeSessionIdForAgent: runtimeSessionIdForAgentDep = runtimeSessionIdForAgent,
  safeId: safeIdDep = safeId,
  threadRuntimeControlKind: threadRuntimeControlKindDep = threadRuntimeControlKind,
  threadRuntimeControlModelInput: threadRuntimeControlModelInputDep = threadRuntimeControlModelInput,
  workspaceTrustState,
  workspaceTrustWarningRecordForMode: workspaceTrustWarningRecordForModeDep = workspaceTrustWarningRecordForMode,
  workspaceTrustAcknowledgementSchemaVersion = WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION,
  workspaceTrustWarningSchemaVersion = WORKSPACE_TRUST_WARNING_SCHEMA_VERSION,
  runtimeThreadControlsSchemaVersion = RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
  runtimeThreadModeControlSchemaVersion = RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION,
  runtimeModelRouteControlSchemaVersion = RUNTIME_MODEL_ROUTE_CONTROL_SCHEMA_VERSION,
} = {}) {
  const trustState = workspaceTrustState ?? createWorkspaceTrustState({
    eventStreamIdForThread: eventStreamIdForThreadDep,
    fixtureProfileForAgent: fixtureProfileForAgentDep,
    optionalString: optionalStringDep,
    operatorControlSource: operatorControlSourceDep,
    runtimeError: runtimeErrorDep,
    runtimeSessionIdForAgent: runtimeSessionIdForAgentDep,
    safeId: safeIdDep,
    workspaceTrustAcknowledgementSchemaVersion,
    workspaceTrustWarningRecordForMode: workspaceTrustWarningRecordForModeDep,
    workspaceTrustWarningSchemaVersion,
	  });

  return {
    updateThreadMode(store, threadId, request = {}) {
      void store;
      void request;
      throwThreadControlRustCoreRequired({ threadId, controlKind: "mode" });
    },
    updateThreadModel(store, threadId, request = {}) {
      void store;
      void request;
      throwThreadControlRustCoreRequired({ threadId, controlKind: "model" });
    },
    updateThreadThinking(store, threadId, request = {}) {
      void store;
      void request;
      throwThreadControlRustCoreRequired({ threadId, controlKind: "thinking" });
    },
    updateThreadRuntimeControls(store, threadId, request = {}) {
      void store;
      throwThreadControlRustCoreRequired({
        threadId,
        controlKind: threadRuntimeControlKindDep(request),
      });
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
}
