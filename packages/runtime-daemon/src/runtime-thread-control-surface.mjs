import crypto from "node:crypto";

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
      return this.updateThreadRuntimeControls(store, threadId, { ...request, control: "mode" });
    },
    updateThreadModel(store, threadId, request = {}) {
      return this.updateThreadRuntimeControls(store, threadId, { ...request, control: "model" });
    },
    updateThreadThinking(store, threadId, request = {}) {
      return this.updateThreadRuntimeControls(store, threadId, { ...request, control: "thinking" });
    },
    updateThreadRuntimeControls(store, threadId, request = {}) {
      const agent = store.agentForThread(threadId);
      const now = nowIso();
      const controlKind = threadRuntimeControlKindDep(request);
      const source = operatorControlSourceDep(request.source);
      const requestedBy =
        optionalStringDep(request.actor ?? request.requested_by) ??
        "operator";
      const workflowGraphId = request.workflow_graph_id ?? null;
      const existingControls = normalizedAgentRuntimeControlsDep(agent);
      const nextControls = {
        ...existingControls,
        model: { ...(existingControls.model ?? {}) },
        updatedAt: now,
      };
      let modelRoute = null;

      if (controlKind === "mode") {
        const mode = normalizeThreadInteractionModeDep(
          request.mode ?? request.interaction_mode ?? request.value,
        );
        const approvalMode = normalizeThreadApprovalModeDep(
          request.approval_mode,
          approvalModeForThreadModeDep(mode),
        );
        nextControls.mode = mode;
        nextControls.approvalMode = approvalMode;
      } else {
        const modelInput = threadRuntimeControlModelInputDep(request, existingControls, agent);
        modelRoute = store.resolveModelRoute(
          {
            model: modelInput.model,
            workflowGraphId,
            workflowNodeId: modelInput.workflowNodeId,
            workflowNodeType: "Model Router",
          },
          {
            evidenceRefs: [`runtime_thread_${controlKind}_control`],
            workflowGraphId,
            workflowNodeId: modelInput.workflowNodeId,
            workflowNodeType: "Model Router",
          },
        );
        nextControls.model = {
          id: modelRoute.requestedModelId,
          routeId: modelRoute.routeId,
          selectedModel: modelRoute.selectedModel,
          endpointId: modelRoute.endpointId,
          providerId: modelRoute.providerId,
          receiptId: modelRoute.receiptId,
          reasoningEffort:
            modelRoute.decision?.reasoning_effort ??
            modelInput.model.reasoning_effort ??
            null,
          privacy: modelInput.model.privacy ?? null,
          maxCostUsd: modelInput.model.max_cost_usd ?? null,
          allow_hosted_fallback: modelInput.model.allow_hosted_fallback ?? null,
          workflowGraphId,
          workflowNodeId: modelRoute.decision?.workflow_node_id ?? modelInput.workflowNodeId,
          updatedAt: now,
        };
      }

      const event = this.appendThreadRuntimeControlEvent(store, {
        agent,
        threadId,
        controlKind,
        controls: nextControls,
        request,
        source,
        requestedBy,
        workflowGraphId,
        modelRoute,
        now,
      });
      const workspaceTrustWarningEvent =
        controlKind === "mode"
          ? this.appendWorkspaceTrustWarningEvent(store, {
              agent,
              threadId,
              controls: nextControls,
              request,
              source,
              requestedBy,
              workflowGraphId,
              modeEvent: event,
              now,
            })
          : null;
      if (typeof contextPolicyRunnerDep?.planThreadControlAgentStateUpdate !== "function") {
        throw runtimeErrorDep({
          status: 500,
          code: "thread_control_state_update_planner_unavailable",
          message: "Thread control updates require Rust policy state-update planning.",
          details: { thread_id: threadId, control_kind: controlKind },
        });
      }
      const stateUpdate = contextPolicyRunnerDep.planThreadControlAgentStateUpdate({
        thread_id: threadId,
        agent,
        control_kind: controlKind,
        controls: nextControls,
        event_id: event.event_id,
        seq: event.seq,
        created_at: event.created_at,
        updated_at: workspaceTrustWarningEvent?.created_at ?? event.created_at,
        workspace_trust_warning_event_id: workspaceTrustWarningEvent?.event_id ?? null,
        workspace_trust_warning_created_at: workspaceTrustWarningEvent?.created_at ?? null,
        model_route: threadControlAgentStateUpdateModelRoute(modelRoute),
      });
      const updatedAgent = stateUpdate.agent;
      if (!updatedAgent?.id) {
        throw runtimeErrorDep({
          status: 502,
          code: "thread_control_state_update_planner_invalid",
          message: "Rust policy state-update planning did not return an agent record.",
          details: { thread_id: threadId, control_kind: controlKind },
        });
      }
      const operationKind = requiredThreadControlOperationKind(stateUpdate, threadId, controlKind);
      store.agents.set(updatedAgent.id, updatedAgent);
      store.writeAgent(updatedAgent, operationKind);
      const thread = store.threadForAgent(updatedAgent);
      const workspaceTrustWarning = workspaceTrustWarningEvent?.payload_summary ?? null;
      return {
        ...thread,
        workspace_trust_warning: workspaceTrustWarning,
        control: {
          schema_version: runtimeThreadControlsSchemaVersion,
          control_kind: controlKind,
          mode: nextControls.mode,
          approval_mode: nextControls.approvalMode,
          model: nextControls.model,
          event_id: event.event_id,
          seq: event.seq,
          receipt_refs: event.receipt_refs,
          policy_decision_refs: event.policy_decision_refs,
          workspace_trust_warning: workspaceTrustWarning,
          workspace_trust_warning_event_id: workspaceTrustWarningEvent?.event_id ?? null,
        },
        event,
        workspace_trust_warning_event: workspaceTrustWarningEvent,
      };
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
      const streamId = eventStreamIdForThreadDep(threadId);
      const workflowNodeId =
        request.workflow_node_id ??
        modelRoute?.decision?.workflow_node_id ??
        (controlKind === "mode"
          ? "runtime.thread-mode"
          : controls.model?.workflowNodeId ?? "runtime.model-router");
      const payload =
        controlKind === "mode"
          ? {
              event_kind: "OperatorControl.Mode",
              control_kind: controlKind,
              mode: controls.mode,
              approval_mode: controls.approvalMode,
              requested_by: requestedBy,
              control_surface: source,
              agent_id: agent.id,
              thread_id: threadId,
              session_id: runtimeSessionIdForAgentDep(agent),
            }
          : {
              ...(modelRoute?.decision ?? {}),
              event_kind: "ModelRouteDecision",
              control_kind: controlKind,
              requested_by: requestedBy,
              control_surface: source,
              agent_id: agent.id,
              thread_id: threadId,
              session_id: runtimeSessionIdForAgentDep(agent),
              model_control: controls.model,
            };
      const controlHash = crypto
        .createHash("sha256")
        .update(JSON.stringify({
          controlKind,
          mode: controls.mode,
          approvalMode: controls.approvalMode,
          model: controls.model,
          workflowNodeId,
        }))
        .digest("hex")
        .slice(0, 16);
      return store.appendRuntimeEvent({
        event_stream_id: streamId,
        thread_id: threadId,
        turn_id: "",
        item_id: `${threadId}:item:${controlKind}-control:${controlHash}`,
        idempotency_key:
          request.idempotency_key ??
          `thread:${threadId}:control.${controlKind}:${controlHash}`,
        source,
        source_event_kind:
          controlKind === "mode"
            ? "OperatorControl.Mode"
            : controlKind === "thinking"
              ? "OperatorControl.Thinking"
              : "OperatorControl.Model",
        event_kind: controlKind === "mode" ? "thread.mode_updated" : "model.route_decision",
        status: "completed",
        actor: "user",
        created_at: now,
        workspace_root: agent.cwd,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        component_kind: controlKind === "mode" ? "runtime_mode" : "model_router",
        payload_schema_version:
          controlKind === "mode"
            ? runtimeThreadModeControlSchemaVersion
            : runtimeModelRouteControlSchemaVersion,
        payload,
        receipt_refs:
          controlKind === "mode"
            ? [`receipt_${agent.id}_mode_${safeIdDep(controls.mode)}_${controlHash}`]
            : [modelRoute?.receiptId].filter(Boolean),
        policy_decision_refs: [`policy_${agent.id}_${controlKind}_allow`],
        artifact_refs: [],
        rollback_refs: [],
        redaction_profile: "internal",
        fixture_profile: fixtureProfileForAgentDep(agent),
      });
    },
    appendWorkspaceTrustWarningEvent(store, input) {
      return trustState.appendWorkspaceTrustWarningEvent(store, input);
    },
    acknowledgeWorkspaceTrustWarning(store, threadId, warningId, request = {}) {
      return trustState.acknowledgeWorkspaceTrustWarning(store, threadId, warningId, request);
    },
  };

  function requiredThreadControlOperationKind(stateUpdate, threadId, controlKind) {
    const expectedOperationKind = `thread.${controlKind}`;
    const operationKind = optionalStringDep(stateUpdate.operation_kind);
    if (!operationKind) {
      throw runtimeErrorDep({
        status: 502,
        code: "thread_control_state_update_operation_kind_missing",
        message: "Rust policy state-update planning did not return an operation kind.",
        details: {
          thread_id: threadId,
          control_kind: controlKind,
          operation_kind: expectedOperationKind,
        },
      });
    }
    if (operationKind !== expectedOperationKind) {
      throw runtimeErrorDep({
        status: 502,
        code: "thread_control_state_update_operation_kind_mismatch",
        message: "Rust policy state-update planning returned an unexpected operation kind.",
        details: {
          thread_id: threadId,
          control_kind: controlKind,
          expected_operation_kind: expectedOperationKind,
          operation_kind: operationKind,
        },
      });
    }
    return operationKind;
  }
}

function threadControlAgentStateUpdateModelRoute(modelRoute = null) {
  if (!modelRoute || typeof modelRoute !== "object" || Array.isArray(modelRoute)) return null;
  return {
    requested_model_id: modelRoute.requestedModelId ?? null,
    selected_model: modelRoute.selectedModel ?? null,
    route_id: modelRoute.routeId ?? null,
    endpoint_id: modelRoute.endpointId ?? null,
    provider_id: modelRoute.providerId ?? null,
    receipt_id: modelRoute.receiptId ?? null,
    decision: modelRoute.decision ?? null,
  };
}
