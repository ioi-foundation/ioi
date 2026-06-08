import {
  modelPolicyForOptions,
  modelWorkflowContext,
} from "./thread-runtime-controls.mjs";

export const RUNTIME_MODEL_ROUTE_SELECTION_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "runtime_model_route_selection_js_facade_retired",
  "rust_daemon_core_model_route_selection_required",
  "agentgres_model_route_selection_truth_required",
];

export function modelRouteSelectionRustCoreRequiredError(operationKind, details = {}) {
  const error = new Error("Runtime model-route selection requires Rust daemon-core model_mount admission.");
  error.code = "runtime_model_route_selection_rust_core_required";
  error.status = 409;
  error.details = {
    boundary: "runtime.model_route_selection",
    operation_kind: operationKind,
    evidence_refs: RUNTIME_MODEL_ROUTE_SELECTION_RUST_CORE_REQUIRED_EVIDENCE_REFS,
    ...details,
  };
  return error;
}

export function createModelRouteSelection() {
  function selectModelRoute({ requestedModel, routeId, capability, policy, body, evidenceRefs = [] }) {
    throw modelRouteSelectionRustCoreRequiredError("select_model_route", {
      requested_model: requestedModel,
      route_id: routeId,
      capability,
      model_policy: policy,
      request_body: body,
      request_evidence_refs: evidenceRefs,
    });
  }

  function resolveModelRoute(options = {}, context = {}) {
    const model = options.model ?? {};
    const requestedModel = model.id ?? model.model ?? "auto";
    const routeId = model.route_id ?? model.route ?? options.route_id ?? "route.local-first";
    const capability = model.capability ?? options.capability ?? "chat";
    const policy = modelPolicyForOptions(options);
    const workflow = modelWorkflowContext({ model, options, context });
    const body = {
      model: requestedModel,
      route_id: routeId,
      model_policy: policy,
      ...workflow,
    };
    return selectModelRoute({
      requestedModel,
      routeId,
      capability,
      policy,
      body,
      evidenceRefs: context.evidenceRefs ?? [],
    });
  }

  function resolveRunModelRoute(agent, request = {}) {
    const options = request.options ?? {};
    if (options.model) {
      return resolveModelRoute(options, {
        evidenceRefs: ["runtime_run_model_route"],
        workflowNodeId: "runtime.model-router",
        workflowNodeType: "Model Router",
      });
    }
    return {
      requestedModelId: agent.requestedModelId ?? agent.modelId,
      selectedModel: agent.modelId,
      routeId: agent.modelRouteId ?? "route.local-first",
      endpointId: agent.modelRouteEndpointId ?? null,
      providerId: agent.modelRouteProviderId ?? null,
      receiptId: agent.modelRouteReceiptId ?? null,
      decision: agent.modelRouteDecision ?? null,
    };
  }

  return {
    resolveModelRoute,
    resolveRunModelRoute,
    selectModelRoute,
  };
}
