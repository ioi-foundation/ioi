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

export function createModelRouteSelection({ modelMounting } = {}) {
  async function selectModelRoute({ requestedModel, routeId, capability, policy, body, evidenceRefs = [] }) {
    if (!modelMounting || typeof modelMounting.selectRoute !== "function") {
      throw modelRouteSelectionRustCoreRequiredError("select_model_route", {
        requested_model: requestedModel,
        route_id: routeId,
        capability,
        model_policy: policy,
        request_body: body,
        request_evidence_refs: evidenceRefs,
      });
    }
    const requestBody = body && typeof body === "object" && !Array.isArray(body) ? body : {};
    const selection = await modelMounting.selectRoute({
      modelId: requestedModel,
      routeId,
      capability,
      policy,
      body: {
        ...requestBody,
        model: requestedModel,
        route_id: routeId,
        model_policy: policy,
      },
      evidenceRefs,
    });
    return runtimeModelRouteFromSelection(selection, {
      requested_model: requestedModel,
      route_id: routeId,
      capability,
      body: requestBody,
    });
  }

  async function resolveModelRoute(options = {}, context = {}) {
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

  async function resolveRunModelRoute(agent, request = {}) {
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

function runtimeModelRouteFromSelection(selection = {}, context = {}) {
  const routeDecision = selection.route_decision ?? {};
  const routeReceipt = selection.routeReceipt ?? selection.route_receipt ?? null;
  const routeReceiptDetails = routeReceipt?.details ?? {};
  const route = selection.route ?? {};
  const endpoint = selection.endpoint ?? {};
  const provider = selection.provider ?? {};
  const decision = {
    ...routeDecision,
    route_id:
      routeDecision.route_id ??
      routeDecision.route_ref ??
      routeReceiptDetails.route_id ??
      route.id ??
      context.route_id ??
      "route.local-first",
    selected_model:
      routeDecision.selected_model ??
      routeDecision.model_ref ??
      routeReceiptDetails.selected_model ??
      endpoint.model_id ??
      endpoint.modelId ??
      context.requested_model ??
      "auto",
    endpoint_id:
      routeDecision.endpoint_id ??
      routeDecision.endpoint_ref ??
      routeReceiptDetails.endpoint_id ??
      endpoint.id ??
      null,
    provider_id:
      routeDecision.provider_id ??
      routeDecision.provider_ref ??
      routeReceiptDetails.provider_id ??
      provider.id ??
      null,
    capability: routeDecision.capability ?? context.capability ?? "chat",
    policy_hash:
      routeDecision.policy_hash ??
      routeReceiptDetails.policy_hash ??
      selection.route_control?.control_hash ??
      null,
    workflow_graph_id:
      routeDecision.workflow_graph_id ??
      routeDecision.workflow_graph_ref ??
      routeReceiptDetails.workflow_graph_id ??
      context.body?.workflow_graph_id ??
      null,
    workflow_node_id:
      routeDecision.workflow_node_id ??
      routeDecision.workflow_node_ref ??
      routeReceiptDetails.workflow_node_id ??
      context.body?.workflow_node_id ??
      null,
    model_mount_route_decision_ref:
      routeDecision.model_mount_route_decision_ref ??
      routeDecision.route_decision_ref ??
      routeReceiptDetails.model_mount_route_decision_ref ??
      null,
  };
  return {
    requestedModelId: context.requested_model ?? "auto",
    selectedModel: decision.selected_model,
    routeId: decision.route_id,
    endpointId: decision.endpoint_id,
    providerId: decision.provider_id,
    receiptId: routeReceipt?.id ?? null,
    decision,
    routeReceipt,
    routeControl: selection.route_control ?? null,
    rust_core_boundary: selection.rust_core_boundary ?? "model_mount.route_control",
    evidence_refs: selection.evidence_refs ?? [],
  };
}
