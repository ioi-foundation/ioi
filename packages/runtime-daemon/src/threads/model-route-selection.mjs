import {
  modelPolicyForOptions,
  modelRouteBindingFromReceipt,
  modelWorkflowContext,
} from "./thread-runtime-controls.mjs";

export function createModelRouteSelection({ modelMounting }) {
  function selectModelRoute({ requestedModel, routeId, capability, policy, body, evidenceRefs = [] }) {
    const selection = modelMounting.selectRoute({ modelId: requestedModel, routeId, capability, policy });
    const receipt = modelMounting.routeSelectionReceipt(selection, {
      body,
      capability,
      evidenceRefs,
    });
    return modelRouteBindingFromReceipt(receipt, requestedModel);
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
