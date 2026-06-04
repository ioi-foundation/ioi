import {
  modelPolicyForOptions,
  modelRouteBindingFromReceipt,
  modelWorkflowContext,
} from "./thread-runtime-controls.mjs";

export function createModelRouteSelection({ modelMounting, normalizeArray }) {
  const array = typeof normalizeArray === "function"
    ? normalizeArray
    : (value) => (Array.isArray(value) ? value : []);

  function selectModelRouteWithFallback({ requestedModel, routeId, capability, policy, body, evidenceRefs = [] }) {
    try {
      const selection = modelMounting.selectRoute({ modelId: requestedModel, routeId, capability, policy });
      const receipt = modelMounting.routeSelectionReceipt(selection, {
        body,
        capability,
        evidenceRefs,
      });
      return modelRouteBindingFromReceipt(receipt, requestedModel);
    } catch (error) {
      const fallbackRouteId = "route.local-first";
      const fallbackPolicy = {
        ...policy,
        allow_hosted_fallback: false,
      };
      const fallbackBody = {
        ...body,
        model: "auto",
        route_id: fallbackRouteId,
        model_policy: fallbackPolicy,
        fallback_triggered: true,
        fallback_reason: error?.code ?? "primary_route_unavailable",
      };
      const fallbackSelection = modelMounting.selectRoute({
        modelId: "auto",
        routeId: fallbackRouteId,
        capability,
        policy: fallbackPolicy,
      });
      fallbackSelection.evaluatedCandidates = [
        ...array(error?.details?.evaluatedCandidates),
        ...array(fallbackSelection.evaluatedCandidates),
      ];
      const receipt = modelMounting.routeSelectionReceipt(fallbackSelection, {
        body: fallbackBody,
        capability,
        evidenceRefs: ["runtime_model_route_fallback", ...evidenceRefs],
      });
      return modelRouteBindingFromReceipt(receipt, requestedModel);
    }
  }

  function resolveModelRoute(options = {}, context = {}) {
    const model = options.model ?? {};
    const requestedModel = model.id ?? model.model ?? model.modelId ?? "auto";
    const routeId = model.routeId ?? model.route_id ?? model.route ?? options.routeId ?? options.route_id ?? "route.local-first";
    const capability = model.capability ?? options.capability ?? "chat";
    const policy = modelPolicyForOptions(options);
    const workflow = modelWorkflowContext({ model, options, context });
    const body = {
      model: requestedModel,
      route_id: routeId,
      model_policy: policy,
      ...workflow,
    };
    return selectModelRouteWithFallback({
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
    selectModelRouteWithFallback,
  };
}
