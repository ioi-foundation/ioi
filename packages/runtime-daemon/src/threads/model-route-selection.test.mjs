import assert from "node:assert/strict";
import test from "node:test";

import { createModelRouteSelection } from "./model-route-selection.mjs";

function routeReceipt({ id, body, selection, capability, evidenceRefs }) {
  return {
    id,
    kind: "model_route_selection",
    createdAt: "2026-06-04T00:00:00.000Z",
    details: {
      model_route_decision: {
        requested_model: body.model,
        selected_model: selection.endpoint?.modelId ?? selection.modelId ?? body.model,
        route_id: selection.route?.id ?? selection.routeId,
        endpoint_id: selection.endpoint?.id ?? selection.endpointId ?? null,
        provider_id: selection.provider?.id ?? selection.providerId ?? null,
        capability,
        evidence_refs: evidenceRefs,
        fallback_triggered: Boolean(body.fallback_triggered),
        fallback_reason: body.fallback_reason ?? null,
        workflow_node_id: body.workflow_node_id ?? null,
      },
    },
  };
}

test("model route selection resolves explicit model route with workflow context", () => {
  const calls = [];
  const helper = createModelRouteSelection({
    normalizeArray: (value) => (Array.isArray(value) ? value : []),
    modelMounting: {
      selectRoute(input) {
        calls.push(["selectRoute", input]);
        return {
          route: { id: input.routeId },
          endpoint: { id: "endpoint-local", modelId: input.modelId },
          provider: { id: "provider-local" },
        };
      },
      routeSelectionReceipt(selection, context) {
        calls.push(["routeSelectionReceipt", context]);
        return routeReceipt({ id: "receipt-direct", selection, ...context });
      },
    },
  });

  const route = helper.resolveModelRoute(
    {
      model: {
        id: "qwen-local",
        routeId: "route.local-first",
        reasoningEffort: "medium",
      },
    },
    {
      evidenceRefs: ["runtime_agent_model_route"],
      workflowNodeId: "runtime.model-router",
      workflowNodeType: "Model Router",
    },
  );

  assert.equal(calls[0][1].modelId, "qwen-local");
  assert.equal(calls[0][1].routeId, "route.local-first");
  assert.equal(calls[1][1].body.model_policy.reasoning_effort, "medium");
  assert.equal(calls[1][1].body.workflow_node_id, "runtime.model-router");
  assert.equal(route.requestedModelId, "qwen-local");
  assert.equal(route.selectedModel, "qwen-local");
  assert.equal(route.routeId, "route.local-first");
  assert.equal(route.endpointId, "endpoint-local");
  assert.equal(route.providerId, "provider-local");
  assert.equal(route.receiptId, "receipt-direct");
});

test("model route selection falls back to local-first route with merged candidate evidence", () => {
  const receiptContexts = [];
  let callCount = 0;
  const helper = createModelRouteSelection({
    normalizeArray: (value) => (Array.isArray(value) ? value : []),
    modelMounting: {
      selectRoute(input) {
        callCount += 1;
        if (callCount === 1) {
          const error = new Error("hosted route blocked");
          error.code = "hosted_route_blocked";
          error.details = {
            evaluatedCandidates: [{ endpointId: "hosted-one", status: "rejected" }],
          };
          throw error;
        }
        return {
          route: { id: input.routeId },
          endpoint: { id: "endpoint-fallback", modelId: "qwen-fallback" },
          provider: { id: "provider-local" },
          evaluatedCandidates: [{ endpointId: "local-one", status: "accepted" }],
        };
      },
      routeSelectionReceipt(selection, context) {
        receiptContexts.push({ selection, context });
        return routeReceipt({ id: "receipt-fallback", selection, ...context });
      },
    },
  });

  const route = helper.selectModelRouteWithFallback({
    requestedModel: "gpt-hosted",
    routeId: "route.hosted",
    capability: "chat",
    policy: { allow_hosted_fallback: true },
    body: { model: "gpt-hosted", route_id: "route.hosted" },
    evidenceRefs: ["runtime_run_model_route"],
  });

  assert.equal(callCount, 2);
  assert.equal(receiptContexts[0].context.body.model, "auto");
  assert.equal(receiptContexts[0].context.body.route_id, "route.local-first");
  assert.equal(receiptContexts[0].context.body.fallback_triggered, true);
  assert.equal(receiptContexts[0].context.body.fallback_reason, "hosted_route_blocked");
  assert.deepEqual(receiptContexts[0].context.evidenceRefs, [
    "runtime_model_route_fallback",
    "runtime_run_model_route",
  ]);
  assert.deepEqual(receiptContexts[0].selection.evaluatedCandidates, [
    { endpointId: "hosted-one", status: "rejected" },
    { endpointId: "local-one", status: "accepted" },
  ]);
  assert.equal(route.requestedModelId, "auto");
  assert.equal(route.selectedModel, "qwen-fallback");
  assert.equal(route.routeId, "route.local-first");
  assert.equal(route.decision.fallback_triggered, true);
});

test("run model route reuses persisted agent route when request has no model override", () => {
  const helper = createModelRouteSelection({
    modelMounting: {
      selectRoute() {
        throw new Error("should not select a route");
      },
      routeSelectionReceipt() {
        throw new Error("should not create a receipt");
      },
    },
  });

  const route = helper.resolveRunModelRoute({
    requestedModelId: "auto",
    modelId: "qwen-existing",
    modelRouteId: "route.local-first",
    modelRouteEndpointId: "endpoint-existing",
    modelRouteProviderId: "provider-existing",
    modelRouteReceiptId: "receipt-existing",
    modelRouteDecision: { selected_model: "qwen-existing" },
  });

  assert.equal(route.requestedModelId, "auto");
  assert.equal(route.selectedModel, "qwen-existing");
  assert.equal(route.routeId, "route.local-first");
  assert.equal(route.endpointId, "endpoint-existing");
  assert.equal(route.providerId, "provider-existing");
  assert.equal(route.receiptId, "receipt-existing");
});
