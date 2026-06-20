import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_MODEL_ROUTE_SELECTION_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  createModelRouteSelection,
} from "./model-route-selection.mjs";

function rustModelMounting(calls = []) {
  return {
    selectRoute(input) {
      calls.push(["selectRoute", input]);
      return {
        route: { id: input.routeId },
        endpoint: { id: "endpoint.local", modelId: input.modelId },
        provider: { id: "provider.local" },
        route_decision: {
          route_decision_ref: "model_mount://route_decision/rust",
          route_ref: input.routeId,
          provider_ref: "provider.local",
          endpoint_ref: "endpoint.local",
          model_ref: input.modelId,
          capability: input.capability,
          policy_hash: "sha256:route-policy",
          workflow_graph_ref: input.body.workflow_graph_id ?? null,
          workflow_node_ref: input.body.workflow_node_id ?? null,
        },
        routeReceipt: {
          id: "receipt.route-selection",
          kind: "model_route_selection",
          details: {
            route_id: input.routeId,
            selected_model: input.modelId,
            endpoint_id: "endpoint.local",
            provider_id: "provider.local",
            model_mount_route_decision_ref: "model_mount://route_decision/rust",
            workflow_graph_id: input.body.workflow_graph_id ?? null,
            workflow_node_id: input.body.workflow_node_id ?? null,
          },
        },
        route_control: {
          record_dir: "model-route-selections",
          record_id: "route_selection:runtime:test",
        },
        rust_core_boundary: "model_mount.route_control",
        evidence_refs: ["model_mount_route_control_rust_owned"],
      };
    },
    routeSelectionReceipt() {
      calls.push(["routeSelectionReceipt"]);
      throw new Error("JS route-selection receipt should not be created");
    },
  };
}

test("model route selection explicit facade uses Rust route-control selection without JS receipt creation", async () => {
  const calls = [];
  const helper = createModelRouteSelection({
    modelMounting: rustModelMounting(calls),
  });

  const route = await helper.resolveModelRoute(
    {
      model: {
        id: "qwen-local",
        route_id: "route.local-first",
        reasoningEffort: "medium",
      },
    },
    {
      evidenceRefs: ["runtime_agent_model_route"],
      workflowNodeId: "runtime.model-router",
      workflowNodeType: "Model Router",
    },
  );

  assert.equal(route.requestedModelId, "qwen-local");
  assert.equal(route.selectedModel, "qwen-local");
  assert.equal(route.routeId, "route.local-first");
  assert.equal(route.endpointId, "endpoint.local");
  assert.equal(route.providerId, "provider.local");
  assert.equal(route.receiptId, "receipt.route-selection");
  assert.equal(route.decision.model_mount_route_decision_ref, "model_mount://route_decision/rust");
  assert.equal(route.decision.workflow_node_id, "runtime.model-router");
  assert.equal(route.routeControl.record_dir, "model-route-selections");
  assert.equal(route.rust_core_boundary, "model_mount.route_control");
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "selectRoute");
  assert.equal(calls[0][1].modelId, "qwen-local");
  assert.equal(calls[0][1].routeId, "route.local-first");
  assert.equal(calls[0][1].body.workflow_node_id, "runtime.model-router");
  assert.equal(Object.hasOwn(calls[0][1].body, "workflowNodeId"), false);
});

test("model route selection validates canonical request shape before Rust route-control selection", async () => {
  const calls = [];
  const helper = createModelRouteSelection({
    modelMounting: rustModelMounting(calls),
  });

  const route = await helper.resolveModelRoute({
    routeId: "route.retired-option",
    model: {
      modelId: "retired-model",
      routeId: "route.retired-model",
    },
  });

  assert.equal(route.requestedModelId, "auto");
  assert.equal(route.routeId, "route.local-first");
  assert.equal(calls.length, 1);
  assert.equal(calls[0][1].modelId, "auto");
  assert.equal(calls[0][1].routeId, "route.local-first");
  assert.equal(calls[0][1].body.model, "auto");
  assert.equal(calls[0][1].body.route_id, "route.local-first");
  assert.equal(Object.hasOwn(calls[0][1].body, "modelId"), false);
  assert.equal(Object.hasOwn(calls[0][1].body, "routeId"), false);
});

test("direct selectModelRoute uses Rust selection instead of creating JS fallback receipt", async () => {
  const calls = [];
  const helper = createModelRouteSelection({
    modelMounting: rustModelMounting(calls),
  });

  const route = await helper.selectModelRoute({
    requestedModel: "gpt-hosted",
    routeId: "route.hosted",
    capability: "chat",
    policy: { allow_hosted_fallback: true },
    body: { model: "gpt-hosted", route_id: "route.hosted" },
    evidenceRefs: ["runtime_run_model_route"],
  });

  assert.equal(route.selectedModel, "gpt-hosted");
  assert.equal(route.routeId, "route.hosted");
  assert.equal(route.receiptId, "receipt.route-selection");
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "selectRoute");
  assert.equal(calls[0][1].body.model_policy.allow_hosted_fallback, true);
});

test("run model route with model override uses Rust route-control selection", async () => {
  const calls = [];
  const helper = createModelRouteSelection({
    modelMounting: rustModelMounting(calls),
  });

  const route = await helper.resolveRunModelRoute(
    {},
    {
      options: {
        model: {
          id: "qwen-local",
          route_id: "route.local-first",
        },
      },
    },
  );

  assert.equal(route.selectedModel, "qwen-local");
  assert.equal(route.decision.workflow_node_id, "runtime.model-router");
  assert.equal(calls.length, 1);
  assert.equal(calls[0][1].body.workflow_node_id, "runtime.model-router");
});

test("model route selection fails closed when Rust route-control client is unavailable", async () => {
  const helper = createModelRouteSelection();

  await assert.rejects(
    () =>
      helper.selectModelRoute({
        requestedModel: "gpt-hosted",
        routeId: "route.hosted",
        capability: "chat",
        policy: { allow_hosted_fallback: true },
        body: { model: "gpt-hosted", route_id: "route.hosted" },
        evidenceRefs: ["runtime_run_model_route"],
      }),
    (error) => {
      assert.equal(error.code, "runtime_model_route_selection_rust_core_required");
      assert.equal(error.details.requested_model, "gpt-hosted");
      assert.equal(error.details.route_id, "route.hosted");
      assert.deepEqual(error.details.request_evidence_refs, ["runtime_run_model_route"]);
      assert.deepEqual(
        error.details.evidence_refs,
        RUNTIME_MODEL_ROUTE_SELECTION_RUST_CORE_REQUIRED_EVIDENCE_REFS,
      );
      return true;
    },
  );
});

test("run model route reuses persisted agent route when request has no model override", async () => {
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

  const route = await helper.resolveRunModelRoute({
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
