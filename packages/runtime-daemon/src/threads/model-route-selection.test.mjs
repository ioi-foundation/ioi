import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_MODEL_ROUTE_SELECTION_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  createModelRouteSelection,
} from "./model-route-selection.mjs";

test("model route selection explicit facade fails closed before JS route selection or receipt creation", () => {
  const calls = [];
  const helper = createModelRouteSelection({
    modelMounting: {
      selectRoute(input) {
        calls.push(["selectRoute", input]);
        throw new Error("JS route selection should not run");
      },
      routeSelectionReceipt(selection, context) {
        calls.push(["routeSelectionReceipt", selection, context]);
        throw new Error("JS route-selection receipt should not be created");
      },
    },
  });

  assert.throws(
    () =>
      helper.resolveModelRoute(
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
      ),
    (error) => {
      assert.equal(error.code, "runtime_model_route_selection_rust_core_required");
      assert.equal(error.status, 409);
      assert.equal(error.details.boundary, "runtime.model_route_selection");
      assert.equal(error.details.operation_kind, "select_model_route");
      assert.equal(error.details.requested_model, "qwen-local");
      assert.equal(error.details.route_id, "route.local-first");
      assert.equal(error.details.capability, "chat");
      assert.equal(error.details.model_policy.reasoning_effort, "medium");
      assert.equal(error.details.request_body.workflow_node_id, "runtime.model-router");
      assert.deepEqual(error.details.request_evidence_refs, ["runtime_agent_model_route"]);
      assert.deepEqual(
        error.details.evidence_refs,
        RUNTIME_MODEL_ROUTE_SELECTION_RUST_CORE_REQUIRED_EVIDENCE_REFS,
      );
      return true;
    },
  );
  assert.deepEqual(calls, []);
});

test("model route selection validates canonical request shape then fails closed before retired aliases run", () => {
  const calls = [];
  const helper = createModelRouteSelection({
    modelMounting: {
      selectRoute(input) {
        calls.push(["selectRoute", input]);
        throw new Error("JS route selection should not run");
      },
      routeSelectionReceipt(selection, context) {
        calls.push(["routeSelectionReceipt", selection, context]);
        throw new Error("JS route-selection receipt should not be created");
      },
    },
  });

  assert.throws(
    () =>
      helper.resolveModelRoute({
        routeId: "route.retired-option",
        model: {
          modelId: "retired-model",
          routeId: "route.retired-model",
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_model_route_selection_rust_core_required");
      assert.equal(error.details.requested_model, "auto");
      assert.equal(error.details.route_id, "route.local-first");
      assert.equal(error.details.request_body.model, "auto");
      assert.equal(error.details.request_body.route_id, "route.local-first");
      return true;
    },
  );
  assert.deepEqual(calls, []);
});

test("direct selectModelRoute fails closed instead of creating JS fallback receipt", () => {
  const calls = [];
  const helper = createModelRouteSelection({
    modelMounting: {
      selectRoute(input) {
        calls.push(["selectRoute", input]);
        throw new Error("JS fallback route selection should not run");
      },
      routeSelectionReceipt(selection, context) {
        calls.push(["routeSelectionReceipt", selection, context]);
        throw new Error("JS fallback route receipt should not be created");
      },
    },
  });

  assert.throws(
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
      return true;
    },
  );
  assert.deepEqual(calls, []);
});

test("run model route with model override fails closed before JS route selection", () => {
  const calls = [];
  const helper = createModelRouteSelection({
    modelMounting: {
      selectRoute(input) {
        calls.push(["selectRoute", input]);
        throw new Error("JS run route selection should not run");
      },
      routeSelectionReceipt(selection, context) {
        calls.push(["routeSelectionReceipt", selection, context]);
        throw new Error("JS run route receipt should not be created");
      },
    },
  });

  assert.throws(
    () =>
      helper.resolveRunModelRoute(
        {},
        {
          options: {
            model: {
              id: "qwen-local",
              route_id: "route.local-first",
            },
          },
        },
      ),
    (error) => {
      assert.equal(error.code, "runtime_model_route_selection_rust_core_required");
      assert.equal(error.details.request_body.workflow_node_id, "runtime.model-router");
      assert.deepEqual(error.details.request_evidence_refs, ["runtime_run_model_route"]);
      return true;
    },
  );
  assert.deepEqual(calls, []);
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
