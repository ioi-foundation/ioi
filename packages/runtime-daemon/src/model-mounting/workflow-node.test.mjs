import assert from "node:assert/strict";
import { test } from "node:test";

import { nativeInvocationResponseShape } from "./workflow-node.mjs";

test("native workflow invocation response reads canonical route decision details", () => {
  const baseInvocation = {
    model: "model.local",
    route: { id: "route.local-first" },
    endpoint: { id: "endpoint.local" },
    instance: { id: "instance.local", backendId: "backend.local" },
    receipt: { id: "receipt.invoke", details: {} },
    routeReceipt: { id: "receipt.route", details: {} },
    responseId: "resp-1",
    previousResponseId: null,
    toolReceiptIds: [],
    outputText: "hello",
    tokenCount: { total_tokens: 1 },
  };

  const response = nativeInvocationResponseShape({
    ...baseInvocation,
    routeReceipt: {
      id: "receipt.route",
      details: {
        model_route_decision: { routeId: "route.local-first", selectedModel: "model.local" },
      },
    },
  });

  assert.deepEqual(response.route_decision, { routeId: "route.local-first", selectedModel: "model.local" });

  const legacyOnly = nativeInvocationResponseShape({
    ...baseInvocation,
    routeReceipt: {
      id: "receipt.route.legacy",
      details: {
        modelRouteDecision: { routeId: "route.legacy" },
      },
    },
  });
  assert.equal(legacyOnly.route_decision, null);
});
