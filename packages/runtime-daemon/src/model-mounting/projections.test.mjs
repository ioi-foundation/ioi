import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildModelRouteDecisions,
} from "./projections.mjs";

function fakeState() {
  return {
    listReceipts: () => [
      {
        id: "receipt.route.1",
        kind: "model_route_selection",
        details: {
          route_id: "route.local-first",
          selected_model: "model.local",
          endpoint_id: "endpoint.local",
          provider_id: "provider.local",
          model_route_decision: {
            route_id: "route.local-first",
            selected_endpoint_id: "endpoint.local",
          },
        },
      },
      { id: "receipt.tool.1", kind: "mcp_tool_invocation", details: {} },
    ],
  };
}

test("route decision projections are derived only from route selection receipts", () => {
  const decisions = buildModelRouteDecisions(fakeState());

  assert.equal(decisions.length, 1);
  assert.equal(decisions[0].route_id, "route.local-first");
  assert.equal(decisions[0].receipt_id, "receipt.route.1");
  assert.equal(decisions[0].selected_endpoint_id, "endpoint.local");
  assert.equal(Object.hasOwn(decisions[0], "routeId"), false);
  assert.equal(Object.hasOwn(decisions[0], "receiptId"), false);
  assert.equal(Object.hasOwn(decisions[0], "modelRouteDecision"), false);
});
