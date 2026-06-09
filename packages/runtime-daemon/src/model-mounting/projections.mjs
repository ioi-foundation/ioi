import * as routeDecision from "./route-decision.mjs";

export function buildModelRouteDecisions(state) {
  return state.listReceipts()
    .filter((receipt) => receipt.kind === "model_route_selection")
    .map(routeDecision.routeDecisionProjectionFromReceipt)
    .filter(Boolean);
}
