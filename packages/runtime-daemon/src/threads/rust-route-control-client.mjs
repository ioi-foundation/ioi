// Rust route-control client — the substitute for the retired JS model-mount
// route-selection engine. The runtime daemon resolves a run's model route by
// asking the Rust hypervisor-daemon (the true-north model-mount substrate)
// instead of the in-process JS facade.
//
// This is the foundational component of the JS model-mount facade retirement
// (see the progress memory). It implements the same `selectRoute(...)` client
// interface that `createModelRouteSelection` injects, EXCEPT it is async (an
// HTTP call), so phase 2 of the retirement makes the run-create path async and
// wires this client in place of the facade.

export const RUST_ROUTE_CONTROL_EVIDENCE_REFS = [
  "runtime_model_route_selection_js_facade_retired",
  "rust_daemon_core_model_route_selection_required",
  "agentgres_model_route_selection_truth_required",
];

function defaultEndpoint() {
  return (
    process.env.IOI_HYPERVISOR_DAEMON_ENDPOINT ??
    process.env.IOI_DAEMON_ENDPOINT ??
    "http://127.0.0.1:8765"
  );
}

/**
 * Build a route-control client backed by the Rust hypervisor-daemon.
 * @param {object} options
 * @param {string} [options.daemonEndpoint] - Rust daemon base URL.
 * @param {string} [options.token] - capability token (bearer).
 * @param {Function} [options.fetchImpl] - fetch override (for tests).
 */
export function createRustRouteControlClient({ daemonEndpoint, token, fetchImpl } = {}) {
  const endpoint = (daemonEndpoint ?? defaultEndpoint()).replace(/\/+$/, "");
  // An explicit null/undefined-but-present fetchImpl means "no transport"
  // (fail closed); only an omitted fetchImpl falls back to the global fetch.
  const doFetch = fetchImpl !== undefined ? fetchImpl : globalThis.fetch;

  async function selectRoute({ modelId, routeId, capability, policy, body, evidenceRefs = [] } = {}) {
    if (typeof doFetch !== "function") {
      const error = new Error("Rust route-control client requires a fetch implementation.");
      error.code = "runtime_model_route_selection_rust_core_unavailable";
      error.status = 409;
      throw error;
    }
    const route = routeId && String(routeId).trim() ? String(routeId).trim() : "route.local-first";
    const requestBody = body && typeof body === "object" && !Array.isArray(body) ? body : {};
    const url = `${endpoint}/v1/model-mount/routes/${encodeURIComponent(route)}/test`;
    const headers = { "content-type": "application/json", accept: "application/json" };
    if (token) {
      headers.authorization = `Bearer ${token}`;
    }
    const response = await doFetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        capability: capability ?? "chat",
        model: modelId,
        route_id: route,
        model_policy: policy ?? null,
        ...requestBody,
      }),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      const error = new Error(
        `Rust route-control resolution failed: ${response.status} ${text}`,
      );
      error.status = response.status;
      error.code = "runtime_model_route_selection_rust_core_failed";
      error.details = {
        boundary: "runtime.model_route_selection",
        route_id: route,
        requested_model: modelId,
        evidence_refs: RUST_ROUTE_CONTROL_EVIDENCE_REFS,
        request_evidence_refs: evidenceRefs,
      };
      throw error;
    }
    const payload = await response.json();
    const selection = payload?.selection ?? payload ?? {};
    const endpointSelection = selection.endpoint ?? {};
    const providerSelection = selection.provider ?? {};
    return {
      route: selection.route ?? { id: route },
      endpoint: {
        id: endpointSelection.id ?? null,
        model_id: endpointSelection.modelId ?? endpointSelection.model_id ?? modelId ?? null,
      },
      provider: providerSelection,
      route_control: selection.route_control ?? null,
      route_decision: selection.route_decision ?? null,
      rust_core_boundary: "model_mount.route_control",
      evidence_refs: RUST_ROUTE_CONTROL_EVIDENCE_REFS,
    };
  }

  return { selectRoute };
}
