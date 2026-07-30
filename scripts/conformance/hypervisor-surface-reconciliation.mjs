#!/usr/bin/env node
import process from "node:process";

const base = (process.env.IOI_HYPERVISOR_DAEMON_URL ?? "").replace(/\/$/, "");
if (!base) throw new Error("IOI_HYPERVISOR_DAEMON_URL must name an isolated test daemon");
if (process.env.IOI_HYPERVISOR_CONFORMANCE_ALLOW_MUTATION !== "1") {
  throw new Error("refusing preference-write proof without IOI_HYPERVISOR_CONFORMANCE_ALLOW_MUTATION=1");
}

async function request(path, { expected = 200, ...init } = {}) {
  const response = await fetch(`${base}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
  const body = await response.json();
  if (response.status !== expected) throw new Error(`${path}: expected ${expected}, received ${response.status}: ${JSON.stringify(body)}`);
  return { response, body };
}

const projection = (await request("/v1/hypervisor/product-surface-projections", {
  method: "POST",
  body: JSON.stringify({ org_ref: "org://local", context: {}, requested_group_kinds: [], preference_projection_refs: [] }),
})).body;
if (projection.schema_version !== "ioi.hypervisor.product_surface_projection.v1" || projection.workspace_entries.length !== 6 || projection.application_entries.length !== 15) throw new Error("compiled projection census mismatch");
const studio = projection.application_entries.find((entry) => entry.identity_ref === "surface://hypervisor/studio");
const embodied = projection.application_entries.find((entry) => entry.identity_ref === "surface://hypervisor/embodied-systems");
if (!studio?.launchable || studio.surface_capability_depth !== "propose" || embodied?.launchable || embodied?.resolved_launch_route !== null) throw new Error("normalized record admission mismatch");

await request("/v1/hypervisor/product-surface-projections", { expected: 403, method: "POST", body: JSON.stringify({ user_ref: "user://substitution", org_ref: "org://local" }) });
await request("/v1/hypervisor/product-surface-projections", { expected: 403, method: "POST", body: JSON.stringify({ org_ref: "org://foreign" }) });

const page = (await request("/v1/hypervisor/collections/query", { method: "POST", body: JSON.stringify({ org_ref: "org://local", collection: "sessions", search: "", filters: [], sort: [], facets: [], cursor: null, page_size: 25 }) })).body;
if (page.schema_version !== "ioi.hypervisor.collection_page.v1" || page.serialized_bytes > 1_048_576 || page.policy_filtered_before_counts_and_cache !== true) throw new Error("bounded collection projection mismatch");
await request("/v1/hypervisor/collections/query", { expected: 400, method: "POST", body: JSON.stringify({ org_ref: "org://local", collection: "sessions", filters: [], sort: [], facets: [], page_size: 51 }) });
await request("/v1/hypervisor/collections/query", { expected: 400, method: "POST", body: JSON.stringify({ org_ref: "org://local", collection: "sessions", filters: [{ field: "status", operator: "execute", value: "x" }], sort: [], facets: [], page_size: 25 }) });
await request("/v1/hypervisor/collections/query", { expected: 400, method: "POST", body: JSON.stringify({ org_ref: "org://local", collection: "sessions", filters: [], sort: [], facets: [], cursor: "cursor:wrong:1", page_size: 25 }) });

const preferenceId = `reconciliation-${Date.now()}`;
const first = (await request(`/v1/hypervisor/preferences/${preferenceId}`, { method: "PUT", body: JSON.stringify({ org_ref: "org://local", preference_kind: "surface_preference", value: { density: "compact" }, expected_revision: 0 }) })).body;
if (first.preference.revision !== 1 || first.receipt.previous_revision !== 0 || first.receipt.revision !== 1 || first.receipt.recovery_required !== false || !String(first.receipt.state_root_ref).startsWith("agentgres://state-root/")) throw new Error("complete mutation receipt mismatch");
await request(`/v1/hypervisor/preferences/${preferenceId}`, { expected: 409, method: "PUT", body: JSON.stringify({ org_ref: "org://local", preference_kind: "surface_preference", value: {}, expected_revision: 0 }) });
const listed = (await request("/v1/hypervisor/preferences?org_ref=org%3A%2F%2Flocal")).body.preferences;
if (!listed.some((record) => record.preference_id === preferenceId && record.revision === 1)) throw new Error("preference read-after-write mismatch");

for (const [route, replacement] of [["/sessions", "/work/sessions"], ["/missions", "/work"], ["/__ioi/legacy", null]]) {
  const { response, body } = await request(route, { expected: 410 });
  if (response.headers.get("cache-control") !== "no-store" || body.code !== "hypervisor.route_retired" || body.canonical_replacement_route !== replacement || body.read_performed || body.mutation_performed || body.final_invocation_performed) throw new Error(`${route}: retirement refusal mismatch`);
}

console.log(JSON.stringify({
  check: "hypervisor-surface-reconciliation",
  result: "PASS",
  projection_id: projection.projection_id,
  workspace_count: projection.workspace_entries.length,
  application_count: projection.application_entries.length,
  admitted_application_count: projection.application_entries.filter((entry) => entry.launchable).length,
  planned_nonlaunchable_count: projection.application_entries.filter((entry) => !entry.launchable).length,
  preference_revision: first.preference.revision,
  collection_page_bytes: page.serialized_bytes,
  denials: ["principal_substitution", "organization_membership", "page_bound", "filter_operator", "cursor_context", "stale_revision"],
  retirement_routes: ["/sessions", "/missions", "/__ioi/*"],
}, null, 2));
