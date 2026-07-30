#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const exists = (relative) => fs.existsSync(path.join(root, relative));

const main = read("apps/hypervisor/src/main.tsx");
const data = read("apps/hypervisor/src/data/productSurface.ts");
const shell = read("apps/hypervisor/src/shell/AppShell.tsx");
const states = read("apps/hypervisor/src/surfaces/SurfaceStateFrame.tsx");
const daemon = read("crates/node/src/bin/hypervisor-daemon.rs");
const handlers = read("crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs");
const packageJson = JSON.parse(read("apps/hypervisor/package.json"));

for (const route of ["/home", "/systems", "/projects", "/applications", "/work", "/settings", "/studio", "/automations", "/ontology", "/data", "/governance", "/provenance", "/evaluations", "/improvement", "/foundry", "/packages", "/developer-workspace", "/developer-console", "/environments", "/operations", "/embodied-systems"]) {
  assert.ok(main.includes(route) || data.includes(route.slice(1)), `missing canonical surface ${route}`);
}
for (const state of ["loading", "empty", "missing_prerequisite", "degraded", "blocked", "approval_pending", "denied", "failed", "recovery", "completed"]) assert.ok(states.includes(state), `missing state ${state}`);
for (const contract of ["application-surface-registration", "surface-release-record", "surface-installation-binding", "system-interface-binding", "surface-serving-binding", "product-surface-projection"]) assert.ok(exists(`docs/architecture/_meta/schemas/hypervisor-${contract}.v1.schema.json`), `missing schema ${contract}`);
assert.match(shell, /data-testid="open-application"/);
assert.match(shell, /hv-breadcrumb/);
assert.match(shell, /navigate\(-1\)/);
assert.match(daemon, /product-surface-projections/);
assert.match(daemon, /collections\/query/);
assert.match(handlers, /hypervisor\.route_retired/);
assert.match(handlers, /preference_revision_conflict/);
assert.match(handlers, /page_size > 50/);
assert.equal(packageJson.scripts["serve:product-ui"], undefined);
assert.equal(packageJson.scripts["serve:app"], "vite preview --host 127.0.0.1 --port 4173");
assert.ok(!data.includes("route_alias"), "client must not admit compatibility aliases");

console.log("Hypervisor product-surface contract: PASS");
