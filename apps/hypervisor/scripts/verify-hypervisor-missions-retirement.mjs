#!/usr/bin/env node
// MISSIONS RETIREMENT verifier (ADR 0056 M5, 2026-09-25) — the negative, no-fallback and typed-retirement
// proof the protected-seed cutover requires (ported-seed-preservation.v1.json per_app_cutover_requirements).
//
// Missions owned no object once goal pursuit left the Hypervisor (R-192 / S5-1: an ioi.ai product over
// thread primitives). ADR 0056 re-parented its tools (Issues → Operations, Builds and Build Schedules →
// Automations, Artifact Ecology → Systems), moved every link off its root (M4) and retired the root:
//   1. TYPED RETIREMENT — GET /__ioi/missions answers 410 with the registered refusal record (JSON) or the
//      retired-route page (HTML), naming /work, having read nothing and written nothing.
//   2. NO FALLBACK — no registry row, no bound module, no catalog registration, no canonical yield: nothing
//      can serve the root again by accident.
//   3. THE TOOLS KEEP SERVING — their legacy lanes under the root and their owners' canonical routes answer
//      200 (an exact-path retirement, never a subtree one).
//   4. NOTHING LEADS THERE — the pages that used to link the root no longer do.
//   5. THE SEED IS PRESERVED — the module stays in the tree, bound to nothing.
//
// Run against a sign-in-off serve (the census posture): IOI_HYPERVISOR_SERVE_URL=http://127.0.0.1:<port>
// Exit: 0 pass · 1 fail · 2 blocked (serve unreachable).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, boundSurface, canonicalSurfaceRoute } from "./surface-registry.mjs";
import { retiredUiRouteFor } from "./v2-route-shell.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
// Its own isolated daemon + serve, the operator signed in (R-240, verifier auth sweep, 2026-09-29). This verifier read
// `IOI_HYPERVISOR_SERVE_URL || :4173` — the OWNER's development serve — with no session; since 2026-09-26 a serve requires
// sign-in, and the ontology/data-source reads behind its pages are caller-scoped. An explicit URL naming the owner's stack
// is refused (verifier-stack.mjs).
import { verifierStack } from "./lib/verifier-stack.mjs";
const STACK = await verifierStack({ serve: true });
const SERVE = STACK.serveUrl;
const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail: String(detail).slice(0, 220) });
const get = (p, accept) => fetch(`${SERVE}${p}`, { headers: { accept }, redirect: "manual" })
  .then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

const reachable = await get("/", "text/html");
if (!reachable.status) { console.error(`BLOCKED: no serve at ${SERVE}`); process.exit(2); }

// 1. Typed retirement.
const json = await get("/__ioi/missions", "application/json");
let refusal = {};
try { refusal = JSON.parse(json.text); } catch { /* reported below */ }
ok("TYPED RETIREMENT (JSON): /__ioi/missions answers 410 with the registered refusal record — route retired, /work as its replacement, nothing read, nothing written",
  json.status === 410 && refusal.schema_version === "ioi.hypervisor.route_retirement_refusal.v1" && refusal.code === "hypervisor.route_retired"
    && refusal.requested_route === "/__ioi/missions" && refusal.canonical_replacement_route === "/work"
    && refusal.read_performed === false && refusal.mutation_performed === false && refusal.final_invocation_performed === false,
  `${json.status} ${json.text.slice(0, 160)}`);
const html = await get("/__ioi/missions", "text/html");
ok("TYPED RETIREMENT (HTML): a browser gets the retired-route page (410) that names /work — a link, never a redirect alias",
  html.status === 410 && html.text.includes("/work") && !html.text.includes("ms-main"), `${html.status}`);

// 2. No fallback.
ok("NO FALLBACK: the registry lists no Missions surface and no module is bound to the root", !SURFACES.some((s) => s.slug === "missions" || s.route === "/__ioi/missions") && !boundSurface("/__ioi/missions", "GET") && !canonicalSurfaceRoute("/__ioi/missions"));
const retired = retiredUiRouteFor("/__ioi/missions");
ok("NO FALLBACK: the route shell retires EXACTLY the root toward /work, and none of the tool lanes beneath it",
  retired?.replacement === "/work" && ["/__ioi/missions/incidents", "/__ioi/missions/builds", "/__ioi/missions/schedules", "/__ioi/missions/ecology"].every((p) => retiredUiRouteFor(p) === null));
const tax = JSON.parse(fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/hypervisor_core_taxonomy.json"), "utf8"));
const records = JSON.parse(fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/hypervisor_surface_records.json"), "utf8"));
ok("NO FALLBACK: the daemon catalog registers no Missions surface (taxonomy and generated records)",
  !tax.application_registrations.some((r) => r.surface_key === "missions") && !JSON.stringify(records).includes("surface://hypervisor/missions\""));
const catalog = await get("/__ioi/api/applications", "application/json");
let apps = [];
try { apps = JSON.parse(catalog.text).applications || []; } catch { /* reported below */ }
ok("NO FALLBACK: the served catalog offers no Missions entry, and its former tools are offered under their owners",
  catalog.status === 200 && apps.length > 0 && !apps.some((a) => a.key === "missions" || a.route === "/__ioi/missions")
    && ["incidents", "jobs", "scheduler", "ecology"].every((k) => apps.some((a) => a.key === k)),
  `${catalog.status} ${apps.length} apps`);

// 3. The tools keep serving.
for (const [lane, canonical] of [["/__ioi/missions/incidents", "/operations/issues"], ["/__ioi/missions/builds", "/automations/runs"], ["/__ioi/missions/schedules", "/automations/schedules"], ["/__ioi/missions/ecology", "/systems/ecology"]]) {
  const a = await get(lane, "text/html");
  const b = await get(canonical, "text/html");
  ok(`THE TOOL KEEPS SERVING: ${lane} and its owner's route ${canonical} answer 200, neither a retirement page`,
    a.status === 200 && b.status === 200 && !/route_retired|Route retired/iu.test(a.text + b.text), `${a.status}/${b.status}`);
}

// 4. Nothing leads there.
const linking = [];
for (const p of ["/__ioi/operations", "/__ioi/sessions", "/__ioi/missions/incidents", "/__ioi/missions/builds", "/__ioi/missions/schedules", "/__ioi/missions/ecology", "/__ioi/evaluations", "/__ioi/foundry/inference"]) {
  const r = await get(p, "text/html");
  if (/href="\/__ioi\/missions(?:[?"#])/.test(r.text)) linking.push(p);
}
ok("NOTHING LEADS THERE: no page that used to link the Missions root still does", linking.length === 0, linking.join(" "));

// 5. The seed is preserved.
const seed = path.join(APP, "surfaces", "missions", "index.mjs");
const mod = await import(seed);
ok("THE SEED IS PRESERVED: the Missions module stays in the tree with its render contract, bound to nothing (seeds are never mass-deleted)",
  fs.existsSync(seed) && typeof mod.render === "function" && mod.meta?.route === "/__ioi/missions");

const passed = results.filter((r) => r.pass).length;
for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.pass || !r.detail ? "" : `  (${r.detail})`}`);
console.log(`${passed}/${results.length} passed`);
process.exit(passed === results.length ? 0 : 1);
