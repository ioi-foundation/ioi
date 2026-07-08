#!/usr/bin/env node
// SUBSTRATE-TRUTH verifier (reclassified substrate_bound by the #31 Reference-UX-Port reset — checks DAEMON TRUTH, NOT reference UX parity) — Foundry · Models done-bar (models seed only).
//
// The parity phase's ninth surface. The reference capture (/__apps/models = the model-catalog app)
// is the familiar baseline; the IOI-owned Foundry landing already renders the SAME catalog grammar at
// /__ioi/foundry over the REAL daemon model-route registry — a Model Catalog where each route carries
// honest availability (probe evidence + staleness), weight custody, credential posture, admission
// trail, and admitted session-binding usage. This cut FORMALIZES that binding (matrix + verifier) and
// names the unsupported lanes. Route administration (enable/disable/probe/select-default) has ONE
// owner — Agent Studio — and the catalog links there rather than duplicating mutation.
//
// SCOPE (tight, by direction): only `models` binds. `modelstudio` (editor_canvas) and `inference`
// (wizard) stay reference_capture — they have no clean daemon truth to bind.
//
// Guard: read-only-projection cross-check. Read the live model-route registry + Foundry substrate,
// then assert the rendered Model Catalog reflects them EXACTLY — one card per route, each carrying the
// route's real availability/custody/credential/probe fields; and the substrate route count matches.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-foundry-models.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jd = async (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
const countOf = (t, needle) => t.split(needle).length - 1;

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/model-routes`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon model-route registry not reachable at " + DAEMON); process.exit(2); }

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix binds models as substrate_bound → /__ioi/foundry (Foundry)", bySlug.models?.parity_class === "substrate_bound" && bySlug.models?.substrate_surface === "/__ioi/foundry" && bySlug.models?.surface_name === "Foundry");
  ok("matrix keeps modelstudio + inference reference_capture (NOT over-claimed in this cut)", bySlug.modelstudio?.parity_class === "reference_capture" && bySlug.inference?.parity_class === "reference_capture");
  ok("no 'covered' anywhere; prior substrate_bound surfaces intact (pipeline/lineage/vertex/jobs/incidents/evalsuites/designer/approvals)", !(matrix.seeds || []).some((s) => s.parity_class === "covered") && ["pipeline", "lineage", "vertex", "jobs", "incidents", "evalsuites", "designer", "approvals"].every((k) => bySlug[k]?.parity_class === "substrate_bound"));

  // 1. Reference baseline.
  const ref = await page(`${SERVE}/__apps/models`);
  ok("reference baseline /__apps/models boots the model-catalog grammar", ref.status === 200 && /model[- ]?catalog/i.test(ref.text));

  // 2. Live daemon truth — the registry the catalog must reflect.
  const mr = await jd("/v1/hypervisor/model-routes");
  const routes = mr.routes || [];
  const ov = await jd("/v1/hypervisor/foundry/overview");
  const subRoutes = (ov.substrate || {}).model_routes;

  // 3. IOI surface = the catalog grammar over real truth (cross-checked).
  const f = await page(`${SERVE}/__ioi/foundry`);
  const t = f.text;
  ok("IOI /__ioi/foundry renders the Foundry landing + Model Catalog section", f.status === 200 && /<h1>Foundry/.test(t) && /id="foundry-model-catalog"/.test(t));
  ok("CROSS-CHECK: exactly one catalog card per real model route (no fabricated/dropped routes)", countOf(t, 'data-model-route="') === routes.length, `cards ${countOf(t, 'data-model-route="')} vs routes ${routes.length}`);
  ok("CROSS-CHECK: the Substrate 'Model routes' stat agrees with the route list + renders", subRoutes === routes.length && /Model routes<\/div>/.test(t), `substrate ${subRoutes} == routes ${routes.length}`);

  const r0 = routes[0];
  if (r0) {
    const av = r0.availability || {}; const cu = r0.custody || {}; const pr = av.probe || {};
    ok("a real route renders its identity (display_name + route_ref)", t.includes(r0.display_name || "__missing_route__") && t.includes(r0.route_ref || "__missing_route__"), r0.display_name);
    ok("a real route renders honest AVAILABILITY (probe state + staleness)", (!av.state || t.includes(`>${av.state}<`)) && (!av.stale || /stale probe/.test(t)), `${av.state}${av.stale ? " (stale)" : ""}`);
    ok("a real route renders CUSTODY (weight class · mount target · privacy posture)", t.includes(cu.weight_class || "__missing_route__") && t.includes(cu.mount_target || "__missing_route__") && t.includes(cu.execution_privacy_posture || "__missing_route__"), `${cu.weight_class}/${cu.mount_target}`);
    ok("a real route renders CREDENTIAL POSTURE", !r0.credential_posture || t.includes(r0.credential_posture), r0.credential_posture);
    ok("a real route renders PROBE evidence (matched model) when probed", !(pr.evidence && pr.evidence.matched_model) || t.includes(pr.evidence.matched_model), pr.evidence?.matched_model || "never probed");
  } else {
    ok("honest empty: no routes ⇒ the catalog says so (no fabrication)", /No model routes registered yet/.test(t), "0 routes");
  }
  ok("route administration is deferred to Agent Studio via the working #model-routes deep-link (not the no-op ?tab= form)", t.includes("/__ioi/agent-studio#model-routes") && !/agent-studio\?tab=model-routes/.test(t));

  // 4. No false coverage — named gaps + siblings named reference-only + brand-clean.
  ok("named gaps: fine-tuning / prompt playground / live inference evals / deployment automation / training runs / model cards", /fine-tuning/.test(t) && /prompt playground/.test(t) && /live inference evals/.test(t) && /deployment automation/.test(t) && /training runs/.test(t) && /model cards/.test(t));
  ok("sibling Foundry seeds named reference-only (Model Studio canvas + inference wizard)", t.includes("/__apps/modelstudio") && t.includes("/__apps/inference"));
  ok("reference capture linked as secondary; IOI surface brand-clean (no Palantir)", t.includes("/__apps/models") && !/\bPalantir\b/.test(t));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`substrate-truth-foundry-models readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
