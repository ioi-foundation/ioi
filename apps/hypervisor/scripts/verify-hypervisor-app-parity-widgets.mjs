#!/usr/bin/env node
// PIXEL-CERTIFIED PARITY verifier — Developer Console · Custom Widgets done-bar (widgets seed only).
//
// The FIFTEENTH faithful port, the EIGHTH from the origin-alignment queue, and the FIRST
// Developer-Console-family certified surface. The #44 sweep proved the Custom Widgets landing
// data-bearing on the capture-origin lane (localhost:9225/workspace/custom-widgets/) while the
// /__apps/widgets proxy lane renders no data (the capture bakes its origin into a JS chunk the
// index-fold cannot reach — the documented adopt-lane gap); this cut stamps
// reference_url_override onto the honest lane and builds /__ioi/developer-console/widgets as a
// READ-ONLY registry lens over the estate's REAL widget/extension registration plane
// (GET /v1/hypervisor/odk/surface-descriptors — the ODK OntologySurfaceDescriptor registry).
//
// THE REGISTRATION BOUNDARY IS THE POINT OF THIS VERIFIER: a read projection over declared
// registrations, never an authoring/build surface.
//   1. MATRIX/CERT/SWEEP: daemon_wired + origin-aligned + REAL non-pinned certification; census >= 15.
//   2. REGISTRY CROSS-CHECKS: the catalog count equals the registry; a registered descriptor's
//      name/ref/pattern/ontology binding render; the empty registry renders the honest empty
//      state (nothing invented); creator/edited/viewed columns are HONEST em-dashes.
//   3. READ-ONLY: no form, no mutation affordance; New widget set ROUTES to the ODK dev kit
//      (where the daemon's descriptor-create authority actually lives — ontology-bound drafts);
//      the reference's dev-kit fork (build in-env vs external SDK/CLI) stays a named gap.
//   4. NO body pixel claim: the certification is SHELL-scoped; rows are masked live data.
//
// FIXTURE ISOLATION: this verifier NEVER writes to the shared daemon. When the real registry is
// empty, the dynamic render checks run against an ISOLATED daemon+serve pair
// (lib/isolated-daemon.mjs) walking the plane's own ladder THERE: declare a DomainOntology
// (POST /v1/hypervisor/odk/ontologies) then register a descriptor bound to it
// (POST /v1/hypervisor/odk/surface-descriptors) — torn down whole.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-widgets.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const sdProbe = await fetch(`${DAEMON}/v1/hypervisor/odk/surface-descriptors`).then((r) => r.json()).catch(() => ({}));
  if (!Array.isArray(sdProbe.surface_descriptors)) { console.error("BLOCKED: daemon surface-descriptor registry not reachable at " + DAEMON); process.exit(2); }

  // The SHARED estate renders as-is (zero writes) — including the honest EMPTY state when the
  // registry has no registrations. The row-rendering proof then runs on an ISOLATED plane.
  const sharedEmpty = sdProbe.surface_descriptors.length === 0;
  let SERVE_D = SERVE, DAEMON_D = DAEMON, plane = null;
  if (sharedEmpty) {
    plane = await startIsolatedPlane({ serve: true });
    if (!plane) { console.error("BLOCKED: registry is empty and target/debug/hypervisor-daemon is not built for the isolated fixture lane"); process.exit(2); }
    SERVE_D = plane.serveUrl; DAEMON_D = plane.daemonUrl;
    const jp = (p, body) => fetch(`${DAEMON_D}${p}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json()).catch(() => ({}));
    const onto = await jp("/v1/hypervisor/odk/domain-ontologies", { domain: "widgets-parity-fixture" });
    const oref = onto && onto.ontology && (onto.ontology.ref || (onto.ontology.id ? `ontology://${onto.ontology.id}` : ""));
    const sdRes = await jp("/v1/hypervisor/odk/surface-descriptors", { name: "widgets-parity-fixture-set", composition_pattern: "list_detail", ontology_ref: oref || "" });
    // NON-VACUITY: the fixture lane must actually register a descriptor — a silent fixture
    // failure would let every registry cross-check pass against an empty plane.
    if (!sdRes || !sdRes.surface_descriptor || !sdRes.surface_descriptor.id) { console.error("BLOCKED: the isolated fixture ladder failed to register a descriptor: " + JSON.stringify(sdRes).slice(0, 200)); await plane.stop(); process.exit(2); }
  }
  const jd = (p) => fetch(`${DAEMON_D}${p}`).then((r) => r.json()).catch(() => ({}));
  const descriptors = ((await jd("/v1/hypervisor/odk/surface-descriptors")).surface_descriptors) || [];

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  const row = bySlug.widgets;
  ok("matrix: widgets is daemon_wired at /__ioi/developer-console/widgets (Developer Console) with landing-IA landmarks", row && row.parity_class === "daemon_wired" && row.candidate_surface === "/__ioi/developer-console/widgets" && row.surface_name === "Developer Console" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the reference is ORIGIN-ALIGNED (reference_url_override → localhost:9225/workspace/custom-widgets/)", row && row.reference_url_override === "http://localhost:9225/workspace/custom-widgets/");
  ok("the estate census accepts widgets among the certified daemon_wired surfaces (>= 15); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 15 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 0b. Certification is REAL, committed, non-pinned, SHELL-scoped.
  let cert = null, certRaw = "";
  try { certRaw = readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8"); cert = JSON.parse(certRaw); } catch { /* */ }
  ok("matrix: widgets is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/widgets.json" && row.parity_class === "daemon_wired");
  ok("the committed certification is REAL: widgets slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "widgets" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
  ok("the certification passed the visual gates on BOTH viewports (theme + structure + landmarks, both sides valid, against the ORIGIN reference)", cert && cert.reference_url === "http://localhost:9225/workspace/custom-widgets/" && cert.viewports.every((v) => v.gates && v.gates.theme_match && v.gates.structural_parity && !v.gates.reference_errored && !v.gates.ioi_errored && v.gates.landmark_covered === v.gates.landmark_applicable));
  ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (descriptor rows are the masked live data, verified semantically below)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));

  // 0c. Sweep contract.
  let sweep = null;
  try { sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* */ }
  const sw = sweep && (sweep.seeds || []).find((s) => s.slug === "widgets");
  ok("clean sweep: widgets classifies data_clean on the aligned (origin/override) lane, with real data evidence", sw && sw.clean_state === "data_clean" && ["origin", "override"].includes(sw.lane_used) && (sw.data_evidence?.table_rows > 0 || sw.data_evidence?.cards > 0), sw ? `${sw.clean_state} via ${sw.lane_used}` : "sweep row missing");
  ok("clean sweep: the proxy-lane no-data blocker stays documented (evidence, not hidden)", sw && (sw.lanes_summary || []).some((l) => l.lane === "proxy" && (l.data_score || 0) < 3), sw ? JSON.stringify((sw.lanes_summary || []).map((l) => `${l.lane}:score${l.data_score}`)) : "");

  // 1. Reference lanes.
  const origin = await page("http://localhost:9225/workspace/custom-widgets/");
  ok("origin-aligned reference serves the Custom Widgets workspace (valid; data-bearing per sweep + cert gates)", origin.status === 200 && /Custom Widgets|custom-widgets/.test(origin.text));
  const ref = await page(`${SERVE}/__apps/widgets`);
  ok("the /__apps/widgets proxy lane still serves (kept as the familiar baseline; documented insufficient — never silently removed)", ref.status === 200);

  // 2. The PORT = the faithful landing shell over the real registry.
  const sp = await page(`${SERVE_D}/__ioi/developer-console/widgets`);
  const t = sp.text;
  ok("the port renders the faithful Custom Widgets landing shell (topbar + band + View pills + table + catalog)", sp.status === 200 && /class="wg-htitle">Custom Widgets</.test(t) && /Develop custom frontend widgets for use within Foundry applications\./.test(t) && /class="wg-thead"/.test(t) && /id="widgets-catalog"/.test(t));
  ok("all matrix reference landmarks render on the port", (row.reference_landmarks || []).every((l) => t.toLowerCase().includes(String(l).toLowerCase())), (row.reference_landmarks || []).filter((l) => !t.toLowerCase().includes(String(l).toLowerCase())).join(" · ") || `${(row.reference_landmarks || []).length}/${(row.reference_landmarks || []).length}`);

  // 3. REGISTRY CROSS-CHECKS (against whichever plane the dynamic render reads).
  ok("the registered-widget-sets count equals the daemon registry", new RegExp(`Registered widget sets <span class="wg-count">${descriptors.length}</span>`).test(t), `registry=${descriptors.length}`);
  ok("rendered rows equal the registry after the declared cap (newest 12)", (t.match(/class="wg-row"/g) || []).length === Math.min(12, descriptors.length), `${(t.match(/class="wg-row"/g) || []).length} rows vs ${Math.min(12, descriptors.length)}`);
  const newest = [...descriptors].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0];
  ok("a REGISTERED descriptor renders: name + ref + composition pattern + ontology binding", !newest || (t.includes(newest.name) && t.includes(newest.ref || newest.id) && t.includes(newest.composition_pattern || "?") && (!newest.ontology_ref || t.includes(newest.ontology_ref))), newest ? newest.ref : "registry empty (fixture lane proves rendering)");
  ok("creator / last-edited-by / last-viewed columns are HONEST em-dashes (no principal or view tracking on the registry)", descriptors.length === 0 || ((t.match(/class="wg-dash"/g) || []).length === 3 * Math.min(12, descriptors.length) && /No registering principal is recorded/.test(t) && /View tracking is not recorded/.test(t)));
  // The SHARED estate's honest empty state (only meaningful when the real registry is empty).
  if (sharedEmpty) {
    const shared = await page(`${SERVE}/__ioi/developer-console/widgets`);
    ok("the SHARED estate's empty registry renders the honest empty state (nothing invented)", /No widget sets registered/.test(shared.text) && /never fabricates rows/.test(shared.text));
  } else {
    ok("the populated registry declares its cap honestly", /newest 12 shown above/.test(t));
  }

  // 4. READ-ONLY — the registration boundary.
  ok("the render carries NO form and no mutation affordance", !/<form/.test(t) && !/method="post"/i.test(t));
  ok("New widget set ROUTES to the ODK dev kit (where descriptor-create authority lives — a link, not a mutation here)", /<a class="wg-hbtn success" href="\/__ioi\/odk"/.test(t) && /mutates nothing/.test(t));
  ok("the registration boundary is declared in place (ontology-bound descriptor records; NO generated UI artifact)", /surface descriptor/i.test(t) && /requires a declared ontology binding/.test(t) && /NO generated UI artifact/.test(t));
  ok("the reference's dev-kit fork + unbound lanes stay NAMED GAPS (build-in-env vs external SDK/CLI · Favorites · Help · principal/view tracking)", /build-in-environment vs scaffold-externally/.test(t) && /generated SDK\/CLI/.test(t) && (t.match(/aria-disabled="true"/g) || []).length >= 2, `${(t.match(/aria-disabled="true"/g) || []).length} disabled controls`);

  // 5. Owner discoverability + brand.
  const cx = await page(`${SERVE_D}/__ioi/connections`);
  ok("owner discoverability: the Connections cockpit (Developer Console) links the registry first-class, and the port links Connections + ODK back", cx.status === 200 && cx.text.includes("/__ioi/developer-console/widgets") && t.includes('href="/__ioi/connections"') && t.includes('href="/__ioi/odk"'));
  ok("the origin-aligned reference + the insufficient proxy lane are BOTH linked and explained on the surface", t.includes("http://localhost:9225/workspace/custom-widgets/") && t.includes("/__apps/widgets") && /renders no data/.test(t));
  ok("IOI surface brand-clean (no Palantir)", !/\bPalantir\b/.test(t));

  if (plane) await plane.stop();
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-widgets readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
