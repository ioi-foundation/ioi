#!/usr/bin/env node
// PIXEL-CERTIFIED PARITY verifier — Studio · Machinery done-bar (#50, machinery seed only).
//
// The NINTH faithful port and the SECOND from the origin-alignment queue. The #44 sweep proved the
// machinery reference data-bearing on the capture-origin lane (localhost:9225/workspace/machinery-app/)
// while the /__apps/machinery proxy lane fails its Marketplace-examples fetch; #50 stamps
// reference_url_override onto the honest lane, REBUILDS /__ioi/studio/machinery in place as the
// faithful light Machinery landing shell, and certifies shell-pixel parity against it.
//
// THE SEMANTIC BOUNDARY IS THE POINT OF THIS VERIFIER: the certified shell is a LANDING over the
// #30 INERT state-machine DEFINITION plane — definitions, never execution. Every pre-port guard is
// KEPT: the 16 fail-closed write lanes, health honesty (empty|incomplete|ready incl. self-loop +
// reachability), the no-run/step-endpoint proof, and honest empty/incomplete rendering. On top,
// the pixel-wave contract: origin-aligned valid reference, proxy blocker documented, REAL committed
// NON-pinned certification, landmarks, census floor (>= 9), and NO body pixel claim.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-studio-machinery.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/state-machines/overview`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon state-machine plane not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  const track = (id) => { if (id) cleanup.push(id); };

  // 0. Matrix current + honest: daemon_wired, origin-aligned, landmark-pinned, census floor.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  const row = bySlug.machinery;
  ok("matrix: machinery is daemon_wired at /__ioi/studio/machinery (Studio) with Machinery-IA landmarks", row && row.parity_class === "daemon_wired" && row.candidate_surface === "/__ioi/studio/machinery" && row.surface_name === "Studio" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the reference is ORIGIN-ALIGNED (reference_url_override → localhost:9225/workspace/machinery-app/)", row && row.reference_url_override === "http://localhost:9225/workspace/machinery-app/");
  ok("matrix keeps workshop + module reference_capture (NOT over-claimed in this cut)", bySlug.workshop?.parity_class === "reference_capture" && bySlug.module?.parity_class === "reference_capture");
  ok("the estate census accepts machinery among the certified daemon_wired surfaces (>= 9 since #50); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 9 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 0b. Shell-pixel certification is REAL, committed, non-pinned, SHELL-scoped.
  let cert = null;
  try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
  ok("matrix: machinery is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/machinery.json" && row.parity_class === "daemon_wired");
  ok("the committed certification is REAL: machinery slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "machinery" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
  ok("the certification passed the visual gates on BOTH viewports (theme + structure + landmarks 10/10, both sides valid, against the ORIGIN reference)", cert && cert.reference_url === "http://localhost:9225/workspace/machinery-app/" && cert.viewports.every((v) => v.gates && v.gates.theme_match && v.gates.structural_parity && !v.gates.reference_errored && !v.gates.ioi_errored && v.gates.landmark_covered === v.gates.landmark_applicable));
  ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (machine rows are the masked live data, verified semantically below)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));

  // 0c. Sweep contract: data_clean on the aligned lane; the proxy blocker stays documented.
  let sweep = null;
  try { sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* */ }
  const sw = sweep && (sweep.seeds || []).find((s) => s.slug === "machinery");
  ok("clean sweep: machinery classifies data_clean on the aligned (origin/override) lane, with real data evidence", sw && sw.clean_state === "data_clean" && ["origin", "override"].includes(sw.lane_used) && (sw.data_evidence?.table_rows > 0 || sw.data_evidence?.cards > 0), sw ? `${sw.clean_state} via ${sw.lane_used}` : "sweep row missing");
  ok("clean sweep: the proxy lane stays recorded (the Marketplace-examples failure lane is evidence, not hidden)", sw && (sw.lanes_summary || []).some((l) => l.lane === "proxy"), sw ? JSON.stringify((sw.lanes_summary || []).map((l) => l.lane)) : "");

  // 1. Reference lanes: the ORIGIN lane renders the data-bearing landing; the proxy lane still serves.
  const origin = await page("http://localhost:9225/workspace/machinery-app/");
  ok("origin-aligned reference renders the Machinery landing (valid, data-bearing)", origin.status === 200 && /Machinery/.test(origin.text));
  const ref = await page(`${SERVE}/__apps/machinery`);
  ok("the /__apps/machinery proxy lane still serves (kept as the familiar baseline; documented insufficient — never silently removed)", ref.status === 200 && /machinery|state machine|process|workflow/i.test(ref.text));

  // 2. INERT CONTRACT — fail-closed write lanes (each malformed definition rejected with a typed code).
  const C = (body) => jd("POST", "/v1/hypervisor/state-machines", body);
  const S = (id, kind) => ({ id, kind });
  const lanes = [
    ["missing name", { states: [S("a", "initial")] }, "state_machine_name_required"],
    ["invalid state id shape", { name: "x", states: [{ id: "A", kind: "initial" }] }, "state_machine_state_id_invalid"],
    ["duplicate state id", { name: "x", states: [S("a", "initial"), S("a", "final")] }, "state_machine_duplicate_state_id"],
    ["no initial state", { name: "x", states: [S("a", "normal")] }, "state_machine_no_initial_state"],
    ["multiple initial states", { name: "x", states: [S("a", "initial"), S("b", "initial")] }, "state_machine_multiple_initial_states"],
    ["invalid state kind", { name: "x", states: [{ id: "a", kind: "weird" }] }, "state_machine_state_kind_invalid"],
    ["transition end unresolved", { name: "x", states: [S("a", "initial")], transitions: [{ id: "t", from: "a", to: "ghost" }] }, "state_machine_transition_end_unresolved"],
    ["duplicate transition id", { name: "x", states: [S("a", "initial"), S("b", "final")], transitions: [{ id: "t", from: "a", to: "b" }, { id: "t", from: "b", to: "a" }] }, "state_machine_duplicate_transition_id"],
    ["guard ref unresolved", { name: "x", states: [S("a", "initial"), S("b", "final")], transitions: [{ id: "t", from: "a", to: "b", guard_ref: "missing" }] }, "state_machine_guard_unresolved"],
    ["malformed owner ref", { name: "x", states: [S("a", "initial")], owner_refs: ["not-a-ref"] }, "state_machine_owner_ref_invalid"],
    // Adversarial-hardening lanes (found by the inert-contract review): a non-string kind must be
    // REJECTED, not silently coerced; ids are length-bounded; ports are non-empty.
    ["non-string state kind (must reject, not coerce to normal)", { name: "x", states: [S("a", "initial"), { id: "b", kind: ["final"] }] }, "state_machine_state_kind_invalid"],
    ["oversized state id (length bound)", { name: "x", states: [{ id: "a".repeat(200), kind: "initial" }] }, "state_machine_state_id_invalid"],
    ["empty input port", { name: "x", states: [S("a", "initial")], inputs: ["", "ok"] }, "state_machine_inputs_invalid"],
    ["non-string guard_ref (must reject, not silently drop the guard)", { name: "x", states: [S("a", "initial"), S("b", "final")], transitions: [{ id: "t", from: "a", to: "b", guard_ref: ["g1"] }], guards: [{ id: "g1", name: "ok" }] }, "state_machine_guard_ref_invalid"],
    ["oversized free text (guard expression)", { name: "x", states: [S("a", "initial")], guards: [{ id: "g1", expression: "x".repeat(5000) }] }, "state_machine_guard_field_invalid"],
    ["non-string free text (transition event)", { name: "x", states: [S("a", "initial"), S("b", "final")], transitions: [{ id: "t", from: "a", to: "b", event: { x: 1 } }] }, "state_machine_transition_field_invalid"],
  ];
  let laneFails = 0, laneDetail = "";
  for (const [label, body, code] of lanes) {
    const r = await C(body);
    const good = r.status === 400 && r.j.error?.code === code;
    if (!good) { laneFails++; laneDetail += `${label}(${r.status}/${r.j.error?.code || "?"}) `; }
  }
  ok(`fail-closed write lanes: all ${lanes.length} malformed definitions rejected with their typed code`, laneFails === 0, laneDetail.trim());

  // 3. Valid definitions — health honesty (empty | incomplete | ready).
  const ready = (await C({ name: "parity-ready", states: [S("new", "initial"), S("mid", "normal"), S("done", "final")], transitions: [{ id: "go", from: "new", to: "mid", event: "e", guard_ref: "g1" }, { id: "fin", from: "mid", to: "done" }], guards: [{ id: "g1", name: "Guard One" }], inputs: ["in1"], outputs: ["out1"], owner_refs: ["agent://ops"] })).j.state_machine;
  track(ready?.id);
  const incomplete = (await C({ name: "parity-incomplete", states: [S("only", "initial")] })).j.state_machine;
  track(incomplete?.id);
  const empty = (await C({ name: "parity-empty" })).j.state_machine;
  track(empty?.id);
  ok("health honesty: ready (initial + transition/final) · incomplete (initial only) · empty (no states)", ready?.health === "ready" && incomplete?.health === "incomplete" && empty?.health === "empty", `${ready?.health}/${incomplete?.health}/${empty?.health}`);
  const selfLoop = (await C({ name: "parity-selfloop", states: [S("a", "initial")], transitions: [{ id: "t", from: "a", to: "a" }] })).j.state_machine;
  track(selfLoop?.id);
  ok("health honesty: a PURE self-loop stays incomplete (a transition to nowhere-new never overstates 'ready')", selfLoop?.health === "incomplete", selfLoop?.health);
  // Reachability: a declared final that the initial state cannot reach must NOT make the machine ready.
  const unreachable = (await C({ name: "parity-unreachable", states: [S("a", "initial"), S("b", "normal"), S("c", "final")], transitions: [{ id: "t", from: "a", to: "b" }] })).j.state_machine;
  track(unreachable?.id);
  ok("health honesty: an UNREACHABLE final state does NOT make a machine 'ready' (reachability is checked)", unreachable?.health === "incomplete", unreachable?.health);
  const disconnectedFinal = (await C({ name: "parity-disconnected", states: [S("a", "initial"), S("z", "final")] })).j.state_machine;
  track(disconnectedFinal?.id);
  ok("health honesty: initial + a disconnected final (no transition) is incomplete, not ready", disconnectedFinal?.health === "incomplete", disconnectedFinal?.health);
  ok("status is always draft (inert); the record carries NO run/current-state/instance field", ready?.status === "draft" && !("current_state" in (ready || {})) && !("running" in (ready || {})) && !("instance" in (ready || {})) && !("run" in (ready || {})));

  // 4. NO EXECUTION endpoint (definition-only).
  const runAttempt = await jd("POST", `/v1/hypervisor/state-machines/${ready?.id}/run`, {});
  const stepAttempt = await jd("POST", `/v1/hypervisor/state-machines/${ready?.id}/step`, {});
  ok("there is NO run/step endpoint (a definition never executes here)", runAttempt.status >= 400 && stepAttempt.status >= 400, `run ${runAttempt.status} · step ${stepAttempt.status}`);

  // 5. The PORT = the faithful landing shell over real definition truth (cross-checked).
  const mp = await page(`${SERVE}/__ioi/studio/machinery?machine=${encodeURIComponent(ready?.id)}`);
  const t = mp.text;
  ok("the port renders the faithful Machinery landing shell (header + hero + View row + table + examples band + truth band)", mp.status === 200 && /class="mch-htitle">Machinery</.test(t) && /Build, manage and monitor your business processes/.test(t) && /class="mch-viewrow"/.test(t) && /class="mch-thead"/.test(t) && /Explore reference examples/.test(t) && /id="machinery-truth"/.test(t) && /id="machinery-states"/.test(t) && /id="machinery-transitions"/.test(t));
  ok("all matrix reference landmarks render on the port", (row.reference_landmarks || []).every((l) => t.toLowerCase().includes(String(l).toLowerCase())), (row.reference_landmarks || []).filter((l) => !t.toLowerCase().includes(String(l).toLowerCase())).join(" · ") || "10/10");
  ok("the fixture machine renders as a live FILE ROW (name + ref + declared census + health/status in the row path)", /class="mch-row"/.test(t) && t.includes("parity-ready") && t.includes(ready.ref) && /states · \d+ transitions · \d+ guards · ready · draft/.test(t));
  ok("live cross-check: rendered machine rows equal the daemon records (count + a real ref renders)", (() => { const rows = (t.match(/class="mch-row"/g) || []).length; return rows > 0 && t.includes(ready.ref); })(), `${(t.match(/class="mch-row"/g) || []).length} rows rendered`);
  ok("CREATOR renders the DECLARED owner_refs[0] honestly (a declaration, not an execution principal); edit/view principals stay em-dashes naming the gap", t.includes("agent://ops") && /No edit principal is recorded on the definition history \(named gap\)/.test(t) && /View tracking is not recorded on the state-machine plane \(named gap\)/.test(t));
  ok("the real machine renders its states with kinds (initial/final), transitions (from→to + event + guard), guards, I/O and owners from real records", t.includes(">new<") && />initial</.test(t) && />final</.test(t) && t.includes(">go<") && t.includes("new → mid") && t.includes("Guard One") && t.includes("in1") && t.includes("out1") && /health ready/.test(t));
  ok("the daemon's own authority_note renders VERBATIM (inert definition — no run/step/execution, no scheduling, no automation binding)", /inert definition — no run\/step\/execution, no scheduling, no automation binding/.test(t));

  // 6. THE HARD BOUNDARY — definitions only, no execution semantics anywhere on the surface.
  ok("the surface is READ-ONLY with NO execution affordance (no run/step/execute form, no current-state value, definitions-not-processes named)", !/action="[^"]*\/(run|step|execute)"/.test(t) && /definitions, not running processes/.test(t) && !/current_state/.test(t));
  ok("named gaps: run/step/execute · scheduling · Automations/Missions/ODK binding · simulation · versioning · graph authoring", /run\/step\/execute/.test(t) && /scheduling/.test(t) && /Automations\/Missions\/ODK binding/.test(t) && /simulation/.test(t) && /versioning/.test(t) && /Graph authoring is a reference-only lane/.test(t));
  ok("unsupported controls are DISABLED IN PLACE with named-gap titles (store dropdown · New graph · Help · Favorites · example-card overlays)", (t.match(/aria-disabled="true"/g) || []).length >= 6 && /Recent installations — marketplace install lanes/.test(t) && /Graph authoring is a reference-only lane/.test(t) && /Favorites are not recorded on the state-machine plane/.test(t) && /Marketplace example installs are a reference-only lane/.test(t), `${(t.match(/aria-disabled="true"/g) || []).length} disabled controls`);
  ok("the examples band is declared verbatim capture chrome (vendor examples, never estate process truth)", /verbatim capture chrome/.test(t) && /not estate process truth/.test(t));

  // 7. Honest empty/incomplete — no fabrication.
  const et = (await page(`${SERVE}/__ioi/studio/machinery?machine=${encodeURIComponent(empty?.id)}`)).text;
  ok("honest empty: a machine with no states renders 'no states' (health empty), not invented states", /health empty/.test(et) && /no states/i.test(et));
  const it = (await page(`${SERVE}/__ioi/studio/machinery?machine=${encodeURIComponent(incomplete?.id)}`)).text;
  ok("honest incomplete: an initial-only machine shows incomplete + no transitions (no fabrication)", /health incomplete/.test(it) && /No transitions declared yet/.test(it));

  // 8. Discoverability + brand.
  ok("sibling Studio seeds named reference-only (workshop + module builders) + Designer linked first-class", t.includes("/__apps/workshop") && t.includes("/__apps/module") && t.includes("/__ioi/studio/designer"));
  const asPage = await page(`${SERVE}/__ioi/agent-studio`);
  ok("owner discoverability: Agent Studio links /__ioi/studio/machinery, and Machinery links back to the owner", asPage.status === 200 && asPage.text.includes("/__ioi/studio/machinery") && t.includes("/__ioi/agent-studio"));
  ok("the origin-aligned reference + the insufficient proxy lane are BOTH linked and explained on the surface", t.includes("http://localhost:9225/workspace/machinery-app/") && t.includes("/__apps/machinery") && /Marketplace-examples fetch fails/.test(t));
  ok("IOI surface brand-clean (no Palantir)", !/\bPalantir\b/.test(t));

  // 9. Cleanup.
  for (const id of cleanup) await jd("DELETE", `/v1/hypervisor/state-machines/${id}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-studio-machinery readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
