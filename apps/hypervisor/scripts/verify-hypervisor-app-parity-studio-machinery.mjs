#!/usr/bin/env node
// Application UX Parity Baseline — Studio · Machinery done-bar (machinery seed only).
//
// The parity phase's tenth surface, and a deliberate INERT-CONTRACT cut (definition-only). The
// reference capture (/__apps/machinery) is the familiar process/state-machine graph builder; the
// IOI-owned /__ioi/studio/machinery renders the SAME grammar as a READ-ONLY view over a NEW inert
// daemon state-machine DEFINITION plane — declared states (initial/normal/final), transitions
// (from→to, event, guard), guards, declared inputs/outputs, owners, health (empty|incomplete|ready),
// and edit history. Nothing runs: no run/step/execute, no current-state, no scheduling, no binding to
// Automations/Missions/ODK — that is a later authority-crossing cut.
//
// SCOPE (tight, by direction): only `machinery` binds; `workshop` + `module` stay reference_capture.
//
// Guard: exercise the daemon contract's fail-closed write lanes with malformed fixtures, prove there
// is NO execution surface, and cross-check the read-only Studio surface against a real definition.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-studio-machinery.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));

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

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix binds machinery as substrate_bound → /__ioi/studio/machinery (Studio)", bySlug.machinery?.parity_class === "substrate_bound" && bySlug.machinery?.substrate_surface === "/__ioi/studio/machinery" && bySlug.machinery?.surface_name === "Studio");
  ok("matrix keeps workshop + module reference_capture (NOT over-claimed in this cut)", bySlug.workshop?.parity_class === "reference_capture" && bySlug.module?.parity_class === "reference_capture");
  ok("no 'covered' anywhere; prior substrate_bound surfaces intact (9)", !(matrix.seeds || []).some((s) => s.parity_class === "covered") && ["pipeline", "lineage", "vertex", "jobs", "incidents", "evalsuites", "designer", "approvals", "models"].every((k) => bySlug[k]?.parity_class === "substrate_bound"));

  // 1. Reference baseline.
  const ref = await page(`${SERVE}/__apps/machinery`);
  ok("reference baseline /__apps/machinery boots the process/state-machine grammar", ref.status === 200 && /machinery|state machine|process|workflow/i.test(ref.text));

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

  // 5. IOI surface = read-only definition view over real truth (cross-checked).
  const mp = await page(`${SERVE}/__ioi/studio/machinery?machine=${encodeURIComponent(ready?.id)}`);
  const t = mp.text;
  ok("IOI /__ioi/studio/machinery renders the definition grammar (title + states + transitions panes)", mp.status === 200 && /<h1[^>]*>Machinery/.test(t) && /id="machinery-states"/.test(t) && /id="machinery-transitions"/.test(t));
  ok("the real machine renders its states with kinds (initial/final), transitions (from→to), guard, and ready health", t.includes("parity-ready") && t.includes(">new<") && />initial</.test(t) && />final</.test(t) && t.includes(">go<") && t.includes("Guard One") && />ready</.test(t));
  ok("the surface is READ-ONLY with NO run affordance (no run/step form, explicit 'no run affordance')", /no run affordance/.test(t) && !/action="[^"]*\/(run|step|execute)"/.test(t) && !/current[_ ]state/i.test(t));

  // 6. Honest empty/incomplete — no fabrication.
  const et = (await page(`${SERVE}/__ioi/studio/machinery?machine=${encodeURIComponent(empty?.id)}`)).text;
  ok("honest empty: a machine with no states renders 'no states' (health empty), not invented states", />empty</.test(et) && /no states/i.test(et));
  const it = (await page(`${SERVE}/__ioi/studio/machinery?machine=${encodeURIComponent(incomplete?.id)}`)).text;
  ok("honest incomplete: an initial-only machine shows incomplete + no transitions (no fabrication)", />incomplete</.test(it) && /No transitions declared yet/.test(it));

  // 7. Named gaps + siblings reference-only + brand-clean.
  ok("named gaps: execution / stepping / scheduling / Automations-Missions-ODK binding / canvas / simulation", /execution \/ stepping/.test(t) && /scheduling/.test(t) && /Automations \/ Missions \/ ODK/.test(t) && /graph authoring/.test(t) && /simulation/.test(t));
  ok("sibling Studio seeds named reference-only (workshop + module builders)", t.includes("/__apps/workshop") && t.includes("/__apps/module"));
  ok("reference capture linked as secondary; IOI surface brand-clean (no Palantir)", t.includes("/__apps/machinery") && !/\bPalantir\b/.test(t));

  // 8. Owner discoverability — Agent Studio links Machinery, and Machinery links back.
  const asPage = await page(`${SERVE}/__ioi/agent-studio`);
  ok("owner discoverability: Agent Studio links /__ioi/studio/machinery, and Machinery links back to the owner", asPage.status === 200 && asPage.text.includes("/__ioi/studio/machinery") && t.includes("/__ioi/agent-studio"));

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
