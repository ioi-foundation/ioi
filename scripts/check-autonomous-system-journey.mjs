#!/usr/bin/env node
// check:autonomous-system-journey — the owner's done-bar: ONE System taken through its whole lifecycle
// THROUGH THE UI (R-240, ADR 0056; .artifacts/mvp-finish-line/journey-gap-map-2026-09-25.md).
//
// WHY THIS EXISTS. Every per-surface gate is right about its own surface. None of them can see the seams
// between steps, and the gap map found the central one by reading: there was no System to hand work to.
// The daemon published seven mode routes per System and the serve answered them with the generic shell;
// blueprints carry no system_ref; session create hard-codes subject_attachments: []; the package
// registry's releases are not the release genesis takes. A lifecycle made of eleven green surfaces and
// ten dead hand-offs is not a lifecycle.
//
// WHAT IT DOES. It walks ONE System (one tag) through the eleven steps the gap map names — create,
// design, data, limits, run, observe, provenance, evaluate, improve, release, operate — and judges every
// step PASS, NAMED_GAP (by code, naming the missing plane) or FAIL, and every hand-off by step N's object
// appearing as an option or a link in step N+1's form. It OWNS its plane: a fresh data directory, its own
// daemon and serve on free ports with the sign-in gate on, the REAL wallet.network fixture as the
// authority, and an operator bootstrapped with the daemon's one-boot token through the serve's first-run
// form. Every write goes through a form the owning surface rendered, found on the page before it is
// submitted. It COMPOSES the existing gates (it does not re-prove them) and ends with a restart and a
// re-read of the System.
//
//   PURE     — the journey table and the verdict rules (apps/hypervisor/scripts/lib/autonomous-system-journey.mjs)
//   SOURCE   — the LIVE leg owns its plane and operator and writes only through rendered forms (and the
//              one JavaScript surface, the New Session composer, through its rendered controls in a browser)
//   BINDING  — floored, CI-bound in the recognised form, and every composed gate runnable
//   LIVE     — the continuous walk: every step's own legs live or NAMED_GAP, none TODO
//   COMPOSE  — the existing gates, run in this invocation on one basis
//
//   --drills        CI-bound, seconds: PURE, SOURCE, BINDING, the verdict rules. No daemon, no browser.
//   --mutation      planted defects against the journey rules — each must go red.
//   --no-compose    the drills and the LIVE walk; composed legs report UNMEASURED (never a pass).
//   --compose=a,b   run only the named composed gates; the rest report UNMEASURED.
//   (default)       the drills, the LIVE walk, then COMPOSE. Exit 0 all eleven steps PASS · 2 journey
//                   incomplete (any NAMED_GAP, TODO or UNMEASURED leg) · 1 FAIL.

import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/autonomous-system-journey.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = path.join(ROOT, "apps", "hypervisor");
const FLOORS = path.join(APP, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP, "scripts", "lib", "autonomous-system-journey.mjs");
const SELF_PATH = fileURLToPath(import.meta.url);
const FIXTURES = path.join(ROOT, "docs", "architecture", "_meta", "schemas", "fixtures");

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const NO_COMPOSE = flag("--no-compose");
const ONLY = (() => { const a = argv.find((x) => x.startsWith("--compose=")); return a ? new Set(a.slice("--compose=".length).split(",").filter(Boolean)) : null; })();

const self = (n) => ({ kind: "self", script: `${n} (this runner)` });
const PURE = self("pure");
const SOURCE = self("source");
const LIVE = self("live");
const COMPOSED = self("compose");

export const CLAUSES = [
  { n: 1, demand: "THE LIFECYCLE WORKS THROUGH THE UI, AS ONE CONTINUOUS WALK. One tag, one System, created by governed genesis and carried through the eleven steps the gap map names — create, design, data, limits, run, observe, provenance, evaluate, improve, release, operate. Each step is PASS, NAMED_GAP or FAIL, and the gate passes only when all eleven PASS", executed_by: [PURE, LIVE, COMPOSED] },
  { n: 2, demand: "EVERY HAND-OFF IS JUDGED. Step N's object must appear as an option or a link in step N+1's form; a step whose hand-off is not judged is red, never skipped. The last step hands off to nothing: the walk ends with a restart and a re-read of the System", executed_by: [PURE, LIVE] },
  { n: 3, demand: "A NAMED GAP IS NEVER A PASS. Any NAMED_GAP step exits 2, \"journey incomplete\"; a gap that reports pass is fabricated and red; a gap the product no longer names is stale and red. Closing a gap flips its row to a live leg with its own assertion, in the same cut that removes it from REQUIRED_GAPS", executed_by: [PURE, LIVE] },
  { n: 4, demand: "EVERY WRITE GOES THROUGH THE FORM ITS OWNING SURFACE RENDERS — found on the rendered page before it is submitted, never the daemon API; a JavaScript surface (the New Session composer) is driven in a browser as the same operator through the controls the page rendered — and authority is a real wallet.network grant for the exact hashes the surface rendered", executed_by: [SOURCE, LIVE] },
  { n: 5, demand: "THE GATE OWNS ITS DAEMON, ITS SERVE AND ITS OPERATOR: a fresh data directory, free ports, the sign-in gate on, the real wallet.network fixture, an operator bootstrapped with the daemon's one-boot token through the serve's first-run form. The owner's data is never read or written, and no shared serve can answer for it", executed_by: [SOURCE, LIVE] },
  { n: 6, demand: "COMPOSED, NOT RE-PROVEN. A leg passes by composition only when the named gate ran green in this invocation on an unmoved basis; not executed, exit 2, a timeout or a moved basis is never a pass", executed_by: [PURE, COMPOSED] },
  { n: 7, demand: "EVERY PASS NAMES ITS EVIDENCE — the live assertion that measured it or the composed gate whose run proved it — and a leg the walk never reached is red, never read as green", executed_by: [PURE, LIVE] },
];

// ---- what the gate holds, not the table ----------------------------------------------------------
// A table that quietly drops a step, a gap, a probe, a live leg or a composed gate still reads clean
// against its own rules, so the sets it must cover are pinned HERE (the propagation gate's lesson:
// its mutation 8 survived until the required consumers moved out of the matrix).
export const REQUIRED_STEPS = Object.freeze(["create", "design", "data", "limits", "run", "observe", "provenance", "evaluate", "improve", "release", "operate"]);

// The gap map's named gaps, each at the leg that owns it. Closing one is a deliberate edit here.
export const REQUIRED_GAPS = Object.freeze({
  "create/legs/template-picker": "system_template_picker_absent",
  "create/legs/approval-in-inbox": "genesis_approval_not_in_inbox",
  // WP-C1 (2026-09-28): blueprint_system_ref_absent and system_data_attachment_absent are closed —
  // their four rows are live legs (REQUIRED_LIVE).
  "limits/legs/limits": "system_limits_authority_node_absent",
  // Journey TODO legs (2026-09-29): the lease half of hand-off 4→5 waits on the same authority node;
  // the withheld half is live (unleased-connection-withheld).
  "limits/handoff/lease-gates-connection-picker": "system_limits_authority_node_absent",
  // WP-B (2026-09-28): a run satisfies "running THE System"; the SESSION half keeps the code here.
  "run/legs/session-subject-system": "session_system_subject_absent",
  "observe/legs/telemetry": "system_telemetry_absent",
  "evaluate/legs/evaluation-ui": "evaluation_ui_consumer_absent",
  "improve/legs/change-sets": "change_set_blueprint_subject_absent",
  "improve/legs/system-scope": "improvement_system_scope_refused",
  "release/legs/system-release": "system_release_absent",
  "operate/legs/typed-lifecycle": "lifecycle_forms_raw_json",
});

// The gaps the System workspace itself names on the page (system-genesis-surfaces.mjs `namedGap`). The
// walk reads each marker: while it is there the gap is true; when it goes, the row is stale.
export const REQUIRED_PROBES = Object.freeze({
  "limits/legs/limits": 'data-system-named-gap="authority node (ADR 0056 Ruling 8)"',
  // Connections names it on the connection's own card, where Set limits would be.
  "limits/handoff/lease-gates-connection-picker": 'data-ioi-standing-recorder="none"',
  "run/legs/session-subject-system": 'data-system-named-gap="System subject on session create (W3 C-1)"',
  "improve/legs/system-scope": 'data-system-named-gap="System-scoped improvement (ADR 0056 P4 change sets)"',
});

// The legs the walk measures today. Turning one back into a TODO is a regression, not a table edit.
export const REQUIRED_LIVE = Object.freeze([
  "create/legs/genesis-admission",
  "create/legs/governed-ladder",
  "create/handoff/system-links-its-design",
  "design/legs/walk-blueprint",
  "design/handoff/walk-designer-offers-ontology",
  // WP-C1 (2026-09-28): the design and the data bound to the System.
  "create/handoff/system-offered-to-studio",
  "design/legs/design-bound-to-system",
  "design/handoff/design-carries-system-data",
  "data/legs/attach-to-system",
  "data/legs/walk-ontology-and-source",
  "data/legs/walk-function",
  "observe/legs/walk-issue",
  "observe/legs/walk-health",
  "run/legs/walk-automation",
  "run/legs/walk-function-step",
  "run/handoff/walk-run-in-work",
  "limits/legs/walk-checkpoint",
  "limits/handoff/walk-checkpoint-gates-run",
  "observe/handoff/walk-observed-to-receipts",
  "evaluate/legs/walk-suite",
  "release/legs/walk-package",
  "provenance/legs/system-evidence",
  "operate/legs/operate-mode",
  "operate/terminal/restart-reread",
  // WP-B (2026-09-28): runs tied to the System.
  "run/legs/automation-installation",
  "run/legs/run-the-system",
  "run/handoff/run-names-system",
  "observe/legs/issue-subject-system",
  "provenance/legs/ledger-by-system",
  // Journey TODO legs (2026-09-29): the New Session composer, driven in a browser; the unleased
  // connection it withholds.
  "run/legs/walk-session",
  "limits/handoff/unleased-connection-withheld",
  // …and THIS walk's improvement through Agent Studio's own forms.
  "improve/legs/walk-improvement",
]);

// The gap map's "Composes (does not re-prove)" list, plus the two R-240 lanes the walk leans on.
export const REQUIRED_COMPOSED = Object.freeze([
  "system-genesis-product-journey", "studio-journey", "cross-surface-propagation", "packages-journey", "automations-journey",
  "governance-journey", "launch-chain", "systems-work-projections", "system-record-seam", "governed-evaluation-plane",
  "improvement-governance-spine", "receipts-on-demand", "dead-controls", "named-gap-truth", "notification-inbox", "agent-studio-write-lanes",
  "notification-panel",
]);

const results = [];
const evidence = { schema: "ioi.autonomous-system-journey-evidence.v1", mode: MODE, started_at: new Date().toISOString(), tag: null, system_id: null, pure: null, source: null, binding: null, live: null, composed: null, verdict: null, mutation: null };
const STAMP = evidence.started_at.replace(/[:.]/g, "-");
function ok(name, cond, detail) {
  results.push({ name, pass: !!cond, detail: detail || "" });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail && !cond ? ` — ${detail}` : ""}`);
}
function writeEvidence() {
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `autonomous-system-journey-${MODE}-${STAMP}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(readText(p));

// ---- PURE ---------------------------------------------------------------------------------------
// Planted tables and planted runs, small enough to reason about: two steps, one hand-off, one terminal.
const leg = (id, kind, extra = {}) => ({ id, kind, what: "w", judged_by: "j", ...extra });
const mini = (edit = (s) => s) => edit([
  { n: 1, id: "a", title: "A", surface: "/a", legs: [leg("l", "live", { assertion: "A1" })], handoff: { into: "b", legs: [leg("h", "live", { assertion: "A2" })] } },
  { n: 2, id: "b", title: "B", surface: "/b", legs: [leg("l", "composed", { gate: "g" })], terminal: { legs: [leg("t", "live", { assertion: "B2" })] } },
]);
const MINI_COMPOSE = [{ id: "g", pkg: "app", script: "check:g", minutes: 1, proves: "p" }];
const MINI_CLAIMS = Object.freeze({ "a/legs/l": { state: "pass", assertion: "A1" }, "a/handoff/h": { state: "pass", assertion: "A2" }, "b/terminal/t": { state: "pass", assertion: "B2" } });
const MINI_GREEN = Object.freeze({ claims: MINI_CLAIMS, composed: { g: { status: 0 } } });
const withGap = () => mini((s) => { s[0].legs.push({ id: "g", kind: "named_gap", what: "w", gap: { code: "x_absent", plane: "p", source: "s", probe: { route: "/r", marker: "m" } } }); return s; });
const withTodo = () => mini((s) => { s[0].legs.push({ id: "t", kind: "todo", what: "w", write: "x" }); return s; });

export function pureFindings(lib) {
  const f = [];
  const expect = (what, got, want) => { if (got !== want) f.push(`${what}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`); };
  // The table as shipped.
  for (const x of lib.journeyFindings({ journey: lib.JOURNEY, compose: lib.COMPOSE, estate: lib.ESTATE, expectSteps: REQUIRED_STEPS.length })) f.push(`table: ${x}`);
  expect("table/steps", lib.JOURNEY.map((s) => s.id).join(","), REQUIRED_STEPS.join(","));
  const index = lib.legIndex(lib.JOURNEY, lib.ESTATE);
  for (const [key, code] of Object.entries(REQUIRED_GAPS)) {
    const l = index[key];
    if (!l || l.kind !== "named_gap" || l.gap?.code !== code) f.push(`table: the gap map's '${code}' is no longer named at ${key}`);
  }
  for (const [key, marker] of Object.entries(REQUIRED_PROBES)) if (index[key]?.gap?.probe?.marker !== marker) f.push(`table: ${key} no longer probes the workspace's own marker ${marker}`);
  for (const key of REQUIRED_LIVE) if (index[key]?.kind !== "live") f.push(`table: ${key} is no longer a live leg of the walk`);
  const composeIds = new Set(lib.COMPOSE.map((c) => c.id));
  for (const id of REQUIRED_COMPOSED) if (!composeIds.has(id)) f.push(`compose: the gap map's '${id}' is not composed`);

  // The rules, against planted tables.
  const rules = (journey, compose = MINI_COMPOSE) => lib.journeyFindings({ journey, compose });
  expect("rules/clean", rules(mini()).length, 0);
  expect("rules/handoff-missing", rules(mini((s) => { delete s[0].handoff; return s; })).length > 0, true);
  expect("rules/handoff-empty", rules(mini((s) => { s[0].handoff.legs = []; return s; })).length > 0, true);
  expect("rules/handoff-wrong-step", rules(mini((s) => { s[0].handoff.into = "z"; return s; })).length > 0, true);
  expect("rules/handoff-unjudged", rules(mini((s) => { delete s[0].handoff.legs[0].judged_by; return s; })).length > 0, true);
  expect("rules/gap-without-plane", rules(mini((s) => { s[0].legs.push({ id: "g", kind: "named_gap", what: "w", gap: { code: "x_absent", source: "s" } }); return s; })).length > 0, true);
  expect("rules/gap-without-code", rules(mini((s) => { s[0].legs.push({ id: "g", kind: "named_gap", what: "w", gap: { code: "absent", plane: "p", source: "s" } }); return s; })).length > 0, true);
  expect("rules/live-without-assertion", rules(mini((s) => { delete s[0].legs[0].assertion; return s; })).length > 0, true);
  expect("rules/todo-without-write", rules(mini((s) => { s[0].legs.push({ id: "t", kind: "todo", what: "w" }); return s; })).length > 0, true);
  expect("rules/unknown-gate", rules(mini((s) => { s[1].legs[0].gate = "nope"; return s; })).length > 0, true);
  expect("rules/uncited-compose", rules(mini(), [...MINI_COMPOSE, { id: "h", pkg: "app", script: "check:h", minutes: 1, proves: "p" }]).length > 0, true);
  expect("rules/no-terminal", rules(mini((s) => { delete s[1].terminal; return s; })).length > 0, true);
  expect("rules/terminal-not-last", rules(mini((s) => { s[0].terminal = { legs: [leg("x", "live", { assertion: "X" })] }; return s; })).length > 0, true);

  // The verdict, against planted runs.
  const v = (journey, input, estate) => lib.verdict(journey, input, estate);
  const claims = (extra) => ({ ...MINI_GREEN, claims: { ...MINI_CLAIMS, ...extra } });
  expect("verdict/green", v(mini(), MINI_GREEN).exit, 0);
  expect("verdict/green-kind", v(mini(), MINI_GREEN).kind, "pass");
  expect("verdict/gap-exits-2", v(withGap(), MINI_GREEN).exit, 2);
  expect("verdict/gap-is-never-pass", v(withGap(), MINI_GREEN).kind, "named_failure");
  expect("verdict/gap-probe-holds", v(withGap(), claims({ "a/legs/g": { state: "named_gap", probe: "holds" } })).exit, 2);
  expect("verdict/gap-reporting-pass", v(withGap(), claims({ "a/legs/g": { state: "pass" } })).exit, 1);
  expect("verdict/gap-stale-probe", v(withGap(), claims({ "a/legs/g": { state: "named_gap", probe: "stale" } })).exit, 1);
  expect("verdict/todo-exits-2", v(withTodo(), MINI_GREEN).exit, 2);
  expect("verdict/todo-reporting-pass", v(withTodo(), claims({ "a/legs/t": { state: "pass" } })).exit, 1);
  expect("verdict/composed-not-run", v(mini(), { ...MINI_GREEN, composed: {} }).exit, 2);
  expect("verdict/composed-exit-2", v(mini(), { ...MINI_GREEN, composed: { g: { status: 2 } } }).exit, 2);
  expect("verdict/composed-exit-1", v(mini(), { ...MINI_GREEN, composed: { g: { status: 1 } } }).exit, 1);
  expect("verdict/composed-basis-moved", v(mini(), { ...MINI_GREEN, composed: { g: { status: 0, basisMoved: true } } }).exit, 1);
  expect("verdict/composed-timeout", v(mini(), { ...MINI_GREEN, composed: { g: { status: null, timedOut: true } } }).exit, 1);
  expect("verdict/composed-claimed-pass", v(mini(), { claims: { ...MINI_CLAIMS, "b/legs/l": { state: "pass" } }, composed: {} }).exit, 1);
  const { ["b/terminal/t"]: _dropped, ...unreached } = MINI_CLAIMS;
  expect("verdict/live-unreached", v(mini(), { ...MINI_GREEN, claims: unreached }).exit, 1);
  expect("verdict/live-foreign-assertion", v(mini(), claims({ "a/legs/l": { state: "pass", assertion: "something else" } })).exit, 1);
  expect("verdict/live-red", v(mini(), claims({ "a/legs/l": { state: "fail", assertion: "A1", detail: "x" } })).exit, 1);
  expect("verdict/handoff-leg-red", v(mini(), claims({ "a/handoff/h": { state: "fail", assertion: "A2", detail: "x" } })).exit, 1);
  expect("verdict/handoff-unjudged", v(mini((s) => { delete s[0].handoff; return s; }), MINI_GREEN).exit, 1);
  expect("verdict/handoff-empty", v(mini((s) => { s[0].handoff.legs = []; return s; }), MINI_GREEN).exit, 1);
  expect("verdict/no-terminal", v(mini((s) => { delete s[1].terminal; return s; }), MINI_GREEN).exit, 1);
  expect("verdict/evidence-less-pass", v(mini((s) => { s[0].legs[0].assertion = ""; return s; }), claims({ "a/legs/l": { state: "pass", assertion: "" } })).exit, 1);
  expect("verdict/setup-failure", v(mini(), { ...MINI_GREEN, setup: ["x"] }).exit, 1);
  expect("verdict/drill-failure", v(mini(), { ...MINI_GREEN, drills: ["x"] }).exit, 1);
  expect("verdict/fail-dominates-gap", v(withGap(), { ...MINI_GREEN, setup: ["x"] }).exit, 1);
  expect("verdict/estate-not-run", v(mini(), MINI_GREEN, [{ id: "e", kind: "composed", gate: "g2", what: "w" }]).exit, 2);
  expect("fill", lib.fill("/systems/{system}/design?t={tag}&id={system_id}", { system: "acme/x", tag: "t1", system_id: "system://acme/x" }), "/systems/acme/x/design?t=t1&id=system://acme/x");
  expect("keys", Object.keys(lib.legIndex(mini())).sort().join(","), "a/handoff/h,a/legs/l,b/legs/l,b/terminal/t");
  return f;
}

// The real eleven-step table with every leg flipped to a live leg the run measured green: the only way
// the verdict may say PASS.
function flippedGreen(lib) {
  const live = (l) => ({ id: l.id, kind: "live", what: l.what, judged_by: l.judged_by, assertion: `planted:${l.id}` });
  const journey = lib.JOURNEY.map((s) => ({ ...s, legs: s.legs.map(live), handoff: s.handoff && { ...s.handoff, legs: s.handoff.legs.map(live) }, terminal: s.terminal && { legs: s.terminal.legs.map(live) } }));
  const claims = {};
  for (const [key, l] of Object.entries(lib.legIndex(journey))) claims[key] = { state: "pass", assertion: l.assertion };
  return { journey, input: { claims, composed: {} } };
}
// The table AS SHIPPED, with every live leg green, every probe holding and every composed gate green.
function shippedBestCase(lib) {
  const claims = {};
  for (const [key, l] of Object.entries(lib.legIndex(lib.JOURNEY, lib.ESTATE))) {
    if (l.kind === "live") claims[key] = { state: "pass", assertion: l.assertion };
    if (l.kind === "named_gap" && l.gap?.probe) claims[key] = { state: "named_gap", probe: "holds" };
  }
  const composed = Object.fromEntries(lib.COMPOSE.map((c) => [c.id, { status: 0 }]));
  return { claims, composed };
}

// ---- SOURCE -------------------------------------------------------------------------------------
// Every pattern below names ONE exact line of the LIVE or COMPOSE leg and is spelled (escapes, [x]
// classes, {2}) so that it cannot match its own text: a source rule satisfied by the regex that states it
// is a rule that can never fail.
export function sourceFindings({ gate, lib }) {
  const f = [];
  const code = gate.split("\n").filter((l) => !/^\s*\/\//u.test(l)).join("\n");
  if (!/dataDir = fs\.mkdtempSync\(/u.test(code) || !/plane = await startIsolatedPlane\(\{ serve: true, dataDir, env: planeEnv/u.test(code)) f.push("the LIVE leg no longer runs its plane on a FRESH data directory of its own");
  if (!/ctx\.resolver = await startRealWalletNetworkPrincipalAuthorityFixture\(\{/u.test(code)) f.push("the LIVE leg no longer takes authority from the REAL wallet.network fixture");
  if (!/planeEnv = \{ \.\.\.ctx\.resolver\.env, IOI_PRODUCT_SIGNIN_REQUIRED: "[1]" \}/u.test(code)) f.push("the LIVE leg no longer measures the product with its sign-in gate on");
  if (!/action: "\/__ioi\/bootstrap",/u.test(code) || !/match\(\/ioi_bootstrap_\[A-Za-z0-9_-\]\+\/gu\)/u.test(code) || !/fs\.readdirSync\(dataDir\)\.filter\(/u.test(code)) f.push("the LIVE leg no longer bootstraps its own operator through the serve's first-run form with the one-boot token from its own plane's log");
  if (/127\.0\.0\.1:8765|\.ioi\/hypervisor\/data/u.test(code)) f.push("the LIVE leg names the owner's daemon or data directory");
  // ONE write path: submitRenderedForm, the gate's only POST, refuses anything but a /__ioi/ form it found
  // on the rendered page.
  const posts = code.match(/"PO[S]T"/gu) || [];
  if (posts.length !== 1 || !/if \(!action\.startsWith\("\/__ioi\/"\)\)/u.test(code) || !/renderedForm\(page\.text, action\)/u.test(code)) f.push("a write no longer goes only through submitRenderedForm — the one POST, to a /__ioi/ form found on the rendered page");
  if (/"(?:PA[T]CH|P[U]T|DE[L]ETE)"|\bfet[c]h\(/u.test(code)) f.push("the gate carries a write verb or a transport outside its one form submitter");
  // The ONE browser leg (the New Session composer is JavaScript) signs in as THIS gate's operator on its
  // own serve and drives only what the page rendered: it carries no request, route or header of its own.
  if (!/await context\.addCookies\(\[\{ name: ctx\.cookie\.slice\(0, at\), value: ctx\.cookie\.slice\(at \+ 1\), url: ctx\.serve \}\]\);/u.test(code)
    || (code.match(/chromium\.laun[c]h\(/gu) || []).length !== 1) f.push("the browser leg no longer runs one browser signed in as this gate's own operator on its own serve");
  if (/\b(?:tab|context|ctx\.browser)\.request\b|\.route\(|setExtraHTTP[H]eaders|\bgoto\((?!`\$\{ctx\.serve\}\/ai#new-session`)/u.test(code)) f.push("the browser leg carries a request of its own, or navigates anywhere but the plane's own New Session composer");
  if (!/FIXTURE_FREE_ENV = Object\.freeze\(\{ IOI_HYPERVISOR_DAEMON_URL: "{2}/u.test(code) || !/env: \{ \.\.\.process\.env, \.\.\.FIXTURE_FREE_ENV,/u.test(code) || !/basisMoved: now\.head !== start\.head/u.test(code)) f.push("the COMPOSE runner no longer clears the shared-daemon redirection or re-reads the basis after each gate");
  if (/fetch\(|readFileSync|Date\.now\(|new Date\(|document\.|window\.|^\s*import\s/mu.test(lib)) f.push("the journey rules reach a browser, a file, a clock, a network or an import");
  for (const name of ["JOURNEY", "COMPOSE", "ESTATE"]) if (!lib.includes(`export const ${name}`)) f.push(`the journey library no longer names \`${name}\``);
  for (const name of ["verdict", "journeyFindings", "legIndex"]) if (!lib.includes(`export function ${name}(`)) f.push(`the journey library no longer exports \`${name}\``);
  return f;
}

// ---- BINDING ------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate, compose }) {
  const f = [];
  for (const s of ["check:autonomous-system-journey", "mutate:autonomous-system-journey"]) if (!rootPkg.scripts?.[s]) f.push(`root_script_missing:${s}`);
  if (!appPkg.scripts?.["check:autonomous-system-journey"]) f.push("app_drills_script_missing");
  const row = (floors.verifiers ?? []).find((r) => r.id === "autonomous-system-journey");
  if (!row) f.push("floor_row_missing");
  else {
    if (!fs.existsSync(path.join(ROOT, row.source))) f.push(`floor_source_absent:${row.source}`);
    if (!(row.runtime_assertions > 0)) f.push("floor_not_pinned");
  }
  if (!/npm run check:autonomous-system-journey --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("ci_not_bound_in_the_recognised_form");
  if (!/mutate:autonomous-system-journey/u.test(ci)) f.push("ci_mutation_not_bound");
  if (!floorsGate.includes("check-autonomous-system-journey")) f.push("floors_gate_does_not_recognise_this_runner");
  // A composed gate the journey cannot run is a leg that can never pass (the genesis product journey had
  // no npm script when the gap map was written: build order step 0).
  for (const c of compose) {
    const pkg = c.pkg === "root" ? rootPkg : appPkg;
    if (!pkg.scripts?.[c.script]) f.push(`composed_script_missing:${c.pkg}:${c.script}`);
  }
  for (const c of CLAUSES) if (!c.executed_by?.length) f.push(`clause_${c.n}_not_executed`);
  if (CLAUSES.length !== 7) f.push(`clause_count:${CLAUSES.length}`);
  return f;
}

// ---- LIVE: the genesis declaration --------------------------------------------------------------
// EXTRACT BEFORE MERGE: these helpers are verify-hypervisor-system-genesis-product-journey.mjs's own
// (exact JCS hashing over the tracked M1 fixtures); both should import one shared copy.
const SYSTEMS_BASE = "/__ioi/systems";
const GENESIS_API = "/v1/hypervisor/autonomous-systems";
const ATTACHMENT_CONTRACT = "schema://ioi/components/hypervisor/system-data-attachment/v1";
const OWNER = "org://acme/research";
const GENESIS_SCOPE = "scope:autonomous_system.genesis_admit";
const MATERIALIZE_SCOPE = "scope:autonomous_system.genesis_materialize";
const INITIALIZE_SCOPE = "scope:autonomous_system.lifecycle.initialize";
const ACTIVATE_SCOPE = "scope:autonomous_system.lifecycle.activate";

const clone = (value) => structuredClone(value);
const fixture = (relative) => JSON.parse(fs.readFileSync(path.join(FIXTURES, relative), "utf8"));
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
const domainHash = (domain, value) => `sha256:${createHash("sha256").update(canonicalJson({ domain, value })).digest("hex")}`;
const artifactHash = (domain, artifact) => `sha256:${createHash("sha256").update(canonicalJson({ domain, artifact })).digest("hex")}`;

function recomputeReleaseHashes(release) {
  const componentMaterial = clone(release.typed_components);
  delete componentMaterial.component_set_hash;
  release.typed_components.component_set_hash = domainHash("ioi.autonomous-system-component-set-jcs-sha256.v1", componentMaterial);
  const releaseMaterial = clone(release);
  delete releaseMaterial.release_root;
  delete releaseMaterial.registry_status;
  delete releaseMaterial.receipts.package_readiness_receipt_ref;
  delete releaseMaterial.release.publisher_signature_ref;
  delete releaseMaterial.release.registry_published_at;
  release.release_root = domainHash("ioi.autonomous-system-manifest-release-root-jcs-sha256.v1", releaseMaterial);
}

function exactGenesisBody() {
  const release = fixture("autonomous-system-manifest-v1/positive-reusable-release.json");
  recomputeReleaseHashes(release);
  const candidate = fixture("autonomous-system-genesis-v1/positive-proposed.json");
  delete candidate.admitted_manifest_root;
  delete candidate.initial_profile_bundle_root;
  delete candidate.cryptographic_origin.genesis_operation_commitment;
  delete candidate.cryptographic_origin.genesis_transition_commitment_ref;
  candidate.initial_component_bindings.admitted_component_set_hash = release.typed_components.component_set_hash;
  return {
    release,
    proposed_instantiation: {
      schema_version: "ioi.autonomous-system-genesis-proposal-input.v1",
      candidate,
      template_bindings: {
        constitution_template_ref: release.constitution_template_ref,
        deployment_template_ref: release.required_profile_templates.deployment_template_ref,
        ordering_admission_finality_template_ref: release.required_profile_templates.ordering_admission_finality_template_ref,
        oracle_evidence_template_refs: release.required_profile_templates.oracle_evidence_template_refs,
        lifecycle_continuity_template_ref: release.required_profile_templates.lifecycle_continuity_template_ref,
        network_enrollment_constraint_ref: release.required_profile_templates.network_enrollment_constraint_ref,
      },
      constitution: fixture("autonomous-system-constitution-v1/positive-draft.json"),
      ordering_profile: fixture("ordering-admission-finality-profile-v1/positive-single-authority.json"),
      oracle_profiles: [fixture("oracle-evidence-profile-v1/positive-fail-closed.json")],
      lifecycle_profile: fixture("lifecycle-continuity-profile-v1/positive-successor-governed.json"),
      network_enrollment: null,
    },
  };
}

function rebindGenesisBodySystem(source, ids) {
  const body = clone(source);
  const proposed = body.proposed_instantiation;
  const candidate = proposed.candidate;
  candidate.system_id = ids.systemId;
  candidate.genesis_id = ids.genesisId;
  candidate.constitution_ref = ids.constitutionRef;
  candidate.initial_profile_refs.deployment_profile_ref = ids.deploymentProfileRef;
  candidate.initial_profile_refs.ordering_admission_finality_profile_ref = ids.orderingProfileRef;
  candidate.initial_profile_refs.oracle_evidence_profile_refs = [ids.oracleProfileRef];
  candidate.initial_profile_refs.lifecycle_continuity_profile_ref = ids.lifecycleProfileRef;
  proposed.constitution.system_id = ids.systemId;
  proposed.constitution.constitution_id = ids.constitutionRef;
  proposed.ordering_profile.system_id = ids.systemId;
  proposed.ordering_profile.constitution_ref = ids.constitutionRef;
  proposed.ordering_profile.ordering_profile_id = ids.orderingProfileRef;
  proposed.oracle_profiles[0].system_id = ids.systemId;
  proposed.oracle_profiles[0].oracle_evidence_profile_id = ids.oracleProfileRef;
  proposed.lifecycle_profile.system_id = ids.systemId;
  proposed.lifecycle_profile.constitution_ref = ids.constitutionRef;
  proposed.lifecycle_profile.lifecycle_profile_id = ids.lifecycleProfileRef;
  return body;
}

function lifecycleDeploymentRevisionForGenesis(genesis) {
  const revision = fixture("autonomous-system-deployment-profile-revision-v1/positive-candidate.json");
  const identity = String(genesis.initial_profile_refs.deployment_profile_ref || "").replace(/\/revision\/sha256:[0-9a-f]{64}$/u, "");
  if (!identity.startsWith("deployment-profile://")) throw new Error("the genesis deployment profile lacks a canonical identity");
  revision.profile.deployment_profile_id = identity;
  revision.profile.system_id = genesis.system_id;
  revision.profile.constitution_ref = genesis.constitution_ref;
  revision.profile.manifest_ref = genesis.manifest_ref;
  revision.profile.ordering_admission_finality_profile_ref = genesis.initial_profile_refs.ordering_admission_finality_profile_ref;
  const root = `sha256:${createHash("sha256").update(canonicalJson({ domain: "ioi.autonomous-system-deployment-profile-revision-jcs-sha256.v1", profile: revision.profile })).digest("hex")}`;
  revision.deployment_profile_root = root;
  revision.deployment_profile_ref = `${revision.profile.deployment_profile_id}/revision/${root}`;
  return revision;
}

// ---- LIVE: transport and forms ------------------------------------------------------------------
// node:http with a 15-minute ceiling: governed posts hold on the wallet, and a Systems projection read
// takes tens of seconds (~49 s with one System, measured by the workspace plan). No redirects followed.
function httpCall(baseUrl, method, route, { form, cookie = "", accept = "" } = {}) {
  const target = new URL(`${baseUrl}${route}`);
  const payload = form === undefined ? null : new URLSearchParams(form).toString();
  return new Promise((resolve) => {
    const done = (r) => resolve(r);
    const request = http.request({
      hostname: target.hostname, port: target.port, path: `${target.pathname}${target.search}`, method,
      headers: {
        ...(payload === null ? {} : { "content-type": "application/x-www-form-urlencoded", "content-length": Buffer.byteLength(payload) }),
        ...(cookie ? { cookie } : {}),
        ...(accept ? { accept } : {}),
      },
    }, (response) => {
      let raw = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { raw += chunk; });
      response.on("error", (error) => done({ status: 0, text: "", json: null, headers: {}, error: error.message }));
      response.on("end", () => {
        let json = null;
        try { json = JSON.parse(raw); } catch { json = null; }
        done({ status: response.statusCode, text: raw, json, headers: response.headers });
      });
    });
    request.on("error", (error) => done({ status: 0, text: "", json: null, headers: {}, error: error.message }));
    request.setTimeout(900_000, () => request.destroy(new Error(`timed out: ${method} ${route}`)));
    if (payload !== null) request.write(payload);
    request.end();
  });
}

const unesc = (s) => String(s).replace(/&quot;/gu, '"').replace(/&gt;/gu, ">").replace(/&lt;/gu, "<").replace(/&amp;/gu, "&");
const journeyState = (html, state) => html.includes(`data-journey-state="${state}"`);
const truthCode = (html, code) => html.includes(`data-truth-code="${code}"`);
function approvalFrom(html) {
  const grab = (key) => (html.match(new RegExp(`data-approval="${key}">(sha256:[0-9a-f]{64})<`, "u")) || [])[1] || null;
  return { policy_hash: grab("policy_hash"), request_hash: grab("request_hash"), effect_hash: grab("effect_hash") };
}

// The form the page RENDERED that posts to `action` (the last one, so a challenge page's own "Resubmit
// with grant" form wins), with the names it offers and the values a browser would submit for it
// untouched: every input's rendered value (a checkbox or radio only when checked), each select's
// selected option (else its first), each textarea's text — the hidden lane, the owner a form prefills,
// the verbatim declaration a challenge page re-offers.
const attrOf = (tag, name) => { const m = tag.match(new RegExp(`\\b${name}="([^"]*)"`, "u")); return m ? unesc(m[1]) : null; };
function renderedForm(html, action) {
  const at = html.lastIndexOf(`action="${action}"`);
  if (at < 0) return null;
  const start = html.lastIndexOf("<form", at);
  const end = html.indexOf("</form>", at);
  if (start < 0 || end < 0) return null;
  const inner = html.slice(start, end);
  const names = new Set([...inner.matchAll(/\bname="([^"]+)"/gu)].map((m) => m[1]));
  const values = {};
  for (const [tag] of inner.matchAll(/<input\b[^>]*>/gu)) {
    const name = attrOf(tag, "name");
    const type = (attrOf(tag, "type") || "text").toLowerCase();
    if (!name || ["submit", "button", "file", "image", "reset"].includes(type)) continue;
    if ((type === "checkbox" || type === "radio") && !/\bchecked\b/u.test(tag)) continue;
    values[name] = attrOf(tag, "value") ?? (type === "checkbox" ? "on" : "");
  }
  const options = {};
  for (const m of inner.matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select>/gu)) {
    const name = attrOf(m[1], "name");
    const offered = [...m[2].matchAll(/<option\b([^>]*)>/gu)].map((o) => o[1]);
    const chosen = offered.find((o) => /\bselected\b/u.test(o)) ?? offered[0];
    if (name) options[name] = new Set(offered.map((o) => attrOf(o, "value") ?? ""));
    if (name && chosen !== undefined) values[name] = attrOf(chosen, "value") ?? "";
  }
  for (const m of inner.matchAll(/<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gu)) {
    const name = attrOf(m[1], "name");
    if (name) values[name] = unesc(m[2]);
  }
  return { names, values, options };
}

// THE ONLY WRITE PATH. A person can only submit a form they can see: the form must be on the page the
// surface rendered, post to a /__ioi/ lane, and offer every field filled. Its own hidden values travel as
// rendered; the filled fields override them.
async function submitRenderedForm(ctx, { id, page, from, action, fields }) {
  if (!action.startsWith("/__ioi/")) throw new Error(`write ${id}: '${action}' is not a form the product renders — every write goes through a /__ioi/ form`);
  const form = renderedForm(page.text, action);
  if (!form) throw new Error(`write ${id}: no form posting to '${action}' is rendered at ${from} (HTTP ${page.status})`);
  const missing = Object.keys(fields).filter((name) => !form.names.has(name));
  if (missing.length) throw new Error(`write ${id}: the form at ${from} renders no field ${missing.join(", ")}`);
  const unoffered = Object.entries(fields).filter(([name, value]) => form.options[name] && !form.options[name].has(String(value)));
  if (unoffered.length) throw new Error(`write ${id}: the form at ${from} offers no option ${unoffered.map(([n, v]) => `${n}=${v}`).join(", ")}`);
  ctx.cache.clear();
  const res = await httpCall(ctx.serve, "POST", action, { form: { ...form.values, ...fields }, cookie: ctx.cookie, accept: "text/html" });
  ctx.walk.push({ id, from, action, status: res.status, state: (res.text.match(/data-journey-state="([a-z_]+)"/u) || [])[1] || null, code: (res.text.match(/data-truth-code="([a-z0-9_.]+)"/u) || [])[1] || null });
  return res;
}
// A page as a signed-in person navigates to it (cached until the next write: workspace pages each cost a
// projection read).
async function page(ctx, route) {
  if (ctx.cache.has(route)) return ctx.cache.get(route);
  const res = await httpCall(ctx.serve, "GET", route, { cookie: ctx.cookie, accept: "text/html" });
  ctx.cache.set(route, res);
  return res;
}
// A daemon read through the serve's /v1 pass-through, as the same person — the expected roots the ladder
// forms ask for are "owner facts you hold from prior receipts" (the form's own label).
const read = (ctx, route) => httpCall(ctx.serve, "GET", route, { cookie: ctx.cookie });
// A module action answers a redirect back to its surface carrying `acted=` and the record, or `refused=`
// and the reason; the outcome is read off that Location, never assumed from the status alone.
function outcomeOf(res) {
  const location = String(res.headers?.location || "");
  const q = new URLSearchParams(location.split("?")[1]?.split("#")[0] || "");
  return { status: res.status, location, q, redirected: res.status === 302 || res.status === 303, refused: q.get("refused") };
}

// A governed step as a person takes it: submit the form, read the daemon's exact challenge off the page,
// approve THOSE hashes in the wallet (the real wallet.network fixture), and paste the grant into the
// challenge page's own "Resubmit with grant" form (the named gap genesis_approval_not_in_inbox).
async function governedStep(ctx, { id, page: from, route, action, fields, scope }) {
  const challenge = await submitRenderedForm(ctx, { id: `${id} (challenge)`, page: from, from: route, action, fields });
  const approval = approvalFrom(challenge.text);
  if (!journeyState(challenge.text, "ready_or_proposed") || !approval.policy_hash || !approval.request_hash) {
    throw new Error(`write ${id}: the surface rendered no authority challenge (HTTP ${challenge.status}, ${(challenge.text.match(/data-truth-code="([a-z0-9_.]+)"/u) || [])[1] || "no code"})`);
  }
  const grant = ctx.resolver.mintForCapability(OWNER, approval.policy_hash, approval.request_hash);
  await ctx.resolver.recordApproval(OWNER, approval.policy_hash, approval.request_hash, grant, scope);
  const resubmit = () => submitRenderedForm(ctx, { id: `${id} (granted)`, page: challenge, from: `${route} → challenge`, action, fields: { wallet_approval_grant: JSON.stringify(grant) } });
  let committed = await resubmit();
  for (let retry = 0; retry < 3 && truthCode(committed.text, "system_lifecycle_authority_resolver_unavailable"); retry += 1) {
    await new Promise((r) => setTimeout(r, 250));
    committed = await resubmit();
  }
  return { challenge, committed, approval };
}

// ---- LIVE: the browser leg ----------------------------------------------------------------------
// The New Session composer is a JavaScript surface: its launcher is a modal the page builds from the
// daemon-backed context, and Start sends the page's own request, not a form. So THIS leg drives it as a
// person does — in chromium, signed in as THIS gate's operator (its own session cookie, on its own
// serve, never another's) — and only opens, clicks, types and ticks controls the page rendered. It
// carries no request of its own (no page.request, no route interception): the page's script is the
// only thing that writes. What the composer did is then judged from daemon truth, never from the page.
async function openComposer(ctx) {
  if (!ctx.browser) {
    const { chromium } = await import("playwright");
    ctx.browser = await chromium.launch({ headless: true });
  }
  const context = await ctx.browser.newContext({ viewport: { width: 1500, height: 1000 } });
  const at = ctx.cookie.indexOf("=");
  await context.addCookies([{ name: ctx.cookie.slice(0, at), value: ctx.cookie.slice(at + 1), url: ctx.serve }]);
  const tab = await context.newPage();
  await tab.goto(`${ctx.serve}/ai#new-session`, { waitUntil: "domcontentloaded", timeout: 600_000 });
  // New Session is the composer page; its governed launcher (harness, connections, placement) opens
  // from the page's own "Advanced launch" control.
  await tab.waitForSelector("#ioi-ns-advanced", { timeout: 600_000 });
  await tab.click("#ioi-ns-advanced");
  await tab.waitForSelector("#ioi-ns-modal.open #ioi-ns-launch", { timeout: 600_000 });
  // The connection rows the launcher rendered: each checkbox's value, and whether a person can tick it
  // (a withheld connection is rendered disabled WITH its reason, never hidden).
  const connections = await tab.locator("#ioi-ns-modal .ioi-ns-cx").evaluateAll((rows) => rows.map((row) => {
    const box = row.querySelector("input.ioi-ns-cx-box");
    return { ref: box ? box.value : "", tickable: !!box && !box.disabled, text: row.textContent || "" };
  }));
  return { context, tab, connections, close: () => context.close().catch(() => {}) };
}

// ---- LIVE: the walk -----------------------------------------------------------------------------
async function liveLeg() {
  const started = Date.now();
  const setup = [];
  const claims = {};
  const L = LIB.legIndex(LIB.JOURNEY, LIB.ESTATE);
  const vars = { tag: `asj${Date.now().toString(36).slice(-6)}`, system: null, system_id: null };
  const ctx = { serve: null, cookie: "", resolver: null, browser: null, walk: [], cache: new Map() };
  const claimLive = (key, cond, detail = "") => {
    const l = L[key];
    if (!l || l.kind !== "live") throw new Error(`the walk claims '${key}', which the table does not hold as a live leg`);
    claims[key] = { state: cond ? "pass" : "fail", assertion: l.assertion, detail: String(detail).slice(0, 240) };
    console.log(`${cond ? "PASS" : "FAIL"}  ${l.assertion}${cond ? "" : ` — ${detail}`}`);
  };
  // TODO(live) markers: the walk passes each point where a live leg is still to be written. A row flipped
  // to live without its leg stops the walk here instead of reading as green.
  const todo = (key) => {
    if (L[key]?.kind !== "todo") throw new Error(`the walk marks '${key}' TODO, but the table no longer does — write its live leg`);
    claims[key] = { state: "todo" };
  };
  const probe = async (key) => {
    const l = L[key];
    const route = LIB.fill(l.gap.probe.route, vars);
    const res = await page(ctx, route);
    const holds = res.status === 200 && res.text.includes(l.gap.probe.marker);
    claims[key] = { state: "named_gap", probe: holds ? "holds" : "stale", detail: `${route} → ${res.status}` };
    console.log(`${holds ? "GAP  " : "STALE"} ${l.gap.code} — ${holds ? `still named by the product at ${route}` : `no longer named at ${route}`}`);
  };
  const probesOf = async (stepId) => { for (const key of Object.keys(L).filter((k) => k.startsWith(`${stepId}/`) && L[k].kind === "named_gap" && L[k].gap?.probe)) await probe(key); };

  // Inherited IOI_* must not leak into the plane or the wallet fixture (the genesis journey's rule), except
  // the explicit ready-timeout and binary knobs CI sets on its wallet-fixture jobs.
  const KNOBS = new Set(["IOI_WALLET_FIXTURE_READY_TIMEOUT_MS", "IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS", "IOI_HYPERVISOR_DAEMON_BINARY"]);
  const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("IOI_") || KNOBS.has(k)));
  let plane = null, plane2 = null, dataDir = null, reached = false;
  try {
    const { startIsolatedPlane } = await import("../apps/hypervisor/scripts/lib/isolated-daemon.mjs");
    const { startRealWalletNetworkPrincipalAuthorityFixture } = await import("../apps/hypervisor/scripts/lib/wallet-network-principal-authority-fixture.mjs");
    console.log("# LIVE — the real wallet.network principal-authority fixture (the first run may compile)");
    ctx.resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv: cleanEnv });

    // THIS GATE OWNS ITS PLANE: a fresh data directory, free ports, the sign-in gate ON.
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "autonomous-system-journey-"));
    const planeEnv = { ...ctx.resolver.env, IOI_PRODUCT_SIGNIN_REQUIRED: "1" };
    plane = await startIsolatedPlane({ serve: true, dataDir, env: planeEnv, baseEnv: cleanEnv });
    if (!plane) throw new Error("BLOCKED: target/debug/hypervisor-daemon is not built");
    ctx.serve = plane.serveUrl;

    // Before anyone exists, a page navigation goes to first-run setup — never to a stranger.
    const gated = await httpCall(ctx.serve, "GET", "/systems", { accept: "text/html" });
    const gatedTo = String(gated.headers.location || "");
    if (gated.status !== 302 || !gatedTo.startsWith("/__ioi/bootstrap")) setup.push(`sign-in gate: a signed-out navigation to /systems answered ${gated.status}${gatedTo ? ` → ${gatedTo}` : ""}, not first-run setup`);
    // The one-boot token is printed only in the plane's own log, inside the data directory this gate owns;
    // a plane handed its data directory writes a restart-named log, so read every one and take the newest.
    const logs = fs.readdirSync(dataDir).filter((n) => /^isolated-daemon.*\.log$/u.test(n)).sort();
    const token = logs.map((n) => fs.readFileSync(path.join(dataDir, n), "utf8")).join("\n").match(/ioi_bootstrap_[A-Za-z0-9_-]+/gu)?.at(-1);
    if (!token) throw new Error("the plane's daemon printed no one-boot bootstrap token");
    // THE OPERATOR, through the serve's own first-run form.
    const firstRun = await page(ctx, "/__ioi/bootstrap");
    const boot = await submitRenderedForm(ctx, { id: "operator", page: firstRun, from: "/__ioi/bootstrap", action: "/__ioi/bootstrap",
      fields: { token, name: "Journey Gate", email: "gate@autonomous-system-journey.invalid", password: "autonomous-system-journey-pass-1" } });
    ctx.cookie = ([].concat(boot.headers["set-cookie"] || []).join("; ").match(/ioi_session=[^;]+/u) || [])[0] || "";
    const who = await read(ctx, "/v1/hypervisor/auth/whoami");
    if (boot.status !== 302 || !ctx.cookie || who.json?.authenticated !== true) throw new Error(`the operator was not signed in through the first-run form (HTTP ${boot.status})`);
    reached = true;

    // ==== STEP 1 — CREATE ==========================================================================
    const name = `journey-${vars.tag}`;
    const ids = {
      systemId: `system://acme/${name}`, genesisId: `genesis://acme/${name}/zero`, constitutionRef: `constitution://acme/${name}/v1`,
      deploymentProfileRef: `deployment-profile://acme/${name}/local/revision/sha256:${"d".repeat(64)}`,
      orderingProfileRef: `ordering-profile://acme/${name}/poa1`, oracleProfileRef: `oracle-evidence-profile://acme/${name}/public-records`,
      lifecycleProfileRef: `lifecycle-profile://acme/${name}/default`,
    };
    vars.system_id = ids.systemId;
    vars.system = ids.systemId.slice("system://".length);
    evidence.tag = vars.tag;
    evidence.system_id = ids.systemId;
    const revision = lifecycleDeploymentRevisionForGenesis(rebindGenesisBodySystem(exactGenesisBody(), ids).proposed_instantiation.candidate);
    const composeRoute = `${SYSTEMS_BASE}/compose?lane=compact`;
    const admit = await governedStep(ctx, {
      id: "genesis", page: await page(ctx, composeRoute), route: composeRoute, action: `${SYSTEMS_BASE}/compose`, scope: GENESIS_SCOPE,
      fields: {
        declaration: JSON.stringify(exactGenesisBody()), system_id: ids.systemId, genesis_id: ids.genesisId, constitution_ref: ids.constitutionRef,
        deployment_profile_ref: revision.deployment_profile_ref, ordering_profile_ref: ids.orderingProfileRef, oracle_profile_ref: ids.oracleProfileRef,
        lifecycle_profile_ref: ids.lifecycleProfileRef,
      },
    });
    // The admission's storage key, read off the committed page's own record (robust to the detail link
    // moving from /__ioi/systems/<asg> to the workspace).
    const tail = (admit.committed.text.match(/system-genesis-admission:\/\/(asg_[0-9a-f]{64})/u) || [])[1] || null;
    const recordRead = tail ? await read(ctx, `${GENESIS_API}/${tail}`) : { json: null };
    const record = recordRead.json?.autonomous_system_genesis_admission;
    const receipt = recordRead.json?.autonomous_system_genesis_receipt;
    claimLive("create/legs/genesis-admission",
      journeyState(admit.committed.text, "completed") && !!tail && record?.system_id === ids.systemId && admit.committed.text.includes(record?.proposal_root || "__none__"),
      `admission ${tail || "none"} · ${record?.system_id || "no record"}`);
    if (!tail || !record || !receipt) throw new Error("step 1: the admission did not commit through the composer");

    // The governed ladder, through the forms the System's GOVERN mode renders (canon puts lifecycle under
    // Govern). Visible-but-not-live, the workspace renders the pending ladder and its forms.
    const governRoute = `/systems/${vars.system}/govern`;
    const ladder = async (id, sub, request, scope) => governedStep(ctx, { id, page: await page(ctx, governRoute), route: governRoute, action: `${SYSTEMS_BASE}/${tail}/${sub}`, fields: { request: JSON.stringify(request) }, scope });
    const materialized = await ladder("materialize", "sequence-zero-materialization", {
      expected_genesis_admission_record_root: domainHash("ioi.autonomous-system-genesis-admission-record-jcs-sha256.v1", record),
      expected_genesis_admission_receipt_root: domainHash("ioi.autonomous-system-genesis-admission-receipt-jcs-sha256.v1", receipt),
    }, MATERIALIZE_SCOPE);
    const seqZero = (await read(ctx, `${GENESIS_API}/${tail}/sequence-zero-materialization`)).json || {};
    const initialized = await ladder("initialize", "initialize", {
      expected_sequence_zero_materialization_root: artifactHash("ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1", seqZero.autonomous_system_sequence_zero_materialization),
      expected_sequence_zero_materialization_receipt_root: artifactHash("ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1", seqZero.autonomous_system_sequence_zero_materialization_receipt),
      deployment_profile_revision: lifecycleDeploymentRevisionForGenesis(record.authorized_genesis),
    }, INITIALIZE_SCOPE);
    const initGraph = (await read(ctx, `${GENESIS_API}/${tail}/initialize`)).json || {};
    const state = initGraph.autonomous_system_activation_state || {};
    const activated = await ladder("activate", "activate", {
      expected_initialize_proposal_root: initGraph.lifecycle_receipt?.bound_facts?.proposal_root,
      expected_initialize_decision_root: initGraph.lifecycle_receipt?.bound_facts?.decision_root,
      expected_initialize_state_root: state.activation_state_root,
      expected_initialize_transition_root: state.transition_root,
      expected_initialize_receipt_root: state.transition_receipt_root,
    }, ACTIVATE_SCOPE);
    claimLive("create/legs/governed-ladder",
      [materialized, initialized, activated].every((s) => journeyState(s.committed.text, "completed")) && activated.committed.text.includes('data-lifecycle-status="active"'),
      `materialize ${materialized.committed.status} · initialize ${initialized.committed.status} · activate ${activated.committed.status}`);
    // create/legs/genesis-depth is COMPOSED (system-genesis-product-journey); the template picker and the
    // inbox approval are named gaps with no marker on the page to probe.

    // ---- HAND-OFF 1 → 2: the System reaches its Design mode, and Design hands off to Studio. ----------
    // Follow the daemon's own published route from the /systems card — never a hand-built path.
    const systems = await page(ctx, "/systems");
    const cardAt = systems.text.indexOf(`data-ioi-system="${ids.systemId}"`);
    const card = cardAt < 0 ? "" : systems.text.slice(cardAt, systems.text.indexOf("data-ioi-system=", cardAt + 20) > 0 ? systems.text.indexOf("data-ioi-system=", cardAt + 20) : cardAt + 8000);
    const designHref = unesc((card.match(/<a href="([^"]+)">design<\/a>/u) || [])[1] || "");
    const design = designHref ? await page(ctx, designHref) : { status: 0, text: "", headers: {} };
    const handoffBlock = (design.text.match(/data-system-handoffs="1"[\s\S]*?<\/p>/u) || [""])[0];
    const handoffLinks = [...handoffBlock.matchAll(/href="([^"]+)"/gu)].map((m) => unesc(m[1]));
    const studio = handoffLinks.includes("/studio") ? await page(ctx, "/studio") : { status: 0, text: "", headers: {} };
    claimLive("create/handoff/system-links-its-design",
      systems.status === 200 && cardAt >= 0 && designHref === `/systems/${vars.system}/design`
        && design.status === 200 && String(design.headers["x-ioi-surface-lane"] || "").startsWith("/__ioi/system-workspace/")
        && design.text.includes('data-system-workspace-mode="design"') && design.text.includes(`data-system-workspace-id="${ids.systemId}"`)
        && studio.status === 200 && studio.headers["x-ioi-surface-route"] === "/studio" && !studio.text.includes("is not available yet"),
      `/systems ${systems.status} card ${cardAt >= 0} · design '${designHref}' ${design.status} · studio ${studio.status} · hand-offs ${handoffLinks.join(" ")}`);
    // HAND-OFF 1→2 (WP-C1): the Design mode's own link to Studio's Draft a blueprint form, whose
    // system_ref select — the caller-filtered Systems projection — offers THIS System, chosen.
    const draftHref = unesc((design.text.match(/data-system-draft-blueprint="1" href="([^"]+)"/u) || [])[1] || "");
    const draftPage = draftHref ? await page(ctx, draftHref) : { status: 0, text: "", headers: {} };
    const draftForm = renderedForm(draftPage.text, "/__ioi/studio/workbench/actions/create-blueprint");
    claimLive("create/handoff/system-offered-to-studio",
      draftHref === `/__ioi/studio/workbench?view=blueprints&system_ref=${encodeURIComponent(ids.systemId)}` && draftPage.status === 200
        && !!draftForm && !!draftForm.options.system_ref?.has(ids.systemId) && draftForm.values.system_ref === ids.systemId && !!draftForm.values.owner_ref,
      `draft link '${draftHref || "none"}' → ${draftPage.status} · form ${!!draftForm} · offers ${draftForm?.options.system_ref ? [...draftForm.options.system_ref].filter(Boolean).join(" ") || "no System" : "no system_ref select"} · chosen '${draftForm?.values.system_ref ?? ""}' · owner '${draftForm?.values.owner_ref ?? ""}'`);
    await probesOf("create");

    // ==== STEP 2 — DESIGN ==========================================================================
    // THIS walk's blueprint, through the form Studio's blueprints view renders — reached by the System's
    // own hand-off, bound to the System the form offers; its owner is the tenant the form itself offers
    // (a person does not type one).
    const blueprintsRoute = "/__ioi/studio/workbench?view=blueprints";
    const draftRoute = draftHref || blueprintsRoute;
    const blueprintName = `bp-${vars.tag}`;
    const blueprint = outcomeOf(await submitRenderedForm(ctx, { id: "blueprint", page: await page(ctx, draftRoute), from: draftRoute, action: "/__ioi/studio/workbench/actions/create-blueprint",
      fields: { name: blueprintName, description: `the journey walk's design for ${ids.systemId}`, graph_json: JSON.stringify({ nodes: [{ id: "system", kind: "concept" }], edges: [] }), system_ref: ids.systemId } }));
    const blueprints = await page(ctx, blueprintsRoute);
    claimLive("design/legs/walk-blueprint",
      blueprint.redirected && !blueprint.refused && blueprint.q.get("acted") === "create-blueprint" && blueprints.status === 200 && blueprints.text.includes(blueprintName),
      `${blueprint.status} ${blueprint.refused ? `refused ${blueprint.refused}: ${blueprint.q.get("reason") || ""}` : blueprint.q.get("acted") || blueprint.location.slice(0, 80)} · listed ${blueprints.text.includes(blueprintName)}`);
    // WP-C1 — THIS walk's blueprint is bound to THIS System, read from daemon truth: the record (the
    // registered StudioBlueprint v1) carries the System and its admitted head, the daemon's
    // System-narrowed list names it, and the System's Design mode lists it by its own ref and name.
    const bpId = blueprint.q.get("record") || "";
    const bpRead = bpId ? ((await read(ctx, `/v1/hypervisor/studio/blueprints/${encodeURIComponent(bpId)}`)).json || {}) : {};
    const boundList = ((await read(ctx, `/v1/hypervisor/studio/blueprints?system_ref=${encodeURIComponent(ids.systemId)}`)).json || {}).blueprints || [];
    const designBound = await page(ctx, `/systems/${vars.system}/design`);
    const bpRowAt = bpRead.blueprint?.ref ? designBound.text.indexOf(`data-system-blueprint="${bpRead.blueprint.ref}"`) : -1;
    const bpRow = bpRowAt >= 0 ? designBound.text.slice(bpRowAt, designBound.text.indexOf("</tr>", bpRowAt)) : "";
    claimLive("design/legs/design-bound-to-system",
      bpRead.ok === true && bpRead.blueprint?.system_ref === ids.systemId && bpRead.blueprint?.schema_version === "ioi.hypervisor.studio.blueprint.v1"
        && typeof bpRead.admitted_head === "string" && bpRead.admitted_head.length > 0
        && boundList.some((b) => b.id === bpId && b.system_ref === ids.systemId) && boundList.every((b) => b.system_ref === ids.systemId)
        && designBound.status === 200 && bpRow.includes(blueprintName),
      `record ${bpId || "none"} system_ref ${bpRead.blueprint?.system_ref || "none"} head ${bpRead.admitted_head ? "known" : "none"} · the System's list ${boundList.length} (holds it ${boundList.some((b) => b.id === bpId)}) · Design row ${bpRowAt >= 0} names it ${bpRow.includes(blueprintName)}`);

    // ==== STEP 3 — DATA ============================================================================
    // THIS walk's ontology and source — the first writes of lib/propagation-matrix.mjs, through the same
    // forms. The declare form is the one a person's kind choice reloads it into.
    const ontologyName = `${vars.tag}-lending`;
    const sourceName = `${vars.tag}-src`;
    const ontologyRoute = "/__ioi/ontology/manager?section=create";
    const ontology = outcomeOf(await submitRenderedForm(ctx, { id: "ontology", page: await page(ctx, ontologyRoute), from: ontologyRoute, action: "/__ioi/ontology/manager/actions/create-ontology", fields: { domain: ontologyName } }));
    const sourceRoute = "/__ioi/data/sources?declare=1&kind=rest_api";
    const source = outcomeOf(await submitRenderedForm(ctx, { id: "source", page: await page(ctx, sourceRoute), from: sourceRoute, action: "/__ioi/data/sources/actions/declare",
      fields: { name: sourceName, endpoint: "https://example.invalid/loans", confirm: "1" } }));
    const odkPage = await page(ctx, "/__ioi/odk");
    const sourcesPage = await page(ctx, "/__ioi/data/sources");
    claimLive("data/legs/walk-ontology-and-source",
      ontology.redirected && !ontology.refused && source.redirected && !source.refused && odkPage.text.includes(ontologyName) && sourcesPage.text.includes(sourceName),
      `ontology ${ontology.status}${ontology.refused ? ` refused ${ontology.refused}` : ""} · source ${source.status}${source.refused ? ` refused ${source.refused}` : ""} · ODK lists it ${odkPage.text.includes(ontologyName)} · sources list it ${sourcesPage.text.includes(sourceName)}`);
    // HAND-OFF 2 → 3, judged now that step 3 has written: the Designer offers THIS walk's ontology.
    const designerPage = await page(ctx, "/__ioi/studio/designer");
    claimLive("design/handoff/walk-designer-offers-ontology",
      designerPage.status === 200 && designerPage.text.includes(ontologyName),
      `designer ${designerPage.status} · offers ${ontologyName} ${designerPage.text.includes(ontologyName)}`);
    // STEP 3 (continued, WP-C1) — THIS walk's ontology and source attached to THIS System from its
    // Design mode's Attach form, whose options are the caller's own ontologies and sources. Each is one
    // SystemDataAttachment record in the System-record seam, read back from the daemon under the System.
    const attachOntId = ontology.q.get("record") || "";
    const walkOntRef = attachOntId ? ((await read(ctx, `/v1/hypervisor/odk/domain-ontologies/${encodeURIComponent(attachOntId)}`)).json?.ontology?.ref || "") : "";
    const walkSourceRef = ((((await read(ctx, "/v1/hypervisor/data-sources")).json || {}).data_sources || []).find((s) => s.name === sourceName) || {}).source_ref || "";
    const designRoute = `/systems/${vars.system}/design`;
    const attachOne = async (id, subject) => outcomeOf(await submitRenderedForm(ctx, { id, page: await page(ctx, designRoute), from: designRoute, action: "/__ioi/systems/attach-data", fields: { subject } }));
    const noAttach = { status: 0, q: new URLSearchParams() };
    const attachedOnt = walkOntRef ? await attachOne("attach-ontology", `ontology|${walkOntRef}`) : noAttach;
    const attachedSrc = walkSourceRef ? await attachOne("attach-source", `data_source|${walkSourceRef}`) : noAttach;
    const seamRecords = ((await read(ctx, `${GENESIS_API}/${encodeURIComponent(ids.systemId)}/records?contract_id=${encodeURIComponent(ATTACHMENT_CONTRACT)}`)).json || {}).records || [];
    const heldFor = (ref) => !!ref && seamRecords.some((r) => r.contract_id === ATTACHMENT_CONTRACT && typeof r.head === "string" && r.current?.subject_ref === ref
      && r.current?.status === "attached" && r.current?.system_binding?.system_id === ids.systemId);
    const attachSaid = (o) => `${o.status} ${o.q.get("acted") || (o.q.get("refused") ? `refused ${o.q.get("refused")}: ${o.q.get("reason") || ""}` : "")}`;
    claimLive("data/legs/attach-to-system",
      [attachedOnt, attachedSrc].every((o) => o.status === 303 && o.q.get("acted") === "attach-data" && !!o.q.get("receipt")) && heldFor(walkOntRef) && heldFor(walkSourceRef),
      `ontology ${walkOntRef || "no ref"} → ${attachSaid(attachedOnt)} · source ${walkSourceRef || "no ref"} → ${attachSaid(attachedSrc)} · the seam holds ${seamRecords.length} attachment(s) (ontology ${heldFor(walkOntRef)}, source ${heldFor(walkSourceRef)})`);
    // HAND-OFF 2→3 (WP-C1): the System's design names the data it uses, by the subjects' own names.
    const designData = await page(ctx, designRoute);
    const attachmentRow = (ref) => { const at = ref ? designData.text.indexOf(`data-subject-ref="${ref}"`) : -1; return at >= 0 ? designData.text.slice(at, designData.text.indexOf("</tr>", at)) : ""; };
    claimLive("design/handoff/design-carries-system-data",
      designData.status === 200 && attachmentRow(walkOntRef).includes(ontologyName) && attachmentRow(walkSourceRef).includes(sourceName),
      `Design ${designData.status} · ontology row names ${ontologyName} ${attachmentRow(walkOntRef).includes(ontologyName)} · source row names ${sourceName} ${attachmentRow(walkSourceRef).includes(sourceName)}`);
    // ==== STEP 4 — LIMITS ==========================================================================
    // THIS walk's checkpoint (ADR 0056 P5), from Leases & Limits' Configuration form: a person's Run now
    // needs a written justification naming the walk. The run step below must then pass it.
    const checkpointName = `checkpoint-${vars.tag}`;
    const limitsRoute = "/governance/limits?tab=checkpoints&view=configuration";
    const configuredCheckpoint = outcomeOf(await submitRenderedForm(ctx, { id: "checkpoint", page: await page(ctx, limitsRoute), from: limitsRoute, action: "/__ioi/governance/limits/checkpoints/new",
      fields: { display_name: checkpointName, interaction_kinds: "automation.run_now", prompt_title: "Why run this now?", prompt_body: "Say why this automation runs by hand.", justification_kind: "response", response_pattern: `^walk ${vars.tag}` } }));
    const checkpointList = await page(ctx, limitsRoute);
    claimLive("limits/legs/walk-checkpoint",
      configuredCheckpoint.status === 303 && configuredCheckpoint.q.get("ok") === "1" && checkpointList.status === 200 && checkpointList.text.includes(checkpointName) && checkpointList.text.includes('data-limits-enablement="enabled"'),
      `configure ${configuredCheckpoint.status} ${configuredCheckpoint.q.get("note") || ""} · listed ${checkpointList.text.includes(checkpointName)}`);
    // HAND-OFF 4 → 5 (connections): THIS walk's connection, added through Connections' Add API key form
    // with its token sealed and no limits. A session may name only a connection whose standing lease is
    // active, so the New Session composer (step 5) must withhold it; leasing it needs the authority node
    // (the named gap probed here, on the connection's own card).
    const cxName = `cx-${vars.tag}`;
    const addConnectionRoute = "/__ioi/connections/add?type=bearer";
    const addedConnection = await submitRenderedForm(ctx, { id: "connection", page: await page(ctx, addConnectionRoute), from: addConnectionRoute, action: "/__ioi/connections/add?type=bearer",
      fields: { name: cxName, base_url: `https://example.invalid/journey/${vars.tag}`, tool_name: "list_loans", tool_path: "/v1/loans", token: `journey-${vars.tag}-sealed-token` } });
    const walkConnector = ((((await read(ctx, "/v1/hypervisor/connectors")).json || {}).connectors || []).find((c) => c.name === cxName)) || null;
    const walkConnectionRef = walkConnector?.connector_id ? `connector:${walkConnector.connector_id}` : "";
    await probesOf("limits");
    // ==== STEP 5 — RUN =============================================================================
    // THIS walk's automation, through the New automation form. An automation names one of this
    // Hypervisor's projects — the daemon refuses any other (automation_project_unknown) — so THIS walk's
    // project must exist first. On a plane with none, New automation renders only the New project form,
    // whose answer returns to New automation with the new project chosen; once one exists, the page renders
    // the automation form and its project select offers it.
    const automationName = `auto-${vars.tag}`;
    const newAutomationRoute = "/__ioi/automations/new";
    const walkProjectId = `project:walk-${vars.tag}`;
    const automationFormPage = async () => {
      const first = await page(ctx, newAutomationRoute);
      if (!renderedForm(first.text, "/__ioi/projects/new")) return { at: newAutomationRoute, page: first, project: null };
      const project = outcomeOf(await submitRenderedForm(ctx, { id: "project", page: first, from: newAutomationRoute, action: "/__ioi/projects/new",
        fields: { project_name: `walk-${vars.tag}`, repository_url: `https://example.invalid/journey/walk-${vars.tag}.git` } }));
      const at = project.location.startsWith(newAutomationRoute) ? project.location : newAutomationRoute;
      return { at, page: await page(ctx, at), project };
    };
    const automationForm = await automationFormPage();
    const walkProject = automationForm.project;
    // WP-B: the automation is created FOR the walk's System — the form's System select must offer it.
    const systemOffered = !!renderedForm(automationForm.page.text, "/__ioi/automations")?.options.system_ref?.has(ids.systemId);
    const createdAutomation = await submitRenderedForm(ctx, { id: "automation", page: automationForm.page, from: automationForm.at, action: "/__ioi/automations",
      fields: { project_ref: walkProjectId, system_ref: ids.systemId, name: automationName, step_kind: "command", step_body: "echo journey" } });
    const automationAt = String(createdAutomation.headers.location || "");
    const automate = await page(ctx, "/__ioi/automations/monitors?tab=automations");
    const walkAutomationRecord = /auto_[0-9a-f]+/u.test(automationAt)
      ? (((await read(ctx, `/v1/hypervisor/automations/${automationAt.match(/auto_[0-9a-f]+/u)[0]}`)).json || {}).automation || {}) : {};
    claimLive("run/legs/walk-automation",
      (!walkProject || (walkProject.status === 303 && walkProject.q.get("ok") === "1" && walkProject.q.get("project") === walkProjectId))
        && createdAutomation.status === 302 && /^\/__ioi\/automations\/auto_[0-9a-f]+/u.test(automationAt) && walkAutomationRecord.project_ref === walkProjectId
        && automate.status === 200 && automate.text.includes(automationName),
      `project ${walkProject ? `${walkProject.status} ${walkProject.q.get("project") || walkProject.q.get("note") || ""}` : "already held"} · create ${createdAutomation.status} → ${automationAt.slice(0, 60) || "no location"} in ${walkAutomationRecord.project_ref || "no project"} · Automate lists it ${automate.text.includes(automationName)}`);
    // THIS walk's session, from the New Session composer — the browser leg (see openComposer). The
    // launcher is opened as a person opens it; THIS walk's project is picked from its project select, the
    // walk's first instruction typed, and no harness binding chosen: the launcher preselects the native
    // worker, whose live runnability probe refuses on a plane with no available model route, and "None
    // — defer to execute-time default" is the choice it offers for that. Then Start, and the daemon's
    // record is read back as the same person.
    const instruction = `walk ${vars.tag} — the done-bar walk's session, in its own project`;
    let composerSaid = "";
    let composerProjects = [];
    let composerConnection = null;
    let composerError = "";
    try {
      const composer = await openComposer(ctx);
      try {
        composerConnection = composer.connections.find((c) => c.ref === walkConnectionRef) || null;
        composerProjects = await composer.tab.locator("#ioi-ns-project option").evaluateAll((os) => os.map((o) => o.value));
        await composer.tab.selectOption("#ioi-ns-project", walkProjectId);
        await composer.tab.fill("#ioi-ns-goal", instruction);
        await composer.tab.selectOption("#ioi-ns-harness", "");
        await composer.tab.click("#ioi-ns-launch");
        await composer.tab.waitForFunction(() => /Session created|rejected|did not reach/u.test(document.querySelector("#ioi-ns-result")?.textContent || ""), null, { timeout: 900_000 });
        composerSaid = await composer.tab.locator("#ioi-ns-result").innerText();
      } finally {
        await composer.close();
      }
    } catch (error) {
      composerError = String(error.message).split("\n")[0].slice(0, 160);
    }
    const walkSessionRef = (composerSaid.match(/session:hyp-[0-9a-f]{64}/u) || [])[0] || "";
    const sessionRead = walkSessionRef ? (await read(ctx, `/v1/hypervisor/sessions/${encodeURIComponent(walkSessionRef)}`)).json || {} : {};
    const walkSession = sessionRead.session || sessionRead;
    const operatorRef = who.json?.principal?.principal_ref || "";
    const provisionReceipt = (walkSession.latest_receipt_refs || []).find((r) => String(r).startsWith("receipt://hypervisor/session-provision/")) || "";
    const sessionsPage = walkSessionRef ? await page(ctx, "/work/sessions") : { status: 0, text: "" };
    claimLive("run/legs/walk-session",
      composerProjects.includes(walkProjectId) && /Session created/u.test(composerSaid) && !!walkSessionRef
        && walkSession.session_ref === walkSessionRef && !!operatorRef && walkSession.owner_ref === operatorRef && walkSession.project_ref === walkProjectId
        && walkSession.initial_input_projection?.content === instruction && walkSession.lifecycle_state === "provisioned"
        && /^environment:\S+$/u.test(walkSession.environment_ref || "") && composerSaid.includes(walkSession.environment_ref)
        && !!provisionReceipt && composerSaid.includes(provisionReceipt)
        && Array.isArray(walkSession.authority_profile?.connection_refs) && walkSession.authority_profile.connection_refs.length === 0
        && sessionsPage.status === 200 && sessionsPage.text.includes(`data-ioi-work-row="${walkSessionRef}"`),
      `${composerError ? `composer: ${composerError} · ` : ""}launcher offers the walk's project ${composerProjects.includes(walkProjectId)} · ${(composerSaid.split("\n")[0] || "no result").slice(0, 60)} ${walkSessionRef || ""} · record owner ${walkSession.owner_ref === operatorRef ? "the operator" : walkSession.owner_ref || "none"} project ${walkSession.project_ref || "none"} instruction ${walkSession.initial_input_projection?.content === instruction} ${walkSession.lifecycle_state || "no state"} · connections ${JSON.stringify(walkSession.authority_profile?.connection_refs ?? null)} · Work / Sessions lists it ${sessionsPage.text.includes(`data-ioi-work-row="${walkSessionRef || "@@"}"`)}`);
    // HAND-OFF 4 → 5 (connections), judged on the composer the session was started from: THIS walk's
    // connection is there, withheld — disabled with its reason — and the daemon holds it bound (its
    // token sealed) with no active standing lease; the session names no connection.
    claimLive("limits/handoff/unleased-connection-withheld",
      addedConnection.status === 302 && String(addedConnection.headers.location || "") === "/__ioi/connections"
        && !!walkConnector && walkConnector.auth_posture === "token-lease:bound" && walkConnector.standing_lease?.status !== "active"
        && !!composerConnection && composerConnection.tickable === false && /no limits set/u.test(composerConnection.text)
        && Array.isArray(walkSession.authority_profile?.connection_refs) && !walkSession.authority_profile.connection_refs.includes(walkConnectionRef),
      `add ${addedConnection.status} → ${String(addedConnection.headers.location || "no location").slice(0, 60)} · connector ${walkConnector ? `${walkConnector.connector_id} ${walkConnector.auth_posture} lease ${walkConnector.standing_lease?.status || "none"}` : "absent"} · composer row ${composerConnection ? `tickable ${composerConnection.tickable} '${composerConnection.text.replace(/\s+/gu, " ").trim().slice(0, 80)}'` : "absent"}`);
    await probesOf("run");
    // HAND-OFF 5 → 6: THIS walk's run. Run now on the automation's own page; the automation's run
    // history names the canonical run it admitted, and Work lists that run by its own ref.
    const automationIdOfWalk = (automationAt.match(/auto_[0-9a-f]+/u) || [])[0] || "";
    const runAction = `/__ioi/automations/${automationIdOfWalk}/run`;
    const promptedRun = automationIdOfWalk
      ? await submitRenderedForm(ctx, { id: "run-now", page: await page(ctx, automationAt), from: automationAt, action: runAction, fields: {} })
      : { status: 0, headers: {}, text: "" };
    // HAND-OFF 4 → 5: THIS walk's checkpoint pauses its Run now behind the prompt; the prompt's own form
    // answers it, and only then does the run happen.
    const paused = promptedRun.status === 200 && String(promptedRun.text || "").includes('data-justification-prompt="1"') && String(promptedRun.text || "").includes("Why run this now?");
    const ranNow = paused
      ? await submitRenderedForm(ctx, { id: "run-now-justified", page: promptedRun, from: `${automationAt} → prompt`, action: runAction, fields: { justify__0__text: `walk ${vars.tag} — the done-bar walk runs its automation` } })
      : promptedRun;
    const runHistory = automationIdOfWalk ? await page(ctx, automationAt) : { text: "" };
    const walkRunRef = unesc((runHistory.text.match(/data-canonical-run="(automation-run:\/\/[^"]+)"/u) || [])[1] || "");
    const workHistory = await page(ctx, "/work/history");
    const workRowAt = walkRunRef ? workHistory.text.indexOf(`data-ioi-work-row="${walkRunRef}"`) : -1;
    const walkRecords = ((await read(ctx, "/v1/hypervisor/justification-records?kind=automation.run_now")).json || {}).justification_records || [];
    const walkRecord = walkRecords.find((r) => (r.checkpointed_item_refs || []).includes(`automation://${automationIdOfWalk}`)) || null;
    const reviewPage = await page(ctx, "/governance/limits?tab=checkpoints&view=review");
    claimLive("limits/handoff/walk-checkpoint-gates-run",
      paused && [302, 303].includes(ranNow.status) && !!walkRecord && walkRecord.justification?.text?.startsWith(`walk ${vars.tag}`)
        && reviewPage.status === 200 && reviewPage.text.includes(`data-limits-record="${walkRecord.record_id}"`),
      `prompted ${paused} · justified run ${ranNow.status} · record ${walkRecord?.record_id || "none"} · Review lists it ${walkRecord ? reviewPage.text.includes(walkRecord.record_id) : false}`);
    claimLive("run/handoff/walk-run-in-work",
      [302, 303].includes(ranNow.status) && !!walkRunRef && workHistory.status === 200 && workRowAt >= 0,
      `run now ${ranNow.status} · run ${walkRunRef || "none named on the automation's history"} · /work/history ${workHistory.status} row ${workRowAt >= 0}`);
    // WP-B — THIS walk's run is THE System's, read from daemon truth: the automation is stored tied to
    // the System; the canonical run's exact installation revision is scoped to it (and its hash is the
    // one the run's resolution froze); the execution the run admitted ran on an environment; the run's
    // Work row names the System; the projection narrowed to the System returns it; and the System's
    // Operate mode lists it.
    const walkRunTail = walkRunRef.replace(/^automation-run:\/\//u, "");
    const canonicalRun = walkRunTail ? ((((await read(ctx, `/v1/hypervisor/automation-runs/${encodeURIComponent(walkRunTail)}`)).json || {}).automation_run) || {}) : {};
    const walkInstallation = canonicalRun.automation_installation_binding_revision_ref
      ? ((((await read(ctx, "/v1/hypervisor/automation-installations")).json || {}).automation_installation_bindings || []).find((b) => b.revision_ref === canonicalRun.automation_installation_binding_revision_ref) || null)
      : null;
    const runExecutionId = (String(canonicalRun.activation_event_ref || "").match(/\/run-now\/(aex_[0-9a-f]+)$/u) || [])[1] || "";
    const runExecution = automationIdOfWalk && runExecutionId
      ? ((((await read(ctx, `/v1/hypervisor/automations/${automationIdOfWalk}/runs`)).json || {}).runs || []).find((r) => r.execution_id === runExecutionId) || null)
      : null;
    claimLive("run/legs/automation-installation",
      systemOffered && walkAutomationRecord.system_ref === ids.systemId
        && !!walkInstallation && walkInstallation.scope_ref === ids.systemId && walkInstallation.enabled === true
        && canonicalRun.automation_installation_binding_hash === walkInstallation.binding_hash
        && !!runExecution && !!runExecution.environment_id,
      `form offers the System ${systemOffered} · automation tied to ${walkAutomationRecord.system_ref || "none"} · installation ${walkInstallation ? `${walkInstallation.revision_ref} scoped ${walkInstallation.scope_ref}` : "none"} · execution ${runExecutionId || "none"} on ${runExecution?.environment_id || "no environment"}`);
    const walkWorkRow = walkRunRef ? ((((await read(ctx, `/v1/hypervisor/work-projection?view=history&subject_ref=${encodeURIComponent(walkRunRef)}`)).json || {}).rows || [])[0] || null) : null;
    const systemLane = (((await read(ctx, `/v1/hypervisor/work-projection?view=history&system_ref=${encodeURIComponent(ids.systemId)}`)).json || {}).rows || []);
    claimLive("run/handoff/run-names-system",
      !!walkWorkRow && walkWorkRow.subject_ref === walkRunRef && walkWorkRow.system_ref === ids.systemId
        && systemLane.some((r) => r.subject_ref === walkRunRef) && systemLane.every((r) => r.system_ref === ids.systemId),
      `Work row ${walkWorkRow ? `names ${walkWorkRow.system_ref || "no System"}` : "absent"} · the System's lane ${systemLane.length} row(s), holds the run ${systemLane.some((r) => r.subject_ref === walkRunRef)}`);
    const operateWork = await page(ctx, `/systems/${vars.system}/operate`);
    claimLive("run/legs/run-the-system",
      operateWork.status === 200 && operateWork.text.includes(`data-system-workspace-id="${ids.systemId}"`) && !!walkRunRef
        && operateWork.text.includes(`data-system-work="${ids.systemId}"`) && operateWork.text.includes(`data-system-work-row="${walkRunRef}"`),
      `operate ${operateWork.status} · lists the run ${walkRunRef ? operateWork.text.includes(`data-system-work-row="${walkRunRef}"`) : "no run"}${operateWork.text.includes('data-system-work-unavailable="1"') ? " · work unreadable" : ""}`);
    // ==== STEP 6 — OBSERVE =========================================================================
    // THIS walk's issue, from Issues' New dialog, naming the System — picked from the dialog's own
    // Systems group (WP-B), and read back from the daemon's issue record.
    const issueName = `issue-${vars.tag}`;
    const issueRoute = "/__ioi/missions/incidents?new=1";
    const issueDialog = await page(ctx, issueRoute);
    const issueOffersSystem = issueDialog.text.includes('<optgroup label="Systems">') && !!renderedForm(issueDialog.text, "/__ioi/missions/incidents/new")?.options.affected?.has(ids.systemId);
    const filed = await submitRenderedForm(ctx, { id: "issue", page: issueDialog, from: issueRoute, action: "/__ioi/missions/incidents/new",
      fields: { title: issueName, affected: ids.systemId } });
    const openIssues = await page(ctx, "/operations/issues?lane=open");
    claimLive("observe/legs/walk-issue",
      [200, 302, 303].includes(filed.status) && !/Not filed/u.test(filed.text) && openIssues.status === 200 && openIssues.text.includes(issueName),
      `filed ${filed.status}${/Not filed/u.test(filed.text) ? " (Not filed)" : ""} · open lane lists it ${openIssues.text.includes(issueName)}`);
    const issueTail = outcomeOf(filed).q.get("issue") || "";
    const issueRecord = issueTail ? ((((await read(ctx, `/v1/hypervisor/support-incidents/${encodeURIComponent(issueTail)}`)).json || {}).incident) || {}) : {};
    const issueAffects = Array.isArray(issueRecord.affected?.object_refs) ? issueRecord.affected.object_refs : [];
    claimLive("observe/legs/issue-subject-system",
      issueOffersSystem && filed.status === 303 && issueRecord.title === issueName && issueAffects.includes(ids.systemId),
      `dialog offers the System ${issueOffersSystem} · filed ${filed.status} ${issueTail || "no issue"} · record affects ${issueAffects.join(", ") || "nothing"}`);
    // THIS walk's health check on its System, from Operations / Health's New check form (ADR 0056 P2):
    // the probe runs `true` in the environment THIS walk's run used, Evaluate now admits its result, and
    // the System's Overview lists the check by its own name with that result's outcome.
    const walkRuns = automationIdOfWalk ? (((await read(ctx, `/v1/hypervisor/automations/${automationIdOfWalk}/runs`)).json || {}).runs || []) : [];
    const walkEnvRef = walkRuns[0]?.environment_id ? `environment://${walkRuns[0].environment_id}` : "";
    const healthName = `health-${vars.tag}`;
    const healthRoute = "/operations/health";
    const declaredCheck = outcomeOf(await submitRenderedForm(ctx, { id: "health-check", page: await page(ctx, healthRoute), from: healthRoute, action: "/__ioi/operations/health/new",
      fields: { display_name: healthName, target: ids.systemId, check_kind: "command_exit", environment_ref: walkEnvRef, command: "true" } }));
    const walkCheckId = declaredCheck.q.get("check") || "";
    const evaluatedCheck = walkCheckId
      ? outcomeOf(await submitRenderedForm(ctx, { id: "health-evaluate", page: await page(ctx, healthRoute), from: healthRoute, action: "/__ioi/operations/health/evaluate", fields: {} }))
      : { status: 0, q: new URLSearchParams() };
    const overview = await page(ctx, `/systems/${vars.system}`);
    const healthRowAt = walkCheckId ? overview.text.indexOf(`data-target-health-check="health-check://${walkCheckId}"`) : -1;
    const healthRow = healthRowAt >= 0 ? overview.text.slice(healthRowAt, overview.text.indexOf("</tr>", healthRowAt)) : "";
    claimLive("observe/legs/walk-health",
      declaredCheck.status === 303 && declaredCheck.q.get("ok") === "1" && /^hc_[0-9a-f]+$/u.test(walkCheckId)
        && evaluatedCheck.q.get("check") === walkCheckId && /^Passed/u.test(evaluatedCheck.q.get("note") || "")
        && overview.status === 200 && healthRow.includes(healthName) && healthRow.includes('data-health-outcome="passed"'),
      `declare ${declaredCheck.status} ${walkCheckId || declaredCheck.q.get("note") || "no check"} · evaluate ${evaluatedCheck.status} ${evaluatedCheck.q.get("note") || ""} · System overview row ${healthRowAt >= 0} passed ${healthRow.includes('data-health-outcome="passed"')}`);
    // STEP 3 (continued) — THIS walk's function, through Ontology / Functions' own forms, tested in the
    // environment the walk's run used (so it is measured here, after the run).
    const fnName = `fn${vars.tag}`;
    const functionsRoute = "/ontology/functions";
    const declaredFn = outcomeOf(await submitRenderedForm(ctx, { id: "function", page: await page(ctx, functionsRoute), from: functionsRoute, action: "/__ioi/ontology/functions/new",
      fields: { display_name: fnName, api_name: fnName, version: "1.0.0", input_name_0: "amount", input_type_0: "integer", input_required_0: "on", output_type: "integer", runtime: "python3",
        source: "import json, sys\nprint(json.dumps(json.load(sys.stdin)['amount'] + 1))\n" } }));
    const walkFnId = declaredFn.q.get("function") || "";
    const fnRoute = `${functionsRoute}?function=${walkFnId}`;
    const testedFn = walkFnId
      ? outcomeOf(await submitRenderedForm(ctx, { id: "function-test", page: await page(ctx, fnRoute), from: fnRoute, action: "/__ioi/ontology/functions/test", fields: { environment_ref: walkEnvRef, in_amount: "41" } }))
      : { status: 0, q: new URLSearchParams() };
    const releasedFn = walkFnId
      ? outcomeOf(await submitRenderedForm(ctx, { id: "function-release", page: await page(ctx, fnRoute), from: fnRoute, action: "/__ioi/ontology/functions/release", fields: {} }))
      : { status: 0, q: new URLSearchParams() };
    const fnList = await page(ctx, functionsRoute);
    const fnRowAt = walkFnId ? fnList.text.indexOf(`data-fn-row="function://${walkFnId}"`) : -1;
    const fnRow = fnRowAt >= 0 ? fnList.text.slice(fnRowAt, fnList.text.indexOf("</tr>", fnRowAt)) : "";
    claimLive("data/legs/walk-function",
      declaredFn.status === 303 && declaredFn.q.get("ok") === "1" && /^fn_[0-9a-f]{16}$/u.test(walkFnId)
        && /^Passed/u.test(testedFn.q.get("note") || "") && /Output: 42/u.test(testedFn.q.get("note") || "")
        && releasedFn.q.get("ok") === "1" && fnRow.includes(fnName) && fnRow.includes('data-fn-tool-operable="1"'),
      `declare ${declaredFn.status} ${walkFnId || declaredFn.q.get("note") || "no function"} · test ${testedFn.q.get("note") || testedFn.status} · release ${releasedFn.q.get("note") || releasedFn.status} · listed ${fnRowAt >= 0} operable ${fnRow.includes('data-fn-tool-operable="1"')}`);
    // STEP 5 (continued) — an automation step that runs THIS walk's released function by exact revision
    // (ADR 0056 P3 cut 3), in THIS walk's project. The walk's checkpoint gates every Run now, so this one
    // is justified too.
    const fnAutoName = `autofn-${vars.tag}`;
    const fnRevisionRef = walkFnId ? `function://${walkFnId}/revision/1` : "";
    const fnAutomationForm = walkFnId ? await automationFormPage() : null;
    const createdFnAuto = walkFnId
      ? await submitRenderedForm(ctx, { id: "function-automation", page: fnAutomationForm.page, from: fnAutomationForm.at, action: "/__ioi/automations",
        fields: { project_ref: walkProjectId, name: fnAutoName, step_kind: "function", step_function: fnRevisionRef, step_body: '{"amount": 99}' } })
      : { status: 0, headers: {}, text: "" };
    const fnAutoAt = String(createdFnAuto.headers?.location || "");
    const fnAutoId = (fnAutoAt.match(/auto_[0-9a-f]+/u) || [])[0] || "";
    const fnRunAction = `/__ioi/automations/${fnAutoId}/run`;
    const fnPrompted = fnAutoId
      ? await submitRenderedForm(ctx, { id: "function-run-now", page: await page(ctx, fnAutoAt), from: fnAutoAt, action: fnRunAction, fields: {} })
      : { status: 0, headers: {}, text: "" };
    const fnPaused = fnPrompted.status === 200 && String(fnPrompted.text || "").includes('data-justification-prompt="1"');
    const fnRanNow = fnPaused
      ? await submitRenderedForm(ctx, { id: "function-run-now-justified", page: fnPrompted, from: `${fnAutoAt} → prompt`, action: fnRunAction, fields: { justify__0__text: `walk ${vars.tag} — the walk runs its function as an automation step` } })
      : fnPrompted;
    const fnExec = fnAutoId ? ((((await read(ctx, `/v1/hypervisor/automations/${fnAutoId}/runs`)).json || {}).runs || [])[0] || {}) : {};
    const fnStepResult = (fnExec.step_results || [])[0] || {};
    claimLive("run/legs/walk-function-step",
      createdFnAuto.status === 302 && !!fnAutoId && [302, 303].includes(fnRanNow.status) && fnExec.status === "done"
        && fnStepResult.kind === "function" && fnStepResult.output?.outcome === "passed" && fnStepResult.output?.output === 100
        && fnStepResult.output?.function_revision_ref === fnRevisionRef,
      `create ${createdFnAuto.status} ${fnAutoId || "no automation"} · prompted ${fnPaused} · run ${fnRanNow.status} · ${fnExec.status || "no execution"} ${fnStepResult.output?.outcome || fnStepResult.output?.error || ""} output ${JSON.stringify(fnStepResult.output?.output)}`);
    await probesOf("observe");
    // HAND-OFF 6 → 7: from THIS walk's Work row, its own link opens the run's receipts (the execution's
    // run timeline), found by the run's own id — the execution the automation's history recorded.
    const workRow = workRowAt >= 0 ? workHistory.text.slice(workRowAt, workHistory.text.indexOf("</tr>", workRowAt)) : "";
    const workRowLink = unesc((workRow.match(/<a href="([^"]+)"/u) || [])[1] || "");
    const runLinkHop = workRowLink ? await httpCall(ctx.serve, "GET", workRowLink, { cookie: ctx.cookie, accept: "text/html" }) : { status: 0, headers: {} };
    const receiptsAt = String(runLinkHop.headers?.location || "");
    const receiptsPage = receiptsAt ? await page(ctx, receiptsAt) : { status: 0, text: "" };
    const walkExecution = (runHistory.text.match(/<code>(aex_[0-9a-f]+)<\/code>/u) || [])[1] || "";
    claimLive("observe/handoff/walk-observed-to-receipts",
      !!workRowLink && runLinkHop.status === 302 && receiptsAt === `/__ioi/run-timeline/${walkExecution}` && receiptsPage.status === 200 && !!walkExecution && receiptsPage.text.includes(walkExecution),
      `row link ${workRowLink || "none"} → ${runLinkHop.status} ${receiptsAt || ""} · receipts page ${receiptsPage.status} names ${walkExecution || "no execution"} ${receiptsPage.text.includes(walkExecution || "@@")}`);

    // ==== STEP 7 — PROVENANCE ======================================================================
    const projection = (await read(ctx, `${GENESIS_API}/projection?view=compact&system_id=${encodeURIComponent(ids.systemId)}`)).json || {};
    const row = (projection.systems || []).find((s) => s.system_id === ids.systemId) || null;
    const chainRoot = row?.canonical_roots?.chain_root || "";
    const latestReceipt = row?.evidence_refs?.latest_receipt_ref || "";
    const evidencePage = await page(ctx, `/systems/${vars.system}/evidence`);
    claimLive("provenance/legs/system-evidence",
      evidencePage.status === 200 && evidencePage.text.includes('data-system-workspace-mode="evidence"') && !!chainRoot && evidencePage.text.includes(chainRoot)
        && !!latestReceipt && evidencePage.text.includes(latestReceipt),
      `evidence ${evidencePage.status} · chain root ${chainRoot ? "known" : "absent"} · latest receipt ${latestReceipt ? "known" : "absent"}`);
    // WP-B — the System's run receipts: the Evidence mode lists THIS walk's run (the Work projection
    // narrowed by system_ref), and the row's own link opens that run's timeline, named by its execution.
    const evidenceRowAt = walkRunRef ? evidencePage.text.indexOf(`data-system-work-row="${walkRunRef}"`) : -1;
    const evidenceRow = evidenceRowAt >= 0 ? evidencePage.text.slice(evidenceRowAt, evidencePage.text.indexOf("</tr>", evidenceRowAt)) : "";
    const evidenceLink = unesc((evidenceRow.match(/<a href="([^"]+)"/u) || [])[1] || "");
    const evidenceHop = evidenceLink ? await httpCall(ctx.serve, "GET", evidenceLink, { cookie: ctx.cookie, accept: "text/html" }) : { status: 0, headers: {} };
    const evidenceReceiptsAt = String(evidenceHop.headers?.location || "");
    const evidenceReceipts = evidenceReceiptsAt ? await page(ctx, evidenceReceiptsAt) : { status: 0, text: "" };
    claimLive("provenance/legs/ledger-by-system",
      evidencePage.status === 200 && evidencePage.text.includes(`data-system-work="${ids.systemId}"`) && evidenceRowAt >= 0 && !!evidenceLink
        && evidenceHop.status === 302 && !!walkExecution && evidenceReceiptsAt === `/__ioi/run-timeline/${walkExecution}`
        && evidenceReceipts.status === 200 && evidenceReceipts.text.includes(walkExecution),
      `evidence lists the run ${evidenceRowAt >= 0} · row link ${evidenceLink || "none"} → ${evidenceHop.status} ${evidenceReceiptsAt || ""} · receipts name ${walkExecution || "no execution"} ${evidenceReceipts.text.includes(walkExecution || "@@")}`);
    await probesOf("provenance");

    // ==== STEP 8 — EVALUATE ========================================================================
    // THIS walk's suite, through the one declaration form Evaluations renders today.
    const suiteName = `suite-${vars.tag}`;
    const evaluationsRoute = "/__ioi/evaluations";
    const declared = outcomeOf(await submitRenderedForm(ctx, { id: "suite", page: await page(ctx, evaluationsRoute), from: evaluationsRoute, action: "/__ioi/evaluations",
      fields: { name: suiteName, subject_scope: "failed_run", consent_requirements: "org_policy" } }));
    const suites = await page(ctx, "/__ioi/evaluations/evalsuites");
    claimLive("evaluate/legs/walk-suite",
      declared.redirected && !declared.refused && suites.status === 200 && suites.text.includes(suiteName),
      `declare ${declared.status}${declared.refused ? ` refused ${declared.refused.slice(0, 80)}` : ""} · the suites list it ${suites.text.includes(suiteName)}`);
    // ==== STEP 9 — IMPROVE =========================================================================
    // THIS walk's improvement, through Agent Studio's own forms. A person records two corrections from
    // the Memory form; the daemon's outcome mining derives a candidate from exactly those entries, and
    // the page renders its Propose form with the candidate as the daemon mined it (a hidden field this
    // walk never fills). The proposal's id is the daemon's, so it is found by its evidence. Simulate,
    // Approve and Apply are its own forms; each outcome is read back from the improvement plane.
    const agentStudioRoute = "/__ioi/agent-studio";
    const correctionTitle = `imp-${vars.tag} correction`;
    const recordedCorrections = [];
    for (const n of [1, 2]) {
      recordedCorrections.push(await submitRenderedForm(ctx, { id: `correction-${n}`, page: await page(ctx, agentStudioRoute), from: agentStudioRoute, action: "/__ioi/agent-studio/intel/memory",
        fields: { title: `${correctionTitle} ${n}`, body: `walk ${vars.tag}: the walk's own correction ${n}`, entry_kind: "correction", sensitivity: "normal" } }));
    }
    const walkCorrections = ((((await read(ctx, "/v1/hypervisor/memory-entries")).json || {}).entries || [])
      .filter((e) => String(e.title || "").startsWith(`${correctionTitle} `) && e.entry_kind === "correction" && e.status === "active")).map((e) => e.entry_ref);
    const improvementsNow = async () => ((((await read(ctx, "/v1/hypervisor/intelligence/improvement-proposals")).json || {}).proposals) || []);
    const ofWalk = (p) => walkCorrections.length === 2 && walkCorrections.every((r) => (p.evidence_refs || []).includes(r));
    const proposedImp = await submitRenderedForm(ctx, { id: "improvement-propose", page: await page(ctx, agentStudioRoute), from: agentStudioRoute, action: "/__ioi/agent-studio/improvements/propose", fields: {} });
    const proposedRecord = (await improvementsNow()).find(ofWalk) || {};
    const impId = proposedRecord.improvement_id || "";
    const improvementAct = async (id, verb) => (impId
      ? submitRenderedForm(ctx, { id, page: await page(ctx, agentStudioRoute), from: agentStudioRoute, action: `/__ioi/agent-studio/improvements/${encodeURIComponent(impId)}/${verb}`, fields: {} })
      : { status: 0, headers: {}, text: "" });
    const simulatedImp = await improvementAct("improvement-simulate", "simulate");
    const simulatedRecord = (await improvementsNow()).find((p) => p.improvement_id === impId) || {};
    const offersGovernance = (await page(ctx, agentStudioRoute)).text.includes(`/improvements/${impId}/governance/request-approval`);
    const approvedImp = await improvementAct("improvement-approve", "approve");
    const approvedRecord = (await improvementsNow()).find((p) => p.improvement_id === impId) || {};
    const appliedImp = await improvementAct("improvement-apply", "apply");
    const appliedRecord = (await improvementsNow()).find((p) => p.improvement_id === impId) || {};
    const walkSkill = appliedRecord.applied_ref
      ? ((((await read(ctx, "/v1/hypervisor/skill-entries")).json || {}).skills || []).find((s) => s.skill_ref === appliedRecord.applied_ref) || null) : null;
    const improvementInbox = impId ? await page(ctx, "/__ioi/improvement/changes?lane=active&filter=all") : { status: 0, text: "" };
    claimLive("improve/legs/walk-improvement",
      recordedCorrections.every((r) => r.status === 302) && walkCorrections.length === 2
        && proposedImp.status === 302 && !!impId && proposedRecord.state === "pending" && proposedRecord.proposal_kind === "skill_improvement" && proposedRecord.signal === "repeated_manual_correction"
        && simulatedImp.status === 302 && !!simulatedRecord.latest_simulation_ref && simulatedRecord.latest_simulation_high_impact === false && simulatedRecord.gate?.posture === "low_impact" && !offersGovernance
        && approvedImp.status === 302 && approvedRecord.state === "approved" && !!operatorRef && approvedRecord.reviewed_by_ref === operatorRef
        && appliedImp.status === 302 && appliedRecord.state === "applied" && String(appliedRecord.applied_ref || "").startsWith("skill-entry://")
        && (appliedRecord.receipt_refs || []).includes(`receipt://hypervisor/improvement/${impId}`)
        && !!walkSkill && walkSkill.quality_state === "accepted" && walkCorrections.every((r) => (walkSkill.source_refs || []).includes(r))
        && improvementInbox.status === 200 && improvementInbox.text.includes(appliedRecord.proposal_ref || "@@"),
      `corrections ${recordedCorrections.map((r) => r.status).join("/")} held ${walkCorrections.length} · propose ${proposedImp.status} ${impId || "no proposal from the walk's corrections"} ${proposedRecord.state || ""} · simulate ${simulatedImp.status} ${simulatedRecord.gate?.posture || "no posture"} high-impact ${simulatedRecord.latest_simulation_high_impact} governance offered ${offersGovernance} · approve ${approvedImp.status} ${approvedRecord.state || ""} by ${approvedRecord.reviewed_by_ref === operatorRef ? "the operator" : approvedRecord.reviewed_by_ref || "nobody"} · apply ${appliedImp.status} ${appliedRecord.state || ""} ${appliedRecord.applied_ref || ""} · skill ${walkSkill ? `${walkSkill.quality_state} from ${(walkSkill.source_refs || []).length} source(s)` : "absent"} · inbox lists it ${improvementInbox.text.includes(appliedRecord.proposal_ref || "@@")}`);
    await probesOf("improve");
    // ==== STEP 10 — RELEASE ========================================================================
    // THIS walk's package, built from step 3's ontology through the form each surface renders: a type,
    // a PUBLISHED revision (the draft is mutable; a descriptor binds only an admitted revision), a
    // descriptor over it, a manifest over the ontology and the descriptor, a draft app over both, a
    // candidate, a release. The refs a person does not type are read off the surface that minted them.
    const ontId = ontology.q.get("record") || "";
    const typeRoute = `/__ioi/ontology/manager?ontology=${encodeURIComponent(ontId)}&section=create&newKind=object-type`;
    const typed = outcomeOf(await submitRenderedForm(ctx, { id: "object-type", page: await page(ctx, typeRoute), from: typeRoute, action: "/__ioi/ontology/manager/actions/upsert-object-type", fields: { def_id: "loan", name: "Loan" } }));
    const historyRoute = `/__ioi/ontology/manager?ontology=${encodeURIComponent(ontId)}&section=history`;
    const published = outcomeOf(await submitRenderedForm(ctx, { id: "publish", page: await page(ctx, historyRoute), from: historyRoute, action: `/__ioi/ontology/manager/actions/publish-revision?ontology=${ontId}`, fields: {} }));
    const revisionRef = published.q.get("record") || "";
    const studioRoute = "/__ioi/studio/workbench?view=descriptors";
    const described = outcomeOf(await submitRenderedForm(ctx, { id: "descriptor", page: await page(ctx, studioRoute), from: studioRoute, action: "/__ioi/studio/workbench/actions/create-descriptor",
      fields: { display_name: `sd-${vars.tag}`, surface_ref: `surface://${vars.tag}/lending`, composition_pattern: "domain_app", ontology_refs: revisionRef,
        canonical_object_model_refs: `object-model://${vars.tag}/lending/loan`, policy_bound_data_view_refs: `view://${vars.tag}/lending/reviewer`, authority_requirement_refs: "scope:lending.review",
        daemon_api_refs: "api://v1/hypervisor/odk", receipt_obligations: `receipt://${vars.tag}/lending/decision`, conformance_profile_refs: `profile://${vars.tag}/lending/v1` } }));
    const sdRef = described.q.get("record") ? `surface-descriptor://${described.q.get("record")}` : "";
    const ontRef = (await read(ctx, `/v1/hypervisor/odk/domain-ontologies/${encodeURIComponent(ontId)}`)).json?.ontology?.ref || "";
    const manifestRoute = "/__ioi/odk/manifests/new";
    const manifestPage = await page(ctx, manifestRoute);
    const manifestOffers = !!ontRef && !!sdRef && manifestPage.text.includes(`value="${ontRef}"`) && manifestPage.text.includes(`value="${sdRef}"`);
    const manifested = await submitRenderedForm(ctx, { id: "manifest", page: manifestPage, from: manifestRoute, action: "/__ioi/odk/manifests", fields: { name: `man-${vars.tag}`, ontology_refs: ontRef, surface_descriptor_refs: sdRef } });
    const manifestId = (String(manifested.headers.location || "").match(/^\/__ioi\/odk\/manifests\/(odk_[0-9a-f]+)/u) || [])[1] || "";
    const appRoute = "/__ioi/domain-apps/new";
    const apped = await submitRenderedForm(ctx, { id: "domain-app", page: await page(ctx, appRoute), from: appRoute, action: "/__ioi/domain-apps", fields: { name: `app-${vars.tag}`, surface_descriptor_ref: sdRef, odk_manifest_ref: manifestId ? `odk://${manifestId}` : "" } });
    const appId = (String(apped.headers.location || "").match(/^\/__ioi\/domain-apps\/(dapp_[0-9a-f]+)/u) || [])[1] || "";
    const packageName = `pkg-${vars.tag}`;
    const registryRoute = "/__ioi/packages/registry";
    const candidate = outcomeOf(await submitRenderedForm(ctx, { id: "package", page: await page(ctx, registryRoute), from: registryRoute, action: "/__ioi/packages/registry/actions/admit-candidate", fields: { package_id: packageName, domain_app_ref: `domain-app://${appId}` } }));
    const packageRoute = `/__ioi/packages/registry?pkg=${packageName}`;
    const released = outcomeOf(await submitRenderedForm(ctx, { id: "release", page: await page(ctx, packageRoute), from: packageRoute, action: `/__ioi/packages/registry/${packageName}/cut-release`, fields: { object_contract_refs: `object-model://${vars.tag}/lending/loan` } }));
    const packagesPage = await page(ctx, "/packages");
    const stage = (name, o) => `${name} ${o.refused ? `refused ${o.refused}` : o.q?.get("acted") || o.status}`;
    claimLive("release/legs/walk-package",
      typed.redirected && !typed.refused && published.q.get("acted") === "publish-revision" && /\/revision\/1$/u.test(revisionRef)
        && described.q.get("acted") === "create-descriptor" && manifestOffers && manifested.status === 302 && !!manifestId
        && apped.status === 302 && !!appId && candidate.q.get("acted") === "admit-candidate" && released.q.get("acted") === "cut-release"
        && packagesPage.status === 200 && packagesPage.text.includes(packageName),
      `${stage("type", typed)} · ${stage("publish", published)} ${revisionRef || "no revision"} · ${stage("descriptor", described)} · manifest ${manifested.status} ${manifestId || "none"} (offers ${manifestOffers}) · app ${apped.status} ${appId || "none"} · ${stage("candidate", candidate)} · ${stage("release", released)} · /packages lists it ${packagesPage.text.includes(packageName)}`);

    // ==== STEP 11 — OPERATE ========================================================================
    const operate = await page(ctx, `/systems/${vars.system}/operate`);
    claimLive("operate/legs/operate-mode",
      operate.status === 200 && operate.text.includes('data-system-workspace-mode="operate"') && operate.text.includes(`data-system-workspace-id="${ids.systemId}"`) && operate.text.includes('data-system-topology="1"'),
      `operate ${operate.status}`);

    // ---- TERMINAL: restart the plane on its own data directory and re-read the System. ----------------
    const overviewRoute = `/systems/${vars.system}`;
    const before = await page(ctx, overviewRoute);
    await plane.stop(); // a plane handed its data directory keeps it on stop: this gate owns and removes it
    plane = null;
    plane2 = await startIsolatedPlane({ serve: true, dataDir, env: planeEnv, baseEnv: cleanEnv });
    if (!plane2) throw new Error("the restarted plane did not boot");
    ctx.serve = plane2.serveUrl;
    ctx.cache.clear();
    const systemsAfter = await page(ctx, "/systems");
    const after = await page(ctx, overviewRoute);
    claimLive("operate/terminal/restart-reread",
      systemsAfter.status === 200 && systemsAfter.text.includes(`data-ioi-system="${ids.systemId}"`)
        && after.status === 200 && after.text.includes(`data-detail-system-id="${ids.systemId}"`)
        && !!chainRoot && before.text.includes(chainRoot) && after.text.includes(chainRoot),
      `/systems ${systemsAfter.status} · overview ${before.status} → ${after.status}`);
  } catch (error) {
    // Before the operator exists this is the plane's ownership failing; after, it is the walk. Either way
    // every live leg it did not reach is red in the verdict (unreached), never read as green.
    setup.push(`${reached ? "walk" : "setup"}: ${String(error.message).split("\n")[0].slice(0, 240)}`);
  } finally {
    try { await ctx.browser?.close(); } catch { /* gone */ }
    try { await plane?.stop(); } catch { /* gone */ }
    try { await plane2?.stop(); } catch { /* gone */ }
    try { await ctx.resolver?.stop(); } catch { /* gone */ }
    try { if (dataDir) fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  return { setup, claims, walk: ctx.walk, vars, reached, seconds: Math.round((Date.now() - started) / 1000) };
}

// ---- COMPOSE ------------------------------------------------------------------------------------
// The env discipline of scripts/lib/acceptance-journey.mjs (FIXTURE_FREE_ENV): every composed gate boots
// its own daemon, so nothing may point it at a shared daemon, a replay server or a fixture. Sign-in is off
// for the composed gates exactly as CI runs them (ci.yml's top-level env); the gates that measure sign-in
// turn it back on for their own serve.
const FIXTURE_FREE_ENV = Object.freeze({ IOI_HYPERVISOR_DAEMON_URL: "", IOI_DAEMON_URL: "", IOI_HYPERVISOR_DAEMON_ADDR: "", IOI_PRODUCT_UI_REPLAY: "", IOI_ACCEPTANCE_FIXTURES: "disabled" });

function basis() {
  const git = (args) => spawnSync("git", args, { cwd: ROOT, encoding: "utf8" }).stdout || "";
  return { head: git(["rev-parse", "--short", "HEAD"]).trim(), dirty: git(["status", "--porcelain"]).trim().length > 0 };
}

// A bounded gate dies as a TREE (the R-15 rule the acceptance harness follows): its own process group,
// SIGTERM at the deadline so it reaps what it owns, SIGKILL after a grace, and once more after any exit.
let activeGroup = null;
process.on("exit", () => { if (activeGroup) { try { process.kill(-activeGroup, "SIGKILL"); } catch { /* gone */ } } });

function runComposed(entry, start, logDir, censusDir) {
  const cmd = entry.pkg === "app" ? ["npm", "run", "-s", entry.script, "--workspace=@ioi/hypervisor-app"] : ["npm", "run", "-s", entry.script];
  const began = Date.now();
  return new Promise((resolve) => {
    let out = "", timedOut = false, settled = false;
    const child = spawn(cmd[0], cmd.slice(1), {
      cwd: ROOT, detached: true, stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, ...FIXTURE_FREE_ENV, IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_VERIFIER_CENSUS_DIR: censusDir },
    });
    activeGroup = child.pid;
    const keep = (d) => { out = (out + d).slice(-512 * 1024); };
    child.stdout.on("data", keep);
    child.stderr.on("data", keep);
    const kill = (signal) => { try { process.kill(-child.pid, signal); } catch { /* gone */ } };
    const deadline = setTimeout(() => { timedOut = true; kill("SIGTERM"); setTimeout(() => kill("SIGKILL"), 20_000).unref(); }, entry.minutes * 60_000);
    const finish = (status) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      kill("SIGKILL");
      activeGroup = null;
      const now = basis();
      try { fs.writeFileSync(path.join(logDir, `${entry.id}.log`), out); } catch { /* best effort */ }
      const lines = out.split("\n").map((l) => l.trim()).filter(Boolean);
      const summary = ([...lines].reverse().find((l) => /\b\d+\/\d+\b|^(PASS|FAIL|OK|VERDICT|===)/u.test(l)) || lines.at(-1) || "").slice(0, 200);
      resolve({ id: entry.id, command: cmd.join(" "), status, timedOut, seconds: Math.round((Date.now() - began) / 1000), basisMoved: now.head !== start.head || now.dirty !== start.dirty, summary });
    };
    child.on("error", () => finish(null));
    child.on("exit", (code) => finish(code));
  });
}

async function composeLeg() {
  const runs = {};
  if (NO_COMPOSE) return { runs, skipped: "--no-compose: every composed leg is UNMEASURED" };
  const start = basis();
  const logDir = path.join(ROOT, ".artifacts", "mvp-finish-line", `autonomous-system-journey-compose-${STAMP}`);
  fs.mkdirSync(logDir, { recursive: true });
  const censusDir = process.env.IOI_VERIFIER_CENSUS_DIR
    ? path.resolve(ROOT, process.env.IOI_VERIFIER_CENSUS_DIR)
    : path.join(ROOT, ".artifacts", "verifier-census", "journeys", "autonomous-system-journey");
  fs.mkdirSync(censusDir, { recursive: true });
  for (const entry of LIB.COMPOSE) {
    if (ONLY && !ONLY.has(entry.id)) continue;
    console.log(`# COMPOSE ${entry.id} — npm run ${entry.script}${entry.pkg === "app" ? " --workspace=@ioi/hypervisor-app" : ""} (≤ ${entry.minutes} min; ${entry.needs})`);
    const run = await runComposed(entry, start, logDir, censusDir);
    runs[entry.id] = run;
    console.log(`#   exit ${run.status}${run.timedOut ? " TIMED OUT" : ""}${run.basisMoved ? " BASIS MOVED" : ""} · ${run.summary} · ${run.seconds}s`);
  }
  return { runs, basis: start, logDir: path.relative(ROOT, logDir) };
}

// ---- run ----------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = pure;
  ok("PURE — the eleven steps are held in order with every leg live, composed, a named gap by code and plane, or a TODO; every non-terminal step judges its hand-off; the gap map's gaps, the workspace's gap markers, today's live legs and the composed gates are all still covered; and the verdict rules hold against planted tables and planted runs", pure.length === 0, pure.slice(0, 4).join(" ; "));
  const src = sourceFindings({ gate: readText(SELF_PATH), lib: readText(LIB_PATH) });
  evidence.source = src;
  ok("SOURCE — the LIVE leg runs its own plane on a fresh data directory with the sign-in gate on and the real wallet.network fixture, bootstraps its own operator through the first-run form, writes only through forms found on the rendered page, and the journey rules reach no browser, file, clock or network", src.length === 0, src.slice(0, 4).join(" ; "));
  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP, "package.json")),
    floors: readJson(FLOORS),
    ci: readText(path.join(ROOT, ".github", "workflows", "ci.yml")),
    floorsGate: readText(path.join(APP, "scripts", "check-verifier-floors.mjs")),
    compose: LIB.COMPOSE,
  });
  evidence.binding = binding;
  ok("BINDING — floored with an existing source, CI-bound in the form the floors gate recognises, every composed gate runnable by its npm script, and every clause executed", binding.length === 0, binding.slice(0, 4).join(" ; "));
  const green = flippedGreen(LIB);
  const g = LIB.verdict(green.journey, green.input);
  ok("VERDICT — the real eleven-step table, every leg measured green with named evidence, is the only exit 0", g.exit === 0 && g.steps.length === 11 && g.steps.every((s) => s.state === "PASS"), `${g.kind} ${g.failures.slice(0, 2).join(" ; ")}`);
  const best = LIB.verdict(LIB.JOURNEY, shippedBestCase(LIB), LIB.ESTATE);
  ok("VERDICT — the table as shipped, even with every live leg and composed gate green, exits 2 (journey incomplete): its named gaps and TODOs are never a pass", best.exit === 2 && best.kind === "named_failure" && best.failures.length === 0 && Object.values(REQUIRED_GAPS).every((c) => best.gaps.includes(c)), `${best.kind} · ${best.gaps.length} gaps · ${best.failures.slice(0, 2).join(" ; ")}`);
  const fabricated = LIB.verdict(LIB.JOURNEY, { ...shippedBestCase(LIB), claims: { ...shippedBestCase(LIB).claims, "limits/legs/limits": { state: "pass" } } }, LIB.ESTATE);
  ok("VERDICT — a named gap that reports pass is fabricated: exit 1", fabricated.exit === 1 && fabricated.failures.some((x) => /fabricated/u.test(x)));
  const unjudged = LIB.JOURNEY.map((s) => (s.id === "data" ? { ...s, handoff: undefined } : s));
  ok("VERDICT — a step whose hand-off is not judged is red", LIB.verdict(unjudged, shippedBestCase(LIB), LIB.ESTATE).exit === 1);
  const notRun = { ...shippedBestCase(LIB), composed: {} };
  const exit2 = { ...shippedBestCase(LIB), composed: Object.fromEntries(LIB.COMPOSE.map((c) => [c.id, { status: 2 }])) };
  const flippedOne = flippedGreen(LIB);
  flippedOne.journey[1].legs[0] = { ...LIB.JOURNEY[1].legs[0] }; // design/legs/blueprint-authoring back to composed…
  delete flippedOne.input.claims["design/legs/blueprint-authoring"]; // …with no live claim left standing for it
  ok("VERDICT — a composed gate that did not run, or exited 2, is never a pass",
    LIB.verdict(flippedOne.journey, { ...flippedOne.input, composed: {} }).exit === 2
      && LIB.verdict(flippedOne.journey, { ...flippedOne.input, composed: { "studio-journey": { status: 2 } } }).exit === 2
      && LIB.verdict(LIB.JOURNEY, notRun, LIB.ESTATE).exit !== 0 && LIB.verdict(LIB.JOURNEY, exit2, LIB.ESTATE).exit !== 0);
  return { pure, src, binding };
}

async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "autonomous-system-journey-mutation-"));
  let planted = 0, caught = 0;
  const mutate = async (what, from, to) => {
    planted += 1;
    const count = original.split(from).length - 1;
    if (count !== 1) { console.log(` FAIL  mutation ${planted} (${what}) — its target occurs ${count} times, not once: the battery no longer plants what it names`); return; }
    const file = path.join(dir, `m${planted}.mjs`);
    fs.writeFileSync(file, original.replace(from, to));
    let f = [];
    try { f = pureFindings(await import(pathToFileURL(file).href)); } catch (e) { f = [`threw:${e.message}`]; }
    if (f.length) caught += 1;
    console.log(`${f.length ? "  ok  " : " FAIL "} mutation ${planted} — ${what}${f.length ? "" : " SURVIVED"}`);
  };
  // The verdict.
  await mutate("VERDICT — a named gap counts as pass", 'return { state: "named_gap", code: leg.gap.code, plane: leg.gap.plane };', 'return { state: "pass", evidence: "live: planted", code: leg.gap.code };');
  await mutate("VERDICT — a named gap that reports pass is believed", 'if (claim && claim.state === "pass") return { state: "fail", why: `fabricated — the named gap', 'if (false) return { state: "fail", why: `fabricated — the named gap');
  await mutate("VERDICT — a stale probe is ignored", 'if (claim && claim.probe === "stale")', "if (false)");
  await mutate("VERDICT — a TODO counts as pass", 'return { state: "todo", write: leg.write };', 'return { state: "pass", evidence: "live: planted" };');
  await mutate("VERDICT — a composed gate that never ran counts as pass", 'if (!run) return { state: "unmeasured"', 'if (!run) return { state: "pass", evidence: "composed: planted"');
  await mutate("VERDICT — a composed gate's exit 2 counts as pass", 'if (run.status === 2) return { state: "unmeasured"', 'if (run.status === 2) return { state: "pass", evidence: "composed: planted"');
  await mutate("VERDICT — an unreached live leg counts as pass", 'if (!claim) return { state: "fail", why: `unreached', 'if (!claim) return { state: "pass", evidence: "live: planted", why: `unreached');
  await mutate("VERDICT — a step whose hand-off is not judged is not red", "if (!step.handoff || !(step.handoff.legs || []).length) judged.push(", "if (false) judged.push(");
  await mutate("VERDICT — a step's hand-off legs are never judged", 'else for (const leg of step.handoff?.legs || []) judge("handoff", leg);', "else void 0;");
  await mutate("VERDICT — the terminal restart is never judged", 'for (const leg of step.terminal.legs) judge("terminal", leg);', "void 0;");
  await mutate("VERDICT — a journey of only named gaps passes", 'gaps.length || todos || unmeasured ? "named_failure" : "pass"', 'todos || unmeasured ? "named_failure" : "pass"');
  await mutate("VERDICT — a pass need not name its evidence", 'if (j.state === "pass" && !/^(live|composed): \\S/u.test(j.evidence || ""))', "if (false)");
  // The table's rules.
  await mutate("RULES — a non-terminal step may omit its hand-off", "f.push(...handoffFindings(step, journey[i + 1], where, gates, cited, once));", "void 0;");
  await mutate("RULES — a hand-off leg need not say what it is judged by", "if (isHandoff && !leg.judged_by)", "if (false)");
  await mutate("RULES — a named gap needs no plane", "if (!g.plane)", "if (false)");
  await mutate("RULES — a live leg needs no assertion", 'if (leg.kind === "live" && !leg.assertion)', "if (false)");
  // The table.
  await mutate("TABLE — step 3's hand-off is dropped", 'handoff: { into: "limits", legs: [', 'handoff_dropped: { into: "limits", legs: [');
  await mutate("TABLE — the limits gap is quietly turned into a TODO", '{ id: "limits", kind: "named_gap", what: "budgets and standing limits for the System",', '{ id: "limits", kind: "todo", write: "planted", what: "budgets and standing limits for the System",');
  await mutate("TABLE — the live 1→2 hand-off is quietly turned into a TODO", '{ id: "system-links-its-design", kind: "live",', '{ id: "system-links-its-design", kind: "todo", write: "planted",');
  await mutate("TABLE — a composed gate drops out of COMPOSE", '{ id: "notification-inbox", pkg: "app",', '{ id: "notification-inbox-dropped", pkg: "app",');
  await mutate("TABLE — the authority-node gap loses its probe", 'probe: { route: "/systems/{system}/govern", marker:', 'probe_dropped: { route: "/systems/{system}/govern", marker:');
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  console.log(`\n${caught}/${planted} planted defects caught`);
  evidence.mutation = { planted, caught };
  return caught === planted;
}

function printJourney(result) {
  console.log(`\n=== JOURNEY — ${evidence.system_id || "(no System was created)"} · tag ${evidence.tag || "-"}`);
  for (const s of result.steps) {
    console.log(`${String(s.n).padStart(2)} ${s.id.padEnd(11)} ${s.state.padEnd(10)} ${s.title}`);
    for (const j of s.legs) {
      const mark = j.part === "handoff" ? "↳ " : j.part === "terminal" ? "⟲ " : "  ";
      const say = j.evidence || (j.state === "named_gap" ? `${j.code} — missing: ${j.plane}` : j.state === "todo" ? `TODO(live): ${j.write}` : j.why || "");
      console.log(`     ${mark}${String(j.leg).padEnd(32)} ${j.state.toUpperCase().padEnd(10)} ${say}`.slice(0, 240));
    }
  }
  for (const j of result.estate) console.log(`   estate ${String(j.leg).padEnd(30)} ${j.state.toUpperCase().padEnd(10)} ${j.evidence || j.why || ""}`.slice(0, 240));
}

async function main() {
  if (MODE === "mutation") {
    const green = await mutation();
    console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
    process.exit(green ? 0 : 1);
  }
  const { pure, src, binding } = await drills();
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} drills passed`);
  emitVerifierCensus({ verifierId: "autonomous-system-journey", sourceUrl: import.meta.url, results });
  if (MODE === "drills") {
    console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
    process.exit(passed === results.length ? 0 : 1);
  }
  const live = await liveLeg();
  evidence.live = live;
  console.log(`\n# LIVE — ${live.setup.length ? live.setup.join("; ") : "the walk completed"} in ${live.seconds}s`);
  for (const w of live.walk) console.log(`#   write ${w.id.padEnd(24)} ${String(w.status).padEnd(4)} ${w.state || ""}${w.code ? ` ${w.code}` : ""}  ${w.action}`);
  const composed = await composeLeg();
  evidence.composed = composed;
  const result = LIB.verdict(LIB.JOURNEY, {
    claims: live.claims,
    composed: composed.runs,
    setup: live.setup,
    drills: [...pure.map((x) => `PURE ${x}`), ...src.map((x) => `SOURCE ${x}`), ...binding.map((x) => `BINDING ${x}`)],
  }, LIB.ESTATE);
  evidence.verdict = result;
  printJourney(result);
  const head = result.kind === "pass" ? "PASS" : result.kind === "named_failure" ? "NAMED FAILURE" : "FAIL";
  console.log(`\n=== VERDICT: ${head} — ${result.label} · ${result.gaps.length} named gap(s) · ${result.todos} TODO leg(s) · ${result.unmeasured} unmeasured`);
  for (const x of result.failures) console.log(`FAIL   ${x}`);
  for (const code of result.gaps) console.log(`NAMED  ${code}`);
  console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
  process.exit(result.exit);
}

main().catch((e) => { console.error(e); try { writeEvidence(); } catch { /* best effort */ } process.exit(1); });
