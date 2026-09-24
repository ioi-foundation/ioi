#!/usr/bin/env node
// check:dead-controls — a control that LOOKS live must DO something (apps/hypervisor/AGENTS.md; R-240).
//
// WHY THIS EXISTS. check:named-gap-perception measures the controls the estate has DECLARED
// unavailable. It cannot see a control that carries no marker and no aria-disabled and still does
// nothing — and that is the dangerous population, because it reads as a promise. The owner found the
// Solution Designer defect by clicking a green button; until this gate, nothing in the estate
// clicked anything. This gate clicks everything.
//
// WHAT IT DOES. For every registered surface it enumerates the live-looking controls out of a real
// browser, exercises each one the way a person would — a select is CHOSEN, a field is TYPED INTO
// and then Enter is pressed, a checkbox is toggled, anything else is clicked — and records five
// signals: the URL moved, the DOM moved, the network fired, a `data-*-state` moved, or anything else
// happened (a popup, a dialog, a download). All five unmoved is a DEAD control. A link with a real
// href is fetched instead, and must LAND: an error status, a refused connection, a fragment with no
// target, or an answer slower than a person will wait for are each counted by name.
//
// THE CENSUS NEVER WRITES. Every request that is not a read is refused at the route and COUNTED as
// the network having fired — the control did try to do something, which is what liveness means.
// That is what lets it run against a populated daemon without touching it.
//
//   PURE   — the classifier over records measured from the live estate, each edge isolated.
//   SOURCE — the census refuses writes, and the classifier reaches no browser, file, clock or network.
//   LIVE   — this gate's OWN serve on its own port, a headless browser, all registered surfaces —
//            and the OWNED SHELL (clause 8): Home, Projects, four settings panes and the account menu,
//            judged by the single-page-app rules the classifier names (reads by RPC name, signals
//            against the page at rest, menu items against the page before the menu, links clicked
//            and their route rendered, resize handles dragged, each exercise from a clean client).
//
//   --drills     CI-bound, seconds: PURE, SOURCE, BINDING, the verdict rules. No browser.
//   --mutation   planted defects against the classifier — each must go red.
//   (default)    the drills, then LIVE. Exit 0 pass, 2 named failure, 1 fail.

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/dead-control-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = path.join(ROOT, "apps", "hypervisor");
const FLOORS = path.join(APP, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP, "scripts", "lib", "dead-control-census.mjs");
const SELF_PATH = fileURLToPath(import.meta.url);
const SERVE_SRC = path.join(APP, "scripts", "serve-product-ui.mjs");

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const flagValue = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-240";

const self = (n) => ({ kind: "self", script: `${n} (this runner)` });
const PURE = self("pure");
const SOURCE = self("source");
const LIVE = self("live");

// THE PIN — measured 2026-09-24 by this gate's OWN LIVE leg, on its own serve, against the local
// daemon. EXACT, never a ceiling: a repair that lowers a count must lower the pin with it.
//
// `dead` is 0 because the two controls this gate found were repaired in the cut that built it: the
// Object Explorer's saved-set Name and Description fields stayed editable beside a natively disabled
// Save. Enter cannot submit through a disabled default button, and the only way to enable Save —
// selecting a type — is a navigation that discards what was typed. Every exit was closed.
//
// THE FIRST CENSUS REPORTED SEVEN DEAD CONTROLS AND FIVE WERE MINE. It clicked every control,
// including two selects and five text fields; a click on a field focuses it and moves nothing, so
// all seven read as dead. Choosing a select and typing into a field (then Enter) found that five of
// them work. The two that remained were real. The practice that caught it is clause 2.
export const PINNED = Object.freeze({
  surfaces_probed: 36,
  states_probed: 2,
  dead: 0,
  click_failed: 0,
  bad_landing: 0,
  dead_anchor: 0,
  slow_landing: 0,
  reference_lane: 18,
  raw_capture_href: 0,
});

// THE OWNED SHELL'S PIN (clause 8) — measured by this gate's own LIVE leg, signed out (the gate carries
// no credential), against the local daemon. Defect counts only: how many controls a page has moves
// with the owner's data (a project card, a session row), and a pin on it would flap for no defect.
export const SHELL_PINNED = Object.freeze({
  shell_routes_probed: 7,
  shell_dead: 0,
  shell_click_failed: 0,
  shell_bad_landing: 0,
});

// Home, Projects, the four settings panes where R-240 found dead controls, and the account menu —
// the menu is a STATE its trigger opens, and its items are judged against the page before it opened.
export const SHELL_TARGETS = Object.freeze([
  { key: "home", route: "/ai" },
  { key: "projects", route: "/projects" },
  { key: "login-configuration", route: "/settings/login" },
  { key: "scim", route: "/settings/scim" },
  { key: "integrations", route: "/settings/org-integrations" },
  { key: "sessions", route: "/settings/environments" },
  { key: "account-menu", route: "/projects", menu: '[data-testid="org-switcher"]' },
]);

export const CLAUSES = [
  { n: 1, demand: "A LIVE-LOOKING CONTROL MUST DO SOMETHING. Exercised the way a person would, it moves the URL, the DOM, the network, a `data-*-state`, or anything else at all; all five unmoved is a DEAD control — the population check:named-gap-perception cannot see, because it carries no marker and no aria-disabled and reads as a promise", executed_by: [PURE, LIVE] },
  { n: 2, demand: "A CONTROL IS EXERCISED BY ITS NATURAL ACTION, never by a click that proves nothing: a select is CHOSEN, a text field is TYPED INTO and then Enter is pressed, a checkbox is toggled. The first census clicked seven fields and called all seven dead; five of them work. A field whose own change moves nothing is still alive when its FORM can submit, because its value is consumed when the form is sent", executed_by: [PURE] },
  { n: 3, demand: "A DECLARED GAP IS NOT IN THIS POPULATION: aria-disabled, native disabled, inert, or inside one is check:named-gap-perception's, and neither census may absorb the other. A bare tabindex is not a control (a scroll region is focusable to be reached, not activated), and a label's liveness is its control's", executed_by: [PURE] },
  { n: 4, demand: "THE CENSUS NEVER WRITES. Every request that is not a read is refused at the route and COUNTED as the network having fired — the control did try — so the census can run against a populated daemon without touching it", executed_by: [SOURCE, LIVE] },
  { n: 5, demand: "A LINK IS ALIVE ONLY IF IT LANDS. A real href is fetched: an error status or a refused connection is a BAD landing, a `#fragment` with no element behind it is a DEAD anchor, and an answer slower than a person will wait for is a SLOW landing — a link that takes 22 seconds passes every one of the five signals and is still broken to the person who clicked it", executed_by: [PURE, LIVE] },
  { n: 6, demand: "A REFERENCE LANE IS COUNTED APART. `/__apps/*` and the developer's reference-capture server are EVIDENCE ONLY (apps/hypervisor/AGENTS.md), and whether they answer depends on whether somebody's capture server is running — so they cannot share a pin with product links, or the gate would fail on every machine that is not this one", executed_by: [PURE, LIVE] },
  { n: 7, demand: "THE POPULATION IS PINNED EXACTLY AND MEASURED BY THIS GATE'S OWN SERVE — not the shared :4173 a developer happens to be running, which would let a gate pass on a process it did not start. A new dead control is red on the day it is written; a repair that lowers a count must lower the pin with it", executed_by: [LIVE] },
  { n: 8, demand: "THE OWNED SHELL IS EXERCISED TOO. It is a single-page app, so its Connect reads (POSTs) pass the write refusal by method NAME and a read-looking name carrying a write verb does not; its network and DOM signals are judged against the page AT REST, because it polls, streams and animates; a menu item is judged against the page before its menu opened, because a menu closing is not the item doing anything (the account menu's Support was exactly that); and its links are CLICKED, because every path answers 200 there, so the route a click opens must render (Join or create an organization opened a blank layout, /changelog the shell's not-found page)", executed_by: [PURE, SOURCE, LIVE] },
];

const results = [];
const evidence = { schema: "ioi.dead-control-census-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, source: null, live: null, verdict: null, mutation: null };
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  results.push(row);
  evidence.drills.push({ ...row, at: new Date().toISOString() });
  console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`);
  return row.pass;
}
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `dead-controls-${MODE}-${evidence.started_at.replace(/[:.]/gu, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(readText(p));

// ---- PURE -----------------------------------------------------------------------------------
// Records measured from the live estate on 2026-09-24, kept verbatim so the drills are about real
// bytes rather than shapes invented to pass.
const SERVE = "http://127.0.0.1:4173";
const OE_SAVENAME = Object.freeze({ tag: "INPUT", type: "", role: null, href: null, visible: true, declared: false, onclick: false, contentEditable: false, cursor: "text", parentCursor: "auto", nestedInControl: false, formCanSubmit: false, text: "Name for the saved object set", cls: "oe-savename" });
const OE_ONTSEL = Object.freeze({ tag: "SELECT", type: null, role: null, href: null, visible: true, declared: false, onclick: false, contentEditable: false, cursor: "default", parentCursor: "auto", nestedInControl: false, formCanSubmit: false, text: "All ontologies (7)", cls: "oe-ontsel oe-ontlive" });
const DSG_ROW = Object.freeze({ tag: "A", type: null, role: null, href: "/__ioi/studio/designer?ontology=ont_18c15c5cd526", visible: true, declared: false, onclick: false, contentEditable: false, cursor: "pointer", parentCursor: "auto", nestedInControl: false, text: "pipe-parity", cls: "dsg-row" });
const DSG_NEW_GAP = Object.freeze({ tag: "SPAN", type: null, role: "button", href: null, visible: true, declared: true, onclick: false, contentEditable: false, cursor: "not-allowed", parentCursor: "auto", nestedInControl: false, text: "New Diagram", cls: "dsg-hbtn success gap" });
const NONE = Object.freeze({ signals: { url: false, dom: false, network: false, state: false, other: false } });

export function pureFindings(lib) {
  const f = [];
  const expect = (what, got, want) => { if (got !== want) f.push(`${what}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`); };

  // THE CONTROL THIS GATE FOUND. Typed into, Enter pressed, nothing moved, and its form's only submit
  // was disabled: dead. The same field beside an ENABLED submit is alive by its form — and without
  // that second case the classifier could call every field dead and still pass the first.
  expect("oe-savename/population", lib.isLiveLooking(OE_SAVENAME), true);
  expect("oe-savename/exercise", lib.exerciseFor(OE_SAVENAME), "type");
  expect("oe-savename/verdict", lib.exerciseVerdict(OE_SAVENAME, NONE).verdict, "dead");
  expect("oe-savename/with-submit", lib.exerciseVerdict({ ...OE_SAVENAME, formCanSubmit: true }, NONE).verdict, "alive_by_form");
  // AND THE REPAIR: disabled beside its disabled Save, it leaves this population for the other one.
  expect("oe-savename/repaired", lib.isLiveLooking({ ...OE_SAVENAME, declared: true }), false);

  // THE FALSE POSITIVE THAT TAUGHT CLAUSE 2. A select is CHOSEN, and choosing this one navigates.
  expect("oe-ontsel/exercise", lib.exerciseFor(OE_ONTSEL), "select");
  expect("oe-ontsel/chosen", lib.exerciseVerdict(OE_ONTSEL, { signals: { ...NONE.signals, url: true } }).verdict, "alive");
  expect("checkbox/exercise", lib.exerciseFor({ tag: "INPUT", type: "checkbox" }), "toggle");
  expect("search/exercise", lib.exerciseFor({ tag: "INPUT", type: "search" }), "type");
  expect("textarea/exercise", lib.exerciseFor({ tag: "TEXTAREA" }), "type");

  // EACH SIGNAL ALONE IS ENOUGH — a check that honoured only some would call a working control dead.
  for (const s of lib.SIGNALS) expect(`signal/${s}`, lib.exerciseVerdict({ tag: "BUTTON" }, { signals: { ...NONE.signals, [s]: true } }).verdict, "alive");
  if (lib.SIGNALS.length !== 5) f.push(`signals: ${lib.SIGNALS.length} signals, five are measured`);
  // A button that moves nothing is dead, and is NOT rescued by a form: a button is not a field.
  expect("button/dead", lib.exerciseVerdict({ tag: "BUTTON", formCanSubmit: true }, NONE).verdict, "dead");
  expect("button/failed", lib.exerciseVerdict({ tag: "BUTTON" }, { error: "element is outside of the viewport" }).verdict, "click_failed");

  // THE POPULATION'S EDGES, each isolated.
  expect("declared-gap", lib.isLiveLooking(DSG_NEW_GAP), false);
  expect("invisible", lib.isLiveLooking({ ...DSG_ROW, visible: false }), false);
  expect("row-link", lib.isLiveLooking(DSG_ROW), true);
  expect("anchor-without-href", lib.isLiveLooking({ ...DSG_ROW, href: null, cursor: "auto" }), false);
  expect("bare-tabindex-region", lib.isLiveLooking({ tag: "DIV", role: null, visible: true, declared: false, cursor: "auto", parentCursor: "auto" }), false);
  expect("role-button-span", lib.isLiveLooking({ tag: "SPAN", role: "button", visible: true, declared: false, cursor: "auto", parentCursor: "auto" }), true);
  expect("pointer-top", lib.isLiveLooking({ tag: "DIV", role: null, visible: true, declared: false, cursor: "pointer", parentCursor: "auto" }), true);
  expect("pointer-inherited", lib.isLiveLooking({ tag: "DIV", role: null, visible: true, declared: false, cursor: "pointer", parentCursor: "pointer" }), false);
  expect("inner-span-of-link", lib.isLiveLooking({ tag: "SPAN", role: "button", visible: true, declared: false, cursor: "pointer", parentCursor: "auto", nestedInControl: true }), false);
  expect("input-inside-label", lib.isLiveLooking({ ...OE_SAVENAME, nestedInControl: true }), true);
  expect("hidden-input", lib.isLiveLooking({ ...OE_SAVENAME, type: "hidden" }), false);

  // LINKS LAND OR THEY DO NOT.
  expect("link/exercise", lib.exerciseFor(DSG_ROW), "fetch");
  expect("fragment/exercise", lib.exerciseFor({ tag: "A", href: "#designer-truth" }), "fragment");
  expect("hash-only/exercise", lib.exerciseFor({ tag: "A", href: "#" }), "click");
  expect("javascript/exercise", lib.exerciseFor({ tag: "A", href: "javascript:void(0)" }), "click");
  const L = (o) => lib.landingVerdict({ exercise: "fetch", ...o }, SERVE).verdict;
  expect("landing/200", L({ abs: `${SERVE}/__ioi/pipeline`, status: 200, ms: 300 }), "alive");
  expect("landing/404", L({ abs: `${SERVE}/__ioi/nope`, status: 404, ms: 20 }), "bad_landing");
  expect("landing/refused", L({ abs: "http://127.0.0.1:1/x", status: null, failure: "ECONNREFUSED" }), "bad_landing");
  expect("landing/slow", L({ abs: `${SERVE}/__ioi/environments`, status: 200, ms: 21809 }), "slow_landing");
  expect("landing/just-under", L({ abs: `${SERVE}/__ioi/environments`, status: 200, ms: lib.SLOW_LANDING_MS }), "alive");
  expect("fragment/missing", lib.landingVerdict({ exercise: "fragment", href: "#nope", fragmentTargetExists: false }, SERVE).verdict, "dead_anchor");
  expect("fragment/present", lib.landingVerdict({ exercise: "fragment", href: "#designer-truth", fragmentTargetExists: true }, SERVE).verdict, "alive");

  // A REFERENCE LANE IS COUNTED APART — both spellings, and a product path is NOT one.
  expect("ref/apps-503", L({ abs: `${SERVE}/__apps/designer`, status: 503, ms: 30 }), "reference_lane");
  expect("ref/capture-refused", L({ abs: "http://localhost:9225/workspace/solution-design/", status: null, failure: "ECONNREFUSED" }), "reference_lane");
  expect("ref/product-path", lib.isReferenceLane(`${SERVE}/__ioi/studio/designer`, SERVE), false);
  expect("ref/other-origin-apps", lib.isReferenceLane("http://example.test/__apps/x", SERVE), false);
  expect("raw-capture", lib.isRawCaptureHref("http://localhost:9225/workspace/evals/"), true);
  expect("raw-capture/serve", lib.isRawCaptureHref(`${SERVE}/__apps/evals`), false);

  // THE OWNED SHELL (clause 8). Its reads are POSTs — a census that refused them could not boot it,
  // and one that allowed every POST would write to the owner's daemon.
  const R = (m, u) => lib.isReadRequest(m, `${SERVE}${u}`);
  expect("read/get", R("GET", "/projects"), true);
  expect("read/connect-list", R("POST", "/api/gitpod.v1.EnvironmentService/ListEnvironments"), true);
  expect("read/connect-get", R("POST", "/api/ioi.v1.UserService/GetAuthenticatedUser"), true);
  expect("write/connect-create", R("POST", "/api/gitpod.v1.AgentService/CreateAgentSession"), false);
  expect("write/connect-update", R("POST", "/api/ioi.v1.ProjectService/UpdateProject"), false);
  expect("write/read-prefix-with-write-verb", R("POST", "/api/ioi.v1.X/GetOrCreateEnvironment"), false);
  expect("write/rotation", R("POST", "/api/ioi.v1.OrganizationService/RegenerateSCIMToken"), false);
  expect("write/prefix-is-not-a-word", R("POST", "/api/ioi.v1.X/ListenForChanges"), false);
  expect("write/surface-action", R("POST", "/__ioi/pipeline/actions/admit-run"), false);
  expect("write/logout", R("POST", "/auth/oidc/logout"), false);
  expect("write/delete-verb", R("DELETE", "/v1/hypervisor/sso-configurations/x"), false);
  // THE SHELL NEVER GOES QUIET. Support: its menu closed and nothing else happened — against the page
  // before the menu opened, nothing moved, and a poll the page makes at rest is not the control's.
  const rest = ["POST /api/gitpod.v1.EventService/WatchEvents", "GET /v1/hypervisor/auth/whoami"];
  const S = (o) => lib.spaSignals({ urlBefore: "/projects", urlAfter: "/projects", textBefore: "Projects", textAfter: "Projects", overlaysBefore: 0, overlaysAfter: 0, requestKeys: [], restKeys: rest, blocked: 0, stateMoved: false, other: 0, ...o });
  expect("spa/support-dead", lib.exerciseVerdict({ tag: "DIV", role: "menuitem" }, { signals: S({ requestKeys: ["POST /api/gitpod.v1.EventService/WatchEvents"] }) }).verdict, "dead");
  expect("spa/dialog-opened", S({ overlaysAfter: 1 }).dom, true);
  expect("spa/text-changed", S({ textAfter: "Projects · Sort by" }).dom, true);
  expect("spa/refused-write", S({ blocked: 1 }).network, true);
  expect("spa/new-request", S({ requestKeys: ["POST /api/gitpod.v1.ProjectService/ListProjects"] }).network, true);
  expect("spa/navigated", S({ urlAfter: "/join-organization" }).url, true);
  expect("spa/popup", S({ other: 1 }).other, true);
  // EVERY PATH ANSWERS 200 — a route a click opened must render. Join or create an organization
  // opened a blank layout; /changelog was the shell's not-found page.
  expect("spa-landing/not-moved", lib.spaLandingVerdict({ urlChanged: false, text: "" }), null);
  expect("spa-landing/blank", lib.spaLandingVerdict({ urlChanged: true, text: "   " })?.verdict, "bad_landing");
  expect("spa-landing/not-found", lib.spaLandingVerdict({ urlChanged: true, text: "4 0 4 IOI looked everywhere. This page doesn't exist. Back to dashboard" })?.verdict, "bad_landing");
  expect("spa-landing/renders", lib.spaLandingVerdict({ urlChanged: true, text: "Organizations — This deployment hosts one organization, so there is no other to join." }), null);

  // A RESIZE HANDLE IS DRAGGED, never clicked — and a drag that moved it is alive by "other".
  expect("drag/exercise", lib.exerciseFor({ tag: "BUTTON", cursor: "ew-resize" }), "drag");
  expect("drag/row", lib.exerciseFor({ tag: "DIV", cursor: "row-resize" }), "drag");
  expect("drag/pointer-is-click", lib.exerciseFor({ tag: "BUTTON", cursor: "pointer" }), "click");
  expect("drag/moved", lib.exerciseVerdict({ tag: "BUTTON", cursor: "ew-resize" }, { signals: { ...NONE.signals, other: true } }).verdict, "alive");
  expect("drag/stuck", lib.exerciseVerdict({ tag: "BUTTON", cursor: "ew-resize" }, NONE).verdict, "dead");
  // WHERE YOU ALREADY ARE: the link to this page, the tab already selected — moving nothing is right.
  // And ONLY those: the same control without the flag is still dead.
  expect("self/link", lib.exerciseVerdict({ tag: "A", href: "/settings/login", selfLink: true }, NONE).verdict, "self");
  expect("self/selected-tab", lib.exerciseVerdict({ tag: "BUTTON", role: "tab", current: true }, NONE).verdict, "self");
  expect("self/not-self-is-dead", lib.exerciseVerdict({ tag: "A", href: "/settings/scim" }, NONE).verdict, "dead");
  expect("self/moved-is-alive", lib.exerciseVerdict({ tag: "A", selfLink: true }, { signals: { ...NONE.signals, dom: true } }).verdict, "alive");
  // A LINK INTO THE SHELL is rendered, a serve page is fetched: /workspaces/<id> answered 200 and drew
  // the shell's not-found page on every row of the Environments surface.
  expect("shell-path/workspaces", lib.isShellPath("/workspaces/env-1"), true);
  expect("shell-path/details", lib.isShellPath("/details/env-1"), true);
  expect("shell-path/settings", lib.isShellPath("/settings/login"), true);
  expect("shell-path/serve-surface", lib.isShellPath("/__ioi/pipeline"), false);
  expect("shell-path/changelog", lib.isShellPath("/changelog"), false);
  expect("shell-path/join", lib.isShellPath("/join-organization"), false);
  expect("shell-path/daemon", lib.isShellPath("/v1/hypervisor/projects"), false);
  expect("shell-path/asset", lib.isShellPath("/static/assets/x.js"), false);
  expect("shell-path/file", lib.isShellPath("/favicon.ico"), false);

  // TOTALS roll up per verdict, which is what the pin is compared against.
  const t = lib.censusTotals([
    { kind: "click", verdict: "dead" }, { kind: "click", verdict: "alive" }, { kind: "click", verdict: "alive_by_form" },
    { kind: "link", verdict: "alive", count: 3 }, { kind: "link", verdict: "slow_landing" },
    { kind: "link", verdict: "reference_lane", abs: "http://localhost:9225/x" }, { kind: "link", verdict: "reference_lane", abs: `${SERVE}/__apps/x` },
  ]);
  expect("totals/dead", t.dead, 1);
  expect("totals/exercised", t.exercised, 3);
  expect("totals/links", t.links_unique, 4);
  expect("totals/live_looking", t.live_looking, 9);
  expect("totals/reference_lane", t.reference_lane, 2);
  expect("totals/raw_capture", t.raw_capture_href, 1);
  expect("totals/slow", t.slow_landing, 1);
  return f;
}

// ---- SOURCE ---------------------------------------------------------------------------------
export function sourceFindings({ gate, lib }) {
  const f = [];
  // THE CENSUS REFUSES WRITES. The guard is read out of this runner's own source, because a census
  // that clicked "Delete" against the owner's daemon would be worse than no census at all.
  if (!/if \(!LIB\.isReadRequest\(method, route\.request\(\)\.url\(\)\)\) \{ blocked\.push/u.test(gate)) f.push("the LIVE leg no longer refuses non-read requests at the route");
  // THE OWNED SHELL is exercised with its own rules, and its account menu is among the targets.
  if (!/SHELL_TARGETS/u.test(gate) || !/org-switcher/u.test(gate)) f.push("the LIVE leg no longer exercises the owned shell and its account menu");
  if (!/LIB\.spaSignals\(/u.test(gate) || !/LIB\.spaLandingVerdict\(/u.test(gate)) f.push("the shell leg no longer judges its signals at rest, or no longer checks that a route a click opened renders");
  for (const name of ["READ_RPC", "WRITE_VERB", "SPA_NOT_FOUND", "SPA_MIN_TEXT"]) {
    if (!lib.includes(`export const ${name}`)) f.push(`the classifier no longer names \`${name}\``);
  }
  if (!/route\.abort\("blockedbyclient"\)/u.test(gate)) f.push("the LIVE leg no longer ABORTS a refused request, so a write could still reach the daemon");
  if (!/blocked\.length > 0/u.test(gate)) f.push("a refused write is no longer counted as the network having fired, so a control that tried to act would read as dead");
  // THIS GATE STARTS ITS OWN SERVE.
  if (!/spawn\(process\.execPath, \[SERVE_SRC\]/u.test(gate)) f.push("the LIVE leg no longer starts its own serve");
  // The classifier reaches nothing.
  if (/fetch\(|readFileSync|Date\.now\(|new Date\(|document\.|window\./u.test(lib)) f.push("the classifier reaches a browser, a file, a clock or a network, so it cannot judge a census captured by somebody else");
  for (const name of ["CLICK_ROLES", "TEXT_TYPES", "SLOW_LANDING_MS", "SIGNALS", "CAPTURE_PORT"]) {
    if (!lib.includes(`export const ${name}`)) f.push(`the classifier no longer names \`${name}\``);
  }
  return f;
}

// ---- BINDING --------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate }) {
  const f = [];
  for (const s of ["check:dead-controls", "mutate:dead-controls"]) {
    if (!rootPkg.scripts?.[s]) f.push(`root_script_missing:${s}`);
  }
  if (!appPkg.scripts?.["check:dead-controls"]) f.push("app_drills_script_missing");
  const row = (floors.verifiers ?? []).find((r) => r.id === "dead-controls");
  if (!row) f.push("floor_row_missing");
  else {
    if (!fs.existsSync(path.join(ROOT, row.source))) f.push(`floor_source_absent:${row.source}`);
    if (!(row.runtime_assertions > 0)) f.push("floor_not_pinned");
  }
  if (!/npm run check:dead-controls --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("ci_not_bound_in_the_recognised_form");
  if (!/mutate:dead-controls/u.test(ci)) f.push("ci_mutation_not_bound");
  if (!floorsGate.includes("check-dead-controls")) f.push("floors_gate_does_not_recognise_this_runner");
  for (const c of CLAUSES) {
    if (!c.executed_by?.length && !c.absence) f.push(`clause_${c.n}_neither_executed_nor_named`);
    if (c.absence && !c.absence.owner) f.push(`clause_${c.n}_absence_without_owner`);
  }
  if (CLAUSES.length !== 8) f.push(`clause_count:${CLAUSES.length}`);
  return f;
}

export function verdict(rows) {
  const failures = [];
  const absences = [];
  for (const c of CLAUSES) {
    const row = rows.find((r) => r.n === c.n);
    if (!row) { failures.push(`row_missing:${c.n}`); continue; }
    if (row.fabricated) { failures.push(`clause_${c.n}_fabricated: ${row.fabricated}`); continue; }
    if (row.red) { failures.push(`clause_${c.n}_red: ${row.red}`); continue; }
    if (row.absent) absences.push({ n: c.n, ...c.absence });
  }
  if (failures.length) return { kind: "fail", failures, absences };
  if (absences.length) return { kind: "named_failure", failures, absences };
  return { kind: "pass", failures, absences };
}

// ---- LIVE -----------------------------------------------------------------------------------
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.on("error", reject);
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
});

// Runs IN THE BROWSER: raw facts about every element that could be a control. The classifier —
// not this function — decides which of them are.
const ENUMERATE = () => {
  const ROLES = ["button", "link", "tab", "menuitem", "menuitemcheckbox", "menuitemradio", "checkbox", "switch", "option", "radio", "treeitem", "combobox"];
  const CONTROL = 'a[href],button,[role=button],[role=link],[role=tab],[role=menuitem],summary';
  const cssPath = (el) => {
    const parts = [];
    for (let n = el; n && n.nodeType === 1 && n !== document.documentElement; n = n.parentElement) {
      if (n.id && document.querySelectorAll(`#${CSS.escape(n.id)}`).length === 1) { parts.unshift(`#${CSS.escape(n.id)}`); break; }
      const sib = [...n.parentElement.children].filter((c) => c.tagName === n.tagName);
      parts.unshift(`${n.tagName.toLowerCase()}${sib.length > 1 ? `:nth-of-type(${sib.indexOf(n) + 1})` : ""}`);
    }
    return parts.join(" > ");
  };
  const out = [];
  for (const el of document.querySelectorAll("body *")) {
    const role = el.getAttribute("role");
    const cs = getComputedStyle(el);
    const maybe = el.matches("a,button,input,select,textarea,summary,[onclick],[contenteditable]") || (role && ROLES.includes(role)) || cs.cursor === "pointer";
    if (!maybe) continue;
    const r = el.getBoundingClientRect();
    const form = el.form || el.closest("form");
    const submit = form ? [...form.querySelectorAll('button:not([type]),button[type=submit],input[type=submit]')].find((b) => !b.disabled) : null;
    const href = el.getAttribute("href");
    out.push({
      css: cssPath(el), tag: el.tagName, type: el.tagName === "INPUT" ? (el.getAttribute("type") || "") : null, role, href,
      visible: r.width > 1 && r.height > 1 && cs.visibility !== "hidden" && cs.display !== "none" && Number(cs.opacity) > 0.05,
      declared: !!el.closest('[aria-disabled="true"],[disabled],[inert]'),
      onclick: el.hasAttribute("onclick"), contentEditable: el.getAttribute("contenteditable") === "true",
      cursor: cs.cursor, parentCursor: el.parentElement ? getComputedStyle(el.parentElement).cursor : "auto",
      nestedInControl: !!el.parentElement?.closest(CONTROL),
      formCanSubmit: !!submit,
      fragmentTargetExists: href && href.startsWith("#") && href.length > 1 ? !!document.getElementById(decodeURIComponent(href.slice(1))) : null,
      inMenu: !!el.closest('[role="menu"]'), targetBlank: el.getAttribute("target") === "_blank",
      current: el.getAttribute("aria-current") === "page" || el.getAttribute("aria-selected") === "true" || (el.getAttribute("role") === "tab" && el.getAttribute("data-state") === "active"),
      selfLink: !!href && !href.startsWith("#") && (() => { try { const u = new URL(href, location.href); return u.origin === location.origin && u.pathname === location.pathname && u.search === location.search; } catch { return false; } })(),
      text: (el.innerText || el.getAttribute("aria-label") || el.getAttribute("title") || el.getAttribute("placeholder") || "").trim().replace(/\s+/gu, " ").slice(0, 50),
      cls: String(el.className?.baseVal ?? el.className ?? "").slice(0, 60),
    });
  }
  return out;
};
const ARM = () => {
  window.__dcMut = 0;
  window.__dcObs?.disconnect();
  window.__dcObs = new MutationObserver((ms) => { window.__dcMut += ms.length; });
  window.__dcObs.observe(document.documentElement, { subtree: true, childList: true, attributes: true, characterData: true });
  window.__dcStates = JSON.stringify([...document.querySelectorAll("*")].flatMap((e) => [...e.attributes].filter((a) => /^data-.*state$/u.test(a.name)).map((a) => `${a.name}=${a.value}`)));
};
const READ = () => ({ mut: window.__dcMut ?? -1, before: window.__dcStates, states: JSON.stringify([...document.querySelectorAll("*")].flatMap((e) => [...e.attributes].filter((a) => /^data-.*state$/u.test(a.name)).map((a) => `${a.name}=${a.value}`))) });

async function liveLeg() {
  const started = Date.now();
  const findings = [];
  let serve = null;
  let browser = null;
  try {
    const { chromium } = await import("playwright");
    const { SURFACES, SURFACE_STATES } = await import(pathToFileURL(path.join(APP, "scripts", "surface-registry.mjs")).href);
    // THIS GATE STARTS ITS OWN SERVE. A fixed port, or the :4173 a developer happens to be running,
    // can answer a gate that started neither — and then the gate is measuring somebody else's build.
    const port = await freePort();
    const uiPort = await freePort();
    const base = `http://127.0.0.1:${port}`;
    serve = spawn(process.execPath, [SERVE_SRC], {
      cwd: APP,
      env: { ...process.env, PORT: String(port), PRODUCT_UI_PORT: String(uiPort), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public") },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const deadline = Date.now() + 60000;
    for (;;) {
      if (Date.now() > deadline) throw new Error("this gate's own serve did not come up in 60s");
      try { const r = await fetch(`${base}/`); if (r.status) break; } catch { /* retry */ }
      await new Promise((r) => setTimeout(r, 500));
    }

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    const page = await context.newPage();
    let requests = 0;
    let blocked = [];
    let other = [];
    // THE CENSUS NEVER WRITES: anything that is not a read is refused here and counted as fired.
    await context.route("**/*", (route) => {
      const method = route.request().method();
      if (!LIB.isReadRequest(method, route.request().url())) { blocked.push(`${method} ${route.request().url()}`); return route.abort("blockedbyclient"); }
      return route.continue();
    });
    page.on("request", () => { requests += 1; });
    // A page this gate opens itself (the shell-landing renderer) is not a popup the control opened.
    let openingOwnPage = false;
    context.on("page", (p) => { if (openingOwnPage) return; other.push(`popup ${p.url()}`); p.close().catch(() => {}); });
    page.on("dialog", (d) => { other.push(`dialog ${d.type()}`); d.dismiss().catch(() => {}); });
    page.on("download", (d) => other.push(`download ${d.suggestedFilename()}`));

    const landings = new Map(); // abs → { status, failure, ms } — measured once, counted per surface
    const land = async (abs) => {
      if (landings.has(abs)) return landings.get(abs);
      const t0 = Date.now();
      let row;
      try {
        const r = await context.request.get(abs, { timeout: 60000, maxRedirects: 5, failOnStatusCode: false });
        row = { status: r.status(), failure: null, ms: Date.now() - t0 };
      } catch (e) { row = { status: null, failure: String(e.message).split("\n")[0].slice(0, 120), ms: Date.now() - t0 }; }
      landings.set(abs, row);
      return row;
    };

    // One scratch page renders every link into the shell, once per target, and judges what it drew.
    const shellRendered = new Map();
    const renderShellLanding = async (abs) => {
      if (shellRendered.has(abs)) return shellRendered.get(abs);
      openingOwnPage = true;
      const probe = await context.newPage().finally(() => { openingOwnPage = false; });
      let out = null;
      try {
        await probe.goto(abs, { waitUntil: "domcontentloaded", timeout: 60000 });
        await probe.waitForTimeout(2500);
        const text = await probe.evaluate(() => (document.querySelector("main") || document.body).innerText || "");
        out = LIB.spaLandingVerdict({ urlChanged: true, text });
      } catch (e) { out = { verdict: "bad_landing", why: `the shell route did not load: ${String(e.message).split("\n")[0].slice(0, 80)}` }; }
      finally { await probe.close().catch(() => {}); }
      shellRendered.set(abs, out);
      return out;
    };
    const rows = [];
    let probed = 0;
    let statesProbed = 0;
    // A STATE ADDS A STATE, NEVER A SURFACE: its page still carries the owning surface's controls
    // (the Designer landing renders behind the Open Diagram dialog), so a link or control already
    // counted on the surface is not counted again. Measured: without this, the two dialog states
    // re-counted the landing's four reference links each and read as eight new defects.
    const seenBySlug = new Map();
    // Every registered surface, then every STATE of one that only a link reaches (the Open Diagram
    // selector is `?open=` on the Designer): a census of canonical routes alone never sees those.
    const targets = [
      ...Object.values(SURFACES).map((s) => ({ slug: s.slug, route: s.canonical_route || s.route, state: false })),
      ...(SURFACE_STATES || []).map((x) => ({ slug: x.slug, route: x.route, state: true })),
    ];
    for (const s of targets) {
      const route = s.route;
      const load = async () => {
        // An exercise can start a navigation that lands AFTER its settle window (type, Enter, a slow
        // GET); the next goto then collides with it. Measured once: it threw the whole leg away.
        for (let attempt = 0; ; attempt += 1) {
          try { await page.goto(base + route, { waitUntil: "domcontentloaded", timeout: 90000 }); break; } catch (e) {
            if (attempt >= 4 || !/interrupted by another navigation/u.test(String(e.message))) throw e;
            await page.waitForLoadState("load", { timeout: 15000 }).catch(() => {});
          }
        }
        // Network idle FIRST, then two agreeing samples: stability is not completeness
        // (check:named-gap-perception paid for that lesson twice).
        await page.waitForLoadState("networkidle", { timeout: 20000 }).catch(() => {});
      };
      const sample = async () => {
        const out = [];
        for (const [i, frame] of page.frames().entries()) {
          try { for (const el of await frame.evaluate(ENUMERATE)) out.push({ frame: i, frameUrl: frame.url(), ...el }); } catch { /* a frame can navigate mid-evaluate */ }
        }
        return out.filter((el) => LIB.isLiveLooking(el));
      };
      // One retry, and the reason kept: measured, a route that answers in 0.2s alone failed to load
      // once while the leg's own load on the daemon (a 44s Environments landing) was at its peak.
      try { await load(); } catch (first) {
        await page.waitForTimeout(3000);
        try { await load(); } catch (e) { findings.push(`route_unreachable: ${route} — ${String(e.message).split("\n")[0].slice(0, 120)} (first attempt: ${String(first.message).split("\n")[0].slice(0, 80)})`); continue; }
      }
      let settled = null;
      let previous = await sample();
      for (let attempt = 0; attempt < 6; attempt += 1) {
        await page.waitForTimeout(500);
        const next = await sample();
        if (JSON.stringify(next.map((x) => x.css)) === JSON.stringify(previous.map((x) => x.css))) { settled = next; break; }
        previous = next;
      }
      if (settled === null) { findings.push(`route_never_settled: ${route}`); continue; }
      if (s.state) statesProbed += 1; else probed += 1;

      const links = new Map();
      const exercises = [];
      // Links key on their target; controls key on what they ARE, as a multiset — a state that
      // appends a sibling to <body> renumbers every DOM path, so a path key cannot tell the
      // landing's own controls from the state's (measured on the perception census).
      const ckey = (el) => `${el.tag}|${el.cls}|${el.role}|${el.text}`;
      if (!seenBySlug.has(s.slug)) seenBySlug.set(s.slug, { links: new Set(), controls: new Map() });
      const seen = seenBySlug.get(s.slug);
      const budget = new Map(seen.controls);
      for (const el of settled) {
        const how = LIB.exerciseFor(el);
        if (how === "fetch" || how === "fragment") {
          const abs = how === "fetch" ? new URL(el.href, el.frameUrl).href : `${el.frameUrl}${el.href}`;
          if (seen.links.has(abs) && !links.has(abs)) continue;
          seen.links.add(abs);
          if (!links.has(abs)) links.set(abs, { kind: "link", surface: s.slug, exercise: how, abs, href: el.href, text: el.text, fragmentTargetExists: el.fragmentTargetExists, count: 0 });
          links.get(abs).count += 1;
        } else {
          if (s.state) {
            const left = budget.get(ckey(el)) || 0;
            if (left > 0) { budget.set(ckey(el), left - 1); continue; }
          }
          // Counted once per surface, across its states: a second state carrying the same dialog
          // does not exercise the same search field again.
          seen.controls.set(ckey(el), (seen.controls.get(ckey(el)) || 0) + 1);
          exercises.push({ ...el, exercise: how });
        }
      }
      for (const l of links.values()) {
        const m = l.exercise === "fetch" ? await land(l.abs) : {};
        let judged = LIB.landingVerdict({ ...l, ...m }, base);
        // A link INTO THE SHELL is fetched as 200 whatever the shell then draws, so it is rendered.
        if (judged.verdict === "alive" && l.exercise === "fetch" && new URL(l.abs).origin === base && LIB.isShellPath(new URL(l.abs).pathname)) {
          judged = (await renderShellLanding(l.abs)) || judged;
        }
        rows.push({ ...l, ...m, ...judged });
      }

      let dirty = false;
      for (const el of exercises) {
        if (dirty) {
          try { await load(); } catch (e) { findings.push(`route_reload_failed: ${route} — ${String(e.message).split("\n")[0].slice(0, 120)}`); break; }
          await page.waitForTimeout(300);
          dirty = false;
        }
        const frame = page.frames()[el.frame];
        if (!frame) { rows.push({ kind: "click", surface: s.slug, ...el, verdict: "click_failed", why: "frame gone" }); dirty = true; continue; }
        const url0 = page.frames().map((f) => f.url()).join("|");
        for (const f of page.frames()) await f.evaluate(ARM).catch(() => {});
        requests = 0; blocked = []; other = [];
        let error = null;
        try {
          const loc = frame.locator(el.css).first();
          if (el.exercise === "select") {
            const opts = await loc.evaluate((x) => ({ cur: x.value, vals: [...x.options].filter((o) => !o.disabled).map((o) => o.value) }));
            const next = opts.vals.find((v) => v !== opts.cur);
            if (next === undefined) error = "select offers no alternative option";
            else await loc.selectOption(next, { timeout: 3000 });
          } else if (el.exercise === "type") {
            await loc.fill("zq", { timeout: 3000 });
            await page.waitForTimeout(600);
            await loc.press("Enter", { timeout: 3000, noWaitAfter: true });
          } else if (el.exercise === "toggle") {
            await loc.click({ timeout: 3000, noWaitAfter: true });
          } else {
            await loc.click({ timeout: 3000, noWaitAfter: true });
          }
        } catch (e) { error = String(e.message).split("\n")[0].slice(0, 160); }
        await page.waitForTimeout(900);
        await page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});
        let mut = 0; let stateMoved = false; let navigated = false;
        for (const f of page.frames()) {
          const r = await f.evaluate(READ).catch(() => null);
          if (!r || r.mut < 0) { navigated = true; continue; }
          mut += r.mut;
          if (r.before !== undefined && r.before !== r.states) stateMoved = true;
        }
        const signals = {
          url: navigated || page.frames().map((f) => f.url()).join("|") !== url0,
          dom: mut > 0,
          network: requests > 0 || blocked.length > 0,
          state: stateMoved,
          other: other.length > 0,
        };
        const judged = LIB.exerciseVerdict(el, { signals, error });
        rows.push({ kind: "click", surface: s.slug, css: el.css, tag: el.tag, text: el.text, cls: el.cls, exercise: el.exercise, signals, blocked: blocked.slice(0, 3), ...judged });
        if (judged.verdict !== "dead") dirty = true;
      }
    }

    // ---- THE OWNED SHELL (clause 8). A single-page app, so three rules change (the classifier's
    // header says why): its Connect reads are POSTs and pass the guard by method name; its network and
    // DOM signals are judged against the page AT REST; its links are CLICKED and the route they open
    // must render. Controls are found again after every reload by what they ARE — the shell's Radix
    // ids change on every load, so a DOM path cannot find the same control twice.
    const shellRows = [];
    let shellProbed = 0;
    const reqKeys = [];
    page.on("request", (q) => reqKeys.push(LIB.requestKey(q.method(), q.url())));
    const ident = (el) => `${el.tag}|${el.role}|${el.text}|${el.href || ""}`;
    const withOcc = (els) => { const n = new Map(); return els.map((el) => { const k = ident(el); const i = n.get(k) || 0; n.set(k, i + 1); return { ...el, ident: k, occ: i }; }); };
    const PAGE_READ = () => {
      const vis = (e) => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && cs.display !== "none"; };
      return { url: location.pathname + location.search + location.hash, text: document.body.innerText, overlays: [...document.querySelectorAll('[role="dialog"],[role="alertdialog"],[role="menu"],[role="listbox"]')].filter(vis).length, main: ((document.querySelector("main") || document.body).innerText || "") };
    };
    const shellEnumerate = async () => withOcc((await page.mainFrame().evaluate(ENUMERATE)).filter((el) => LIB.isLiveLooking(el)));
    const shellSeen = new Set();
    for (const t of SHELL_TARGETS) {
      const open = async () => {
        // EACH EXERCISE STARTS FROM A CLEAN CLIENT. The shell persists UI state (a collapsed sidebar,
        // a sort) in browser storage, so one exercise's click would hide the next one's control across
        // every reload — measured: two rail controls read "not found again" for exactly that reason.
        await page.evaluate(() => { try { localStorage.clear(); sessionStorage.clear(); } catch { /* no origin yet */ } }).catch(() => {});
        await page.goto(base + t.route, { waitUntil: "domcontentloaded", timeout: 90000 });
        await page.waitForTimeout(2500); // the shell boots client-side; networkidle never comes (it streams)
      };
      try { await open(); } catch { findings.push(`shell_route_unreachable: ${t.route}`); continue; }
      // THE PAGE AT REST: every request key heard while nobody touches anything.
      const restFrom = reqKeys.length; const restBlocked = blocked.length;
      await page.waitForTimeout(2000);
      const rest = [...reqKeys.slice(restFrom), ...blocked.slice(restBlocked).map((b) => LIB.requestKey(b.split(" ")[0], b.slice(b.indexOf(" ") + 1)))];
      const openMenu = async () => { await page.locator(t.menu).first().click({ timeout: 4000 }); await page.waitForTimeout(700); };
      let preMenu = await page.evaluate(PAGE_READ); // re-read after every reload: time-varying text must not read as an item's effect
      if (t.menu) { try { await openMenu(); } catch { findings.push(`shell_menu_unopenable: ${t.key}`); continue; } }
      const population = (await shellEnumerate()).filter((el) => (t.menu ? el.inMenu : !el.inMenu) && !shellSeen.has(el.ident));
      shellProbed += 1;
      let dirty = false;
      for (const target of population) {
        shellSeen.add(target.ident);
        if (dirty) {
          try { await open(); preMenu = await page.evaluate(PAGE_READ); if (t.menu) await openMenu(); } catch (e) { findings.push(`shell_reload_failed: ${t.route} — ${String(e.message).split("\n")[0].slice(0, 100)}`); break; }
          dirty = false;
        }
        let now = null;
        for (let attempt = 0; attempt < 6 && !now; attempt += 1) { // the shell keeps rendering after load
          now = (await shellEnumerate()).find((el) => el.ident === target.ident && el.occ === target.occ);
          if (!now) await page.waitForTimeout(500);
        }
        if (!now) { shellRows.push({ kind: "click", surface: `shell:${t.key}`, tag: target.tag, text: target.text, verdict: "click_failed", why: "not found again after reload" }); dirty = true; continue; }
        const before = t.menu ? preMenu : await page.evaluate(PAGE_READ);
        await page.evaluate(ARM).catch(() => {});
        const k0 = reqKeys.length; const b0 = blocked.length; other = [];
        let error = null;
        try {
          const loc = page.locator(now.css).first();
          const how = LIB.exerciseFor(now);
          if (how === "select") {
            const opts = await loc.evaluate((x) => ({ cur: x.value, vals: [...x.options].filter((o) => !o.disabled).map((o) => o.value) }));
            const next = opts.vals.find((v) => v !== opts.cur);
            if (next === undefined) error = "select offers no alternative option"; else await loc.selectOption(next, { timeout: 3000 });
          } else if (how === "type") {
            await loc.fill("zq", { timeout: 3000 }); await page.waitForTimeout(500); await loc.press("Enter", { timeout: 3000, noWaitAfter: true });
          } else if (how === "drag") {
            // Dragged 60px along its axis; it is alive if the handle itself moved (a layout change is
            // not visible text, so the at-rest DOM signal would not see it).
            const r0 = await loc.boundingBox();
            if (!r0) error = "the handle has no box to drag";
            else {
              const horizontal = /^(ew|col|e|w)-resize$/u.test(now.cursor || "");
              await page.mouse.move(r0.x + r0.width / 2, r0.y + r0.height / 2); await page.mouse.down();
              await page.mouse.move(r0.x + r0.width / 2 + (horizontal ? 60 : 0), r0.y + r0.height / 2 + (horizontal ? 0 : 60), { steps: 6 }); await page.mouse.up();
              const r1 = await loc.boundingBox().catch(() => null);
              if (r1 && (Math.abs(r1.x - r0.x) > 2 || Math.abs(r1.y - r0.y) > 2 || Math.abs(r1.width - r0.width) > 2 || Math.abs(r1.height - r0.height) > 2)) other.push("dragged: the handle moved");
            }
          } else {
            // Links too: every path answers 200 here. A list that re-renders as its data lands can
            // detach the element between finding and clicking (measured: a project card, clickable
            // every time alone, timed out once in a full run) — so a timed-out click finds the control
            // again by what it IS and tries once more before it counts as a failure.
            try { await loc.click({ timeout: 3000, noWaitAfter: true }); } catch (first) {
              if (!/Timeout/u.test(String(first.message))) throw first;
              const again = (await shellEnumerate()).find((el) => el.ident === target.ident && el.occ === target.occ);
              if (!again) throw first;
              await page.locator(again.css).first().click({ timeout: 3000, noWaitAfter: true });
            }
          }
        } catch (e) { error = String(e.message).split("\n")[0].slice(0, 160); }
        await page.waitForTimeout(1500);
        const after = await page.evaluate(PAGE_READ).catch(() => ({ url: "(navigated away)", text: "", overlays: 0, main: "" }));
        const r = await page.evaluate(READ).catch(() => null);
        const newBlocked = blocked.slice(b0).map((b) => LIB.requestKey(b.split(" ")[0], b.slice(b.indexOf(" ") + 1))).filter((k) => !rest.includes(k));
        const signals = LIB.spaSignals({
          urlBefore: before.url, urlAfter: after.url, textBefore: before.text, textAfter: after.text,
          overlaysBefore: before.overlays, overlaysAfter: after.overlays,
          requestKeys: reqKeys.slice(k0), restKeys: rest, blocked: newBlocked.length,
          stateMoved: !!(r && r.before !== undefined && r.before !== r.states), other: other.length,
        });
        let judged = LIB.exerciseVerdict(now, { signals, error });
        if (judged.verdict === "alive" && signals.url) {
          await page.waitForTimeout(1500);
          const landed = await page.evaluate(PAGE_READ).catch(() => ({ main: "" }));
          judged = LIB.spaLandingVerdict({ urlChanged: true, text: landed.main }) || judged;
        }
        shellRows.push({ kind: "click", surface: `shell:${t.key}`, tag: now.tag, text: now.text, href: now.href, cls: now.cls, cursor: now.cursor, exercise: LIB.exerciseFor(now), signals, blocked: newBlocked.slice(0, 3), ...judged });
        if (judged.verdict !== "dead" || t.menu) dirty = true;
      }
    }
    const shellTotals = LIB.censusTotals(shellRows);
    const shellMeasured = { shell_routes_probed: shellProbed, shell_exercised: shellTotals.exercised, shell_dead: shellTotals.dead, shell_click_failed: shellTotals.click_failed, shell_bad_landing: shellTotals.bad_landing };
    for (const key of Object.keys(SHELL_PINNED)) {
      if (shellMeasured[key] !== SHELL_PINNED[key]) findings.push(`${key}: measured ${shellMeasured[key]}, pinned ${SHELL_PINNED[key]} — ${shellMeasured[key] > SHELL_PINNED[key] ? "a NEW defect landed" : "a repair landed and the pin must come down with it"}`);
    }
    rows.push(...shellRows.filter((x) => ["dead", "click_failed", "bad_landing"].includes(x.verdict)).map((x) => ({ ...x, shell: true })));

    const totals = LIB.censusTotals(rows.filter((x) => !x.shell));
    const measured = { surfaces_probed: probed, states_probed: statesProbed, ...totals, ...shellMeasured };
    for (const key of Object.keys(PINNED)) {
      if (measured[key] !== PINNED[key]) {
        findings.push(`${key}: measured ${measured[key]}, pinned ${PINNED[key]} — ${measured[key] > PINNED[key] ? "a NEW defect landed" : "a repair landed and the pin must come down with it"}`);
      }
    }
    const named = rows.filter((r) => ["dead", "click_failed", "bad_landing", "dead_anchor", "slow_landing"].includes(r.verdict)).map((r) => ({ surface: r.surface, verdict: r.verdict, text: r.text, target: r.abs || r.css || r.href || "", why: r.why }));
    return { findings, measured, named, rows, seconds: Math.round((Date.now() - started) / 1000) };
  } catch (error) {
    return { findings: [`live leg threw: ${String(error.message).slice(0, 200)}`], measured: null, named: [], rows: [], seconds: Math.round((Date.now() - started) / 1000) };
  } finally {
    try { await browser?.close(); } catch { /* already gone */ }
    try { serve?.kill("SIGTERM"); } catch { /* already gone */ }
  }
}

// ---- run ------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = pure;
  ok("PURE — the control this gate found reads dead and its repair leaves the population; each of the five signals alone is enough; a field is exercised by typing or choosing, and is alive by its form only when that form can submit; declared gaps, bare tabindex regions and inner spans are out; links land, refuse, crawl or point at nothing; reference lanes are counted apart", pure.length === 0, pure.slice(0, 4).join(" ; "));

  const src = sourceFindings({ gate: readText(SELF_PATH), lib: readText(LIB_PATH) });
  evidence.source = src;
  ok("SOURCE — the LIVE leg refuses and aborts every non-read request and counts it as fired, starts its own serve, and the classifier reaches no browser, file, clock or network", src.length === 0, src.slice(0, 4).join(" ; "));

  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP, "package.json")),
    floors: readJson(FLOORS),
    ci: readText(path.join(ROOT, ".github", "workflows", "ci.yml")),
    floorsGate: readText(path.join(APP, "scripts", "check-verifier-floors.mjs")),
  });
  ok("BINDING — floored with an existing source, CI-bound in the form the floors gate recognises, and every clause executed or named with an owner", binding.length === 0, binding.slice(0, 4).join(" ; "));

  const all = CLAUSES.map((c) => ({ n: c.n }));
  ok("VERDICT — a table missing seven of its eight rows is a FAIL", verdict([{ n: 1 }]).kind === "fail");
  ok("VERDICT — eight green rows with no absence is a PASS", verdict(all).kind === "pass");
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", verdict(all.map((r) => (r.n === 8 ? { ...r, absent: true } : r))).kind === "named_failure");
  ok("VERDICT — a gate reporting success without evidence is fabricated", verdict(all.map((r) => (r.n === 1 ? { ...r, fabricated: "x" } : r))).kind === "fail");
  return { pure, src, binding };
}

async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dead-control-mutation-"));
  let planted = 0;
  let caught = 0;
  const mutate = async (what, transform) => {
    planted += 1;
    const text = transform(original);
    if (text === original) { console.log(`FAIL  mutation ${planted} (${what}) — the planted defect changed nothing`); return; }
    const file = path.join(dir, `m${planted}.mjs`);
    fs.writeFileSync(file, text);
    let f = [];
    try { f = pureFindings(await import(pathToFileURL(file).href)); } catch (e) { f = [`threw:${e.message}`]; }
    if (f.length) caught += 1;
    console.log(`${f.length ? "  ok  " : " FAIL "} mutation ${planted} — ${what}${f.length ? "" : " SURVIVED"}`);
  };

  await mutate("DEAD — nothing is ever dead", (t) => t.replace('return { verdict: "dead", why:', 'return { verdict: "alive", why:'));
  await mutate("SIGNALS — the DOM signal stops counting", (t) => t.replace('"url", "dom", "network", "state", "other"', '"url", "network", "state", "other"'));
  await mutate("SIGNALS — the network signal stops counting, so a refused write reads dead", (t) => t.replace('"url", "dom", "network", "state", "other"', '"url", "dom", "state", "other"'));
  await mutate("FORM — any field is rescued by its form, submit or not", (t) => t.replace("if (field && el.formCanSubmit === true)", "if (field)"));
  await mutate("FORM — no field is ever rescued by its form", (t) => t.replace("if (field && el.formCanSubmit === true)", "if (false)"));
  await mutate("FORM — a button is rescued by a form too", (t) => t.replace('const field = ["select", "type", "toggle"].includes(exerciseFor(el));', "const field = true;"));
  await mutate("EXERCISE — a select is clicked instead of chosen", (t) => t.replace('if (el.tag === "SELECT") return "select";', ""));
  await mutate("EXERCISE — a text field is clicked instead of typed into", (t) => t.replace('if (el.tag === "TEXTAREA" || (el.tag === "INPUT" && TEXT_TYPES.includes(el.type || ""))) return "type";', ""));
  await mutate("EXERCISE — a checkbox is clicked as a button", (t) => t.replace('if (el.tag === "INPUT" && (el.type === "checkbox" || el.type === "radio")) return "toggle";', ""));
  await mutate("EXERCISE — a fragment link is fetched instead of resolved", (t) => t.replace('if (el.href.startsWith("#")) return el.href.length > 1 ? "fragment" : "click";', ""));
  await mutate("POPULATION — declared gaps are judged here too", (t) => t.replace("el.declared === true", "false"));
  await mutate("POPULATION — invisible controls are judged", (t) => t.replace("el.visible !== true || ", ""));
  await mutate("POPULATION — a bare role is not enough", (t) => t.replace('|| CLICK_ROLES.includes(el.role || "")', ""));
  await mutate("POPULATION — an inherited pointer counts as its own control", (t) => t.replace(' && el.parentCursor !== "pointer"', ""));
  await mutate("POPULATION — the inner span of a link is judged separately", (t) => t.replace("if (el.nestedInControl === true && ", "if (false && "));
  await mutate("POPULATION — a hidden input is a control", (t) => t.replace('(el.tag === "INPUT" && el.type !== "hidden")', '(el.tag === "INPUT")'));
  await mutate("LANDING — an error status lands", (t) => t.replace("if (link.status >= 400)", "if (link.status >= 600)"));
  await mutate("LANDING — a refused connection lands", (t) => t.replace("if (link.failure || link.status == null)", "if (false)"));
  await mutate("LANDING — slowness is never measured", (t) => t.replace("if (link.ms > SLOW_LANDING_MS)", "if (false)"));
  await mutate("LANDING — the slow bound is off by one the wrong way", (t) => t.replace("if (link.ms > SLOW_LANDING_MS)", "if (link.ms >= SLOW_LANDING_MS)"));
  await mutate("LANDING — a missing fragment target lands", (t) => t.replace('return link.fragmentTargetExists ? { verdict: "alive"', 'return true ? { verdict: "alive"'));
  await mutate("REFERENCE — the capture origin is a product link", (t) => t.replace('if (u.port === CAPTURE_PORT && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) return true;', ""));
  await mutate("REFERENCE — /__apps/ is a product link", (t) => t.replace('return u.origin === serveOrigin && u.pathname.startsWith("/__apps/");', "return false;"));
  await mutate("REFERENCE — any origin's /__apps/ is a reference lane", (t) => t.replace('return u.origin === serveOrigin && u.pathname.startsWith("/__apps/");', 'return u.pathname.startsWith("/__apps/");'));
  await mutate("RAW CAPTURE — never counted", (t) => t.replace("try { const u = new URL(abs); return u.port === CAPTURE_PORT; } catch { return false; }", "return false;"));
  await mutate("TOTALS — links count as exercised", (t) => t.replace("      t.links_unique += 1;", "      t.links_unique += 1; t.exercised += 1;"));
  await mutate("TOTALS — duplicate links counted once", (t) => t.replace("t.live_looking += r.count || 1;", "t.live_looking += 1;"));

  // THE OWNED SHELL (clause 8).
  await mutate("READ — any POST reads as a read, so the census could write", (t) => t.replace("return !!m && READ_RPC.test(m[1]) && !WRITE_VERB.test(m[1]);", "return true;"));
  await mutate("READ — a read-prefixed name with a write verb passes", (t) => t.replace(" && !WRITE_VERB.test(m[1]);", ";"));
  await mutate("AT REST — a request heard while nobody touched anything counts as the control's", (t) => t.replace("(m.requestKeys || []).some((k) => !rest.has(k))", "(m.requestKeys || []).length > 0"));
  await mutate("AT REST — an overlay opening does not count as the DOM moving", (t) => t.replace(" || m.overlaysBefore !== m.overlaysAfter", ""));
  await mutate("SPA LANDING — the shell's not-found page lands", (t) => t.replace('if (SPA_NOT_FOUND.test(t)) return { verdict: "bad_landing"', 'if (false) return { verdict: "bad_landing"'));
  await mutate("SPA LANDING — a blank route lands", (t) => t.replace("if (t.length < SPA_MIN_TEXT)", "if (false)"));
  await mutate("SELF — every control that moved nothing is excused as pointing where you are", (t) => t.replace("return el?.selfLink === true || el?.current === true;", "return true;"));
  await mutate("DRAG — a resize handle is clicked instead of dragged", (t) => t.replace('if (/^(ew|ns|col|row|e|w|n|s)-resize$/u.test(el.cursor || "")) return "drag";', ""));
  await mutate("SHELL PATH — a serve-rendered page is rendered as a shell route", (t) => t.replace("if (!p.startsWith(\"/\") || SERVE_RENDERED.test(p)) return false;", "if (!p.startsWith(\"/\")) return false;"));

  console.log(`\n${caught}/${planted} planted defects caught`);
  evidence.mutation = { planted, caught };
  return caught === planted;
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
  emitVerifierCensus({ verifierId: "dead-controls", sourceUrl: import.meta.url, results });
  if (MODE === "drills") {
    console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
    process.exit(passed === results.length ? 0 : 1);
  }

  const live = await liveLeg();
  evidence.live = live;
  console.log(`\n# LIVE — ${live.findings.length === 0 ? "green" : live.findings.join("; ")} in ${live.seconds}s`);
  if (live.measured) console.log(`# measured ${JSON.stringify(live.measured)}`);
  for (const n of live.named) console.log(`#   ${n.verdict.padEnd(13)} ${n.surface.padEnd(12)} ${JSON.stringify(n.text).slice(0, 40).padEnd(40)} ${String(n.target).slice(0, 80)} — ${n.why}`);

  const rows = CLAUSES.map((c) => {
    const row = { n: c.n };
    const red = [];
    if (c.executed_by.some((e) => e.script.startsWith("pure")) && pure.length) red.push("PURE");
    if (c.executed_by.some((e) => e.script.startsWith("source")) && src.length) red.push("SOURCE");
    if (c.executed_by.some((e) => e.script.startsWith("live")) && live.findings.length) red.push("LIVE");
    if (red.length) row.red = `${red.join("+")} (this runner)`;
    if (c.absence) row.absent = true;
    return row;
  });
  if (binding.length) rows.find((r) => r.n === 7).red = `BINDING: ${binding.join("; ")}`;

  const result = verdict(rows);
  evidence.verdict = result;
  console.log(`\n=== VERDICT: ${result.kind.toUpperCase()}${result.failures.length ? ` — ${result.failures.join(" ; ")}` : ""}`);
  for (const a of result.absences) console.log(`NAMED  clause ${a.n}: ${a.what}`);
  console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
  process.exit(result.kind === "pass" ? 0 : result.kind === "named_failure" ? 2 : 1);
}

main().catch((e) => { console.error(e); writeEvidence(); process.exit(1); });
