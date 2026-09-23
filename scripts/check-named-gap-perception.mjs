#!/usr/bin/env node
// check:named-gap-perception — a control the estate declares UNAVAILABLE must read as unavailable
// to the person looking at it (apps/hypervisor/AGENTS.md; R-239).
//
// WHAT WENT WRONG. Every surface parity verifier asserts the same two things about a declared gap:
// `aria-disabled="true"` and a `title` containing "named gap". Both were true of the Solution
// Designer's `New Diagram` while it rendered as a solid green primary button with an ordinary arrow
// cursor — the markup carries `class="dsg-hbtn success gap"` and NO `.dsg-hbtn.gap` rule was ever
// written. The owner found it by clicking it. An attribute assertion cannot see it, so this gate
// reads COMPUTED STYLE out of a real browser instead.
//
// THE POPULATION IS PINNED, NOT APPROVED. 33 of 36 surfaces carry this debt today and one CSS rule
// family will not land in the same cut that discovered it. So the counts below are an EXACT pin, on
// the pattern `check:canon-document-residuals` already uses: a NEW gap that renders as primary is
// red on the day it is written, and a repair that lowers the population must lower the pin with it.
// A bound that silently absorbs progress stops being a bound.
//
//   PURE   — the classifier over records measured from the live estate, each edge isolated.
//   SOURCE — the marker vocabulary: eleven spellings for one convention, and which have a rule.
//   LIVE   — this gate's OWN serve on its own port, a headless browser, all 36 registered surfaces.
//
//   --drills           CI-bound, seconds: PURE, SOURCE, BINDING, the verdict rules. No browser.
//   --mutation         planted defects against the classifier — each must go red.
//   (default)          the drills, then LIVE. Exit 0 pass, 2 named failure, 1 fail.

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/named-gap-perception.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = path.join(ROOT, "apps", "hypervisor");
const FLOORS = path.join(APP, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP, "scripts", "lib", "named-gap-perception.mjs");
const SERVE_SRC = path.join(APP, "scripts", "serve-product-ui.mjs");

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const flagValue = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-239";

const self = (n) => ({ kind: "self", script: `${n} (this runner)` });
const PURE = self("pure");
const SOURCE = self("source");
const LIVE = self("live");

// THE PIN — measured 2026-09-23 by this gate's OWN LIVE leg, on its own serve. EXACT, never a
// ceiling: a repair that lowers the population must lower the pin with it, or the bound silently
// absorbs progress and stops being a bound.
//
// THE COUNTS ARE THE LABELLED POPULATION. An icon-only gap has no label to dim, so its perception
// is a different question and it is deliberately out of these numbers — a first hand census
// reported 47 unmarked gaps by counting icon-only controls too, and this gate measures 30, which is
// the labelled subset consistent with the other four counts. The larger number was not wrong, it
// was a different population, and mixing the two would make the pin uncomparable with itself.
//
// AND THE FIRST CENSUS UNDER-COUNTED THIS ONE BY MORE THAN HALF. It sampled 600ms after
// domcontentloaded and reported 272 labelled / 242 unreachable; the settled truth is 624 / 594,
// because several surfaces hydrate their rows from the daemon after that. The three counts it got
// RIGHT — primary_fill, cursor_not_disabled, unmarked_gap — are the ones living in statically
// rendered header chrome, which is present immediately. That is why the live leg now proves
// settlement instead of waiting a fixed interval.
//
// `primary_fill` and `cursor_not_disabled` are BELOW the first census (18 and 68) for two separate
// reasons, and only one of them is a repair. The Designer's six controls were fixed as the worked
// example before this pin was taken, so reverting that repair is red here — correct, not a coupling
// to work around. The much larger drop, 16 to 4, is a CORRECTION: twelve of those were never
// defects. `.spl-hbtn.gap{opacity:.62}` and its siblings had already dimmed them, and a first build
// of the classifier could not see it because opacity does not change backgroundColor. The four that
// remain are genuinely undressed: machinery, evalsuites, incidents and explorer.
export const PINNED = Object.freeze({
  surfaces_probed: 36,
  labelled: 624,
  primary_fill: 4,
  cursor_not_disabled: 62,
  unreachable_control: 594,
  unmarked_gap: 30,
});

export const CLAUSES = [
  { n: 1, demand: "A DECLARED GAP MUST READ AS ONE, and that is a question about COMPUTED STYLE rather than about markup: the estate's parity verifiers all assert `aria-disabled` plus a `title`, and both were true of a solid green primary button that silently did nothing. The classifier judges the four ways a gap can fail to communicate, each independently so one cannot mask another", executed_by: [PURE] },
  { n: 2, demand: "THE CURSOR IS THE FASTEST SIGNAL A PERSON GETS and `default` says \"not clickable, not refused\" — which is the one thing this control is. A declared gap renders `cursor: not-allowed` or the pointer is lying", executed_by: [PURE, LIVE] },
  { n: 3, demand: "A DECLARED GAP IS NEVER STYLED AS THE THING TO CLICK: a saturated opaque fill on an unavailable control is not a subtle defect, it is the most prominent promise on the surface. Saturation AND alpha are both required, because the estate's own gap fill is grey and nearly transparent and either test alone would condemn the convention it exists to protect", executed_by: [PURE, LIVE] },
  { n: 4, demand: "`aria-disabled` ON A BARE SPAN IS AN ATTRIBUTE ON A NON-CONTROL — assistive technology has nothing to describe as disabled, and with no tabindex a keyboard user cannot reach it to be told anything at all. A declared gap carries a role and is focusable, or its declaration reaches nobody who needs it", executed_by: [PURE, LIVE] },
  { n: 5, demand: "A MARKER CLASS WITHOUT `aria-disabled` IS INVISIBLE TO EVERY GATE IN THIS ESTATE, because every one of them keys on the attribute it lacks — and a screen reader announces it as an ordinary enabled control, actively vouching for it. Measured: 30 labelled such controls, including a real `<button>` styled solid blue", executed_by: [PURE, LIVE] },
  { n: 6, demand: "PROSE IS NOT A CONTROL: `*-gapnote` carries the EXPLANATION of what is unavailable and why, so dimming or refusing it would hide the one thing on the surface doing its job. Excluded by name rather than by a pattern, because a pattern that guessed would eventually swallow a control", executed_by: [PURE, SOURCE] },
  { n: 7, demand: "ONE CONVENTION MUST NOT HAVE ELEVEN SPELLINGS. `gap` is the shared marker and ten surfaces each minted a private one; a convention nobody can apply by habit is a convention that will be forgotten, which is exactly how 33 surfaces acquired this debt. The vocabulary is read from the SERVE SOURCE and compared against the classifier's list, so a twelfth spelling is red", executed_by: [SOURCE] },
  { n: 8, demand: "THE POPULATION IS PINNED EXACTLY AND MEASURED BY THIS GATE'S OWN SERVE — not the shared :4173 a developer happens to be running, which would let a gate pass on a process it did not start. A new defect is red on the day it is written; a repair that lowers the count must lower the pin with it", executed_by: [LIVE], absence: { what: "THE DEBT IS RECORDED, NOT REPAIRED. 33 of 36 surfaces carry it and this gate does not fix them: the shared `.gap` rule family, the `role`/`tabindex` additions and the 30 missing `aria-disabled` attributes are a separate cut, because they change visible output on 33 surfaces and the pixel-certification and parity baselines must be re-frozen in the same commit that moves them. ONE SURFACE IS PARTIALLY REPAIRED as the worked example — the Solution Designer's six controls now render muted with `not-allowed` — and it is only PARTIAL: they remain bare spans, so clause 4 still finds them unreachable. The treatment itself is the owner's call and has not been approved estate-wide", owner: `the Hypervisor app owner for the gap treatment and the baseline re-freeze (${OWNER_Q})` } },
];

const results = [];
const evidence = { schema: "ioi.named-gap-perception-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, source: null, live: null, verdict: null, mutation: null };
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
  const file = path.join(dir, `named-gap-perception-${MODE}-${evidence.started_at.replace(/[:.]/gu, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(readText(p));

// ---- PURE -----------------------------------------------------------------------------------
// Records measured from the live estate on 2026-09-23, kept verbatim so the drills are about real
// bytes rather than about shapes invented to pass.
const NEW_DIAGRAM_BEFORE = Object.freeze({ text: "New Diagram", className: "dsg-hbtn success gap", tag: "SPAN", role: null, tabindex: null, ariaDisabled: true, cursor: "default", backgroundColor: "rgb(35, 133, 81)" });
const INCIDENTS_NEW = Object.freeze({ text: "New", className: "in-new gap", tag: "BUTTON", role: null, tabindex: null, ariaDisabled: false, cursor: "pointer", backgroundColor: "rgb(45, 114, 210)" });
const CONVENTION = Object.freeze({ text: "Cleanup", className: "vtx-hbtn gap", tag: "SPAN", role: "button", tabindex: "0", ariaDisabled: true, cursor: "not-allowed", backgroundColor: "rgba(0, 0, 0, 0)" });
const GAPNOTE = Object.freeze({ text: "This ontology declares no object types", className: "dsg-gapnote", tag: "P", role: null, tabindex: null, ariaDisabled: false, cursor: "auto", backgroundColor: "rgba(0, 0, 0, 0)" });

export function pureFindings(lib) {
  const f = [];
  const has = (what, findings, code) => {
    if (!findings.some((line) => line.startsWith(`${code}:`))) f.push(`${what}: did not report ${code} — ${findings.slice(0, 2).join("; ") || "(clean)"}`);
  };
  const hasNot = (what, findings, code) => {
    if (findings.some((line) => line.startsWith(`${code}:`))) f.push(`${what}: reported ${code} and should not have`);
  };

  // THE CASE THE OWNER FOUND, and each of its three findings named separately: a case asserting
  // only "some finding appeared" would let two of the three be deleted unnoticed.
  const before = lib.perceptionFindings(NEW_DIAGRAM_BEFORE);
  has("new-diagram/before", before, "cursor_not_disabled");
  has("new-diagram/before", before, "primary_fill");
  has("new-diagram/before", before, "unreachable_control");
  hasNot("new-diagram/before", before, "unmarked_gap");

  // THE PARTIAL REPAIR, which must read as partial and not as done.
  const after = lib.perceptionFindings({ ...NEW_DIAGRAM_BEFORE, cursor: "not-allowed", backgroundColor: "rgba(143, 153, 168, 0.15)" });
  hasNot("new-diagram/after", after, "cursor_not_disabled");
  hasNot("new-diagram/after", after, "primary_fill");
  has("new-diagram/after", after, "unreachable_control");

  // BOTH HALVES OF REACHABILITY, SEPARATELY. `aria-disabled` is chosen over the native `disabled`
  // attribute precisely so the control stays perceivable and a person can find out WHY — and the
  // why lives in the `title`. A role with no tabindex is announced correctly and still cannot be
  // reached; a tabindex with no role is reachable and announced as nothing. Drilled apart because a
  // check asserting only the bare-span case is satisfied by one that tests the role alone.
  const roleOnly = lib.perceptionFindings({ ...NEW_DIAGRAM_BEFORE, cursor: "not-allowed", backgroundColor: "rgba(0,0,0,0)", role: "button", tabindex: null });
  has("reach/role-without-tabindex", roleOnly, "unreachable_control");
  const tabOnly = lib.perceptionFindings({ ...NEW_DIAGRAM_BEFORE, cursor: "not-allowed", backgroundColor: "rgba(0,0,0,0)", role: null, tabindex: "0" });
  has("reach/tabindex-without-role", tabOnly, "unreachable_control");

  // FULLY REPAIRED IS CLEAN — without this the classifier could refuse everything and still pass.
  const done = lib.perceptionFindings({ ...NEW_DIAGRAM_BEFORE, cursor: "not-allowed", backgroundColor: "rgba(143, 153, 168, 0.15)", role: "button", tabindex: "0" });
  if (done.length !== 0) f.push(`new-diagram/repaired: a fully repaired control is not clean — ${done[0]}`);
  if (lib.perceptionFindings(CONVENTION).length !== 0) f.push("convention: the estate's own shipped gap treatment does not read clean, so the gate condemns the thing it is protecting");
  // THE OTHER SHIPPED TREATMENT: `.spl-hbtn.gap{opacity:.62;cursor:not-allowed}` on nine surfaces,
  // and the same idiom in `.mapp-gap`, `.rgy-gap`, `.fus-gap`. A saturated fill DIMMED out of
  // prominence is a conventional disabled treatment and must read clean — a first build of this
  // classifier read only `backgroundColor`, which `opacity` does not change, and reported all ten
  // as undressed primary buttons. Pinning those as debt would have made a later repair look like a
  // regression.
  const dimmed = lib.perceptionFindings({ ...NEW_DIAGRAM_BEFORE, className: "spl-hbtn success gap", cursor: "not-allowed", opacity: "0.62", role: "button", tabindex: "0" });
  if (dimmed.length !== 0) f.push(`dimmed: a saturated fill deliberately dimmed to .62 with not-allowed was condemned — ${dimmed[0]}`);
  // AND THE EDGE MUST STILL BITE AT FULL STRENGTH, or the opacity test becomes a way to pass.
  const undimmed = lib.perceptionFindings({ ...NEW_DIAGRAM_BEFORE, className: "mch-hbtn success gap", cursor: "not-allowed", opacity: "1", role: "button", tabindex: "0" });
  has("undimmed/machinery", undimmed, "primary_fill");

  // THE MARKER WITHOUT THE ATTRIBUTE, and it must NOT also be called unreachable: it is a real
  // <button>, keyboard-reachable, and saying otherwise would be a second false sentence.
  const unmarked = lib.perceptionFindings(INCIDENTS_NEW);
  has("incidents/new", unmarked, "unmarked_gap");
  has("incidents/new", unmarked, "primary_fill");
  hasNot("incidents/new", unmarked, "unreachable_control");

  // PROSE IS UNTOUCHED, both directions.
  if (lib.perceptionFindings(GAPNOTE).length !== 0) f.push("gapnote: explanatory prose was judged as a control");
  if (lib.hasGapMarker("dsg-gapnote")) f.push("gapnote: reads as a gap marker");
  // AND THE CASE THAT MAKES THE EXCLUSION LOAD-BEARING. Found by a surviving mutation: deleting
  // NOT_CONTROL_MARKERS changed nothing, because `dsg-gapnote` is not in GAP_MARKER_TOKENS and
  // exact-token matching already excluded it — the guard could not fire, so it could be removed
  // unnoticed. It becomes reachable exactly when a prose note ALSO carries the shared marker, which
  // the LIVE leg's `[class*="gap"]` capture will hand to the classifier. That is the case the
  // exclusion exists for, so it is the case that must be drilled.
  if (lib.hasGapMarker("dsg-gapnote gap")) f.push("gapnote: a prose note carrying the shared `gap` marker is judged as a control, so dimming it would hide the explanation of what is unavailable");
  if (!lib.hasGapMarker("dsg-hbtn success gap")) f.push("marker: the shared `gap` token is not recognised");
  if (!lib.hasGapMarker("fus-new fus-gap")) f.push("marker: a private `*-gap` spelling is not recognised");
  if (lib.hasGapMarker("pb-strip")) f.push("marker: a class with no gap token reads as a marker");

  // NOTHING THAT IS NOT A GAP IS JUDGED AT ALL.
  if (lib.perceptionFindings({ text: "Recents", className: "dsg-pill on", tag: "SPAN", role: null, tabindex: null, ariaDisabled: false, cursor: "pointer", backgroundColor: "rgba(45, 114, 210, .3)" }).length !== 0) {
    f.push("live-control: an ordinary enabled control was judged as a gap");
  }

  // THE FILL TEST, both halves, because either alone is wrong.
  if (!lib.isPrimaryFill("rgb(35, 133, 81)", "1")) f.push("fill: a solid green button at full opacity does not read as primary");
  if (lib.isPrimaryFill("rgb(35, 133, 81)", "0.62")) f.push("fill: a solid green button DIMMED to .62 still reads as primary, so a deliberate treatment is condemned");
  if (!lib.isPrimaryFill("rgb(35, 133, 81)", "0.9")) f.push("fill: a barely-dimmed button stopped reading as primary, so any token opacity would excuse a fill");
  if (!lib.isPrimaryFill("rgb(45, 114, 210)")) f.push("fill: a solid blue button does not read as primary");
  if (lib.isPrimaryFill("rgba(143, 153, 168, 0.15)")) f.push("fill: the estate's own gap fill reads as primary");
  if (lib.isPrimaryFill("rgb(150, 150, 150)")) f.push("fill: an opaque GREY reads as primary — saturation is not being tested");
  if (lib.isPrimaryFill("rgba(35, 133, 81, 0.05)")) f.push("fill: a barely-there green reads as primary — alpha is not being tested");
  if (lib.isPrimaryFill("rgba(0, 0, 0, 0)")) f.push("fill: transparent reads as a fill");
  if (lib.parseColor("not-a-colour") !== null) f.push("parse: a non-colour parsed");

  // TOTALS roll up per code, which is what the pin is compared against.
  const totals = lib.censusTotals([NEW_DIAGRAM_BEFORE, INCIDENTS_NEW, CONVENTION, GAPNOTE]);
  if (totals.labelled !== 3) f.push(`totals: counted ${totals.labelled} labelled gaps in a set holding three plus one prose note`);
  if (totals.primary_fill !== 2) f.push(`totals: counted ${totals.primary_fill} primary fills where two are present`);
  if (totals.unmarked_gap !== 1) f.push(`totals: counted ${totals.unmarked_gap} unmarked gaps where one is present`);
  return f;
}

// ---- SOURCE ---------------------------------------------------------------------------------
export function sourceFindings({ serve, lib }) {
  const f = [];
  // THE VOCABULARY, read from the serve rather than trusted. A twelfth spelling nobody told the
  // classifier about is a surface whose gaps this gate silently does not police.
  const used = new Set();
  for (const m of serve.matchAll(/class="([^"]*)"/gu)) {
    for (const token of m[1].split(/\s+/u)) {
      if (/gap/iu.test(token) && !token.includes("${")) used.add(token);
    }
  }
  const known = new Set([...LIB.GAP_MARKER_TOKENS, ...LIB.NOT_CONTROL_MARKERS]);
  const unknown = [...used].filter((t) => !known.has(t)).sort();
  if (unknown.length) f.push(`the serve uses gap-ish class token(s) the classifier does not know: ${unknown.join(", ")} — a surface whose marker is unknown is one this gate does not police`);

  // THE FINDING ITSELF: one convention, eleven spellings. Asserted as a fact so that CONSOLIDATING
  // them is what makes this clause move, rather than the clause quietly tracking whatever exists.
  if (LIB.GAP_MARKER_TOKENS.length !== 11) f.push(`the marker vocabulary is ${LIB.GAP_MARKER_TOKENS.length} spellings; it was eleven when measured, and a change here must be a deliberate consolidation`);
  if (!LIB.GAP_MARKER_TOKENS.includes("gap")) f.push("`gap`, the shared marker, is not in the vocabulary");

  // HOW MANY OF THEM HAVE A RULE AT ALL. This is the root cause in one number.
  const ruled = new Set([...serve.matchAll(/\.([a-z-]+)\.gap\{/gu)].map((m) => m[1]));
  if (ruled.size < 7) f.push(`only ${ruled.size} selectors define a \`.gap\` rule; seven shipped when measured, so a rule was deleted`);

  // The classifier reaches nothing — a relying party must be able to re-derive from a census.
  if (/fetch\(|readFileSync|Date\.now\(|new Date\(|document\.|window\./u.test(lib)) {
    f.push("the classifier reaches a browser, a file, a clock or a network, so it cannot judge a census captured by somebody else");
  }
  for (const marker of ["GAP_MARKER_TOKENS", "NOT_CONTROL_MARKERS", "SATURATION_FLOOR", "FILL_ALPHA_FLOOR"]) {
    if (!lib.includes(marker)) f.push(`the classifier no longer names \`${marker}\``);
  }
  return f;
}

// ---- BINDING --------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate }) {
  const f = [];
  for (const s of ["check:named-gap-perception", "mutate:named-gap-perception"]) {
    if (!rootPkg.scripts?.[s]) f.push(`root_script_missing:${s}`);
  }
  if (!appPkg.scripts?.["check:named-gap-perception"]) f.push("app_drills_script_missing");
  const row = (floors.verifiers ?? []).find((r) => r.id === "named-gap-perception");
  if (!row) f.push("floor_row_missing");
  else {
    if (!fs.existsSync(path.join(ROOT, row.source))) f.push(`floor_source_absent:${row.source}`);
    if (!(row.runtime_assertions > 0)) f.push("floor_not_pinned");
  }
  if (!/npm run check:named-gap-perception --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("ci_not_bound_in_the_recognised_form");
  if (!/mutate:named-gap-perception/u.test(ci)) f.push("ci_mutation_not_bound");
  if (!floorsGate.includes("check-named-gap-perception")) f.push("floors_gate_does_not_recognise_this_runner");
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
    if (row.below_floor) { failures.push(`clause_${c.n}_below_floor: ${row.below_floor}`); continue; }
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

async function liveLeg() {
  const started = Date.now();
  const findings = [];
  let serve = null;
  let browser = null;
  try {
    const { chromium } = await import("playwright");
    const { SURFACES } = await import(pathToFileURL(path.join(APP, "scripts", "surface-registry.mjs")).href);
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
    const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
    const list = Object.values(SURFACES);
    const controls = [];
    let probed = 0;
    for (const s of list) {
      const route = s.canonical_route || s.route;
      try {
        await page.goto(base + route, { waitUntil: "domcontentloaded", timeout: 90000 });
      } catch { findings.push(`route_unreachable: ${route}`); continue; }
      probed += 1;

      // THE PAGE MUST SETTLE BEFORE IT IS COUNTED, and settling is PROVED rather than waited for.
      // A first build sampled 500ms after domcontentloaded and measured 272 labelled controls on one
      // run and 624 on the next — surfaces that hydrate rows from the daemon were counted mid-load.
      // An exact pin over a population that cannot reproduce itself is not a bound, it is a coin
      // toss that fails CI at random. So each surface is sampled twice and must AGREE; a surface
      // that never agrees is reported by name rather than silently contributing whichever number
      // the race happened to produce.
      const sample = async () => {
        const out = [];
        for (const frame of page.frames()) {
          try {
            out.push(...await frame.evaluate(() => [...document.querySelectorAll('[aria-disabled="true"], [class*="gap"]')].map((el) => {
              const cs = getComputedStyle(el);
              return { text: (el.textContent || "").trim().replace(/\s+/gu, " ").slice(0, 40), className: String(el.className || ""),
                tag: el.tagName, role: el.getAttribute("role"), tabindex: el.getAttribute("tabindex"),
                ariaDisabled: el.getAttribute("aria-disabled") === "true", cursor: cs.cursor, backgroundColor: cs.backgroundColor, opacity: cs.opacity };
            })));
          } catch { /* a frame can navigate mid-evaluate; the others still count */ }
        }
        return out;
      };
      let settled = null;
      let previous = await sample();
      for (let attempt = 0; attempt < 6; attempt += 1) {
        await page.waitForTimeout(500);
        const next = await sample();
        if (next.length === previous.length && JSON.stringify(next) === JSON.stringify(previous)) { settled = next; break; }
        previous = next;
      }
      if (settled === null) { findings.push(`route_never_settled: ${route} — sampled six times 500ms apart and the control set kept changing, so no count from it can be pinned`); continue; }
      for (const c of settled) controls.push({ surface: s.slug, route, ...c });
    }

    const totals = LIB.censusTotals(controls);
    const measured = { surfaces_probed: probed, ...totals };
    for (const key of Object.keys(PINNED)) {
      if (measured[key] !== PINNED[key]) {
        findings.push(`${key}: measured ${measured[key]}, pinned ${PINNED[key]} — ${measured[key] > PINNED[key] ? "a NEW defect landed" : "a repair landed and the pin must come down with it"}`);
      }
    }
    return { findings, measured, seconds: Math.round((Date.now() - started) / 1000) };
  } catch (error) {
    return { findings: [`live leg threw: ${String(error.message).slice(0, 200)}`], measured: null, seconds: Math.round((Date.now() - started) / 1000) };
  } finally {
    try { await browser?.close(); } catch { /* already gone */ }
    try { serve?.kill("SIGTERM"); } catch { /* already gone */ }
  }
}

// ---- run ------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = pure;
  ok("PURE — the four ways a declared gap fails to communicate, each isolated: the pointer says clickable, the fill says primary, the attribute sits on something assistive technology does not treat as a control, and the marker class carries no attribute at all. A fully repaired control reads clean and the estate's own shipped convention is not condemned", pure.length === 0, pure.slice(0, 4).join(" ; "));

  const src = sourceFindings({ serve: readText(SERVE_SRC), lib: readText(LIB_PATH) });
  evidence.source = src;
  ok("SOURCE — every gap-ish class token the serve actually uses is one the classifier knows, the shared `gap` marker is among them, at least the seven shipped `.gap` rules still exist, and the classifier reaches no browser, file, clock or network", src.length === 0, src.slice(0, 4).join(" ; "));

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "named-gap-mutation-"));
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

  await mutate("CURSOR — any cursor is accepted", (t) => t.replace('if (control?.cursor !== "not-allowed") {', "if (false) {"));
  await mutate("CURSOR — `default` is accepted as disabled", (t) => t.replace('control?.cursor !== "not-allowed"', 'control?.cursor !== "not-allowed" && control?.cursor !== "default"'));
  await mutate("FILL — saturation stops being tested", (t) => t.replace("return Math.max(bg.r, bg.g, bg.b) - Math.min(bg.r, bg.g, bg.b) > SATURATION_FLOOR;", "return true;"));
  await mutate("FILL — alpha stops being tested", (t) => t.replace("if (bg.a <= FILL_ALPHA_FLOOR) return false;", ""));
  await mutate("FILL — nothing is ever a primary fill", (t) => t.replace("export function isPrimaryFill(backgroundColor, opacity = 1) {", "export function isPrimaryFill(backgroundColor, opacity = 1) {\n  return false;"));
  await mutate("FILL — the saturation floor is raised past a green button", (t) => t.replace("export const SATURATION_FLOOR = 40;", "export const SATURATION_FLOOR = 200;"));
  await mutate("FILL — opacity stops being read, so a deliberate dim is condemned", (t) => t.replace("  if (Number.isFinite(alpha) && alpha <= DIMMED_OPACITY_CEILING) return false;", ""));
  await mutate("FILL — the dim ceiling rises past full strength, so nothing is ever primary", (t) => t.replace("export const DIMMED_OPACITY_CEILING = 0.8;", "export const DIMMED_OPACITY_CEILING = 1;"));
  await mutate("REACH — the finding is never emitted", (t) => t.replace("  if (missing.length) {", "  if (false) {"));
  await mutate("REACH — a role alone is enough, unfocusable", (t) => t.replace('if (declared && control?.tabindex == null) missing.push("no tabindex");', ""));
  await mutate("REACH — a tabindex alone is enough, announced as nothing", (t) => t.replace('if (declared && !control?.role) missing.push("no role");', ""));
  await mutate("UNMARKED — a marker with no attribute is accepted", (t) => t.replace("if (marked && !declared) {", "if (false) {"));
  await mutate("MARKER — the shared `gap` token drops out of the vocabulary", (t) => t.replace('"gap", "mst-gap"', '"mst-gap"'));
  await mutate("MARKER — a private spelling drops out", (t) => t.replace('"fus-gap", ', ""));
  await mutate("MARKER — prose notes become controls", (t) => t.replace("if (tokens.some((t) => NOT_CONTROL_MARKERS.includes(t))) return false;", ""));
  await mutate("MARKER — everything is a marker", (t) => t.replace("return tokens.some((t) => GAP_MARKER_TOKENS.includes(t));", "return true;"));
  await mutate("SCOPE — non-gaps are judged too", (t) => t.replace("if (!marked && !declared) return findings;", ""));
  await mutate("TOTALS — the labelled count stops filtering to gaps", (t) => t.replace('if (!hasGapMarker(control.className) && control.ariaDisabled !== true) continue;', ""));
  await mutate("PARSE — a non-colour parses as black", (t) => t.replace("if (match === null) return null;", "if (match === null) return { r: 0, g: 0, b: 0, a: 1 };"));

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
  emitVerifierCensus({ verifierId: "named-gap-perception", sourceUrl: import.meta.url, results });
  if (MODE === "drills") {
    console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
    process.exit(passed === results.length ? 0 : 1);
  }

  const live = await liveLeg();
  evidence.live = live;
  console.log(`\n# LIVE — ${live.findings.length === 0 ? "green" : live.findings.join("; ")} in ${live.seconds}s`);
  if (live.measured) console.log(`# measured ${JSON.stringify(live.measured)}`);

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
  if (binding.length) rows.find((r) => r.n === 8).red = `BINDING: ${binding.join("; ")}`;

  const result = verdict(rows);
  evidence.verdict = result;
  console.log(`\n=== VERDICT: ${result.kind.toUpperCase()}${result.failures.length ? ` — ${result.failures.join(" ; ")}` : ""}`);
  for (const a of result.absences) console.log(`NAMED  clause ${a.n}: ${a.what}`);
  console.log(`evidence: ${path.relative(ROOT, writeEvidence())}`);
  process.exit(result.kind === "pass" ? 0 : result.kind === "named_failure" ? 2 : 1);
}

main().catch((e) => { console.error(e); writeEvidence(); process.exit(1); });
