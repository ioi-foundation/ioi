#!/usr/bin/env node
// check:seed-depth — THE UX SEED DEPTH CENSUS (R-241; apps/hypervisor/docs/ux-seed-depth-phase.md).
//
// The phase's unit is a reference FLOW state, not a landing page: 33 of 39 seeds had recorded only their
// landing, so their flows were never ported and the surfaces filled them with hand-rolled forms. This
// gate holds the tracked record of every flow state of every adopted app (apps/hypervisor/seed-depth.v1.json)
// to four rules:
//
//   1. Every state has ONE disposition: bound · refused · named_gap · open.
//   2. A bound or refused state names its proof — a file and the EXACT text of an assertion or test in
//      it. The text must still be there: renaming or deleting the proof breaks the claim here, not
//      silently.
//   3. A named gap says what the person SEES (`shown_as`) and why; an open state says why it is open.
//      Open states are debt the census counts down; they are never a pass by omission.
//   4. The populations are PINNED EXACTLY per app and disposition. A change re-pins here with its
//      reason beside the number, in the same commit — so a state cannot quietly move from bound to open
//      or disappear.
//
// Apps later in the phase order carry status not_started and no states until their cut begins.
// Static: reads tracked files only (the live proofs are the cited verifiers, which run in their own gates).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const RECORD = path.join(APP, "seed-depth.v1.json");

const DISPOSITIONS = ["bound", "refused", "named_gap", "open"];
const PHASE_ORDER = ["automate", "pipeline-builder", "sessions", "ontology-manager", "data-connection"];

// Pinned populations. Re-pin with the reason beside the number, in the commit that moves it.
const PINS = {
  // 2026-09-27 (R-241): 34 → 37 — the Overview's sections: Recently triggered is bound (automatic runs,
  // with the condition that fired them); Failures in last 4 weeks is fed by the same events but unproven
  // (open); Recently viewed always reads empty because no view history is kept (open). Open 4 → 6.
  // Before that, 2026-09-27 (R-241): 31 → 34 — the header driven: File → Rename is bound (UpdateResourceName, and the
  // Location row names the project). Found on the way: Favorite is refused but silent (open), Move / Share /
  // Trash are disabled with no Hypervisor counterpart (named gap), Open automation… is undriven (open).
  // Open 3 → 4 (rename left, favorite and open-automation joined).
  // Before that, 2026-09-27 (R-241): 28 → 31 — the detail page's side tabs, driven: History (the automation's runs as
  // events, filtered), Execute (a manual execution is the automation's Run now) and Telemetry (counted from
  // its executions) are bound by one live assertion; "the side tabs undriven" leaves open, and History's
  // Edits filter joins it (no per-automation edit history is kept yet). Open stays 3.
  // Before that, 2026-09-27 (R-241): 27 → 28 — Settings split in two. The expiration date is now the automation's
  // expires_at, enforced by the daemon (scheduler and webhook stop firing it): bound. Event and effect
  // retries are refused by name (the executor does not retry): refused. Open 4 → 3.
  // Before that, 2026-09-27 (R-241): first census — 27 flow states: the 18 harvested wizard / list / detail states plus
  // the edit, save-as and detail-write states found by driving the adopted app. 12 bound (each a live
  // assertion of check:adopted-automate), 9 refused by name (object, threshold and dependency conditions;
  // Action, Logic and Notification effects), 2 named gaps (Unknown Agent; Unknown effect for command and
  // proposal steps), 4 open (header rename unproven; the side tabs undriven; settings accepted but not
  // enforced; the editor's Time label for a manual automation).
  automate: { total: 37, bound: 18, refused: 10, named_gap: 3, open: 6 },
  "pipeline-builder": { total: 0, bound: 0, refused: 0, named_gap: 0, open: 0 },
  sessions: { total: 0, bound: 0, refused: 0, named_gap: 0, open: 0 },
  "ontology-manager": { total: 0, bound: 0, refused: 0, named_gap: 0, open: 0 },
  "data-connection": { total: 0, bound: 0, refused: 0, named_gap: 0, open: 0 },
};

const results = [];
const ok = (name, pass, detail = "") => results.push({ name, pass: !!pass, detail });

let record = null;
try { record = JSON.parse(fs.readFileSync(RECORD, "utf8")); } catch (e) { ok("the seed-depth record parses", false, String(e.message)); }

if (record) {
  ok("the record declares its schema", record.schema === "ioi.hypervisor.seed-depth.v1", String(record.schema));
  const apps = Array.isArray(record.apps) ? record.apps : [];
  ok("the record lists the phase's apps in the phase order", JSON.stringify(apps.map((a) => a.id)) === JSON.stringify(PHASE_ORDER), apps.map((a) => a.id).join(" → "));

  const fileCache = new Map();
  const readTracked = (rel) => {
    if (!fileCache.has(rel)) { try { fileCache.set(rel, fs.readFileSync(path.join(ROOT, rel), "utf8")); } catch { fileCache.set(rel, null); } }
    return fileCache.get(rel);
  };

  for (const app of apps) {
    const states = Array.isArray(app.states) ? app.states : [];
    const problems = [];
    const ids = new Set();
    for (const s of states) {
      if (!s.id || ids.has(s.id)) problems.push(`duplicate or missing id ${s.id}`);
      ids.add(s.id);
      if (!s.label) problems.push(`${s.id}: no label`);
      if (!DISPOSITIONS.includes(s.disposition)) { problems.push(`${s.id}: disposition ${s.disposition}`); continue; }
      if (s.disposition === "bound" || s.disposition === "refused") {
        const text = readTracked(s.proof?.file || "");
        if (text === null) problems.push(`${s.id}: proof file ${s.proof?.file} not found`);
        else if (!s.proof?.text || !text.includes(s.proof.text)) problems.push(`${s.id}: proof text is not in ${s.proof?.file}: "${String(s.proof?.text).slice(0, 60)}"`);
      }
      if (s.disposition === "named_gap" && !(String(s.shown_as || "").length >= 8 && String(s.reason || "").length >= 20)) problems.push(`${s.id}: a named gap says what is shown and why`);
      if (s.disposition === "open" && String(s.reason || "").length < 20) problems.push(`${s.id}: an open state says why it is open`);
    }
    if (app.status === "not_started" && states.length) problems.push("a not_started app carries states");
    if (app.status !== "not_started" && !(app.verifier && readTracked(app.verifier) !== null)) problems.push(`its verifier ${app.verifier} is not a tracked file`);
    ok(`${app.id}: every state has one disposition and a proof, a shown gap or a reason`, problems.length === 0, problems.slice(0, 6).join(" · "));

    const got = { total: states.length, ...Object.fromEntries(DISPOSITIONS.map((d) => [d, states.filter((s) => s.disposition === d).length])) };
    const pin = PINS[app.id];
    ok(`${app.id}: populations pinned exactly`, !!pin && JSON.stringify(got) === JSON.stringify(pin),
      `got ${JSON.stringify(got)}${pin ? ` · pinned ${JSON.stringify(pin)}` : " · no pin"}`);
  }
  // No tenant identifiers ride in a public record.
  const raw = fs.readFileSync(RECORD, "utf8");
  ok("the record carries no reference-tenant URL or resource id", !/palantirfoundry|ri\.[a-z-]+\.main\.[a-z-]+\.[0-9a-f]{8}-/u.test(raw), "");
}

const fails = results.filter((r) => !r.pass);
for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
const open = record ? (record.apps || []).reduce((n, a) => n + (a.states || []).filter((s) => s.disposition === "open").length, 0) : null;
console.log(`\n${results.length - fails.length}/${results.length} passed · open flow states: ${open}`);
process.exit(fails.length ? 1 : 0);
