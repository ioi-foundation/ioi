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
const PHASE_ORDER = ["automate", "pipeline-builder", "sessions", "ontology-manager", "data-connection", "approvals"];

// Pinned populations. Re-pin with the reason beside the number, in the commit that moves it.
const PINS = {
  // 2026-09-27 (R-240 Arm A): 37 → 39 — the header's project breadcrumb now opens the project (it went nowhere:
  // the resolver never applied the header's ResourceAncestor fragment; check:adopted-dead-controls found it),
  // and the daemon-stopped state answers an error rather than an empty list. Both bound.
  // Before that, 2026-09-27 (R-241): Failures in last 4 weeks proved (a webhook-fired run whose step failed is listed):
  // open → bound; Automate open 6 → 5.
  // Before that, 2026-09-27 (R-241): 34 → 37 — the Overview's sections: Recently triggered is bound (automatic runs,
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
  automate: { total: 39, bound: 24, refused: 10, named_gap: 3, open: 2 },
  // 2026-09-27 (R-241): Proposals bound — the family's change sets by status (proposed open, merged merged,
  // rejected/abandoned closed), each proposal's page over its change set (diff of declared outputs, rebase
  // check, events). Open 5 → 4.
  // Before that, 2026-09-27 (R-240 Arm A): 16 → 18 — Data recipes (/data/recipes) opens the adopted builder (v2 recipes were
  // invisible on the owner's route), and the daemon-stopped state answers an error. Both bound.
  // Before that, 2026-09-27 (R-241, ADR 0056 P4 cut 2c): 15 → 16 — Create is bound (a founding change set, landing in the
  // editor on its draft sandbox) and its location dialog joins as bound (the recipe registry is the one
  // location); Streaming and the Faster / External computes are refused by name. Open 8 → 5.
  // Before that, 2026-09-27 (R-241, ADR 0056 P4 cut 2b): 14 → 15 — the editor opens a pipeline read-only on its Main
  // sandbox (bound: editor.open); its graph (no transforms derived from a recipe's steps, no edit operation)
  // and its outputs pane (declared outputs without columns or a target ontology) move open → named gap.
  // Open 10 → 8.
  // Before that, 2026-09-27 (R-241, ADR 0056 P4 cut 2a): 11 → 14 — the landing over DataRecipe families and change sets:
  // the list (outputs from each recipe's declared outputs, Batch, never deployed), Search and the creator are
  // bound by check:adopted-pipeline; the Project filter is a named gap (a DataRecipe is held in no project).
  // Open 11 → 10.
  // Before that, 2026-09-27 (R-241): Pipeline Builder's cut begins — 11 states harvested read-only (landing,
  // examples, the create form and its two choices, the editor's graph, add data, outputs, proposals, history,
  // deploy); all open until bound to DataRecipe revisions and TransformationRuns.
  "pipeline-builder": { total: 28, bound: 17, refused: 3, named_gap: 6, open: 2 },
  // 2026-09-27 (R-241, Sessions cut 1): first rows — rename, auto-stop, Goal mode and the page's own port sync
  // refused by name; services and tasks named (absent planes); logs bound in the adapter but not yet live-asserted.
  sessions: { total: 24, bound: 12, refused: 7, named_gap: 5, open: 0 },
  // 2026-09-28 (R-241, Ontology Manager O6, proposals): the one open Proposals row becomes twenty over ODK's proposal plane.
  // Bound (check:adopted-ontology, live): Your proposals, the state tabs (open → In review and Assigned to you, applied →
  // Merged, withdrawn → Closed), a proposal's Overview, Review changes and History, Approve (an ODK proposal merges when
  // approved: the daemon's /apply), Close (the daemon's /withdraw), the pages' fence and the stopped daemon. Refused by
  // name: a stale proposal's approval (the daemon's ontology_proposal_stale), Reject, reviewers, editing the request,
  // deciding again, Create branch, Add edits to Branch. Named: the branch switcher (no branches kept), comments, a merged
  // proposal's before side and a stale proposal's diff (no revision snapshots). 41 → 60; open 7 → 6.
  // Before that, 2026-09-28 (R-241, Object Explorer O4): Explorer's landing adopted (/workspace/hubble) — the one open landing row
  // becomes six: the catalog and Recents bound (Recents shared with the Ontology Manager), counts, empty shortcuts and
  // lists named, object search open. 36 → 41.
  // Before that, 2026-09-28 (R-241, Ontology Manager O3): Functions bound — a released function crashed the section (the list read
  // its locator's kind, and the answer had none); it lists now, visible. Its Source column joins as a named gap (a
  // Hypervisor function has no code repository). 35 → 36; open 8 → 7.
  // Before that, 2026-09-28 (R-241, Ontology Manager O3): first census — 35 flow states: the 27 harvested (Discover, 13 sections, an
  // object type and its tabs, Explorer's landing) plus 8 found by driving the adopted app (a link type's page and its foreign
  // key, New, editing, the migration page, the daemon stopped, the fence). 16 bound by check:adopted-ontology; 11 named
  // gaps (what an ODK model does not hold, in the reference's own empty states; Cleanup's usage read); 8 open (Functions
  // unproven, Proposals unmapped, Monitor opens a missing app, Object views says "Failed", New and edit give false or no
  // reasons, the migration page undriven, Explorer not routed).
  "ontology-manager": { total: 60, bound: 28, refused: 7, named_gap: 19, open: 6 },
  // 2026-09-28 (R-241, Data Connection D0): the harvest — 22 flow states, all open until the app is adopted. Examples
  // built on the tenant at the owner's direction (a REST API source; the "Connecting to AWS S3" example, its sync run —
  // it fails without the training bucket's credentials) gave a source's and a sync's pages.
  // 2026-09-28 (R-241, Data Connection D1): adopted at /workspace/data-ingestion-app behind its fence — the landing and
  // the Sources list bound over the data-source plane (check:adopted-data-connection), with the stopped-daemon state and
  // the fence; Syncs, Agents, Listeners and External stacks named (none exists), and the runtime badge. 22 → 25.
  // 2026-09-28 (R-241, Data Connection D2, part 1): a source's Overview bound (opened from the list; the mirror's index
  // refreshed to the tenant's current build — the old runtime had loaded new chunks); New source's false "no permission"
  // tooltip joins as open. 25 → 26.
  // 2026-09-28 (R-241, Data Connection D2, part 2): a source's Code imports and Webhooks bound (both off, nothing can turn
  // either on); the webhooks callout's false runtime reason joins as open, the reference's two fixed-on switches named;
  // Connection settings' reads bound but the page shows a false "no permission" (no update route) — stays open. 26 → 28.
  // 2026-09-28 (R-241, Data Connection D3): New source creates a data-source declaration (REST API; a draft until its
  // domain is set), the setup's steps walk through, and a REST source's connection settings save its endpoint — seven
  // states bound; any other type refused by name; the reference's connector directory named. 28 → 30.
  // 2026-09-28 (R-241, Data Connection D4): syncs over the import ladder — a sync is a capability-lease plan on one of the
  // caller's sources, its builds the plan's materializing runs. The Syncs list (and its filters), a source's Batch syncs
  // table, a sync's Overview, Configuration and Versions bound (named gap → bound 1, open → bound 4); a run's status
  // (Waiting, Canceled, driven live) and the stopped-daemon Syncs list join as bound; Run (needs a wallet-authority grant)
  // and Delete refused by name; Versions' history, Created by, the output dataset, the live banner and the build report
  // named; a failed run (needs a grant to drive) and New / Duplicate / Save (undriven) open. The splash row's proof text
  // (stale since D3, so this gate was red) now cites the assertion. 30 → 41.
  "data-connection": { total: 41, bound: 21, refused: 3, named_gap: 11, open: 6 },
  // 2026-09-28 (R-241, Approvals A1): first census — 74 flow states: the 60 harvested (the inbox's quick filters, the type,
  // status, creator and sort menus, search, the eight request types and their facets, a request's page, invite reviewers,
  // edit, a reviewer task, a comment; the Compass request-access and New project dialogs the harvest walked to make its
  // example) plus 14 found by driving the adopted app (the governance request's page, each decision, the fence, the stopped
  // daemon, the inbox's other planes, the shared sidebar). 29 bound by check:adopted-approvals over a live parked challenge;
  // 5 refused by name (Approve on a parked effect — no passphrase field and no key here — a governance Reject, Close,
  // invite reviewers, a comment); 38 named gaps (the seven reference types with no Hypervisor counterpart, the access
  // facets, Control Panel's redirecting task ids, the 20 Compass dialog states, Edit, the reviewer task card, Request
  // changes, the inbox's other planes, the sidebar); 2 open (a challenge's Approved / Completed / Closed statuses, a
  // thread approval — both mapped and unit-tested, neither driven).
  approvals: { total: 74, bound: 29, refused: 5, named_gap: 38, open: 2 },
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
    // An app with a bound state names the live verifier that proves it (a tracked file); before its first
    // binding it names none rather than borrowing another app's.
    if (states.some((st) => st.disposition === "bound") && !(app.verifier && readTracked(app.verifier) !== null)) problems.push(`its verifier ${app.verifier} is not a tracked file`);
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
