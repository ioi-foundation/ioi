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
  // 2026-09-28 (R-241, Ontology Manager O7): four open rows over the daemon's `caller_may_change` (the ODK list and get now say
  // per read whether the caller may change an ontology: its owner or an administrator of its organization). Editing splits
  // in four — who may edit (a member reads the reference's own "You do not have edit permissions", the owner gets the
  // editable page) and the owner's Review changes bound; an object type's save named (the reference's "Backing datasource is
  // missing"); an action type's save refused by name (Hypervisor:OntologyEditNotBound). New splits in three — disabled for a
  // member with the reference's own, now true, permission reason (bound); the owner's creation wizard, stopped at its
  // backing datasource, and the kinds the model keeps none of, named. Object views named ("Object views are not enabled": the
  // Hypervisor keeps no object views); the migration assistant named (nothing to move into project permissions).
  // 60 → 65; bound 28 → 31, refused 7 → 8, named 20 → 25, open 5 → 1 (Explorer's object search stays open).
  // Before that, 2026-09-28 (R-240 Arm A, dead-control census): Monitor this object type no longer opens the shell's not-found page — the
  // reference's Data Health links open Operations → Health. Its row becomes a named gap: an object type is not a health-check
  // target and holds no objects to observe. named 19 → 20; open 6 → 5.
  // Before that, 2026-09-28 (R-241, Ontology Manager O6, proposals): the one open Proposals row becomes twenty over ODK's proposal plane.
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
  "ontology-manager": { total: 65, bound: 31, refused: 8, named_gap: 25, open: 1 },
  // 2026-09-29 (R-241, Data Connection D8): 60 → 63. The schedule editor's chunk (51877) reached the mirror, and the open
  // row splits in three, driven by check:adopted-data-connection over daemon truth: choosing "On a schedule" renders the
  // reference's schedule editor, each cron expression it composes checked by the daemon's own cron parser (the automation
  // scheduler's GET /v1/hypervisor/cron-preview) — bound; a sync saved on a schedule, in Edit syncs and on its
  // Configuration page, refused by name at its checkpoint read and its create-schedules before anything is written (no
  // schedule runs a sync: each run takes its own wallet-authority grant, and the scheduler's Time triggers fire automation
  // steps, none of which admits a materializing run) — refused; Duplicate sync on a schedule declares the new sync and its
  // schedule is refused — refused. A REST source's Edit syncs, reached by URL, joins as bound: its lease plans (none) and
  // its New — the source's Create webhook — off, its tooltip the runtime reason D5 made true (never a permission). bound
  // 36 → 38, refused 8 → 10, named 15, open 1 → 0.
  "data-connection": { total: 63, bound: 38, refused: 10, named_gap: 15, open: 0 },
  // Before that, 2026-09-29 (R-241, Data Connection D7): 51 → 60. Edit syncs' chunk reached the mirror, and the open row splits in
  // eight, driven by check:adopted-data-connection over daemon truth: the page (the source's lease plans, each its dataset
  // in the source's folder; a sync's panel: schedule Manually, build policy Always, the plan's configuration), a panel's
  // Save (the plan's PATCH) and Bulk edit with the schedule Manually (what is already true: nothing written) bound; what
  // a plan cannot hold in the panel (transaction type, build policy, compute profile, Run), Bulk edit's maximum duration
  // and Run N syncs (the build service's submitBuild) refused by name; Start pipelining (the Pipeline Builder's create, in
  // a new tab) named. Where a source is filed (Parent folder, Output folder and its settings page: its project's folder,
  // else the organization folder — a project-filed source read "local /" and the output folder "error") and the stopped-
  // daemon Edit syncs join as bound. Found on the way: "On a schedule" crashes on a chunk the mirror lacks (open). bound
  // 31 → 36, refused 5 → 8, named 14 → 15, open 1 → 1 (source.edit-syncs closed, source.edit-syncs.schedule opened).
  // Before that, 2026-09-29 (R-241, Data Connection D6): 43 → 51. The reference's checkpoint prompt chunks reached the mirror, so the
  // writes are driven by a click, and the one open row splits in seven: a configuration's Save after a real edit (the
  // plan's PATCH), the checkpoint read before a write (the daemon's justification-checkpoint plane: its catalog gates no
  // lease-plan write, so none applies), Duplicate's Create sync, New on a custom source (the reference's YAML editor, the
  // plan's ladder written in it) and a new sync's output folder (its source's project folder, else the owner's
  // organization folder; nothing created) bound; New on a bucket (the reference's file-sync form) and what a plan cannot
  // hold refused by name. The checkpoint read with the daemon stopped joins as bound. Found on the way: Edit syncs crashes
  // on a chunk the mirror lacks (open). bound 25 → 31, refused 3 → 5, open 1 → 1 (sync.create-duplicate-save closed,
  // source.edit-syncs opened).
  // Before that, 2026-09-28 (R-241, Data Connection D2 part 3 / D5): 41 → 43. A source's Virtual tables (none, and none can be) and
  // Logs (the reference's log viewer over its syncs' run receipts) bound; Explore source (no explore plane) and the Webhooks
  // callout (no webhook plane, no other runtime) named, each shown in the reference's words made true at the wire; a failed
  // run bound by check:adopted-data-connection-runs (a sealed authority grants the lease and the session, the daemon refuses
  // the grantless execute, and the sync reads Failed). Duplicate sync's page joins as bound and its destination crumb as a
  // named gap. The writes (New, Duplicate's Create sync, Save) stay open: bound at the adopted layer and asserted through
  // the serve, but a click never reaches them — the reference's checkpoint prompt chunks are missing from the local mirror.
  // bound 21 → 25, named 11 → 14, open 6 → 1.
  // Earlier, in order:
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
  // 2026-09-28 (R-241, Approvals A2): the two open rows become five, all driven live by check:adopted-approvals over daemon
  // truth. A challenge Approved (the operator's passphrase on the daemon's decision route mints one grant), Completed (the
  // requester's retry consumes it; a replay is refused) and Closed (a restarted daemon with a shortened pending window —
  // IOI_HYPERVISOR_AUTHORITY_CHALLENGE_TTL_MS, which can only shorten it — lets an ask expire undecided): bound. A thread
  // approval parked on a real run through the daemon's thread-approval route, listed with who asked and when (the inbox row
  // now carries both) and its page: bound. Its decisions: refused by name (they take a wallet grant for the exact lease;
  // the refusal no longer points at a run card that does not exist). 74 → 77; bound 29 → 33, refused 5 → 6, open 2 → 0.
  // Before that, 2026-09-28 (R-241, Approvals A1): first census — 74 flow states: the 60 harvested (the inbox's quick filters, the type,
  // status, creator and sort menus, search, the eight request types and their facets, a request's page, invite reviewers,
  // edit, a reviewer task, a comment; the Compass request-access and New project dialogs the harvest walked to make its
  // example) plus 14 found by driving the adopted app (the governance request's page, each decision, the fence, the stopped
  // daemon, the inbox's other planes, the shared sidebar). 29 bound by check:adopted-approvals over a live parked challenge;
  // 5 refused by name (Approve on a parked effect — no passphrase field and no key here — a governance Reject, Close,
  // invite reviewers, a comment); 38 named gaps (the seven reference types with no Hypervisor counterpart, the access
  // facets, Control Panel's redirecting task ids, the 20 Compass dialog states, Edit, the reviewer task card, Request
  // changes, the inbox's other planes, the sidebar); 2 open (a challenge's Approved / Completed / Closed statuses, a
  // thread approval — both mapped and unit-tested, neither driven).
  approvals: { total: 77, bound: 33, refused: 6, named_gap: 38, open: 0 },
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
