// autonomous-system-journey — the autonomous-systems lifecycle as DATA, and the pure rules that keep the
// journey table and its verdict honest (R-240, ADR 0056; .artifacts/mvp-finish-line/journey-gap-map-2026-09-25.md).
//
// The owner's done-bar is that a person can take ONE System through its whole life in the product. Every
// per-surface gate is right about its own surface, and none of them can see the seams BETWEEN steps: the
// gap map's central finding was that there was no System to hand work to at all. So the journey is held
// here as data — eleven steps, each with the legs that must be proven and the hand-off it owes the next
// step — and every leg is exactly one of
//
//   live       measured by the gate's own continuous walk, judged by the assertion it names
//   composed   proven by an existing gate this journey RUNS; never re-proven here
//   named_gap  absent today, by code, naming the missing plane — never a pass
//   todo       buildable today, its live leg not yet written — never a pass
//
// A hand-off is judged by step N's object appearing as an option or a link in step N+1's form. A step
// whose hand-off is not judged is red, never skipped. The last step hands off to nothing: the walk ends
// with a restart and a re-read of the System.
//
// It reaches no browser, file, clock or network and imports nothing, so a planted copy of it can be
// loaded from anywhere by the mutation battery.

export const TAG = "{tag}";
export const LEG_KINDS = Object.freeze(["live", "composed", "named_gap", "todo"]);

// ---- COMPOSE -----------------------------------------------------------------------------------
// The existing gates this journey RUNS and does not re-prove. `pkg` names the package.json that holds
// the script: "app" = @ioi/hypervisor-app, "root" = the repository root. Two are run in their ROOT form on
// purpose: the app workspace's `check:cross-surface-propagation` and `check:dead-controls` are their
// CI-bound drills, and a drill proves nothing about the product.
export const COMPOSE = Object.freeze([
  { id: "system-genesis-product-journey", pkg: "app", script: "check:system-genesis-product-journey", minutes: 120, needs: "daemon + real wallet.network fixture",
    proves: "M1.6/M1.7 genesis through the surfaces with real wallet grants: compact and advanced lanes, blocker reports, the governed ladder, the System workspace's seven served modes and its policy, two-System isolation, continuity through the forms, restart byte-exact, the degraded daemon" },
  { id: "studio-journey", pkg: "app", script: "check:studio-journey", minutes: 30, needs: "daemon",
    proves: "blueprints and descriptors created, updated and promoted through Studio's own action lane; promotion composes a real Governance ApprovalRequest seen on the approvals page; restart" },
  { id: "cross-surface-propagation", pkg: "root", script: "check:cross-surface-propagation", minutes: 45, needs: "daemon + chromium",
    proves: "a value written through its owning surface's form appears on every consumer by its own name: ontology, object type, source and mapping into the Designer, Pipeline and ODK; a Designer diagram into Studio's blueprints; a filed issue into Issues, /operations/issues and Work / Incidents" },
  { id: "system-record-seam", pkg: "app", script: "check:system-record-seam", minutes: 60, needs: "daemon + real wallet.network fixture",
    proves: "records admitted under a bounded System through the contract-typed seam with the SystemScopedObjectBinding derived — the daemon half of attaching data to a System" },
  { id: "automations-journey", pkg: "app", script: "check:automations-journey", minutes: 30, needs: "daemon",
    proves: "the /automations mount over the daemon automations family; identity-first write verbs through the serve's action lanes; runs bound to the acting principal" },
  { id: "launch-chain", pkg: "app", script: "check:launch-chain", minutes: 30, needs: "daemon",
    proves: "one owned Session through the typed launch chain with a daemon-resolved subject attachment, principal-bound receipts, stop/archive and restart recovery" },
  { id: "systems-work-projections", pkg: "app", script: "check:systems-work-projections", minutes: 30, needs: "daemon",
    proves: "a real admitted Session becomes one Work row with the owner's identity and a typed deep link; the Systems projection answers under policy" },
  { id: "governance-journey", pkg: "app", script: "check:governance-journey", minutes: 30, needs: "daemon",
    proves: "submit, approve or deny with a daemon-resolved reviewer, decision receipt, readback; stale and withdrawn refusals typed; restart" },
  { id: "receipts-on-demand", pkg: "app", script: "check:receipts-on-demand", minutes: 60, needs: "daemon + real wallet.network fixture",
    proves: "after a run, ONE request to the surface's retrieval route answers what it touched and under what authority, citing receipts" },
  { id: "governed-evaluation-plane", pkg: "app", script: "check:governed-evaluation-plane", minutes: 45, needs: "daemon + two stub model servers",
    proves: "Evaluations as a governed daemon plane: released suites, frozen epochs, admitted runs, derived verdict floors (no UI consumer yet)" },
  { id: "improvement-governance-spine", pkg: "app", script: "check:improvement-governance-spine", minutes: 30, needs: "daemon",
    proves: "the direct improvement proposal path and the bounded campaign spine; the campaign owns no production mutation" },
  { id: "agent-studio-write-lanes", pkg: "app", script: "check:agent-studio-write-lanes", minutes: 20, needs: "daemon",
    proves: "improvement Propose / Approve / Reject / Apply and their governance gates, submitted as a signed-in operator and judged by the daemon's recorded state" },
  { id: "packages-journey", pkg: "app", script: "check:packages-journey", minutes: 45, needs: "daemon",
    proves: "DomainApp packages: candidate, release, installation, recall and uninstall through the UI action lane; launchability earned by a serving binding" },
  { id: "notification-inbox", pkg: "app", script: "check:notification-inbox", minutes: 15, needs: "daemon",
    proves: "the P1 notification inbox as a daemon projection of owner events: identity first, one link back per item, re-derived after a restart (no surface renders it)" },
  { id: "notification-panel", pkg: "app", script: "check:notification-panel", minutes: 15, needs: "daemon + chromium",
    proves: "the shell's panel over the P1 inbox in a browser: rows are the API's for the same person, one link each, day groups, family chips, the rail's link, signed-out and outage states" },
  { id: "named-gap-truth", pkg: "app", script: "check:named-gap-truth", minutes: 20, needs: "daemon",
    proves: "every named-gap reason and user-reaching string is true at its emission point against the router" },
  { id: "dead-controls", pkg: "root", script: "check:dead-controls", minutes: 60, needs: "own serve + chromium",
    proves: "every live-looking control on the registered surfaces does something; exits 2 by design while its three named absences stand" },
]);

// ---- THE JOURNEY -------------------------------------------------------------------------------
// Placeholders the gate fills: {tag} (the run's tag), {system} (the System's route tail, e.g.
// acme/journey-asj1a2b3c), {system_id} (system://…).
export const JOURNEY = Object.freeze([
  {
    n: 1, id: "create", title: "Create a System from a template",
    surface: "/__ioi/systems/compose (Studio · System Genesis Composer, compact lane), then the governed ladder's forms on /systems/{system}/govern",
    legs: [
      { id: "genesis-admission", kind: "live", what: "the composer's rendered form, submitted without a grant for the daemon's exact challenge, then resubmitted through the challenge page's own form with a real wallet.network grant for those hashes: ONE admission whose daemon record carries the walk's system_id",
        assertion: "CREATE — the composer's rendered form admits ONE System with a real wallet grant for the exact hashes the surface showed" },
      { id: "governed-ladder", kind: "live", what: "materialize, initialize and activate through the forms the System's Govern mode renders, each challenged and granted; the committed page carries the live chain status",
        assertion: "CREATE — materialize, initialize and activate commit through the forms the System's Govern mode renders, and the System is active" },
      { id: "genesis-depth", kind: "composed", gate: "system-genesis-product-journey", what: "the genesis state matrix: honest empty, blocker reports, premature activation refused, two-System isolation, restart byte-exact, the degraded daemon" },
      { id: "template-picker", kind: "named_gap", what: "a template picker: the composer takes a raw JSON declaration, not a System release picked from a registry",
        gap: { code: "system_template_picker_absent", plane: "Studio / Templates (ADR 0056 M8) over a registry-backed System release", source: "gap map step 1; build order 3" } },
      { id: "approval-in-inbox", kind: "named_gap", what: "approving genesis in the Governance approvals inbox: today the grant is minted in the wallet and PASTED into the challenge form",
        gap: { code: "genesis_approval_not_in_inbox", plane: "the genesis challenge folded into Governance approvals (a wallet approval, not a pasted grant)", source: "gap map step 1; build order 3" } },
    ],
    handoff: { into: "design", legs: [
      { id: "system-links-its-design", kind: "live", judged_by: "the created System is a card on /systems whose design link — the daemon's own published mode route — lands on the served System workspace in Design mode for THIS System, and that page's hand-off to Studio lands",
        assertion: "HAND-OFF 1→2 — /systems lists the created System, its Design link lands on the System workspace for it, and the workspace's hand-off to Studio lands" },
      { id: "system-offered-to-studio", kind: "named_gap", judged_by: "Studio's blueprint form offers the System as a system_ref option",
        gap: { code: "blueprint_system_ref_absent", plane: "blueprint system_ref (Studio blueprint plane)", source: "gap map hand-off 1→2; build order 4 (contract-first)",
          probe: { route: "/systems/{system}/design", marker: 'data-system-named-gap="blueprint system_ref (Studio blueprint plane)"' } } },
    ] },
  },
  {
    n: 2, id: "design", title: "Design it in Studio",
    surface: "/studio (blueprints, descriptors) · /__ioi/studio/designer (Solution Designer)",
    legs: [
      { id: "blueprint-authoring", kind: "composed", gate: "studio-journey", what: "blueprints and descriptors created, updated and promoted through Studio's own action lane" },
      { id: "designer-to-blueprints", kind: "composed", gate: "cross-surface-propagation", what: "a diagram saved in the Designer is listed among Studio's blueprints" },
      { id: "walk-blueprint", kind: "live", what: "THIS walk's blueprint bp-{tag}, created through the form Studio's blueprints view renders (its owner the tenant the form offers) and read back BY NAME on that view",
        assertion: "DESIGN — THIS walk's blueprint is created through Studio's own form and listed by its own name on Studio's blueprints" },
      { id: "design-bound-to-system", kind: "named_gap", what: "a design bound to the System",
        gap: { code: "blueprint_system_ref_absent", plane: "blueprint system_ref (Studio blueprint plane)", source: "gap map step 2; build order 4 (contract-first)" } },
    ],
    handoff: { into: "data", legs: [
      { id: "studio-offers-data", kind: "composed", gate: "cross-surface-propagation", judged_by: "an ontology admitted in the Ontology Manager is offered by the Solution Designer and Open Diagram · Recent (the gap map's 2→3 works in reverse)" },
      { id: "walk-designer-offers-ontology", kind: "live", judged_by: "THIS walk's ontology {tag}-lending, written in step 3, is offered by the Solution Designer by its own name",
        assertion: "HAND-OFF 2→3 — the Solution Designer offers THIS walk's ontology by its own name" },
      { id: "design-carries-system-data", kind: "named_gap", judged_by: "the System's design names the data it uses, under the System",
        gap: { code: "system_data_attachment_absent", plane: "data and ontology attached to a System through the record seam", source: "gap map hand-off 2→3; build order 4" } },
    ] },
  },
  {
    n: 3, id: "data", title: "Bring in data and an ontology",
    surface: "/__ioi/ontology/manager · /__ioi/data/sources · /__ioi/odk",
    legs: [
      { id: "owner-scoped-authoring", kind: "composed", gate: "cross-surface-propagation", what: "ontology, object type, properties, a declared source and its mapping written through their forms and shown by every consumer" },
      { id: "record-seam", kind: "composed", gate: "system-record-seam", what: "the daemon admits records under a bounded System with the binding derived (no surface drives it)" },
      { id: "walk-ontology-and-source", kind: "live", what: "THIS walk's ontology {tag}-lending and source {tag}-src, written through Ontology Manager's create form and Data sources' declare form (the first writes of lib/propagation-matrix.mjs) and read back BY NAME on the ODK and Data sources",
        assertion: "DATA — THIS walk's ontology and source are written through their owning forms and listed by their own names" },
      { id: "attach-to-system", kind: "named_gap", what: "attaching the data and the ontology to the System",
        gap: { code: "system_data_attachment_absent", plane: "data and ontology attached to a System through the record seam", source: "gap map step 3; build order 4" } },
    ],
    handoff: { into: "limits", legs: [
      { id: "data-offered-to-limits", kind: "named_gap", judged_by: "the System's connections and data are offered in the Leases & Limits lane",
        gap: { code: "system_limits_authority_node_absent", plane: "authority node (ADR 0056 Ruling 8)", source: "gap map step 4 and its hand-off; build order 11" } },
    ] },
  },
  {
    n: 4, id: "limits", title: "Set leases, limits and checkpoints",
    surface: "the Leases & Limits lane (absent) · /systems/{system}/govern (budgets)",
    legs: [
      { id: "limits", kind: "named_gap", what: "budgets and standing limits for the System",
        gap: { code: "system_limits_authority_node_absent", plane: "authority node (ADR 0056 Ruling 8)", source: "gap map step 4 (a named gap by ruling: the owner has no authority node, and none is stood up unasked); build order 11",
          probe: { route: "/systems/{system}/govern", marker: 'data-system-named-gap="authority node (ADR 0056 Ruling 8)"' } } },
      { id: "checkpoints", kind: "named_gap", what: "checkpoints for the System",
        gap: { code: "system_checkpoints_absent", plane: "Checkpoints (ADR 0056 P5)", source: "gap map step 4; build order 11" } },
    ],
    handoff: { into: "run", legs: [
      { id: "lease-gates-connection-picker", kind: "todo", judged_by: "a standing lease gates the connection a session or automation may pick (the gap map's 4→5 works for connections)",
        write: "name the gate that proves the picker is gated in the UI (check:session-authority-profile proves the daemon path only), or drive it: lease a connection, find it offered on the New Session composer, revoke it, find it withheld" },
      { id: "limits-bound-runs", kind: "named_gap", judged_by: "the System's limits bound the runs it starts",
        gap: { code: "system_limits_authority_node_absent", plane: "authority node (ADR 0056 Ruling 8)", source: "gap map hand-off 4→5; build order 11" } },
    ] },
  },
  {
    n: 5, id: "run", title: "Run sessions and automations on an environment",
    surface: "/ai#new-session (New Session composer) · /automations",
    legs: [
      { id: "sessions", kind: "composed", gate: "launch-chain", what: "one owned Session through the typed launch chain, receipted and recoverable" },
      { id: "automations", kind: "composed", gate: "automations-journey", what: "automations created and run through the serve's action lanes" },
      { id: "walk-session-and-automation", kind: "todo", what: "THIS walk's run",
        write: "launch a session from the New Session composer on an environment, and create and start automation auto-{tag} through /automations' create form (project_ref required), against a deterministic stub model (the ollama-dialect stub check:governed-evaluation-plane runs)" },
      { id: "run-the-system", kind: "named_gap", what: "running THE System: a session or run attached to the System",
        gap: { code: "session_system_subject_absent", plane: "System subject on session create (W3 C-1)", source: "gap map step 5 (session create hard-codes subject_attachments: []); build order 5",
          probe: { route: "/systems/{system}/operate", marker: 'data-system-named-gap="System subject on session create (W3 C-1)"' } } },
      { id: "automation-installation", kind: "named_gap", what: "an automation installed onto the System and an environment",
        gap: { code: "automation_system_binding_absent", plane: "Automations rebound onto automation-specs, installations and runs (installation → System + environment)", source: "gap map step 5; build order 5" } },
    ],
    handoff: { into: "observe", legs: [
      { id: "run-becomes-work", kind: "composed", gate: "systems-work-projections", judged_by: "an admitted Session becomes one Work row carrying its typed deep link (the gap map's 5→6 works for runs)" },
      { id: "walk-run-in-work", kind: "todo", judged_by: "THIS walk's run is a row on /work", write: "GET /work and find the walk's session by its own id" },
      { id: "run-names-system", kind: "named_gap", judged_by: "the run's Work row names the System",
        gap: { code: "session_system_subject_absent", plane: "System subject on session create (W3 C-1)", source: "gap map hand-off 5→6; build order 5" } },
    ] },
  },
  {
    n: 6, id: "observe", title: "Watch health, telemetry, notifications and issues",
    surface: "/operations · /operations/issues · the notification inbox",
    legs: [
      { id: "issues", kind: "composed", gate: "cross-surface-propagation", what: "an issue filed from Issues' New dialog is listed in its open lane, at /operations/issues and on Work / Incidents" },
      { id: "notification-projection", kind: "composed", gate: "notification-inbox", what: "owner events project into the inbox with one link back, re-derived after a restart" },
      { id: "walk-issue", kind: "live", what: "THIS walk's issue issue-{tag}, filed from Issues' New dialog naming the walk's System by reference (affected=__other, affected_ref={system_id}) and read back BY NAME at /operations/issues?lane=open",
        assertion: "OBSERVE — THIS walk's issue, naming the System by reference, is filed from Issues' own dialog and listed by its own name in the open lane" },
      { id: "notifications-ui", kind: "composed", gate: "notification-panel", what: "the shell's panel renders the inbox: rows are the API's items for the same person, one link each to the owning record, distinct signed-out and outage states (closed 2026-09-26: the P1 inbox UI)" },
      { id: "health", kind: "named_gap", what: "health for the System",
        gap: { code: "system_health_checks_absent", plane: "health-check plane (ADR 0056 P2)", source: "gap map step 6; build order 7",
          probe: { route: "/systems/{system}", marker: 'data-system-named-gap="health-check plane (ADR 0056 P2)"' } } },
      { id: "telemetry", kind: "named_gap", what: "telemetry for the System",
        gap: { code: "system_telemetry_absent", plane: "telemetry (ADR 0056 P6)", source: "gap map step 6; build order 7 (after P1 and P2)" } },
      { id: "issue-subject-system", kind: "named_gap", what: "the System offered as an issue's subject",
        gap: { code: "issue_system_subject_absent", plane: "Issues subjects including the System", source: "gap map step 6; build order 7" } },
    ],
    handoff: { into: "provenance", legs: [
      { id: "run-answers-receipts", kind: "composed", gate: "receipts-on-demand", judged_by: "after a run, one request to the surface's retrieval route answers what it touched, citing receipts (the gap map's 5→7 works for runs)" },
      { id: "walk-observed-to-receipts", kind: "todo", judged_by: "THIS walk's observed run links to its receipts", write: "from the walk's Work row, follow its link to the run's receipts and find them by the run's own id" },
    ] },
  },
  {
    n: 7, id: "provenance", title: "Read its provenance receipts",
    surface: "/systems/{system}/evidence · /provenance (Work Ledger)",
    legs: [
      { id: "run-receipts", kind: "composed", gate: "receipts-on-demand", what: "a run's receipts answered in one step" },
      { id: "system-evidence", kind: "live", what: "the System's genesis and lifecycle evidence on its Evidence mode",
        assertion: "PROVENANCE — the System's Evidence mode shows its own chain root and latest receipt from the advanced projection" },
      { id: "ledger-by-system", kind: "named_gap", what: "System lifecycle, blueprint, session and evaluation receipts in the Work Ledger, filterable by system_ref",
        gap: { code: "ledger_system_lane_absent", plane: "Work Ledger lane by system_ref", source: "gap map step 7; build order 6",
          probe: { route: "/systems/{system}/evidence", marker: 'data-system-named-gap="Work Ledger lane by system_ref"' } } },
    ],
    handoff: { into: "evaluate", legs: [
      { id: "receipts-to-evaluation", kind: "named_gap", judged_by: "a run's receipts are offered as the subject of an evaluation",
        gap: { code: "evaluation_ui_consumer_absent", plane: "Evaluations rebound onto the governed evaluation plane", source: "gap map hand-off →8; build order 8" } },
    ] },
  },
  {
    n: 8, id: "evaluate", title: "Evaluate it",
    surface: "/evaluations",
    legs: [
      { id: "governed-plane", kind: "composed", gate: "governed-evaluation-plane", what: "the governed evaluation plane on the daemon" },
      { id: "walk-suite", kind: "todo", what: "THIS walk's suite", write: "declare suite-{tag} through the one form /evaluations renders today (suite declaration) and read it back BY NAME" },
      { id: "evaluation-ui", kind: "named_gap", what: "evaluating from the UI: the governed evaluation plane has zero UI consumers",
        gap: { code: "evaluation_ui_consumer_absent", plane: "Evaluations rebound onto the governed evaluation plane", source: "gap map step 8; build order 8" } },
      { id: "evaluation-system-field", kind: "named_gap", what: "an evaluation naming the System it measured",
        gap: { code: "evaluation_system_field_absent", plane: "the evaluation System field", source: "system workspace plan (the Evidence mode's named gap)" } },
    ],
    handoff: { into: "improve", legs: [
      { id: "result-proposes-change", kind: "named_gap", judged_by: "an evaluation result is offered as the basis of a change set",
        gap: { code: "change_set_plane_absent", plane: "change sets (ADR 0056 P4)", source: "gap map hand-off →9; build order 9" } },
    ] },
  },
  {
    n: 9, id: "improve", title: "Improve it through a change set",
    surface: "/improvement · /__ioi/agent-studio (improvements) · /governance/approvals",
    legs: [
      { id: "improvement-forms", kind: "composed", gate: "agent-studio-write-lanes", what: "Propose / Approve / Reject / Apply and their governance gates land (the dead forms repaired 2026-09-25)" },
      { id: "improvement-spine", kind: "composed", gate: "improvement-governance-spine", what: "the direct proposal path and the campaign spine" },
      { id: "approval-decision", kind: "composed", gate: "governance-journey", what: "approvals decided with a daemon-resolved reviewer and a decision receipt" },
      { id: "walk-improvement", kind: "todo", what: "THIS walk's improvement",
        write: "propose imp-{tag} through /__ioi/agent-studio/improvements/propose, request its approval, decide it on /governance/approvals, apply it; judge by the daemon's recorded state" },
      { id: "change-sets", kind: "named_gap", what: "a change set that yields a successor blueprint",
        gap: { code: "change_set_plane_absent", plane: "change sets (ADR 0056 P4)", source: "gap map step 9; build order 9" } },
      { id: "system-scope", kind: "named_gap", what: "improving THE System: the improvement plane refuses a System scope by name",
        gap: { code: "improvement_system_scope_refused", plane: "System-scoped improvement (ADR 0056 P4 change sets)", source: "system workspace plan (the Improve mode)",
          probe: { route: "/systems/{system}/improve", marker: 'data-system-named-gap="System-scoped improvement (ADR 0056 P4 change sets)"' } } },
    ],
    handoff: { into: "release", legs: [
      { id: "successor-offered-for-release", kind: "named_gap", judged_by: "the applied change set's successor blueprint is offered for release",
        gap: { code: "change_set_plane_absent", plane: "change sets (ADR 0056 P4)", source: "gap map build order 9 → 10" } },
    ] },
  },
  {
    n: 10, id: "release", title: "Package and release it",
    surface: "/packages",
    legs: [
      { id: "domainapp-packages", kind: "composed", gate: "packages-journey", what: "DomainApp packages: candidate, release, install, recall, uninstall" },
      { id: "walk-package", kind: "todo", what: "THIS walk's package", write: "create package pkg-{tag} and cut its release through Packages' own forms; read it BY NAME on /packages" },
      { id: "system-release", kind: "named_gap", what: "a System release cut from a promoted blueprint — the object step 1's picker lists (today the registry's releases are DomainApp surface releases and genesis takes an inline manifest release)",
        gap: { code: "system_release_absent", plane: "System release (registry-backed, cut from a promoted blueprint)", source: "gap map step 10; build order 10" } },
    ],
    handoff: { into: "operate", legs: [
      { id: "release-offered-to-operate", kind: "named_gap", judged_by: "the new System release is offered to the running System (upgrade) and to step 1's picker (the gap map's 10→1)",
        gap: { code: "system_release_absent", plane: "System release (registry-backed, cut from a promoted blueprint)", source: "gap map hand-off 10→1; build order 10" } },
    ] },
  },
  {
    n: 11, id: "operate", title: "Operate it",
    surface: "/systems/{system}/operate · /systems/{system}/govern (lifecycle forms)",
    legs: [
      { id: "operate-mode", kind: "live", what: "the Operate mode served for the walk's System",
        assertion: "OPERATE — the System's Operate mode is served for it, with its desired-versus-observed topology" },
      { id: "lifecycle-forms", kind: "composed", gate: "system-genesis-product-journey", what: "continuity (dissolution) through the lifecycle forms; cross-System substitution refused" },
      { id: "typed-lifecycle", kind: "named_gap", what: "operating without raw JSON: the lifecycle forms take hand-computed roots and pasted grants",
        gap: { code: "lifecycle_forms_raw_json", plane: "typed lifecycle forms with the wallet approval in the approvals inbox", source: "gap map step 11; build order 3" } },
    ],
    terminal: { legs: [
      { id: "restart-reread", kind: "live", judged_by: "after a full restart of the plane on its own data directory, /systems still lists the System and its Overview renders the same identity and chain root",
        assertion: "RESTART — after the plane restarts on its own data directory, /systems lists the System and its Overview shows the same chain root" },
    ] },
  },
]);

// Estate-wide gates the walk leans on and does not belong to one step.
export const ESTATE = Object.freeze([
  { id: "dead-controls", kind: "composed", gate: "dead-controls", what: "no live-looking control on the walked surfaces does nothing" },
  { id: "named-gap-truth", kind: "composed", gate: "named-gap-truth", what: "every named-gap reason the walk meets is true where it is emitted" },
]);

// ---- keys, fill ----------------------------------------------------------------------------------
export function keyOf(stepId, part, legId) {
  return `${stepId}/${part}/${legId}`;
}

export function legIndex(journey, estate = []) {
  const out = {};
  for (const step of journey) {
    for (const leg of step.legs || []) out[keyOf(step.id, "legs", leg.id)] = leg;
    for (const leg of step.handoff?.legs || []) out[keyOf(step.id, "handoff", leg.id)] = leg;
    for (const leg of step.terminal?.legs || []) out[keyOf(step.id, "terminal", leg.id)] = leg;
  }
  for (const leg of estate) out[keyOf("estate", "legs", leg.id)] = leg;
  return out;
}

export function fill(template, vars) {
  return String(template).replace(/\{(tag|system|system_id)\}/gu, (_, k) => (vars[k] == null ? `{${k}}` : String(vars[k])));
}

// ---- the table's own rules -----------------------------------------------------------------------
const SNAKE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/u;

function legFindings(leg, where, gates, cited, isHandoff) {
  const f = [];
  if (!leg || !leg.id || !LEG_KINDS.includes(leg.kind)) return [`${where}: not a leg (kind '${leg?.kind}')`];
  if (isHandoff && !leg.judged_by) f.push(`${where}: a hand-off leg that does not say which object of this step must appear in the next step's form is not judged`);
  if (!isHandoff && !leg.what) f.push(`${where}: says nothing about what it proves`);
  if (leg.kind === "live" && !leg.assertion) f.push(`${where}: a live leg names no assertion — a pass it reported would name no evidence`);
  if (leg.kind === "composed") {
    if (!gates.has(leg.gate)) f.push(`${where}: cites '${leg.gate}', which the journey does not compose`);
    else cited.add(leg.gate);
  }
  if (leg.kind === "named_gap") {
    const g = leg.gap || {};
    if (!SNAKE.test(g.code || "")) f.push(`${where}: a named gap needs a snake_case code`);
    if (!g.plane) f.push(`${where}: a named gap must name the missing plane`);
    if (!g.source) f.push(`${where}: a named gap must cite where it is recorded`);
    if (g.probe && (!g.probe.route || !g.probe.marker)) f.push(`${where}: a probe needs a route and a marker`);
  }
  if (leg.kind === "todo" && !leg.write) f.push(`${where}: a TODO must say which live leg is to be written`);
  if (leg.kind !== "named_gap" && leg.gap) f.push(`${where}: only a named gap carries a gap`);
  return f;
}

// A step that is not the last owes the next step a hand-off: which of its objects must appear, as an
// option or a link, in the next step's form. A step whose hand-off is not judged is red, never skipped.
function handoffFindings(step, next, where, gates, cited, once) {
  const f = [];
  if (!step.handoff) return [`${where}: hand-off unchecked — nothing proves its object reaches step ${step.n + 1}`];
  if (step.handoff.into !== next.id) f.push(`${where}: hands off to '${step.handoff.into}', not the next step '${next.id}'`);
  if (!(step.handoff.legs || []).length) f.push(`${where}: hand-off unchecked — it names no leg`);
  for (const leg of step.handoff.legs || []) { once("handoff", leg); f.push(...legFindings(leg, `${where} hand-off ${leg?.id}`, gates, cited, true)); }
  return f;
}

export function journeyFindings({ journey, compose, estate = [], expectSteps = null }) {
  const f = [];
  const gates = new Set(compose.map((c) => c.id));
  const cited = new Set();
  if (expectSteps !== null && journey.length !== expectSteps) f.push(`the journey has ${journey.length} steps, not ${expectSteps}`);
  const ids = journey.map((s) => s.id);
  if (new Set(ids).size !== ids.length) f.push("a step id is named twice");
  journey.forEach((step, i) => {
    const where = `step ${step.n} ${step.id}`;
    if (step.n !== i + 1) f.push(`${where}: numbered out of order`);
    if (!step.title || !step.surface) f.push(`${where}: names no title or surface`);
    if (!Array.isArray(step.legs) || !step.legs.length) f.push(`${where}: proves nothing — no legs`);
    const seen = new Set();
    const once = (part, leg) => { const k = `${part}/${leg?.id}`; if (seen.has(k)) f.push(`${where}: leg '${k}' named twice`); seen.add(k); };
    for (const leg of step.legs || []) { once("legs", leg); f.push(...legFindings(leg, `${where} leg ${leg?.id}`, gates, cited, false)); }
    const last = i === journey.length - 1;
    if (last) {
      if (step.handoff) f.push(`${where}: the last step hands off to nothing`);
      if (!step.terminal || !(step.terminal.legs || []).length) f.push(`${where}: the walk does not end with a restart and a re-read`);
      for (const leg of step.terminal?.legs || []) { once("terminal", leg); f.push(...legFindings(leg, `${where} terminal ${leg?.id}`, gates, cited, true)); }
    } else {
      if (step.terminal) f.push(`${where}: only the last step is terminal`);
      f.push(...handoffFindings(step, journey[i + 1], where, gates, cited, once));
    }
  });
  for (const leg of estate) f.push(...legFindings(leg, `estate ${leg?.id}`, gates, cited, false));
  const scripts = new Set();
  for (const c of compose) {
    if (!c.id || !c.script || !["app", "root"].includes(c.pkg) || !(c.minutes > 0) || !c.proves) f.push(`compose ${c.id}: incomplete`);
    if (scripts.has(`${c.pkg}:${c.script}`)) f.push(`compose ${c.id}: runs a script another entry already runs`);
    scripts.add(`${c.pkg}:${c.script}`);
    if (!cited.has(c.id)) f.push(`compose ${c.id}: runs a gate no leg cites — composition that evidences nothing`);
  }
  return f;
}

// ---- the verdict ---------------------------------------------------------------------------------
// `input` is what the run measured, never what the table hopes:
//   claims    leg key → { state, assertion?, probe?, detail } written by the LIVE walk
//   composed  gate id → { status, timedOut, basisMoved, summary } written by the COMPOSE runner
//   setup     failures before the walk could measure anything (daemon, wallet, operator)
//   drills    PURE / SOURCE / BINDING findings of this invocation
export function legVerdict(leg, key, input) {
  const claim = (input.claims || {})[key];
  if (leg.kind === "live") {
    if (!claim) return { state: "fail", why: `unreached — the walk never measured '${leg.assertion}'` };
    if (claim.state === "pass" && claim.assertion === leg.assertion) return { state: "pass", evidence: `live: ${leg.assertion}` };
    if (claim.state === "pass") return { state: "fail", why: "fabricated — a pass that does not name this leg's assertion" };
    return { state: "fail", why: claim.detail || "red" };
  }
  if (leg.kind === "named_gap") {
    if (claim && claim.state === "pass") return { state: "fail", why: `fabricated — the named gap ${leg.gap.code} reported pass; closing a gap flips its row to a live leg with its own assertion` };
    if (claim && claim.probe === "stale") return { state: "fail", why: `stale — the product no longer names '${leg.gap.plane}' at ${leg.gap.probe?.route}; flip the row to a live leg or correct the plane` };
    return { state: "named_gap", code: leg.gap.code, plane: leg.gap.plane };
  }
  if (leg.kind === "todo") {
    if (claim && claim.state === "pass") return { state: "fail", why: "fabricated — a TODO leg has no live leg to pass it" };
    return { state: "todo", write: leg.write };
  }
  if (leg.kind === "composed") {
    if (claim && claim.state === "pass") return { state: "fail", why: `fabricated — a composed leg passes only by ${leg.gate}'s own run` };
    const run = (input.composed || {})[leg.gate];
    if (!run) return { state: "unmeasured", why: `${leg.gate} was not executed in this invocation` };
    if (run.basisMoved) return { state: "fail", why: `${leg.gate} ran on a moved basis` };
    if (run.timedOut) return { state: "fail", why: `${leg.gate} timed out` };
    if (run.status === 0) return { state: "pass", evidence: `composed: ${leg.gate} exit 0` };
    if (run.status === 2) return { state: "unmeasured", why: `${leg.gate} exited 2 — its own named failure or BLOCKED, never a pass` };
    return { state: "fail", why: `${leg.gate} exit ${run.status}` };
  }
  return { state: "fail", why: `unknown leg kind '${leg.kind}'` };
}

const RANK = { pass: 0, unmeasured: 1, todo: 2, named_gap: 3, fail: 4 };
const STATE_OF = { pass: "PASS", unmeasured: "UNMEASURED", todo: "TODO", named_gap: "NAMED_GAP", fail: "FAIL" };

export function stepVerdict(step, input, { last = false } = {}) {
  const judged = [];
  const judge = (part, leg) => judged.push({ part, leg: leg.id, kind: leg.kind, ...legVerdict(leg, keyOf(step.id, part, leg.id), input) });
  for (const leg of step.legs || []) judge("legs", leg);
  if (!(step.legs || []).length) judged.push({ part: "legs", leg: "-", kind: "-", state: "fail", why: "a step with no legs proves nothing" });
  if (!last) {
    if (!step.handoff || !(step.handoff.legs || []).length) judged.push({ part: "handoff", leg: "-", kind: "-", state: "fail", why: "hand-off unchecked — a step whose hand-off is not judged is red, never skipped" });
    else for (const leg of step.handoff?.legs || []) judge("handoff", leg);
  } else if (!step.terminal || !(step.terminal.legs || []).length) {
    judged.push({ part: "terminal", leg: "-", kind: "-", state: "fail", why: "the walk does not end with a restart and a re-read" });
  } else {
    for (const leg of step.terminal.legs) judge("terminal", leg);
  }
  const worst = judged.reduce((w, j) => (RANK[j.state] > RANK[w] ? j.state : w), "pass");
  return { n: step.n, id: step.id, title: step.title, state: STATE_OF[worst], legs: judged };
}

export function verdict(journey, input, estate = []) {
  const failures = [];
  const steps = journey.map((step, i) => stepVerdict(step, input, { last: i === journey.length - 1 }));
  const estateRows = estate.map((leg) => ({ part: "estate", leg: leg.id, kind: leg.kind, ...legVerdict(leg, keyOf("estate", "legs", leg.id), input) }));
  const all = [...steps.flatMap((s) => s.legs.map((j) => ({ ...j, step: `step ${s.n} ${s.id}` }))), ...estateRows.map((j) => ({ ...j, step: "estate" }))];
  for (const j of all) if (j.state === "fail") failures.push(`${j.step} ${j.part} ${j.leg}: ${j.why}`);
  // EVERY PASS NAMES ITS EVIDENCE: a live assertion or a composed gate's own run.
  for (const j of all) if (j.state === "pass" && !/^(live|composed): \S/u.test(j.evidence || "")) failures.push(`${j.step} ${j.part} ${j.leg}: a pass that names no evidence`);
  for (const x of input.setup || []) failures.push(`setup: ${x}`);
  for (const x of input.drills || []) failures.push(`drills: ${x}`);
  const gaps = [...new Set(all.filter((j) => j.state === "named_gap").map((j) => j.code))];
  const todos = all.filter((j) => j.state === "todo").length;
  const unmeasured = all.filter((j) => j.state === "unmeasured").length;
  const kind = failures.length ? "fail" : gaps.length || todos || unmeasured ? "named_failure" : "pass";
  const exit = kind === "pass" ? 0 : kind === "named_failure" ? 2 : 1;
  const passing = steps.filter((s) => s.state === "PASS").length;
  const label = kind === "pass" ? `all ${steps.length} steps PASS` : kind === "named_failure" ? `journey incomplete — ${passing} of ${steps.length} steps PASS` : `FAIL — ${failures.length} failure(s)`;
  return { kind, exit, label, failures, gaps, todos, unmeasured, passing, steps, estate: estateRows };
}
