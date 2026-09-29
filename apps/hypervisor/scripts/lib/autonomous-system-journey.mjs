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
      { id: "system-offered-to-studio", kind: "live", judged_by: "the System's Design mode links to Studio's Draft a blueprint form, and that form's system_ref select — built from the caller-filtered Systems projection — offers THIS System, already chosen (closed 2026-09-28: R-240 journey WP-C1, the StudioBlueprint v1 contract carries system_ref)",
        assertion: "HAND-OFF 1→2 — the System's Design mode hands off to Studio's blueprint form, which offers THIS System as the blueprint's system_ref" },
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
      { id: "design-bound-to-system", kind: "live", what: "THIS walk's blueprint bound to THIS System: created from the hand-off's form with system_ref = the System; the daemon's record carries that system_ref under the registered StudioBlueprint v1 contract with its admitted head, the daemon's System-narrowed blueprint list names it, and the System's Design mode lists it by its own ref and name (closed 2026-09-28: R-240 journey WP-C1)",
        assertion: "DESIGN — THIS walk's blueprint is bound to THIS System in the daemon's record and listed by its own name on the System's Design mode" },
    ],
    handoff: { into: "data", legs: [
      { id: "studio-offers-data", kind: "composed", gate: "cross-surface-propagation", judged_by: "an ontology admitted in the Ontology Manager is offered by the Solution Designer and Open Diagram · Recent (the gap map's 2→3 works in reverse)" },
      { id: "walk-designer-offers-ontology", kind: "live", judged_by: "THIS walk's ontology {tag}-lending, written in step 3, is offered by the Solution Designer by its own name",
        assertion: "HAND-OFF 2→3 — the Solution Designer offers THIS walk's ontology by its own name" },
      { id: "design-carries-system-data", kind: "live", judged_by: "the System's Design mode lists THIS walk's ontology and source — attached in step 3 — by their own names, read from the caller's own ontology and data-source planes beside the seam's admitted heads (closed 2026-09-28: R-240 journey WP-C1)",
        assertion: "HAND-OFF 2→3 — the System's Design mode names THIS walk's attached ontology and source by their own names" },
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
      { id: "walk-function", kind: "live", what: "THIS walk's function fn{tag}, declared from Ontology / Functions' New function form (an integer input and output, Python), test-run from its own Run a test form in the environment the walk's run used, released from its own Release form, and read back on /ontology/functions by its own name as released with an operable tool revision (closed 2026-09-26: ADR 0056 P3)",
        assertion: "DATA — THIS walk's function is declared, test-run and released through Ontology / Functions' own forms, and listed by its own name with an operable tool revision" },
      { id: "attach-to-system", kind: "live", what: "THIS walk's ontology and source attached to THIS System from its Design mode's Attach form (the options are the caller's own ontologies and sources): each is ONE SystemDataAttachment v1 record admitted through the System-record seam with a receipt, and the daemon's record list under the System holds both — each naming its subject by ref, attached, the binding derived to this System (closed 2026-09-28: R-240 journey WP-C1)",
        assertion: "DATA — THIS walk's ontology and source are attached to THIS System through its Design mode's form, and the System-record seam holds both attachments under the System" },
    ],
    handoff: { into: "limits", legs: [
      { id: "data-offered-to-limits", kind: "named_gap", judged_by: "the System's connections and data are offered in the Leases & Limits lane",
        gap: { code: "system_limits_authority_node_absent", plane: "authority node (ADR 0056 Ruling 8)", source: "gap map step 4 and its hand-off; build order 11" } },
    ] },
  },
  {
    n: 4, id: "limits", title: "Set leases, limits and checkpoints",
    surface: "/governance/limits (Leases & Limits: checkpoints) · /systems/{system}/govern (budgets)",
    legs: [
      { id: "limits", kind: "named_gap", what: "budgets and standing limits for the System",
        gap: { code: "system_limits_authority_node_absent", plane: "authority node (ADR 0056 Ruling 8)", source: "gap map step 4 (a named gap by ruling: the owner has no authority node, and none is stood up unasked); build order 11",
          probe: { route: "/systems/{system}/govern", marker: 'data-system-named-gap="authority node (ADR 0056 Ruling 8)"' } } },
      { id: "walk-checkpoint", kind: "live", what: "THIS walk's checkpoint checkpoint-{tag}, configured from Leases & Limits' Configuration form (/governance/limits): a person's Run now needs a written justification matching the walk's tag, listed enabled by its own name (closed 2026-09-26: ADR 0056 P5)",
        assertion: "LIMITS — THIS walk's checkpoint on Run now is configured through Leases & Limits' own form and listed enabled by its own name" },
    ],
    handoff: { into: "run", legs: [
      { id: "walk-checkpoint-gates-run", kind: "live", judged_by: "THIS walk's Run now is paused behind its checkpoint's prompt, answered on the prompt's own form, and only then runs; the justification record names the walk's automation and Review lists it",
        assertion: "HAND-OFF 4→5 — THIS walk's checkpoint pauses its Run now until justified, and Review lists the record naming the walk's automation" },
      { id: "unleased-connection-withheld", kind: "live", judged_by: "THIS walk's connection cx-{tag}, added through Connections' Add API key form (its token sealed, no limits set), reaches the New Session composer WITHHELD: the launcher renders it disabled with the reason that it has no limits, the daemon's connector record is bound with no active standing lease, and the session the walk starts from that composer names no connection in its closed authority profile",
        assertion: "HAND-OFF 4→5 — THIS walk's unleased connection is withheld by the New Session composer, disabled with its reason, and the daemon holds it bound with no standing lease" },
      { id: "lease-gates-connection-picker", kind: "named_gap", judged_by: "a standing lease gates the connection a session may pick: THIS walk's connection, once leased on Connections, is offered on the New Session composer, and once its limits are removed it is withheld again",
        gap: { code: "system_limits_authority_node_absent", plane: "authority node (ADR 0056 Ruling 8)",
          source: "gap map hand-off 4→5 (connections); build order 11. A standing lease is a grant the deployment's authority node records (the daemon's standing-envelope decision runs the sealed approver); the walk's plane takes its authority from the wallet.network fixture and a daemon speaks to one wallet.network, so the walk moves onto a local authority node only with journey WP-A (held on the owner's approver ruling). The product names it on the connection's own card, where Set limits would be",
          probe: { route: "/__ioi/connections", marker: 'data-ioi-standing-recorder="none"' } } },
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
      { id: "walk-automation", kind: "live", what: "THIS walk's automation auto-{tag}, created through the New automation form (/__ioi/automations/new: a command step, a manual schedule) in THIS walk's project project:walk-{tag}, and listed by its own name on Automate. The project must exist — the daemon refuses an automation naming any project it does not hold (automation_project_unknown, 2026-09-27 R-241) — so the walk creates it first through the rendered New project form New automation offers on a plane with none, and the automation form's project select then offers it",
        assertion: "RUN — THIS walk's automation is created through the New automation form and listed by its own name on Automate" },
      { id: "walk-session", kind: "live", what: "THIS walk's session, started from the New Session composer — a JavaScript surface, so driven in a browser as the walk's operator: /ai#new-session, its Advanced launch, THIS walk's project picked from the launcher's project select, the walk's first instruction typed, no harness binding (the execute-time default), Start. The daemon's record is the session the composer sent: owned by the signed-in operator, in THIS walk's project, carrying the typed instruction as its first transcript entry, provisioned on its own environment with the provision receipt the launcher named, and an empty closed authority profile; Work / Sessions lists it by its own ref",
        assertion: "RUN — THIS walk's session is started from the New Session composer, and the daemon's record is the session it sent: the operator's, in THIS walk's project, with the typed instruction, on a provisioned environment, listed on Work / Sessions" },
      { id: "run-the-system", kind: "live", what: "running THE System: THIS walk's run of auto-{tag} — an automation created for the System — is listed on the System's Operate mode by its own canonical run ref, read from the Work projection narrowed to the System (system_ref), where a run serves the System its installation is scoped to (closed 2026-09-28: R-240 journey WP-B — a run satisfies 'a session or run'; the session half stays named below)",
        assertion: "RUN — THIS walk's run is attached to THE System: the System's Operate mode lists it by its own canonical run ref" },
      { id: "session-subject-system", kind: "named_gap", what: "a SESSION attached to the System: session create takes no System subject (the launch chain attaches only its harness launch and its project), so no session names a System — runs do since WP-B",
        gap: { code: "session_system_subject_absent", plane: "System subject on session create (W3 C-1)", source: "gap map step 5 (session create hard-codes subject_attachments: []); build order 5 — the run half closed 2026-09-28 (WP-B); the walk's session is started from the composer since 2026-09-29 (walk-session), and neither the composer nor session create offers a System to name",
          probe: { route: "/systems/{system}/operate", marker: 'data-system-named-gap="System subject on session create (W3 C-1)"' } } },
      { id: "walk-function-step", kind: "live", what: "THIS walk's automation autofn-{tag}, created through the New automation form in THIS walk's project with a function step pinned to the walk's released function fn{tag} (inputs {\"amount\": 99}); its Run now, justified on the walk's checkpoint prompt, runs that exact revision and the step records Passed with output 100 (closed 2026-09-27: ADR 0056 P3 cut 3 — automations consume Ontology's functions by exact revision)",
        assertion: "RUN — THIS walk's automation runs THIS walk's released function as a step, by exact revision, and records its output" },
      { id: "automation-installation", kind: "live", what: "an automation installed onto the System and an environment: THIS walk's automation auto-{tag} is created from the New automation form FOR the walk's System (its System select offers the caller's own Systems; the daemon admits only an ACTIVE System in the author's inventory) and stored tied to it; its Run now mints the canonical chain with the installation's scope_ref = the System, so the run's exact installation revision is scoped to the System; and the run executes on an environment (closed 2026-09-28: R-240 journey WP-B)",
        assertion: "RUN — THIS walk's automation is created for THE System from the New automation form, and its run's installation is scoped to the System and executes on an environment" },
    ],
    handoff: { into: "observe", legs: [
      { id: "run-becomes-work", kind: "composed", gate: "systems-work-projections", judged_by: "an admitted Session becomes one Work row carrying its typed deep link (the gap map's 5→6 works for runs)" },
      { id: "walk-run-in-work", kind: "live", judged_by: "THIS walk's run — Run now pressed on its automation's own page, admitted as a canonical AutomationRun whose lifecycle reaches the shared work-lifecycle plane (R-240) — is a row on /work/history, found by the run ref the automation's run history names",
        assertion: "HAND-OFF 5→6 — THIS walk's Run now is a row on Work, found by its own canonical run ref" },
      { id: "run-names-system", kind: "live", judged_by: "THIS walk's run's row in the daemon's Work projection names the System (system_ref, from its installation's scope), and the projection narrowed to that System returns the row (closed 2026-09-28: WP-B)",
        assertion: "HAND-OFF 5→6 — THIS walk's run's Work row names THE System, and the Work projection narrowed to the System returns it" },
    ] },
  },
  {
    n: 6, id: "observe", title: "Watch health, telemetry, notifications and issues",
    surface: "/operations · /operations/issues · the notification inbox",
    legs: [
      { id: "issues", kind: "composed", gate: "cross-surface-propagation", what: "an issue filed from Issues' New dialog is listed in its open lane, at /operations/issues and on Work / Incidents" },
      { id: "notification-projection", kind: "composed", gate: "notification-inbox", what: "owner events project into the inbox with one link back, re-derived after a restart" },
      { id: "walk-issue", kind: "live", what: "THIS walk's issue issue-{tag}, filed from Issues' New dialog naming the walk's System (picked from the dialog's own Systems group since WP-B; affected={system_id}) and read back BY NAME at /operations/issues?lane=open",
        assertion: "OBSERVE — THIS walk's issue, naming the System by reference, is filed from Issues' own dialog and listed by its own name in the open lane" },
      { id: "notifications-ui", kind: "composed", gate: "notification-panel", what: "the shell's panel renders the inbox: rows are the API's items for the same person, one link each to the owning record, distinct signed-out and outage states (closed 2026-09-26: the P1 inbox UI)" },
      { id: "walk-health", kind: "live", what: "THIS walk's health check health-{tag}, declared from Operations / Health's New check form on the walk's System (probe `true` in the environment the walk's run used), evaluated with Evaluate now, and read back on /systems/{system} by its own name with the result's outcome (closed 2026-09-26: ADR 0056 P2)",
        assertion: "OBSERVE — THIS walk's health check observes the System, is evaluated from Operations / Health, and its Passed result shows on the System's Overview" },
      { id: "telemetry", kind: "live", what: "telemetry for the System: THIS walk's health evaluation (walk-health) produces an admitted ioi.health_check.passed point about its check, scoped to the System, through the telemetry plane — one event stream per series (ADR 0056 P6). The plane's bounded range read of that series holds the point by the result's own observation ref, admitted, value 1, with its receipt and the rolling mean the daemon derives and names; the System's Overview draws the series with that point as its latest; and Operations / Telemetry (the preserved Quiver port's landing, rebound onto the plane) lists the series and opens it on the same point (closed 2026-09-29: ADR 0056 P6)",
        assertion: "OBSERVE — THIS walk's health evaluation is a receipted telemetry point about the System: the range read holds it by its own observation ref, and the System's Overview and Operations / Telemetry show it" },
      { id: "issue-subject-system", kind: "live", what: "the System offered as an issue's subject: Issues' New dialog offers THE System in its Systems group (the caller's own Systems, from the projection that filters by who asks); THIS walk's issue picks it, and the daemon's issue record names the System among its affected objects (closed 2026-09-28: R-240 journey WP-B)",
        assertion: "OBSERVE — Issues' New dialog offers THE System as a subject, and THIS walk's issue filed against it names the System in its daemon record" },
    ],
    handoff: { into: "provenance", legs: [
      { id: "run-answers-receipts", kind: "composed", gate: "receipts-on-demand", judged_by: "after a run, one request to the surface's retrieval route answers what it touched, citing receipts (the gap map's 5→7 works for runs)" },
      { id: "walk-observed-to-receipts", kind: "live", judged_by: "from THIS walk's Work row, its own link opens the run's receipts — the execution's run timeline — which names the execution by its own id",
        assertion: "HAND-OFF 6→7 — THIS walk's Work row links to its run's receipts, found by the run's own id" },
    ] },
  },
  {
    n: 7, id: "provenance", title: "Read its provenance receipts",
    surface: "/systems/{system}/evidence · /provenance (Work Ledger)",
    legs: [
      { id: "run-receipts", kind: "composed", gate: "receipts-on-demand", what: "a run's receipts answered in one step" },
      { id: "system-evidence", kind: "live", what: "the System's genesis and lifecycle evidence on its Evidence mode",
        assertion: "PROVENANCE — the System's Evidence mode shows its own chain root and latest receipt from the advanced projection" },
      { id: "ledger-by-system", kind: "live", what: "run receipts filterable by system_ref: the System's Evidence mode lists THIS walk's run, read from the Work projection narrowed to the System, and the row's own link opens that run's timeline and receipts, found by its execution's own id. The lane is the Work projection's system_ref filter — the legacy /work-ledger refuses every authenticated deployment, so it is not hosted there. Lifecycle receipts are the Evidence mode's own (system-evidence); blueprint, session and evaluation receipts reach the lane when their own named gaps close (blueprint_system_ref_absent, session_system_subject_absent, evaluation_system_field_absent) (closed 2026-09-28: R-240 journey WP-B)",
        assertion: "PROVENANCE — the System's Evidence mode lists THIS walk's run, and its link opens that run's timeline and receipts" },
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
      { id: "walk-suite", kind: "live", what: "THIS walk's suite suite-{tag}, declared through the one form Evaluations renders today (/__ioi/evaluations#new-suite: a subject scope and a consent rung) and listed by its own name on the suites",
        assertion: "EVALUATE — THIS walk's suite is declared through Evaluations' own form and listed by its own name" },
      { id: "evaluation-ui", kind: "named_gap", what: "evaluating from the UI: the governed evaluation plane has zero UI consumers",
        gap: { code: "evaluation_ui_consumer_absent", plane: "Evaluations rebound onto the governed evaluation plane", source: "gap map step 8; build order 8" } },
      { id: "evaluation-system-field", kind: "named_gap", what: "an evaluation naming the System it measured",
        gap: { code: "evaluation_system_field_absent", plane: "the evaluation System field", source: "system workspace plan (the Evidence mode's named gap)" } },
    ],
    handoff: { into: "improve", legs: [
      { id: "result-proposes-change", kind: "named_gap", judged_by: "an evaluation result is offered as the basis of a change set",
        gap: { code: "change_set_evaluation_basis_absent", plane: "an evaluation result as a change set's basis (ADR 0056 P4 — the change-set plane exists; nothing links a result to one)", source: "gap map hand-off →9; build order 9" } },
    ] },
  },
  {
    n: 9, id: "improve", title: "Improve it through a change set",
    surface: "/improvement · /__ioi/agent-studio (improvements) · /governance/approvals",
    legs: [
      { id: "improvement-forms", kind: "composed", gate: "agent-studio-write-lanes", what: "Propose / Approve / Reject / Apply and their governance gates land (the dead forms repaired 2026-09-25)" },
      { id: "improvement-spine", kind: "composed", gate: "improvement-governance-spine", what: "the direct proposal path and the campaign spine" },
      { id: "approval-decision", kind: "composed", gate: "governance-journey", what: "approvals decided with a daemon-resolved reviewer and a decision receipt" },
      { id: "walk-improvement", kind: "live", what: "THIS walk's improvement, through Agent Studio's own forms: two corrections imp-{tag} recorded from its Memory form, the candidate the daemon's outcome mining derives from exactly those entries proposed from its rendered Propose form, simulated, approved and applied — read back from the improvement plane (its id is the daemon's, so it is found by its evidence: THIS walk's corrections). The daemon's gate rules it low impact (the simulation changes nothing), so no Governance approval is offered and the plane's own review approves it — the high-impact approval path is the composed improvement-forms and approval-decision legs; applying it writes an accepted skill whose sources are the walk's corrections, with the improvement's receipt, and the Improvement inbox lists it applied. The improvement is the workspace's, not THE System's (system-scope below)",
        assertion: "IMPROVE — THIS walk's improvement is proposed from the corrections it recorded, simulated, approved and applied through Agent Studio's own forms, and the daemon holds it applied as an accepted skill with its receipt" },
      { id: "change-sets", kind: "named_gap", what: "a change set that yields a successor blueprint",
        gap: { code: "change_set_blueprint_subject_absent", plane: "a System blueprint as a change-set subject (ADR 0056 P4 — the plane carries data_recipe subjects only)", source: "gap map step 9; build order 9" } },
      { id: "system-scope", kind: "named_gap", what: "improving THE System: the improvement plane refuses a System scope by name",
        gap: { code: "improvement_system_scope_refused", plane: "System-scoped improvement (ADR 0056 P4 change sets)", source: "system workspace plan (the Improve mode)",
          probe: { route: "/systems/{system}/improve", marker: 'data-system-named-gap="System-scoped improvement (ADR 0056 P4 change sets)"' } } },
    ],
    handoff: { into: "release", legs: [
      { id: "successor-offered-for-release", kind: "named_gap", judged_by: "the applied change set's successor blueprint is offered for release",
        gap: { code: "change_set_blueprint_subject_absent", plane: "a System blueprint as a change-set subject (ADR 0056 P4 — the plane carries data_recipe subjects only)", source: "gap map build order 9 → 10" } },
    ] },
  },
  {
    n: 10, id: "release", title: "Package and release it",
    surface: "/packages",
    legs: [
      { id: "domainapp-packages", kind: "composed", gate: "packages-journey", what: "DomainApp packages: candidate, release, install, recall, uninstall" },
      { id: "walk-package", kind: "live", what: "THIS walk's package pkg-{tag}: step 3's ontology gains an object type and is PUBLISHED from Ontology Manager's History as an M05.1 revision; Studio's descriptor form binds that revision (composition domain_app); ODK's manifest form lists the ontology and the descriptor; the New Domain App form builds the draft app over both; Packages freezes it as a candidate and cuts an immutable release — every write through the form the surface rendered — and /packages lists it by its own name",
        assertion: "RELEASE — THIS walk's package is built from its own published ontology revision through Studio, ODK, Domain Apps and Packages' own forms, released, and listed by its own name on /packages" },
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
