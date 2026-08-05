# Surface implementation briefs — index

One brief per canonical surface under `internal-docs/implementation/surfaces/`.
Each has the same five byte-derived sections: canon digest · schema map ·
UI seed map (with corrections vs v0) · schema→UI binding table · ordered PR
list. Authored 2026-08-05 (Phase A of the bring-to-life run,
`internal-docs/overhaul/2026-08-05-hypervisor-bring-to-life-run.md`); each
brief is refreshed against the bytes before its surface is built (Phase B).

## File list and wave assignments

| Brief | Route | Kind | Primary waves |
|---|---|---|---|
| [home.md](home.md) | `/home` | core workspace | W0.1 · W1 |
| [systems.md](systems.md) | `/systems` | core workspace | W1 |
| [projects.md](projects.md) | `/projects` | core workspace | W1 |
| [applications.md](applications.md) | `/applications` | core workspace | W0.2 · W1 |
| [work.md](work.md) | `/work` (owns `/work/sessions`) | core workspace | W0.6 · W1 · W3 (lineage) · W4 (Cut #2) |
| [settings.md](settings.md) | `/settings` | core workspace | W0.5 · W4 |
| [studio.md](studio.md) | `/studio` | owner application | W1 · W3 (blueprints) |
| [automations.md](automations.md) | `/automations` | owner application | W0.6 (scheduler read) · W1 · W2 |
| [ontology.md](ontology.md) | `/ontology` | owner application | W1 · W2 |
| [data.md](data.md) | `/data` | owner application | W1 · W2 · W3 (sources CRUD) |
| [governance.md](governance.md) | `/governance` | owner application | W0.6 (inbox) · W1 · W2 |
| [provenance.md](provenance.md) | `/provenance` | owner application | W1 |
| [evaluations.md](evaluations.md) | `/evaluations` | owner application | W1 · W3 (epochs/holdouts/challenges) |
| [improvement.md](improvement.md) | `/improvement` | owner application | W1 · W2 · W3 (agendas/campaigns) |
| [foundry.md](foundry.md) | `/foundry` | owner application | W1 · W2 |
| [packages.md](packages.md) | `/packages` | owner application | W3 (registry family — biggest build) |
| [developer-workspace.md](developer-workspace.md) | `/developer-workspace` | owner application | W1 |
| [developer-console.md](developer-console.md) | `/developer-console` | owner application | W2 |
| [environments.md](environments.md) | `/environments` | substrate | W1 · W2 |
| [operations.md](operations.md) | `/operations` | substrate | W1 · W2 |

Embodied Systems (`/embodied-systems`) is a reserved, nonlaunchable
registration row in the compiler (planned) — no brief, no UI work.

## Epics (cross-surface, 2026-08-05 audit absorption)

- [`../scm-transition-chain-epic.md`](../scm-transition-chain-epic.md) — the
  Git/Agentgres transition-chain epic: five P0 truthfulness defects (§1,
  lands before any surface presents the Git workflow as governed), the
  owner-by-owner missing-interface table (§2), the missing-contracts
  build-list (§3), P0→P3 wave interleaving (§4). Coverage lands ONLY in
  existing owners; the nine affected briefs (projects, developer-console,
  developer-workspace, automations, work, governance, provenance, operations,
  settings) each carry a final `### Git/Agentgres transition-chain interfaces
  (epic)` pointer to their §2 row.
- [`../repo-ux-disposition.md`](../repo-ux-disposition.md) — repository-wide
  surface disposition ledger (estate surfaces outside these briefs: CLI/TUI,
  editor targets, hypervisor-web, developers.ioi.ai, benchmarks, aiagent.xyz,
  sas.xyz, QM); UNDISPOSITIONED rows await one owner-scope ruling pass
  (charter ledger row).

## Shared plumbing every brief assumes (Wave 0)

- **W0.1** v2 route shell: the 23 canonical routes as the shell route table;
  legacy `/__ioi/*` serves until each app's cutover; typed-410 per route at
  cutover.
- **W0.2** product-surface compiler v1: one projection feeding
  nav/catalog/palette/launch from registration records; kills the
  hand-maintained catalogs; Applications workspace is its first consumer.
- **W0.3** read-projection client + authority client (CapabilityLease flow:
  403 wallet challenge → 428 credential → receipted lease).
- **W0.4** event client on the M5 plane (`/v1/event-streams`,
  `/v1/subscriptions`); per-resource SSE wrapped, not extended.
- **W0.5** identity truth: delete adapter identity constants +
  `IDENTITY_REWRITES`; wire or kill the 5 fixture-only RPCs.
- **W0.6** backend enablers (serialize — central router is a merge hotspot):
  sessions/overview · unified approvals inbox · `GET /v1` capability index ·
  scheduler status read.

## Layering (C-1..C-4, canon 2026-08-05)

Session-serving UI binds through `subject_attachments[]` (owner-registered
`subject_kind`/`subject_ref`/`attachment_role`) — never a named app-family
field; `foundry_eval_training` is retired; the thread plane is daemon-internal
with Session as the single platform object over it. Byte sites still carrying
retired fields are recorded in the briefs that own them and migrate at the PR
that touches them.

## Wave 3 build-list rollup (route-missing families found in Phase A)

One line per surface; full detail in each brief's §2. W0.5/W0.6 items are
marked — they land in Wave 0, not Wave 3.

- **studio** — `studio/blueprints` draft CRUD + layout artifact +
  promote-through-gates (composes governance approval-requests).
- **automations** — AutomationInstallationBinding + spec revisioning ·
  AutomationRun→Session/GoalRun lineage (daemon writes session
  `subject_attachments` in the execution path) · object-set monitor triggers +
  effect/step families · WorkflowTemplate read family + step-graph view ·
  process-graph run/step/bind · **W0.6**: scheduler liveness status (schedule
  posture already projected via `/v1/hypervisor/operations`).
- **ontology** — proposal/branch/merge plane · object-instance search ·
  per-principal saved explorations/object sets · action-type execution ·
  receipt-on-delete fixes (domain-ontology delete is unreceipted today).
- **data** — DataSource PATCH/DELETE · ingestion/extraction/connection-test
  authority (daemon's own named `wired:false` boundary) ·
  datasets/time-series/media-sets plane (needs Data-vs-Foundry owner ruling).
- **governance** — **W0.6**: unified approvals-inbox (folds 4+2 decision
  planes) · approval-transition-receipt read route · capability-lease
  detail/revoke · reviewer-as-principal validation · retention/marking policy,
  justification checkpoints, constitution/amendment history, network
  enrollment (all zero-route today).
- **provenance** — unified receipt-stream projection with principal
  coordinates (today's readouts are local-operator-only) · optional
  lineage-graph / learning-flow-graph projections.
- **evaluations** — released suite-revision lifecycle (+
  `verification_cost_class`) · EvaluationEpoch · sealed-holdout custody ·
  EvaluationExposureLedger · evaluator dependency/validity graph ·
  re-verification / affected-result discovery · run/scorecard family ·
  mutation-receipt family (defect: live receiptless creates/deletes).
- **improvement** — ImprovementAgenda · ImprovementCampaign +
  order-assignment receipts · ImprovementOrderCutoffReceipt · UpgradeProposal
  handoff object · ImprovementEvidenceClaim · approve/reject/create receipt
  family (approve/reject are receiptless today).
- **foundry** — datasets (factory runs/snapshots/candidate data/holdouts) ·
  training/tuning (pipeline runs, trials, checkpoints, teacher sessions) ·
  experiment-optimization cycles · deploy lineage (conversion runs, registry
  versions, promotion bundles) · Foundry-side eval assets · learning-boundary
  projection route. (No training/dataset routes exist anywhere today.)
- **packages** — the whole `packages/*` registry family (package, immutable
  release, install bindings, deprecation/disable/recall/revocation +
  receipts) building around the existing install-admission planner · compiler
  recall hook into product-surface-projections · marketplace
  install/upload/federation/search lanes re-filed over the registry.
- **developer-workspace** — editor-access-lease GET list · environment backup
  list + restore-prepare/apply/cancel ladder.
- **developer-console** — conformance / developer-app registration ·
  developer-kit on-ramps · inbound webhook/service registry (scope against
  Automations' webhook ownership first).
- **environments** — HypervisorEnvironmentRouteBinding routes ·
  service/task start-stop · `mark_active` + activity signals · evidenced
  project discovery + `create_from_context_url` · cleanup-obligation verbs ·
  env-scoped ScmAuthRequirement · **W0.5**: two adapter lies
  (CreateEnvironmentLogsToken fabrication, MarkEnvironmentActive no-op).
- **operations** — unified infrastructure-jobs projection (subjects via
  `subject_attachments`) · capacity/utilization overview · RPO/RTO +
  degraded/partition rollup · **W0.6**: scheduler read surface.
- **systems** — System interface-binding plane (schema exists, zero rows/
  routes/compiler join) · registry entry for the read-projection contract.
- **projects** — HypervisorProjectDiscoveryProposal family · project
  PATCH/update plane · receipts on create/delete.
- **applications** — dynamic registration/admission family (extension+tool
  CRUD, install/enable/recall verbs, durable storage replacing
  `include_str!`) · compiler grouping + policy filtering + system-interface
  join (sequenced with the Packages registry build).
- **settings** — **W0.5**: org identity read record (whoami exists, org
  record doesn't) · org-policy defaults family · preference scope+schema
  listing · delivery-channels family (Automations-owned) · learning-boundary
  org default (Governance-owned, governed-upgrade-proposal on change).
- **work** — **W0.6**: sessions/overview · session
  lineage/fork/children/transition/history family (the one first-class family
  with none) · `subject_attachments` field on daemon session records (C-1
  backend; three retired named-field sites recorded) ·
  HypervisorWorkQueue/WorkItem object family · unified work-subject/facet
  projections · `hypervisor-session` JSON Schema registry gap · execution
  loop Cut #2 (W4).
- **home** — `home-cockpit` + `session-operations` projections (documented in
  daemon-runtime/api.md, absent from the daemon; Home composes 7 per-family
  reads client-side today). Note: the live `/automations` redirect hijacks a
  canonical v2 route into `/__ioi/automations` — deleted at Automations
  cutover.
