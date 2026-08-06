# Foundry — implementation brief

Canonical route: `/foundry` · Owner: Foundry (owner application)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted
Amended 2026-08-06: training-program revision audit — W3.0 contract wave inserted,
route-plane defect register added (§6), functional-interface targets added to §4;
canon counterpart is foundry.md "Reproducible Training Program Revisions" +
the FoundryTrainingStackBlueprintRevision contract family.

## 1. Canon digest

- Foundry is the candidate/evaluator asset builder and admitted experimental
  executor for worker/model/eval/persistent-training/dataset/registry/endpoint/
  package work over Hypervisor Core (core-clients-surfaces.md:2496-2498). It
  produces what other surfaces use: model catalog entries/cards, registry
  entries, model routes and model-mount candidates, WorkerPackages, datasets/
  feature views/holdouts, dataset-factory runs, training pipelines, experiment
  optimization cycles, artifact conversion, endpoints, batch inference,
  eval-suite/world/scorer/verifier candidates, recipes, quality gates,
  promotion proposals, and package publication proposals
  (core-clients-surfaces.md:2500-2513).
- Foundry never self-mutates the runtime. Its experiment optimizer is a
  subordinate execution profile; it does not own the ImprovementCampaign,
  freeze evaluation truth, select the release candidate, or make the release
  decision. Durable improvements go through governed proposals, independent
  eval gates, wallet approvals, and Agentgres admission
  (core-clients-surfaces.md:2515-2522; ledger row :1356-1366 — "not campaign
  owner, evaluation-epoch truth, candidate-selection authority, or release
  owner").
- Foundry binds the active `InstitutionalLearningBoundaryProfile`, individual
  training-evidence eligibility, source rights, model-route rights, derivative
  lineage, and revocation impact before consuming evidence or promoting a
  derived artifact; a green learning-boundary projection is never ambient
  permission to train (core-clients-surfaces.md:2524-2528). Foundry must show
  the exact boundary, eligibility, source-rights, route-rights, destination
  scope, and export disposition before a job begins (:1087-1088). The facet
  never becomes a 14th app or a second privacy selector (:1055-1056).
- Canonical route is `/foundry` (core-clients-surfaces.md:900); the legacy
  Model Catalog tool resolves as `Foundry / Models` (:1413). `Model` is the
  product label; `ModelRoute` remains the internal runtime object for
  provider, custody, fallback, spend, privacy, eligibility, and invocation
  policy (:1455-1458).
- Owner doc IA: a platform IA, not a wizard — pane ledger foundry.md:173-217;
  the stable conceptual split is Discover / Build / Train-Tune / Evaluate /
  Optimize / Deploy-Route / Govern (foundry.md:219-257). Evaluations owns the
  judgment contract, exposure, validity, and re-verification posture
  (foundry.md:235-241); Governance owns activation decisions (foundry.md:254-257).
- Object-first, not agent-first: control / data+metadata / execution /
  serving+governance planes over immutable objects (foundry.md:259-296);
  training artifacts and deployable artifacts are distinct lineage nodes,
  conversion/packaging are governed downstream stages (foundry.md:297-303);
  autonomous optimizers are advisory and may not directly mutate a registry
  alias, model route, endpoint, approval state, or traffic split
  (foundry.md:305-311). ~38 minimal objects at foundry.md:1131-2059
  (FoundrySpec :1209, FoundryRunPlan :1263, FoundryDatasetFactoryRun :1707,
  FoundryTrainingPipelineRun :1821, FoundryPromotionBundle :1973, etc.).
- Pattern/example supply is upstream input; an example is never proof of
  production readiness (foundry.md:845-866). ioi.ai coordination is not
  Foundry and Foundry is not a chat room (core-clients-surfaces.md:2530-2532).
- C-4 in force: `foundry_eval_training` is retired from `session_kind` —
  workload identity comes only from `subject_attachments`
  (core-clients-surfaces.md:3960-3990). Surviving byte sites: the token still
  appears as a `profile_kind` enum value on the MCP-gateway profile contract —
  docs/architecture/components/connectors-tools/contracts.md:162 and
  doctrine.md:156. That is a different field (context-profile kind, not
  session kind), but it names the retired workload-as-kind pattern; record
  here, reconcile at the PR that touches those files. Zero code sites
  (grep over *.rs/*.mjs/*.cjs: none).

## 2. Schema map

| Canon object / contract | Canon block | Daemon route(s) today |
|---|---|---|
| FoundrySpec (draft, kinds model_tune/model_eval/tool_build/inference_endpoint/ontology) | foundry.md:1209; `ioi.hypervisor.foundry-spec.v1` (foundry_routes.rs:31,35-41) | hypervisor-daemon.rs:1324-1333 (list/create/get/patch/delete) |
| FoundryRunPlan (draft) | foundry.md:1263; `ioi.hypervisor.foundry-run-plan.v1` (foundry_routes.rs:32) | hypervisor-daemon.rs:1335-1345 |
| Foundry overview projection (specs+plans+substrate) | foundry.md:173-176 | hypervisor-daemon.rs:1320-1323 (foundry_routes.rs:204) |
| ModelRoute registry (probe/enable/disable/select-default/session-bindings) | core-clients-surfaces.md:1456-1458 | hypervisor-daemon.rs:2087-2124 |
| Model-route mutation admission (planner-admitted mutation) | core-clients-surfaces.md:2515-2522 | hypervisor-daemon.rs:1076 |
| Model weight custody admission | foundry.md:279-282 (data-plane custody refs) | hypervisor-daemon.rs:1080 |
| Model-mount plane: server, tokens, providers, backends, endpoints, artifacts import, catalog import-url, downloads, instances/load, runtime engines/select, vault refs/status/health, receipts(+replay), projection, native-local, mcp, routes(+test), workflow nodes/receipt-gate — 48 routes | foundry.md:249-253 (Deploy/Route) | hypervisor-daemon.rs:635-766 |
| OpenAI-compat inference + catalog reads (`/v1/models`, `/v1/models/routes`, `/v1/models/catalog/search`, `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, `/v1/embeddings`) | foundry.md:249-253 | hypervisor-daemon.rs:617-618,681,750-753 |
| Worker package install admission (kernel planner, 202+record) | core-clients-surfaces.md:2504 | hypervisor-daemon.rs:1099 (lifecycle_routes.rs:6615) |
| Training-evidence sources: memory/skill entries + lifecycle + mutation proposals + projections (read for eligibility only) | core-clients-surfaces.md:2524-2526, :1024-1026 | hypervisor-daemon.rs:1651-1770; `/v1/skills` :1026 |
| Eval-suite candidates (model_eval drafts feed Evaluations) | foundry.md:235-241 | eval-suites CRUD hypervisor-daemon.rs:1919-1930 (Evaluations-owned) |
| InstitutionalLearningBoundaryProfile projection (per-job boundary/eligibility/rights readout) | core-clients-surfaces.md:1051-1056, :1087-1088; foundry.md:49-52 | `route-missing` — **W3** |
| Dataset plane: FoundryDatasetFactoryRun/DatasetSnapshot/CandidateDataRecord/holdouts | foundry.md:1707,1235,1654; core-clients-surfaces.md:2505-2506 | `route-missing` — **W3** |
| Training/tuning plane: FoundryTrainingPipelineRun/Trial/CheckpointArtifact/TeacherSession | foundry.md:1821,1285,1300,1374 | `route-missing` — **W3** |
| Experiment optimization: FoundryExperimentOptimizationCycle (advisory) | foundry.md:1884,305-311 | `route-missing` — **W3** |
| Deploy lineage: FoundryArtifactConversionRun/RegistryVersion/RouteBinding/PromotionBundle | foundry.md:1927,1344,1361,1973 | `route-missing` — **W3** |
| Foundry-side eval assets: ExecutableEvalSuite/EvalWorld/EvalTrajectoryRun/TrajectoryScorecard | foundry.md:1398,1419,1438,1475 | `route-missing` — **W3** (judgment stays Evaluations) |
| Training-program revision family: FoundryTrainingStackBlueprintRevision + TrainingPhasePlan + DataMixture/SequenceFormat/OptimizerNumerics profiles + ResolvedExecutionPlan + RolloutPolicy/DistillationPlan + EnvironmentLifecycleProfile + Checkpoint/Performance contracts | foundry.md "Reproducible Training Program Revisions" + contract block | `route-missing` — **W3.0** (contract registration precedes every mutation route) |

No Foundry-family JSON Schema exists in `docs/architecture/_meta/schemas/`
(158 files; zero model-route/foundry/model-mount entries) — the daemon schema
strings above are the only registered shapes. Registry entries land with each
W3 family.

## 3. UI seed map

- **T2 substrate readout `/__ioi/foundry`** (serve-product-ui.mjs:9496-9601
  handlers; renderers :3021-3201): overview head + Model Catalog section over
  `/v1/hypervisor/model-routes` (:3076-3108), FoundrySpec draft CRUD forms
  (new/edit/patch/delete → daemon foundry routes; :3123-3166), FoundryRunPlan
  draft CRUD (:3174-3201), Evals section listing `model_eval` drafts
  (:3115). Deliberately inert: "Nothing here trains, evaluates, serves, or
  promotes" (:3072). **wired** (reads + draft writes).
- **T3 registered surface `models`** — surface-registry.mjs:57 (owner
  "Foundry", title "Model Catalog", route `/__ioi/foundry/models`,
  capabilities `["browse"]`). Renderer serve-product-ui.mjs:5212-5280,
  handler :8785: one card per daemon model route with availability/probe
  evidence/custody/credential posture. census: 39 controls — 20 implemented
  (9 daemon-read, 9 local-view), **0 governed-receipted**, 6
  disabled-missing-authority, 8 unsupported-reference, 7 reference-data-only.
  Compare/playground, model detail, Registered-models import, facet search:
  **dead** (named gaps, census `missing_authority_contracts`). **partial**.
- **Model-route administration lives on Agent Studio, not the catalog**:
  `#model-routes` tab (serve-product-ui.mjs:2983-2998, table :2488-2519)
  posts probe/enable/disable/select-default to
  `/__ioi/agent-studio/model-routes/:id/:act` which proxies to the daemon
  verbs (serve-product-ui.mjs:9446-9449). **wired** (receipted,
  planner-admitted). Known gotcha: stale probe evidence yields 412 on launch;
  POST `:id/probe` refreshes.
- **Intel readouts** `/__ioi/agent-studio/intel/memory`, `/intel/skills`,
  `/intel/graph` (serve-product-ui.mjs:2567-2635, :9288): memory/skill entry
  create + promote/dispute/mark_stale lifecycle forms over
  hypervisor-daemon.rs:1651-1770. **wired**, but owned elsewhere (see
  Corrections #4) — Foundry consumes reads only.
- **T4 reference-only seeds**: `/__apps/models` (model-registry capture,
  "familiar baseline, never a rebound surface"), `/__apps/modelstudio`,
  `/__apps/inference` (serve-product-ui.mjs:3106). Preserved dormant per
  ported-seed invariant.
- Canonical `/foundry` does not resolve (census: `{"route": "/foundry",
  "resolves": false}`); daemon-level `/sessions`/`/missions`/`/__ioi/*` are
  already typed-410 (hypervisor-daemon.rs:610-612) — the serve process, not
  the daemon, owns `/__ioi/foundry*` today.

### Corrections vs v0

- v0 said: "model-mount plane (45 routes!)" — bytes show **48** exact
  `/v1/model-mount/*` registrations (hypervisor-daemon.rs:635-766), plus the
  4 OpenAI-compat inference routes (:750-753) and 3 models/catalog reads
  (:617,:618,:681) riding the same kernel (`model_mount`,
  hypervisor-daemon.rs:200).
- v0 said: "training/dataset families largely exist under foundry+model-mount"
  — bytes show **no training, dataset, trial, checkpoint, registry-version,
  or promotion route exists anywhere** (full 663-route sweep). The daemon
  Foundry family is 5 registrations — overview + draft-only specs/run-plans
  (hypervisor-daemon.rs:1320-1345), "deliberately inert … no training
  execution, no eval execution, no promotion mutation"
  (foundry_routes.rs:1-16). Model-mount covers weight custody/serving, not
  training. Train/Build/Optimize IA sections therefore open read-first over
  honest absence, with the section-2 W3 rows as their build-list.
- v0 said: "inherits `models` surface" — the models registration is
  browse-only with **0 governed controls** (census + surface-registry.mjs:57);
  the actual receipted model-route verbs live on Agent Studio's
  `#model-routes` tab (serve-product-ui.mjs:2491, 9446-9449). The rehome
  source for Foundry's authority actions is Agent Studio, not the catalog.
- v0 said: Foundry "inherits … intelligence memory/skills" — canon places
  personal memory/skill preferences in Settings
  (core-clients-surfaces.md:981), the durable memory substrate in Agent
  Wiki/`ioi-memory` (:1044-1047), and gives Foundry only contextual
  eligible-evidence/learning-flow/route-rights projections (:1024-1026,
  :2524-2526). This brief binds memory/skill entries **read-only** as
  training-evidence eligibility; the lifecycle verbs on the intel readout are
  not rehomed under `/foundry` (cross-brief boundary — Improvement/Settings
  own those panes).
- Packet said the 14 registered surfaces live at `apps/hypervisor/surfaces/<slug>/`
  — bytes: only 6 extracted module dirs exist there; `models`/`listings`
  registration + render live in `scripts/surface-registry.mjs` and
  `scripts/serve-product-ui.mjs` (census `module` fields are aspirational for
  these slugs).

## 4. Schema→UI binding table

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| Discover · catalog grid (one card per route: availability, probe evidence + staleness, custody, credential, lifecycle) | ModelRoute · GET /v1/hypervisor/model-routes (+ /overview :2092) | wired at /__ioi/foundry/models | wired-read (read client) |
| Discover · catalog name/facet search | GET /v1/models/catalog/search (hypervisor-daemon.rs:681) + client filter | dead (census view-only gap) | wired-read |
| Discover · model detail page (card, custody, admission trail) | GET /v1/hypervisor/model-routes/:id + /v1/model-mount/vault/refs,/vault/status | dead (named gap) | wired-read |
| Discover · compare/playground (two routes → prompt → run) | no governed catalog workflow; raw /v1/chat/completions exists (:750) | dead | disabled-named-gap (census missing-authority row) |
| Build · FoundrySpec list/create/edit/delete (5 kinds) | foundry-spec.v1 · hypervisor-daemon.rs:1324-1333 | wired draft CRUD on /__ioi/foundry | wired-action-receipted (draft writes must gain receipt refs — the eval-suites receiptless-mutation defect generalizes; else disabled-named-gap) |
| Build · FoundryRunPlan list/create/delete | foundry-run-plan.v1 · hypervisor-daemon.rs:1335-1345 | wired draft CRUD | wired-action-receipted (same receipt obligation) |
| Train/Tune · pipelines, teacher sessions, dataset factory, checkpoints | foundry.md:1707,1821,1374,1300 · route-missing | absent | disabled-named-gap now; wired after W3 |
| Evaluate · model_eval drafts + link-out to Evaluations suites/runs | specs?kind=model_eval (foundry_routes.rs:270-277); eval-suites :1919-1930 | wired (drafts) / read link | wired-read; judgment stays Evaluations (foundry.md:235-241) |
| Optimize · experiment cycles, attempt lineage | foundry.md:1884 · route-missing | absent | disabled-named-gap now; W3 (advisory-only rendering, foundry.md:305-311) |
| Deploy · instances loaded/load, runtime engines/select, downloads(+cancel), storage cleanup, endpoints, artifacts import, catalog import-url, native-local | model-mount plane hypervisor-daemon.rs:635-766 | reads partial (adapter maps `model-routes`, `receipts` — ioi-api-adapter.mjs:322-330); actions unexposed | wired-read for state; actions wired-action-receipted via authority client (403 wallet challenge → 428 credential → receipt refs) |
| Deploy · route admin verbs: probe / enable / disable / select-default | POST /v1/hypervisor/model-routes/:id/{probe,enable,disable,select-default} (:2102-2116) | wired on Agent Studio tab | wired-action-receipted, rehomed into /foundry Deploy pane |
| Deploy · route create/patch/delete + mutation admission | :2087-2100 + admission :1076 | wired (Studio) | wired-action-receipted |
| Deploy · session bindings rows (which sessions serve which route) | POST :id/session-bindings :2118; GET /v1/hypervisor/model-route-session-bindings :2122 | wired list | wired-read; session rows bind through `subject_attachments` only (C-1; core-clients-surfaces.md:3971-3990) — never a named app field |
| Govern · receipts stream + replay drilldown | GET /v1/model-mount/receipts,/receipts/:id,/receipts/:id/replay (:738-743) | wired reads exist | wired-read (hashes behind proof drilldowns) |
| Govern · learning-boundary badge on every job/spec/promotion pane | InstitutionalLearningBoundaryProfile projection · route-missing (W3) | absent | disabled-named-gap now; when wired, projection-only — **never ambient permission**, never a toggle (core-clients-surfaces.md:2527-2528, :1096-1099) |
| Govern · promotion bundle queue / route-binding candidates | foundry.md:1973 · route-missing | absent | disabled-named-gap; W3 (activation decisions stay Governance) |
| Govern · weight-custody + worker-package admission timelines | POST-only planners :1080, :1099 | invisible | wired-read over admission records (new read projection is part of the W3 row) |
| Train/Tune · blueprint revision diff viewer (revision N vs N-1: phases, profiles, budgets, gates) | FoundryTrainingStackBlueprintRevision + phase-plan/profile content hashes · W3.0 schemas | absent | disabled-named-gap now; wired-read after W3.0 (diff computed over admitted revisions, never drafts) |
| Train/Tune · data-mixture/curriculum inspector (per-stage weights, token budgets, tokenizer accounting, filter versions) | FoundryDataMixtureProfile · W3.1 | absent | disabled-named-gap; wired-read after W3.1 |
| Train/Tune · backend compatibility panel (blueprint revision × TrainerBackendProfile capability report) | FoundryResolvedExecutionPlan.backend_capability_report_ref · W3.2 | absent | disabled-named-gap; wired-read; incompatibility renders as named readiness gap, never silent downgrade |
| Train/Tune · run DAG + controls (phase graph, stage state, pause/resume/stop) | FoundryTrainingPipelineRun.blueprint_revision_ref + phase plans · W3.2 | absent | controls wired-action-receipted via CapabilityLease; reads projection-only |
| Train/Tune · live goodput/bottleneck view (qualified tokens/s, MFU, stalls, waste; every number carries phase/numerator/scope/fingerprint) | FoundryPerformanceContract observations · W3.4 | absent | wired-read; unqualified throughput numbers are a render defect |
| Train/Tune · rollout-staleness queue (policy lag distribution, paused/resumable attempts, accepted-token ratio) | FoundryRolloutPolicy attempt records · W3.2 | absent | disabled-named-gap; wired-read after W3.2 |
| Train/Tune · environment snapshot browser (world image hash, fork lineage, reset/recovery evidence) | FoundryEnvironmentLifecycleProfile + snapshots · W3.2 | absent | disabled-named-gap; wired-read after W3.2 |
| Train/Tune · checkpoint restore evidence (required-state completeness, restore verification, last admitted step) | FoundryCheckpointContract · W3.3 | absent | wired-read; a checkpoint without restore verification renders as unverified, not as restorable |
| Govern · gate/promotion lineage (revision → phases → checkpoints → gates → promotion bundle) | revision family + FoundryPromotionBundle · W3.3 | absent | wired-read; activation stays Governance (INV-13) |

## 5. Ordered PR list

1. **W0 (rides W0.2/W0.3)** — register Foundry in the product-surface
   compiler feed; route `/foundry` in the v2 shell route table (bodies may be
   read-first). No new daemon routes.
2. **W1** — `/foundry` shell with the seven-section IA; Discover pane
   wired-read over model-routes + overview + catalog search; honest-absence
   panels (named, visible) for Train/Optimize/Promotion. Zero fixture data.
3. **W1** — rehome the `/__ioi/foundry` specs/run-plans panes into
   `/foundry` Build/Evaluate sections (read + draft forms preserved; seed
   surfaces keep serving until cutover per the 6-step rule).
4. **W1** — Govern pane read-first: model-mount receipts/replay reads,
   projection, vault status; session-bindings list rendered via
   `subject_attachments`.
5. **W2** — Deploy pane authority actions via the CapabilityLease client:
   route verbs (probe/enable/disable/select-default/create/patch/delete) and
   model-mount lifecycle actions (downloads, instance load, runtime select,
   storage cleanup, catalog import-url); every control receipted or
   disabled-named-gap.
6. **W2** — spec/run-plan mutation receipts: draft CRUD gains receipt refs
   (or is demoted to disabled-named-gap until it does).
7. **W3.0 (contract-and-migration wave — precedes every mutation route and
   every mutation UI)** — register the Foundry JSON Schema family in
   `docs/architecture/_meta/schemas/` with generated Rust/TS contracts:
   foundry-spec/run-plan v2 plus the training-program revision family
   (BlueprintRevision, TrainingPhasePlan, DataMixtureProfile,
   SequenceFormatProfile, OptimizerNumericsProfile, ResolvedExecutionPlan,
   RolloutPolicy, DistillationPlan, EnvironmentLifecycleProfile,
   CheckpointContract, PerformanceContract). Migrate the two local
   schema-string constants onto registered shapes (v1 free-form `inputs` /
   opaque `steps` stay readable under v1 names, never as v2 semantics —
   adapter migration, not field mapping). Spec/run-plan writes move onto
   Agentgres admission (expected-head CAS + receipts + revision) closing
   defects D-3/D-4. Per family, before any route lands: state machine +
   legal-transition table, authority path (CapabilityLease), named refusal
   dimensions with negative fixtures, recovery semantics, telemetry
   segment-root commitment points, and tests.
8. **W3.1-W3.4 (backend-first, serialized on hypervisor-daemon.rs)** —
   W3.1 dataset family (`foundry/dataset-factory-runs`, snapshots,
   candidate-data, holdout custody, mixture profiles); W3.2 executor/
   lifecycle family (pipeline runs bound to admitted blueprint revisions,
   trials, teacher sessions, rollout-attempt records with staleness +
   resumption, environment lifecycle/snapshots); W3.3 checkpoint/recovery
   family (checkpoint contract enforcement, restore-verification evidence,
   deploy-lineage: conversion runs, registry versions, promotion bundles —
   read/propose only); W3.4 performance/telemetry family (qualified
   throughput observations, goodput ledger, stall taxonomy, segment-root
   commits) + optimizer cycles (advisory). Each wave lands routes +
   registered schema + UI in the same PR set. Measurement (W3.4 read plane)
   lands before any throughput-optimization work is accepted.
9. **W3** — learning-boundary projection route + badge wiring across every
   Foundry job/promotion pane (projection-only).
10. **W4** — event consumption for probe/receipt/run updates moves to
    `/v1/event-streams` + `/v1/subscriptions`; legacy model-mount SSE
    (`/v1/model-mount/server/events` :642) wrapped, not extended.
11. **W4** — cutover: `/__ioi/foundry*`, `/__ioi/foundry/models`, and the
    Agent Studio `#model-routes` tab retire with typed 410s; `models` row
    exits surface-registry; `/__apps/models`/`modelstudio`/`inference`
    captures remain dormant T4 evidence; reconcile the two
    `foundry_eval_training` profile_kind byte sites (connectors-tools
    contracts.md:162, doctrine.md:156) in whichever PR touches those files.

## 6. Route-plane defect register (audited 2026-08-06)

Byte-verified against `foundry_routes.rs` on master at 64b0607f4:

- **D-1 persistence dishonesty — FIXED (this PR).** Spec create/patch and
  run-plan create discarded `persist_record` errors (`let _ =`) while
  returning success. Now a persist failure returns typed
  `foundry_persist_failed` (500 on create, `ok:false` on patch) — INV-14.
- **D-2 mutable meaning — FIXED (this PR).** Run plans referenced their spec
  by mutable id only, so a later spec PATCH silently changed an existing
  plan's meaning. Plans now pin `spec_content_hash` (timestamp-excluded
  content hash) at creation; plan GET reports `spec_drifted`/`spec_missing`
  as computed read fields (rows are views — drift is never persisted back).
- **D-3 unregistered schemas — W3.0.** `ioi.hypervisor.foundry-spec.v1` /
  `foundry-run-plan.v1` are local string constants; no
  `_meta/schemas/` registration, no generated contracts.
- **D-4 no admission — W3.0, gates all mutation UI.** Writes are direct
  JSON-file persistence: not Agentgres-admitted, CAS-protected, receipted,
  or revisioned. Per the Agentgres positioning constraints (#168, canon
  #169), admission is the only write story — no surface may present these
  drafts with mutation semantics beyond draft CRUD until W3.0 lands.
- **D-5 authority named, unenforced — W2/W3.** `authority_policy_ref` is
  declared-only; enforcement arrives with the CapabilityLease client wave.
- **D-6 free-form payloads — W3.0.** Spec `inputs` and run-plan `steps` are
  opaque JSON; v2 schemas type them (phase plans, profiles) and the v1
  shapes survive read-only under v1 names.
