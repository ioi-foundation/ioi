# IOI Zero-to-Hero Agent Systems Rolling Plan

Last updated: 2026-04-02 07:18 America/New_York
Owner: active Codex session
Status: living plan

Canonical strategy:

- `docs/plans/ioi-zero-to-hero-agent-systems-guide.md`

This document is the execution scratchboard for the guide above.

It exists to keep the active working set small while preserving a trustworthy
reference point for iteration, handoff, and restart.

## How to use this document

- keep only the current execution window and the next window here
- do not restate the full guide
- do not turn this into a second strategy doc
- prefer links to evidence, diffs, dashboards, and benchmark outputs over
  pasted logs
- record only decisions that still affect the next few steps
- archive stale detail by compressing it into 1 to 3 bullets under
  `Recently completed`

## Definition of usefulness

This rolling plan is healthy when it answers five questions quickly:

1. What are we trying to complete right now?
2. What did we just finish that materially changes the next move?
3. What are the next 3 to 5 tasks?
4. What is blocked or risky?
5. What evidence proves progress?

If it stops doing that, compress it.

## Long-horizon objective

Take IOI from a capable but uneven agent platform to a disciplined,
benchmark-backed, role-first system with:

- explicit router -> planner -> specialist -> verifier -> human gate ->
  synthesize flow
- stronger local and multimodal model tiering
- benchmark-first promotion of model presets
- broader registry-backed skill surfacing
- stronger workload-specific pipelines for research, coding, computer use, and
  artifacts
- a state-of-the-art Spotlight execution UX instead of a worklog-heavy debug UX

## Current baseline

What is true today:

- Studio is the strongest typed pipeline
- desktop service already has meaningful planning and verification structure
- local GPU dev still defaults to `llama3.2:3b`
- the experimental model matrix now exists and is benchmark-wired without
  changing the shipped default
- parent-playbook routes now emit explicit `route_family`, `topology`, and
  `verifier_state` metadata through receipts into Spotlight
- the research route now uses registry-backed skill recall and explicit prep
  summaries outside Studio
- the research lane now emits explicit citation-verifier scorecards through
  parent-playbook receipts into Spotlight
- the coding lane now runs a typed context -> executor -> targeted-test
  verifier -> patch synthesizer flow with operator-visible receipts
- the computer-use lane now emits typed perception, verification, recovery,
  and approval summaries through receipts into Spotlight
- the artifact lane now runs an explicit context -> generate -> judge flow with
  typed generation, quality, and repair receipts rendered into Spotlight
- the primary Spotlight chat lane now keeps the execution card visible with
  typed stage, progress, and pause summaries while raw trace stays behind an
  explicit execution-drawer affordance
- the first full-coverage model-matrix run now retains artifact, coding,
  research, and computer-use evidence together, and the next forcing function
  is turning the retained red slices into route-conformant wins before any
  preset promotion

Primary references:

- `apps/autopilot/src-tauri/src/kernel/local_engine/mod.rs`
- `apps/autopilot/src-tauri/src/kernel/local_engine/bootstrap.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/pipeline.rs`
- `crates/services/src/agentic/desktop/service/step/mod.rs`
- `crates/services/src/agentic/skill_registry.rs`
- `apps/autopilot/src/windows/SpotlightWindow/components/ConversationTimeline.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/ArtifactHubViews.tsx`

## Current focus

Artifact remains closed-green on
`docs/evidence/agent-model-matrix/runs/2026-03-31T20-35-31-743Z`, coding is
reclosed on
`docs/evidence/agent-model-matrix/runs/2026-04-02T10-02-13-443Z`, and research
is now reclosed on the official retained rerun at
`docs/evidence/agent-model-matrix/runs/2026-04-02T11-15-56-717Z`. The research
closure came from treating the cross-domain TCG PDF as a bounded grounded
support artifact in selected-source quality and selected-source subject-
alignment scoring, instead of demanding that every selected source behave like
a primary authority page. The shipped default stays frozen at `keep_default`;
this is a route-conformance win, not a promotion case.

## Rolling window

### Recently completed

- the fresh full-coverage matrix window is captured at
  `docs/evidence/agent-model-matrix/runs/2026-04-02T09-17-40-700Z`: artifact
  stayed closed-green, research reopened on the completion-gate /
  source-independence seam, and coding reopened on a narrow
  `patch_synthesis_handoff` `IncompleteWorkerResult` instead of the earlier
  execution deadlock shape
- the research red is reclosed end-to-end: authority expansion and pending
  follow-up now retain the cross-domain TCG PDF, selected-source quality now
  counts a grounded external publication artifact as valid support when paired
  with a real authority source, selected-source subject alignment now accepts
  that support shape without lying about which source actually aligned, and the
  official retained rerun at
  `docs/evidence/agent-model-matrix/runs/2026-04-02T11-15-56-717Z/planner-grade-local-oss/research-nist-pqc-briefing/retained-result.json`
  passed with `localScore=1`, `citationVerifierPass=true`,
  `sourceIndependenceRate=1`, `selected_source_quality_floor_met=true`, and
  `selected_source_subject_alignment_floor_met=true`:
  `crates/services/src/agentic/desktop/service/step/queue/support/pipeline/signal.rs`
  `crates/services/src/agentic/desktop/service/step/queue/support/query/pre_read/selection_metrics.rs`
  `crates/services/src/agentic/desktop/service/step/queue/processing/web_pipeline/read.rs`
  `cargo test -q -p ioi-services document_briefing_quality_observation_accepts_grounded_external_pdf_support_with_authority_pairing -- --nocapture`
  `cargo test -q -p ioi-services document_briefing_selected_source_alignment_accepts_grounded_external_pdf_support -- --nocapture`
  `cargo test -q -p ioi-services document_briefing_quality_observation_rejects_grounded_same_authority_selection_when_distinct_domain_floor_is_required -- --nocapture`
  `cargo test -q -p ioi-services pre_read_selection_sources_merge_pending_authority_with_live_support_artifact -- --nocapture`
- the coding red is reclosed end-to-end: worker-result materialization now
  synthesizes a structured patch handoff from the parent playbook’s implement
  and verifier receipts when the patch synthesizer completes without an
  explicit structured payload, the new regression
  `materialize_patch_synthesis_completion_recovers_from_parent_receipts` is
  green, `evidence_audited_parent_playbook_advances_across_all_steps` stays
  green, and the official retained rerun at
  `docs/evidence/agent-model-matrix/runs/2026-04-02T10-02-13-443Z/coding-executor-local-oss/coding-path-normalizer-fixture/retained-result.json`
  passed with `localScore=1` and `patchSynthesisReady=true`:
  `crates/services/src/agentic/desktop/service/lifecycle/worker_results.rs`
  `cargo test -q -p ioi-services materialize_patch_synthesis_completion_recovers_from_parent_receipts -- --nocapture`
  `cargo test -q -p ioi-services evidence_audited_parent_playbook_advances_across_all_steps -- --nocapture`
- benchmark surfaces are refreshed to the newest retained reruns:
  `docs/evidence/agent-model-matrix/latest-summary.json`
  `docs/evidence/agent-model-matrix/latest-summary.md`
  `apps/benchmarks/src/generated/benchmark-data.json`
  `apps/benchmarks/public/generated/benchmark-data.json`
- Phase 1 hierarchy normalization now has three green sub-slices in place:
  explicit route-contract receipt fields, bounded `verifier_outcome`, and
  registry-backed Spotlight fallback that resolves known playbook contracts
  before lexical lane guesses; completion receipts now also carry aggregated
  `selected_skills` and `prep_summary` so prep context survives to the final
  parent handoff, blocked parent-playbook receipts now preserve that prep
  context too, and workflow-ID aliases now keep known built-in routes out of
  the heuristic lane; started receipts now preserve prep context as well, so
  the remaining heuristics are limited to truly unknown routes; the receipt
  builder/parser extractions are landed and the shared Rust and TypeScript
  surfaces are locally green:
  `crates/services/src/agentic/desktop/service/lifecycle/parent_playbook_receipts.rs`
  `crates/services/src/agentic/desktop/service/lifecycle/worker_results.rs`
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.routeContracts.ts`
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
  `npx tsc --noEmit -p apps/autopilot/tsconfig.json`
  `npx tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
  `cargo test -q -p ioi-services citation_grounded_brief_surfaces_research_verifier_scorecard -- --nocapture`
  `cargo test -q -p ioi-services artifact_generation_gate_surfaces_context_generation_and_quality_receipts -- --nocapture`
  `cargo test -q -p ioi-services browser_postcondition_gate_surfaces_perception_and_recovery_receipts -- --nocapture`
  `cargo check -q -p ioi-validator`

### In progress

- exit the primitive-blocker window and resume the canonical guide from a
  truthful retained baseline where artifact, coding, and research are all
  reclosed-green
- keep the shipped default frozen at `keep_default`; the newest retained
  reruns prove route-conformance repairs, but promotion still needs repeated
  full-coverage evidence rather than isolated lane wins

### Current window goal

Resume the canonical guide from the new all-green retained baseline without
reopening closed lanes or drifting back into lane-local matrix churn, while
preserving `keep_default`.

### Next 5 tasks

1. Compress the just-closed blocker window into stable evidence anchors:
   artifact at `2026-03-31T20-35-31-743Z`, coding at
   `2026-04-02T10-02-13-443Z`, and research at
   `2026-04-02T11-15-56-717Z`.
2. Resume the canonical guide on the next narrow implementation slice outside
   the matrix loop: audit only truly contract-less route fallbacks and any
   remaining non-terminal skill-handoff gaps.
3. Keep route-family / topology / verifier / prep receipts as the source of
   truth for Spotlight and downstream consumers; do not reintroduce topology or
   lexical inference where typed metadata now exists.
4. Land the next guide slice with focused local validation before opening
   another full-coverage matrix window.
5. Spend the next full-coverage matrix run only after that materially new guide
   slice is in place, and keep `keep_default` frozen until repeated retained
   coverage justifies otherwise.

### Exit criteria for the current window

- the rolling window points at the next canonical guide slice rather than an
  already-closed retained blocker
- retained artifact baseline evidence remains preserved, coding is refreshed-
  green on `docs/evidence/agent-model-matrix/runs/2026-04-02T10-02-13-443Z`,
  and research is refreshed-green on
  `docs/evidence/agent-model-matrix/runs/2026-04-02T11-15-56-717Z`
- the explicit route-contract, bounded verifier-outcome, built-in
  playbook/workflow fallback, and started/blocked/completed prep-handoff
  slices remain landed, and the coding patch-synthesis materialization seam is
  now closed too; the research support-artifact scoring/alignment seam is
  closed too
- benchmark surfaces reflect the latest retained research rerun
- no green lane is reopened without a fresh retained regression or a materially
  different benchmark-honest move
- the promotion recommendation remains default-safe and benchmark-backed at
  `keep_default`

### Next window preview

The next implementation slice should return to the guide proper: continue the
remaining route-contract / skill-handoff normalization work, then reopen a full
coverage matrix window from the now-stable artifact + coding + research
baseline.

### Risks

- the newest retained rerun is research-only, so it proves the route repair but
  not full scorecard promotion by itself
- the last full-coverage window still contains the pre-fix research red, so do
  not confuse the new research reclosure with a new full-window promotion case
- hierarchy normalization still touches receipts, routing, and Spotlight
  surfaces that already have lane-specific logic, so the remaining
  ultimate-fallback and skill-handoff cleanup can drift into a larger refactor
  unless the write scope stays narrow
- skill-discovery and Spotlight work intersect already-active Studio and
  artifact files in this dirty worktree, so changes must stay narrow and avoid
  stomping
- multimodal lanes remain credential-blocked in this environment

### Decisions

- do not replace the default local preset before benchmark evidence says to
- keep the architecture role-first and benchmark-first, not brand-first
- keep this document as a rolling window tracker, not a second master plan
- prefer promotion gates tied to receipts, benchmarks, and UX evidence instead
  of anecdotal "felt better" judgments
- use capabilities-suite as the phase-0 research and coding matrix substrate
  until a better retained workload harness exists
- keep the hierarchy small and typed; do not build a large generic swarm just
  to make the UI look more agentic
- route metadata should be emitted in parent-playbook receipts and consumed by
  Spotlight before any heuristic fallback is attempted
- planner-of-record ownership and verifier role should travel together in route
  receipts so Spotlight and downstream consumers do not infer them indirectly
  from topology alone
- keep verifier lifecycle state separate from bounded verifier outcome so
  completion receipts can say "completed with warning" without inventing a new
  topology or lying about semantic success
- when explicit route fields are absent, prefer built-in playbook contract
  fallback over lexical lane inference so Spotlight stays aligned with the
  kernel's typed hierarchy
- final parent-playbook completion receipts should preserve aggregated prep
  cues so downstream consumers do not need to scrape earlier step receipts just
  to recover selected skills or route prep context
- terminal blocked parent-playbook receipts should preserve aggregated prep
  cues too, so operator-facing failure surfaces retain the same route context
- grounded external publication artifacts may satisfy the support side of a
  document-briefing pair when they are cross-domain, non-low-priority, and
  paired with a real authority source; do not force every selected support
  source to masquerade as a primary authority page
- keep verifier receipts focused on bounded, typed outcomes first; widen only
  when the route records why it had to expand coverage or recover
- keep the matrix runner on the shipped default unless a challenger wins
  repeatedly on the fully covered scorecard set
- preserve live coding benchmark stability by setting `RUST_MIN_STACK` in the
  capabilities-backed matrix runner rather than hand-editing retained evidence
- do not append static authority seed URLs for document briefings just to force
  authority candidates into retained research; preserve typed web observation
  and citation-verifier integrity
- when pending-inventory reuse would collapse a grounded document briefing
  below its distinct-domain floor, prefer read-backed authority plus
  distinct-domain official support from the already discovered inventory before
  escalating to more search churn
- distinct-domain floors for grounded document briefings must be satisfied by
  genuinely grounded cross-domain support, not by same-authority-family
  overrides or generic official-policy neighbors
- coding is now retained-green on
  `docs/evidence/agent-model-matrix/runs/2026-04-02T10-02-13-443Z`; do not
  spend another same-window coding rerun unless a fresh retained regression or
  a materially different benchmark-honest move justifies reopening that lane
- parent playbook orchestration should keep awaiting an active child until the
  merge clears `active_child_session_id`; an empty child queue is not itself a
  trustworthy terminal signal
- Phase 1 work should prefer explicit route contracts and verifier semantics
  over new workers, broader topology changes, or benchmark-unbacked UX churn

### Evidence

Canonical strategy:

- `docs/plans/ioi-zero-to-hero-agent-systems-guide.md`

Current window evidence:

- `docs/evidence/agent-model-matrix/latest-summary.json`
- `docs/evidence/agent-model-matrix/latest-summary.md`
- `docs/evidence/agent-model-matrix/runs/2026-03-31T20-35-31-743Z`
- `docs/evidence/agent-model-matrix/runs/2026-04-02T09-17-40-700Z`
- `docs/evidence/agent-model-matrix/runs/2026-04-02T10-02-13-443Z`
- `docs/evidence/agent-model-matrix/runs/2026-04-02T10-02-13-443Z/coding-executor-local-oss/coding-path-normalizer-fixture/retained-result.json`
- `docs/evidence/agent-model-matrix/runs/2026-04-02T11-15-56-717Z`
- `docs/evidence/agent-model-matrix/runs/2026-04-02T11-15-56-717Z/planner-grade-local-oss/research-nist-pqc-briefing/retained-result.json`
- `crates/services/src/agentic/desktop/service/step/queue/processing/web_pipeline/search/planning.rs`
- `crates/services/src/agentic/desktop/service/step/queue/processing/web_pipeline/read.rs`
- `crates/services/src/agentic/desktop/service/step/queue/support/pipeline/pending.rs`
- `crates/services/src/agentic/desktop/service/step/queue/support/pipeline/signal.rs`
- `crates/services/src/agentic/desktop/service/step/queue/support/query/pre_read/selection_metrics.rs`
- `crates/services/src/agentic/desktop/service/step/action/processing/repair.rs`
- `crates/services/src/agentic/desktop/service/step/mod.rs`
- `crates/services/src/agentic/desktop/agent_playbooks.rs`
- `crates/services/src/agentic/desktop/service/lifecycle/parent_playbook_receipts.rs`
- `crates/services/src/agentic/desktop/service/lifecycle/worker_results.rs`
- `crates/services/src/agentic/desktop/service/step/cognition.rs`
- `crates/types/src/app/events.rs`
- `crates/ipc/proto/public/v1/public.proto`
- `crates/validator/src/standard/orchestration/grpc_public/events_handlers/kernel_mapping.rs`
- `apps/autopilot/src/types.ts`
- `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.routeContracts.ts`
- `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
- `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/ArtifactHubViews.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/styles/Chat.css`
- `apps/benchmarks/src/generated/benchmark-data.json`
- `apps/benchmarks/public/generated/benchmark-data.json`
