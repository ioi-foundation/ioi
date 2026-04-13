# Studio Artifact Execution-Witness Validation Plan

Last updated: 2026-04-12
Owner: Studio / artifact generation / acceptance / repair
Status: proposed

Companion documents:

- `docs/plans/studio-artifact-runtime-event-truth-plan.md`
- `docs/plans/studio-prepared-context-contract-plan.md`
- `docs/plans/studio-claude-artifact-parity-plan.md`

## Purpose

This plan addresses the failure mode where Studio can report:

- a verified artifact
- one or more "repair pass(es)"
- a surfaced primary artifact view

while the delivered artifact is still behaviorally broken.

The target end state is:

- repair is counted by cleared obligations, not just candidate lineage
- acceptance is grounded in execution witnesses, not only model judgment
- validation remains renderer-shaped and generic, not domain-specific
- the repair loop consumes typed failure evidence instead of free-form guesses

This plan is intentionally anti-heuristic. The goal is not to add more
special-case checks for "buttons that look wrong" or "quantum explainers with
bad tabs." The goal is to define a generic execution contract per renderer and
require the artifact to satisfy it before Studio treats the result as accepted.

## Diagnosis

The current pipeline has repair machinery, but it is not yet robust enough to
guarantee behaviorally correct artifacts.

### 1. "Repair pass" is currently lineage truth, not execution truth

Studio's surfaced repair count is derived from candidate convergence lineage in:

- `apps/autopilot/src-tauri/src/kernel/studio/task_state.rs:3`

That tells us a non-initial refinement happened. It does not tell us:

- whether required interactions were actually exercised
- whether the repaired artifact cleared the original failure
- whether the surfaced primary artifact is behaviorally sound

### 2. Interaction validation is still too presence-based

The current HTML interaction gate accepts artifacts that merely contain
interactive-looking affordances such as:

- `<button`
- `onclick=`
- `addEventListener(`

Relevant seam:

- `crates/api/src/studio/html.rs:4274`

That means an artifact with `onclick="showPanel(...)"` can appear interactive
even if `showPanel` is undefined and every button fails at runtime.

### 3. Modal-first HTML currently relaxes too much of the acceptance contract

In modal-first HTML mode:

- brief-level structural interaction validation is bypassed in
  `crates/api/src/studio/payload.rs:814`
- renderer primary-view contract checks are effectively bypassed in
  `crates/api/src/studio/payload.rs:1202`
- render-evaluation evidence is skipped in
  `crates/api/src/studio/render_eval.rs:43`

This makes the lane more tolerant for streaming, but it also weakens the final
acceptance bar too much.

### 4. Soft validation and normalization still allow "good enough looking" drafts

The payload layer can:

- synthesize payloads from raw output
- repair HTML bodies from raw output
- downgrade some structural failures to soft validation notes

Relevant seams:

- `crates/api/src/studio/payload.rs:541`
- `crates/api/src/studio/payload.rs:576`
- `crates/api/src/studio/payload.rs:932`

That is useful for recovery, but by itself it is not a proof that the artifact
works.

### 5. The current repair loop is prompt-driven, not obligation-driven

The runtime does support repair attempts in:

- `crates/api/src/studio/generation/runtime_materialization.rs:166`
- `crates/api/src/studio/generation/runtime_materialization.rs:870`

But the repair input is still too dependent on model-judged failures and
renderer contract prose. It is not yet powered by a typed witness report like:

- unresolved handler reference
- click action produced no state change
- required interaction remained unwitnessed
- console error blocked the active attempt

## Core doctrine

The governing rule for this plan is:

> A Studio artifact is not accepted because it looks interactive or because a
> model judged it favorably. It is accepted only when its renderer-specific
> obligations are satisfied by machine-verifiable witnesses.

That implies:

- repairs are measured by obligation clearance, not by attempt count
- model judging remains useful for ranking and explanation, but cannot override
  hard execution failures
- renderer adapters may differ, but the acceptance framework stays uniform

## Desired end state

For an interactive HTML artifact, Studio should not accept the result until it
has witnessed all of the following classes of truth:

1. document truth
2. boot truth
3. interaction truth
4. presentation truth
5. query-outcome truth

Concrete examples:

- document is fully closed and parseable
- no fatal runtime exceptions during initial boot
- actionable controls are discoverable
- required interactions can actually be exercised
- each exercised interaction produces a meaningful visible state transition
- no required interaction remains unwitnessed
- the queried artifact outcome actually materializes and remains renderable

The same pattern should generalize to other renderers:

- SVG: parseable, labeled, visually non-empty, request-faithful
- JSX sandbox: compiles, mounts, no fatal runtime error, interaction obligations
  witnessed
- PDF embed: source validity, structural completeness, artifact renderability

## Target architecture

### Layer 1: Obligation synthesis

Introduce a typed acceptance-obligation bundle derived from:

- requested outcome kind
- renderer kind
- artifact class
- brief interaction contract
- edit intent

Suggested shape:

- `obligation_id`
- `family`
- `severity`
- `required`
- `witness_strategy`
- `target_selectors`
- `expected_state_change`
- `source`

Examples of obligation families:

- `document_complete`
- `primary_surface_present`
- `runtime_boot_clean`
- `controls_discovered`
- `default_state_visible`
- `interaction_witnessed`
- `shared_detail_updates`
- `view_switch_changes_state`
- `artifact_query_outcome_materialized`

Normative rule:

- obligations are derived from typed request/brief state, not invented from
  artifact-specific prose after the fact

### Layer 2: Execution witness engine

Introduce a renderer-aware witness engine that runs artifacts and records
machine-verifiable evidence.

Suggested witness report shape:

- `attempt_id`
- `obligation_id`
- `status` (`passed`, `failed`, `blocked`, `not_applicable`)
- `evidence_kind`
- `summary`
- `detail`
- `selector`
- `console_errors`
- `dom_delta_summary`
- `screenshot_ref`
- `timestamp`

For HTML/JSX, the witness engine should support:

- booting the artifact in a headless browser
- collecting console/runtime errors
- discovering actionable controls
- executing control actions
- observing DOM/state transitions
- verifying that visible state actually changes

Examples of generic visible state changes:

- `hidden` / `aria-hidden` / `aria-expanded` / `aria-selected` toggles
- active panel changes
- text changes in a declared shared detail surface
- a comparison region or metric surface changes
- focused detail content changes after hover/focus/click

Normative rule:

- "contains onclick" is not a witness
- "button exists" is not a witness
- "judge says interaction is good" is not a witness
- only executed evidence counts as an interaction witness

### Layer 3: Acceptance decision merger

Keep model judging, but demote it below hard witness truth.

Decision order should become:

1. payload validation
2. renderer contract validation
3. execution witness report
4. model judgment
5. final acceptance decision

Hard rule:

- a candidate cannot classify as `pass` if required obligations failed
- a model judge cannot override failed witness obligations

### Layer 4: Repair planning from typed failures

Repair input should be generated from failed obligations, not only from prose
repair hints.

Example repair payload content:

- `failedObligations`
- `blockedObligations`
- `witnessSummaries`
- `selectorsAndTargets`
- `runtimeErrors`
- `requiredInteractionCoverage`
- `firstPaintFailures`

This lets repair stay generic and composable:

- fix missing handler definitions
- repair no-op controls
- add missing target panels
- wire shared detail surfaces
- resolve runtime exceptions

without inventing domain-specific heuristics.

## Workstreams

### Workstream 1: Make acceptance obligations first-class

Goal:

- move from ad hoc renderer checks to a typed obligation contract

Implementation:

- define `StudioArtifactAcceptanceObligation` types in the Studio API layer
- derive obligations from request + brief + renderer + artifact class
- persist obligations on candidate summary and materialization contract

Primary files:

- `crates/api/src/studio/types.rs`
- `crates/api/src/studio/payload.rs`
- `crates/api/src/studio/planning.rs`

Deliverables:

- new typed obligation schema
- obligation derivation helpers for each renderer family
- contract persistence for accepted, failed, and unwitnessed obligations

### Workstream 2: Build a generic HTML/JSX witness executor

Goal:

- witness actual interaction behavior instead of relying on hook presence

Implementation:

- reuse the browser render/evaluation path to load the artifact
- collect boot/runtime errors
- discover actionable controls generically
- exercise one or more actions per required interaction family
- record DOM/state deltas

Primary files:

- `crates/api/src/studio/render_eval.rs`
- `crates/api/src/studio/html.rs`
- `crates/api/src/studio/generation/validation_preview.rs`
- browser execution/evaluation helpers already used by render capture

Deliverables:

- HTML/JSX witness runner
- `StudioArtifactWitnessReport`
- failure categories like:
  - unresolved handler
  - runtime exception
  - no-op control
  - target missing
  - required interaction unwitnessed

### Workstream 3: Remove modal-first acceptance blind spots

Goal:

- keep modal-first streaming benefits without disabling final behavioral truth

Implementation:

- separate `draft-surface tolerance` from `final acceptance tolerance`
- keep lightweight early streaming if needed
- always run final renderer contract + witness evaluation before acceptance

Primary files:

- `crates/api/src/studio/payload.rs`
- `crates/api/src/studio/render_eval.rs`
- `crates/api/src/studio/generation/candidate_materialization.rs`

Deliverables:

- modal-first no longer bypasses final interaction validation
- modal-first no longer skips render evidence when deciding final acceptance
- draft surfacing and final acceptance become two explicit states

### Workstream 4: Turn renderer contract failures into obligation failures

Goal:

- unify structural validation with witness validation

Implementation:

- make `renderer_primary_view_contract_failure(...)` feed typed failed
  obligations instead of only a contradiction string
- make `enforce_renderer_judge_contract(...)` consume those failed
  obligations

Primary files:

- `crates/api/src/studio/payload.rs`

Deliverables:

- renderer contract checks produce structured failures
- judge downgrade becomes deterministic from obligation failures
- repair receives typed failures instead of loose prose only

### Workstream 5: Make repair attempt inputs witness-driven

Goal:

- ensure repair targets the real broken behavior

Implementation:

- extend repair prompt payloads with failed obligation bundles and witness data
- distinguish:
  - parse/shape repair
  - behavior repair
  - presentation polish
- only count a repair as successful if one or more previously failed
  obligations clear on the next attempt

Primary files:

- `crates/api/src/studio/generation/runtime_materialization.rs`
- `crates/api/src/studio/generation/materialization_prompt.rs`
- `crates/api/src/studio/generation/non_swarm_bundle.rs`

Deliverables:

- witness-driven repair payloads
- obligation delta tracking between attempts
- repair success counted by cleared failures, not just by refinement lineage

### Workstream 6: Redefine surfaced repair/verification UX

Goal:

- make the UI truthful about what actually happened

Implementation:

- separate:
  - `repair_attempt_count`
  - `obligations_cleared_count`
  - `required_obligations_failed_count`
- surface execution-grounded verification steps such as:
  - `Boot artifact`
  - `Exercise controls`
  - `Verify state changes`
  - `Repair broken interactions`

Primary files:

- `apps/autopilot/src-tauri/src/kernel/studio/task_state.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/pipeline.rs`
- `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts`

Deliverables:

- UI no longer implies that a repair pass means success
- operator rail can show "repair attempted but 3 obligations still failing"
- receipts can show exactly which obligations cleared or remained blocked

### Workstream 7: Remove heuristic normalization as an acceptance substitute

Goal:

- keep recovery helpers optional, not authoritative

Implementation:

- keep payload synthesis/repair only for salvage and parsing
- do not let normalization stand in for acceptance proof
- review and reduce soft-validation downgrades that mask broken interactions
- revisit minimum-interaction injection so it cannot be confused with a real
  interaction pass

Primary files:

- `crates/api/src/studio/payload.rs`
- `crates/api/src/studio/tests.rs`

Deliverables:

- normalization remains a parser/recovery tool
- acceptance truth must still come from obligations + witnesses
- reduced reliance on injected interaction shims as proof of quality

## Renderer strategy

This plan should stay generic by using renderer adapters, not artifact-specific
heuristics.

### Shared framework

Every renderer should implement:

- obligation synthesis
- witness execution when applicable
- deterministic hard-failure rules
- repair payload shaping from failed obligations

### HTML / JSX adapter

Use:

- DOM boot success
- console/runtime error capture
- actionable control discovery
- interaction execution and DOM-state witness capture

### SVG adapter

Use:

- parse success
- render success
- visible mark density
- labeling/accessibility presence

### PDF / Markdown / Mermaid / download bundle

Use:

- source completeness
- structural validity
- required content presence
- renderer/output materialization success

Not every renderer needs dynamic interaction execution, but every renderer does
need typed obligations and hard acceptance truth.

## Rollout phases

### Phase 1: Truthful failure reporting

Ship first:

- obligation schema
- witness report schema
- UI wording that distinguishes repair attempts from cleared obligations

Success condition:

- Studio can say exactly why a candidate is still broken

### Phase 2: HTML/JSX execution witnesses

Ship next:

- boot/error witnesses
- control discovery
- click/focus/change witness execution
- state-delta verification

Success condition:

- broken onclick handlers and no-op controls fail acceptance deterministically

### Phase 3: Witness-driven repair

Ship next:

- repair prompt payloads derived from failed obligations
- obligation delta tracking between attempts

Success condition:

- repair attempts target concrete failed behavior and can be measured

### Phase 4: Full acceptance merger

Ship last:

- final acceptance requires cleared hard obligations
- model judge becomes advisory for ranking and explanation, not a veto override

Success condition:

- Studio does not surface a broken interactive artifact as accepted

## Test plan

### Unit tests

Add tests for:

- unresolved inline handler references
- buttons present but no meaningful state change
- controls wired to missing targets
- click interactions that only log or mutate invisible state
- artifacts with required interactions but unwitnessed behavior
- modal-first HTML still requiring final witness clearance

Primary files:

- `crates/api/src/studio/tests.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/tests.rs`

### Integration tests

Add fixtures where:

- the first candidate looks plausible but has undefined handlers
- the repair pass fixes the handlers and clears the witness obligations
- the artifact remains blocked if some controls still fail

Key assertion pattern:

- `repair_attempts > 0` must not imply `accepted == true`
- `accepted == true` requires `failed_required_obligations == 0`

### Regression corpus

Create a compact corpus of renderer-shaped failures:

- truncated HTML
- inert button bars
- undefined handlers
- missing panel targets
- one working control and several dead ones
- runtime exception during initial boot

The goal is not to curate domain examples forever. The goal is to lock in the
generic failure classes that the witness framework must catch.

## Success metrics

We should consider this plan successful when:

- a broken interactive artifact cannot clear acceptance just by containing
  buttons or handler strings
- "repair pass" in UI is no longer conflated with "artifact fixed"
- modal-first HTML can still stream early drafts without weakening final
  acceptance truth
- witness failures are reusable across many artifact domains without adding
  bespoke heuristics
- repaired artifacts are accepted because previously failed obligations were
  cleared, not because the model sounded more confident

## Non-goals

This plan is not trying to:

- encode domain-specific rules for every kind of explainer, dashboard, or app
- require pixel-perfect end-to-end UI tests for every artifact
- replace model judgment entirely

The goal is narrower and stronger:

- make acceptance and repair execution-grounded
- keep the framework renderer-shaped and generic
- stop broken interactions from slipping through as "verified"
