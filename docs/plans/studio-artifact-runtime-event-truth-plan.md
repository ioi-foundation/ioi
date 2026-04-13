# Studio Artifact Runtime Event Truth Plan

Last updated: 2026-04-12
Owner: Studio / Spotlight / artifact runtime / execution fabric
Status: proposed

Companion documents:

- `docs/plans/studio-claude-artifact-parity-plan.md`
- `docs/plans/studio-prepared-context-contract-plan.md`
- `docs/plans/studio-route-first-decompose-second-plan.md`
- `docs/plans/autopilot-desktop-ux-visibility-scratchboard.md`

## Purpose

This plan takes the April 12 artifact UX/runtime discussion to its actual end
state:

- one truthful runtime event source
- one incremental user-facing thinking rail
- no heuristic or fallback inference in the main artifact lane
- no drift between narration, streaming previews, and the actual queried outcome

The goal is not to maintain two different stories:

- one "real" harness story
- one "narrated" UI story

The goal is to keep one runtime truth and render two projections from it:

1. a compact operator-facing timeline
2. a deeper contract/receipts inspector

## Core doctrine

The governing rule for this plan is:

> Visible artifact thinking must be a projection of actual committed runtime
> events, not a predeclared queue and not a UI-only interpretation layer.

That implies five constraints:

- Every visible step must correspond to a real runtime event.
- Steps appear incrementally when they happen.
- Stream previews stay attached to the attempt that produced them.
- Route, skill, brief, author, verify, replan, and present remain typed backend
  events, not text-only UI heuristics.
- The query outcome is not considered successful until the requested artifact
  surface is actually materialized or a typed failure is emitted.

## Current repo reality

### 1. The main rail is event-shaped, but not event-truthful enough

Studio already renders the artifact lane from `runtimeNarrationEvents` in:

- `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts`

But the current projection collapses the stream to the latest event per
`stepId`, which destroys attempt history and makes replans look contradictory.

Relevant seam:

- `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts:132`

### 2. Stream previews come from a different channel than the visible step rail

Live preview rendering currently depends on `executionEnvelope.livePreviews`,
worker receipts, and change receipts in:

- `apps/autopilot/src/windows/SpotlightWindow/components/studioExecutionChrome.ts`
- `apps/autopilot/src/windows/SpotlightWindow/components/studioExecutionPreview.ts`

That means the visible stream is not owned by the same append-only timeline as
the step rail, so replans and envelope swaps can visually sever stream
continuity.

Relevant seams:

- `apps/autopilot/src/windows/SpotlightWindow/components/studioExecutionChrome.ts:65`
- `apps/autopilot/src/windows/SpotlightWindow/components/studioExecutionPreview.ts:74`

### 3. Step labels are backend copy, not display vocabulary

The current labels shown in the artifact rail come directly from event titles
created in backend progress emitters.

Relevant seams:

- `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs:72`
- `apps/autopilot/src-tauri/src/kernel/studio/skills.rs:303`
- `apps/autopilot/src-tauri/src/kernel/studio/materialization.rs:99`

This is why the rail currently reads like:

- `The user wants Create an interactive HTML artifact...`
- `Decide whether to read skill guidance`
- `Replan artifact execution`

instead of a tighter operator vocabulary.

### 4. The skill decision model still collapses two distinct truths

Artifact preparation always derives `skill_needs` for relevant renderers in:

- `crates/api/src/studio/planning.rs:2333`

Artifact skill selection then searches the runtime skill corpus plus published
skill records in:

- `apps/autopilot/src-tauri/src/kernel/studio/skills.rs:649`

But the final `should_read_skill` flag is currently derived as
`!selected_skills.is_empty()` in:

- `crates/api/src/studio/generation/planning_and_judging.rs:158`

That collapses:

- "guidance was needed but none was found"
- "guidance was not needed"

into one visible result.

### 5. Studio and local Codex skills are not the same capability universe

The Studio artifact pipeline searches the runtime skill corpus and public skill
records. It does not currently search the local Codex `SKILL.md` directory that
this shell session can use directly.

That means a request can reasonably need frontend guidance while still showing
"no skill attached" in Studio if the runtime corpus does not return a qualifying
published skill.

Relevant seam:

- `apps/autopilot/src-tauri/src/kernel/studio/skills.rs:649`

### 6. The rail has no per-step icon model

The process list currently renders every step as plain text rows with status and
no event-type iconography.

Relevant seam:

- `apps/autopilot/src/windows/SpotlightWindow/components/StudioConversationPanels.tsx:264`

## Desired end state

For an ask like `Create an interactive HTML artifact that explains quantum
computers`, Studio should behave like this:

1. Route to artifact and publish that decision.
2. Append `Understand request`.
3. Append `Check for guidance`.
4. If guidance is needed and found, append `Read frontend guidance`.
5. If guidance is needed and not found, append `Guidance unavailable` with a
   truthful reason.
6. Append `Shape artifact brief`.
7. Append `Write artifact` and keep stream previews attached to that attempt.
8. If execution changes, append `Switch execution strategy` as a new event, then
   append a new `Write artifact` attempt.
9. Append `Verify artifact`.
10. Append `Open artifact`.

The operator-facing rail should never show future queued work that has not
happened yet.

## Target architecture

### Layer 1: Runtime event log

Introduce one append-only runtime event log for artifact runs.

Suggested shape:

- `event_id`
- `attempt_id`
- `event_type`
- `status`
- `occurred_at`
- `summary`
- `detail`
- `preview_ref`
- `artifact_id`
- `strategy`
- `metadata`

Normative rule:

- Events are appended when the runtime commits to a transition.
- Existing events are not overwritten in place.
- Status changes for the same conceptual step produce a new event instance, not
  a projection-time replacement.

### Layer 2: Preview stream log

Make stream previews event-attached, not envelope-attached.

That means:

- `author_artifact` events can own live preview snapshots
- replans start a new `attempt_id`
- prior preview content remains attributable to the attempt that produced it

The execution envelope can still carry live previews for deeper inspectors, but
the main operator rail should render from event-linked preview state.

### Layer 3: Contract/receipt projection

Keep the canonical execution contract, completion invariants, and receipts for:

- inspector surfaces
- verification
- auditability
- debugging

But demote them from the primary artifact thinking surface.

## Workstreams

### Workstream 1: Replace "latest by step id" with true append-only event instances

Goal:

- make the artifact rail incremental instead of queue-like

Implementation:

- add monotonic runtime event sequencing to the artifact session/materialization
  contract
- stop collapsing the visible rail to one row per `stepId`
- let repeated steps appear as separate attempts when they actually recur

Required changes:

- extend `StudioArtifactRuntimeNarrationEvent` or replace it with a richer
  runtime event type in:
  - `crates/api/src/studio/types.rs`
- update merge/persist logic in:
  - `apps/autopilot/src-tauri/src/kernel/studio.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/materialization.rs`
- replace the `latestByStep` projection in:
  - `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts`

Acceptance:

- a direct-author replan produces:
  - one author attempt
  - one strategy-switch event
  - one new author attempt
- the rail never shows future queued steps that did not happen

### Workstream 2: Unify visible thinking and live preview around one event source

Goal:

- stop losing or visually severing token streaming when execution state changes

Implementation:

- attach stream snapshots to the active runtime event or attempt
- treat direct-author output as part of the `author_artifact` event family
- keep the latest preview for the active attempt visible until superseded by a
  newer preview from the same or later attempt

Required changes:

- add event-linked preview metadata in:
  - `crates/api/src/studio/types.rs`
- emit preview snapshots from generation into the event/attempt model in:
  - `crates/api/src/studio/generation/runtime_materialization.rs`
  - `crates/api/src/studio/generation/non_swarm_bundle.rs`
- update Spotlight preview resolution so the main artifact card reads from the
  event timeline first and the execution envelope second:
  - `apps/autopilot/src/windows/SpotlightWindow/components/studioExecutionPreview.ts`
  - `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts`

Acceptance:

- a direct-author run that replans still shows the last good streaming preview
  from the first attempt until the second attempt emits new output
- the main rail never drops to an empty preview shell while a valid active
  preview still exists

### Workstream 3: Split skill semantics into need, discovery, and attachment

Goal:

- tell the truth about why a skill was or was not used

Implementation:

- replace the binary `should_read_skill` mental model with distinct fields such
  as:
  - `guidance_evaluated`
  - `guidance_recommended`
  - `guidance_found`
  - `guidance_attached`
  - `search_scope`
  - `failure_reason`
- make the operator rail show one of:
  - `Check for guidance`
  - `Read frontend guidance`
  - `Guidance unavailable`
  - `No extra guidance needed`

Required changes:

- revise skill discovery resolution types in:
  - `crates/api/src/studio/types.rs`
  - `crates/api/src/studio/generation/planning_and_judging.rs`
- update preparation emitters in:
  - `apps/autopilot/src-tauri/src/kernel/studio/skills.rs`
- remove projection-time or selection-count-based fallbacks around skill read
  inference in:
  - `apps/autopilot/src-tauri/src/kernel/studio/pipeline.rs`
  - `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts`

Acceptance:

- the rail can distinguish:
  - "guidance required and attached"
  - "guidance required but not found"
  - "guidance not needed"
- no UI branch infers a skill read just because `selected_skills` is non-empty
- no backend branch infers "no skill needed" merely because zero skills were
  returned

### Workstream 4: Make labels and icons frontend-owned display vocabulary

Goal:

- stop leaking backend phrasing directly into the main artifact rail

Implementation:

- backend emits stable event types and concise machine-facing summaries
- frontend maps event types to:
  - user-facing label
  - icon
  - optional status verb
  - compact explanatory copy

Suggested event label mapping:

- `understand_request` -> `Understand request`
- `artifact_route_committed` -> `Route to artifact`
- `skill_discovery` -> `Check for guidance`
- `skill_read` -> `Read guidance`
- `artifact_brief` -> `Shape artifact brief`
- `author_artifact` -> `Write artifact`
- `replan_execution` -> `Switch execution strategy`
- `verify_artifact` -> `Verify artifact`
- `present_artifact` -> `Open artifact`

Suggested icon families:

- compass / route
- sparkle / guidance
- file-text / brief
- code / author
- shuffle / strategy switch
- shield-check / verify
- panel-open / present

Required changes:

- add event-type to icon/label mapping in:
  - `apps/autopilot/src/windows/SpotlightWindow/components/StudioConversationPanels.tsx`
  - `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts`
- simplify backend event titles in:
  - `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/skills.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/materialization.rs`

Acceptance:

- the rail no longer includes prompt-echo titles like
  `The user wants Create an interactive HTML artifact...`
- each step row shows an appropriate icon without relying on generic status-only
  chrome

### Workstream 5: Make route commitment and queried-outcome completion explicit

Goal:

- ensure artifact route selection and artifact completion stay coupled

Implementation:

- emit a typed `artifact_route_committed` event once the route is locked
- track the active execution attempt separately from the queried outcome
- do not mark the artifact request as effectively complete until:
  - the requested artifact payload exists
  - verification state is coherent
  - the artifact surface is openable

Required changes:

- add route and outcome completion events in:
  - `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/content_session.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/materialization.rs`
- tighten blocked/ready projection logic in:
  - `apps/autopilot/src-tauri/src/kernel/studio/pipeline.rs`
  - `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts`

Acceptance:

- a run that routes to artifact but fails to materialize cannot look "pending but
  healthy"
- a run that replans and succeeds still produces the originally queried artifact
  outcome

### Workstream 6: Make skill discovery honest about search scope

Goal:

- explain why a relevant skill was not attached

Implementation:

- record which capability universe was searched:
  - runtime published skills
  - local workspace skills
  - plugin-backed guidance assets
  - none
- in the short term, at minimum report `search_scope` and `search_status`
- in the long term, optionally unify Studio capability search with local skill
  packages and plugin/MCP guidance assets

Required changes:

- extend skill discovery result metadata in:
  - `crates/api/src/studio/types.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/skills.rs`
- update operator-facing copy in:
  - `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts`
  - `apps/autopilot/src/windows/SpotlightWindow/components/StudioConversationPanels.tsx`

Acceptance:

- for a request that clearly wants design guidance, the UI can say either:
  - `Read frontend guidance`
  - `No published runtime guidance matched this request`
- the operator is not forced to infer whether the miss was due to routing or
  corpus coverage

## Sequencing

### Phase 1: Event truth foundation

- richer runtime event type
- append-only event persistence
- attempt ids
- route-commit event

### Phase 2: Preview continuity

- event-linked preview snapshots
- main rail reads preview from event timeline
- preserve preview across replans

### Phase 3: Skill truth

- split skill semantics
- remove residual `should_read_skill` fallbacks
- add search-scope visibility

### Phase 4: UX vocabulary

- frontend-owned labels
- per-step icons
- cleaner step copy

### Phase 5: Outcome integrity hardening

- query-outcome completion contract
- blocked/ready truth tightening
- end-to-end regression coverage

## Required test coverage

Add or update tests for:

- append-only narration preserves repeated `author_artifact` attempts
- replan emits `switch_execution_strategy` without mutating prior attempt rows
- stream preview continuity survives direct-author -> plan-execute replans
- skill discovery distinguishes:
  - no guidance needed
  - guidance needed but unavailable
  - guidance attached
- artifact route commitment without successful materialization yields typed
  blocked outcome
- successful replan still returns the originally queried artifact payload

Suggested seams:

- `apps/autopilot/src-tauri/src/kernel/studio/tests.rs`
- `crates/api/src/studio/tests.rs`

## Definition of done

This plan is complete when all of the following are true:

- The main artifact rail is incremental and append-only.
- The rail is generated from real runtime events, not queue projection.
- Stream previews remain visible and attributable across replans.
- Step labels and icons are intentional and frontend-owned.
- Skill visibility tells the truth about need, search, and attachment.
- The queried artifact outcome remains the primary contract, even when strategy
  changes mid-run.
- The execution contract still exists, but it becomes secondary evidence rather
  than the primary user-facing story.
