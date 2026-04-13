# Studio Claude Artifact Parity Plan

Last updated: 2026-04-11
Owner: Studio / Spotlight / artifact runtime / capability registry
Status: proposed

Companion documents:

- `docs/plans/studio-route-first-decompose-second-plan.md`
- `docs/plans/autopilot-canvas-runtime-unification-plan.md`
- `docs/plans/autopilot-desktop-ux-visibility-scratchboard.md`

## Purpose

This plan closes the parity gap highlighted by the April 11 comparison between
Claude's artifact flow and Autopilot Studio for single-file artifact requests.

Two gaps matter most:

1. thinking UX
2. skill-before-authoring runtime behavior

The target is not visual mimicry for its own sake. The target is the same user
truth:

- the operator can see what the system is doing in the main lane
- the system explicitly shows when it read a relevant skill before authoring
- the artifact surface opens early and stays attached while authoring happens
- raw receipts remain available, but they stop being the primary storytelling
  layer for ordinary artifact runs

## Current repo reality

### 1. Direct-author is the default fast lane for many artifact asks

`crates/api/src/execution.rs` currently routes fresh single-file artifact asks
such as `html_iframe`, `markdown`, `svg`, `mermaid`, and `pdf_embed` into
`DirectAuthor` by default.

Relevant seams:

- `crates/api/src/execution.rs:503`
- `crates/api/src/execution.rs:1426`

### 2. Direct-author skips planning context and skill selection entirely

Studio currently bypasses planning context for `DirectAuthor` in both the
prepare path and the materialization path.

Relevant seams:

- `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs:518`
- `apps/autopilot/src-tauri/src/kernel/studio/materialization.rs:107`

When no planning context exists, non-swarm generation synthesizes a minimal
direct-author context with:

- no blueprint
- no artifact IR
- no selected skills
- no exemplars

Relevant seam:

- `crates/api/src/studio/generation/non_swarm_bundle.rs:35`

The current test suite explicitly encodes this behavior.

Relevant seam:

- `crates/api/src/studio/tests.rs:423`

### 3. Standard materialization uses selected skill guidance, direct-author does not

The normal materialization prompt includes selected skill guidance.

Relevant seam:

- `crates/api/src/studio/generation/materialization_prompt.rs:150`

The direct-author prompt path does not accept or serialize selected skills at
all.

Relevant seam:

- `crates/api/src/studio/generation/materialization_prompt.rs:215`

### 4. The frontend already has richer prep data, but live runs hide it

The live Studio lane currently suppresses `ExecutionRouteCard` while the run is
active and falls back to:

- a generic pending bubble
- a generic thinking pill
- generic stage copy such as `Building the artifact surface`

Relevant seams:

- `apps/autopilot/src/windows/SpotlightWindow/components/ConversationTimeline.tsx:175`
- `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.ts:323`
- `apps/autopilot/src/windows/SpotlightWindow/components/StudioArtifactSurface.tsx:127`

At the same time, `ExecutionRouteCard` can already render prepared context and
selected skills when it is allowed to show.

Relevant seam:

- `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx:307`

## Parity bar

For a request like `Create an interactive HTML artifact that explains quantum
computers`, Studio should behave like this:

1. Show a task-specific orchestration title in the main lane.
2. Show a short live step list rather than a generic pending bubble.
3. Explicitly show the skill read before authoring starts.
4. Allow the operator to open the selected skill details inline or beside the
   artifact.
5. Open the artifact surface early and keep it attached during generation.
6. Show code or file previews as part of the same thought flow.
7. Keep receipts and raw traces as secondary evidence, not the main narrative.

## Workstreams

### Workstream 1: Make skill resolution mandatory before artifact authoring

Goal:

- every artifact run, including `DirectAuthor`, gets a pre-author context pass

Implementation:

- split artifact execution into:
  - route
  - prepare context
  - author
  - verify
  - present
- always resolve a planning context for artifact runs before generation starts
- allow the direct-author branch to use a lightweight planning context instead
  of a zero-context bypass
- preserve `DirectAuthor` as an authoring mode, not as a context-skip mode

Required changes:

- remove the `DirectAuthor -> None` planning-context bypass in:
  - `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/materialization.rs`
- replace the synthetic empty direct-author planning context in:
  - `crates/api/src/studio/generation/non_swarm_bundle.rs`
- decide the minimum prep contract that all artifact runs must have:
  - brief
  - lightweight blueprint or scaffold family
  - skill needs
  - selected skills
  - optional exemplars

Acceptance:

- a direct-author HTML run retains non-empty `selected_skills` when a matching
  design skill exists
- the active Studio session snapshot shows selected skills before the first
  authored file lands

### Workstream 2: Feed selected skills into direct-author prompts

Goal:

- the fast path should use the same skill spine as the planned path

Implementation:

- extend the direct-author prompt builder to accept:
  - selected skills
  - optional blueprint focus
  - optional artifact IR focus
- add compact local-runtime serialization so the prompt stays small but still
  carries the selected skill spine
- include the skill name and its highest-value guidance in the direct-author
  prompt rather than only the raw user request

Required changes:

- extend:
  - `build_studio_artifact_direct_author_prompt_for_runtime`
  - `build_studio_artifact_direct_author_continuation_prompt_for_runtime`
- thread selected-skill context through the direct-author call sites in
  `non_swarm_bundle.rs`

Acceptance:

- direct-author prompt logs contain selected skill guidance when a skill was
  resolved
- the direct-author prompt remains raw-request-first, but no longer operates as
  if no skill existed

### Workstream 3: Replace generic pending chrome with a typed live thought timeline

Goal:

- the main Studio conversation lane should tell the same story Claude tells:
  not raw receipts, but a compact step-by-step run narrative

Implementation:

- introduce a first-class `StudioThinkingStep` or equivalent view model derived
  from session materialization state, not from generic receipt heuristics
- render the live run as a compact ordered list in the conversation lane
- each step should carry:
  - label
  - status
  - optional detail
  - optional file preview/code preview
  - optional skill reference

Suggested default artifact steps:

1. Understand the request
2. Prepare artifact brief
3. Read selected skill
4. Author artifact
5. Verify artifact
6. Present artifact

Required changes:

- replace the generic live pending bubble path in
  `ConversationTimeline.tsx`
- stop suppressing the richer route/prep story just because the run is active
- derive task-specific titles instead of generic surface copy in
  `useSpotlightSurfaceState.ts`

Acceptance:

- live artifact runs do not read as `Thinking` plus `Building the artifact surface`
- the main lane shows a step list with at least one skill-aware step when a
  skill exists

### Workstream 4: Add an explicit skill-read affordance in the live artifact lane

Goal:

- when Studio says it read a skill, the operator can inspect that skill without
  leaving the run

Implementation:

- expose the selected skill as a clickable step in the live thought timeline
- open the existing skill detail surface in a side rail, split panel, or
  attached inspector
- reuse the current capability-registry and skill-detail machinery instead of
  inventing a second skill viewer

Required changes:

- reuse skill-detail resolution already present in:
  - `StudioArtifactEvidencePanel.tsx`
  - `useSpotlightCapabilityRegistry`
- add a live-run surface entry point from the main lane

Acceptance:

- during the run, the operator can open the exact selected skill that Studio
  claims it is using
- the skill detail opens beside the artifact without breaking the main run

### Workstream 5: Keep receipts as evidence, not primary narration

Goal:

- raw receipts should remain truthful and inspectable without becoming the main
  UX for ordinary artifact generation

Implementation:

- keep `ExecutionRouteCard`, evidence drawer, and artifact evidence views for:
  - raw receipts
  - judge output
  - worker details
  - merge and repair details
- move the main story to typed live-thinking steps
- only show raw streaming code blocks inline when they support the current
  authoring step

Acceptance:

- ordinary artifact runs can be followed without opening the evidence drawer
- evidence drawer still exposes the same raw receipts and trace depth as today

## Rollout sequence

### Phase 1: Runtime parity

- implement mandatory pre-author context for all artifact runs
- feed selected skills into direct-author prompts
- update tests that currently assert `selected_skills.is_empty()` for the
  direct-author path

Exit bar:

- backend state and prompt logs prove that direct-author runs are skill-aware

### Phase 2: Live thinking parity

- ship typed live-thinking steps in the conversation lane
- remove generic pending bubble ownership for active artifact runs
- keep the artifact surface attached from the start of artifact materialization

Exit bar:

- the quantum-computers artifact flow reads like a real staged run in the main
  lane

### Phase 3: Skill inspector parity

- add click-through from the skill-read step to the skill detail pane
- support side-by-side skill and artifact viewing

Exit bar:

- the operator can inspect the selected skill during the run without leaving the
  Studio surface

### Phase 4: Native screenshot proof

- capture fresh native proof in the same scenario family as the comparison
  screenshots
- use the existing UX visibility scratchboard discipline

Exit bar:

- native screenshots show:
  - explicit live thought steps
  - explicit skill-read step
  - attached artifact surface
  - no generic receipt wall as the primary run narrative

## Acceptance criteria

Studio reaches parity for this gap when all of the following are true:

- a direct-author HTML artifact run resolves and stores selected skills before
  authoring
- the direct-author prompt includes selected skill guidance
- the live conversation lane shows a task-specific thought timeline rather than
  only generic pending chrome
- the live timeline explicitly shows the skill-read step when a matching skill
  exists
- the operator can open the selected skill details inline or beside the artifact
- the artifact surface opens early and remains attached during the run
- receipts remain available in evidence views, but they are no longer the
  default storytelling layer for standard artifact generation

## Non-goals

- do not collapse all artifact work into swarm just to gain more visible steps
- do not remove receipts, pipeline steps, or artifact evidence panels
- do not make Studio visually identical to Claude if the same operator truth can
  be achieved with Autopilot-native chrome
- do not regress the route-first execution work already underway
