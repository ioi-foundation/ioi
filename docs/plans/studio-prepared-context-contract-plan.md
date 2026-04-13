# Studio Prepared-Context Contract Plan

Last updated: 2026-04-11
Owner: Studio / execution fabric / capability registry / artifact runtime
Status: proposed

Companion documents:

- `docs/specs/CIRC.md`
- `docs/specs/CEC.md`
- `docs/plans/studio-claude-artifact-parity-plan.md`
- `docs/plans/studio-route-first-decompose-second-plan.md`

## Purpose

This plan defines the long-term architecture for artifact skill usage and
pre-authoring context in Studio.

The governing goal is:

- discover artifact needs naturally from typed request semantics
- enforce prepared context explicitly before authoring begins

That is the CIRC/CEC-aligned answer to the current tension between "hardcoded
skill wiring" and "let the model figure it out at authoring time."

The target system should not hardcode which skills to use, and it should not
leave skill retrieval to prompt-time improvisation. Instead, it should:

1. normalize the request into typed artifact needs
2. resolve brief, structure, exemplars, and skill context from those needs
3. emit receipt-backed prepared context
4. allow authoring only after that contract is satisfied

## Core doctrine

The core rule for this plan is:

> Skill discovery should be dynamic. Prepared-context resolution should be
> mandatory.

That implies four non-negotiable boundaries:

- CIRC remains responsible for intent resolution and typed artifact-shape
  normalization.
- Prepared-context synthesis becomes an explicit pre-authoring contract phase.
- Authoring modes such as `DirectAuthor` remain execution strategies, not
  exemptions from context resolution.
- CEC governs the authoring, verification, and completion phases only after
  prepared context is resolved or explicitly failed.

## Why the current shape is still wrong

The repo is closer to the right behavior than it was before parity work, but
the architecture is still not in its final form.

### What is already right

- Skill selection is already dynamic in
  `apps/autopilot/src-tauri/src/kernel/studio/skills.rs`.
- The planning context already contains the right family of inputs:
  `brief`, `blueprint`, `artifact_ir`, `selected_skills`, and
  `retrieved_exemplars`.
- The runtime and UI can already carry selected skills through authoring and
  render them to the operator.

### What is still wrong

- Prepared context is still treated as workflow wiring rather than a
  first-class execution contract.
- Generation entrypoints still accept `Option<StudioArtifactPlanningContext>`,
  which means the execution surface still models "missing planning context" as
  a valid state.
- Some paths still synthesize minimal fallback context inside generation rather
  than treating missing prepared context as a discovery/synthesis failure.
- The code still reads as if direct authoring happens first and planning
  context is an optional enhancement, rather than authoring being downstream of
  context resolution.

### Why that is wrong

- It weakens CIRC by allowing execution-path concerns to decide whether typed
  preparation happens.
- It weakens CEC by treating discovery and synthesis as optional for a class of
  artifact runs.
- It makes continuation, repair, and future authoring modes vulnerable to
  context drift.
- It prevents the runtime from having a clean receipt-backed invariant such as
  "prepared context resolved before authoring."

## Desired end state

The final system should behave like this for every artifact run:

1. Resolve intent and artifact outcome shape.
2. Derive typed artifact needs from the normalized request.
3. Run prepared-context synthesis once for the run or revision.
4. Produce one explicit prepared-context object and one receipt-backed
   resolution record.
5. Hand that prepared context into whichever authoring strategy is selected.
6. Reuse the same prepared context across initial authoring, continuation,
   repair, and revision unless the request semantics materially change.
7. Fail with a typed discovery/synthesis error if prepared context cannot be
   justified, rather than silently authoring without it.

## Target architecture

### Phase layout

The artifact pipeline should be expressed as five phases:

1. `intent_and_outcome_resolution`
2. `prepared_context_synthesis`
3. `execution_mode_selection`
4. `authoring_and_verification`
5. `presentation_and_completion`

The important change is that `prepared_context_synthesis` is no longer a helper
inside specific workflows. It becomes a required contract phase between CIRC
and authoring.

### Phase 1: Intent and outcome resolution

This phase stays under CIRC discipline.

Inputs:

- user request
- refinement context when present
- active capabilities, renderer constraints, and runtime policy

Outputs:

- normalized artifact request
- typed artifact intent and renderer family
- typed authoring obligations
- typed preparation requirements

This phase must not emit hardcoded skill names, skill file paths, or model-time
instructions. It should emit typed needs only.

### Phase 2: Prepared-context synthesis

This phase is the new contract boundary.

It should consume typed artifact needs and produce a required
`PreparedArtifactContext`-style object. This can evolve from the current
`StudioArtifactPlanningContext`, but it should no longer be optional at the
authoring boundary.

Minimum fields:

- normalized request summary
- `brief`
- optional `blueprint`
- optional `artifact_ir`
- `skill_needs`
- resolved `selected_skills`
- optional `retrieved_exemplars`
- provenance and policy metadata
- `resolution_receipt`

Normative rules:

- discovery decides whether zero, one, or multiple skills are relevant
- workflow code must not decide whether discovery runs
- authoring must not be allowed to begin without a resolved prepared-context
  object or an explicit typed failure
- zero selected skills is valid
- skipped discovery is not valid

### Phase 3: Execution mode selection

Execution-mode selection should happen after prepared context is known.

That keeps mode choice honest:

- `DirectAuthor` means one bounded authoring unit
- `PlanExecute` means one structured synthesis unit
- `MicroSwarm` or `AdaptiveWorkGraph` mean decomposition is justified

It must not mean:

- no prepared context
- no skill discovery
- no pre-authoring brief

### Phase 4: Authoring and verification

All authoring paths should consume the same prepared-context contract:

- initial authoring
- continuation
- repair
- refinement
- swarm worker prompts where applicable

The model should receive prepared context explicitly. It should not be expected
to rediscover skills or restage artifact preparation during authoring.

If authoring determines the prepared context is insufficient, that should
surface as a typed contract violation or refinement request, not as silent
prompt drift.

### Phase 5: Presentation and completion

UI and receipts should project the same truth:

- prepared context was synthesized
- these skill needs were evaluated
- these skills were selected
- authoring began after that work completed

Receipts remain the source of truth. The thinking lane is the user-facing
projection of those typed phases.

## Contract changes

### 1. Replace optional planning context at authoring boundaries

The generation API should stop treating planning context as optional for
artifact authoring entrypoints.

Current shape:

- `Option<StudioArtifactPlanningContext>`

Target shape:

- `StudioArtifactPreparedContext`

Migration note:

- the current type can be renamed, wrapped, or split, but the important change
  is contractual, not cosmetic
- the authoring boundary must stop admitting `None`

### 2. Split typed needs from resolved context

The pipeline should distinguish:

- `ArtifactPreparationNeeds`
- `ArtifactPreparedContext`

`ArtifactPreparationNeeds` is the typed output of resolution.

`ArtifactPreparedContext` is the typed output of discovery and synthesis.

That separation prevents the current blur where "planning context" means both
"things we think we need" and "the actual resolved payload."

### 3. Add prepared-context receipts

Prepared context should emit a first-class typed receipt, for example:

- `prepared_context_resolved`

Suggested fields:

- request hash
- renderer
- execution mode
- skill need summary
- selected skill ids
- exemplar count
- blueprint presence
- artifact IR presence
- provenance
- evidence commit hash

This receipt is what CEC-style completion and UI projection should read from.

### 4. Treat missing prepared context as a typed failure

If prepared context cannot be synthesized, the run should fail with a typed
error such as:

- `ERROR_CLASS=PreparedContextMissing`
- or a specialized `DiscoveryMissing` / `SynthesisFailed` variant

What should not happen:

- silently building a minimal empty context in generation code
- silently dropping selected skills during continuation or repair
- letting authoring proceed because the fast lane "probably knows what to do"

## Dynamic skill discovery rules

### What should be dynamic

The following should be discovered from typed artifact needs:

- whether any skill is needed
- which skill families are relevant
- how many skills to include
- whether exemplars are worth retrieving
- whether blueprint or artifact IR depth is needed

### What should not be dynamic

The following should not be left to authoring-time model judgment:

- whether prepared-context discovery runs at all
- whether the selected-skill set persists into continuation or repair
- whether the UI may claim a skill was used
- whether a run is allowed to skip the pre-authoring gate

## Future-facing extension: capability packages, not just local skills

The current plan is intentionally skill-centered because that is the immediate
gap, but the longer-term design should generalize beyond local `SKILL.md`
documents.

The better abstraction is:

- discover context and capability assets needed for the run
- admit them through policy and provenance
- materialize them into prepared context before authoring

That lets the system support more than one asset shape:

- local skill docs
- packaged skills from a catalog or market
- plugins that ship skill docs plus templates or scripts
- MCP-backed plugins that expose tools and also ship guidance
- connector-backed capability packages that provide both instructions and
  runtime affordances

### Proposed vocabulary upgrade

Over time, the runtime should distinguish at least three related concepts:

- `GuidanceAsset`
- `ToolingAsset`
- `CapabilityPackage`

Suggested meanings:

- `GuidanceAsset`: a human/model-facing instruction package such as a local
  skill doc, generated skill doc, exemplar pack, or design playbook
- `ToolingAsset`: a runtime surface such as an MCP server, plugin tool bundle,
  connector route, or script/template pack
- `CapabilityPackage`: an installable or registry-backed unit that may contain
  both guidance and tooling

In that world, today's `selected_skills` becomes a compatibility subset of a
broader concept such as:

- `selected_guidance_assets`
- `selected_tooling_assets`
- `selected_capability_packages`

The plan does not need to rename everything immediately, but it should leave
room for that migration.

### Why this is a better target end state

This avoids creating three parallel systems:

- skills for prompt guidance
- plugins for runtime tools
- MCP packages for external capability

Instead, all three become discovery-backed assets participating in one
prepared-context contract.

That is especially important for future workflows like:

- discovering a missing frontend-design package that contains both a design
  skill and an MCP-backed component library tool
- installing a data-viz package that provides chart templates, exemplar files,
  and a render-validation MCP
- resolving a connector-backed research package that includes both retrieval
  tools and guidance on how to use them well

### Proposed pre-authoring asset pipeline

The prepared-context phase can grow into four subphases:

1. `preparation_needs_inference`
2. `asset_candidate_discovery`
3. `asset_admission_and_optional_install`
4. `prepared_context_assembly`

#### 1. `preparation_needs_inference`

Infer typed needs such as:

- design guidance needed
- domain exemplar pack useful
- special runtime tool surface required
- verification helper package useful

This stays query-agnostic in structure and CIRC-aligned.

#### 2. `asset_candidate_discovery`

Search candidate assets from:

- local installed skills
- local plugins
- registered MCP packages
- connector registries
- optional market or package catalogs

This should return typed candidates, not ad hoc prompt text.

#### 3. `asset_admission_and_optional_install`

If the best candidate is not already installed, the runtime may:

- install automatically when policy allows
- prefetch in the background
- pause for approval when permissions or trust posture require it
- fail closed when installation is required but not allowed

This should be policy-driven and receipt-backed.

Important rule:

- authoring should not opportunistically install packages on its own
- installation belongs to the prepared-context phase, not the model's
  improvisation loop

#### 4. `prepared_context_assembly`

Assemble the final authoring input from admitted assets:

- selected guidance snippets
- selected tool namespaces
- templates, scripts, or exemplars
- package provenance and version pins

The authoring model receives the assembled context, not the burden of discovery.

### Capability-package manifest direction

Longer term, the repo could benefit from a unified manifest shape that can map
cleanly onto the existing market and tool vocabulary.

A capability package should be able to declare:

- package id and version
- provenance and trust class
- semantic tags and typed applicability
- provided guidance assets
- provided tool namespaces or MCP endpoints
- required permissions
- install strategy
- compatibility constraints
- verification hooks

This fits naturally with the existing registry and market direction in
`crates/types/src/app/agentic/market.rs` and the existing dynamic tool escape
hatch in `crates/types/src/app/agentic/tools/agent_tool.rs`.

### Installation policy and trust posture

If the system ever supports automatic discovery and installation, the plan
should include hard boundaries:

- no silent network installs without policy support
- package provenance must be explicit
- versions must be pinned into receipts
- installed tooling must advertise required capabilities before activation
- prepared context must record whether an asset was already present, newly
  installed, or rejected

Suggested receipts:

- `capability_asset_discovered`
- `capability_asset_admitted`
- `capability_asset_installed`
- `guidance_asset_selected`
- `tooling_asset_activated`

### UI implications for installable assets

This future-oriented shape gives the thinking lane a much richer and still
truthful story:

1. Understand request
2. Prepare artifact brief
3. Discover capability assets
4. Install approved package
5. Read selected guidance
6. Activate tool surface
7. Author artifact
8. Verify output

That is a better long-term UX than pretending everything is either "the model
thought harder" or "a skill was read."

### CIRC alignment

This keeps query interpretation clean:

- no query-conditioned hardcoded skill branches
- no artifact-class shortcut saying "HTML always read frontend skill"
- no model-family-specific workflow branch deciding whether discovery happens

Instead:

- typed artifact needs are inferred first
- skill candidates are admitted through registry-backed discovery
- selected skills become resolved context, not routing heuristics

### CEC alignment

This keeps execution disciplined:

- discovery and context assembly happen before authoring
- authoring is a deterministic downstream consumer of prepared context
- verification and completion can rely on typed prepared-context receipts
- failure to resolve required context terminates early instead of causing a
  hidden execution shortcut

## UI and observability implications

The UI should reflect the contract, not reverse-engineer it.

The main Studio thinking lane should project steps like:

1. Understand request
2. Prepare artifact brief
3. Evaluate skill needs
4. Read selected skills
5. Author artifact
6. Verify output
7. Present artifact

Important rule:

- these steps should be derived from typed runtime state and receipts
- they should not be inferred from generic pending strings or prompt-only hints

That lets the UI truthfully show:

- zero-skill runs
- one-skill direct-author runs
- multi-skill structured runs
- repair and revision runs that reuse or refresh prepared context

## Migration plan

### Phase 0: Codify the contract

Goal:

- make the intended invariant explicit in code and docs

Changes:

- add a dedicated prepared-context contract doc and wire-level comments
- identify every authoring entrypoint that still admits optional planning
  context
- define the typed failure shape for missing prepared context

Acceptance:

- there is one canonical statement in the repo that authoring cannot begin
  without resolved prepared context

### Phase 1: Separate needs from context

Goal:

- stop overloading `StudioArtifactPlanningContext`

Changes:

- introduce a typed `ArtifactPreparationNeeds` object
- evolve or replace `StudioArtifactPlanningContext` with
  `StudioArtifactPreparedContext`
- make the boundary between "needs inferred" and "context resolved" explicit

Acceptance:

- resolution code produces typed preparation needs before discovery
- discovery code produces a prepared-context object rather than mutating a
  maybe-context in place

### Phase 2: Make prepared context mandatory at authoring boundaries

Goal:

- remove `Option<...>` from authoring entrypoints

Changes:

- update non-swarm generation entrypoints
- update direct-author, continuation, and repair entrypoints
- update refinement and revision reuse paths
- remove internal synthetic empty-context fallback logic

Acceptance:

- authoring APIs cannot be called without prepared context
- direct-author remains available but cannot bypass prepared-context synthesis

### Phase 3: Add receipt-backed prepared-context resolution

Goal:

- make the contract observable and judgeable

Changes:

- emit a typed `prepared_context_resolved` receipt
- carry that receipt through session state, receipts, and revision metadata
- use the receipt to drive thinking-lane projection

Acceptance:

- session snapshots show whether prepared context resolved and what it resolved
- completion and audit surfaces can point to typed evidence instead of freeform
  strings

### Phase 4: Unify reuse semantics across authoring flows

Goal:

- eliminate context drift between initial authoring and follow-up passes

Changes:

- define when a revision reuses prepared context versus invalidates and refreshes
  it
- thread the same prepared context object through continuation, repair, and
  refinement
- make invalidation reasons explicit when a refresh is required

Acceptance:

- selected skills do not disappear between initial generation and repair unless
  the request semantics changed and a refresh receipt explains why

### Phase 5: Add conformance coverage

Goal:

- make the contract hard to regress

Changes:

- add tests that prove every artifact strategy resolves prepared context first
- add tests for zero-skill valid runs versus skipped-discovery invalid runs
- add tests for repair and continuation preserving prepared context
- add tests ensuring model-family or prompt-budget branches do not control
  whether discovery runs

Acceptance:

- regressions require consciously breaking conformance tests rather than
  slipping in through workflow shortcuts

## Success criteria

This plan is complete when all of the following are true:

- skill discovery is driven by typed artifact needs, not by hardcoded workflow
  branches
- prepared-context synthesis is a required contract phase before authoring
- authoring entrypoints no longer accept missing prepared context
- zero-skill runs are supported without pretending discovery never happened
- continuation, repair, and revision reuse the same prepared context unless
  explicit invalidation occurs
- the UI can truthfully say which preparation steps happened because the
  runtime emitted receipts for them
- direct authoring means "single bounded authoring unit," not "skip
  preparation"

## Non-goals

This plan does not require:

- forcing a skill onto every artifact run
- replacing lightweight direct authoring with heavy planning for all runs
- moving skill choice into prompt-only agent judgment
- making the UI mimic another product's visuals exactly

## Immediate next moves

The best follow-on implementation sequence is:

1. introduce typed `ArtifactPreparationNeeds`
2. introduce or rename `StudioArtifactPreparedContext`
3. remove optional prepared-context authoring entrypoints
4. add `prepared_context_resolved` receipts
5. add capability-asset discovery and admission as a future extension layer
6. update thinking-lane projection to read those receipts directly
