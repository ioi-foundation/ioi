# Autopilot Studio Artifact Implementation Plan

Last updated: 2026-03-28
Status: active execution plan
Depends on:

- `docs/plans/autopilot-studio-artifact-real-output-convergence-plan.md`
- `docs/plans/autopilot-canvas-runtime-unification-plan.md`
- `docs/specs/ioi-cli.md`

## Mission

Implement the Studio artifact system so that the culminated end state is reached
through real artifact generation, real Studio-path verification, and hard-gated
provenance, without allowing mock-safe or CLI-only shortcuts to masquerade as
completion.

Inference unavailability must fail fast and explicitly. Studio artifact flows
must not substitute a mock backend when real inference is unavailable.

## Execution doctrine

This plan exists to prevent the exact undermining that happened before.

The implementation worker must treat the following as incomplete, even if code
compiles and the corpus looks superficially green:

- desktop Studio still falls back to mock or deterministic continuity while the
  proof path stays green
- desktop Studio hides inference failure behind mock output instead of returning
  a typed error
- CLI evidence mislabels provenance
- case summaries omit provenance or fallback state
- render looks acceptable only because a deterministic shell replaced the real
  draft
- the same weak runtime both generates and clears the artifact
- the proof path does not run the same desktop/kernel/surface code path that the
  user interacts with
- routing, briefing, generation, or repair reintroduce ad hoc heuristics or
  lexical fallbacks
- file growth makes the ontology too monolithic to implement or review safely

## Product parity contract

Every implementation slice must improve at least one of these parity dimensions
without regressing the others:

1. first visible artifact quality
2. truthful system behavior
3. localized refinement continuity
4. revision inspectability
5. style/taste carry-forward
6. renderer-spectrum consistency

If a change improves only the paper architecture while leaving the user-facing
artifact experience generic, untruthful, or restart-heavy, it does not satisfy
this plan.

## Workstream 0. Product-path fail-fast contract

### Objective

Eliminate confusing substitute behavior before further quality work proceeds.

### Required changes

1. Remove all mock-runtime fallback from Studio artifact execution.
2. Replace silent substitution with explicit typed inference errors.
3. Make those errors surface consistently in:
   - desktop Studio
   - CLI parity commands
   - corpus evidence
   - verified reply composition
4. Keep any remaining mocks or fixtures strictly confined to narrow non-product
   unit/contract tests.

### Done means

- users see a truthful inference failure instead of a fake artifact
- parity proof cannot proceed on a substituted runtime

## Workstream 1. Truth before quality

### Objective

Make provenance and lifecycle impossible to hide.

### Required changes

1. Replace runtime-origin detection based on `type_name_of_val(...)` with an
   explicit typed provenance model carried through:
   - API generation bundle
   - kernel session state
   - artifact manifest verification
   - CLI evidence
   - Studio UI
2. Distinguish at minimum:
   - real remote model runtime
   - real local runtime
   - fixture runtime
   - deterministic continuity fallback
   - inference unavailable
3. Surface actual runtime/model/lifecycle/fallback state in:
   - Studio status UI
   - artifact evidence drawer
   - CLI `artifact generate`
   - CLI `artifact inspect`
   - corpus case summaries

### Done means

- mock can no longer exist in the Studio artifact product path
- fallback can no longer disappear between raw evidence and summarized evidence
- operators can tell what generated the artifact without opening source code
- inference outages are surfaced as errors, not simulated success

## Workstream 2. Use the real Studio path for parity proof

### Objective

Make the acceptance harness exercise the same code path that users actually run.

### Required changes

1. Split artifact proof into two explicit lanes:
   - pure contract/unit lane with no runtime substitution inside the user path
   - live Studio parity lane
2. Keep the contract lane for schema and manifest validation only.
3. Build a live Studio runner that drives:
   - route selection
   - materialization
   - inference error behavior
   - render capture
   - revision actions
   through the desktop/kernel artifact path rather than only the direct CLI
   bundle path.
4. Record in evidence whether a case was produced by:
   - direct contract path
   - full Studio path

### Done means

- the same failure class seen in the desktop app is visible to the harness
- CLI-only success can no longer certify desktop parity

## Workstream 3. First-paint excellence and renderer-native variation

### Objective

Make the first visible artifact good enough that refinement feels worthwhile.

### Required changes

1. Add renderer-native generation strategies that shape:
   - information architecture
   - visual hierarchy
   - interaction affordances
   - content density
   from the typed brief rather than from a reusable shell
2. Add repeated-run variation evaluation for creative renderers.
3. Penalize renderer house-style dominance when it overwhelms request fidelity.
4. Keep fast draft behavior, but only when the draft is meaningfully usable.

### Done means

- creative renderers produce distinct strong outputs for distinct prompts in the
  same class
- first paint is good enough to earn continued refinement

## Workstream 4. Restore model-first generation for non-workspace artifacts

### Objective

Ensure that the primary artifact view is the real model-led draft, not a generic
continuity shell.

### Required changes

1. Keep typed routing and typed brief planning.
2. Preserve candidate generation with controlled stochasticity for creative
   renderers.
3. Stop replacing a `repairable` HTML candidate with a deterministic shell as
   the default visible artifact.
4. Introduce honest lifecycle behavior:
   - show the draft as `draft` or `refining`
   - allow judged upgrade shortly after
   - reserve deterministic output for continuity-only fallback with explicit
     labeling
5. Penalize archetype dominance directly in judging and verification.
6. Keep the ontology generic:
   - route selection stays renderer-agnostic
   - briefing stays domain-agnostic
   - renderer-specific materializers consume typed inputs without lexical prompt
     switches as final logic

### Done means

- HTML, JSX, and SVG artifacts lead with request-shaped drafts
- deterministic fallback is present only as a disclosed subordinate path
- final logic remains ontology-first rather than heuristic-shaped

## Workstream 5. Separate production from acceptance judging

### Objective

Stop weak self-approval.

### Required changes

1. Keep structural validation as a cheap prefilter.
2. Run final acceptance judging through a stronger and separate runtime or
   external acceptance layer.
3. Persist both:
   - production runtime provenance
   - acceptance judge provenance
4. Make parity cases fail if producer and final judge collapse into the same weak
   runtime.

### Done means

- a mock or weak producer cannot clear itself as parity-ready

## Workstream 6. Make patch-first continuity real

### Objective

Bring artifact iteration to Claude/Gemini-grade continuity instead of regen
resets.

### Required changes

1. Make follow-up requests patch the current artifact by default.
2. Preserve artifact-local selection from both Render and Source.
3. Carry style steering, reference hints, and taste memory across revisions.
4. Ensure revision history supports:
   - compare
   - restore
   - branch
5. Judge continuity explicitly:
   - did the patch preserve the current artifact identity?
   - did the targeted edit remain scoped?
   - did branching avoid destructive overwrite?

### Done means

- refinement flows are judged on continuity, not only on final appearance

## Workstream 7. Render/Source/Evidence coherence

### Objective

Ensure the surfaced artifact, the editable source, and the evidence trail remain
one coherent object throughout the session.

### Required changes

1. Make render-local selections and source-local selections resolve into the same
   typed edit-target model.
2. Ensure every revision updates:
   - render
   - source
   - evidence
   - revision history
   consistently.
3. Prevent stale evidence or stale tabs from describing a previous artifact
   state after patching.

### Done means

- users never have to guess which revision Render, Source, and Evidence refer to
- targeted edits can start from either surface without ontology drift

## Workstream 8. Rewrite the corpus gate so it cannot be undermined

### Objective

Turn the corpus into a hard blocker instead of a reporting tool.

### Required changes

1. Remove `--mock` and fixture-backed cases from the live parity lane.
2. Keep fixtures, when needed at all, outside the product-path proof and only at
   narrow unit/contract boundaries.
3. Add automatic classification downgrades for:
   - fixture runtime
   - missing provenance
   - hidden inference failure
   - fallback-used primary artifact
   - non-desktop proof for desktop parity cases
4. Include rendered captures from the surfaced artifact, not just materialized
   source files.
5. Make summary totals depend on provenance and surfaced lifecycle, not only on
   the judge JSON.

### Done means

- the corpus cannot go green while the real product path is still lying

## Workstream 9. Periodic refactoring and module decomposition

### Objective

Keep the ontology and execution path understandable while the work expands.

### Required changes

1. Add explicit refactor checkpoints after each major workstream.
2. Split oversized files whenever they begin to conflate domains or block safe
   parallel progress.
3. If implementation naturally fans out in parallel, partition work strictly by
   ontology boundary and explicit file ownership.
4. Require integration checkpoints after every parallel tranche so duplicated
   logic does not survive mergeback.
5. Prioritize decomposition of monolithic surfaces such as:
   - `apps/autopilot/src-tauri/src/kernel/studio.rs`
   - `crates/api/src/studio.rs`
   - `crates/cli/src/commands/artifact.rs`
   - `scripts/run-studio-artifact-corpus.ts`
   - `apps/autopilot/src/windows/SpotlightWindow/components/StudioArtifactSurface.tsx`
6. Extract modules by ontology boundary, not by incidental string pattern or UI
   chrome.
7. Treat unbounded file growth during implementation as a regression against the
   plan.

### Done means

- the codebase reflects the same clean ontology that the docs require
- parallel implementation can proceed without accidental domain coupling

## Workstream 10. Keep docs and CLI contracts aligned

### Objective

Ensure the system tells the same truth in docs, manifests, CLI output, and UI.

### Required changes

1. Update CLI docs for any provenance, judging, lifecycle, or inspection changes.
2. Keep the convergence plan, implementation plan, and CLI spec aligned.
3. Treat doc drift around proof sources, fallback semantics, or acceptance rules
   as a regression.

### Done means

- there is one canonical statement of what counts as real proof and completion

## Ordered execution loop

The implementation must run in this order:

1. Enforce the product-path fail-fast contract.
2. Fix provenance modeling and visibility.
3. Fix live Studio-path harness coverage.
4. Raise first-paint quality and renderer-native variation.
5. Remove deterministic-primary HTML behavior.
6. Separate acceptance judging from weak production runtimes.
7. Harden patch-first continuity and revision evidence.
8. Enforce Render/Source/Evidence coherence.
9. Refactor along ontology boundaries before continuing if files become
   monolithic.
10. Rewrite corpus gating and stop conditions.
11. Re-run the full parity corpus through the real Studio path.
12. Continue repairing until zero `repairable` and zero `blocked` remain.

## File ownership map

### Kernel / API / CLI

- `apps/autopilot/src-tauri/src/kernel/studio.rs`
- `apps/autopilot/src-tauri/src/kernel/task.rs`
- `apps/autopilot/src-tauri/src/models.rs`
- `crates/api/src/studio.rs`
- `crates/cli/src/commands/artifact.rs`

### Studio UI

- `apps/autopilot/src/components/StatusBar.tsx`
- `apps/autopilot/src/store/agentStore.ts`
- `apps/autopilot/src/windows/SpotlightWindow/components/ArtifactRendererHost.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/StudioArtifactSurface.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSession.ts`

### Proof / docs

- `scripts/run-studio-artifact-corpus.ts`
- `docs/specs/ioi-cli.md`
- `docs/plans/autopilot-studio-artifact-real-output-convergence-plan.md`
- `docs/plans/autopilot-studio-artifact-implementation-plan.md`

## Hard stop condition

The worker must not close this mission while any of the following remain true:

- any required parity case still relies on mock or fixture inference
- any Studio artifact request still substitutes mock output when inference is
  unavailable
- any primary surfaced artifact still uses deterministic continuity fallback
- any provenance field is missing, misleading, or hidden from the top-level
  summary
- any desktop Studio failure mode is absent from the proof path
- any ontology boundary has collapsed back into ad hoc heuristic or lexical
  routing/generation logic
- any parity dimension in the product parity contract regresses while another is
  being improved
- any monolithic file remains on the critical path without the scheduled
  decomposition the work now requires
- any case remains `repairable` or `blocked`
- any acceptance rule in the convergence plan still fails
