# Autopilot Studio Artifact Real Output Convergence Plan

Last updated: 2026-03-28
Status: active canonical convergence plan
Replaces: the retired Studio artifact spectrum master guide, SOTA output plan, and surface remediation plan

## Purpose

This is the single canonical plan for Studio artifact convergence.

It replaces the previous three-document plan set because that set described the
right product shape but failed to enforce the right completion contract. The
result was a system that could look typed, judged, and corpus-validated while
still missing the actual end state:

- Studio as the control plane
- artifacts as the work products
- renderers as interchangeable delivery backends
- `workspace_surface` as one renderer, not the ontology for all outcomes
- verification and judging as the authority over what Studio may claim
- real request-faithful artifacts, not archetype-shaped continuity shells
- hard errors when inference is unavailable, instead of fake momentum via mock
  runtime substitution

## Culminated end state

Studio reaches the target state only when all of the following are true at the
same time:

1. Non-workspace artifacts are model-first and request-grounded.
   - `html_iframe`, `jsx_sandbox`, `svg`, `markdown`, `mermaid`, `pdf_embed`,
     and `download_card` all produce primary work products whose structure,
     language, interaction, and visual hierarchy are materially shaped by the
     request.
2. Creative renderers use controlled exploration instead of one deterministic
   shell.
   - candidate generation uses non-zero temperature where appropriate
   - evidence records candidate metadata and winner rationale
   - the winning candidate is selected by judging, not by first-valid output
3. The default artifact workflow is `fast draft -> refine -> judged -> locked`.
   - the first visible artifact may be a draft
   - a stronger judged revision may upgrade it without resetting the session
   - lifecycle state is explicit and user-visible
4. Follow-up requests patch the current artifact by default.
   - refinement is patch-first unless the user explicitly asks to replace or
     branch
   - targeted edits can be attached from Render or Source via artifact-local
     selection
5. Revisions are durable and inspectable.
   - compare, restore, and branch are first-class flows
   - style steering, references, and taste memory persist across turns
6. Fallbacks are truthful and subordinate.
   - if inference is unavailable, Studio returns an explicit typed error state
     instead of substituting mock generation
   - deterministic or repaired continuity output may exist only when it is
     explicitly requested or explicitly labeled as non-primary recovery output
   - it never silently passes as the primary successful artifact outcome
   - it never appears as clean `ready` unless the same semantic bar is cleared
7. Quality proof comes from the real Studio path.
   - not pre-authored fixture files
   - not mock-safe corpus shortcuts
   - not a CLI-only path that bypasses the desktop kernel/surface behavior

## SOTA parity lens

The target is not "better than before." The target is parity with the best
artifact-native systems on the dimensions users actually feel.

Studio must clear all of these dimensions together:

1. First-paint quality
   - the first artifact the user sees is already recognizably about the request
   - the page structure, graphic logic, and interaction model feel intentional
   - the result is not a generic shell plus a request-specific patch
2. Refinement quality
   - follow-up turns preserve identity and patch locally by default
   - targeted edits feel scoped, not destructive
   - branch/restore/compare are natural continuation tools
3. Trust quality
   - Studio tells the truth when inference fails
   - Studio tells the truth when quality is not yet good enough
   - no hidden substitute output is allowed to impersonate success
4. Taste quality
   - style steering, references, and tone memory influence later revisions
   - artifacts remain request-faithful rather than style-template dominated
5. Evidence quality
   - the operator can inspect why a candidate won
   - revisions are reviewable and reversible
   - provenance is visible without spelunking raw files
6. Spectrum quality
   - the same ontology works across documents, visuals, interactive artifacts,
     bundles, and workspace projects
   - non-workspace artifacts are not treated as lesser or temporary paths

## Product-quality bar

An artifact deserves the primary view only when it clears all of these product
expectations:

- the request is visible in the primary composition, not relegated to a caption
- the information architecture is specific to the request domain
- charts, diagrams, and interactions are semantically relevant
- brand, naming, and CTA patterns are implied by the request rather than copied
  from a canned archetype
- render quality is strong enough that a user would reasonably continue refining
  from this artifact instead of discarding it immediately

If those conditions are not met, the artifact may still exist, but it has not
earned primary-view authority.

## Gap from the retired plan set

The retired plan set went off track in six concrete ways:

1. It split doctrine, UX, and quality proof across multiple files without a
   single hard completion contract.
2. It allowed contract-valid CLI proof to stand in for real Studio artifact
   experience.
3. It never made runtime provenance a hard gate.
   - `mock`
   - `fixture`
   - deterministic fallback
   - desktop-path bypass
   were all allowed to coexist with a "green" corpus result.
4. It allowed the producer and the final acceptance judge to collapse into the
   same weak runtime.
5. It allowed the surfaced HTML artifact to be replaced by a deterministic
   continuity shell before the operator saw the real draft.
6. It treated evidence as present if it was recorded somewhere, instead of
   requiring the summary and stop condition to actively reject undermining
   provenance.

## Non-negotiables

- zero ad hoc heuristics as final routing or generation authority
- zero lexical routing shortcuts as final logic
- zero benchmark phrase maps as final logic
- zero filename-string repair logic
- zero reply-text-only completion authority
- clean generic ontology
- clean ontology-first agentic process domains
- schema-first typed planning
- explicit state machine
- renderer-specific verification contracts
- clean separation between route selection, materialization, execution,
  verification, judging, and reply composition
- zero lexical fallbacks in final routing, generation, refinement, or repair
- no mock runtime may exist in the Studio artifact product path
- no fixture runtime may exist in the Studio artifact product path
- no inference failure may be masked by a mock runtime substitution
- no mock, fixture, or deterministic continuity path may satisfy the parity bar
  for non-workspace artifacts
- no CLI-only proof may satisfy desktop Studio parity on its own

## Progression doctrine

Progress must be demonstrated by generating real artifacts at each phase, not by
declaring the architecture complete.

### Phase 1. Truth surfaces

Before chasing visual quality, Studio must tell the truth about:

- runtime source
- model name
- candidate origin
- whether fallback was used
- whether the surfaced artifact came from the desktop Studio path
- whether inference was unavailable

This phase is incomplete if any summary, manifest, CLI output, or UI surface can
still present mock or fallback output as live primary generation, or hide an
inference failure behind substitute output.

### Phase 2. Model-first artifact generation

Creative renderers must lead with model-generated drafts and keep deterministic
continuity output subordinate.

This phase is incomplete if:

- `html_iframe` still defaults to a canned launch shell
- the main body of the artifact remains archetype-dominated
- the user must read an appended request note to recognize what the artifact is
  about

### Phase 3. Patch-first continuity and revision UX

Artifact refinement must preserve continuity by default.

This phase is incomplete if:

- follow-up requests restart from scratch unnecessarily
- targeted partial edits cannot be attached from artifact-local selection
- revisions cannot be compared, restored, and branched with evidence

### Phase 4. Real-output convergence proof

The parity bar is only met when the real Studio path clears a judged corpus with
no remaining `repairable` or `blocked` cases.

This phase is incomplete if:

- any required corpus slice still runs on mock or fixture inference
- the desktop Studio path is not exercised
- the final acceptance judge is the same weak runtime that generated the output

### Phase 5. Operator-feel convergence

The product must feel coherent under repeated use, not just satisfy isolated
one-shot prompts.

This phase is incomplete if:

- repeat runs in the same renderer class still collapse toward one house shell
- refinement turns feel like regeneration rather than continuation
- evidence, render, and source disagree about what the artifact currently is
- inference failure handling breaks trust more than it preserves momentum

## Required live corpus

The canonical corpus must include at minimum:

1. markdown document artifact
2. HTML explainer / landing artifact
3. JSX interactive artifact
4. SVG visual artifact
5. Mermaid diagram artifact
6. PDF artifact
7. download-card artifact
8. workspace-surface artifact

Additional parity coverage is mandatory:

1. at least 3 semantically different HTML prompts in the same renderer class
2. at least 2 follow-up refinement prompts that should patch the existing
   artifact
3. at least 1 targeted partial-edit flow
4. at least 1 revision compare/restore flow
5. at least 1 style-reference or tone-steering flow
6. repeated-run variation checks for at least 1 creative renderer class
7. at least 1 inference-unavailable case proving truthful failure behavior

## Required evidence per case

Every live corpus case must persist:

- typed routing result
- typed artifact brief
- typed edit intent when applicable
- candidate set metadata
- winning candidate rationale
- artifact manifest
- verified reply
- materialized files
- rendered output
- screenshots or captures of the surfaced result when applicable
- revision history evidence when applicable
- runtime provenance for generation and judging
- whether the case was produced through the desktop Studio path or a narrower
  CLI contract path
- explicit inference availability or failure evidence

## Typed rubric

Every case is judged against:

- request faithfulness
- concept coverage
- interaction relevance
- layout coherence
- visual hierarchy
- completeness
- generic-shell / archetype dominance detection
- trivial-shell / placeholder detection
- whether the surfaced output deserves to be the primary artifact view
- whether a refinement patched correctly instead of restarting unnecessarily
- whether continuity and revision UX meet the parity bar
- whether provenance is truthful
- whether inference failure handling is truthful
- whether the first visible artifact would satisfy the parity bar for continued
  refinement
- whether repeated runs show healthy variation without losing request fidelity

Every case must classify as exactly one of:

- `pass`
- `repairable`
- `blocked`

## Hard blockers

The corpus must classify a case as `blocked` or `repairable` when any of the
following occur:

- runtime source is `mock` or `fixture` for a parity case
- output origin is unknown, mislabeled, or missing
- inference was unavailable and the system substituted mock or fake primary
  output instead of surfacing an explicit error
- fallback was used for the surfaced primary artifact
- lifecycle is `partial`, `blocked`, or `failed`
- the case was proven only through the CLI bundle path while the desktop Studio
  path remains unverified
- producer and final acceptance judge collapse into the same weak runtime
- case summaries omit provenance or fallback evidence that exists in the raw run
- a generic shell wins because the judge or harness failed to penalize it
- repeated runs collapse onto a renderer house style that overwhelms the request

## Refactoring doctrine

This convergence work must preserve a clean ontology in code, not just in docs.

- monolithic files must be periodically split as implementation advances
- domain boundaries must remain explicit:
  - outcome routing
  - artifact briefing
  - edit intent
  - candidate materialization
  - execution
  - verification
  - judging
  - reply composition
- renderer-specific logic must not leak back into ontology or routing domains
- refactoring is not optional cleanup after convergence; it is part of
  convergence

Refactoring is mandatory whenever file growth or context density starts to
undermine execution clarity, reviewability, or parallel implementation safety.

## Release gate

No release, completion claim, or parity claim is allowed unless the following
are all true at once:

- real Studio-path parity corpus is green
- provenance and lifecycle are truthful in UI, CLI, and evidence
- inference-unavailable behavior is explicit and user-comprehensible
- repeated-run variation checks prove that creative renderers are not trapped in
  one generic shell
- no critical-path module remains so monolithic that ontology boundaries are
  obscured

## Stop condition

This plan is complete only when all of the following are true:

- frontend build/type proof passes for touched Studio surfaces
- Rust compile/test proof passes for touched kernel and CLI surfaces
- targeted tests cover generation, judging, fallback truthfulness, runtime
  provenance, inference-unavailable error handling, patch-first refinement,
  selection-based edits, and revision history
- CLI proof covers inspect, validate, materialize, route/query, compose-reply,
  and provenance-aware judging/inspection
- the live corpus and parity corpus both run through the real Studio path
- the final judgment summary reports zero `repairable` and zero `blocked`
- no acceptance criterion remains unmet
