# Studio Research-Backed Artifact and Inline Tool UI Plan

Last updated: 2026-04-18
Owner: Studio / Spotlight / agent runtime / artifact UX
Status: proposed

Companion documents:

- `docs/plans/agentic-runtime-cleanup-90s-plan.md`
- `docs/plans/studio-claude-artifact-parity-plan.md`
- `docs/plans/studio-artifact-runtime-event-truth-plan.md`

## Purpose

This plan closes the gap the April 16 Unsloth comparison exposed for researched
artifact requests such as:

- `Create an HTML file that explains quantum computers`
- `Build a researched landing page about current AI safety practice`
- `Write a product explainer page with recent sources`

Two gaps matter most:

1. runtime sequencing
2. main-lane storytelling

Today IOI has strong primitives for web retrieval, file writing, receipts, and
verification, but it does not default to the same end-to-end shape that the
Unsloth request-scoped loop shows in
`examples/onsolth-screenshots/Screenshot_2026-04-16_17-51-36.png` and
`examples/onsolth-screenshots/onsloth-chat.html`:

- research first
- author with fresh evidence still in hand
- inspect what was written
- verify the artifact
- show the operator the run as inline activity, not as a wall of cards

The target is not pixel mimicry. The target is the same operator truth:

- researched artifact asks automatically gather context before writing
- the builder sees real source material, not just a collapsed summary
- the runtime performs a bounded write-then-verify loop
- the main conversation lane reads like a calm activity transcript with
  reasoning disclosure
- receipts and deep diagnostics remain available, but they stop being the
  default visual language

## UI Thesis

Visual thesis:

- a calm transcript surface with inline tool activity, sparse disclosure, and
  the artifact itself as the dominant visual object

Content plan:

1. compact reasoning disclosure
2. inline tool activity group
3. artifact surface or file preview
4. short final answer and source handoff

Interaction thesis:

- tool rows stream in sequentially
- reasoning stays collapsed until the operator asks for it
- cards move to inspectors, exceptions, and explicit secondary surfaces

## Reference UI spec from the Unsloth capture

This section is intentionally concrete. The target should be recognizably
closer to `examples/onsolth-screenshots/onsloth-chat.html` and
`examples/onsolth-screenshots/onsloth-chat.css`, while still using IOI's own
palette and component system.

### 1. Overall lane geometry

- keep the conversation lane narrow and reading-focused rather than panel-like
- target a thread width around `44rem`, with inner content slightly narrower
- keep the top chrome visually light and overlayed rather than boxed into the
  transcript
- target header-overlay height around `44px`, with thread top padding around
  `56px` so the transcript clears the chrome cleanly
- keep thread side padding around `20px`
- use generous horizontal breathing room around the lane, but keep the actual
  message column compact
- preserve smooth vertical scrolling and subtle arrival motion

Why this matters:

- the screenshot feels like a reading surface first and a control panel second

### 2. Message hierarchy

The saved Unsloth markup has a very clear order inside an assistant turn:

1. tool activity group
2. reasoning disclosure
3. assistant prose
4. source chips

IOI should adopt the same hierarchy for researched artifact runs.

Normative rules:

- do not place the final prose answer above the run activity
- do not interleave route cards and micro-event cards between activity rows and
  the final answer
- keep the artifact surface visually adjacent to this sequence rather than
  separating it into a distant card block

### 3. User message treatment

- keep user messages as the only obvious bubble treatment in the lane
- right-align the bubble
- keep it compact, with rounded corners and muted fill
- cap width near `80%` so it reads as a prompt, not a panel
- keep the bubble closer to `rounded-2xl` than to a sharp rectangle
- keep padding in the small-message range, roughly `16px x 10px`

Normative rule:

- assistant content should not mirror the same bubble treatment unless the
  content is a true exception state

### 4. Assistant run treatment

- assistant turns should feel mostly unboxed
- the lane should read like flowing transcript content with inserted interactive
  rows
- use card surfaces only for:
  - errors
  - approvals
  - branch exceptions
  - inspector-only material

Normative rule:

- a successful artifact run should not look like a stack of detachable cards

### 5. Tool activity group anatomy

The saved Unsloth UI uses a `ghost` tool group rather than a heavy card. That
is the correct direction for IOI.

Required anatomy:

- one compact group header row
- left icon at `16px` scale
- medium-weight summary label such as `6 tool calls`
- chevron affordance on the right
- a very light tinted background, closer to `muted/10` than to a filled panel
- small vertical padding and tight row rhythm
- rounded group edges, closer to `rounded-lg` than to a full card radius
- keep row gaps near the `8px` rhythm and row padding near `6px`

Inside the group:

- each tool row is a single horizontal line first
- icon column is fixed-width and visually quiet
- label is left-aligned and occupies the flexible width
- primary action text is darker than the prefix text
- row expansion is available, but collapsed is the default resting state

Suggested IOI copy shape:

- `Searched "quantum computers explained basics qubits superposition entanglement"`
- `Read ibm.com`
- `Read nist.gov`
- `Wrote quantum_computers.html`
- `Verified quantum_computers.html`
- `Previewed quantum_computers.html`

Normative rules:

- default the group itself to open for the active run
- default individual tool rows to collapsed except for the currently active row
  or the most recently completed row
- prefer one concise sentence per row over metadata-heavy badges
- do not surface raw JSON, receipt blobs, or route jargon in the default row

### 6. Expanded tool row behavior

When a tool row expands, the saved Unsloth UI uses a simple indented content
region instead of a nested card.

Required behavior:

- indent expanded content under the row label
- use a restrained left offset, roughly one icon column plus gap
- render fetched or previewed content in a subdued monospace or preformatted
  block
- cap preview height and allow internal scrolling for long content
- keep the preview background lighter than a full card and darker than the lane
  background
- prefer `text-xs`-scale detail blocks with `p-2`-style compact padding

Normative rule:

- expansion should feel like revealing detail inside the transcript, not opening
  another panel inside the panel

### 7. Reasoning disclosure anatomy

The saved Unsloth transcript places reasoning in its own disclosure row after
tool activity and before the final prose. That is the correct mental model.

Required anatomy:

- separate reasoning row from the tool group
- use a small icon and subdued text treatment
- summary copy should be duration-oriented and compact, such as:
  - `Thought for 1 second`
  - `Thought for 8 seconds`
- keep it collapsed by default
- when expanded, render the thinking content at a slightly smaller size than
  the main prose
- target expanded reasoning copy around the `13.5px` utility-text tier rather
  than full body size

Normative rules:

- reasoning is disclosure, not a full panel
- the summary row should not compete visually with tool activity or the artifact
- if reasoning content is unavailable, omit the disclosure rather than rendering
  a dead container

### 8. Final answer treatment

The final prose in the reference capture is not the largest visual object. It
lands after the run activity and reads as a handoff.

Required behavior:

- keep the answer in normal assistant prose flow, not a branded answer card
- prefer short intro copy followed by concise lists only when needed
- place file outcome and next steps inside the prose or directly beside the
  artifact surface
- treat the answer as the conclusion of the run, not the container for the run

Normative rule:

- `AnswerCard` should not remain the primary delivery format for successful
  researched artifact runs

### 9. Source chip treatment

The saved Unsloth transcript ends with quiet inline source chips rather than a
large citations card. IOI should match that behavior.

Required anatomy:

- sources sit directly beneath the final answer
- chips wrap naturally across lines
- each chip contains:
  - favicon or small site mark
  - truncated source title
- chips use tiny type, light borders, and transparent or near-transparent fill
- keep chips compact, roughly `px-2 py-1` with small rounded corners

Normative rules:

- do not move sources into a separate large card by default
- source chips should feel like supporting evidence, not a competing section
- the same selected source pack used during authoring should drive these chips

### 10. Typography and spacing

The saved Unsloth capture succeeds mostly through restraint.

Required baseline:

- body copy around the mid-15px range
- relaxed assistant line height
- smaller utility text for tool rows and disclosures
- mono numerics only where numbers actually benefit from alignment
- tight vertical spacing inside activity groups
- larger spacing between major transcript blocks than within a block

Normative rules:

- do not increase type scale just to create hierarchy
- create hierarchy with weight, contrast, indentation, and spacing first

### 11. Motion and transitions

The reference uses small-scale collapsible and entrance motion. IOI should do
the same.

Required motion rules:

- fade and slide new messages in subtly
- collapse and expand activity groups within roughly `150ms` to `200ms`
- rotate disclosure chevrons without flourish
- avoid springy, bouncy, or dashboard-style animation

Normative rule:

- motion should make the transcript feel alive, not busy

### 12. Color direction

The user explicitly called out not to copy the green accents. That should be
respected.

Required color direction:

- keep the surface mostly neutral
- use muted fills and low-contrast separators
- reserve accent color for state cues, not for every interactive row
- keep icons and utility text in a subdued foreground tier

Normative rules:

- do not re-theme the lane around green
- do not rely on saturated borders or cards to create hierarchy

### 13. What IOI should not copy

- the exact Unsloth brand accent colors
- the exact LM Studio header chrome
- the misleading behavior shown later in the transcript where the model claims
  it cannot create the file after previously implying it had

### 14. What IOI should copy

- transcript-first hierarchy
- compact collapsible tool group
- separate reasoning disclosure row
- quiet source chips
- compact geometry
- cardless successful assistant turns

## Core doctrine

The governing rule for this plan is:

> A researched artifact run should execute and render as one coherent chain:
> research -> source pack -> author -> inspect -> verify -> present.

That implies six constraints:

- artifact routing must decide whether research is required before authoring
- the authoring step must receive selected evidence, not just a synthesized
  brief
- verification must be a required phase for file-producing runs
- visible inline tool rows must be projections of actual runtime events
- the main lane should be mostly cardless for normal successful runs
- route cards, receipt cards, and debug cards should move to secondary context

## Current repo reality

### 1. Artifact and research are still separate first-class routes

`artifact_generation_gate` currently behaves like `context -> build ->
validation` and does not own a research phase. In practice that means artifact
work can route into a build path before the runtime decides whether fresh
external grounding is required.

Relevant seams:

- `crates/services/src/agentic/runtime/agent_playbooks.rs`
- `crates/services/src/agentic/runtime/service/step/intent_resolver/instruction_contract.rs`
- `crates/services/src/agentic/runtime/service/step/cognition.rs`

### 2. The web pipeline is optimized to finish with a summary

The web pipeline does strong source gathering, but it is optimized to culminate
in a cited summary and completion contract rather than preserving a selected
source pack for immediate artifact authoring.

Relevant seams:

- `crates/services/src/agentic/runtime/service/step/queue/processing/web_pipeline/mod.rs`
- `crates/services/src/agentic/runtime/service/step/queue/processing/web_pipeline/read.rs`
- `crates/services/src/agentic/runtime/service/step/queue/processing/completion.rs`

### 3. Artifact verification is not yet a mandatory runtime ritual

IOI has file tools and artifact surfaces, but the runtime does not yet make
`write -> inspect -> verify -> optional repair` the default contract for normal
single-file artifact work.

Relevant seams:

- `crates/services/src/agentic/runtime/tools/builtins/common_tools_chat_fs.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/materialization.rs`
- `apps/autopilot/src/windows/SpotlightWindow/components/StudioArtifactSurface.tsx`

### 4. The main conversation lane is still too card-heavy

The current Spotlight surface tells the story through `ExecutionRouteCard`,
`ExecutionMomentList`, `AnswerCard`, artifact cards, and micro-event cards. For
artifact and research runs this reads more like a dashboard than a transcript.

Relevant seams:

- `apps/autopilot/src/windows/SpotlightWindow/components/ConversationTimeline.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionMomentList.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/AnswerCard.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/MicroEventCard.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/styles/Chat.css`

### 5. The backend already emits enough truth to start rendering inline tool rows

Workload receipts already carry `web__search`, `web__read`, and other
tool-derived detail with user-facing progress text such as `Searching the web`
and `Reading <domain>`. This means the first inline-tool UI can be built from
real runtime events instead of waiting for a full event-schema redesign.

Relevant seams:

- `apps/autopilot/src-tauri/src/kernel/events/stream/workload_receipt.rs`
- `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
- `apps/autopilot/src/windows/SpotlightWindow/hooks/useTurnContexts.ts`

## Desired end state

For a request like `Create an interactive HTML artifact that explains quantum
computers`, Spotlight should behave like this:

1. Route the ask into a research-backed artifact flow.
2. Open a compact reasoning disclosure with one clear live label.
3. Stream an inline activity group in the main lane:
   - `Searched "quantum computers basics"`
   - `Read ibm.com`
   - `Read nist.gov`
   - `Wrote quantum_computers.html`
   - `Verified the file`
   - `Previewed the artifact`
4. Open the artifact surface early and keep it attached while writing.
5. If verification fails, show one bounded repair attempt in the same group.
6. Finish with a short final answer, artifact link, and source list.

The operator should not need to mentally reconstruct the run from cards,
receipts, and debug chrome.

## Target architecture

### Layer 1: Research-backed artifact routing

Introduce a first-class researched artifact route or equivalent typed branch
inside the artifact playbook.

Suggested runtime shape:

- `artifact_direct`
- `artifact_research_backed`
- `artifact_repair`

Suggested routing triggers:

- the user asks for explanation or education with factual grounding
- the task implies freshness, citations, or external comparison
- the output format is HTML, Markdown, or other explainer artifact where source
  quality will materially affect the result

### Layer 2: Source pack contract

Add a typed source-pack handoff between research and authoring.

Suggested shape:

- `query_intent`
- `selected_sources`
- `selected_excerpts`
- `citation_handles`
- `facts_to_preserve`
- `freshness_notes`

Normative rule:

- authoring receives the source pack directly
- summary generation becomes a presentation step, not the only retained output

### Layer 3: Artifact verify loop

Normalize a required post-write phase for artifact-producing runs.

Suggested default sequence:

1. write file
2. inspect file contents or preview
3. run lightweight verification
4. if verification fails, do one bounded repair pass
5. reopen or refresh the artifact surface

### Layer 4: Inline activity projection

Render one compact tool-activity transcript in the main lane.

Suggested frontend model:

- `ToolActivityGroup`
- `ToolActivityRow`
- `ReasoningDisclosure`
- `ArtifactOutcomeMessage`

Normative rule:

- the main lane uses inline rows, not stacked cards, for normal research and
  artifact progress

## Workstreams

### Workstream 1: Add a research-backed artifact playbook

Goal:

- artifact asks that need grounding should automatically research before writing

Implementation:

- add a dedicated researched-artifact branch inside the agent playbooks
- teach the intent resolver to prefer that branch for grounded explainer asks
- make the runtime carry an explicit artifact-run phase model:
  - `prepare`
  - `research`
  - `author`
  - `verify`
  - `present`
- keep the current fast path for obviously local, self-contained artifacts

Required changes:

- update `crates/services/src/agentic/runtime/agent_playbooks.rs`
- update `crates/services/src/agentic/runtime/service/step/intent_resolver/instruction_contract.rs`
- update `crates/services/src/agentic/runtime/service/step/cognition.rs`

Acceptance:

- grounded artifact asks no longer skip directly to authoring
- self-contained artifact asks can still route to a fast local path
- runtime state makes the current artifact phase explicit

### Workstream 2: Preserve a source pack for the author

Goal:

- the builder should write from fresh evidence, not from a collapsed summary

Implementation:

- introduce a typed source-pack structure in runtime state
- let web retrieval produce both:
  - a user-facing summary
  - a builder-facing evidence pack
- thread the source pack into artifact authoring prompts and builder context
- retain citation handles so the final artifact and final answer can cite the
  same source selection

Required changes:

- update `crates/services/src/agentic/runtime/types.rs`
- update the web pipeline under
  `crates/services/src/agentic/runtime/service/step/queue/processing/web_pipeline/`
- update artifact authoring context assembly wherever file-producing artifact
  prompts are built

Acceptance:

- researched artifact runs retain a non-empty selected source pack
- the authoring prompt can reference selected excerpts and citation handles
- the source pack survives long enough for both authoring and final handoff

### Workstream 3: Make verification a required artifact phase

Goal:

- file-producing runs should not end at `write succeeded`

Implementation:

- define per-artifact-type verification contracts:
  - file exists
  - file is readable
  - preview opens or refreshes
  - lightweight sanity checks pass
- require one read-back or preview step after write
- require one bounded repair loop when verification fails
- persist verification outcome as a typed run result rather than generic tool
  chatter

Suggested first-pass verification for HTML:

- file path exists
- file contents are non-empty
- artifact surface can load the file
- lightweight DOM or renderer sanity checks pass if available

Required changes:

- update artifact runtime orchestration in `crates/services`
- update Studio surface hooks in `apps/autopilot/src-tauri/src/kernel/studio`
- update the artifact surface projection in
  `apps/autopilot/src/windows/SpotlightWindow/components/StudioArtifactSurface.tsx`

Acceptance:

- researched HTML artifact runs always emit at least one verify event
- failed verification triggers one repair attempt before final failure
- successful runs expose a typed verification success in the transcript

### Workstream 4: Introduce first-class inline tool activity events

Goal:

- the UI should tell the runtime story without relying on card heuristics

Implementation:

- start with workload receipts as the truth source for web and file activity
- add a typed projection layer that groups adjacent related events into one
  `ToolActivityGroup`
- teach the projection layer to collapse details into screenshot-style row copy:
  - `Searched ...`
  - `Read <domain>`
  - `Wrote <file>`
  - `Verified <artifact>`
- preserve raw receipt payloads for inspector surfaces
- once the UI shape is stable, consider promoting the projection into a more
  explicit backend event type

Required changes:

- update `apps/autopilot/src-tauri/src/kernel/events/stream/workload_receipt.rs`
- update `apps/autopilot/src/windows/SpotlightWindow/hooks/useTurnContexts.ts`
- update `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
- update `apps/autopilot/src/types.ts`

Acceptance:

- a researched artifact run renders grouped inline tool rows from real events
- the UI can distinguish search, read, write, verify, and preview activity
- inspectors still expose the underlying raw receipt detail

### Workstream 5: Replace card-heavy conversation chrome with a calmer inline lane

Goal:

- the main lane should feel like the screenshot: transcript-first, disclosure
  oriented, and mostly cardless

Implementation:

- create new main-lane components:
  - `ReasoningDisclosure`
  - `ToolActivityGroup`
  - `ToolActivityRow`
  - `InlineArtifactOutcome`
- refactor `ConversationTimeline.tsx` so inline groups become the primary
  render path for artifact and research runs
- enforce assistant-turn ordering as:
  - activity group
  - reasoning disclosure
  - prose handoff
  - source chips
- demote the following from the main successful-run lane:
  - `ExecutionRouteCard`
  - `ExecutionMomentList`
  - `AnswerCard`
  - `MicroEventCard`
- keep card treatment only for:
  - approvals
  - errors
  - exceptional branch explanations
  - secondary inspectors
- tune `Chat.css` toward a calmer, denser transcript surface with stronger
  hierarchy and less panel chrome

Frontend design constraints:

- no hero-card behavior inside the conversation lane
- default to rows, dividers, inline metadata, and disclosure instead of panels
- keep one dominant object per successful artifact run: the artifact surface
- reasoning and source details should expand inline, not open more cards by
  default
- keep the thread width reading-oriented and compact
- keep assistant turns mostly unboxed
- use muted ghost surfaces for activity groups instead of filled cards
- keep user prompts as the only obvious chat bubbles in successful runs
- source chips must sit directly below the final prose handoff
- row labels should use plain language rather than internal route vocabulary
- expanded row detail should reveal inline beneath the row, not in a separate
  inspector card

Required changes:

- update `apps/autopilot/src/windows/SpotlightWindow/components/ConversationTimeline.tsx`
- update or replace the current card components under
  `apps/autopilot/src/windows/SpotlightWindow/components/`
- update `apps/autopilot/src/windows/SpotlightWindow/styles/Chat.css`
- update any lane state shaping in
  `apps/autopilot/src/windows/SpotlightWindow/components/StudioConversationSurface.tsx`

Acceptance:

- a normal researched artifact run no longer centers route and answer cards in
  the main lane
- the first thing the operator sees is reasoning disclosure plus inline tool
  activity
- the artifact surface reads as the dominant output rather than one more card
- tool groups use compact ghost styling rather than bordered panels
- reasoning appears as its own collapsed disclosure row, not as a card
- source links render as quiet inline chips beneath the final handoff
- the assistant lane reads as one transcript flow rather than stacked modules

### Workstream 6: Add parity benchmarks and rollout gates

Goal:

- close the quality gap with a measurable bar, not a subjective feeling

Implementation:

- create a small benchmark set of researched artifact prompts:
  - quantum computers explainer HTML
  - current AI safety practices explainer
  - comparison page using multiple current sources
- record:
  - selected route
  - number and quality of sources used
  - whether a source pack reached authoring
  - whether verification ran
  - whether the main lane showed inline activity correctly
- add screenshot or DOM snapshot coverage for the inline activity group
- gate rollout behind successful runtime and UI benchmark results

Acceptance:

- benchmark prompts consistently route into research-backed artifact mode when
  warranted
- produced artifacts visibly improve in factual depth and structure
- the UI snapshots show inline activity groups instead of the old card stack

## Recommended execution order

1. Add researched-artifact routing and phase state.
2. Add the source-pack contract and thread it into authoring.
3. Make verification mandatory for file-producing runs.
4. Build the first inline tool-activity projection from workload receipts.
5. Replace the main-lane card stack with the inline transcript UI.
6. Add parity benchmarks, snapshot tests, and rollout gates.

This order matters. If the UI ships before the runtime contract is improved,
Spotlight will only render a prettier version of the same weaker orchestration.

## Acceptance bar

This plan is complete when all of the following are true:

- a grounded HTML artifact ask routes into a researched-artifact flow by
  default
- the authoring step receives a non-empty selected source pack
- the runtime emits explicit write, verify, and preview activity
- the main lane renders those events as inline tool rows rather than stacked
  cards
- the artifact surface opens early and remains visually primary
- the final answer becomes a short handoff instead of the main narrative object

## Non-goals

- replacing all inspector and debug surfaces with transcript UI
- removing cards from approvals, failures, or deep diagnostics
- forcing research for obviously local or purely synthetic artifact asks
- imitating the exact Unsloth visual styling rather than matching the better
  operator experience
