# Autopilot Agent Studio Quality Harness Runtime Parity Master Guide

Owner: Autopilot Runtime / Agent Studio
Status: Draft campaign guide
Created: 2026-05-30
Target end state: `agent_studio_quality_harness_runtime_parity_proven`

Fresh evidence root:

`docs/evidence/autopilot-agent-studio-quality-harness-runtime-parity/`

Primary references:

- `.internal/plans/autopilot-agent-studio-product-reliability-context-quality-hardening-master-guide.md`
- `.internal/plans/autopilot-agent-studio-contextual-streaming-harness-ux-master-guide.md`
- `.internal/plans/autopilot-lm-studio-quality-routing-chat-ux-parity-master-guide.md`
- `.internal/plans/autopilot-conversation-artifact-embedded-document-canvas-master-guide.md`
- `.internal/playbooks/substrate-absorption-rubric-playbook.md`
- `internal-docs/reverse-engineering/unsolth/`
- live Unsloth web UI screenshots and observations captured during this campaign

## Executive Intent

This campaign exists because Autopilot still produces responses that feel mechanically assembled while the reference web harness produces model-shaped answers with natural structure, current sources, visible tool work, and clean response actions.

The target is not to embed the reference engine. Autopilot must stay Autopilot-native:

- daemon-owned model routing;
- daemon-owned tool execution;
- daemon-owned context acquisition;
- daemon-owned artifact lifecycle;
- daemon-owned stream events;
- Studio GUI as presentation only.

The campaign target is achieved only when Agent Studio can repeatedly produce high-quality, model-authored, source-grounded responses through its own runtime harness, with no deterministic synthesis scaffolding, no canned fallback answers, no stale-source guesses, no product-facing trace noise, and no monolithic harness files that make the system hard to reason about.

## Product Standard

For a prompt such as:

```text
which is a better investment, filecoin or akash network?
```

Autopilot Agent should:

1. Recognize that the answer needs fresh market context.
2. Search/read current source material and quote-grade market data for both assets.
3. Feed compact source notes back to the selected model.
4. Stream provider-visible thinking or concise planning when available.
5. Show concrete tool rows as search/read/quote work happens.
6. Stream the final answer as model text, not snap in a deterministic template.
7. Display sources at the bottom of the response in a human source strip.
8. Display response actions and metrics.
9. Keep raw receipts, timestamps, confidence diagnostics, trace ids, payloads, and source excerpts in Runs/Tracing/evidence.

The final answer may use tables, sections, bullets, caveats, and comparison framing, but that structure must come from the model or from a light formatting pass over model output. It must not come from hard-coded templates such as `Story 1`, `Briefing for`, `What happened`, `Run date`, `Overall confidence`, or deterministic multi-story summaries.

## Scope

In scope:

- model-in-the-loop answer synthesis after tools;
- removal of deterministic answer synthesis and fallback report paths;
- quality parity for web-researched answers;
- quality parity for website/artifact generation;
- bounded context acquisition;
- current market data and source freshness;
- source chips/links and bottom response actions;
- context remaining display in the chat header;
- inference settings toggle/sidebar in the chat UX;
- removal of the persistent Tracing side rail from the chat surface;
- streamed thinking, tool rows, generated source/content, and final answer tokens;
- response metrics and token/sec;
- runtime contract ownership;
- file/module size and naming refactors required to keep the harness understandable.

Out of scope:

- broad Rust tool catalogue retesting;
- default harness parity rediscovery;
- workflow compositor graph canvas;
- copying another product's visual styling;
- using another product's engine inside Autopilot;
- exposing hidden chain-of-thought;
- turning this into a generic marketplace/provider expansion campaign.

## Hard Product Rules

These are P0 rules.

1. No deterministic product answers.
   - Remove deterministic web summaries, story summaries, source comparison templates, confidence blurbs, timestamp blurbs, canned reports, canned artifact pages, and fixture prose from product paths.
   - Tests may use fixed fixtures for assertions, but the product runtime must not route through deterministic answer builders.
2. No silent fallback to product-ineligible models.
   - No `local:auto`, fixture models, story models, embedding models, or deterministic fixtures unless an explicit developer/test mode is active and visibly marked outside product chat.
3. No stale-source financial/current answers.
   - For prices, current market cap, performance, news, laws, versions, and "latest/current" prompts, retrieve fresh data or produce a clean model-authored blocker.
4. No product-facing trace details.
   - Keep run timestamps, confidence scores, raw source timestamps, receipt ids, trace ids, endpoint URLs, fixture paths, and JSON payloads out of the chat answer.
5. No GUI-owned harness semantics.
   - The GUI can render sources, settings, tool rows, metrics, and artifacts. It cannot own model synthesis, context planning, policy, artifact execution, or source selection.
6. No monolithic harness files.
   - Any touched product/runtime/GUI harness file over 2000 LOC must be split before the final verdict unless it is explicitly a generated artifact or vendored reference outside the product harness.

## Reference Observations To Absorb

Use `internal-docs/reverse-engineering/unsolth/` and live GUI exploration as reference material.

Important behavioral patterns to study and port as Autopilot-native primitives:

- tool-capable chat keeps the model in control of final synthesis;
- web search returns snippets and directs the model to read source URLs for full context;
- tool calls stream as events before final answer;
- duplicate tool calls are discouraged by conversation feedback, not hidden deterministic substitution;
- after tool iteration, the final response is generated in a final streaming model pass with tool results in conversation context;
- reasoning-capable models can stream reasoning separately from answer content;
- final usage/timing metadata is emitted as response metadata;
- the UI shows sources and response actions near the response instead of dumping trace data into chat;
- model loading/generation is serialized enough to avoid cross-request token leaks.

Do not copy code or visual branding. Convert these observations into Autopilot-native contracts and tests.

## Harness-To-Harness Runtime Shape

The primary parity target is the runtime loop, not a pile of product-copy heuristics.
Autopilot should absorb the reference shape as a generic CIRC/CEC-compatible harness
pattern:

1. Classify the user objective into bounded context facets.
   - Examples: current scalar facts, comparison context, official documentation,
     workspace files, generated artifact source, user-only action.
   - Facets describe what evidence the model needs; they are not final-answer
     templates.
2. Acquire evidence through governed tools.
   - Search returns candidate snippets.
   - Read/fetch tools acquire full source notes.
   - Workspace questions use workspace search/read rather than runtime-specific
     assumptions.
   - Artifact requests stream generated source/content through the daemon-owned
     artifact path.
3. Feed useful tool results back into the same synthesis context.
   - Do not throw away context just because one grounding floor is satisfied.
   - Quote/current scalar evidence may be mandatory, but it should not starve
     the model of comparison, risk, use-case, or background context needed for
     the actual question.
4. Let the selected model write the final answer.
   - The harness may provide answer requirements and safety boundaries.
   - The harness must not provide deterministic product prose, canned summaries,
     fixed report shells, or domain-specific final copy.
5. Validate final output against contract invariants.
   - Reject fixture leaks, trace leaks, stale current claims, unsupported scalar
     claims, missing required citations, and hidden reasoning leaks.
   - If the output fails validation, either repair by acquiring missing context
     or produce a clean model-authored blocker. Do not substitute a deterministic
     fallback answer.

This shape scales because the primitives are evidence facets, tool events,
conversation context, and final-output validation. Domain terms can seed evidence
facets, but should not become an unbounded family of hand-written answer
templates.

## Quality Rubric

For response quality, evaluate:

- factual correctness against current sources;
- direct answer to the user's question;
- natural model-authored structure;
- useful comparison framing;
- appropriate uncertainty without boilerplate;
- source-grounded claims;
- no unsupported price or metric claims;
- no deterministic headings or repeated canned phrasing;
- no internal implementation language;
- readable Markdown rendering;
- bottom source strip and response actions;
- metrics shown without clutter.

For artifact quality, evaluate:

- model-generated source, not canned shell;
- streamed source/content during generation;
- valid preview from the generated source;
- human handoff with artifact embed;
- source/preview/export/revise actions;
- no fixture markers or hash placeholders.

For harness quality, evaluate:

- typed context acquisition;
- model-in-loop synthesis;
- streaming events in order;
- source compaction before model use;
- policy and trace retention outside chat;
- cleanup after each live run;
- maintainable module boundaries.

## Evidence And Validation Discipline

Every live comparison cycle must run the apps consecutively:

1. Launch the reference web UI.
2. Run the matched prompt.
3. Capture screenshots of prompt, thinking, tool rows, source/content streaming where visible, final answer, sources/actions, metrics, and model/settings surface.
4. Kill reference UI server, model workers, browser sessions, and child processes.
5. Verify cleanup.
6. Launch Autopilot GUI and daemon.
7. Run the matched prompt through Agent Studio with comparable model/settings where available.
8. Capture the same screenshots plus traces, receipts, route decisions, model invocation receipts, context planner decisions, token metrics, side-effect proof, and cleanup proof.
9. Kill Autopilot, runtime bridge, daemon, model workers, preview servers, browser sessions, and child processes.
10. Verify cleanup.

Do not run both model-serving stacks concurrently when GPU or memory contention can affect quality, latency, or model state.

For every scenario write a manifest row with:

- row id;
- stage;
- prompt;
- app under test;
- mode: Ask or Agent;
- selected model/provider/route;
- inference settings;
- context remaining before/after where available;
- context planner decision;
- searches/reads/tools used;
- source list;
- artifact ids/revisions where relevant;
- stream event coverage;
- screenshots;
- traces/receipts;
- response metrics;
- cleanup proof;
- quality notes;
- classification;
- owner for blockers.

## Classifications

Use these row classifications:

- `live_pass`
- `fixed_then_pass`
- `headless_pass`
- `cross_client_pass`
- `quality_match_pass`
- `model_synthesis_pass`
- `context_acquisition_pass`
- `source_grounding_pass`
- `market_data_pass`
- `ux_streaming_pass`
- `source_strip_pass`
- `settings_ui_pass`
- `metric_pass`
- `artifact_delivery_pass`
- `refactor_pass`
- `policy_gate_pass`
- `sandbox_effect_pass`
- `supporting_pass`
- `supporting_pass_with_product_decision`
- `rejected_with_product_decision`
- `deferred_optional`
- `blocked_with_owner`
- `partial_unproven`
- `gap`
- `fixture_leak`
- `silent_route_downgrade`
- `deterministic_answer_leak`
- `stale_context_answer`
- `hidden_cot_leak`
- `trace_leak`
- `monolithic_module_debt`

No P0 row may remain `gap`, `partial_unproven`, `fixture_leak`, `silent_route_downgrade`, `deterministic_answer_leak`, `stale_context_answer`, `hidden_cot_leak`, `trace_leak`, `monolithic_module_debt`, or ownerless `blocked_with_owner`.

## Required Matched Prompts

Run each prompt through the reference UI and then through Autopilot.

Current and investment:

```text
which is a better investment, filecoin or akash network?
Which is a better investment right now, Akash or Filecoin? Use current sources.
Compare Filecoin and Akash Network as DePIN investments, including current price, market cap, seven-day performance, and risks.
```

Educational and sourced:

```text
Create an HTML file that explains quantum computers.
Create a website that explains post-quantum computers.
Create a website that explains post-quantum cryptography versus post-quantum computers, with sources.
Create an HTML file about photonic quantum computing and use sources.
```

Repository and tool harness:

```text
Call some tools and explore this repository, then summarize what you learned.
Explore this disposable app repo and summarize the architecture.
Find where the API base URL is configured in this repo.
Fix the failing test in this repo and explain the change.
```

Direct Ask:

```text
Explain recursion in two paragraphs and one tiny JavaScript example.
Explain post-quantum cryptography versus post-quantum computers.
Write a short tagline for a quantum computing learning site.
```

Artifact iteration:

```text
Create a website artifact about postquantum computers with a dark cyber-scientific design.
Make the website denser, with a stronger first section and fewer decorative cards.
Show this code change as a reviewable patch artifact and apply it only after approval.
```

## Stage 0: Campaign Seed And Baseline

Purpose: capture the current state without repeating old campaigns.

Actions:

1. Create the evidence root.
2. Record dirty worktree state without reverting user work.
3. Record current model registry, product-visible models, selected model, route, loaded model workers, and loaded-count truth.
4. Record current file size inventory for product/runtime/GUI harness files.
5. Launch Autopilot and capture baseline screenshots:
   - chat surface;
   - model picker;
   - inference settings, if present;
   - context remaining indicator, if present;
   - response metrics, if present;
   - source strip/actions, if present;
   - tracing/run surface location.
6. Run one current failure prompt and capture the failure.
7. Kill all processes and record cleanup proof.

Exit criteria:

- Baseline manifest exists.
- Failure classes are named with evidence.
- File size and module-boundary baseline exists.

## Stage 1: Reference UI Discovery

Purpose: understand observable behavior before changing Autopilot.

Actions:

1. Launch the reference web UI.
2. Click through:
   - model selector;
   - chat input controls;
   - thinking toggle;
   - search toggle;
   - code/tool toggle;
   - inference/model settings;
   - response action icons;
   - source display;
   - context remaining display;
   - conversation history.
3. Run at least three matched prompts:
   - one investment/current prompt;
   - one sourced website prompt;
   - one tool/repository prompt.
4. Capture screenshots at each visible state.
5. Record the event flow as observed by the user, not internal speculation.
6. Kill reference processes and verify cleanup.

Exit criteria:

- Reference behavior notes are written under the evidence root.
- Screenshots cover source strip, response actions, context remaining, and inference settings.
- Gaps are mapped to Autopilot stages below.

## Stage 2: Reverse-Engineering Crosswalk

Purpose: convert reference notes into Autopilot-native implementation requirements.

Actions:

1. Read `internal-docs/reverse-engineering/unsolth/`.
2. Map the reference primitives to Autopilot primitives:
   - model load/generation serialization;
   - streaming token path;
   - reasoning stream mapping;
   - tool call loop;
   - web search/read behavior;
   - final model synthesis after tool results;
   - metadata and tokens/sec;
   - cancellation and cleanup.
3. Record what should be absorbed, rejected, or already exists.
4. Explicitly mark any reference behavior that is only visual and should not move into the daemon.

Exit criteria:

- Crosswalk markdown exists in evidence.
- Every selected requirement has an owner layer: daemon, shared runtime contract, extension adapter, or webview presentation.

## Stage 3: Deterministic Synthesis Purge

Purpose: remove the main cause of low-quality, repetitive answers.

Actions:

1. Search for deterministic product answer builders and fallback renderers:
   - `Story `;
   - `Briefing for`;
   - `What happened`;
   - `Run date`;
   - `Overall confidence`;
   - `Web retrieval summary`;
   - `Current market data suggests`;
   - canned artifact shells;
   - fixture markers;
   - local auto fallback copy.
2. Classify each occurrence:
   - product path;
   - test fixture;
   - evidence-only;
   - dead code.
3. Remove product-path deterministic synthesis.
4. Replace fallback answers with:
   - model synthesis after tool context;
   - clean model-authored blocker when source/model requirements are unmet.
5. Add regression tests that fail if banned phrases appear in product chat output.

Exit criteria:

- No product path emits deterministic summaries or canned fallback answers.
- Tests prove banned product strings cannot reach chat.
- Evidence can still retain diagnostics outside chat.

## Stage 4: Model-In-Loop Tool Synthesis

Purpose: make tools inform the model instead of replacing the model.

Required runtime loop:

1. Build typed context/tool plan.
2. Let the selected model decide tool calls where appropriate, within policy and budget.
3. Execute tools through daemon-owned contracts.
4. Append compact tool results into model conversation context.
5. Run a final streaming model pass.
6. Render the final answer from model output.

Actions:

- Implement or repair final synthesis after web, file, shell, and artifact tools.
- Ensure no tool-only successful turn ends without model-authored handoff unless the tool itself is the user-visible deliverable and a model handoff would be wrong.
- Add duplicate-tool prevention as model feedback, not deterministic substitution.
- Preserve policy gates and fail-closed behavior.

Exit criteria:

- Web-researched answers are model-authored after tool results.
- Tool-only deterministic answer paths are gone.
- Final answer streams instead of snapping in after completion.

## Stage 5: Web Research And Fresh Data Quality

Purpose: match the quality of sourced answers while staying reliable.

Requirements:

- Current/investment prompts require fresh source acquisition in Agent mode.
- Price/market cap/performance claims require quote-grade sources for both compared assets.
- If one asset lacks quote-grade data, either search again with a better query or state the limitation in model-authored text.
- Do not use stale article prices as current price.
- Do not print run date, confidence score, source timestamps, or retrieval internals in chat.
- Sources shown in chat should be human-readable titles/domains/links.

Actions:

1. Add typed `market_data_required` and `current_source_required` context decisions.
2. Prefer direct quote sources for price/market cap/performance.
3. Use article sources for qualitative narrative only.
4. Compact sources into model-ready notes with clear provenance.
5. Add tests for stale article price rejection.
6. Add live proof for Filecoin/Akash prompts.

Exit criteria:

- Current price and market cap are correct against fresh source evidence during the run.
- Model answer does not claim missing data as fact.
- Sources are displayed cleanly at the bottom.

## Stage 5A: Runtime-Wide Same-Disease Audit And Full Loop Migration

Purpose: after the visible quality failure reaches parity, audit the whole runtime
for the same class of disease instead of leaving deterministic branches hidden in
other lanes. This is a required migration gate, not optional cleanup: the final
verdict cannot claim the target state unless the product harness is loop-native
across every answer-producing lane that remains in scope. The end state is a
complete migration to model -> tool -> result -> model cycles for product
cognition, with deterministic layers retained only at the action boundary and in
supporting infrastructure.

Sequence constraint: first achieve and screenshot at least one representative
product-quality parity exemplar through Agent Studio, then use that proof as the
baseline for the runtime-wide crawl. Do not let the crawl drift into product
surface comparison; read harness-to-harness code paths and remove remaining
deterministic answer-shaping at the runtime contract level.

This sequence is deliberate: the first green exemplar proves the desired loop
shape in one real lane, but it is not the finish line. After that exemplar, the
campaign must move from product smoke alarm to runtime surgery and inspect every
answer-producing path for the same disease class. The crawl should prove that
Autopilot is not merely phrase-banning old symptoms, but has migrated the
underlying runtime toward selected-model cognition over typed tool results.

Post-exemplar mandate: once preliminary product parity is demonstrated, crawl
every inch of the Agent runtime, daemon adapters, queue processors, synthesis
helpers, artifact lanes, recovery paths, GUI projections, and supporting tests
for remnants of deterministic answer-shaping. The campaign is not complete
until product cognition is fully loop-native: `model -> governed tool -> typed
result -> model`, with deterministic code confined to enforcement,
observation, normalization, validation, receipts, traces, side-effect state,
cleanup, replay, typed-result shaping, and presentation metadata.

Migration target:

- `model -> governed tool -> typed tool result -> model` is the default cognitive
  cycle.
- Deterministic code may enforce policy, approval, receipts, traces,
  side-effect accounting, cleanup, normalization, output validation, and
  presentation metadata.
- Deterministic code must not replace iterative cognition, author product
  conclusions, decide final prose, fabricate blockers, or collapse a turn merely
  because one narrow evidence facet passed.
- The action boundary remains the wave-collapse boundary: policy verdicts,
  approvals, tool side effects, receipts, typed tool results, traces, replay, and
  cleanup are deterministic and auditable there; final user meaning returns to
  the selected model with those results in context.
- Deterministic layers are allowed to observe, enforce, normalize, validate,
  record, and clean up. They are not allowed to become the hidden author of the
  answer, the final recommendation, the human-facing blocker, or the artifact
  handoff.
- The runtime must not keep a parallel deterministic "answer compiler" for web,
  repo, shell, artifact, memory, browser/computer, or delegation lanes. Typed
  tool results may be normalized deterministically, but the selected model owns
  the final comparison, recommendation, explanation, artifact handoff, and
  blocker prose.
- A preliminary green web/currentness exemplar is not sufficient to close the
  campaign. After that exemplar passes, crawl every answer-producing runtime
  lane for hidden remnants of deterministic finalization, deterministic blockers,
  canned source compilers, template-shaped artifact handoffs, stale context
  fallbacks, and GUI-owned harness semantics.
- The final campaign verdict must explicitly state whether this migration is
  complete across the audited runtime. Anything less is `partial_unproven`, even
  if the first product-quality smoke test looks good.
- The audit must crawl every reachable answer-producing branch deeply enough to
  justify a `100_percent_loop_native_migration` manifest decision. Any remaining
  deterministic product finalizer, canned blocker, source-report compiler,
  artifact handoff template, or stale fallback is a P0 defect until removed,
  quarantined behind explicit test-only mode, or converted into typed
  action-boundary infrastructure that feeds the selected model.
- The audit must distinguish deterministic action-boundary collapse from
  deterministic answer-shaping. Collapse is correct for policy, approval, tool
  side effects, receipts, traces, typed result records, replay, cleanup, and
  validation. Collapse is a defect when it authors final product meaning,
  final comparison, recommendation, blocker prose, source report, artifact
  handoff, or user-facing summary.
- Preserve wave collapse at the action boundary only. Policy, tool approvals,
  receipts, trace records, side-effect state, cleanup, replay, and typed tool
  results may be deterministic. Product-facing conclusions, recommendations,
  comparisons, explanations, blockers, and artifact handoffs must be
  model-authored after the model sees those typed results.
- Test fixtures may contain old deterministic shapes only when they are
  explicitly rejection fixtures. Remove, rename, or quarantine fixtures that make
  legacy `Story`, `Briefing`, timestamp/confidence, canned blocker, or fixture
  artifact output look like an acceptable product path.

Definition of the disease:

- A tool or retrieval path completes by emitting deterministic product prose
  instead of feeding evidence back to the selected model.
- A narrow grounding gate declares success after one facet is satisfied while
  discarding other context the user objective needs.
- A fallback produces canned answer text, canned artifact source, source-list
  pseudo-answers, confidence/timestamp prose, or fixture output in product chat.
- A GUI or adapter layer owns harness semantics that should be daemon/runtime
  owned.
- A validation guard only bans phrases after the fact instead of fixing the
  acquisition/synthesis loop that created them.
- Unit tests repeatedly proving deterministic formatting contracts instead of
  proving loop behavior, model-authored finalization, typed result preservation,
  and benchmark/live quality outcomes.

Audit surface:

- web search/read/currentness;
- market/scalar data;
- workspace search/read and repo Q&A;
- file write/edit/delete handoffs;
- shell/test repair handoffs;
- browser/computer observation handoffs;
- artifact generation/revision/export;
- memory/search/context recall;
- delegation/subagent summaries;
- Ask/Agent boundary blockers;
- provider/model route fallback;
- cancellation/recover finalization;
- any remaining deterministic test fixture accidentally reachable from product.
- test-only harness scaffolding that still encodes obsolete product prose and
  increases the chance of compaction or future refactors reviving it.

Actions:

1. Search product runtime and GUI code for deterministic answer construction:
   `format!`/template paths that include user-facing conclusions, source-list
   summaries, canned blockers, fixture prose, static website shells, confidence
   lines, run timestamps, or hard-coded domain conclusions.
2. For each occurrence, classify:
   - evidence-only/test-only;
   - product validation guard;
   - product answer path requiring removal;
   - product UX presentation-only;
   - dead code.
3. Convert product answer paths to the generic harness shape:
   - context facet decision;
   - governed tool/evidence acquisition;
   - compact evidence notes;
   - model-in-loop final synthesis;
   - output validation and repair/acquire-more-context if needed.
4. Add focused tests for every converted lane that prove:
   - deterministic product strings cannot reach chat;
   - useful tool evidence is preserved for final model synthesis;
   - final product text is selected-model output or a model-authored blocker;
   - trace/evidence retains diagnostics outside chat.
5. Replace broad deterministic unit tests with smaller contract tests or
   benchmark/live proofs:
   - keep deterministic fixtures only for leak rejection, validation, and
     normalization;
   - remove tests whose expected value is canned final prose;
   - add harness-loop tests that verify model/tool/result/model sequencing,
     iteration caps, retry feedback, and typed result retention.
6. Refactor immediately if the converted lane is buried in a monolithic module or
   mixes planning, execution, synthesis, and presentation.
7. Add live GUI proof for at least one representative non-web lane after the web
   investment lane passes.

Exit criteria:

- A runtime-wide audit manifest exists under the evidence root.
- Every product answer-producing lane has an owner layer and classification.
- No known product lane still relies on deterministic answer synthesis.
- No known product lane uses a deterministic blocker when model-authored
  synthesis can still run with the available typed tool results.
- Every remaining deterministic product-adjacent helper is classified as
  enforcement, observation, normalization, receipt/trace, cleanup, policy, typed
  result shaping, or presentation-only.
- At least web/currentness, workspace repo Q&A, artifact generation, and shell/test
  repair have focused proof of the generic model-in-loop shape.
- Legacy deterministic fixtures are either removed or clearly quarantined as
  rejection-only fixtures with names that cannot be confused for product
  rendering paths.

## Stage 6: Source Strip And Response Actions

Purpose: absorb quality-of-life response affordances without trace clutter.

Chat response should include, when applicable:

- bottom source strip with title/domain chips;
- source hover/expand details;
- copy response action;
- retry/regenerate action;
- continue action when stopped by max tokens;
- open artifact/source/preview actions for artifacts;
- open run/tracing action that navigates to a separate surface, not a persistent chat side rail;
- bottom metrics row.

The source strip must not show:

- raw retrieval timestamps;
- confidence scores;
- trace ids;
- receipt ids;
- absolute file paths;
- JSON payloads.

Actions:

- Add or refine response action component in the existing workbench visual language.
- Move persistent Tracing side rail out of chat.
- Ensure traces remain available in Runs/Tracing.
- Add screenshots proving collapsed and expanded source states.

Exit criteria:

- Chat source display is product-facing.
- Trace remains separate and discoverable.
- No receipts or trace internals appear in the answer.

## Stage 7: Context Remaining And Inference Settings UX

Purpose: provide local-model usability controls comparable to modern local chat apps.

Requirements:

- Show remaining context in the top-right chat header when the active provider exposes enough information.
- If exact context is unavailable, show an honest approximate state or hide the indicator.
- Add an inference settings toggle/sidebar for the current chat route.
- Preserve the OpenVSCode look.
- Do not make the chat sidebar into a model-control dumping ground.

Inference settings should cover supported fields:

- model;
- provider/route;
- reasoning/thinking mode;
- context length;
- max output tokens;
- temperature;
- top-p;
- top-k;
- min-p where supported;
- repeat/presence/frequency penalties where supported;
- stop strings;
- structured output/tool mode where supported;
- CPU/GPU/load state where supported.

Actions:

- Route settings changes through daemon/shared contracts.
- Show unsupported fields as unavailable or omit them, not fake controls.
- Capture screenshots before and after changes.

Exit criteria:

- Context remaining display is truthful.
- Inference settings round-trip to daemon invocation payloads.
- GUI owns presentation only.

## Stage 8: Streaming UX Completion

Purpose: make the response feel alive while work happens.

Requirements:

- Stream provider-visible thinking where available.
- Use concise runtime planning only when provider-visible thinking is absent.
- Show sequential tool rows as calls occur.
- Show source/content streaming for generated HTML, Markdown, code, and artifacts.
- Stream the final answer after tools.
- Collapse work rows into `Worked for Xs` after completion.
- Markdown must render inline and block syntax correctly.

Forbidden:

- abstract narration such as "Preparing governed Agent run";
- pill tags replacing the actual stream;
- raw tool payloads;
- hidden chain-of-thought;
- deterministic handoff text.

Exit criteria:

- Screenshots prove live thinking/tool/content/final streaming for every golden prompt family.
- Markdown renders in final answers.

## Stage 9: Artifact Quality And Auto-Detection

Purpose: artifact generation should produce the actual requested deliverable.

Requirements:

- If the model emits valid HTML/CSS/JS, package it as a website artifact.
- If the model emits Markdown/report/diff/table payloads, package them as typed artifacts when appropriate.
- Artifact auto-detection must be typed and validated, not prompt-specific.
- Invalid source should remain visible as streamed content with a clean error, not become a fake preview.
- No canned artifact shells.

Actions:

- Stream artifact source from model output.
- Validate and create artifact records/revisions.
- Render preview from the generated source.
- Show handoff plus compact artifact embed.
- Add source/preview/export/revise actions.

Exit criteria:

- Website prompts produce real model-generated source and preview.
- Artifact source matches model output.
- No fixture marker or fallback shell is present.

## Stage 10: Ask Versus Agent Behavior

Purpose: preserve the product contract while improving quality.

Rules:

- Ask is direct model chat.
- Ask does not claim to have fresh data or use tools unless explicitly supported by an Ask retrieval feature.
- Agent is governed harness execution with tools, policy, receipts, traces, and artifacts.
- Agent may gather context by default when context improves correctness.

Required proof:

- Ask stable conceptual answer.
- Ask current query cleanly explains it needs fresh retrieval or routes user to Agent behavior.
- Agent current query retrieves and answers.
- Agent repo query searches/reads the opened user-like workspace.
- Agent artifact query creates artifact.

Exit criteria:

- No responsibility mixing.
- Quality improvements do not turn Ask into hidden Agent.

## Stage 11: Product Model And Fixture Hygiene

Purpose: keep product routing clean.

Requirements:

- Model picker shows only product-usable chat models by default.
- Story, embedding, fixture, and test-only models are hidden from product chat unless an explicit developer/test mode is active.
- Loaded model counts reflect live model workers, not artifacts or stale slots.
- Selected route, route receipt, model invocation, and metrics agree.

Actions:

- Re-audit product model registry after any quality changes.
- Add tests for selector filtering and loaded-count truth.
- Capture GUI evidence.

Exit criteria:

- No product-visible fixture route.
- No impossible loaded model count.

## Stage 12: Modularization And Refactor Checkpoint

Purpose: prevent context-window drift and make the harness easy to traverse.

Mandatory checks:

1. List every touched product/runtime/GUI harness file and LOC count.
2. Any touched file over 2000 LOC must be split or explicitly proven generated/vendored/non-harness.
3. Any module mixing more than one ownership concern must be split.
4. Any broad rename must be product-native and avoid reference-substrate names.
5. Add tests for extracted modules before continuing.

Refactor candidates:

- context planner;
- web retrieval planning;
- market data extraction;
- model-in-loop synthesis;
- deterministic fallback removal guards;
- response/source strip rendering;
- response metrics rendering;
- inference settings adapter;
- artifact source detection;
- artifact preview lifecycle;
- chat Markdown rendering;
- scenario/evidence runners.

Preferred boundaries:

- `context/` owns typed context frames and budgets;
- `research/` owns search/read/quote acquisition and source compaction;
- `synthesis/` owns model-in-loop answer generation and forbidden fallback guards;
- `artifacts/` owns artifact records, source detection, validation, and preview;
- `streaming/` owns event normalization;
- `presentation/` owns webview rendering only;
- `metrics/` owns token/timing display data;
- `tests/fixtures/` owns deterministic fixtures, never product runtime branches.

Exit criteria:

- No touched harness file over 2000 LOC remains unresolved.
- Module ownership map is written.
- Refactors have tests and live smoke proof.

## Stage 13: Golden Quality Matrix

Purpose: prove behavior, not isolated fixes.

Run the required matched prompts through consecutive reference and Autopilot cycles.

For each prompt, compare:

- answer completeness;
- factual correctness;
- source freshness;
- model-authored naturalness;
- stream behavior;
- source strip/actions;
- metrics;
- latency;
- artifact deliverable where applicable.

Exit criteria:

- Every P0 prompt is `quality_match_pass`, `fixed_then_pass`, or has an explicit product decision.
- No deterministic answer leakage.
- No stale-source answer.

## Stage 14: Integrated Soak

Purpose: catch stale state, cache leaks, and repeated-template regressions.

Run a mixed sequence across fresh sessions:

1. Ask direct conceptual answer.
2. Agent current investment answer.
3. Agent sourced website artifact.
4. Agent repo exploration.
5. Agent code edit/test repair.
6. Agent artifact revision.
7. Ask currentness boundary.
8. Model unload/reload.
9. Repeat investment prompt with different wording.
10. Repeat website prompt with a different topic.

Checks:

- no repeated deterministic structure;
- no stale source reuse;
- no previous-topic artifact leak;
- no route downgrade;
- no fixture model leak;
- no loaded-count inflation;
- no process leftovers;
- no hidden trace data in chat;
- no unexplained spinner-only wait over 30 seconds.

Exit criteria:

- Soak passes or every blocker is fixed and rerun.

## Final Deliverables

Finish by writing:

- `docs/evidence/autopilot-agent-studio-quality-harness-runtime-parity/quality-harness-runtime-final-manifest.json`
- `docs/evidence/autopilot-agent-studio-quality-harness-runtime-parity/final-quality-harness-runtime-verdict.md`

The final verdict must honestly state whether `agent_studio_quality_harness_runtime_parity_proven` is achieved.

The verdict must include:

- evidence paths;
- screenshot paths;
- reference comparison summary;
- row classifications;
- source quality findings;
- deterministic purge findings;
- fixes applied;
- refactors performed;
- files split or renamed;
- product decisions;
- remaining blockers, if any, with owner and next proof step.

## Launch Prompt

Use this prompt to run the campaign:

```text
/goal Run the Autopilot Agent Studio Quality Harness Runtime Parity campaign described in .internal/plans/autopilot-agent-studio-quality-harness-runtime-parity-master-guide.md.

Work autonomously until the target end state is achieved and validated: agent_studio_quality_harness_runtime_parity_proven.

Focus on behavioral quality parity and Autopilot-native harness improvement. Do not repeat broad catalogue testing, default harness rediscovery, or unrelated substrate campaigns except as focused regression proof.

Use fresh evidence under docs/evidence/autopilot-agent-studio-quality-harness-runtime-parity/.

Launch the reference web UI and Autopilot one at a time. For each matched scenario, capture screenshots and findings from the reference UI, kill it and verify cleanup, then launch Autopilot Agent Studio, run the matched prompt, capture screenshots/traces/receipts/route decisions/source lists/metrics/cleanup proof, and update the manifest.

Use internal-docs/reverse-engineering/unsolth/ to crosswalk observable reference behavior into Autopilot-native runtime changes. Do not use the reference engine inside Autopilot.

Remove deterministic product synthesis and fallback answers entirely. Product answers must be model-authored after tool/context acquisition or cleanly fail with a model-authored blocker. No Story 1, Briefing for, What happened, Web retrieval summary, run timestamp, confidence score, canned artifact page, fixture marker, local:auto fallback, or other deterministic report scaffolding may appear in product chat.

Improve the Agent Studio UX while preserving the OpenVSCode look: streamed thinking/planning, sequential live tool rows, streamed generated source/content, streamed final answer tokens, collapsed Worked-for summary, clean handoff, artifact deliverables, bottom source strip, response action icons, response metrics, context remaining top-right, and inference settings toggle/sidebar. Tracing belongs in its own surface, not as a persistent chat side rail.

Keep Ask as direct model answers and Agent as governed harness execution. Agent should gather bounded context by default when it improves correctness, including fresh web/market data for current or investment prompts and workspace search/read for user-like repo prompts.

After the visible quality failure reaches parity, audit the entire runtime for the same disease: deterministic product prose, narrow evidence gates that discard useful context, canned blockers/artifacts, GUI-owned harness semantics, and phrase-ban patches that do not repair the underlying acquisition/synthesis loop. Crawl every product answer lane, worker handoff lane, artifact handoff lane, web/currentness lane, repo-question lane, browser/computer lane, and recovery/escalation lane for remnants of deterministic answer-shaping. Convert affected product lanes to the generic context-facet -> governed tools -> compact evidence -> selected-model synthesis -> validation shape. Treat this as a required migration gate: the runtime must be `model -> tool -> typed result -> model` native across product answer lanes, with deterministic layers limited to enforcement, observation, normalization, policy, receipts, traces, side effects, cleanup, typed-result shaping, and presentation metadata.

Preserve the action boundary as the deterministic wave-collapse boundary: policy, approvals, receipts, traces, typed tool results, side effects, cleanup, replay, and evidence records are deterministic there. Do not let that boundary author final product meaning. Final comparisons, recommendations, explanations, artifact handoffs, and blockers must come from the selected model after it sees the typed results.

During the runtime-wide audit, remove or quarantine deterministic test fixtures that encode obsolete product prose. Keep fixed fixtures only for rejection, validation, normalization, and leak-prevention tests. Replace canned-prose unit expectations with harness-loop proofs, benchmark/live quality checks, or contract tests that verify `model -> tool -> result -> model` sequencing and typed-result preservation.

Refactor immediately if files become monolithic or module boundaries become unintuitive. Any touched product/runtime/GUI harness file over 2000 LOC must be split or justified as generated/vendored/non-harness before the final verdict.

No P0 row may remain gap, partial_unproven, fixture_leak, silent_route_downgrade, deterministic_answer_leak, stale_context_answer, hidden_cot_leak, trace_leak, monolithic_module_debt, or ownerless blocked_with_owner.

Kill Autopilot, runtime bridge, daemon, model workers, preview servers, browser sessions, reference UI server, reference model workers, shell/test child processes, and fixture servers after every live scenario and record cleanup proof.

Do not hand back with prose only. Finish by writing:
- docs/evidence/autopilot-agent-studio-quality-harness-runtime-parity/quality-harness-runtime-final-manifest.json
- docs/evidence/autopilot-agent-studio-quality-harness-runtime-parity/final-quality-harness-runtime-verdict.md

The final verdict must honestly state whether agent_studio_quality_harness_runtime_parity_proven is achieved, with evidence paths, screenshots, row classifications, fixes, refactors, product decisions, and every remaining blocker if any.
```

## Latest Validation

Status: Blocked

Evidence: `docs/evidence/autopilot-agent-studio-quality-harness-runtime-parity/stage3-currentness-retrieval/2026-05-31T08-23-49-910Z/`

Root cause: the earlier harness validated focus and daemon turn completion, but it did not prove model-backed token streaming and allowed canned Agentgres run projections to masquerade as assistant answers. Studio now routes chat through daemon-owned `/v1/chat/completions` streaming, and this harness rejects canned daemon projections.

Queries tested: pending.

Remaining blockers: Assistant response did not render for prompt: Which is a better investment right now, .

Connector sprint readiness impact: Agent Studio chat focus and prompt submission are Playwright-controlled and daemon-routed; connector work remains dry-run only.
