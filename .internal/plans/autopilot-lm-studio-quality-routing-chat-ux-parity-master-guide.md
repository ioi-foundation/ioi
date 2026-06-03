# Autopilot LM Studio Quality, Model Routing, And Chat UX Parity Plus Master Guide

Owner: Autopilot Workbench / Agent Studio / Runtime Daemon / Model Runtime / Artifact Runtime / Chat UX / Runs / Tracing / Evidence Runtime

Status: active planning guide

Created: 2026-05-28

Primary references:

- `.internal/plans/autopilot-conversation-artifact-embedded-document-canvas-master-guide.md`
- `.internal/plans/autopilot-headless-runtime-unification-parity-master-guide.md`
- `.internal/playbooks/substrate-absorption-rubric-playbook.md`
- `.ioi/autopilot-daemon/conversation-artifacts/records/artifact_static-html-js_b5d33604f72f.json`
- `.ioi/autopilot-daemon/receipts/receipt_model_invocation_2d4eb8be-dc70-465b-819e-8154e80ba00e.json`
- `/home/heathledger/.lmstudio/conversations/1779941075092.conversation.json`
- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js`
- `packages/runtime-daemon/src/model-mounting.mjs`

## Executive Intent

Autopilot must be able to meet or exceed LM Studio on the same underlying model
for ordinary product-facing chat and generated artifact requests.

The current failure mode is not subtle:

```text
User: Create a website that explains postquantum computers.

LM Studio:
  qwen/qwen3.5-9b
  thinking enabled
  3863 generated tokens
  complete explanation
  complete HTML/CSS website source
  visible generation stats

Autopilot:
  user-facing selector implied qwen/qwen3.5
  artifact generation silently routed model=auto
  route.local-first selected local:auto
  backend ioi_fixture produced 19 completion tokens
  fixture text was accepted into a website artifact
```

This guide targets three legs:

```text
1. Quality parity
   Same model, same prompt, same settings class, comparable answer depth,
   comparable generated code/artifact quality, no deterministic fixture leakage.

2. Model mounting and routing configurables parity
   Autopilot exposes and honors the same important model/load/sampling/reasoning
   controls LM Studio exposes, plus daemon-owned route truth and no silent
   downgrade to fixtures.

3. Chat UX parity plus
   Autopilot matches the useful LM Studio chat affordances while preserving
   Autopilot's stronger harness contract: streaming thinking/work/tool rows,
   collapsible work summaries, clean final answers, artifact embeds, and
   response metrics at the bottom of completed turns.
```

The target is not to clone LM Studio's product. LM Studio is a light local model
chat shell. Autopilot is an IDE agent harness with policy, traces, tools,
artifacts, and daemon ownership.

The target is that Autopilot must not lose model quality, controllability, or
human readability merely because it has a stronger harness.

## Visual Boundary

Do not change Autopilot into an LM Studio-looking chat app.

Agent Studio should keep the VS Code/OpenVSCode workbench feel:

- command-center and editor-shell density
- dark workbench styling
- native sidebars and panels
- compact IDE controls
- code/workflow/operator affordances
- restrained typography and spacing

The campaign should absorb missing capabilities as components, not as a visual
reskin. Good examples:

- add a bottom response metrics row
- add a collapsible thinking section when the provider exposes thinking
- add richer model/config popovers or settings drawers
- add clear model route truth summaries
- add artifact source/preview actions
- add clean work-row components for tool activity

Bad examples:

- replacing the Agent Studio transcript with LM Studio's layout
- copying LM Studio spacing, colors, icons, or settings panel design
- making the left rail a chat-only app shell
- moving trace/debug details into product chat
- turning model settings into a large always-visible right panel unless that is
  a deliberate Autopilot workbench panel decision

The correct product shape is:

```text
Autopilot workbench shell
  Agent Studio chat rail
    VS Code-native transcript styling
    added model/thinking/metrics/artifact components where useful
  Runs/Tracing panels
    deep receipts, route decisions, logs, evidence
  Models panel
    full model mounting/routing/configuration depth
```

## Core Product Principle

The model picker and response UI must tell the truth.

If the UI says qwen, the model receipts for that turn must say qwen. If the
runtime cannot use qwen, the user must see a direct blocked/unavailable state.
Autopilot must never silently replace a product turn with `local:auto`,
`autopilot:native-fixture`, `stories260k`, or another deterministic fixture.

Fixture models are allowed only in tests and explicit fixture proof campaigns.
They are not product fallback.

## Engine Ownership Boundary

LM Studio is a reference implementation for this campaign, not an Autopilot
runtime dependency.

Autopilot may inspect LM Studio behavior, screenshots, logs, conversation JSON,
and public/local API behavior to understand the desired quality, configuration,
metrics, and chat UX shape. Autopilot must not ship by calling LM Studio's
engine inside the product path.

Missing primitives must be ported into Autopilot-native runtime ownership:

- daemon-supervised local inference processes
- Autopilot-owned provider and backend drivers
- daemon-owned route decisions and model invocation receipts
- Autopilot-owned sampling/load/reasoning/config contracts
- Autopilot-owned metrics and streaming event projections
- fixture-free fail-closed behavior for product turns

It is acceptable to use LM Studio as an oracle during comparison cycles. It is
not acceptable for the final parity proof to depend on LM Studio GUI, LM Studio
daemon, or LM Studio model workers being available.

## Definition Of Done

The campaign is complete only when the final verdict can honestly state:

```text
lm_studio_quality_routing_chat_ux_parity_plus_proven
```

Required conditions:

- The same realistic prompts run through LM Studio and Autopilot with the same
  model family and comparable settings.
- Each app is launched and inspected one at a time. Do not run LM Studio GUI and
  Autopilot GUI concurrently when the GPU cannot carry both.
- Every GUI run has screenshots of the prompt, settings/model selection, live
  generation state, final response, metrics, and any artifact preview.
- LM Studio behavior is captured from GUI screenshots, conversation JSON,
  logs, public local API behavior where available, and source/resource search
  where legally and practically applicable.
- Autopilot behavior is captured from GUI screenshots, daemon receipts, traces,
  model route decisions, model invocation receipts, artifact records, and logs.
- Autopilot Ask mode can produce a direct answer comparable to LM Studio for
  pure chat requests.
- Autopilot Agent mode can produce a real artifact comparable to LM Studio's
  generated code output for artifact requests.
- Autopilot preserves selected model identity through Agent thread creation,
  Ask streaming, artifact generation, rebuild, edit, and export paths.
- Autopilot exposes the actual selected provider, endpoint, model, route,
  fallback policy, reasoning mode, and sampling/load settings in product UX or
  trace surfaces as appropriate.
- Product chat never shows raw fixture markers, raw filesystem scaffolding,
  receipt ids, JSON payloads, route payloads, or trace details by default.
- Product chat shows useful bottom-of-response metrics comparable to LM Studio:
  model, generated tokens, elapsed time, tokens/sec, stop reason, and optionally
  time-to-first-token when available.
- Thinking streams, tool/work rows, work-summary capsules, final answers, and
  artifacts render in a human-readable transcript.
- No P0 row remains `gap`, `partial_unproven`, `fixture_leak`,
  `silent_route_downgrade`, or ownerless blocked.

## Evidence Root

Generate fresh evidence under:

```text
docs/evidence/autopilot-lm-studio-quality-routing-chat-ux-parity/
```

Final outputs:

```text
docs/evidence/autopilot-lm-studio-quality-routing-chat-ux-parity/lm-studio-quality-routing-chat-ux-final-manifest.json
docs/evidence/autopilot-lm-studio-quality-routing-chat-ux-parity/final-lm-studio-quality-routing-chat-ux-verdict.md
```

Supporting evidence should be grouped by timestamped scenario directories:

```text
docs/evidence/autopilot-lm-studio-quality-routing-chat-ux-parity/
  2026-05-28T.../
    lm-studio/
      screenshots/
      conversation.json
      settings.json
      logs/
      source-search-notes.md
    autopilot/
      screenshots/
      receipts/
      traces/
      artifact-records/
      model-route-decisions/
      logs/
    comparison/
      prompt.md
      rubric.json
      verdict.md
      diff-notes.md
      cleanup.json
```

## GPU And Process Discipline

The GPU cannot reliably carry both GUI apps at once. The campaign must use this
cycle:

```text
1. Launch LM Studio only.
2. Capture LM Studio GUI/settings/output/evidence.
3. Stop LM Studio and verify no LM Studio model workers remain.
4. Launch Autopilot only.
5. Capture Autopilot GUI/settings/output/evidence.
6. Stop Autopilot, runtime bridge, daemon, model workers, preview servers, and
   spawned helpers.
7. Verify cleanup before the next scenario.
```

If Autopilot needs the same model through LM Studio-compatible HTTP, use one of
these approaches and record the decision:

- Prefer an Autopilot-native model backend pointing at the same model artifact
  or an equivalent local runtime, so the LM Studio GUI does not need to stay
  open.
- If an LM Studio local server is the only way to access the model, run it as an
  explicit backend dependency for that scenario and do not run the full LM
  Studio GUI at the same time. Record this as `supporting_pass_with_product_decision`
  until Autopilot-native mounting is proven.
- Never let Autopilot silently fall back to a fixture because the preferred
  backend is unavailable.

Every live scenario must include process cleanup proof:

```text
ps -ef filtered for:
  lm-studio
  lms
  autopilot
  runtime-daemon
  openvscode
  electron
  node model worker
  llama.cpp / ollama / vllm
  preview servers
```

## Clean-Room Boundary

Use LM Studio as behavioral reference and interoperability target.

Allowed:

- GUI screenshots
- user-visible settings
- conversation JSON exported or stored by the user's local app
- local logs
- local HTTP API probes
- source/resource search where the installed package exposes readable
  configuration or prompt templates
- public documentation if needed

Not allowed:

- copying proprietary UI assets
- copying proprietary source implementation
- depending on private LM Studio internals as a production runtime contract
- shipping LM Studio-specific hacks instead of daemon-owned provider adapters

Autopilot should absorb product and runtime lessons into IOI-native contracts.

## Row Classifications

Use these classifications in the manifest:

- `live_pass`
- `fixed_then_pass`
- `headless_pass`
- `cross_client_pass`
- `supporting_pass`
- `supporting_pass_with_product_decision`
- `quality_match_pass`
- `routing_truth_pass`
- `mounting_config_pass`
- `ux_parity_pass`
- `metric_parity_pass`
- `policy_gate_pass`
- `sandbox_effect_pass`
- `rejected_with_product_decision`
- `deferred_optional`
- `blocked_with_owner`
- `partial_unproven`
- `gap`
- `fixture_leak`
- `silent_route_downgrade`

No P0 row may remain `gap`, `partial_unproven`, `fixture_leak`,
`silent_route_downgrade`, or ownerless blocked.

## Manifest Row Schema

Each row should include:

```json
{
  "id": "quality.website.postquantum.same-model",
  "priority": "P0",
  "leg": "quality",
  "scenario": "postquantum website",
  "lmStudioEvidence": {
    "screenshots": [],
    "conversationJson": "",
    "settings": {},
    "logs": []
  },
  "autopilotEvidence": {
    "screenshots": [],
    "receipts": [],
    "traceRefs": [],
    "artifactRecords": [],
    "routeDecision": ""
  },
  "expected": "",
  "actual": "",
  "classification": "quality_match_pass",
  "owner": "model-runtime",
  "fixRefs": [],
  "remainingRisk": ""
}
```

## Quality Rubric

Do not expect byte-identical output. Quality parity means the Autopilot answer
is in the same class of usefulness as LM Studio under comparable conditions.

For generated website prompts, require:

- real selected model, not fixture
- reasoning mode respected
- prompt-specific interpretation
- human-readable design intent
- complete HTML/CSS/JS source or artifact source
- artifact preview actually reflects the generated source
- no generic topic-swap template unless the prompt explicitly asks for a simple
  template
- no fixture markers
- no raw local paths in product chat
- no “created artifact” final with unusable content
- if Autopilot chooses artifact-first UX, source and preview must be available
  directly from the artifact

For direct chat prompts, require:

- direct model answer in Ask mode
- no harness/tool scaffolding in the answer
- no forced artifact projection
- comparable answer depth to LM Studio
- streaming tokens visible during generation
- final metrics visible below the answer

For agent prompts, require:

- work rows as tools/actions occur
- collapsible `Worked for Xs` summary after completion
- clean final handoff message
- artifacts or diffs rendered as embeds when created
- traces/receipts only in Runs/Tracing/evidence

## Model Routing Truth Requirements

Autopilot must track and expose:

- requested route
- requested model
- requested endpoint when explicit
- selected model
- selected endpoint
- selected provider
- selected backend
- fallback allowed
- fallback triggered
- fallback reason
- denied providers
- provider eligibility
- privacy posture
- local/remote placement
- route policy hash
- load instance id
- model invocation receipt
- response id / previous response id
- reasoning mode
- sampling parameters
- context/load parameters
- stream status
- stop reason
- token counts
- elapsed time
- tokens/sec

The product UI should show a compact truth summary; full details live in
Tracing.

Bad:

```text
Header says qwen/qwen3.5, artifact uses local:auto.
```

Good:

```text
qwen/qwen3.5-9b via LM Studio
Reasoning: Think
Temp 1.0 - top-p .95 - top-k 20
3863 tokens - 27.2 tok/s - stop: eos
```

## Model Mounting And Configurable Breadth

LM Studio exposes a broad operator model-control surface. Autopilot does not
need identical placement, but it must expose and honor equivalent controls
where they affect output quality, latency, routing, or reliability.

Audit and prove at least:

- model selection
- provider selection
- route selection
- explicit model versus auto route
- provider fallback policy
- local-only / privacy posture
- context length
- context overflow behavior
- CPU thread count
- GPU offload / acceleration policy where available
- flash attention / backend acceleration decision where available
- temperature
- top-p
- top-k
- min-p where supported
- repeat penalty
- presence penalty
- frequency penalty where supported
- stop strings
- max output tokens / limit response length
- structured output toggle
- tool-use mode
- reasoning / thinking mode
- vision capability where supported
- embeddings model selection
- model load/unload state
- tokens/sec and timing metrics

Classify unsupported settings:

- `mounting_config_pass` when Autopilot has an equivalent and proves it.
- `supporting_pass_with_product_decision` when the provider does not support
  the setting but Autopilot cleanly records that fact.
- `rejected_with_product_decision` when Autopilot intentionally does not expose
  a control because it conflicts with product direction.
- `gap` when the control matters and is missing.

## Chat UX Requirements

Autopilot should absorb LM Studio's useful chat UX features and combine them
with harness-aware affordances.

Required completed-turn layout:

```text
Assistant response

  [collapsible work summary]
  Worked for 42s - used 3 tools - created 1 artifact

  [clean final answer]
  Here is the website. I built it as a sandboxed artifact and included the
  source so you can revise it.

  [artifact embed when applicable]

  [bottom metrics]
  qwen/qwen3.5-9b - 3863 tokens - 27.2 tok/s - 141.9s - stop: eos
```

Required live-turn layout:

```text
Thinking...
  streamed thinking summary where model/provider exposes it

I'll inspect the relevant files.
Exploring 1 folder >

I'll draft the artifact source.
Using model qwen/qwen3.5-9b >

Working...
  streamed answer tokens as they arrive
```

Do not show phase tags such as:

```text
Thinking   Using tools   Preparing response
```

Do not show product users:

- `TOOLCAT_*`
- fixture markers
- raw route JSON
- raw receipt ids
- raw filesystem fixture paths
- daemon-internal scaffolding
- source hashes
- trace payloads

## Stage 0 - Seed Audit And Baseline Lock

Goal: lock the exact failure and baseline before changing anything.

Tasks:

- Record the current Autopilot failure artifact that contains
  `IOI model router fixture response from local:auto`.
- Record the current LM Studio reference conversation.
- Record all screenshots supplied by the user.
- Save the exact prompt strings:
  - `Create a website that explains postquantum computers`
  - `Create a website that explains post-quantum computers`
- Write an initial manifest with known P0 gaps:
  - fixture leakage into product artifact
  - silent route downgrade from qwen-selected thread to `auto`
  - artifact generator bypasses selected model
  - no bottom-of-response metrics parity
  - incomplete thinking/token streaming parity
  - insufficient model configurables parity

Evidence:

- screenshots of existing failure
- artifact record path
- model invocation receipt path
- LM Studio conversation JSON path
- source line references

Exit criteria:

- Baseline verdict says `not_parity`.
- Every known failure has an owner and next proof step.

## Stage 1 - LM Studio Behavioral Capture

Goal: capture LM Studio as the reference behavior.

Launch only LM Studio.

For each reference prompt:

- capture model picker
- capture settings panel
- capture system prompt state
- capture custom fields state
- capture sampling settings
- capture context settings
- capture reasoning/thinking controls
- capture live thinking stream
- capture live token stream
- capture final answer
- capture bottom/status metrics
- export/copy conversation JSON
- copy relevant logs
- probe local API only if the server is explicitly enabled

This stage is intentionally interactive. Click around the LM Studio app to
discover user-visible model and chat affordances, including:

- model picker
- model load/unload status
- settings drawer
- system prompt panel
- custom fields panel
- sampling controls
- context overflow controls
- structured output toggle
- reasoning/thinking controls
- vision/tool toggles
- conversation notes
- copy/regenerate/edit/delete actions
- split view or panel controls
- response stats and hidden/expanded thinking behavior
- local server/API controls if present

Capture screenshots before and after expanding each relevant affordance. The
purpose is not to copy the UI. The purpose is to identify the component-level
capability Autopilot should support in its own workbench visual language.

Search readable LM Studio app resources where applicable for:

- prompt template
- reasoning toggle mapping
- parameter names
- model list source
- response metrics source
- conversation persistence format

Do not copy implementation. Summarize behavior.

Exit criteria:

- A `lm-studio-reference-profile.json` exists with model, settings, prompt
  template observations, metrics, and screenshots.
- The reference answer quality is summarized in a rubric file.

## Stage 2 - Autopilot Current-State Reproduction

Goal: reproduce Autopilot's behavior through the real GUI.

Launch only Autopilot and its required daemon/runtime processes.

Run the same prompt in:

- Ask mode
- Agent mode
- Agent artifact mode

Capture:

- model selector state
- route selector state
- reasoning selector state
- permission state
- live transcript
- final transcript
- artifact embed
- expanded artifact view
- bottom metrics if present
- Runs/Tracing handoff
- daemon receipts
- route decisions
- model invocation receipts
- artifact records
- cleanup proof

Exit criteria:

- The reproduction identifies whether the selected model is preserved or
  downgraded.
- The manifest marks each run as `live_pass`, `fixture_leak`,
  `silent_route_downgrade`, or another concrete classification.

## Stage 3 - Route Truth And Fixture-Fail-Closed Fix

Goal: make silent fixture fallback impossible for product chat.

Requirements:

- If the user explicitly selected qwen, artifact generation must call qwen.
- If the selected provider is unavailable, show a product error and trace
  receipt, not fixture content.
- `route.local-first` may have test fallback only when the scenario is
  explicitly marked fixture/test.
- `local:auto` and `autopilot:native-fixture` must be hidden from product model
  choices unless a developer/test flag is active.
- The artifact generator must reject fixture text before creating or rebuilding
  an artifact.
- The model selector must display the actual selected model/endpoint after route
  resolution.

Focused tests:

- explicit qwen stays qwen through Ask
- explicit qwen stays qwen through Agent thread
- explicit qwen stays qwen through artifact generation
- unavailable qwen blocks visibly
- fixture marker cannot enter artifact source

Exit criteria:

- No product path can generate a user-visible artifact from fixture output.
- Route receipts and UI agree.

## Stage 4 - Model Mounting Breadth Audit

Goal: compare Autopilot's model management surface with LM Studio's useful
model management breadth.

LM Studio reference rows:

- loaded model
- model search/list
- local model path
- context length
- CPU threads
- GPU offload/acceleration
- model load status
- model unload/eviction
- embeddings if present
- OpenAI-compatible local server state

Autopilot rows:

- local GGUF import/mount/load/unload
- LM Studio discovered provider
- Ollama provider
- vLLM provider
- OpenAI-compatible provider
- local folder provider
- native local provider
- embeddings model
- route.local-first
- route.native-local
- explicit endpoint selection
- auto route behavior
- fallback behavior
- load policy and idle eviction

Exit criteria:

- Every model/mounting row is classified.
- P0 product rows have live proof or concrete product-scope decision.

## Stage 5 - Sampling, Reasoning, And Load Config Mapping

Goal: prove Autopilot can send and record the settings that shape answer
quality.

For qwen/qwen3.5-9b, map LM Studio controls to Autopilot request fields:

- temperature
- top_p
- top_k
- min_p
- repeat_penalty
- presence_penalty
- frequency_penalty
- stop strings
- max_tokens
- context length
- context overflow policy
- CPU threads
- GPU offload
- reasoning/thinking mode
- tool mode
- structured output

For each setting:

- identify LM Studio UI label
- identify LM Studio persisted config key when available
- identify OpenAI-compatible request field when available
- identify Autopilot daemon contract field
- identify receipt field
- identify UI location
- prove a live invocation or record why provider support is absent

Exit criteria:

- `model-configurable-mapping.json` exists.
- Autopilot can run the reference prompt with LM Studio-equivalent settings.

## Stage 6 - Thinking And Streaming Parity

Goal: make Autopilot's live response feel as transparent as LM Studio without
dumping raw harness internals.

Requirements:

- If the provider streams thinking/reasoning, Autopilot renders it in a
  collapsible thinking section.
- If reasoning is disabled, Autopilot clearly records `Reasoning off`.
- Tokens stream into the answer as they arrive.
- Tool/work rows stream between thinking and answer where applicable.
- Work rows collapse after completion into a summary capsule.
- Trace details remain in Tracing.

Test prompts:

- direct educational answer
- generated website
- code exploration with tool use
- artifact edit/rebuild

Exit criteria:

- Screenshots prove live thinking, live work rows, live answer token streaming,
  collapsed summary, and clean final answer.

## Stage 7 - Direct Ask Quality Parity

Goal: Ask mode should match LM Studio direct-chat quality.

Run at least:

- `Create a website that explains postquantum computers`
- `Explain post-quantum cryptography to a high-school student`
- `Write a compact HTML landing page about neutral atom quantum computers`
- `Compare photonic quantum computers and superconducting quantum computers`

For each:

- LM Studio reference run
- Autopilot Ask run with same model/settings
- side-by-side quality rubric
- screenshots
- metrics
- route receipts

Exit criteria:

- Autopilot Ask produces comparable direct answers with no harness leakage.
- Bottom metrics match LM Studio's useful metric breadth.

## Stage 8 - Agent Artifact Quality Parity

Goal: Agent mode should produce the thing, not a canned summary.

Run realistic artifact prompts:

- `Create a website that explains postquantum computers.`
- `Make the website more cyber-scientific and add a roadmap section.`
- `Export the page source and show me the preview.`
- `Revise the intro to clarify post-quantum cryptography versus post-quantum computers.`

Requirements:

- Agent may produce a concise handoff message, but the artifact source must
  contain the model-authored content.
- The generated artifact must be viewable in compact and expanded preview.
- The source must be inspectable.
- The preview must update after edits.
- Build/conversion logs stay in Tracing.

Exit criteria:

- Autopilot artifact quality is comparable to LM Studio's generated HTML answer
  while preserving Autopilot artifact UX.

## Stage 9 - Artifact Extraction And Projection

Goal: safely convert model-authored output into artifacts without destroying
quality.

Implement/prove a two-phase path:

```text
Phase 1: real model draft
  stream model answer/source
  preserve source text
  record route/settings/metrics

Phase 2: artifact projection
  extract complete HTML/CSS/JS or structured artifact content
  sandbox preview
  create artifact record/revision
  show source and preview
```

Hard requirements:

- No fallback from a poor model answer to a fake template unless explicitly
  marked as an error/recovery state.
- If extraction fails, show a clean failure and preserve the model answer.
- If model output is prose plus code, preserve both.
- If model output is structured JSON, preserve the raw source in trace/evidence
  and show clean artifact state.

Exit criteria:

- The same LM Studio-style generated HTML can become an Autopilot artifact
  without losing content.

## Stage 10 - Response Metrics Parity

Goal: show useful generation stats at the bottom of Autopilot responses.

Required metrics:

- model
- provider
- route
- reasoning mode
- generated tokens
- prompt tokens when available
- total tokens when available
- elapsed time
- tokens/sec
- stop reason
- time to first token when available
- stream/cancel status

UX shape:

```text
qwen/qwen3.5-9b via LM Studio - Think - 3863 tokens - 27.2 tok/s - 141.9s - stop: eos
```

Trace link may sit beside the metrics, but raw receipts must not.

Exit criteria:

- Completed Ask and Agent turns show response metrics.
- Metrics match daemon receipts and provider usage.
- Missing provider metrics degrade gracefully with clear labels.

## Stage 11 - Chat Transcript Parity Plus

Goal: make the chat transcript feel better than LM Studio for agent work while
remaining as readable as LM Studio for direct chat.

Required states:

- user prompt bubble
- live thinking section
- live tool/work rows
- live streamed answer
- collapsed work summary
- clean final answer
- artifact embed
- expanded artifact
- error state
- stopped/canceled state
- retry/regenerate state
- copy/export action
- bottom metrics

Left sidebar requirements:

- preserve the Autopilot/OpenVSCode sidebar visual language
- show conversation history primarily in the Agent Studio chat view
- hide context/handoffs/debug panels unless explicitly opened
- no session cards with raw thread ids as primary product text
- artifact counts may be secondary, not dominant
- do not copy LM Studio's left rail or chat-list appearance

Exit criteria:

- Screenshots show transcript parity with the LM Studio reference and the
  user's example work-row screenshots.
- Screenshots prove Autopilot still looks like Autopilot inside the workbench,
  with added components rather than an LM Studio visual clone.

## Stage 12 - Source And Runtime Search

Goal: extract the right lessons from LM Studio and Autopilot source/runtime
without overfitting.

Search LM Studio evidence for:

- conversation persistence schema
- prompt template and reasoning markers
- settings keys
- stats fields
- OpenAI-compatible API behavior
- local model list behavior

Search Autopilot source for:

- route fallback and auto model selection
- fixture model registration
- model selector filtering
- artifact generator request body
- streaming request body
- metrics capture and rendering
- reasoning selector mapping
- provider parameter translation

Write:

```text
lm-studio-source-search-notes.md
autopilot-source-search-notes.md
delta-map.md
```

Exit criteria:

- Every implemented fix links back to a source-level responsibility.

## Stage 13 - Cross-Client And Headless Contract

Goal: make sure fixes are not trapped in the GUI.

Prove through daemon/headless APIs:

- explicit model route request
- explicit provider/endpoint request
- sampling settings
- reasoning settings
- stream events
- metrics
- artifact creation
- fixture rejection
- route failure when selected model unavailable

Then prove GUI consumes the same contract.

Exit criteria:

- GUI is presentation-only for model truth and artifact lifecycle.
- CLI/TUI/headless clients can rely on the same route and metrics contract.

## Stage 14 - Regression Guard

Goal: prevent this failure class from returning.

Add focused tests/proofs for:

- selected route with explicit model never turns into `auto` for artifact calls
  unless the user explicitly selected auto
- product chat cannot select fixture models by default
- product artifact creation rejects fixture text
- generated website prompt produces complete topic-specific source
- bottom metrics render for streamed and non-streamed completions
- reasoning mode is preserved in request and receipt
- route receipt and UI selector agree
- unavailable selected provider shows a clean error, not fallback content

Exit criteria:

- Static tests, daemon tests, and live GUI proof all cover the failure class.

## Stage 15 - Integrated Soak

Goal: prove the three legs together.

Run an integrated comparison suite:

1. Direct Ask: educational explanation.
2. Direct Ask: complete HTML answer.
3. Agent: generate website artifact.
4. Agent: revise artifact.
5. Agent: export artifact source.
6. Route failure: selected model unavailable.
7. Configurable change: temperature/top-p/reasoning changed and reflected.
8. Stop/cancel during streaming.
9. Long response with bottom metrics.
10. Simple greeting under 10 seconds, no artifact projection.

For each scenario:

- LM Studio reference where applicable
- Autopilot live GUI proof
- source/receipt/trace proof
- screenshot proof
- cleanup proof
- manifest row

Exit criteria:

- Final verdict can state `lm_studio_quality_routing_chat_ux_parity_plus_proven`.

## Prompt Set

Use realistic prompts, not self-referential harness narration.

Quality prompts:

- `Create a website that explains postquantum computers.`
- `Create a website that explains post-quantum computers.`
- `Explain post-quantum cryptography versus post-quantum computers.`
- `Write a short educational guide to neutral atom quantum computers.`
- `Build a single-file HTML page about photonic quantum computing.`

Routing/config prompts:

- `Answer in three bullets using the selected model.`
- `Generate a 1200-token explanation and report the response metrics.`
- `Use reasoning if enabled and explain the result cleanly.`
- `Return valid JSON describing a website plan.`

Agent/artifact prompts:

- `Create a website artifact about postquantum computers with a dark cyber-scientific design.`
- `Make the artifact more specific: add hardware archetypes and a roadmap.`
- `Show the source and rebuild the preview.`
- `Export the revised website source.`

Failure prompts:

- selected model unavailable
- LM Studio provider stopped
- route fallback disabled
- fixture model hidden
- invalid structured output
- stream canceled mid-response

## Final Verdict Requirements

The final verdict markdown must include:

- one-paragraph outcome
- whether parity plus is proven
- table of all P0/P1 rows
- screenshot index
- route/model truth summary
- LM Studio settings summary
- Autopilot settings summary
- quality comparison summary
- chat UX comparison summary
- model mounting/configurable comparison summary
- every fix made
- every remaining blocker, owner, reproduction, and next proof step

The final manifest JSON must include every scenario row and every
classification.

## Hard Stop Conditions

Pause implementation and refactor if:

- model-routing code becomes monolithic or unintuitive
- artifact projection logic grows into one giant function
- UI rendering mixes route truth, trace payloads, and product chat in one module
- fixtures leak into product paths again
- tests require running both GUI apps concurrently
- evidence cannot prove which model produced the output

Do not keep iterating on broad prompts if a P0 route or fixture leak is present.
Fix the smallest responsible layer first, then rerun focused proof.
