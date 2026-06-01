# Autopilot Agent Studio Glass Box Work Lane Master Guide

Owner: Autopilot Runtime / Agent Studio
Status: Draft campaign guide
Created: 2026-06-01
Target end state: `glass_box_work_lane_target_proven`

Primary references:

- `.internal/plans/autopilot-agent-studio-contextual-streaming-harness-ux-master-guide.md`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/inline-rendering.md`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/ui-state-machine.md`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/component-manifest.json`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/screenshots/golden_work_summary_collapsed_current.png`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/screenshots/golden_work_summary_expanded_mixed_tools_current.png`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/screenshots/golden_tool_stream_edit_rows_current.png`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/screenshots/golden_chat_thinking_current.png`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/screenshots/golden_chat_streaming_text_delta_current.png`

## Executive Intent

Agent Studio should make agent work feel visible, trustworthy, and alive without turning the main chat into an internal log viewer.

The target is a glass box work lane:

- Collapsed completed work shows only a minimal headline: `Worked for 34s`.
- Expanding that headline reveals a source-rich, sequential record of observable work.
- Tool rows show human-facing action details, favicons, source chips, excerpts, streamed stdout/source snippets, and status.
- Thinking shows concise thought previews or provider-exposed reasoning, never hidden chain-of-thought.
- Final answers remain clean, markdown-rendered, and product-facing.
- Raw receipts, JSON, daemon event names, fixture paths, model hashes, policy payloads, and full logs stay in Runs/Tracing/evidence.

This is not a black-box chat and not a raw trace dump. It is a polished, user-facing glass box.

## Product Decision Lock

The work-summary headline is intentionally sparse.

Collapsed:

```text
Worked for 34s >
```

Not:

```text
Worked for 34s · searched 3 times · read 2 pages · used 5 sources
```

The expanded view carries the magic.

Expanded:

```text
Searched "Filecoin vs Akash Network investment comparison 2026"
  [favicon] Akash vs. Filecoin Comparison...
  [favicon] Comparing the Features...
  [favicon] Filecoin vs Akash Network...

Read coingecko.com
  Price, market cap, volume, and 24h change extracted.

Read akash.network
  Current project positioning and infrastructure details extracted.

Drafted final comparison
  Compared liquidity, market size, recent performance, use case, and risk.
```

Tracing:

- receipt ids
- raw tool payloads
- model invocation hashes
- route selection internals
- policy verdict JSON
- daemon event names
- fixture paths
- complete stdout/stderr logs
- full source extraction dumps

## Scope

This campaign is about Agent Studio chat/run rail presentation and the daemon/shared contracts needed to power it.

In scope:

- collapsed and expanded work summary UX
- thought preview streaming
- provider reasoning streaming when exposed by the provider
- sequential live tool rows
- source-rich web rows with favicons
- file/code exploration rows
- shell/test rows
- browser/computer observation rows
- artifact/source streaming rows
- markdown rendering in final answers and expanded rows
- response metrics placement
- trace handoff links
- screenshots and visual regression evidence
- runtime event normalization that prevents GUI-only harness semantics

Out of scope:

- workflow compositor canvas
- broad tool catalogue retesting
- marketplace/provider business logic
- copying another product's branding
- showing hidden chain-of-thought
- moving receipts/tracing into the main chat transcript

## UX Principles

1. Main transcript stays readable.
2. Completed work collapses to one quiet headline.
3. Expanded work shows observable actions, not internal machinery.
4. Thinking previews explain intent at human resolution.
5. Tool rows show what happened, what source/file/page was involved, and whether it succeeded.
6. Source rows use favicon, title, domain, and compact excerpt when available.
7. The final answer streams and remains markdown-rendered.
8. Every product-visible row has a trace ref, but trace refs are not visible unless the user opens Tracing.
9. Agent Studio presents; daemon/runtime owns semantics.
10. When the user asks "what did you do?", the answer is visible without opening raw logs.

## Thinking Preview Contract

Autopilot must distinguish:

- `provider_reasoning_delta`: reasoning text explicitly emitted by a provider/model for display.
- `thought_preview_delta`: concise user-facing progress preview generated for the work lane.
- `assistant_answer_delta`: answer text intended for the final response.

Rules:

- Do not expose hidden chain-of-thought.
- Do not fabricate detailed private reasoning.
- Do show short previews such as:
  - `Finding current price and market cap sources.`
  - `Checking whether the sources agree.`
  - `Comparing liquidity, recent performance, and risk.`
  - `Drafting the final comparison.`
  - `Preparing the website source.`
  - `Rendering the artifact preview.`
- Thought previews should be collapsible after completion.
- If provider reasoning is enabled and exposed, render it in a separate collapsible reasoning block with clear labeling.
- If provider reasoning is disabled or unavailable, thought previews are enough.

## Work Row Contract

Each visible row must be derived from a typed runtime event, not from GUI string guessing.

Required public fields:

- `row_id`
- `turn_id`
- `status`: `pending | running | succeeded | failed | blocked | skipped`
- `kind`: `thought | search | read | file | edit | shell | test | browser | computer | artifact | policy | finalization`
- `headline`
- `summary`
- `started_at`
- `completed_at`
- `duration_ms`
- `public_refs`
- `trace_ref`
- `privacy_classification`

Optional row fields:

- `source_chips`
- `excerpt_preview`
- `stream_preview`
- `artifact_ref`
- `file_ref`
- `browser_session_ref`
- `error_summary`
- `metrics`

Rows must never include raw internal payloads in product chat.

## Source Chip Contract

Source chips are product-facing and should appear inside expanded search/read rows and below final answers when citations are relevant.

Each source chip should support:

- favicon
- title
- domain
- canonical URL
- freshness label when relevant
- source type: `search_result | read_page | api_quote | document | browser_capture`
- compact hover/expanded excerpt
- source health: `used | inspected | rejected | blocked`
- trace handoff

Rules:

- Favicons are fetched/cached through a safe runtime-owned path.
- Missing favicon falls back to a neutral globe icon.
- Do not show raw URL query strings unless the domain/title are ambiguous.
- Do not show source ids or receipt ids in chat.
- Rejected/blocked sources may be visible only when useful to explain reliability.

## Collapsed Summary Contract

Collapsed completed work shows:

```text
Worked for Xs >
```

Allowed variants:

```text
Stopped after Xs >
Waiting for you >
Blocked after Xs >
Failed after Xs >
```

Disallowed in collapsed headline:

- tool counts
- source counts
- receipt counts
- model route names
- fixture labels
- raw status codes
- trace ids
- JSON snippets

The expanded state may show tool/source counts, but only in human language.

## Expanded Summary Contract

The expanded work lane renders rows in chronological order:

1. thought preview rows
2. tool start rows
3. live progress rows
4. tool result rows
5. artifact/source stream rows
6. finalization row

Examples:

```text
Searched "post-quantum computers hardware error correction"
Read nist.gov
Read ibm.com
Created index.html
Rendered website preview
Drafted final answer
```

For code tasks:

```text
Explored repository root
Read package.json
Read src/App.tsx
Edited src/App.tsx
Ran npm test
```

For browser/computer tasks:

```text
Opened sandbox browser
Observed page
Clicked search input
Captured result as artifact
Waiting for user login
```

## Streaming Behavior

While running:

1. Show `Thinking about your request · Xs`.
2. Stream thought previews as short rows.
3. Append tool rows as actions occur.
4. Stream source/code/stdout previews inside the active row when useful.
5. Stream the final answer in place.
6. On completion, collapse work rows into `Worked for Xs >` and leave the final answer/artifact visible.

The user should never see the answer snap from empty to complete when the provider supports streaming.

## Markdown And Inline Rendering

Final answers and expanded work excerpts must render markdown safely.

Required:

- headings
- bold/italic
- lists
- tables
- inline code
- fenced code blocks
- links
- source chips
- basic citation/source row layout

Not allowed by default:

- unsafe inline HTML
- arbitrary scripts
- untrusted iframes
- raw Mermaid execution without sandboxed renderer

Use the inline rendering contract from `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/inline-rendering.md` as a reference, but implement in Autopilot's own workbench language.

## Runtime Ownership

Daemon/shared runtime owns:

- work row event production
- thought preview classification
- provider reasoning normalization
- tool input/result summaries
- source chip metadata
- favicon fetch/cache policy
- artifact/source preview refs
- response metrics
- trace refs
- privacy classification
- cleanup proof

Agent Studio owns:

- layout
- expansion/collapse
- rendering markdown and source chips
- visual state transitions
- keyboard/focus behavior
- opening Tracing for a selected row

If a work row can only be produced by GUI-specific parsing, that is a bug. Push the semantic event down into the daemon/shared contract.

## Visual State Machine

Map Agent Studio states to the clean-room interface parity state vocabulary:

- `IDLE`: composer ready
- `THINKING`: thought preview and pending state visible
- `STREAMING`: answer/source deltas visible
- `TOOL_PROPOSED`: approval or pending row
- `COMMAND_RUNNING`: shell/test row with live preview
- `COMMAND_FAILED`: shell/test row with compact error and trace handoff
- `BROWSER_OBSERVING`: managed browser/computer session row
- `COMPLETED`: work collapsed, final answer/artifact visible
- `CANCELLED`: stopped row and partial trace handoff
- `RECONNECTING`: reconnect banner without losing work lane state
- `REPLAYING`: read-only replay of row timeline

Do not copy external styling. Preserve Autopilot/OpenVSCode visual language.

## Campaign Stages

### Stage 0 - Baseline Inventory

Capture current Agent Studio behavior for:

- web research answer
- website artifact generation
- repo exploration
- code edit plus test
- browser/computer observation
- cancellation/reconnect

Evidence:

- screenshots before/while/after
- trace refs
- event logs
- current DOM snapshots
- defects list

Exit criteria:

- Baseline screenshots show collapsed, expanded, final, and trace states.
- Existing raw/internal leakage is catalogued.

### Stage 1 - Event Schema And Runtime Boundary

Define or update typed events for:

- `thought_preview_delta`
- `provider_reasoning_delta`
- `tool_work_row_started`
- `tool_work_row_updated`
- `tool_work_row_completed`
- `source_chip_observed`
- `work_summary_collapsed`
- `work_summary_expanded`
- `response_metrics_ready`

Exit criteria:

- Schema documented in code or internal docs.
- Daemon emits public row summaries and trace refs.
- GUI does not infer tool semantics from raw stdout/JSON.

### Stage 2 - Minimal Collapsed Summary

Implement completed work headline:

```text
Worked for Xs >
```

Exit criteria:

- No tool/source counts in collapsed headline.
- Failed/cancelled/waiting variants render correctly.
- Visual regression screenshots cover narrow and wide chat panes.

### Stage 3 - Expanded Tool Timeline

Implement chronological expanded rows for:

- web search
- web read
- file read/search
- file edit
- shell/test
- artifact source/build/preview
- browser/computer observation
- policy wait

Exit criteria:

- Rows are readable without opening Tracing.
- Tool rows include public summary, status, and duration.
- Raw payloads are absent from product chat.

### Stage 4 - Source-Rich Web Rows

Add source chips with favicons for search/read rows.

Exit criteria:

- Search rows show query plus result chips.
- Read rows show domain/title plus compact excerpt.
- Favicon fallback works.
- Source chips open/copy canonical URLs safely.
- Trace has raw payloads; chat does not.

### Stage 5 - Thought Preview Stream

Implement thought previews that stream while work is active.

Exit criteria:

- Thought previews appear before and between tool rows.
- No hidden chain-of-thought is exposed.
- Provider reasoning, when enabled, is visually distinct from runtime thought previews.
- Completion collapses previews under the work lane.

### Stage 6 - Final Answer Streaming And Markdown

Ensure final answer streams token-by-token or chunk-by-chunk and renders markdown.

Exit criteria:

- Headings, lists, tables, links, inline code, and fenced code render correctly.
- Final answer does not snap in as a fully completed block when streaming is available.
- Final markdown does not leak raw scaffold text.

### Stage 7 - Artifact And Source Streaming

For website/document/app artifacts:

- stream source preview while generated
- create artifact row
- render compact artifact embed
- allow expanded preview
- keep build logs in Tracing

Exit criteria:

- Website source appears as a live preview row or artifact source panel.
- Artifact embed appears after completion.
- The work lane shows creation/rendering steps.
- No canned fallback artifacts are generated.

### Stage 8 - Browser And Computer Rows

Represent browser/computer automation as managed session rows.

Exit criteria:

- Sandbox browser / local browser / desktop labels render.
- Observe / take over / return control states are visible where applicable.
- Waiting-for-user actions render as user-action rows.
- Sensitive screenshots follow quarantine policy.

### Stage 9 - Metrics And Footer Actions

Add bottom-of-response metrics and small actions without clutter:

- model/provider/route truth where user-facing
- elapsed time
- time-to-first-token when available
- generated tokens and tokens/sec when available
- stop reason when useful
- copy/regenerate/open tracing actions

Exit criteria:

- Metrics are below response, not in the collapsed work headline.
- Metrics are absent when unavailable instead of guessed.
- Route truth agrees with daemon receipts.

### Stage 10 - Visual Parity And Hardening

Use the clean-room interface parity screenshot set as a design checklist.

Required comparisons:

- `golden_work_summary_collapsed_current.png`
- `golden_work_summary_expanded_mixed_tools_current.png`
- `golden_chat_thinking_current.png`
- `golden_tool_stream_edit_rows_current.png`
- `golden_chat_streaming_text_delta_current.png`
- `golden_browser_observation_card_current.png`

Exit criteria:

- Autopilot keeps its own workbench look.
- Target interaction states are present.
- No card-within-card clutter.
- Text does not overflow narrow panes.

### Stage 11 - Product Proof Matrix

Run live GUI scenarios:

1. `Which is a better investment right now, Akash or Filecoin?`
2. `Create a website that explains post-quantum computers.`
3. `Create an HTML file about photonic quantum computing and use sources.`
4. `Call some tools and explore this repository, then summarize what you learned.`
5. `Fix this failing test in a disposable repo and show me the patch.`
6. `Open a sandbox browser, inspect this fixture page, and summarize what changed.`

For each scenario capture:

- before prompt
- active thinking preview
- active tool row
- expanded work row with source chips/excerpts
- final streamed answer
- collapsed `Worked for Xs`
- artifact/browser embed where applicable
- response metrics
- trace handoff
- cleanup proof

### Stage 12 - Regression Guard

Add tests and screenshot checks that prevent regression to:

- collapsed headline bloat
- raw JSON in chat
- fixture markers in chat
- missing markdown rendering
- missing source chips for web rows
- hidden chain-of-thought leakage
- tool rows owned solely by GUI parsing
- final answer snap instead of stream where streaming is available

Prefer behavior/screenshot checks over brittle source-string tests.

## Evidence Directory

Generate fresh evidence under:

```text
docs/evidence/autopilot-agent-studio-glass-box-work-lane/
```

Expected final artifacts:

```text
docs/evidence/autopilot-agent-studio-glass-box-work-lane/glass-box-work-lane-final-manifest.json
docs/evidence/autopilot-agent-studio-glass-box-work-lane/final-glass-box-work-lane-verdict.md
```

## Row Classifications

Use these classifications:

- `live_pass`
- `fixed_then_pass`
- `headless_pass`
- `ux_parity_pass`
- `source_rich_pass`
- `markdown_pass`
- `thought_preview_pass`
- `streaming_pass`
- `artifact_pass`
- `browser_session_pass`
- `supporting_pass`
- `supporting_pass_with_product_decision`
- `rejected_with_product_decision`
- `deferred_optional`
- `blocked_with_owner`
- `partial_unproven`
- `gap`
- `trace_leak`
- `hidden_cot_leak`
- `raw_payload_leak`
- `fixture_leak`

No P0 row may remain `gap`, `partial_unproven`, `trace_leak`, `hidden_cot_leak`, `raw_payload_leak`, `fixture_leak`, or ownerless blocked.

## P0 Acceptance Criteria

The target is proven only when:

- Collapsed completed work shows only `Worked for Xs`.
- Expanded work rows show readable source-rich observable work.
- Web rows include favicons/source chips/excerpts.
- Thought previews stream without hidden chain-of-thought leakage.
- Final answers stream and render markdown.
- Artifacts show source/build/preview rows plus compact embeds.
- Browser/computer sessions show managed live-session rows.
- Raw payloads and receipts stay in Tracing.
- Daemon/shared contracts own row semantics.
- Live GUI proof covers the product matrix.
- Final manifest and verdict are written.

## Explicit Non-Goals

- Do not expose hidden model chain-of-thought.
- Do not turn Tracing into chat.
- Do not show receipt ids in chat.
- Do not add tool/source counts to the collapsed headline.
- Do not copy another product's visual skin.
- Do not build brittle one-off prompt heuristics for this UX.

## Final Verdict Template

The final verdict must state:

- whether `glass_box_work_lane_target_proven` is achieved
- evidence path for every stage
- screenshot path for every key state
- raw-leak/fixture-leak/hidden-CoT audit result
- row classifications
- product decisions
- remaining blockers with owners, if any

