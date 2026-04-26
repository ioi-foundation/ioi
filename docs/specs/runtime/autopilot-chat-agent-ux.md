# Autopilot Agent Chat UX Contract

Status: IN PROGRESS

Autopilot chat should feel like a VS Code/Codex-style agent transcript: compact, useful while work is happening, quiet when there is nothing to inspect, and deep only when the operator opens the runtime workbench.

## Default Chat Layout

Default chat is answer-first and process-light.

```text
Thinking / Working disclosure, only when meaningful
  concise work summary
  meaningful tool calls
  sources or evidence used

Final answer
Sources, when present
Compact run badges
```

The chat lane must not render a large Runtime Facts dashboard by default. Model, route, evidence tier, and settlement/projection state may appear as compact badges. Policy, capability, and approval details appear in chat only when they affect execution: blocked work, pending approval, unavailable tools, missing settlement evidence, or failed validation.

## Pending Layout

Pending chat shows a single compact working disclosure. It should name the current useful activity if available, for example:

```text
Thinking...
  Reading context
  Calling search_code
  Checking result
```

It should not show empty Tool Calls, Observations, or Validation sections.

## Completed No-Tool Layout

A no-tool answer should stay clean:

```text
Final answer
Local: qwen3.5:9b · Projection-only · View details
```

No "No tools called" block should render in the default lane.

## Completed With Tools/Sources

When runtime records show meaningful work, chat shows a compact process disclosure before the final answer:

```text
Worked for 34s · 3 tool calls · 2 sources
  Read file ConversationTimeline.tsx
  Ran npm run typecheck
  Captured GUI screenshot

Final answer
Sources: ConversationTimeline.tsx · final.png · manifest.json
```

Tool rows use redacted argument/result summaries. Source and evidence pills use safe metadata and local icon/fallbacks. The renderer must not fetch arbitrary remote favicons during render.

## Gated, Blocked, Failed, And Retry Layout

Gates and failures may surface in chat because they change the operator's next action. Rows should state the block plainly and link to details:

```text
Approval required · View request
Tool unavailable · View capability details
Validation failed · View evidence
Retrying after timeout · 2 attempts
```

## Runtime Workbench Layout

The workbench owns full runtime depth. It should remain available from View details, Evidence, source/evidence pills, and process rows.

Default chat workbench sections:

- Process
- Tools
- Sources
- Evidence
- Runtime Details
- Trace Export

Runtime Details contains policy decisions, capabilities, approvals, receipts, settlement/projection state, and trace/export controls.

## Source And Favicon Contract

Source pills support:

- URL sources: domain label and cached/known favicon when already present in runtime metadata, otherwise globe fallback.
- Files: file icon and basename.
- Commands: terminal icon and command label.
- Screenshots/images: image icon and capture label.
- Trace/receipt/evidence: shield/check icon and authority tier.

Rendering source pills must not initiate arbitrary network requests for favicons. Use source metadata already projected by runtime, or deterministic local icon fallback.

## Chain-Of-Thought And Scratchboard Boundary

Chat may show structured work summaries, plans, tool choices, observations, validation, retries, and evidence references. It must not present provider-private chain-of-thought as an authoritative hidden scratchpad. Model-generated rationale may appear only as labeled proposal, note, or summary material and should not be confused with kernel/runtime records.

## Validation Expectations

GUI probes should prove:

- seeded intent opens Chat;
- default chat does not show a large Runtime Facts dashboard;
- final answer is visible and primary;
- process disclosure appears only when meaningful;
- tool rows appear when tools ran;
- empty process categories are omitted;
- source pills render with favicon/icon fallback;
- local GPU mode shows `Local: qwen3.5:9b`;
- projection-only is a compact badge;
- workbench opens and contains full runtime details.
