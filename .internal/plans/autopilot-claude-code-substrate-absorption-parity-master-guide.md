# Autopilot Claude Code Substrate Absorption Parity Master Guide

Owner: Autopilot Workbench / Agent Studio / Rust Agentic Runtime / Runtime Daemon / Tool Runtime / Policy Runtime / MCP Runtime / CLI and SDK Strategy

Status: active planning guide

Created: 2026-05-27

Baseline audit:

- `docs/evidence/claude-code-agent-harness-gap-audit/2026-05-27-current-state-gap-audit.md`
- `docs/evidence/claude-code-agent-harness-gap-audit/2026-05-27-gap-manifest.json`

Baseline proven state:

- `docs/evidence/autopilot-agent-studio-full-default-harness-parity/final-default-harness-parity-verdict.md`
- `docs/evidence/autopilot-antigravity-harness-parity-plus/final-antigravity-harness-parity-plus-verdict.md`

Reference substrate:

- `examples/claude-code-main/claude-code-main/src/tools.ts`
- `examples/claude-code-main/claude-code-main/src/Tool.ts`
- `examples/claude-code-main/claude-code-main/src/query.ts`
- `examples/claude-code-main/claude-code-main/src/services/tools/StreamingToolExecutor.ts`
- `examples/claude-code-main/claude-code-main/src/services/tools/toolOrchestration.ts`
- `examples/claude-code-main/claude-code-main/src/services/tools/toolExecution.ts`
- `examples/claude-code-main/claude-code-main/src/hooks/useCanUseTool.tsx`
- `examples/claude-code-main/claude-code-main/src/types/permissions.ts`
- `examples/claude-code-main/claude-code-main/src/services/compact/autoCompact.ts`
- `examples/claude-code-main/claude-code-main/src/utils/analyzeContext.ts`
- `examples/claude-code-main/claude-code-main/src/tools/ToolSearchTool/ToolSearchTool.ts`
- `examples/claude-code-main/claude-code-main/src/tools/MCPTool/MCPTool.ts`
- `examples/claude-code-main/claude-code-main/src/tools/AgentTool/AgentTool.tsx`
- `examples/claude-code-main/claude-code-main/src/tasks/LocalShellTask/LocalShellTask.tsx`
- `examples/claude-code-main/claude-code-main/src/tools/SkillTool/SkillTool.ts`

Parent guides:

- `.internal/plans/autopilot-agent-studio-full-default-harness-parity-proof-master-guide.md`
- `.internal/plans/autopilot-antigravity-harness-parity-plus-master-guide.md`

## Executive Intent

Autopilot is already green against the default harness and Antigravity parity-plus
claims. This campaign must not repeat Rust catalogue testing.

The next target is Claude Code substrate absorption parity: identify, implement,
prove, or consciously reject the runtime primitives in `examples/claude-code-main`
that would materially strengthen Autopilot.

The campaign is not a clone effort. Claude Code is terminal-first and CLI/SDK
native; Autopilot is IDE-first and daemon-owned. We absorb substrate primitives
only when they improve Autopilot's product direction:

1. streaming tool execution
2. richer permission grammar
3. context analyzer and compaction substrate
4. lifecycle hooks
5. deferred tool and MCP discovery
6. task/team/teammate substrate
7. shell background and stall ergonomics
8. runtime skills/plugins/slash-command strategy
9. CLI/SDK/headless bridge decision
10. long-tail tool registry classification

Alternate substrate discovery should wait until this campaign closes or produces
a reusable absorption rubric. Otherwise every new substrate will rediscover the
same categories without landing improvements.

## Clean-Room Boundary

Use the Claude Code example as a behavioral and architectural reference. Do not
copy proprietary code, user-facing copy, styling, assets, or private identifiers.
Implement IOI-native equivalents that preserve Autopilot's daemon authority,
tracing, policy, work-summary, and IDE UX principles.

## Definition Of Done

The campaign is complete only when the final manifest can honestly state:

```text
claude_code_substrate_absorption_parity_proven
```

Required conditions:

- every `P0` row in the baseline audit is `live_pass`, `fixed_then_pass`,
  `supporting_pass_with_product_decision`, or `rejected_with_product_decision`
- no `P0` row remains `gap`, `partial_unproven`, or ownerless blocked
- `P1` rows either have live/product proof or an explicit product-scope decision
- no default harness regression is introduced
- Ask remains direct model answers
- Agent remains governed harness execution
- product chat shows clean work-summary capsules plus final answers only
- receipts, raw tool payloads, fixture paths, JSON dumps, and trace details stay
  in Runs/Tracing/evidence, not the main chat transcript
- browser/computer automation remains represented as managed live session
  artifacts with observe/takeover/return controls
- simple natural-language turns stay under 30 seconds unless trace evidence
  explains the delay
- every scenario has cleanup proof for Autopilot, runtime bridge, daemon, shell
  children, browser children, and computer-use children

## Non-Negotiable Rules

- Do not rerun broad Rust catalogue scenarios as a substitute for this work.
- Start every stage with a focused reproduction against the specific substrate
  primitive.
- Use the real Autopilot IDE GUI and Agent Studio for product-impacting proof.
- CLI, SDK, static, or unit proof may support terminal/headless rows, but it
  cannot close an IDE/product UX row by itself.
- Use disposable workspaces, shell processes, MCP servers, browser profiles,
  task stores, memory stores, and plugin/skill fixtures.
- Kill and verify cleanup after every live scenario.
- Screenshot GUI proof and review screenshots for UX defects.
- If files become monolithic or modules become unintuitive, stop feature work and
  refactor before continuing.
- When a row is not right for Autopilot, write an explicit product decision. Do
  not leave it as ambient non-parity.

## Evidence Root

Use:

```text
docs/evidence/autopilot-claude-code-substrate-absorption-parity/
```

Each scenario directory must include:

- `scenario.json`
- `baseline-gap-ids.json`
- `gui-before.png` when GUI proof is applicable
- `gui-during.png` when the state is visual or streaming
- `gui-after.png` when GUI proof is applicable
- `chat-transcript.json`
- `runtime-events.jsonl`
- `trace-events.jsonl`
- `policy-verdicts.jsonl`
- `receipts.jsonl`
- `side-effects-before.json`
- `side-effects-after.json`
- `latency.json`
- `cleanup-proof.json`
- `failure-analysis.md` when a scenario fails
- `fixes-applied.md` when code changed
- `product-decision.md` when a row is rejected, deferred, or scoped differently
- `stage-verdict.json`

Final campaign outputs:

- `docs/evidence/autopilot-claude-code-substrate-absorption-parity/claude-code-substrate-absorption-final-manifest.json`
- `docs/evidence/autopilot-claude-code-substrate-absorption-parity/final-claude-code-substrate-absorption-verdict.md`

## Outcome Classes

Use these status values in manifests:

- `live_pass`: proven through the live IDE GUI with screenshots, traces, and cleanup
- `fixed_then_pass`: defect found, fixed, tested, and live-proven
- `supporting_pass`: unit, CLI, SDK, or static evidence that supports but does
  not close product parity by itself
- `supporting_pass_with_product_decision`: non-GUI row closed by support evidence
  and explicit product decision
- `policy_gate_pass`: elevated or risky action correctly paused or denied
- `sandbox_effect_pass`: effect occurred only inside disposable sandbox
- `rejected_with_product_decision`: intentionally not absorbed into Autopilot
- `deferred_optional`: valid but outside the current product/default scope
- `blocked_with_owner`: blocked with reproduction, owner, evidence path, and next step
- `partial_unproven`: implemented or sketched, but not yet proven
- `gap`: not implemented or not meaningfully tested

## Manifest Shape

Each row in the final manifest must include:

```json
{
  "id": "CC-HARNESS-001",
  "priority": "P0",
  "area": "streaming_tool_execution",
  "status": "fixed_then_pass",
  "owner": "Runtime tool executor",
  "sourceRequirements": [
    "examples/claude-code-main/claude-code-main/src/services/tools/StreamingToolExecutor.ts"
  ],
  "productDecision": "",
  "implementationRefs": [],
  "tests": [],
  "liveEvidence": [],
  "screenshots": [],
  "cleanupProof": "",
  "residualRisk": "",
  "nextProofStep": ""
}
```

## Stage 0: Campaign Harness And Rubric

Gap IDs: all

Objective:

- Convert the Claude Code gap manifest into an executable campaign tracker.
- Add a product-decision path for rows that are not right for Autopilot.
- Ensure the harness can collect GUI evidence, support evidence, cleanup, and
  final verdicts without broad catalogue assumptions.

Required work:

- Seed a campaign manifest from
  `docs/evidence/claude-code-agent-harness-gap-audit/2026-05-27-gap-manifest.json`.
- Add scenario selection by `CC-HARNESS-*` id.
- Add final manifest and verdict builders.
- Add screenshot checks for product chat, permission menus, tracing, task/team
  views, shell cards, MCP discovery, and context analyzer surfaces.

Proof:

- Manifest build succeeds.
- A no-op Agent Studio launch records baseline GUI, trace panel, and cleanup.
- No default harness evidence is overwritten.

Exit criteria:

- All rows are tracked with priority, owner, status, source requirements, and
  next proof step.

## Stage 1: Streaming Tool Execution

Gap ID:

- `CC-HARNESS-001`

Objective:

- Decide and implement Autopilot's equivalent of streaming tool execution.
- Preserve daemon authority while allowing safe tool execution to begin before
  the full assistant turn is complete, when the model/provider stream provides
  enough structured tool-call input.

Required behavior:

- Streamed tool calls can enter `queued`, `executing`, `completed`, `yielded`,
  or `discarded` states.
- Read-only or declared concurrency-safe tools can run in parallel.
- Mutating, exclusive, or stateful tools serialize.
- If a shell/process tool fails in a way that invalidates sibling work, sibling
  subprocesses are canceled and trace records explain why.
- Streaming fallback cannot leak duplicate effects.
- Interrupt behavior distinguishes cancelable tools from blocking tools.

Scenarios:

- Two concurrent read-only file/search tools complete in parallel.
- One read-only tool and one exclusive file mutation serialize correctly.
- A failing shell command cancels a sibling long-running shell process.
- A stream fallback discards queued but not yet executed tool calls.
- GUI shows work-summary capsules; raw streaming tool payloads stay in Tracing.

Exit criteria:

- `CC-HARNESS-001` is `live_pass` or `fixed_then_pass`.
- No regression in normal Agent Studio turn completion or chat output rendering.

## Stage 2: Permission Grammar Absorption

Gap ID:

- `CC-HARNESS-002`

Objective:

- Map Claude-style permission concepts into an IOI-native permission grammar
  without confusing Ask and Agent responsibilities.

Required decisions:

- `default`: map to existing Default permissions.
- `auto`: map to Auto-review with explicit low-risk classifier policy.
- `bypassPermissions`: map to Full access / yolo, with strong session labeling.
- `acceptEdits`: decide whether it maps to editor hunk approval only.
- `plan`: map to plan-only execution and hunk proposal mode.
- `dontAsk`: decide whether it is supported, rejected, or absorbed by Full access.
- `bubble`: decide whether it applies to delegated workers.

Required work:

- Define typed permission mode, rule source, rule destination, and decision
  reason schemas.
- Record classifier-backed auto-review decisions separately from user decisions.
- Preserve approval menu UX in Agent Studio.
- Ensure bridge/API calls carry mode changes to daemon threads.

Scenarios:

- Default permissions gates destructive file mutation.
- Auto-review allows low-risk read/test command and blocks destructive/external action.
- Full access runs a disposable mutation without approval and is visibly labeled.
- Plan-only prepares an edit without applying it.
- Delegated worker inherits or bubbles permission according to explicit rule.

Exit criteria:

- `CC-HARNESS-002` has a product decision matrix and live proof for all supported modes.

## Stage 3: Context Analyzer And Compaction

Gap ID:

- `CC-HARNESS-003`

Objective:

- Give Autopilot an operator-visible and runtime-usable context analyzer inspired
  by Claude's category accounting, without polluting product chat.

Required behavior:

- Context budget accounts for system, user, assistant, tool calls, tool results,
  files, memory, MCP tools, deferred tools, skills/plugins, diagnostics, browser
  snapshots, and reserved output buffer.
- Tool result payloads can be budgeted, summarized, or replaced with artifact refs.
- Compaction records what was summarized, what was restored, and what was dropped.
- Compaction has a circuit breaker for repeated failures.
- Deferred tool/MCP accounting does not require loading the full catalog.

Scenarios:

- Context analyzer reports categories before and after a realistic code task.
- Large tool output is replaced with artifact reference and still recoverable.
- Cognitive compaction preserves active goal, constraints, touched files, and
  next action.
- Compaction failure circuit breaker prevents retry churn.
- GUI shows context pressure in an operator surface, not in chat transcript.

Exit criteria:

- `CC-HARNESS-003` is closed with live GUI proof and supporting unit tests.

## Stage 4: Hook Lifecycle

Gap ID:

- `CC-HARNESS-004`

Objective:

- Define an IOI-native hook lifecycle that covers the useful Claude lifecycle
  phases while preserving daemon governance.

Required hook phases:

- session start
- pre-tool
- post-tool success
- post-tool failure
- permission denied
- stop / completion gate
- task created
- task completed
- teammate idle or worker idle
- pre-compact
- post-compact

Required behavior:

- Hooks can be advisory or blocking.
- Blocking hooks must explain continuation requirements in Tracing and product UI.
- Hook output is summarized for the model only when needed.
- Hook failures cannot silently complete a run.
- Hooks must be scoped and policy-governed.

Scenarios:

- Pre-tool hook blocks a forbidden disposable mutation.
- Post-tool hook records diagnostics after file edit.
- Stop hook blocks completion on failing test and allows completion after repair.
- Pre-compact/post-compact hooks record compaction metadata.
- Worker idle hook triggers a parent-visible update.

Exit criteria:

- `CC-HARNESS-004` is live-proven with at least one blocking and one advisory hook path.

## Stage 5: Deferred Tool Search And MCP

Gap ID:

- `CC-HARNESS-005`

Objective:

- Absorb the useful part of Claude's ToolSearch/MCP flow: keep tool context
  small, let the model discover relevant tools, and preserve approval/auth gates.

Required behavior:

- Model-visible governed tool search can query deferred tools.
- Exact `select:<tool_name>` and keyword search are supported or consciously rejected.
- MCP tools, resources, prompts, and skills have separate status surfaces.
- MCP auth and server approval produce trace-side receipts and clean user prompts.
- Deferred MCP tools do not inflate the base context window.

Scenarios:

- Start with a large mock MCP catalog that is not fully loaded into model context.
- Agent searches for a specific tool, selects it, invokes it, and gets a result.
- MCP resource list/read works with trace receipts.
- MCP auth-required tool pauses in `Waiting for user` or approval state.
- Product chat shows a clean result and work capsule only.

Exit criteria:

- `CC-HARNESS-005` is closed or has explicit product decisions for unsupported Claude-specific affordances.

## Stage 6: Task, Team, And Teammate Substrate

Gap ID:

- `CC-HARNESS-006`

Objective:

- Decide how far Autopilot should absorb Claude's task/team substrate on top of
  the existing subagent and delegation manager.

Required behavior:

- Task create/get/update/list/stop/output semantics are mapped or rejected.
- Named worker/teammate messaging is mapped or rejected.
- Parent/child cancellation, output retrieval, and failure propagation are explicit.
- Worker output is visible through product surfaces and trace artifacts.

Scenarios:

- Parent creates two tasks: one code edit task and one verification task.
- One worker completes and contributes a result.
- One worker fails and produces a failure panel with trace evidence.
- Parent reads task output and synthesizes final answer.
- Stop/cancel propagates to active children.

Exit criteria:

- `CC-HARNESS-006` has live proof for supported task/team lanes and product decisions for the rest.

## Stage 7: Shell Background And Stall Ergonomics

Gap ID:

- `CC-HARNESS-007`

Objective:

- Improve retained shell UX with backgrounding, output retrieval, and prompt-stall
  detection where it fits Autopilot.

Required behavior:

- Long foreground shell commands can transition to background with retained id.
- Output is retrievable without dumping unbounded stdout into chat.
- Interactive prompt stalls are detected and surfaced with guidance.
- Kill/terminate paths clean process trees and record receipts.

Scenarios:

- Long command backgrounds after threshold and remains inspectable.
- Agent reads/tails output later.
- Interactive prompt fixture triggers Waiting for user or guidance state.
- Kill command terminates process tree and records cleanup.

Exit criteria:

- `CC-HARNESS-007` is closed with live GUI proof through Agent Studio or a product decision explaining why existing retained shell controls are sufficient.

## Stage 8: Skills, Plugins, And Slash Commands

Gap ID:

- `CC-HARNESS-008`

Objective:

- Decide whether runtime skills/plugins/slash commands belong in Autopilot, and
  if so prove a minimal product-native implementation.

Required decisions:

- Operator-side Codex skills are not the same as Autopilot runtime skills.
- Runtime skills must have discovery, trust, invocation, context budgeting, and
  trace receipts.
- Plugins/marketplace flows are optional unless product scope promotes them.

Scenarios if supported:

- Discover a local runtime skill.
- Invoke the skill through Agent mode as a forked or scoped execution.
- Enforce trust/approval before third-party skill execution.
- Account for skill prompt/context in context analyzer.
- Show clean product output and trace-side receipts.

Exit criteria:

- `CC-HARNESS-008` is either implemented with a minimal live proof or closed as
  `rejected_with_product_decision` / `deferred_optional`.

## Stage 9: CLI, SDK, Headless, And Long-Tail Tool Decisions

Gap IDs:

- `CC-HARNESS-009`
- `CC-HARNESS-010`
- `CC-HARNESS-012`

Objective:

- Avoid accidental scope creep by classifying terminal-first and long-tail Claude
  features against Autopilot's product strategy.

Required work:

- Classify each Claude-only surface as:
  - `product_default`
  - `optional_provider`
  - `replaced_by_autopilot_surface`
  - `terminal_sdk_strategy`
  - `rejected`
- Decide whether CLI/SDK/headless parity is part of Autopilot's near-term product.
- Decide long-tail tools: NotebookEdit, PowerShell, REPL primitives, Worktree
  enter/exit, RemoteTrigger, Monitor, Brief/upload, cron, AskUserQuestion,
  TodoWrite, and Task V2.

Scenarios:

- Product decision manifest is reviewed against existing Autopilot surfaces.
- Any promoted default lane gets a focused proof.
- Any rejected lane has rationale and replacement path.

Exit criteria:

- `CC-HARNESS-009`, `CC-HARNESS-010`, and `CC-HARNESS-012` are not left as vague gaps.

## Stage 10: Browser/Computer Regression Guard

Gap ID:

- `CC-HARNESS-011`

Objective:

- Preserve Autopilot's current product advantage for browser/computer automation
  while substrate work changes runtimes below it.

Required behavior:

- Managed live session card still appears for browser/computer tasks.
- Sandbox browser remains default for agent browsing.
- Local browser and Desktop are opt-in and visibly labeled.
- Observe, Take over, Return control, and Waiting for user remain present.
- Receipts and raw browser/computer details stay in Tracing/evidence.

Scenarios:

- Sandbox browser task with compact and expanded view.
- Local browser opt-in task.
- Desktop visual GUI observation task.
- Manual-only fixture triggers Waiting for user.

Exit criteria:

- `CC-HARNESS-011` remains `parity_plus_for_product`.

## Stage 11: Integrated Soak

Gap IDs: all supported rows

Objective:

- Prove the absorbed substrate works together under realistic coding objectives,
  not synthetic narration prompts.

Prompt classes:

- "Patch this disposable helper to normalize run status labels, add tests, and
  summarize the diff."
- "Find why this fixture test fails, fix the smallest layer, and rerun only the
  focused test."
- "Use a delegated worker to inspect browser fixture behavior while the parent
  patches the harness."
- "Add a mock MCP tool, discover it through deferred search, use it, and keep
  the answer clean."
- "Run a long retained shell task, background it, detect a stall, recover, and
  finish with trace evidence."

Required checks:

- No simple turn exceeds 30 seconds without trace explanation.
- No raw fixture marker appears in product chat.
- No monolithic file growth is left unresolved.
- Cleanup proof passes after each scenario.
- Default harness and Antigravity parity smoke checks remain green.

Exit criteria:

- Final manifest and verdict are written.
- Every P0 is closed, rejected with product decision, or blocked with owner and
  no claim of full absorption parity.

## Final Verdict Rules

The final verdict may say `claude_code_substrate_absorption_parity_proven` only if:

- all P0 rows are closed with allowed statuses
- all P1 rows have product decisions and no ownerless gap
- all promoted product-default rows have live product proof
- rejected/deferred rows have explicit rationale
- final cleanup proof passes

If those conditions are not met, the verdict must say:

```text
claude_code_substrate_absorption_parity_not_yet_proven
```

and list every remaining blocker with owner, reproduction, evidence path, and
next proof step.
