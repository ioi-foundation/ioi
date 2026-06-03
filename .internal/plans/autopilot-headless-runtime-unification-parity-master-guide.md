# Autopilot Headless Runtime Unification Parity Master Guide

Owner: Autopilot Workbench / Agent Studio / Runtime Daemon / Agent SDK / CLI / TUI / Tool Runtime / Policy Runtime / Evidence Runtime

Status: active campaign guide

Created: 2026-05-27

Rubric:

- `.internal/playbooks/substrate-absorption-rubric-playbook.md`

Baseline proven state:

- `docs/evidence/autopilot-agent-studio-full-default-harness-parity/final-default-harness-parity-verdict.md`
- `docs/evidence/autopilot-antigravity-harness-parity-plus/final-antigravity-harness-parity-plus-verdict.md`
- `docs/evidence/autopilot-claude-code-substrate-absorption-parity/final-claude-code-substrate-absorption-verdict.md`

## Executive Intent

This campaign proves that Agent Studio GUI, CLI, and TUI are clients of the same
daemon/headless runtime contract. It is not another broad Rust tool catalogue
campaign and it is not another substrate-discovery pass.

The desired product shape is:

- daemon owns agent turns, tool execution, policy, approvals, events, traces,
  receipts, replay, side effects, cleanup, and recovery
- SDK, GUI, CLI, and TUI consume the daemon contract through shared client
  adapters or thin endpoint-specific clients
- GUI provides richer presentation only
- CLI and TUI can run the same core harness lanes without the GUI
- no P0 harness semantics are trapped in extension/UI code

The final state is valid only when the final verdict can honestly state:

```text
headless_runtime_unification_parity_proven
```

## Non-Negotiable Rules

- Do not repeat broad Rust catalogue testing.
- Start from the default harness, Antigravity parity-plus, and Claude Code
  absorption baselines.
- Use realistic prompts and disposable fixtures for live scenarios.
- Keep Ask as direct model answers and Agent as governed harness execution.
- Product chat shows clean work-summary capsules plus final answers only.
- Raw fixture markers, tool payloads, JSON dumps, trace details, receipt ids, and
  filesystem scaffolding belong in Runs, Tracing, and evidence.
- Browser/computer automation remains a managed live session artifact with
  compact preview, expanded observe view, Sandbox browser / Local browser /
  Desktop labels, Observe / Take over / Return control controls, and
  Waiting-for-user states.
- GUI proof is required for presentation lanes; headless proof is required for
  harness semantics.
- If a capability exists only in the GUI layer and is not strictly presentation,
  push it down into the daemon or shared runtime contract.
- If files become monolithic or modules become unintuitive, stop feature work and
  refactor before continuing.
- Kill Autopilot, runtime bridge, daemon, spawned shells, browser fixtures, MCP
  servers, task workers, and computer-use processes after live scenarios and
  record cleanup proof.
- Simple natural-language turns over 30 seconds are defects unless trace
  evidence explains the delay.

## Evidence Root

Use:

```text
docs/evidence/autopilot-headless-runtime-unification-parity/
```

Final outputs:

```text
docs/evidence/autopilot-headless-runtime-unification-parity/headless-runtime-unification-final-manifest.json
docs/evidence/autopilot-headless-runtime-unification-parity/final-headless-runtime-unification-verdict.md
```

Each scenario directory should include the applicable subset of:

- `scenario.json`
- `ownership-evidence.json`
- `headless-api-transcript.json`
- `sdk-transcript.json`
- `cli-transcript.json`
- `tui-transcript.json`
- `gui-screenshots.json`
- `runtime-events.jsonl`
- `trace-events.jsonl`
- `policy-verdicts.jsonl`
- `receipts.jsonl`
- `side-effects-before.json`
- `side-effects-after.json`
- `latency.json`
- `cleanup-proof.json`
- `stage-verdict.json`
- `failure-analysis.md`
- `fixes-applied.md`
- `product-decision.md`

## Ownership Classes

Every row must classify the current ownership layer:

- `daemon_owned`: harness semantics are owned by daemon/headless runtime APIs
- `shared_client_adapter`: client translation lives in SDK/shared adapter code
- `gui_only_debt`: core semantics exist only in the GUI or extension
- `cli_only_debt`: core semantics exist only in CLI/TUI
- `tui_missing`: TUI cannot consume a P0 daemon contract available elsewhere
- `intentional_ui_presentation`: GUI-only because the row is display/layout only

## Outcome Classes

Use these status values:

- `live_pass`: proven through live product GUI with screenshots, traces, and cleanup
- `fixed_then_pass`: defect found, fixed, tested, and proven
- `headless_pass`: proven through daemon/headless runtime APIs without GUI
- `cross_client_pass`: same daemon contract consumed by GUI/CLI/TUI or SDK/CLI/TUI
- `supporting_pass`: static, unit, CLI, SDK, or contract evidence that supports a row
- `supporting_pass_with_product_decision`: support evidence plus explicit scope decision
- `policy_gate_pass`: risky action correctly paused, denied, or approval-gated
- `sandbox_effect_pass`: effect occurred only inside a disposable fixture
- `intentional_ui_presentation`: strictly presentation-only GUI behavior
- `rejected_with_product_decision`: intentionally not part of Autopilot scope
- `deferred_optional`: outside current default/product scope
- `blocked_with_owner`: concrete blocker with owner, reproduction, evidence, and next step
- `partial_unproven`: implemented or plausible but not proven enough
- `gap`: missing or not meaningfully verified

No P0 row may remain `gap`, `partial_unproven`, `gui_only_debt`,
`tui_missing`, or ownerless blocked in the final verdict.

## Manifest Shape

Each manifest row must include:

```json
{
  "id": "HRU-001",
  "priority": "P0",
  "capability": "agent turns",
  "ownership": "daemon_owned",
  "status": "headless_pass",
  "clients": ["daemon", "sdk", "cli", "tui", "gui"],
  "evidence": ["docs/evidence/.../stage-verdict.json"],
  "proof_summary": "Start turn, stream events, execute tool, emit trace, and clean up through daemon API.",
  "owner": "Runtime daemon",
  "remaining_work": []
}
```

## Required Capability Rows

### HRU-001 Agent Turn Contract

Priority: P0

Prove daemon/headless APIs can:

- create/list/get threads
- start turns
- stream events
- expose turn/run ids
- emit final output
- clean up after the scenario

GUI, CLI, and TUI must consume this contract instead of owning a private loop.

### HRU-002 Ask vs Agent Separation

Priority: P0

Prove Ask remains direct model answers and Agent remains governed harness
execution. GUI presentation can differ, but routing and semantics must live below
the UI layer.

### HRU-003 Tool Execution And File Mutation

Priority: P0

Prove headless APIs can execute tools and perform disposable file write/edit/delete
or patch effects with policy and trace evidence. CLI/TUI/GUI must invoke the same
daemon tool route or shared SDK contract.

### HRU-004 Runtime Events, Traces, Receipts, Replay

Priority: P0

Prove events, traces, receipts, replay, inspect, and side-effect state are emitted
by the daemon and consumable outside the GUI.

### HRU-005 Policy Modes And Approvals

Priority: P0

Prove Default permissions, Auto-review, and Full access map to daemon thread
policy/approval modes. Approval creation, approval decision, revoke, pause, and
resume must be daemon-owned.

### HRU-006 Context Analyzer And Compaction

Priority: P0

Prove context budget, compaction policy, compact, restore/replay references, and
goal/constraint preservation are daemon/headless surfaces.

### HRU-007 Hook Lifecycle

Priority: P1

Prove hook lifecycle decisions are daemon/shared-runtime concerns, not GUI-only
code paths. If a hook class is not product-default, close it with a product
decision.

### HRU-008 Delegation, Subagents, And Tasks

Priority: P0

Prove task/subagent create, wait, input, cancel, resume, assign, and result lanes
are daemon-owned and consumed by non-GUI clients.

### HRU-009 Retained Shell Lifecycle

Priority: P0

Prove retained shell creation, input, backgrounding, stall detection, output
retrieval, terminate/reset, and cleanup are headless runtime lanes, with GUI/CLI/TUI
presentation as clients.

### HRU-010 MCP And Deferred Tool Discovery

Priority: P0

Prove deferred tool search, MCP status, server import/add/remove/enable/disable,
tool fetch, and tool invoke are daemon/headless contracts.

### HRU-011 Browser/Computer Managed Sessions

Priority: P0

Prove browser/computer sessions expose daemon/runtime artifacts for Sandbox
browser, Local browser, and Desktop labels; Observe, Take over, Return control,
and Waiting-for-user states; and GUI live viewport presentation.

### HRU-012 Stop, Cancel, Recover

Priority: P0

Prove turn interrupt, steer, resume, task/job cancel, subagent cancel, and recovery
paths are daemon-owned and cross-client visible.

### HRU-013 Latency And Simple-Turn Timing

Priority: P0

Prove simple Ask and Agent turns complete under 30 seconds unless trace evidence
explains the delay.

### HRU-014 SDK Shared Client Adapter

Priority: P0

Prove the Agent SDK exposes the canonical daemon routes and event mapping used by
clients, rather than duplicating runtime semantics.

### HRU-015 CLI Client Adapter

Priority: P0

Prove CLI commands are daemon clients for core harness lanes and can run without
the GUI.

### HRU-016 TUI Client Adapter

Priority: P0

Prove TUI commands are daemon clients for core harness lanes and can run without
the GUI. TUI may render differently, but must not have a private runtime loop.

### HRU-017 Cross-Client Golden Scenarios

Priority: P0

Run cross-client evidence for:

1. code edit plus focused test repair
2. policy-gated disposable file mutation
3. retained shell background/stall/recover
4. delegated worker verification task
5. deferred MCP/mock tool discovery and invocation
6. browser/computer managed session artifact
7. stop/cancel/recover path
8. context compaction and restore path
9. clean Ask direct answer path
10. governed Agent harness execution path

The same daemon/headless contract must be the authority across all available
clients.

## Campaign Stages

### Stage 0 - Baseline And Harness

Verify baselines exist, evidence root is fresh, and the campaign runner records
guide, playbook, commit, date, and environment.

### Stage 1 - Ownership Matrix

Inspect daemon, SDK, GUI, CLI, and TUI sources for route ownership and private
runtime loops. Classify every row with the ownership taxonomy.

### Stage 2 - Headless Daemon Contract Proof

Start the daemon without GUI. Exercise thread, turn, tool, policy, context, MCP,
memory, subagent/task, cancellation, trace, replay, and cleanup routes.

### Stage 3 - SDK Proof

Use the SDK/shared client adapter to consume daemon routes and event mapping.
Verify it does not own core harness semantics.

### Stage 4 - CLI Proof

Use CLI commands against a live daemon endpoint for tool discovery, stream/events,
approval/policy, compact, browser/computer discovery, and cancellation.

### Stage 5 - TUI Proof

Use TUI JSON/headless modes against a live daemon endpoint. Verify the TUI reports
daemon routes and does not run a private harness loop.

### Stage 6 - Focused GUI Product Proof

Launch the real Autopilot IDE GUI for only the product-impacting rows:

- Ask vs Agent routing
- work-summary capsule and clean chat output
- approval menu policy mapping
- browser/computer managed session live viewport presentation

Screenshots must be reviewed for UX regressions.

### Stage 7 - Cross-Client Golden Scenarios

Run the ten golden scenarios through the daemon and available clients, using
realistic disposable tasks. Do not rerun broad catalogue sweeps.

### Stage 8 - Cleanup And Replay Audit

Verify no spawned daemon, runtime bridge, GUI, shell, browser, MCP, task worker, or
computer-use process remains. Verify final manifest rows reference concrete
evidence.

## Final Verdict Requirements

The final verdict must include:

- final status string
- current commit
- evidence root
- one row per required capability
- ownership classification per row
- status per row
- client coverage per row
- evidence paths per row
- latency summary
- cleanup summary
- defect/fix summary
- remaining blockers, if any, with owner and next proof step

The verdict may state `headless_runtime_unification_parity_proven` only if:

- every P0 row is proven or intentionally presentation-only where applicable
- no P0 row remains `gap`, `partial_unproven`, `gui_only_debt`, `tui_missing`, or
  ownerless blocked
- GUI-only code owns only presentation
- CLI/TUI can drive the core daemon/headless contract without the GUI
- all required final files exist
- cleanup proof exists
