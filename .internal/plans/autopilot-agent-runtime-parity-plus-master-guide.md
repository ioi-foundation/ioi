# Autopilot Agent Runtime Parity Plus Master Guide

Owner: Autopilot Runtime Daemon / Agent Studio / Rust Agentic Runtime / OpenVSCode Workbench / Policy and Sandbox Runtime

Status: active planning guide

Created: 2026-06-01

Target verdict:

```text
agent_runtime_parity_plus_proven
```

This guide supersedes broad catalogue-style testing for the next runtime pass.
The goal is to bring Autopilot's agent runtime to parity-plus as an operator
harness: durable, replayable, interruptible, reviewable, sandboxed,
source-rich, model/tool/result/model-native, and product-clean.

The reference substrate is the clean-room Antigravity dossier under:

- `internal-docs/reverse-engineering/antigravity/clean-room/`
- `internal-docs/reverse-engineering/antigravity/ux/`
- `internal-docs/reverse-engineering/antigravity/antigravity-brain-memory-architecture.md`
- `internal-docs/reverse-engineering/antigravity/antigravity-runtime-traces.md`
- `internal-docs/reverse-engineering/antigravity/antigravity-protocol-schemas.md`

Use those files as behavioral requirements only. Do not copy source, CSS,
assets, binary internals, or product skin. Implement IOI-native runtime
primitives.

## Baselines Already Earned

Do not repeat these campaigns except as focused regression proof:

- Default harness catalogue proof:
  `docs/evidence/autopilot-agent-studio-full-default-harness-parity/`
- Headless/runtime unification proof:
  `docs/evidence/autopilot-headless-runtime-unification-parity/`
- Conversation artifact canvas proof:
  `docs/evidence/autopilot-conversation-artifact-embedded-document-canvas/`
- Glass-box work lane proof:
  `docs/evidence/autopilot-agent-studio-glass-box-work-lane/glass-box-work-lane-final-manifest.json`

The glass-box pass is especially important: it gives the campaign a working
product timeline, source-rich rows, artifact embeds, and managed browser
session projection. The remaining work should push semantics deeper into the
daemon/runtime and editor integration, not merely add UI labels.

## Definition Of Done

The campaign is complete only when the final manifest can honestly state:

```text
agent_runtime_parity_plus_proven
```

Required conditions:

- every P0 row in this guide is `live_pass`, `fixed_then_pass`,
  `headless_pass`, or `policy_gate_pass`
- no P0 row remains `gap`, `partial_unproven`, `trace_leak`,
  `raw_payload_leak`, `fixture_leak`, `hidden_cot_leak`, or ownerless blocked
- Agent runs persist durable trajectory state that survives GUI reload,
  daemon restart, and extension-host reconnect
- active run memory has IOI-native brain artifacts: plan, task checklist,
  walkthrough, scratch workspace, and replay references
- every tool/action transition is recorded as typed runtime state with
  redacted receipts and trace refs
- every model turn follows model -> tool -> typed result -> model loops until
  completion or an explicit stop condition
- deterministic runtime layers enforce policy, normalize evidence, redact,
  receipt, replay, and validate; they never author product answers
- every file edit has either hunk review state or an explicit governed
  direct-write policy reason
- hunk accept/reject/rollback handles stale edits, overlapping hunks, multi-file
  edits, and out-of-band workspace mutations
- Stop, cancel, recover, and replay work through daemon-owned state, not GUI
  memory
- shell/browser/computer-use effects are sandboxed, lease-governed, redacted,
  timeout-bound, and cleaned up
- product chat remains clean: raw JSON, receipt ids, route internals, fixture
  paths, policy payloads, model hashes, and daemon event names stay in
  Runs/Tracing/evidence
- live GUI proof covers realistic repo work, browser work, shell/test repair,
  denial/approval, cancellation/resume, replay, and hunk review

## Evidence Root

Use:

```text
docs/evidence/autopilot-agent-runtime-parity-plus/
```

Final outputs:

- `docs/evidence/autopilot-agent-runtime-parity-plus/agent-runtime-parity-plus-final-manifest.json`
- `docs/evidence/autopilot-agent-runtime-parity-plus/final-agent-runtime-parity-plus-verdict.md`

Every stage scenario directory must include:

- `scenario.json`
- `source-requirements.json`
- `implementation-refs.json`
- `gui-before.png`
- `gui-active.png` when visual state changes
- `gui-after.png`
- `runtime-events.jsonl`
- `trajectory-state.json`
- `trace-refs.json`
- `receipts.jsonl`
- `policy-verdicts.jsonl`
- `side-effects-before.json`
- `side-effects-after.json`
- `latency.json`
- `cleanup-proof.json`
- `failure-analysis.md` when a defect appears
- `fixes-applied.md` when code changes
- `stage-verdict.json`

## Outcome Classes

Use these statuses:

- `live_pass`: proven through real Autopilot GUI with screenshots, traces, and cleanup
- `fixed_then_pass`: defect found, fixed, verified, and live-proven
- `headless_pass`: daemon/headless API proof for runtime ownership
- `cross_client_pass`: GUI/CLI/TUI consume the same daemon contract
- `policy_gate_pass`: elevated action paused or denied before effect
- `sandbox_effect_pass`: effect occurred only inside disposable sandbox
- `supporting_pass`: static/unit/CLI evidence that does not close product proof alone
- `supporting_pass_with_product_decision`: supporting proof plus explicit scope decision
- `rejected_with_product_decision`: intentionally not adopted, with reason
- `deferred_optional`: outside default product claim
- `blocked_with_owner`: blocked with owner, reproduction, and next proof step
- `partial_unproven`: implemented or sketched but not fully proven
- `gap`: not meaningfully implemented or tested
- `trace_leak`: trace/receipt/internal payload leaked into product UI
- `hidden_cot_leak`: hidden chain-of-thought exposed
- `raw_payload_leak`: raw JSON/tool/policy payload exposed
- `fixture_leak`: fixture/deterministic marker exposed in product output

## Low-Level Runtime Map

This campaign must touch or explicitly audit the following implementation
surfaces. A stage cannot close if the relevant ownership layer is not named in
its `implementation-refs.json`.

### Rust Runtime Loop And Cognition

- `crates/services/src/agentic/runtime/service/decision_loop/mod.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/orchestration.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/pending_resume.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/cognition/mod.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/cognition/inference.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/cognition/final_reply.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/cognition/tool_prompting.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/cognition/workspace_changes.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/signals/`

Audit requirement:

- no deterministic product answer shapers remain on the final answer path
- finalization uses model-authored answers plus validators/sanitizers
- tool results re-enter the model loop as typed results, not prewritten prose
- completion gates are explicit and traceable

### Tool Execution And Action Boundary

- `crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/tool_outcome.rs`
- `crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/tool_outcome/support.rs`
- `crates/services/src/agentic/runtime/service/tool_execution/processing/phases/finalize_action_processing.rs`
- `crates/services/src/agentic/runtime/service/tool_execution/processing/repair/`
- `crates/services/src/agentic/runtime/service/actions/resume/`
- `crates/services/src/agentic/runtime/service/actions/checks.rs`

Audit requirement:

- policy, receipt, redaction, side effects, and cleanup collapse at the action
  boundary
- product text does not come from tool adapters except as typed evidence/result
- failed, denied, timed out, cancelled, and resumed actions share a typed schema

### Queue, Web Research, And Grounded Answering

- `crates/services/src/agentic/runtime/service/queue/processing/web_pipeline/`
- `crates/services/src/agentic/runtime/service/queue/support/query/`
- `crates/services/src/agentic/runtime/service/queue/support/pipeline/`
- `crates/services/src/agentic/runtime/service/queue/support/synthesis/`
- `crates/services/src/agentic/runtime/service/handler/web_research.rs`

Audit requirement:

- web/search/read are context acquisition tools, not deterministic final answer
  authors
- source inventory, candidate recovery, redaction, and citation normalization
  are allowed
- product answer structure comes from the model finalization pass
- current/high-stakes queries gather fresh sources or fail closed with a clean
  product explanation

### Policy, Lease, Sandbox, And Runtime Locality

- `crates/services/src/agentic/runtime/service/policy.rs`
- `crates/services/src/agentic/runtime/service/lifecycle/handlers/approval_authority.rs`
- `crates/services/src/agentic/runtime/service/lifecycle/handlers/operator_control.rs`
- `crates/services/src/agentic/runtime/service/lifecycle/runtime_locality.rs`
- `crates/services/src/agentic/runtime/service/lifecycle/sudo.rs`
- `crates/services/src/agentic/runtime/service/handler/approvals.rs`
- `crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs`
- `crates/services/src/agentic/runtime/service/handler/execution/execution/workload_spec.rs`

Audit requirement:

- full access, auto-review, and default permissions map to daemon-owned leases
- risky command/file/network/browser/desktop actions pause before effect
- leases are revocable, expiring, traceable, and visible to all clients
- sandbox blocks symlink traversal, ignored-file access, network by default,
  credential-looking env/log output, and sibling-prefix escapes

### Delegation, Subagents, And Worker Recovery

- `crates/services/src/agentic/runtime/service/lifecycle/delegation/`
- `crates/services/src/agentic/runtime/service/lifecycle/worker_results/`
- `crates/services/src/agentic/runtime/service/lifecycle/browser_subagent.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/worker.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/cognition/worker_context.rs`

Audit requirement:

- subagents have linked child trajectories, parent references, scorecards, and
  resumable state
- failed workers produce typed evidence and recovery prompts
- worker state survives GUI reload and daemon restart

### Memory, Context, Compaction, And Brain Artifacts

- `crates/services/src/agentic/runtime/service/memory/`
- `crates/services/src/agentic/runtime/service/lifecycle/compaction.rs`
- `crates/services/src/agentic/runtime/service/planning/`
- `crates/services/src/agentic/runtime/service/decision_loop/cognition/history/`

Audit requirement:

- run memory is separate from user workspace files
- active plan/task/walkthrough/scratch artifacts are daemon-owned
- compaction preserves tool/result/action state and does not flatten pending
  hunk/lease/session state into vague prose

### Runtime Bridge And Client Contract

- `crates/node/src/bin/ioi-runtime-bridge.rs`
- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-event-utils.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio-work-summary.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio/studio-panel-html.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio/agent-answer-stream.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio/agent-final-handoff-stream.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio/operational-surface.js`
- `scripts/run-autopilot-agent-studio-live-gui-validation.mjs`
- `scripts/lib/agent-studio-live-gui-validation/`

Audit requirement:

- GUI renders runtime state; it does not own core harness semantics
- stream events are typed, versioned, replayable, and safe for CLI/TUI reuse
- glass-box work lane remains product-clean while Runs/Tracing keeps details

## Source Requirement Map

The low-level requirements must be traced back to these clean-room reference
docs:

- Runtime loop:
  `internal-docs/reverse-engineering/antigravity/clean-room/runtime-loop.md`
- Trajectory schema:
  `internal-docs/reverse-engineering/antigravity/clean-room/trajectory-schema.md`
- Brain/memory:
  `internal-docs/reverse-engineering/antigravity/antigravity-brain-memory-architecture.md`
- Permissions:
  `internal-docs/reverse-engineering/antigravity/clean-room/permissions.md`
- Sandbox:
  `internal-docs/reverse-engineering/antigravity/clean-room/sandbox.md`
- Tool registry:
  `internal-docs/reverse-engineering/antigravity/clean-room/tool-registry.md`
- UI state:
  `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/ui-state-machine.md`
- Inline rendering:
  `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/inline-rendering.md`
- UX reconciliation:
  `internal-docs/reverse-engineering/antigravity/ux/antigravity-workbench-ux-reconciliation.md`

## P0 Runtime Rows

The final manifest must include at least these rows.

| ID | Priority | Runtime Target | Primary Implementation Surface | Required Proof |
| --- | --- | --- | --- | --- |
| ARP-P0-001 | P0 | Durable trajectory store | `decision_loop/`, new or existing trajectory module, bridge event persistence | Headless restart plus GUI replay proof |
| ARP-P0-002 | P0 | Active brain artifacts | `memory/`, `planning/`, Agent Studio run state | Plan/task/walkthrough/scratch created, updated, replayed |
| ARP-P0-003 | P0 | Model/tool/result/model loop native | `cognition/`, `tool_outcome/`, `queue/support/synthesis/` | No deterministic final answer authoring; tool results return to model |
| ARP-P0-004 | P0 | Editor hunk proposal state | `workspace_changes.rs`, OpenVSCode editor integration | Inline hunk render for disposable edit |
| ARP-P0-005 | P0 | Hunk accept/reject/rollback | editor integration, runtime action boundary | Accept/reject single hunk, reject all, rollback after stale change |
| ARP-P0-006 | P0 | Stop/cancel/recover | `pending_resume.rs`, lifecycle handlers, bridge | Cancel active model/tool, kill children, resume from durable state |
| ARP-P0-007 | P0 | Stop hook validation | `actions/checks.rs`, tool execution repair loop | Failing test/diagnostic blocks completion and returns to model loop |
| ARP-P0-008 | P0 | Policy lease model | `policy.rs`, approval handlers, Studio permissions menu | allow-once, deny, revoke, expiry, full access mapping |
| ARP-P0-009 | P0 | Sandbox hardening | execution workload/firewall/locality modules | symlink, ignored file, network deny, env redaction, output caps |
| ARP-P0-010 | P0 | Shell lifecycle | execution handlers, retained process state | background, stream, stall, terminate, cleanup proof |
| ARP-P0-011 | P0 | Browser/computer managed session runtime | browser subagent, bridge events, Studio session cards | observe/take-over/return/waiting states survive replay |
| ARP-P0-012 | P0 | Delegation trajectory linkage | `lifecycle/delegation/`, `worker_results/` | child run linked, failed child recovered, parent evidence merged |
| ARP-P0-013 | P0 | Replay and reconnect | bridge, trajectory, Studio render contract | reload/reconnect displays same run state without double effects |
| ARP-P0-014 | P0 | Trace/product boundary | final reply sanitizer, work summary, tracing surface | no raw payloads/receipts/fixture paths in chat |
| ARP-P0-015 | P0 | Cross-client daemon ownership | headless API plus GUI/CLI/TUI where available | same contract used without GUI-only harness logic |

## P1 Runtime Rows

| ID | Priority | Runtime Target | Required Decision |
| --- | --- | --- | --- |
| ARP-P1-001 | P1 | Mermaid and richer inline renderers | Adopt if product-safe, otherwise defer with reason |
| ARP-P1-002 | P1 | Artifact walkthrough document | Adopt as daemon-owned run artifact |
| ARP-P1-003 | P1 | Restart backend UX | Adopt if restart preserves trajectory, otherwise document blocker |
| ARP-P1-004 | P1 | Policy lease timeline surface | Adopt minimal first version, defer analytics polish |
| ARP-P1-005 | P1 | Rule/onboarding files | Adopt only as structured policy/compiler inputs, not prompt-only rules |

## Stage 0: Baseline Import And Gap Tracker

Objective:

- Convert this guide into an executable campaign tracker.
- Seed the final manifest with P0/P1 rows.
- Record current evidence baselines without rerunning broad catalogue tests.

Implementation pointers:

- `.internal/plans/autopilot-antigravity-harness-parity-plus-master-guide.md`
- `docs/evidence/autopilot-agent-studio-glass-box-work-lane/glass-box-work-lane-final-manifest.json`
- `scripts/run-autopilot-agent-studio-live-gui-validation.mjs`
- `scripts/lib/agent-studio-live-gui-validation/trace-summary.mjs`

Proof:

- Manifest builder emits all ARP rows.
- No row is accidentally marked green from unrelated catalogue evidence.
- Worktree file-size and monolith audit recorded.

Exit criteria:

- `stage-0-baseline/stage-verdict.json` lists every row with owner and source
  requirements.

## Stage 1: Trajectory And Brain Substrate

Objective:

- Add daemon-owned durable run state and active run memory artifacts.

Reference docs:

- `internal-docs/reverse-engineering/antigravity/clean-room/trajectory-schema.md`
- `internal-docs/reverse-engineering/antigravity/antigravity-brain-memory-architecture.md`

Required behavior:

- Each Agent turn has a durable trajectory id.
- Each step has sequence, type, status, timestamps, parent/child refs,
  policy refs, trace refs, and redacted payload refs.
- Active brain contains:
  - `implementation_plan`
  - `task_checklist`
  - `walkthrough`
  - `scratch_refs`
  - `artifact_refs`
  - `replay_cursor`
- Brain state lives outside user project files unless explicitly promoted.
- GUI reload and daemon restart can reconstruct the current run.

Implementation pointers:

- `crates/services/src/agentic/runtime/service/memory/`
- `crates/services/src/agentic/runtime/service/planning/`
- `crates/services/src/agentic/runtime/service/decision_loop/`
- `crates/node/src/bin/ioi-runtime-bridge.rs`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio-work-summary.js`

Proof scenarios:

- Start a disposable repo task, observe plan/task creation, kill/restart GUI,
  reopen run, and confirm task state and work lane remain.
- Start a tool-using task, kill daemon after step N, restart, and confirm replay
  shows completed steps without re-executing side effects.

Exit criteria:

- `ARP-P0-001` and `ARP-P0-002` are `headless_pass` and `live_pass`.

## Stage 2: Model Tool Result Model Loop Native

Objective:

- Remove remaining deterministic final answer behavior from runtime paths.
- Keep deterministic code only for enforcement, observation, redaction,
  normalization, receipts, replay, and validators.

Implementation pointers:

- `decision_loop/cognition/mod.rs`
- `decision_loop/cognition/inference.rs`
- `decision_loop/cognition/final_reply.rs`
- `decision_loop/cognition/tool_prompting.rs`
- `tool_execution/.../tool_outcome.rs`
- `queue/support/synthesis/`
- `queue/processing/web_pipeline/`

Required audit:

- Search for answer-authoring names such as `draft`, `story`, `briefing`,
  `deterministic`, `fallback`, `summary`, and `template`.
- Classify each instance as:
  - enforcement/normalization allowed
  - evidence packet allowed
  - product answer authoring forbidden
  - dead code removable
- Rename misleading types to `EvidencePacket`, `ToolResultPacket`,
  `SourceInventory`, `AnswerValidation`, or similarly precise names.

Proof scenarios:

- Current/investment query: runtime gathers sources, passes typed source/tool
  results back to model, final answer is model-authored, no deterministic
  "Story 1" / "Briefing for" / timestamp/confidence boilerplate.
- Website artifact query: model authors source/content; artifact lifecycle
  renders deliverable; no canned projection shells.
- Repo question: workspace search/read results feed model finalization; no
  internal runtime repository assumptions unless the user's workspace is the
  runtime repo.

Exit criteria:

- `ARP-P0-003` is `fixed_then_pass`.
- Static guard rejects deterministic product templates.
- Live GUI proof shows natural model-authored answers.

## Stage 3: Editor Hunk Workflow

Objective:

- Make code edits reviewable in the editor, not just summarized in chat.

Reference docs:

- `internal-docs/reverse-engineering/antigravity/ux/antigravity-workbench-ux-reconciliation.md`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/ui-state-machine.md`
- `internal-docs/reverse-engineering/antigravity/clean-room/tool-registry.md`

Required behavior:

- File edit tools create pending hunk records with exact-match preconditions.
- The editor renders additions/deletions inline.
- User can focus next/previous hunk.
- User can accept/reject a single hunk.
- User can accept/reject all pending hunks.
- Stale hunks are detected when file contents drift.
- Reject restores original content.
- Multi-file edits can be partially accepted and safely rolled back.

Implementation pointers:

- `decision_loop/cognition/workspace_changes.rs`
- `tool_execution/.../tool_outcome.rs`
- `tool_execution/.../repair/`
- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio/studio-panel-html.js`
- OpenVSCode editor decoration APIs in the extension host

Proof scenarios:

- Disposable repo formatter fix: propose hunk, accept hunk, run test.
- Same fix: reject hunk, verify file restored.
- Modify file externally after proposal: stale hunk state blocks apply.
- Multi-hunk edit: accept one, reject one, verify final file and trace.

Exit criteria:

- `ARP-P0-004` and `ARP-P0-005` are `live_pass`.

## Stage 4: Policy Lease And Sandbox Runtime

Objective:

- Turn permissions into daemon-owned leases and harden sandbox effects.

Reference docs:

- `internal-docs/reverse-engineering/antigravity/clean-room/permissions.md`
- `internal-docs/reverse-engineering/antigravity/clean-room/sandbox.md`

Required behavior:

- Permission modes map to leases:
  - default permissions
  - auto-review
  - full access
  - allow once
  - deny
  - revoke
  - expiry
- Risky actions pause before effect.
- Sandbox enforces:
  - workspace boundary
  - symlink escape rejection
  - sibling-prefix escape rejection
  - ignored-file protection
  - default network deny for shell
  - redacted env/stdout/stderr
  - timeout and output caps

Implementation pointers:

- `policy.rs`
- `lifecycle/handlers/approval_authority.rs`
- `handler/approvals.rs`
- `handler/execution/execution/firewall_policy.rs`
- `handler/execution/execution/workload_spec.rs`
- `lifecycle/runtime_locality.rs`
- `lifecycle/sudo.rs`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio/operational-surface.js`

Proof scenarios:

- Risky shell command pauses; allow-once runs; lease expires.
- Denied command returns typed denial to model.
- Revoke a lease and rerun same command; it pauses again.
- Shell cannot read `.env`, symlink target outside workspace, or sibling path.
- Shell network attempt denied unless a specific lease exists.

Exit criteria:

- `ARP-P0-008` and `ARP-P0-009` are `policy_gate_pass` and
  `sandbox_effect_pass`.

## Stage 5: Stop, Cancel, Recover, And Stop Hook

Objective:

- Make interruption and recovery reliable at runtime level.

Reference docs:

- `internal-docs/reverse-engineering/antigravity/clean-room/runtime-loop.md`
- `internal-docs/reverse-engineering/antigravity/clean-room/modules/stop_hooks.py`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/ui-state-machine.md`

Required behavior:

- Stop cancels model stream.
- Stop terminates shell/browser/computer-use child process trees.
- Cancel persists terminal state and cleanup receipts.
- Resume restarts from durable trajectory cursor without replaying completed
  side effects.
- Finish is blocked when diagnostics or tests fail.
- Stop-hook failure is injected as typed tool/result context and model continues.

Implementation pointers:

- `decision_loop/pending_resume.rs`
- `actions/resume/`
- `actions/checks.rs`
- `lifecycle/handlers/operator_control.rs`
- `lifecycle/handlers/resume.rs`
- `queue/processing/pause_state.rs`
- `scripts/lib/agent-studio-live-gui-validation/prompt-submit.mjs`

Proof scenarios:

- Cancel during model stream.
- Cancel during long shell command.
- Cancel during browser session.
- Resume after daemon restart.
- Failing test blocks completion, model edits again, test passes, completion
  allowed.

Exit criteria:

- `ARP-P0-006`, `ARP-P0-007`, `ARP-P0-010`, and `ARP-P0-013` are
  `fixed_then_pass` or `live_pass`.

## Stage 6: Typed Stream Contract And Glass-Box Work Lane

Objective:

- Ensure the GUI, CLI, and TUI consume the same typed event stream.

Baseline:

- `docs/evidence/autopilot-agent-studio-glass-box-work-lane/glass-box-work-lane-final-manifest.json`

Required behavior:

- Events are versioned and typed:
  - thinking preview
  - provider reasoning
  - text delta
  - tool proposed
  - policy blocked
  - tool running
  - tool result
  - hunk proposed
  - hunk decision
  - browser/computer session
  - artifact source
  - final answer
  - metrics
  - cleanup
- Product chat receives safe projection.
- Runs/Tracing receives full details.
- Replay uses the same event stream.

Implementation pointers:

- `crates/node/src/bin/ioi-runtime-bridge.rs`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-event-utils.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio-work-summary.js`
- `apps/autopilot/openvscode-extension/ioi-workbench/studio/studio-panel-html.js`
- `scripts/lib/agent-studio-live-gui-validation/trace-summary.mjs`

Proof scenarios:

- GUI live run.
- Headless event stream replay.
- Reload GUI from persisted events.
- Verify collapsed work lane remains `Worked for Xs`.

Exit criteria:

- `ARP-P0-014` and `ARP-P0-015` are `cross_client_pass` or `live_pass`.

## Stage 7: Delegation And Subagent Lanes

Objective:

- Make delegated work first-class and recoverable.

Required behavior:

- Parent run can spawn child trajectory.
- Child has independent steps, policy, evidence, and cleanup.
- Parent work lane shows child summary, not raw child payloads.
- Failed child returns typed error/evidence to parent model loop.
- Browser subagent sessions are managed live artifacts.

Implementation pointers:

- `lifecycle/delegation/`
- `lifecycle/worker_results/`
- `lifecycle/browser_subagent.rs`
- `decision_loop/worker.rs`
- `decision_loop/cognition/worker_context.rs`

Proof scenarios:

- Delegate repo verification task.
- Child fails test and parent handles recovery.
- Browser subagent inspects fixture and returns evidence.
- Kill/restart during child run and recover parent/child linkage.

Exit criteria:

- `ARP-P0-012` is `live_pass`.

## Stage 8: Browser And Computer Session Runtime Polish

Objective:

- Preserve the current managed live session UX while pushing state ownership
  deeper into daemon/runtime.

Baseline:

- Glass-box final manifest managed session proof.

Required behavior:

- Sandbox browser, local browser, and desktop session kinds are typed.
- Observe/take-over/return control are runtime state transitions.
- Waiting-for-user state exists for login, CAPTCHA, payment, file picker, or
  other manual-only action.
- Screenshot quarantine/redaction is enforced before persistence.
- Session state survives replay/reconnect.

Implementation pointers:

- `lifecycle/browser_subagent.rs`
- `handler/execution/handlers/automation.rs`
- `studio/operational-surface.js`
- `studio/studio-panel-html.js`
- `internal-docs/reverse-engineering/antigravity/clean-room/interface-parity/inline-rendering.md`

Proof scenarios:

- Sandbox browser fixture inspect.
- Take over and return control.
- Waiting-for-user fixture action.
- Replay managed session card after reload.

Exit criteria:

- `ARP-P0-011` is `live_pass`.

## Stage 9: Evidence, Replay, And Product Boundary

Objective:

- Make evidence useful without polluting chat.

Required behavior:

- Receipts/traces/policy payloads live in Runs/Tracing/evidence.
- Product chat exposes source-rich work rows and clean handoff only.
- Replay can show historic run state from trajectory/evidence.
- Redaction runs before persistence, not after.

Implementation pointers:

- `queue/processing/*receipts.rs`
- `handler/execution/execution/receipt_emission.rs`
- `handler/pii.rs`
- `final_reply.rs`
- `studio-work-summary.js`
- `studio-panel-html.js`

Proof scenarios:

- Chat leak audit for every P0 scenario.
- Evidence pane opens trace detail from source/work row.
- Replay historic run with no live tool execution.

Exit criteria:

- No leak status remains in final manifest.

## Stage 10: Refactor And Naming Hygiene

Objective:

- Keep the runtime navigable under limited context windows.

Rules:

- No newly touched source file should grow past 2,000 LOC without an immediate
  split plan or split patch.
- Legacy answer-shaping names must be renamed when touched:
  - `story`
  - `briefing`
  - `draft`
  - `hybrid`
  - `deterministic` when it means product answer authoring
- Use responsibility names:
  - `EvidencePacket`
  - `SourceInventory`
  - `ToolResultPacket`
  - `AnswerValidation`
  - `ActionReceipt`
  - `TrajectoryStep`
  - `PolicyLease`
  - `HunkProposal`
- Tests should prove behavior, not preserve brittle source-string templates.

Required audit commands:

```bash
rg -n "story|briefing|draft|hybrid|deterministic|fallback|template" crates/services/src/agentic/runtime/service apps/autopilot/openvscode-extension/ioi-workbench
find crates/services/src/agentic/runtime/service apps/autopilot/openvscode-extension/ioi-workbench -type f \( -name '*.rs' -o -name '*.js' -o -name '*.mjs' \) -print0 | xargs -0 wc -l | sort -nr | head -40
```

Exit criteria:

- Every remaining legacy name has a documented reason or replacement issue.
- New modules align with runtime ownership boundaries.

## Stage 11: Integrated Product Soak

Objective:

- Prove the runtime behaves as one coherent harness, not isolated green rows.

Required live scenarios:

1. Disposable repo failing test:
   - plan created
   - hunk proposed
   - user accepts hunk
   - test fails once
   - stop hook blocks completion
   - model fixes
   - test passes
   - walkthrough created
2. Risky command:
   - policy lease prompts
   - deny returns typed result
   - allow-once runs
   - lease expiry verified
3. Browser fixture:
   - sandbox browser opens
   - observe/take-over/return
   - waiting-for-user state demonstrated
   - replay survives reload
4. Delegated worker:
   - child trajectory starts
   - child emits evidence
   - parent merges result
   - restart recovers both
5. Cancellation:
   - cancel active shell/browser/model path
   - no child processes remain
   - resume from durable cursor
6. Current-source question:
   - fresh context gathered
   - source chips shown
   - final answer model-authored
   - no deterministic template remnants

Exit criteria:

- Integrated soak manifest contains all P0 rows with evidence paths.
- Final cleanup proves no Autopilot, runtime bridge, daemon, shell, browser,
  computer-use, preview server, worker, or model process remains unexpectedly.

## Final Manifest Shape

Each row must use this shape:

```json
{
  "id": "ARP-P0-001",
  "priority": "P0",
  "title": "Durable trajectory store",
  "status": "fixed_then_pass",
  "owner": "Rust runtime trajectory substrate",
  "sourceRequirements": [
    "internal-docs/reverse-engineering/antigravity/clean-room/trajectory-schema.md"
  ],
  "implementationRefs": [
    "crates/services/src/agentic/runtime/service/decision_loop/mod.rs"
  ],
  "tests": [],
  "liveEvidence": [],
  "screenshots": [],
  "traceRefs": [],
  "cleanupProof": "",
  "leakAudit": {
    "hiddenCotLeak": false,
    "traceLeak": false,
    "rawPayloadLeak": false,
    "fixtureLeak": false
  },
  "residualRisk": "",
  "nextProofStep": ""
}
```

The final verdict must include:

- target verdict
- P0/P1 summary table
- source requirement coverage
- implementation reference coverage
- live GUI evidence paths
- headless/cross-client proof paths
- leak audit
- cleanup proof
- refactor/naming audit
- remaining blockers, if any, with owner and next step

## Immediate Tactical Start

Start with Stage 0 and Stage 1. Do not begin with a broad GUI soak.

First implementation slice:

1. Add a runtime-owned `TrajectoryStep`/`PolicyLease`/`RunBrain` contract.
2. Persist it from the daemon path before GUI rendering.
3. Project it into the existing glass-box work lane.
4. Prove reload/restart recovery on one disposable repo scenario.
5. Only then continue into hunk workflow.

This order prevents the campaign from producing attractive UI over in-memory
state. The whole point of parity-plus is that the operator can trust the run
after interruptions, edits, approvals, and recovery.

## Latest Validation

Status: Achieved

Evidence: `docs/evidence/autopilot-agent-runtime-parity-plus/stage-4-policy-lease-sandbox/live-gui-sibling-write-boundary-denial/2026-06-02T20-32-58-887Z/`

Root cause: the earlier harness validated focus and daemon turn completion, but it did not prove model-backed token streaming and allowed canned Agentgres run projections to masquerade as assistant answers. Studio now routes chat through daemon-owned `/v1/chat/completions` streaming, and this harness rejects canned daemon projections.

Queries tested: agent blocked sibling workspace write.

Remaining blockers: none.

Connector sprint readiness impact: Agent Studio chat focus and prompt submission are Playwright-controlled and daemon-routed; connector work remains dry-run only.
