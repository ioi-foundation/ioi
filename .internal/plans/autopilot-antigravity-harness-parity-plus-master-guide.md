# Autopilot Antigravity Harness Parity Plus Master Guide

Owner: Autopilot Workbench / Agent Studio / Rust Agentic Runtime / Runtime Daemon / Agent IDE / Workflow Compositor / Policy and Sandbox Runtime

Status: active planning guide

Created: 2026-05-27

Baseline audit:

- `docs/evidence/antigravity-agent-harness-gap-audit/2026-05-27-current-state-gap-audit.md`
- `docs/evidence/antigravity-agent-harness-gap-audit/2026-05-27-gap-manifest.json`

Baseline default harness proof:

- `docs/evidence/autopilot-agent-studio-full-default-harness-parity/tool-catalogue-full-default-harness-parity-final-manifest.json`
- `docs/evidence/autopilot-agent-studio-full-default-harness-parity/final-default-harness-parity-verdict.md`

Reference reverse-engineering dossier:

- `internal-docs/reverse-engineering/antigravity-tool-catalogue.md`
- `internal-docs/reverse-engineering/antigravity-runtime-traces.md`
- `internal-docs/reverse-engineering/antigravity-protocol-schemas.md`
- `internal-docs/reverse-engineering/antigravity-brain-memory-architecture.md`
- `internal-docs/reverse-engineering/antigravity-sandbox-boundary-report.md`
- `internal-docs/reverse-engineering/ux/antigravity-workbench-ux-reconciliation.md`

Parent guides:

- `.internal/plans/autopilot-agent-studio-full-default-harness-parity-proof-master-guide.md`
- `.internal/plans/autopilot-agent-studio-rust-tool-catalogue-live-ide-verification-12h-master-guide.md`
- `.internal/plans/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus-12h-master-guide.md`
- `.internal/plans/autopilot-electron-workbench-workflow-compositor-parity-master-guide.md`

## Executive Intent

The default Rust harness catalogue is green. This campaign must not repeat that
catalogue proof.

The next target is Antigravity-grade harness parity plus: make Autopilot
observable, reversible, restartable, reviewable, sandboxed, and operator-safe at
the level described in `internal-docs/reverse-engineering`.

The campaign climbs this ladder:

1. trajectory and brain substrate
2. editor hunk workflow
3. sandbox and lease UX
4. stop, cancel, recover loop
5. context and typed stream contract
6. delegation lanes
7. live browser/computer polish
8. evidence panes, rules, onboarding, and optional provider clarity

This is a product-runtime campaign. The primary question is no longer "can the
tool execute?" It is "can an operator trust, inspect, interrupt, replay, and
recover the autonomous run inside the IDE?"

## Clean-Room Boundary

Use the Antigravity notes only as behavioral requirements and compatibility
targets. Do not copy proprietary code, assets, names, icons, CSS, binary blobs,
or private schemas beyond the clean-room-compatible interfaces documented in
the reverse-engineering files.

Autopilot should implement IOI-native equivalents:

- daemon-owned authority, policy, receipts, and replay
- Agentgres/trajectory-compatible durable state
- IOI-native Policy Lease UX instead of direct Battle Mode cloning
- managed browser/computer sessions instead of hidden headless automation
- clean product chat plus trace/evidence detail outside the transcript

## Definition Of Done

The campaign is complete only when a final manifest can honestly say:

```text
antigravity_harness_parity_plus_proven
```

Required conditions:

- all `P0` and `P1` gaps from the baseline audit are `live_pass`,
  `fixed_then_pass`, or explicitly reclassified with a product decision
- no `P0` gap remains `partial_unproven`, `gap`, or `blocked`
- no raw test fixture markers, trace payloads, receipt ids, JSON dumps, or
  filesystem scaffolding appear in product chat
- every workspace mutation has a visible causal step and trace/evidence record
- every edit proposal has reviewable hunk state or an explicit direct-write
  policy reason
- Stop Agent kills or cancels model streams, shell trees, browser sessions, and
  child workers
- crash/restart proof resumes from durable state, not from in-memory luck
- shell execution has a hardened sandbox path with default network deny,
  environment filtering, timeout enforcement, output caps, and cleanup proof
- elevated effects require Policy Lease UX with revocation
- browser/computer automation has live managed session artifacts and
  `Waiting for user` handoff for manual-only actions
- final cleanup proves no Autopilot, runtime bridge, daemon, shell, browser, or
  computer-use child process remains

Provider-specific features may remain outside the claim only when they are
explicitly marked optional and absent from the default product surface.

## Non-Negotiable Rules

- Run product proof through the real Autopilot IDE GUI and Agent Studio.
- Do not count CLI-only or SDK-only proof as product parity. Use it only as
  supporting evidence after a GUI scenario exists.
- Do not rerun broad catalogue scenarios as a substitute for fixing a specific
  harness gap.
- Start each stage with the smallest live reproduction and end with an
  integrated GUI proof.
- Use disposable workspaces, browser profiles, shell commands, memory state,
  subagent tasks, and computer-use sessions.
- Kill Autopilot, runtime bridge, daemon, shell children, browser children, and
  computer-use sessions after every scenario; record cleanup.
- Refactor immediately when a file becomes monolithic.
- Keep Ask as direct model answers and Agent as governed harness execution.
- Keep receipts and traces in Runs/Tracing/evidence, not product chat.
- Screenshot every GUI proof and review screenshots for product UX defects.

## Evidence Root

Use:

```text
docs/evidence/autopilot-antigravity-harness-parity-plus/
```

Each stage receives:

```text
docs/evidence/autopilot-antigravity-harness-parity-plus/<timestamp>-stage-<n>-<slug>/
```

Every scenario directory must include:

- `scenario.json`
- `baseline-gap-ids.json`
- `gui-before.png`
- `gui-during.png` when the state is visual
- `gui-after.png`
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
- `stage-verdict.json`

Final campaign outputs:

- `docs/evidence/autopilot-antigravity-harness-parity-plus/antigravity-harness-parity-plus-final-manifest.json`
- `docs/evidence/autopilot-antigravity-harness-parity-plus/final-antigravity-harness-parity-plus-verdict.md`

## Outcome Classes

Use these status values in manifests:

- `live_pass`: proven in the live GUI with trace, screenshots, and cleanup
- `fixed_then_pass`: defect found, fixed, tested, and live-proven
- `supporting_pass`: unit/CLI/SDK evidence that supports but does not close GUI
  parity by itself
- `policy_gate_pass`: elevated action correctly paused or denied before effect
- `sandbox_effect_pass`: effect occurred only inside disposable sandbox
- `deferred_optional`: explicitly outside the product/default claim
- `blocked_with_owner`: blocked with reproduction, owner, evidence, and next
  proof step
- `partial_unproven`: implemented or sketched, but not yet live-proven
- `gap`: not implemented or not yet meaningfully tested

## Manifest Shape

Each gap row in the final manifest must include:

```json
{
  "id": "AG-HARNESS-001",
  "priority": "P0",
  "status": "fixed_then_pass",
  "owner": "Runtime trajectory substrate",
  "sourceRequirements": [
    "internal-docs/reverse-engineering/antigravity-protocol-schemas.md:226"
  ],
  "implementationRefs": [],
  "tests": [],
  "liveEvidence": [],
  "screenshots": [],
  "cleanupProof": "",
  "residualRisk": "",
  "nextProofStep": ""
}
```

## Stage 0: Baseline Import And Harness

Gap IDs: all

Objective:

- Convert the audit manifest into a campaign tracker.
- Build or update helper scripts that can collect screenshots, traces, receipts,
  cleanup, and gap verdicts without reusing catalogue-only assumptions.

Required work:

- Create a campaign manifest seeded from
  `docs/evidence/antigravity-agent-harness-gap-audit/2026-05-27-gap-manifest.json`.
- Add scenario selection by gap id.
- Add a final manifest builder for this campaign.
- Add screenshot review hooks for product chat, hunk UI, evidence pane, lease
  dialog, terminal cards, browser sessions, and recovery UI.

Proof:

- Static manifest build passes.
- A no-op GUI launch captures baseline Agent Studio, run/tracing pane, and
  cleanup proof.

Exit criteria:

- Stage 0 manifest lists all `AG-HARNESS-*` rows.
- No row is lost or accidentally reclassified green.

## Stage 1: Trajectory And Brain Substrate

Gap IDs:

- `AG-HARNESS-001`
- `AG-HARNESS-006`
- supporting setup for `AG-HARNESS-018`

Objective:

- Establish durable per-run trajectory state and active per-run brain artifacts.
- This is the root substrate for replay, recovery, evidence panes, stop hooks,
  subagent linkage, and operator trust.

Required runtime behavior:

- Every Agent run has a durable trajectory id.
- Every step has ordered metadata, status, tool/event payload, policy decision,
  and error payload when applicable.
- A compatibility layer can write and read the Antigravity-inspired seven-table
  SQLite shape:
  - `trajectory_meta`
  - `steps`
  - `gen_metadata`
  - `executor_metadata`
  - `parent_references`
  - `trajectory_metadata_blob`
  - `battle_mode_infos`
- Binary/protobuf compatibility may start as IOI-native typed blobs, but field
  mapping must be documented and stable.
- Every Agent run creates a session brain directory outside the workspace:
  - `implementation_plan.md`
  - `task.md`
  - `walkthrough.md`
  - `scratch/`
- Shell tools cannot read or write sibling brain directories directly.
- Completed brain artifacts are preserved read-only or tamper-evident.

Product behavior:

- Chat stays clean.
- Run/Tracing shows a trajectory id and links to implementation plan, task list,
  walkthrough, and scratch artifacts.
- Evidence pane can render these artifacts when Stage 8 lands.

Focused proof scenarios:

1. Simple file-read Agent run writes trajectory records and brain skeleton.
2. Mutating file edit run writes pre/post state and walkthrough.
3. Failed tool run writes error details and no false completion.

Exit criteria:

- SQLite/trajectory inspection shows ordered steps with status and payload.
- Brain directory contains the four required artifacts.
- Cleanup passes.
- Manifest rows `AG-HARNESS-001` and `AG-HARNESS-006` are at least
  `fixed_then_pass`.

## Stage 2: Editor Hunk Workflow

Gap IDs:

- `AG-HARNESS-004`
- `AG-HARNESS-005`

Objective:

- Make code edits reviewable in the editor, not just visible in traces.
- Prove exact-match edit semantics and multi-hunk rollback before product UX
  polish is counted.

Required runtime behavior:

- Single hunk edits must validate exact target content before writing.
- Stale hunk attempts fail with a structured stale-hunk error.
- Multi-hunk edits validate every hunk before committing any bytes.
- Partial multi-hunk failure leaves the target file completely unchanged.
- Every proposed hunk has an id, file path, before range, after range,
  originating step id, and rollback metadata.

Required product behavior:

- Pending hunks render as editor decorations.
- User can focus next/previous hunk with keyboard shortcuts.
- User can accept focused hunk.
- User can reject focused hunk and restore the original lines.
- Chat shows a work summary and clean answer only.
- Trace records hunk decisions and resulting file state.

Focused proof scenarios:

1. Single exact edit success: pending hunk appears, user accepts, file changes.
2. Single stale edit failure: no file mutation, clear error trace.
3. Multi-hunk success: two hunks appear, accept/reject decisions are recorded.
4. Multi-hunk second hunk stale: no mutation to either hunk.

Exit criteria:

- Screenshots show pending hunk UI, focus state, accept, and reject.
- `side-effects-after.json` proves file state.
- `AG-HARNESS-004` and `AG-HARNESS-005` close.

## Stage 3: Shell Sandbox, Policy Lease, And Live Output

Gap IDs:

- `AG-HARNESS-008`
- `AG-HARNESS-009`
- `AG-HARNESS-010`

Objective:

- Move shell execution from "tool works" to "operator-safe sandboxed process
  with visible output and lease-governed authority."

Required runtime behavior:

- Shell commands run in a hardened Linux sandbox path when available.
- Default behavior denies external network.
- Workspace is the only writeable project mount, plus approved temp locations.
- Host filesystem is read-only or inaccessible.
- `.gitignore` / `.agyignore` sensitive reads are blocked.
- Symlinks are canonicalized before read/write permission checks.
- Environment is scrubbed before spawn.
- Output has a configured cap.
- CPU-bound and long-running commands time out or shift into managed retained
  session state.
- Process groups are killed on terminate, timeout, cancel, and cleanup.

Required product behavior:

- Running command appears in a live subprocess card with stdout/stderr.
- Card shows running, succeeded, failed, killed, and timed-out states.
- Card has a visible kill control for retained/background commands.
- Elevated action opens Policy Lease Dialog with:
  - authority scope
  - policy hash
  - duration
  - affected resources
  - expected receipt
  - replay consequences
  - allow once / deny / revoke semantics
- Active Leases panel lists grants and supports revocation.

Focused proof scenarios:

1. Benign command streams output and succeeds.
2. Long command streams output, then user kills it.
3. Outside workspace write is blocked.
4. Symlink escape read is blocked.
5. Ignored secret file read is blocked.
6. Network command is denied by default, then allowed once by lease, then
   denied again after revocation.
7. Environment print proves secret keys are absent.
8. Output flood is capped with trace-side full/capped metadata.

Exit criteria:

- `AG-HARNESS-008`, `AG-HARNESS-009`, and `AG-HARNESS-010` close.
- Cleanup proves no shell child remains.

## Stage 4: Stop, Cancel, Recover

Gap IDs:

- `AG-HARNESS-002`
- `AG-HARNESS-003`
- `AG-HARNESS-007`

Objective:

- Make interruption and recovery boring, reliable, and visible.
- Completion must be earned by verification, not merely asserted by the model.

Required runtime behavior:

- Stop Agent aborts model stream and runtime action loop.
- Stop Agent terminates shell trees, browser sessions, and child agents.
- Cancelled steps are persisted in trajectory state.
- Runtime crash/restart reconnects to durable trajectory state.
- Stop hooks evaluate:
  - changed files
  - diagnostics delta
  - configured tests
  - policy postconditions
- Stop hook can return allow or block.
- Blocked completion feeds a clear reason back into the agent loop.

Required product behavior:

- Stop button is visible during active Agent work.
- Cancelled state appears in Run/Tracing and product chat gets a clean stopped
  summary.
- Crash/reconnect UI shows recovery state, not a silent reset.
- Goal Verification Panel shows failed checks and links to diagnostics/test
  output.

Focused proof scenarios:

1. Stop active retained shell and browser turn.
2. Kill runtime bridge mid-run, restart, and resume from trajectory.
3. Attempt completion with broken code; stop hook blocks.
4. Repair code and complete; stop hook allows.

Exit criteria:

- `AG-HARNESS-002`, `AG-HARNESS-003`, and `AG-HARNESS-007` close.
- Recovery proof includes trajectory before/after and no orphan process.

## Stage 5: Context And Typed Stream Contract

Gap IDs:

- `AG-HARNESS-011`
- `AG-HARNESS-012`
- `AG-HARNESS-015`

Objective:

- Prove the model receives the right context, the bridge rejects unauthenticated
  callers, and the UI stream is typed instead of inferred from raw text blobs.

Required runtime behavior:

- Agent prompt context includes:
  - active file path
  - cursor position
  - selected text
  - active diagnostics
  - relevant workspace rules
  - ignore rules
  - semantic/memory hits
- Every bridge/RPC request requires fresh local session authority.
- Missing/stale local auth tokens fail closed.
- Stream events are typed:
  - thinking/progress
  - answer delta
  - tool proposal
  - policy decision
  - tool started
  - tool completed
  - verification
  - run completed/failed/cancelled

Required product behavior:

- Ask renders direct model answer stream.
- Agent renders governed work stream and clean final answer.
- Raw tool payloads never leak into product chat.
- Trace has the full typed event stream.

Focused proof scenarios:

1. Active editor context probe with selected text and diagnostics.
2. Ignored file context denial.
3. Missing/stale bridge auth negative request.
4. Typed stream recording for Ask and Agent.

Exit criteria:

- `AG-HARNESS-011`, `AG-HARNESS-012`, and `AG-HARNESS-015` close.

## Stage 6: Delegation Lanes And Scoped Workers

Gap IDs:

- `AG-HARNESS-013`

Objective:

- Upgrade subagents from "tool call passed" to visible, scoped, auditable worker
  lanes.

Required runtime behavior:

- Parent run creates child trajectory ids.
- Child trajectories are linked to parent.
- Child workers have explicit allowed tools and workspace scope.
- Default child workspace is read-only unless parent grants writeback.
- Child failure propagates as structured parent-visible state.
- Child contribution trace maps child outputs to file hunks or artifacts.

Required product behavior:

- Delegation Matrix shows parent and child lanes.
- Child status shows pending/running/succeeded/failed/cancelled.
- Parent final answer includes clean summary, not child trace dump.
- Run/Tracing links parent and child trajectories.

Focused proof scenarios:

1. Parent delegates two read-only child inspections.
2. One child succeeds and one child fails.
3. Parent awaits both and continues with fallback.
4. Child proposes a patch; parent controls writeback.

Exit criteria:

- `AG-HARNESS-013` closes.

## Stage 7: Browser And Computer Automation Polish

Gap IDs:

- `AG-HARNESS-014`

Objective:

- Turn the managed browser/computer session card into a true operator viewport,
  including live refresh and manual handoff.

Already proven:

- compact managed session card
- expanded observe view
- `Sandbox browser`, `Local browser`, and `Desktop` labels
- take-over and return-to-agent control states

Remaining requirements:

- Live screenshot/viewport refresh while actions execute.
- Visible target/action markers when useful.
- `Waiting for user` state for login, CAPTCHA, payment, file picker, credential,
  and other manual-only actions.
- User takeover pauses agent control.
- Return-to-agent resumes agent control.
- Local browser and Desktop sessions are opt-in, clearly labeled, and more
  tightly gated than sandbox browser sessions.

Focused proof scenarios:

1. Sandboxed browser observe/action stream with live refresh.
2. Manual-only login/CAPTCHA fixture enters `Waiting for user`.
3. User takes over, performs manual fixture action, returns control.
4. Local browser/desktop opt-in request is denied by default, then allowed by
   explicit lease.

Exit criteria:

- `AG-HARNESS-014` closes.

## Stage 8: Evidence Pane, Artifact Rendering, And Rule Composer

Gap IDs:

- `AG-HARNESS-016`
- `AG-HARNESS-017`

Objective:

- Put plans, task lists, walkthroughs, browser snapshots, and structured policy
  rules where operators can inspect them without polluting chat.

Required product behavior:

- Evidence Pane renders:
  - implementation plan
  - task checklist
  - walkthrough
  - relevant screenshots/browser snapshots
  - verification outputs
- Evidence Pane updates while the run progresses.
- Product chat references evidence only through compact work summaries.
- Rule/Policy Composer edits structured constraints.
- Structured rules compile into enforceable runtime policy, not prompt-only text.

Focused proof scenarios:

1. Live run updates task checklist in Evidence Pane.
2. Completion writes walkthrough and shows it in Evidence Pane.
3. Rule Composer denies a file or shell action.
4. Rule Composer allows a previously blocked benign action after scoped change.

Exit criteria:

- `AG-HARNESS-016` and `AG-HARNESS-017` close.

## Stage 9: Signed Replay, Onboarding, And Provider Decisions

Gap IDs:

- `AG-HARNESS-018`
- `AG-HARNESS-019`
- `AG-HARNESS-020`

Objective:

- Add parity-plus proof that goes beyond Antigravity where useful: signed
  receipts, replayable state, onboarding readiness, and explicit provider
  decisions.

Required work:

- Signed receipt bundle for at least:
  - one file edit
  - one shell command
  - one policy decision
  - one verification result
- Pre/post state hashes for file mutations.
- Replay panel can restore or inspect pre/post checkpoints.
- Onboarding checklist verifies:
  - daemon health
  - runtime bridge health
  - sandbox support
  - browser automation support
  - model route availability
  - local provider readiness
- Provider matrix classifies each optional provider lane as:
  - default
  - optional local
  - optional external
  - marketplace/connector
  - unsupported/deferred
- Any provider promoted to default must get a hermetic fixture proof.

Focused proof scenarios:

1. Signed edit + shell receipt replay.
2. Bootstrapper pass/fail screenshots.
3. Provider matrix final decision.
4. Hermetic fixture for any promoted provider.

Exit criteria:

- `AG-HARNESS-018`, `AG-HARNESS-019`, and `AG-HARNESS-020` are closed or
  explicitly deferred optional.

## Stage 10: Integrated Antigravity Parity Plus Soak

Gap IDs: all

Objective:

- Prove the individual fixes compose into a real operator workflow.

Integrated scenario:

1. User asks Agent to make a small code change.
2. Agent creates brain artifacts and trajectory.
3. Agent proposes exact editor hunks.
4. User accepts one hunk and rejects or revises another.
5. Agent runs sandboxed tests in live subprocess card.
6. Elevated network or shell action pauses at Policy Lease Dialog.
7. Browser automation opens managed sandbox session.
8. Manual-only fixture triggers `Waiting for user`.
9. Agent delegates a read-only review to child worker.
10. Stop hook initially blocks due to a deliberate failing diagnostic.
11. Agent fixes it.
12. Completion succeeds.
13. Signed receipts and walkthrough are visible in Evidence Pane/Tracing.
14. GUI/runtime crash recovery is simulated before final completion or in a
    sibling integrated run.
15. Final cleanup proves no leaked processes.

Exit criteria:

- Final manifest verdict is `antigravity_harness_parity_plus_proven`.
- No `P0`/`P1` row remains open.
- All remaining `P2` rows are either closed or explicitly deferred optional
  with owner and next proof step.

## Recommended Implementation Order

Do not implement UI first if the state does not exist. Build in this order:

1. trajectory schema and event writer
2. brain artifact lifecycle
3. hunk proposal data model
4. editor hunk renderer and decision route
5. sandbox runner and shell output event stream
6. policy lease model
7. stop/cancel/recovery runtime primitives
8. evidence pane projections
9. delegation matrix projections
10. browser/computer viewport refresh and handoff states
11. rule composer
12. signed receipt/replay layer
13. onboarding and provider matrix

## Regression Guardrails

Every stage must preserve:

- default harness final manifest stays green
- Ask remains direct answers
- Agent remains governed harness
- product chat remains clean
- no unmanaged browser/computer windows for Agent automation
- simple turns stay under 30 seconds unless trace evidence explains otherwise
- cleanup proof stays clean

Run focused regression after each stage:

```bash
node --check scripts/run-autopilot-agent-studio-chat-ux-hardening-goal.mjs
node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs
node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs
node scripts/build-hypervisor-full-default-harness-parity-manifest.mjs --final
```

Add more focused tests per stage. Do not rely on the above as the only proof.

## Final Verdict Template

The final markdown must include:

- baseline default harness verdict
- baseline Antigravity gap counts
- final gap counts
- rows closed by stage
- rows deferred optional with rationale
- screenshots index
- trace/trajectory index
- cleanup proof
- residual risks
- next parity-plus targets

The final JSON manifest must be machine-checkable and must not require prose to
determine whether the campaign passed.
