# Autopilot Cursor Substrate Absorption Parity Master Guide

Owner: Autopilot Workbench / Agent Studio / Runtime Daemon / Policy Runtime / Tool Runtime / Retrieval Runtime / Evidence Runtime / IDE Integration

Status: active planning guide

Created: 2026-05-27

Rubric:

- `.internal/playbooks/substrate-absorption-rubric-playbook.md`

Cursor reverse-engineering inputs:

- `internal-docs/reverse-engineering/cursor/cursor-substrate-map.md`
- `internal-docs/reverse-engineering/cursor/cursor-capability-matrix.json`
- `internal-docs/reverse-engineering/cursor/cursor-autopilot-delta-audit.md`
- `internal-docs/reverse-engineering/cursor/cursor-reverse-engineering-evidence-manifest.json`

Cursor reference tree:

- `examples/cursor`
- `examples/cursor/usr/share/cursor/resources/app/extensions/cursor-agent-exec`
- `examples/cursor/usr/share/cursor/resources/app/extensions/cursor-agent-worker`
- `examples/cursor/usr/share/cursor/resources/app/extensions/cursor-browser-automation`
- `examples/cursor/usr/share/cursor/resources/app/extensions/cursor-mcp`
- `examples/cursor/usr/share/cursor/resources/app/extensions/cursor-retrieval`
- `examples/cursor/usr/share/cursor/resources/app/extensions/cursor-shadow-workspace`
- `examples/cursor/usr/share/cursor/resources/app/extensions/cursor-worktree-textmate`
- `examples/cursor/usr/share/cursor/resources/app/extensions/cursor-file-service`
- `examples/cursor/usr/share/cursor/resources/app/extensions/cursor-ndjson-ingest`
- `examples/cursor/usr/share/cursor/resources/app/resources/helpers/crepectl`
- `examples/cursor/usr/share/cursor/resources/app/resources/helpers/cursorsandbox`

Baseline proven state:

- `docs/evidence/autopilot-agent-studio-full-default-harness-parity/final-default-harness-parity-verdict.md`
- `docs/evidence/autopilot-antigravity-harness-parity-plus/final-antigravity-harness-parity-plus-verdict.md`
- `docs/evidence/autopilot-claude-code-substrate-absorption-parity/final-claude-code-substrate-absorption-verdict.md`
- `docs/evidence/autopilot-headless-runtime-unification-parity/final-headless-runtime-unification-verdict.md`

Parent guides:

- `.internal/plans/autopilot-agent-studio-full-default-harness-parity-proof-master-guide.md`
- `.internal/plans/autopilot-antigravity-harness-parity-plus-master-guide.md`
- `.internal/plans/autopilot-claude-code-substrate-absorption-parity-master-guide.md`
- `.internal/plans/autopilot-headless-runtime-unification-parity-master-guide.md`

## Executive Intent

Autopilot is already green against default harness parity, Antigravity parity-plus,
Claude Code substrate absorption, and headless runtime unification. This campaign
must not repeat those broad proofs.

The next target is Cursor substrate absorption parity: identify, implement, prove,
or intentionally reject the Cursor-specific primitives surfaced by
`examples/cursor` that materially improve Autopilot.

The campaign is not a clone effort. Cursor is a VS Code fork with proprietary
extension and sidecar behavior. Autopilot is IDE-first, daemon-owned, traceable,
and governed by explicit Ask versus Agent separation. Absorb the useful substrate
ideas as IOI-native contracts, not as copied code or product imitation.

The primary Cursor deltas are:

1. shadow workspace dry-run validation before visible edit application
2. LSP/TextMate isolation for background worktrees and duplicate file trees
3. local workspace sandbox policies similar to `.cursor/sandbox.json`
4. MCP OAuth refresh lease and concurrent connection stability
5. local retrieval/indexing substrate and search-provider integration lessons
6. agent-authored interactive canvas/artifact UX with persisted state
7. browser automation overlay lessons relative to managed session viewports
8. detached worker lifecycle and survival semantics for long-running agents
9. pre-push/commit-time review automation
10. local log ingestion and stream wiring decisions

## Clean-Room Boundary

Use Cursor only as behavioral and architectural evidence. Do not copy:

- proprietary source
- private identifiers
- user-facing copy
- icons, styling, or visual assets
- compiled helper implementations
- service credentials, update flows, or hidden endpoint behavior

Implement Autopilot-native equivalents that preserve:

- daemon-owned runtime authority
- governed Agent execution
- Ask as direct model answer
- policy receipts and trace-side auditability
- clean product chat with work-summary capsules and final answers only
- evidence, receipts, raw tool payloads, and fixture paths outside main chat
- managed browser/computer live session artifacts
- disposable fixtures and cleanup proof

## Definition Of Done

The campaign is complete only when the final manifest can honestly state:

```text
cursor_substrate_absorption_parity_proven
```

Required conditions:

- every `P0` row is `live_pass`, `fixed_then_pass`,
  `supporting_pass_with_product_decision`, or `rejected_with_product_decision`
- no `P0` row remains `gap`, `partial_unproven`, or ownerless blocked
- every `P1` row either has product proof, support proof plus a product decision,
  or an explicit deferred/rejected decision
- the reverse-engineering artifacts are schema-consistent enough to seed and
  reproduce campaign rows
- shadow workspace, LSP isolation, and sandbox policy decisions are proven with
  live disposable code-change scenarios
- MCP refresh lease behavior is proven with a hermetic mock OAuth/MCP fixture or
  rejected/deferred with an explicit product decision
- canvas/artifact UX is decided with screenshots and product reasoning
- browser automation remains represented as Autopilot managed session artifacts
  unless a Cursor-specific overlay primitive is intentionally absorbed
- detached worker survival is mapped onto daemon/headless runtime contracts
- no default harness, Antigravity, Claude Code, or headless unification baseline
  regresses
- simple natural-language turns stay under 30 seconds unless trace evidence
  explains the delay
- every live scenario records cleanup proof for Autopilot, runtime bridge,
  daemon, spawned shells, browser fixtures, MCP servers, task workers, shadow
  workspaces, and helper processes

## Non-Negotiable Rules

- Do not rerun broad Rust catalogue testing.
- Do not redo the Cursor reverse-engineering pass except to close evidence
  quality gaps that affect campaign rows.
- Start from the Cursor reverse-engineering deliverables and the already-proven
  Autopilot baselines.
- Use realistic disposable tasks: code edits, lint/test repair, sandboxed shell
  execution, mock MCP refresh contention, pre-push review fixtures, and artifact
  UX tasks.
- Use the real Autopilot IDE GUI and Agent Studio for product-impacting proof.
- CLI, SDK, unit, or static proof may support substrate rows, but cannot close
  product UX rows alone.
- Ask remains direct model answers.
- Agent remains governed harness execution.
- Product chat shows clean work-summary capsules plus final answers only.
- Raw probe names, fixture paths, JSON payloads, receipts, traces, helper args,
  and filesystem scaffolding belong in Runs, Tracing, and evidence.
- Screenshot GUI proof and inspect screenshots for UX defects.
- If files become monolithic or modules become unintuitive, stop feature work and
  refactor before continuing.
- Kill and verify cleanup after every live scenario.
- For compiled Cursor helpers, prove Autopilot behavior with IOI-native fixtures;
  do not depend on Cursor binaries for final parity.

## Evidence Root

Use:

```text
docs/evidence/autopilot-cursor-substrate-absorption-parity/
```

Each scenario directory must include:

- `scenario.json`
- `cursor-source-evidence.json`
- `baseline-coverage.json`
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

```text
docs/evidence/autopilot-cursor-substrate-absorption-parity/cursor-substrate-absorption-final-manifest.json
docs/evidence/autopilot-cursor-substrate-absorption-parity/final-cursor-substrate-absorption-verdict.md
```

## Outcome Classes

Use these status values in manifests:

- `live_pass`: proven through the live IDE GUI with screenshots, traces, and cleanup
- `fixed_then_pass`: defect found, fixed, tested, and live-proven
- `headless_pass`: proven through daemon/headless APIs where product UI is not the owner
- `cross_client_pass`: proven across GUI, CLI, TUI, SDK, or daemon clients where applicable
- `supporting_pass`: unit, CLI, SDK, static, or fixture evidence supports the row
- `supporting_pass_with_product_decision`: support evidence plus explicit product decision
- `policy_gate_pass`: elevated or risky action correctly paused, denied, or approved
- `sandbox_effect_pass`: effect occurred only inside a disposable sandbox
- `rejected_with_product_decision`: intentionally not absorbed into Autopilot
- `deferred_optional`: valid but outside current product/default scope
- `blocked_with_owner`: blocked with reproduction, owner, evidence path, and next step
- `partial_unproven`: implemented or sketched, but not yet proven
- `gap`: not implemented or not meaningfully tested

## Manifest Shape

Each row in the final manifest must include:

```json
{
  "id": "CURSOR-SUBSTRATE-001",
  "priority": "P0",
  "area": "shadow_workspace_validation",
  "status": "fixed_then_pass",
  "owner": "Runtime daemon / workspace validation",
  "cursorEvidence": [
    "internal-docs/reverse-engineering/cursor/cursor-substrate-map.md",
    "examples/cursor/usr/share/cursor/resources/app/extensions/cursor-shadow-workspace/dist/extension.js"
  ],
  "baselineCoverage": [
    "docs/evidence/autopilot-headless-runtime-unification-parity/final-headless-runtime-unification-verdict.md"
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

## Campaign Rows

### CURSOR-SUBSTRATE-000: Evidence Schema And Source Polish

Priority: P0

Area: campaign_inputs

Cursor basis:

- `internal-docs/reverse-engineering/cursor/cursor-capability-matrix.json`
- `internal-docs/reverse-engineering/cursor/cursor-reverse-engineering-evidence-manifest.json`

Intent:

- Normalize the Cursor reverse-engineering deliverables so the campaign can
  generate deterministic rows and source citations.

Required work:

- Decide whether `cursor-capability-matrix.json` remains a top-level array or is
  wrapped in `{ "capabilities": [] }`.
- Ensure every capability has a stable id, priority, classification,
  Autopilot-delta classification, source files, and symbols.
- Add line refs or symbol refs to the evidence manifest where practical.
- Mark behavior as confirmed, inferred, or dynamic-probe-required.

Proof:

- A campaign seed script or static check can load all four reverse-engineering
  deliverables.
- The generated campaign manifest includes every Cursor-specific gap without
  hand-written row drift.

### CURSOR-SUBSTRATE-001: Shadow Workspace Dry-Run Validation

Priority: P0

Area: shadow_workspace_validation

Cursor basis:

- `cursor-shadow-workspace`
- `aiserver.v1.ShadowWorkspaceService`
- `GetLintsForChange`
- `SwGetLinterErrors`
- `SwCallDiagnosticsExecutor`
- `SwWriteTextFileWithLints`

Intent:

- Autopilot should be able to validate proposed edits in a hidden disposable
  workspace before applying or presenting final changes to the active workspace.

Required work:

- Implement or wire an Autopilot-native shadow workspace validation lane.
- Use a disposable git worktree or temp clone rooted outside the active tree.
- Apply proposed edits to the shadow workspace first.
- Run focused tests, type checks, lint checks, or configured validators there.
- Surface clean product status in Agent Studio, with trace details in evidence.
- Do not make the GUI own validation semantics.

Proof:

- Live Agent Studio scenario fixes a disposable code defect.
- The first mutation occurs in the shadow workspace.
- The active workspace receives only the validated edit.
- Trace proves validation result, receipts, side effects, and cleanup.

### CURSOR-SUBSTRATE-002: LSP And Watcher Isolation For Background Worktrees

Priority: P0

Area: lsp_watcher_isolation

Cursor basis:

- `cursor-worktree-textmate`
- custom language ids such as `worktree-typescript`, `worktree-python`,
  `worktree-rust`
- `.cursor/worktrees` path patterns

Intent:

- Background validation workspaces must not overload language servers, file
  watchers, search indexers, or duplicate diagnostics in the operator workspace.

Required work:

- Define Autopilot's isolation strategy for shadow workspaces.
- Prefer daemon-owned ignore/watch exclusion plus editor-level presentation
  markers over product-visible language spoofing when possible.
- If editor-level language isolation is needed, implement a minimal
  Autopilot-native scheme.
- Ensure search, file watching, LSP, diagnostics, and indexing do not double-run
  against shadow files.

Proof:

- GUI/live proof creates a shadow workspace while the IDE is open.
- Screenshots and logs show no duplicate diagnostics in the active editor.
- File watcher/indexer evidence shows shadow paths are isolated or intentionally
  included only as trace artifacts.

### CURSOR-SUBSTRATE-003: Local Sandbox Policy Model

Priority: P0

Area: sandbox_policy

Cursor basis:

- `cursorsandbox`
- `.cursor/sandbox.json`
- `vscode.cursor.pushSandboxNetworkFileEntries`
- `cursor-agent-exec`

Intent:

- Autopilot should support a workspace-readable local sandbox policy model for
  agent-run shell and tool effects, while keeping final enforcement daemon-owned.

Required work:

- Decide Autopilot policy file name and schema, or explicitly map to existing
  policy configuration.
- Support read/write directory grants and network policy grants for disposable
  local commands.
- Map product menu modes like Default permissions, Auto-review, and Full access
  into daemon policy fields.
- Ensure policy changes are reflected in traces and not only in UI state.
- Do not depend on Cursor's compiled `cursorsandbox`.

Proof:

- Live GUI scenario attempts allowed and denied disposable shell/file/network
  operations.
- Allowed effects happen only in sandboxed fixtures.
- Denied effects produce policy receipts and clean chat answers.
- Full access behavior is explicit and trace-backed.

### CURSOR-SUBSTRATE-004: MCP OAuth Refresh Lease And Concurrent Connections

Priority: P0

Area: mcp_oauth_concurrency

Cursor basis:

- `cursor-mcp`
- `cursor-agent-exec/patches/@modelcontextprotocol+sdk+1.25.1.patch`
- `prepareForRefresh`
- `releaseRefreshLeaseOnError`
- `SiblingAlreadyRefreshedError`
- `OAuthRefreshTransientError`

Intent:

- Concurrent MCP connections sharing credentials must not corrupt refresh state
  or spam the user with duplicated auth prompts.

Required work:

- Build a hermetic mock MCP/OAuth fixture with shared token refresh state.
- Prove one refresh lease holder and sibling reconnect behavior.
- Map auth-required and elicitation-required states to Waiting for user.
- Keep tokens and refresh internals out of product chat.

Proof:

- Headless and, if product-impacting, GUI proof runs two concurrent MCP
  connections against the mock fixture.
- Only one refresh path mutates token state.
- Sibling connection recovers or waits without duplicate user prompts.
- Trace includes lease and policy receipts.

### CURSOR-SUBSTRATE-005: Local Retrieval And Indexing Substrate

Priority: P1

Area: retrieval_indexing

Cursor basis:

- `cursor-retrieval`
- `crepectl`
- `registerTextSearchProvider2`
- `registerGrepProvider`
- `GitGraph`
- `getRelevantPaths`

Intent:

- Decide whether Cursor's local index/search-provider strategy changes
  Autopilot's retrieval roadmap beyond the already-proven Claude Code and
  Antigravity context substrate.

Required work:

- Compare Cursor retrieval with current Autopilot search, memory, and context
  analyzer lanes.
- Decide whether to absorb search-provider integration, git-relevance codemaps,
  incremental indexing, or none.
- If absorbed, implement IOI-native fixtures and proof against disposable repos.

Proof:

- Product decision plus support proof, or live proof if the feature lands in UI.
- Retrieval outputs must be artifact refs or trace evidence, not raw chat spam.

### CURSOR-SUBSTRATE-006: Commit-Time And Pre-Push Review Automation

Priority: P1

Area: commit_review_automation

Cursor basis:

- `cursor-retrieval`
- `shouldRunBugbot`
- `cursor.runEditorBugbot`
- `scoreCommitInternal`

Intent:

- Decide whether Autopilot should proactively review local commits before push,
  and if so how it remains explicit, respectful, and traceable.

Required work:

- Define product scope: automatic, opt-in, or rejected.
- If absorbed, use disposable git repos and local commits.
- Ensure background review cannot surprise users with network or account effects.
- Surface findings in Runs/Tracing or an explicit review panel, not as noisy
  main chat messages.

Proof:

- Product decision plus support/live proof depending on scope.

### CURSOR-SUBSTRATE-007: Agent-Authored Interactive Canvas Artifacts

Priority: P1

Area: canvas_artifacts

Cursor basis:

- `cursor-agent-exec/dist/agent-sdk/cursor/canvas`
- `.canvas.tsx`
- `.canvas.data.json`
- `useCanvasState`
- `useCanvasAction`
- `openAgent`
- `newComposerChat`

Intent:

- Decide whether Autopilot should support a structured stateful artifact/canvas
  model beyond current markdown/HTML artifacts.

Required work:

- Preserve Autopilot's artifact and Runs model.
- Do not let arbitrary agent-authored UI bypass policy, tracing, or user intent.
- If absorbed, start with a minimal safe artifact runtime and state sidecar.
- Ensure canvas actions create governed Agent/Ask requests.

Proof:

- GUI screenshots show artifact creation, state persistence, and a governed
  action path, or a product decision rejects/defer this substrate.

### CURSOR-SUBSTRATE-008: Browser Automation Overlay Versus Managed Viewports

Priority: P1

Area: browser_automation_ux

Cursor basis:

- `cursor-browser-automation`
- `cursor.browserView.executeJavaScript`
- `area-screenshot-selected`
- Simple Browser webview control

Intent:

- Confirm Autopilot's managed browser/computer session artifact remains the
  correct product shape, or absorb a narrow overlay primitive if it improves
  operator control.

Required work:

- Compare Cursor Simple Browser overlay against Autopilot compact preview,
  expanded observe, take over, return control, and waiting-for-user states.
- Preserve Sandbox browser / Local browser / Desktop labels.
- Do not move browser automation semantics into the GUI layer.

Proof:

- Live GUI browser automation proof with screenshots.
- Product decision explaining whether overlay selection becomes an Autopilot
  control or remains covered by current managed viewport UX.

### CURSOR-SUBSTRATE-009: Detached Worker Lifecycle And Survival Semantics

Priority: P0

Area: detached_worker_lifecycle

Cursor basis:

- `cursor-agent-worker`
- detached `cursor-agent` spawn
- PID files
- UNIX sockets
- install/update tracking

Intent:

- Ensure Autopilot long-running Agent work survives the right client lifecycle
  events without trapping harness semantics in GUI or extension code.

Required work:

- Map Cursor worker survival concepts onto Autopilot's daemon/headless runtime.
- Prove GUI close/reopen, CLI/TUI reconnect, active run recovery, and cleanup.
- Ensure update/install tracking does not orphan stale workers.

Proof:

- Cross-client scenario starts a long-running disposable task.
- GUI disconnect/reconnect does not lose daemon-owned run state.
- CLI/TUI can observe or cancel the same run.
- Cleanup proof shows no orphaned worker/process remains.

### CURSOR-SUBSTRATE-010: Local Log Ingestion And Stream Wiring

Priority: P2

Area: log_ingestion

Cursor basis:

- `cursor-ndjson-ingest`
- `/ingest/${ingestPathId}`
- `X-Debug-Session-Id`
- `.cursor/debug-*.log`

Intent:

- Decide whether Autopilot needs a local HTTP/NDJSON ingestion lane or whether
  daemon event streams and trace artifacts already cover this cleanly.

Required work:

- Compare against headless runtime unification trace/event/replay streams.
- Reject with product decision unless a concrete missing integration appears.

Proof:

- Supporting proof and product decision are sufficient unless implemented.

### CURSOR-SUBSTRATE-011: Containerized Environment Definition Schema

Priority: P2

Area: environment_schema

Cursor basis:

- `cursor-always-local`
- `.cursor/environment.json`
- Dockerfile/snapshot/ports/terminals schema

Intent:

- Decide whether Cursor's environment schema should inform Autopilot project
  setup, task bootstrapping, or future cloud/local environment lanes.

Required work:

- Compare with existing Autopilot fixture, sandbox, and task environment models.
- Defer or absorb only if it improves product setup.

Proof:

- Product decision or focused support proof.

### CURSOR-SUBSTRATE-012: File Service And Workspace API Boundary

Priority: P1

Area: file_service_api_boundary

Cursor basis:

- `cursor-file-service`
- `vscode.cursor` workspace APIs
- Cursor-specific extension registrations

Intent:

- Identify whether Cursor's file-service boundary offers a useful pattern for
  keeping file semantics out of GUI code and in daemon/shared contracts.

Required work:

- Compare against Autopilot file write/edit/delete daemon ownership.
- Add proof only if a missing boundary appears.

Proof:

- Supporting proof plus product decision, or live proof if a boundary moves.

## Stage 0: Cursor Evidence Polish And Campaign Seed

Rows: CURSOR-SUBSTRATE-000

Objective:

- Turn the Cursor reverse-engineering deliverables into deterministic campaign
  inputs.

Required work:

- Normalize `cursor-capability-matrix.json`.
- Add stable ids and priority fields.
- Add line/symbol evidence to the manifest where practical.
- Generate the initial campaign manifest from reverse-engineering data.

Proof:

- Static validation passes.
- Campaign seed manifest contains all Cursor-specific rows.

## Stage 1: Shadow Workspace Validation Spine

Rows: CURSOR-SUBSTRATE-001, CURSOR-SUBSTRATE-002

Objective:

- Build or verify the Autopilot-native shadow validation lane and watcher/LSP
  isolation model.

Required work:

- Implement the smallest daemon/shared-runtime contract needed for background
  validation.
- Keep the GUI as presentation only.
- Use disposable git repos and focused test/lint fixtures.

Proof:

- Live GUI proof for validated edit application.
- Headless proof for daemon validation contract.
- Screenshot proof that duplicate diagnostics do not leak into the active editor.

## Stage 2: Sandbox Policy Absorption

Rows: CURSOR-SUBSTRATE-003

Objective:

- Absorb the useful part of Cursor's local sandbox policy idea into Autopilot's
  daemon-owned permission model.

Required work:

- Implement or map workspace policy schema.
- Test read/write/network allow and deny paths.
- Confirm Full access / Auto-review / Default permissions mapping.

Proof:

- Live GUI proof plus daemon trace receipts.
- Sandbox effect proof.

## Stage 3: MCP OAuth And Elicitation Robustness

Rows: CURSOR-SUBSTRATE-004

Objective:

- Prove concurrent MCP credential refresh stability using a hermetic fixture.

Required work:

- Build mock OAuth/MCP server.
- Exercise concurrent refresh and sibling recovery.
- Map auth/elicitation to Waiting for user.

Proof:

- Headless proof for refresh lease.
- GUI proof only if user-facing auth/elicitation state is affected.

## Stage 4: Retrieval And Commit Review Decisions

Rows: CURSOR-SUBSTRATE-005, CURSOR-SUBSTRATE-006

Objective:

- Decide what, if anything, Cursor's retrieval and commit-time review substrate
  changes for Autopilot.

Required work:

- Compare current Autopilot context/search/review lanes.
- Implement only the deltas that materially improve product workflow.

Proof:

- Product decisions for each row.
- Live proof for any absorbed feature.

## Stage 5: Canvas And Artifact UX Decision

Rows: CURSOR-SUBSTRATE-007

Objective:

- Decide whether Autopilot needs stateful, interactive, agent-authored artifacts.

Required work:

- Compare with current artifact/Runs architecture.
- Prototype only if a minimal safe version is clearly product-positive.
- Keep artifact actions governed.

Proof:

- Product decision and screenshots, or live proof if implemented.

## Stage 6: Browser Automation UX Delta

Rows: CURSOR-SUBSTRATE-008

Objective:

- Confirm managed live session artifacts remain the default, and identify any
  useful overlay interaction to absorb.

Required work:

- Run live browser/computer scenario.
- Compare overlay selection against observe/take-over/return-control UX.

Proof:

- GUI screenshots for compact preview, expanded observe, takeover, return, and
  waiting-for-user if applicable.
- Product decision for overlay absorption/rejection.

## Stage 7: Detached Worker Survival And Cross-Client Recovery

Rows: CURSOR-SUBSTRATE-009

Objective:

- Prove long-running Agent work is daemon-owned and survives appropriate client
  lifecycle transitions.

Required work:

- Use GUI, CLI, TUI, and daemon/headless APIs.
- Start, observe, interrupt, resume, cancel, and cleanup a disposable long task.

Proof:

- Cross-client pass.
- No orphaned worker or helper processes.

## Stage 8: Long-Tail Cursor Rows And Product Decisions

Rows: CURSOR-SUBSTRATE-010, CURSOR-SUBSTRATE-011, CURSOR-SUBSTRATE-012

Objective:

- Close Cursor long-tail rows with explicit support proof, product decisions, or
  live proof when warranted.

Required work:

- Avoid speculative implementation.
- Write clear decisions for rejected/deferred rows.

Proof:

- Supporting proof with product decisions or live proof.

## Stage 9: Integrated Cursor Absorption Soak

Rows: all P0 and implemented P1 rows

Objective:

- Demonstrate the absorbed Cursor primitives working together without regressing
  the already-proven harness.

Required scenarios:

1. Shadow-validated code edit plus focused test repair
2. Sandbox policy allow/deny file and shell effects
3. Concurrent MCP refresh fixture
4. Browser/computer managed session proof
5. Detached worker reconnect and cancel path
6. Product chat clean summary capsule plus final answer
7. Cleanup proof across daemon, GUI, CLI/TUI, shell, browser, MCP, and shadow
   workspace processes

Proof:

- Final integrated manifest has no P0 gaps.
- All screenshots are human-legible and free of raw trace/fixture noise in chat.
- Final cleanup proof passes.

## Final Verdict Requirements

Write:

```text
docs/evidence/autopilot-cursor-substrate-absorption-parity/cursor-substrate-absorption-final-manifest.json
docs/evidence/autopilot-cursor-substrate-absorption-parity/final-cursor-substrate-absorption-verdict.md
```

The final verdict must include:

- verdict string
- campaign start and end timestamps
- baseline references
- Cursor source evidence references
- row table with status, priority, owner, evidence, and residual risk
- product decisions for rejected/deferred/support-only rows
- screenshots for GUI/product rows
- cleanup proof references
- explicit remaining blockers, if any

The final verdict may state:

```text
cursor_substrate_absorption_parity_proven
```

only when every P0 row is closed with proof or an explicit product decision that
does not weaken Autopilot's default harness, Antigravity parity-plus, Claude Code
absorption, or headless runtime unification claims.
