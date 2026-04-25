# Agentic Runtime Audit

## 1. Status / Progress Log

Status: COMPLETE

| Time/Pass | Status | Sections Updated | Key Findings | Next Step |
|---|---|---|---|---|
| 2026-04-25 Pass 0 | IN PROGRESS | Created audit structure | Repository appears to contain Rust runtime crates, TS agent IDE/workbench surfaces, autopilot app code, and Python swarm bindings. Existing untracked/modified user files are present and will not be touched. | Complete repository cartography before proposing fixes. |
| 2026-04-25 Pass 1 | COMPLETE | Repository architecture map, Appendix file index, Open questions | Primary runtime surface is the Tauri Autopilot app backed by Rust service crates, with CLI and shared agent-ide surfaces as alternate entrypoints/projections. Agent execution, policy, receipts, browser/computer use, workflows, artifact generation, memory, and UI surfaces are mapped by file path. | Trace runtime execution flows before A-Z critique. |
| 2026-04-25 Pass 2 | COMPLETE — NEEDS VERIFICATION | Runtime execution flow, Critical findings so far, Appendix paths | Main bounded-action flow has deterministic request construction and settlement receipts, but graph execution and some UI/projection paths sit outside the same settlement model. Policy records omit matched rule provenance, approval authority scope is not enforced during grant validation, and non-browser/non-web tool timeout coverage is incomplete or delegated elsewhere. | Begin A-Z category audit, starting with lifecycle/planning/tools/policy/receipts. |
| 2026-04-25 Pass 3 | COMPLETE | A-Z categories A-Q, Critical findings so far | Agent-service runtime has substantial typed seams and tests, but graph execution, trace-bundle exports, workflow/connector commands, and some inference/MCP paths remain outside the canonical settlement and timeout model. | Extract cross-cutting invariants, critical gaps, roadmap, patch candidates, and test plan. |
| 2026-04-25 Pass 4 | COMPLETE | Executive summary, invariants, critical gaps, roadmap, patch candidates, test plan, appendix | Final audit identifies 11 concrete critical/high/medium findings and 8 patch candidates. The main architectural risk is not absence of a bounded runtime; it is multiple adjacent execution surfaces that have not yet been forced through the bounded runtime. | Ready for follow-up implementation planning. |

## 2. Executive summary

Status: COMPLETE

The repository already contains serious bounded-runtime foundations: canonical action and receipt structs, policy evaluation, approval grant types, pending-action resume state, browser/computer-use drivers, artifact execution envelopes, workflow receipts, trace exports, and broad test coverage. The strongest path is the `desktop_agent` action execution flow, which normalizes model tool proposals into deterministic `ActionRequest`s, evaluates policy, persists policy/commit/evidence records, and emits settlement receipts.

The main product/runtime risk is boundary drift. Several adjacent surfaces can run consequential work outside the same settlement invariant: Agent Studio graph execution, workflows, connector/plugin/local-engine commands, trace-bundle exports, and some graph/MCP/inference timeout paths. These are not abstract best-practice gaps; they are concrete call paths named in this audit.

Top priority is to make the safe path universal: graph/workflow/tool/browser/code/connector actions should all pass through a canonical policy/approval/capability/receipt envelope, and UI/export surfaces must distinguish projection evidence from verifier-grade settlement records. The recommended roadmap starts with graph settlement, approval-scope enforcement, matched-rule provenance, trace authority cleanup, and uniform runtime deadlines.

## 3. Repository architecture map

Status: COMPLETE

Phase 1 scope is complete enough to begin execution-flow tracing. This section is an evidence map only; fixes and risk judgments are deferred to later sections.

### 3.1 Major workspace packages and apps

- Rust workspace root: [Cargo.toml](/home/heathledger/Documents/ioi/repos/ioi/Cargo.toml)
  - App/backend: [apps/autopilot/src-tauri](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri)
  - Runtime/service layer: [crates/services](/home/heathledger/Documents/ioi/repos/ioi/crates/services)
  - Shared runtime API and chat/artifact contracts: [crates/api](/home/heathledger/Documents/ioi/repos/ioi/crates/api)
  - Shared canonical types: [crates/types](/home/heathledger/Documents/ioi/repos/ioi/crates/types)
  - Native drivers: [crates/drivers](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers)
  - Durable memory: [crates/memory](/home/heathledger/Documents/ioi/repos/ioi/crates/memory)
  - State/storage/consensus/execution primitives: [crates/state](/home/heathledger/Documents/ioi/repos/ioi/crates/state), [crates/storage](/home/heathledger/Documents/ioi/repos/ioi/crates/storage), [crates/consensus](/home/heathledger/Documents/ioi/repos/ioi/crates/consensus), [crates/execution](/home/heathledger/Documents/ioi/repos/ioi/crates/execution)
  - CLI/node surfaces: [crates/cli](/home/heathledger/Documents/ioi/repos/ioi/crates/cli), [crates/node](/home/heathledger/Documents/ioi/repos/ioi/crates/node)
  - Plugin/runtime extension crates: [crates/plugins](/home/heathledger/Documents/ioi/repos/ioi/crates/plugins)
- JS/TS workspace root: [package.json](/home/heathledger/Documents/ioi/repos/ioi/package.json)
  - Desktop app frontend: [apps/autopilot/src](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src)
  - Shared workbench/runtime package: [packages/agent-ide](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide)
  - Additional web/apps workspaces are declared under `apps/*` and `packages/*`.
- Product README evidence: [apps/autopilot/README.md](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/README.md) describes the primary product as a native Tauri desktop agent runtime with policy gates, receipts, multi-window UX, Zustand/Tauri event sync, and Rust backend state.

### 3.2 Runtime entrypoints

- Tauri app bootstrap: [apps/autopilot/src-tauri/src/lib.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/lib.rs)
  - Initializes app data paths, memory runtime, inference runtimes, browser/GUI/terminal drivers, connector managers, workflow manager, plugin manager, and Tauri command handlers.
  - Creates local/remote model runtimes via `create_inference_runtime`, `create_chat_routing_inference_runtime`, and `create_acceptance_inference_runtime`.
- Tauri command surface: [apps/autopilot/src-tauri/src/lib.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/lib.rs)
  - Registers task/session commands, artifact commands, governance commands, workflow commands, graph commands, connector commands, event/artifact/session queries, observability, and project commands.
- Agent service RPC entrypoint: [crates/services/src/agentic/runtime/service/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/mod.rs)
  - `RuntimeAgentService` implements `BlockchainService` with methods `start@v1`, `resume@v1`, `step@v1`, `post_message@v1`, `register_approval_authority@v1`, `revoke_approval_authority@v1`, and `delete_session@v1`.
- CLI runtime client: [crates/cli/src/commands/agent.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/cli/src/commands/agent.rs)
  - Creates a `session_id`, calls `desktop_agent.start@v1`, then loops `desktop_agent.step@v1`.
- Shared TS runtime bridge: [apps/autopilot/src/services/TauriRuntime.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/TauriRuntime.ts) and [packages/agent-ide/src/runtime/session-runtime.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-runtime.ts)
  - Wrap Tauri invokes/events behind the `AssistantSessionRuntime` abstraction consumed by the workbench UI.

### 3.3 Agent execution paths

- Lifecycle handlers: [crates/services/src/agentic/runtime/service/lifecycle/handlers](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/lifecycle/handlers)
  - Start/resume/post-message/delete-session/approval-authority handling lives here.
- Main step loop: [crates/services/src/agentic/runtime/service/step/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/mod.rs)
  - Hydrates session state, resumes running state, applies recovery/resource guards, resolves intent/clarification, handles browser lease state, resumes pending actions, processes queued work, or enters the cognitive loop.
- Action/tool-call processing: [crates/services/src/agentic/runtime/service/step/action/processing/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/mod.rs)
  - Repairs/refines model tool outputs, normalizes middleware calls, expands macros, applies instruction-contract grounding, then enters action execution phases.
- Execution handler facade: [crates/services/src/agentic/runtime/service/handler/execution/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/mod.rs)
  - Collects action execution, deterministic request construction, policy enforcement, receipt emission, and execution policy helpers.
- Concrete action executor path: [crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs)
  - Checks worker assignment tool allowlists, prepares tool metadata, constructs deterministic action context, enforces policy, executes meta-tools/adapters/browser/terminal/filesystem/system tools, and persists terminal settlement outcomes when execution state is available.

### 3.4 Planning, decomposition, and swarm paths

- Agent step planner/queue modules: [crates/services/src/agentic/runtime/service/step/queue](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/queue), [crates/services/src/agentic/runtime/service/step/planner/tests.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/planner/tests.rs)
  - Queue processing, worker dispatch, web pipeline, completion receipts, synthesis, and planner tests.
- Shared execution graph/swarm types: [crates/api/src/execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/execution.rs)
  - Defines `SwarmPlan`, `SwarmWorkItem`, worker/change/merge/verification receipts, execution graph mutation, repair, replan, and execution envelope types.
- Chat artifact swarm planning: [crates/api/src/chat/generation/swarm_plan.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_plan.rs)
  - Builds planner/skeleton/section/style/interaction/integrator work items with dependencies, lease requirements, and acceptance criteria.
- Agent Studio graph runner: [apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs)
  - Executes local graph/DAG nodes with model bindings, governance tier metadata, cache, events, max steps, and timeout settings.

### 3.5 Inference/model adapter paths

- Inference trait surface: [crates/api/src/vm/inference/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/vm/inference/mod.rs)
  - Defines `InferenceRuntime`, streaming default behavior, embedding, typed model/media operations, lifecycle hooks, provenance, and `LocalSafetyModel`.
- HTTP/OpenAI/Anthropic/Ollama adapter: [crates/api/src/vm/inference/http_adapter.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/vm/inference/http_adapter.rs)
  - Implements remote/local HTTP inference, request and streaming idle timeouts, OpenAI tool-call mode, Ollama native streaming, and response parsing.
- App-level inference runtime wiring: [apps/autopilot/src-tauri/src/lib.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/lib.rs)
  - Chooses local runtime URLs from env, OpenAI fallback via `OPENAI_API_KEY`, routing/acceptance runtimes, and health checks.
- Model registry/capability types: [crates/types/src/app/model_registry.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/model_registry.rs), [crates/types/src/app/inference.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/inference.rs)

### 3.6 Tool execution paths

- Tool executor: [crates/services/src/agentic/runtime/execution/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/mod.rs)
  - `ToolExecutor` dispatches `AgentTool` calls to browser, screen, filesystem, math, system, MCP, and other handlers. It also emits workload events/receipts.
- Built-in tool definitions: [crates/services/src/agentic/runtime/tools/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/tools/mod.rs), [crates/services/src/agentic/runtime/tools/builtins](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/tools/builtins)
  - `discover_tools` exposes built-in tool schemas.
- Tool type/contracts: [crates/types/src/app/agentic/tools](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/agentic/tools)
  - Shared tool enums and screen/browser/target/PII/commerce tool type definitions.
- MCP runtime execution: [crates/services/src/agentic/runtime/execution/mcp](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/mcp)

### 3.7 Browser and computer-use paths

- Browser driver core: [crates/drivers/src/browser/driver_core.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser/driver_core.rs)
  - Manages browser process, lease flag, request timeouts, health probing/reset, pinned Chromium revision/hash envs, and launch arguments.
- Browser execution handler: [crates/services/src/agentic/runtime/execution/browser/handler.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/browser/handler.rs)
  - Handles snapshot/click/synthetic click/hover/type/follow-up, screenshots, and visual overlays.
- Screen/computer-use dispatch: [crates/services/src/agentic/runtime/execution/screen/dispatch.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/screen/dispatch.rs)
  - Handles GUI click/type/scroll/snapshot/focus/copy/paste, visual hashes, semantic/SoM resolution, and phase-based browser guards.
- Native OS operator: [crates/drivers/src/gui/operator.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/gui/operator.rs)
  - Uses native capture/input libraries, computes perceptual hashes, and performs low-level mouse/keyboard injection.

### 3.8 Artifact generation and validation paths

- Chat/artifact contract surface: [crates/api/src/chat.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat.rs), [crates/api/src/chat](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat)
  - Exports chat planning, routing, artifact materialization, render evaluation, topology, HTML/PDF helpers, validation, and payload contracts.
- Artifact runtime plan: [crates/api/src/chat/generation/runtime_plan.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/runtime_plan.rs)
  - Resolves runtime locality/tier/policy for artifact steps, including local HTML authoring temperature/token policy.
- Autopilot artifact pipeline: [apps/autopilot/src-tauri/src/kernel/chat/pipeline.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/chat/pipeline.rs), [apps/autopilot/src-tauri/src/kernel/chat/materialization.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/chat/materialization.rs), [apps/autopilot/src-tauri/src/kernel/chat/revisions.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/chat/revisions.rs)
- Operator-run projection: [apps/autopilot/src-tauri/src/kernel/chat/operator_run.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/chat/operator_run.rs)
  - Projects chat artifact sessions into operator-run UI phases, previews, file refs, and verification refs.
- Artifact persistence commands/tests: [apps/autopilot/src-tauri/src/kernel/artifacts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/artifacts)

### 3.9 Persistence, state, and projection paths

- Canonical action/receipt state keys and structs: [crates/types/src/app/action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs)
  - Defines `ActionRequest`, canonical request hashing, `CommittedAction`, `PolicyDecisionRecord`, `ApprovalAuthority`, `ApprovalGrant`, execution observations, postcondition proofs, required receipt manifests, settlement bundles, and state key prefixes.
- App state/projection: [apps/autopilot/src-tauri/src/kernel/state.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/state.rs)
  - Maintains current task state, syncs planning/runtime views, saves local task state, emits Tauri task events, and hydrates session history.
- Event/artifact projection and memory append: [apps/autopilot/src-tauri/src/kernel/events/emission.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/events/emission.rs)
  - Registers kernel events/artifacts, updates in-memory `AppState`, appends to `ioi-memory`, and emits Tauri events.
- Durable memory runtime: [crates/memory/src/lib.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/memory/src/lib.rs)
  - SQLite-backed memory for thread checkpoints/messages, archival records, artifact records, and artifact blobs.
- Lower-level storage/state: [crates/storage/src/wal.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/storage/src/wal.rs), [crates/storage/src/redb_epoch_store.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/storage/src/redb_epoch_store.rs), [crates/state/src](/home/heathledger/Documents/ioi/repos/ioi/crates/state/src)

### 3.10 Policy, permissions, approvals, and authority paths

- Policy engine: [crates/services/src/agentic/policy/engine.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/engine.rs)
  - Evaluates `ActionRequest` against rules/default policy and PII overlay, returning allow/block/require-approval verdicts.
- Rule model: [crates/services/src/agentic/rules.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/rules.rs)
  - Defines action rules, conditions, default policy, approvals, domains, paths, commands, apps, intents, and text-pattern conditions.
- Policy enforcement and deterministic request construction: [crates/services/src/agentic/runtime/service/handler/execution/execution/determinism.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/determinism.rs), [crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs)
  - Builds canonical action requests/workload specs, evaluates leases, validates approval grants, runs policy, records decisions/receipts, and emits firewall interceptions.
- Receipt persistence helpers: [crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs)
  - Persists committed action, determinism evidence, policy decision, firewall receipt, settlement bundle, execution observation, postcondition proof, and required receipt manifest.
- Wallet/approval validation: [crates/services/src/wallet_network/handlers/approval.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/wallet_network/handlers/approval.rs), [crates/services/src/wallet_network/validation.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/wallet_network/validation.rs)
  - Registers/revokes approval authorities, records decisions, validates approval grants/signatures/expiry/revocation/policy hash/session binding, and consumes grants.
- Governance/Tauri approval bridge: [apps/autopilot/src-tauri/src/kernel/governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/governance.rs)
- TS approval parsing/projection: [packages/agent-ide/src/runtime/shield-approval.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/shield-approval.ts), [packages/agent-ide/src/runtime/assistant-session-runtime-types.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/assistant-session-runtime-types.ts)

### 3.11 Workflow orchestration paths

- Automation workflow manager/types/commands: [apps/autopilot/src-tauri/src/kernel/workflows](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/workflows)
  - Stores automation workflow registry/artifacts/state/recent receipts, monitor workflows, trigger types, install/run/pause/resume/delete/export commands, and workflow run receipts.
- Agent Studio local graph execution: [apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs), [apps/autopilot/src-tauri/src/orchestrator/store.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/store.rs)
- Workflow UI: [apps/autopilot/src/surfaces/MissionControl/MissionControlWorkflowsView.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/surfaces/MissionControl/MissionControlWorkflowsView.tsx), [apps/autopilot/src/surfaces/MissionControl/MissionControlRunsView.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/surfaces/MissionControl/MissionControlRunsView.tsx)

### 3.12 UI surfaces related to runs, artifacts, traces, approvals, workflows, and chat

- Runtime bridge and session controller: [apps/autopilot/src/services/TauriRuntime.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/TauriRuntime.ts), [packages/agent-ide/src/runtime/session-controller.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-controller.ts), [packages/agent-ide/src/runtime/session-runtime.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-runtime.ts)
- Chat shell: [apps/autopilot/src/windows/ChatShellWindow/index.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/index.tsx)
- Approval/gate UI: [apps/autopilot/src/windows/ChatShellWindow/components/ChatApprovalCard.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ChatApprovalCard.tsx), [apps/autopilot/src/windows/ChatShellWindow/components/ChatPasswordCard.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ChatPasswordCard.tsx), [packages/agent-ide/src/runtime/use-session-gate-state.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/use-session-gate-state.ts)
- Artifact/evidence/run UI: [apps/autopilot/src/windows/ChatShellWindow/components/ChatArtifactPanel.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ChatArtifactPanel.tsx), [apps/autopilot/src/windows/ChatShellWindow/components/ArtifactHubEvidenceViews.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ArtifactHubEvidenceViews.tsx), [apps/autopilot/src/windows/ChatShellWindow/components/ExecutionRouteCard.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ExecutionRouteCard.tsx), [apps/autopilot/src/windows/ChatShellWindow/components/VisualEvidenceCard.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/VisualEvidenceCard.tsx)
- Trace/debug surfaces: [packages/agent-ide/src/features/Editor/Trace/TraceViewer.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/features/Editor/Trace/TraceViewer.tsx), [apps/autopilot/src/windows/ChatShellWindow/utils/traceBundleExportModel.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/utils/traceBundleExportModel.ts)
- Capabilities/runtime catalog: [apps/autopilot/src/surfaces/Capabilities](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/surfaces/Capabilities)
- Workspace/runtime shell: [apps/autopilot/src/surfaces/Workspace](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/surfaces/Workspace)

### 3.13 Test and validation infrastructure

- Rust CLI/runtime integration tests: [crates/cli/tests](/home/heathledger/Documents/ioi/repos/ioi/crates/cli/tests)
  - Includes agent budget, pause/resume, resilience, swarm, trace, MCP, browser live runtime, computer-use suite, capabilities, routing/refusal receipt, wallet-network/session-channel, policy synthesis, PII determinism, and related e2e tests.
- Runtime service tests: [crates/services/src/agentic/runtime/service](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service)
  - Includes lifecycle, planner, cognition, queue, browser completion, action processing, command contract, anti-loop, incident/recovery, and execute-tool-phase tests.
- Policy/wallet tests: [crates/services/src/agentic/policy/tests.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/tests.rs), [crates/services/src/wallet_network](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/wallet_network)
- Browser/computer-use tests: [crates/drivers/src/browser](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser), [crates/services/src/agentic/runtime/execution/screen](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/screen)
- Chat/artifact tests: [crates/api/src/chat/tests](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/tests), [apps/autopilot/src-tauri/src/kernel/chat/tests](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/chat/tests)
- TS runtime/UI tests: [packages/agent-ide/src/runtime](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime), [apps/autopilot/src/windows/ChatShellWindow](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow)
- Desktop probe scripts: [apps/autopilot/scripts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/scripts)

## 4. Runtime execution flow

Status: COMPLETE — NEEDS VERIFICATION

The core `desktop_agent` service has a bounded-action settlement path. Some adjacent product paths, especially Agent Studio graph execution and UI-local projections, use separate or weaker governance semantics and must be handled explicitly in the A-Z findings.

### 4.1 User instruction to model/planner/work item creation

- Entrypoints:
  - UI task start: [apps/autopilot/src-tauri/src/kernel/task.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/task.rs), `start_task`, `encode_start_agent_params`, `build_start_agent_tx_bytes`.
  - CLI start/step loop: [crates/cli/src/commands/agent.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/cli/src/commands/agent.rs).
  - Service dispatch: [crates/services/src/agentic/runtime/service/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/mod.rs), `RuntimeAgentService::call`.
- Flow:
  - `start_task` creates an optimistic `AgentTask`, optional chat/workflow/knowledge preparation, a run bundle artifact, and a `task-started` Tauri event.
  - Non-chat-primary tasks bootstrap a signed `desktop_agent.start@v1` transaction with `StartAgentParams`.
  - `handle_start` in [crates/services/src/agentic/runtime/service/lifecycle/handlers/start.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/lifecycle/handlers/start.rs) rejects duplicate sessions, optionally hydrates swarm context, appends the initial user chat message, constructs `AgentState { status: Running, max_steps, budget, execution_queue, pending_* }`, persists it, and updates `agent::history`.
  - `handle_step` in [crates/services/src/agentic/runtime/service/step/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/mod.rs) hydrates state, verifies running/resumable status, applies recovery/resource/intent guards, bootstraps or processes queued work, and otherwise runs the cognitive loop.
  - Cognitive loop chooses routing tier, gathers perception, calls `cognition::think`, then sends raw model output to `action::process_tool_output`.
- State transitions:
  - UI: `AgentPhase::Running` is set before chain commit.
  - Runtime: canonical session status starts as `AgentStatus::Running`.
- Authority/evidence:
  - Service calls are signed system transactions.
  - The instruction itself is persisted into the structured chat store via `append_chat_to_scs`.
  - UI events and local task state are projections, not settlement authority.
- Failure behavior:
  - Duplicate start is rejected.
  - `handle_step` can pause for clarification, fail resource limits, resume pending actions, or enter recovery before model cognition.

### 4.2 Plan/work item to tool/browser/computer-use execution

- Entrypoints:
  - Queue/work orchestration: [crates/services/src/agentic/runtime/service/step/queue](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/queue).
  - Model tool-output processing: [crates/services/src/agentic/runtime/service/step/action/processing/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/mod.rs), `process_tool_output`.
  - Execute phase: [crates/services/src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/execute.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/execute.rs), `execute_tool_phase`.
  - Service execution: [crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs), `handle_action_execution`.
- Flow:
  - Raw model output is normalized via middleware, repaired when possible, macro-expanded, instruction-grounded, and converted into an `AgentTool`.
  - `process_tool_output` computes an `ActionRequest` hash for idempotency and checks `tool_execution_log`.
  - `execute_tool_phase` bootstraps execution contract evidence, duplicate detection, prechecks, optional timer-contract rewrite, and calls `execute_tool_with_optional_timeout`.
  - `execute_tool_with_optional_timeout` wraps WebResearch and browser tools in timeouts; otherwise it calls `service.handle_action_execution_with_state` directly.
  - `handle_action_execution` checks worker assignment tool allowlists, prepares the tool, builds determinism context, enforces policy, optionally repairs focus, constructs `ToolExecutor`, sets browser lease for browser tools, and dispatches to meta-tools, dynamic adapters, or `ToolExecutor::execute`.
- Browser/computer-use side effects:
  - Browser tools route through [crates/services/src/agentic/runtime/execution/browser/handler.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/browser/handler.rs) and [crates/drivers/src/browser/driver_core.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser/driver_core.rs).
  - Screen/GUI tools route through [crates/services/src/agentic/runtime/execution/screen/dispatch.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/screen/dispatch.rs) and [crates/drivers/src/gui/operator.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/gui/operator.rs).
- Failure behavior:
  - Browser tools have service-level timeout receipts.
  - Non-browser/non-WebResearch tools rely on lower-level tool-specific behavior unless their resolved intent is WebResearch.
  - Focus-sensitive tools can fail with deterministic `ERROR_CLASS=FocusMismatch`.

### 4.3 Tool execution to observation/evidence/receipt persistence

- Entrypoints:
  - Determinism context: [crates/services/src/agentic/runtime/service/handler/execution/execution/determinism.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/determinism.rs), `build_determinism_context`.
  - Policy/lease/approval gate: [crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs), `enforce_policy_and_record`.
  - Receipt persistence: [crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs).
- Flow:
  - Tool arguments and the tool payload are serialized with JCS; tool hash and request hash are computed.
  - Window binding is resolved for window-bound targets.
  - `WorkloadSpec::evaluate_lease` runs before policy execution.
  - On allow or approved grant, the runtime persists `PolicyDecisionRecord`, `FirewallDecisionReceipt`, `CommittedAction`, and `DeterminismEvidence`.
  - `ToolExecutor` returns `ToolExecutionResult`; visual observations are stored as memory artifacts and referenced by checksum.
  - `persist_terminal_settlement` loads the persisted committed action and policy decision, then writes `RequiredReceiptManifest`, `ExecutionObservationReceipt`, `PostconditionProof`, and `SettlementReceiptBundle`.
- Event projection:
  - `emit_execution_contract_receipt_event_with_metadata` emits `KernelEvent::ExecutionContractReceipt` with `authoritative: false`; persisted receipt structs are the authoritative layer.
- Concrete finding:
  - `PolicyDecisionRecord::build` is always called with `Vec::new()` for `matched_rules` in the traced path, so policy decision records lack verifier-visible rule provenance even when explicit rules matched.

### 4.4 Artifact generation to evaluation/validation/promotion

- Entrypoints:
  - App materialization: [apps/autopilot/src-tauri/src/kernel/chat/materialization.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/chat/materialization.rs).
  - Runtime planning: [crates/api/src/chat/generation/runtime_plan.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/runtime_plan.rs).
  - Non-swarm generation: [crates/api/src/chat/generation/non_swarm_bundle.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/non_swarm_bundle.rs), [crates/api/src/chat/generation/non_swarm_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/non_swarm_finalize.rs).
  - Swarm generation: [crates/api/src/chat/generation/swarm_bundle.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle.rs), [crates/api/src/chat/generation/swarm_bundle_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle_finalize.rs).
  - Render evaluation: [crates/api/src/chat/render_eval.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/render_eval.rs).
- Flow:
  - Materialization resolves runtime plan, prepared context, brief, selected skills, exemplars, render evaluator, generation timeout, and optional progress observers.
  - Non-swarm path generates one or more candidates, optionally evaluates render output, computes candidate validations, ranks candidates, selects the first primary-view-clearing candidate or the best available candidate, validates an `ExecutionEnvelope`, and returns `ChatArtifactGenerationBundle` with `candidate_summaries`, `winning_candidate_id`, `winner`, `validation`, and `render_evaluation`.
  - Swarm path builds a dispatch plan, executes independent patch workers concurrently with `JoinSet`, applies patch envelopes, records worker/patch/merge/replan receipts, evaluates render output, computes validation, builds an execution envelope, and returns a final bundle.
  - App materialization registers final files/artifacts and updates chat artifact session materialization/pipeline views.
- Failure behavior:
  - Missing runtimes or blocked generation produce blocked artifact sessions rather than synthetic successful artifacts.
  - Direct-author artifact timeouts can replan from `DirectAuthor` to `PlanExecute`.
- Concrete finding:
  - Swarm finalization returns `candidate_summaries: Vec::new()` and `winning_candidate_id: None`, so the swarm path lacks the same candidate/winner provenance exposed by the non-swarm path.

### 4.5 Approval-required action to approval grant/deny/resume

- Entrypoints:
  - Require approval from policy path: `enforce_policy_and_record` in [firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs).
  - Pending approval state: [crates/services/src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/pending_approval.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/pending_approval.rs).
  - UI response command: [apps/autopilot/src-tauri/src/kernel/governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/governance.rs), `gate_respond`.
  - Runtime resume: [crates/services/src/agentic/runtime/service/lifecycle/handlers/resume.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/lifecycle/handlers/resume.rs), [crates/services/src/agentic/runtime/service/actions/resume](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/actions/resume).
- Flow:
  - A policy `RequireApproval` verdict persists a policy decision/firewall receipt, emits a firewall interception, and returns `TransactionError::PendingApproval(request_hash)`.
  - `handle_pending_approval` persists pending tool JCS/hash/request nonce/visual hash/tool call on `AgentState`, marks status `Paused("Waiting for approval")`, registers incident pending approval, and appends a system chat message.
  - `gate_respond` polls committed raw state to ensure pending action metadata is chain-visible before acting.
  - The desktop UI currently fails closed for normal policy gates with `"Desktop UI cannot mint approval authority locally. Submit an externally issued ApprovalGrant via resume@v1."`
  - `handle_resume` writes an externally supplied `ApprovalGrant` under `get_approval_grant_key(session_id)`, appends a system resume message, sets the agent running, and the next step resumes the canonical pending action.
  - Resume validation loads the grant, verifies signature/authority/expiry/policy hash, validates PII review linkage when relevant, runs visual prechecks, then re-enters action execution.
- Failure behavior:
  - Policy-gate cancel is a no-op that leaves the agent paused.
  - Sudo-password resume is a separate runtime-secret path with TTL and one-time secret semantics.
- Concrete findings:
  - `ApprovalAuthority.scope_allowlist` exists structurally but is not enforced in `validate_registered_approval_grant`.
  - `gate_respond` updates local `gate_response` before returning the fail-closed error; UI reconciliation needs verification to ensure this optimistic mirror cannot imply approval.

### 4.6 Failed action to retry/repair/resume

- Entrypoints:
  - Post-execution finalization: [crates/services/src/agentic/runtime/service/step/action/processing/phases/finalize_action_processing.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/phases/finalize_action_processing.rs).
  - Pending resume: [crates/services/src/agentic/runtime/service/step/pending_resume.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/pending_resume.rs).
  - Incident recovery: [crates/services/src/agentic/runtime/service/step/incident](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/incident).
- Flow:
  - Finalization classifies failures, computes attempt keys, tracks repeat counts, records retry budgets, and gates unchanged retries.
  - Deterministic repair can queue patch-miss, workspace package-manifest, lowercase-rename, or incident-recovery actions.
  - Certain CEC terminal errors fail the agent immediately.
  - User-intervention failures pause with explicit resume text; approval and sudo flows preserve canonical pending tool metadata.
- Failure behavior:
  - Repeated unchanged failures transition to paused retry-guard states.
  - Some WebResearch unexpected-state and timeout paths intentionally continue or complete with bounded fallback messaging.
- Authority/evidence:
  - Recovery retries are annotated in determinism evidence via `recovery_retry` and `recovery_reason` when execution reaches `enforce_policy_and_record`.
  - Repairs queued before a new action still need their own subsequent action settlement.

### 4.7 Swarm/work-item dispatch to worker output/merge/verification

- Entrypoints:
  - Agent-service delegation primitives: `AgentDelegate`, `AgentAwait`, `AgentComplete` in [action_execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs).
  - Chat artifact swarm plan: [crates/api/src/chat/generation/swarm_plan.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_plan.rs).
  - Chat artifact swarm execution: [crates/api/src/chat/generation/swarm_bundle.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle.rs).
- Flow:
  - `handle_start` can hydrate `SwarmContext` from a `SWARM:` goal prefix.
  - Chat artifact swarm creates planner/skeleton/section/style/interaction/integrator/validation work items with dependencies and lease metadata.
  - Independent work items are dispatched in bounded batches with a parallelism cap; workers run under `JoinSet`.
  - Patch envelopes are applied to a canonical artifact payload; conflicts create graph mutation and replan receipts.
  - Finalization validates schema, runs render evaluation, computes validation, builds an execution envelope, and records swarm execution metadata.
- Failure behavior:
  - Lost worker results and invalid payloads return bounded `ChatArtifactGenerationError`.
  - Conflicted patches are rejected and recorded, with repair/replan receipts rather than silent merge.
- UNCERTAIN:
  - Agent-service child-session swarm merge/verification semantics need separate tracing beyond the artifact-swarm path.

### 4.8 Runtime event emission to persistence and UI projection

- Entrypoints:
  - Event/artifact registration: [apps/autopilot/src-tauri/src/kernel/events/emission.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/events/emission.rs).
  - App task state projection: [apps/autopilot/src-tauri/src/kernel/state.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/state.rs), `update_task_state`.
  - TS session controller: [packages/agent-ide/src/runtime/session-controller.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-controller.ts).
- Flow:
  - Rust event stream handlers build `AgentEvent`s and artifacts, append them to app state, persist them via `orchestrator::append_event` / artifact store helpers, and emit Tauri events such as `agent-event`, `artifact-created`, `task-updated`, `task-completed`, and session projection updates.
  - `update_task_state` syncs planning artifacts, calls `task.sync_runtime_views`, persists local task state to `ioi-memory`, and emits UI events.
  - TS controller appends unique events/artifacts by id and applies optimistic continue state before committed backend changes arrive.
- Authority model:
  - UI events and `ExecutionContractReceiptEvent { authoritative: false }` are projection/evidence mirrors.
  - Persisted state keys in `crates/types/src/app/action.rs` are the settlement authority for action receipts.
- Concrete finding:
  - The app has multiple projection stores (`AppState.current_task`, memory task snapshots, Tauri events, session controller state) that need explicit reconciliation tests against canonical runtime state for gate, pending, failed, and completed statuses.

## 5. A-Z audit findings

Status: COMPLETE

Categories A-Q are complete below. Later passes will normalize duplicate findings across categories into Critical gaps, Roadmap, Patch candidates, and Test plan.

### A. Agent lifecycle

Status: COMPLETE

What exists today:
- Canonical runtime lifecycle is stored in `AgentState.status: AgentStatus` with `Idle`, `Running`, `Completed`, `Failed`, `Paused`, and `Terminated` variants in [crates/services/src/agentic/runtime/types.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/types.rs).
- `AgentState` carries durable pending-action metadata: `pending_tool_jcs`, `pending_tool_hash`, `pending_request_nonce`, `pending_visual_hash`, and `pending_tool_call`.
- Lifecycle handlers exist for start, resume, post message, delete session, approval-authority registration/revocation under [crates/services/src/agentic/runtime/service/lifecycle/handlers](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/lifecycle/handlers).
- `handle_step` enforces running/resumable state, resource limits, pending action resume, queue processing, and cognitive loop progression in [step/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/mod.rs).
- UI task lifecycle is projected separately through `AgentTask.phase` and `update_task_state` in [apps/autopilot/src-tauri/src/kernel/state.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/state.rs).

Weaknesses and risks:
- `handle_delete_session` deletes state and logs “Deleted/Terminated” but does not persist a canonical `AgentStatus::Terminated` tombstone. A deleted session cannot be distinguished from never-created state by raw-state consumers.
- There is no obvious service-level `cancel@v1`; UI `cancel_task`/`dismiss_task` clear local app state and memory snapshots, but the canonical `desktop_agent` state may continue to exist unless separately deleted.
- UI `start_task` and `continue_task` set local `AgentPhase::Running` before backend/chain convergence, so projection drift is possible during transaction submit/commit failure.
- `gate_respond` mutates local `gate_response` before returning a fail-closed error for normal approval gates. This is projection-only, but it needs explicit reconciliation tests.
- `AgentStatus::Paused(String)` is string-coded; `AgentPauseReason::from_message` mitigates some cases, but pause state is not an enum on the persisted status itself.

Why it matters:
- Lifecycle state is the operator’s main safety signal. Stale “running”, “approved”, or “complete” projections can cause unsafe follow-on actions even if the lower-level policy path fails closed.

Recommended change:
- Add canonical `cancel@v1` / `terminate@v1` that persists a terminal tombstone with reason, timestamp, and cancellation actor before optional cleanup.
- Change persisted pause status to a typed pause record or add a typed `pause_reason` field alongside the legacy string.
- Add a projection reconciler invariant: UI can be optimistic only until a bounded deadline, then it must rehydrate from canonical state.

Risk level: High  
Effort level: M  
Suggested validation: lifecycle integration tests for start failure, cancel, delete/tombstone, resume from each pause reason, and UI projection reconciliation after rejected transaction.

### B. Planning and decomposition

Status: COMPLETE

What exists today:
- Typed planner structs exist in [crates/services/src/agentic/runtime/types.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/types.rs): `PlannerState`, `PlanStep`, `PlannerStatus`, `PlanStepConstraint`, `PlannerDiscoveryRequirement`, and `ExecutionPlanState`.
- `AgentState.execution_queue: Vec<ActionRequest>` stores queued executable requests.
- `WorkerAssignment`, `WorkerTemplateDefinition`, `AgentPlaybookDefinition`, and parent playbook run structs model delegated work, budgets, allowed tools, success criteria, and merge mode.
- Queue processing and planner tests live under [crates/services/src/agentic/runtime/service/step/queue](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/queue) and [crates/services/src/agentic/runtime/service/step/planner/tests.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/planner/tests.rs).
- Chat artifact planning has a separate swarm plan model in [crates/api/src/chat/generation/swarm_plan.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_plan.rs).

Weaknesses and risks:
- `AgentState.execution_queue` stores `ActionRequest` rather than `PlanStep`, so by the time execution is queued, dependency status, constraints, and receipt obligations are not naturally attached to the executable item.
- `PlanStep.arguments_json` is a string, not a typed canonical tool payload or schema-validated value.
- Planner status and cursor exist, but dynamic replanning/graph mutation receipts appear stronger in chat artifact execution than in the main `desktop_agent` planner path.
- Worker assignment tool allowlists are enforced in `handle_action_execution`, but plan validation before execution is not visible as a mandatory gate in the traced path.
- No clear run-level budget object ties max steps, token budget, wall-clock budget, tool deadlines, and verification requirements into one planner input.

Why it matters:
- LLM planning should produce an intermediate representation the runtime can validate before any side effect. A queue of loosely connected action requests makes dependency, retry, and receipt requirements harder to prove.

Recommended change:
- Introduce a canonical `ExecutablePlan` settlement artifact that binds `PlanStep`s to typed tool payloads, dependencies, budget, timeout, approval requirement, and receipt manifest before dispatch.
- Make `execution_queue` hold references to validated plan steps or include `PlanStepConstraint` and expected receipt keys.
- Require replans to create `ExecutionReplanReceipt`-style records in the main agent path, not only chat artifacts.

Risk level: High  
Effort level: L  
Suggested validation: planner fixture that emits invalid dependencies, invalid tool args, expired budget, and missing receipt requirements; assert no execution occurs before plan validation passes.

### C. Tool invocation and capability boundaries

Status: COMPLETE

What exists today:
- `AgentTool` variants and tool target typing live under [crates/types/src/app/agentic/tools](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/agentic/tools).
- Built-in tool schemas are exposed through `discover_tools` in [crates/services/src/agentic/runtime/tools/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/tools/mod.rs).
- Tool-output normalization, repair, macro expansion, instruction grounding, idempotency hash checks, and execution prechecks live in [process_tool_output](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/mod.rs).
- `handle_action_execution` enforces worker assignment allowed tools and constructs deterministic request/policy state before tool dispatch.
- `ToolExecutor` in [crates/services/src/agentic/runtime/execution/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/mod.rs) dispatches browser, screen, filesystem, system, MCP, web, math, and dynamic tools.
- `WorkloadSpec::evaluate_lease` is checked before policy decision settlement.

Weaknesses and risks:
- Capability enforcement is split across worker assignment allowlists, policy rules, workload leases, tool prechecks, and executor-specific guards. There is no single deny-by-default `CapabilityLease` object passed to every executor.
- Approval authority `scope_allowlist` is not enforced during grant validation, so registry scope is weaker than the type suggests.
- `PolicyDecisionRecord.matched_rules` is empty in the execution path, weakening tool authorization provenance.
- Non-browser/non-WebResearch tools do not have a visible global timeout wrapper in the traced service layer.
- Dynamic tools and adapters rely on admission logic in [action_execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs) and [adapters](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/adapters); they need the same pre/postcondition manifest as built-ins.

Why it matters:
- Tools are the side-effect boundary. If capability checks are distributed without a canonical lease and receipt, it becomes difficult to prove a given side effect had the exact authority intended.

Recommended change:
- Create a required `CapabilityLeaseDecision`/`ToolInvocationEnvelope` produced before execution and consumed by every executor, including dynamic adapters and MCP.
- Enforce approval authority scope against `ActionTarget`/tool name/workload target before accepting a grant.
- Add a service-level timeout/default deadline in the tool invocation envelope, with per-tool overrides only narrowing or explicitly extending it under policy.

Risk level: High  
Effort level: L  
Suggested validation: tool authorization matrix tests across built-in, MCP, dynamic, browser, shell, filesystem, and graph-node tools; include out-of-scope approval authority and hanging tool fixtures.

### D. Browser and computer-use harness

Status: COMPLETE

What exists today:
- Browser driver core in [crates/drivers/src/browser/driver_core.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser/driver_core.rs) manages process launch, pinned Chromium envs, lease flag, health probing/reset, and request timeouts.
- Browser actions execute through [crates/services/src/agentic/runtime/execution/browser/handler.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/browser/handler.rs) with snapshots, clicks, synthetic clicks, hover, type, screenshot, and follow-up validation.
- Screen/computer-use dispatch lives in [crates/services/src/agentic/runtime/execution/screen/dispatch.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/screen/dispatch.rs).
- Native OS input/capture lives in [crates/drivers/src/gui/operator.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/gui/operator.rs) with perceptual hash checks before low-level actions.
- Service-level browser timeout is applied in both `execute_tool_with_optional_timeout` and `handle_action_execution` for browser targets.

Weaknesses and risks:
- Browser lease is set with `service.browser.set_lease(true)` for browser tools and pending browser actions; no matching release path was found in the traced snippets. This may be handled elsewhere, but is currently UNCERTAIN.
- Native `inject_click` emits a `FirewallInterception` on visual drift with zero `request_hash` and `session_id: None` in [operator.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/gui/operator.rs), making the event non-authoritative and hard to join to a settled action.
- Origin/domain checks exist through policy conditions and workload lease observed domain, but before/after DOM/screenshot provenance is not clearly included in `SettlementReceiptBundle`; visual artifact hashes can be attached only when returned by the executor.
- Browser launch arguments conditionally include no-sandbox behavior for CI/root. This is pragmatic, but needs an explicit runtime receipt or environment warning when sandbox is disabled.
- Raw coordinate/foreground operations depend heavily on tier/focus/visual hash checks; tests should prove these fail closed under focus drift and DOM/visual mismatch.

Why it matters:
- Browser and OS actions are high-risk because they can click, type, upload, paste, or navigate outside the model’s text world. They need before/after observations, target provenance, and replayable evidence.

Recommended change:
- Add an `InteractionReceipt` for browser/screen actions with before observation hash, selected element/coordinate binding, origin/domain/window binding, action, after observation hash, and postcondition.
- Make browser lease scoped and RAII-like: acquired for a request hash, released on completion/error/timeout, and auditable.
- Convert low-level visual drift events into action-scoped postcondition proofs when they occur inside a settled request.

Risk level: High  
Effort level: M  
Suggested validation: Playwright/browser fixture and native-operator simulation for domain mismatch, stale element, visual drift, timeout, and disabled sandbox environment; assert receipts and fail-closed state.

### E. Policy, approvals, and authority

Status: COMPLETE

What exists today:
- `PolicyEngine::evaluate_with_working_directory` in [crates/services/src/agentic/policy/engine.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/engine.rs) evaluates rules, default policy, working directory, target aliases, and PII overlay. It blocks fail-closed on invalid request hashes and high-risk PII inspection failures.
- `ActionRules`, `Rule`, `RuleConditions`, and `DefaultPolicy` live in [crates/services/src/agentic/rules.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/rules.rs).
- `enforce_policy_and_record` in [firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs) binds policy hash, capability lease, approval grant, policy decision record, firewall decision receipt, committed action, and determinism evidence before side effects.
- `ApprovalAuthority` and `ApprovalGrant` are typed in [crates/types/src/app/action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs). Grants bind request hash, policy hash, audience, nonce, counter, expiry, optional usage count, optional window id, PII action, scoped exception, and signature.
- Approval validation exists in both runtime resume path [approvals.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/actions/resume/approvals.rs) and wallet-network validation [crates/services/src/wallet_network/validation.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/wallet_network/validation.rs).
- Desktop `gate_respond` is fail-closed for policy gates; it cannot mint local approval authority and tells callers to submit an externally issued `ApprovalGrant`.

Weaknesses and risks:
- `ApprovalAuthority.scope_allowlist` is not enforced by `validate_registered_approval_grant`; an authority registry entry can advertise scope without runtime enforcement.
- `PolicyDecisionRecord.matched_rules` is empty, so policy decisions do not explain rule causality.
- Desktop approval UX cannot currently approve normal policy gates, which is safe but product-incomplete. If UI communicates approval affordances without an external grant flow, it is misleading.
- Agent Studio graph execution has its own `GovernanceTier` and `check_governance`; `GovernanceTier::Silent` auto-approves `RequireApproval` decisions instead of producing external approval authority.
- Approval grant consumption/replay protection appears stronger in wallet-network handlers, but the direct runtime `enforce_policy_and_record` path loads a grant by session key and validates structural/signature/policy/request binding; explicit consumption semantics need deeper verification across both paths.

Why it matters:
- Target invariant: no consequential action may execute unless a verifier can reconstruct the exact request, policy hash, matched rules, approval authority, scope, deadline, and grant. Missing scope and rule provenance leave holes in that proof.

Recommended change:
- Extend policy evaluation to return `PolicyEvaluationRecord { verdict, matched_rule_ids, default_policy_used, pii_decision_hash, lease_check }` and persist it directly into `PolicyDecisionRecord`.
- Enforce `ApprovalAuthority.scope_allowlist` against canonical target labels, tool names, and/or workload scopes before accepting a grant.
- Replace graph `GovernanceTier::Silent` auto-approval with a simulator-only receipt or require the same `ApprovalGrant` path for consequential nodes.
- Add approval consumption state to the `desktop_agent` path if it is not already guaranteed by wallet-network validation.

Risk level: Critical  
Effort level: L  
Suggested validation: policy replay fixtures, out-of-scope authority grant test, expired grant test, revoked authority test, graph strict/silent governance tests, and approval replay/counter tests.

### F. Receipts, evidence, and provenance

Status: COMPLETE

What exists today:
- Canonical action/receipt structs live in [crates/types/src/app/action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs): `CommittedAction`, `DeterminismEvidence`, `PolicyDecisionRecord`, `FirewallDecisionReceipt`, `ExecutionObservationReceipt`, `PostconditionProof`, `RequiredReceiptManifest`, and `SettlementReceiptBundle`.
- Each receipt type verifies a canonical hash over its content using JCS or codec canonicalization.
- `persist_terminal_settlement` in [receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs) persists manifest, execution observation, postcondition proof, and settlement bundle after tool execution.
- Visual evidence blobs are stored as memory artifacts with checksum metadata in `persist_visual_observation`.
- `ExecutionContractReceiptEvent` explicitly marks emitted event receipts as `authoritative: false`, preserving the “events are UX mirrors” direction.
- Chat artifact execution has `ExecutionEnvelope` and receipt-like swarm/change/merge/verification records in [crates/api/src/execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/execution.rs).

Weaknesses and risks:
- Required receipt manifests are currently generic for all targets: `execution.outcome` and `execution.terminal_outcome`. Browser clicks, file writes, network fetches, commerce, clipboard, and OS actions should have target-specific before/after/postcondition requirements.
- `ExecutionObservationReceipt` stores history/error and optional visual artifact hash, but not a typed before/after observation set, command digest, exit code, URL/domain, file hash diff, or MCP server identity.
- `SettlementReceiptBundle` stores hashes, but does not itself include or point to state keys/URI references for reconstructing each child artifact. Consumers must know key derivation conventions.
- Firewall signing seed is deterministically derived from chain id and account id if not present. This gives stable signatures but is not a hardware/external attestation boundary.
- Agent Studio graph execution and workflow manager receipts are not unified with `SettlementReceiptBundle`.
- `KernelEvent::ExecutionContractReceipt` events contain hash-like evidence strings but are explicitly non-authoritative; UI must not display them as settled receipts without a persisted bundle lookup.

Why it matters:
- A receipt bundle is only as strong as its required evidence. Generic terminal receipts are insufficient for high-consequence actions such as browser checkout, file mutation, credential use, OS paste, or external API calls.

Recommended change:
- Define target-specific receipt manifests for `ActionTarget` categories: browser, screen, fs, sys, net, model, media, commerce, clipboard, connector/MCP.
- Include child receipt references in `SettlementReceiptBundle`: state keys or artifact ids for committed action, policy decision, observations, postconditions, visual blobs, and external verifier artifacts.
- Promote chat `ExecutionEnvelope` and workflow receipts into the same settlement-root model or explicitly label them non-settlement projections.
- Replace deterministic local firewall signing seed with a configured key/attestation provider for production profiles, while preserving dev-mode fixtures.

Risk level: High  
Effort level: XL  
Suggested validation: golden canonical receipt fixtures; replay test that reconstructs a full settlement bundle from state only; browser/file/network target-specific manifest tests; event-vs-state authority tests.

### G. State, persistence, and projections

Status: COMPLETE

What exists today:
- Canonical runtime state is persisted through `StateAccess` with service namespace keys for agent state, policy decisions, commits, receipts, incidents, and approval grants.
- `MemoryRuntime` in [crates/memory/src/lib.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/memory/src/lib.rs) stores chat/thread checkpoints, archival memory, artifact records, and blobs in SQLite.
- App task projection lives in `AppState.current_task`, updated through [state.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/state.rs), persisted via `orchestrator::save_local_task_state`, and emitted over Tauri.
- Event/artifact indexes and run bundle references are updated in [events/emission.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/events/emission.rs).
- TS session state is maintained by [packages/agent-ide/src/runtime/session-controller.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-controller.ts).
- Lower-level storage primitives exist in [crates/storage/src/wal.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/storage/src/wal.rs), [crates/storage/src/redb_epoch_store.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/storage/src/redb_epoch_store.rs), and [crates/state/src](/home/heathledger/Documents/ioi/repos/ioi/crates/state/src).

Weaknesses and risks:
- The app maintains several mirrors: canonical service state, memory snapshots, `AppState.current_task`, Tauri events, session projection, and TS Zustand state. Rebuild/reconciliation rules are not clearly centralized.
- UI task state is sometimes updated before chain commit (`start_task`, `continue_task`, `gate_respond`), creating windows of stale or misleading state.
- `handle_delete_session` removes canonical state and local checkpoint rather than persisting an auditable terminal tombstone.
- `register_event` appends event refs and memory events, but event ids are UUIDs rather than content-addressed/canonical. Good for UX, weak for replay.
- Memory persistence uses artifacts and blobs, but not all authoritative receipt records are mirrored into a user-visible evidence atlas.

Why it matters:
- Projection drift is a correctness issue in agentic runtimes because operators make approval and intervention decisions from UI state.

Recommended change:
- Add a projection reconciler that periodically rebuilds `AgentTask`/session projections from canonical service state plus memory artifacts, with deterministic conflict resolution.
- Add projection checkpoint versioning and source-of-truth labels: `canonical`, `optimistic`, `stale`, `reconciled`, `failed_to_reconcile`.
- Persist lifecycle tombstones and deletion receipts.
- Content-address or hash-link important event projections to canonical receipt records when available.

Risk level: High  
Effort level: L  
Suggested validation: projection replay tests from raw state; stale gate/approval UI tests; delete/tombstone migration tests; snapshot rebuild tests after simulated Tauri event loss.

### H. Artifact generation and validation

Status: COMPLETE

What exists today:
- Artifact routes, manifests, materialization contracts, candidate summaries, render evaluation, and validation structs are represented in `ioi_api::chat` and Autopilot model types.
- Non-workspace materialization in [materialization.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/chat/materialization.rs) resolves runtimes, prepared context, timeouts, generation strategy, progress, render evaluator, and fallback/blocked artifacts.
- Non-swarm generation in [non_swarm_bundle.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/non_swarm_bundle.rs) produces candidates, render evaluations, validations, ranked candidates, and a winner.
- Non-swarm finalization in [non_swarm_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/non_swarm_finalize.rs) validates the execution envelope and records `candidate_summaries`, `winning_candidate_id`, `winning_candidate_rationale`, `validation`, and `render_evaluation`.
- Swarm generation/finalization in [swarm_bundle.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle.rs) and [swarm_bundle_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle_finalize.rs) records work, patch, merge, verification, graph mutation, dispatch, repair, and replan receipts.
- Render acceptance policy and validation merge logic live in [render_eval.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/render_eval.rs).

Weaknesses and risks:
- Swarm artifacts omit `candidate_summaries` and `winning_candidate_id`, causing inconsistent provenance across execution strategies.
- Render evaluation is optional; if no evaluator is configured or unsupported, validation can still proceed. That may be appropriate for some renderers, but the materialization contract should clearly record “skipped by policy” vs “unavailable”.
- Artifact validation is not tied to `SettlementReceiptBundle`; chat execution envelopes are validated separately from action settlement receipts.
- HTML/JS sandboxing was not fully verified in this pass. Search shows artifact render surfaces and iframe-like renderers, but final sandbox/CSP guarantees need a dedicated UI/browser pass.
- Direct-author provisional validation can surface artifacts quickly; this is useful, but artifact promotion needs a stricter “primary view cleared by evidence” gate for product-ready mode.

Why it matters:
- Artifacts are durable outputs users may trust, export, or build on. Promotion without reproducible validation evidence creates product and security risk.

Recommended change:
- Require every promoted artifact to include `ArtifactPromotionReceipt { artifact_hashes, validation_hash, render_eval_hash, execution_envelope_hash, settlement_refs }`.
- Normalize swarm and non-swarm provenance so every artifact has candidate/canonical-merge lineage and selected-winner rationale.
- Add explicit validation status labels: `validated`, `validated_without_render_eval`, `blocked`, `repairable`, `provisional`.
- Verify renderer sandbox/CSP and store that evidence as a postcondition proof for interactive artifacts.

Risk level: High  
Effort level: L  
Suggested validation: render regression fixtures; HTML sandbox tests; artifact promotion tests requiring validation evidence; swarm vs non-swarm provenance equivalence tests; blocked artifact tests ensuring no synthetic success.

### I. Swarm/concurrent execution

Status: COMPLETE

What exists today:
- Chat artifact swarm planning builds typed `SwarmPlan`/`SwarmWorkItem` records with dependencies, read/write paths, write regions, lease requirements, acceptance criteria, retry budgets, and verification policies in [crates/api/src/chat/generation/swarm_plan.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_plan.rs) and [crates/api/src/execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/execution.rs).
- Artifact swarm execution uses bounded dispatch batches, a runtime-specific parallelism cap, and `JoinSet` worker concurrency in [swarm_bundle.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle.rs).
- Patch application records worker, patch, merge, graph-mutation, repair, and replan receipts; conflicts become blocked graph mutations rather than silent overwrites.
- Repair can dynamically spawn follow-up work items, re-run render evaluation, and record repair/replan receipts in [swarm_bundle_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle_finalize.rs).
- Main `desktop_agent` delegation has separate parent/child worker-result paths under [crates/services/src/agentic/runtime/service/lifecycle/worker_results](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/lifecycle/worker_results).

Weaknesses and risks:
- Chat artifact swarm has dependency-aware concurrent dispatch, but no general-purpose runtime-wide lease lock manager for write paths/write regions. Conflict detection is patch-level and semantic, not a shared lock service.
- Worker receipts include `read_paths`, `write_paths`, and `write_regions`, but there is no visible enforcement that two concurrently dispatched work items cannot mutate overlapping scopes.
- `JoinSet` waits for all workers in a batch; if a worker future hangs, the batch relies on lower-level model/request timeouts rather than a batch-level cancellation deadline.
- Agent Studio graph execution is sequential (`queue.pop()` loop) and uses `maxSteps`/`timeoutMs` checks only between nodes. A long-running `execute_ephemeral_node` call is not wrapped in a node-level timeout in [graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs).
- Agent-service child-session swarm merge/verification semantics are separate from artifact swarm receipts and need a unifying settlement root.

Why it matters:
- Concurrent agents need deterministic scope ownership. Without lease locks and batch-level cancellation, independent workers can create non-replayable conflicts or hang the run despite a declared graph timeout.

Recommended change:
- Add a runtime `ScopeLeaseRegistry` for swarm/workflow/graph execution that grants read/write leases over canonical path, region, connector, browser session, and artifact scopes.
- Wrap every swarm dispatch batch and graph node execution in explicit deadlines that cancel unfinished futures and emit timeout receipts.
- Promote swarm merge and verification receipts into the same settlement-root model as tool actions, with child receipt references.

Risk level: High  
Effort level: L  
Suggested validation: concurrency simulation with overlapping write regions, hung worker future, lost worker result, conflicting patches, and graph node timeout; assert cancellation, failed receipts, and no artifact promotion without verification.

### J. Inference adapters and model runtime

Status: COMPLETE

What exists today:
- `InferenceRuntime` in [crates/api/src/vm/inference/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/vm/inference/mod.rs) defines text inference, streaming, embeddings, media operations, model lifecycle operations, runtime provenance, and safety-model hooks.
- `HttpInferenceRuntime` in [http_adapter.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/vm/inference/http_adapter.rs) supports OpenAI-compatible, Anthropic, and Ollama-native request strategies.
- OpenAI tool requests set `tool_choice: "required"` and `parallel_tool_calls: false`; JSON mode sets `response_format` when no tools are present.
- HTTP clients have request timeouts derived from env/defaults; streaming paths use idle timeouts through `next_stream_chunk_with_idle_timeout`.
- Tests cover OpenAI streaming accumulation, tool-call request serialization, Ollama native streaming idle timeout, explicit timeout env overrides, and local/remote streaming selection in [http_adapter/tests.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/vm/inference/http_adapter/tests.rs).
- Typed receipt structs exist for inference and model lifecycle workloads in [crates/types/src/app/inference.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/inference.rs) and [crates/types/src/app/model_registry.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/model_registry.rs).

Weaknesses and risks:
- `InferenceRuntime` has no cancellation token parameter. Dropping the future may cancel in Tokio contexts, but the runtime contract does not make cancellation or abort propagation explicit.
- `execute_inference_streaming` default implementation ignores the token channel and delegates to non-streaming execution, so streaming support is optional and not capability-advertised at the trait boundary.
- Provider errors are mostly collapsed into `VmError::HostError("Network Error..." / "Provider Error...")`; there is no retry taxonomy for transient network failures, rate limits, invalid request, refusal, context overflow, or safety refusal.
- Retry/fallback strategy is not centralized. Local/remote runtime selection is wired at app startup in [apps/autopilot/src-tauri/src/lib.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/lib.rs), but per-call fallback policy is not a verifier-visible runtime decision.
- Token usage is not generally captured in `WorkloadInferenceReceipt` even though fields exist; model calls often return bytes with no receipt-level latency/token accounting.
- Prompt/input contexts are byte blobs; structured output enforcement exists for provider JSON mode/tool mode but is not a universal runtime contract.

Why it matters:
- Model calls are proposal generators. The runtime still needs deterministic timeouts, refusal classification, budget accounting, and structured-output validation so model failures do not become ambiguous runtime failures.

Recommended change:
- Add `InferenceRequestEnvelope { model_id, capability, deadline, token_budget, structured_schema_hash, cancellation_id, fallback_policy }` and persist an `InferenceDecisionReceipt`.
- Extend `InferenceRuntime` with explicit capability metadata and cancellation/deadline input.
- Classify provider errors into stable machine codes and wire retries/fallbacks through policy rather than ad hoc caller behavior.
- Populate `WorkloadInferenceReceipt` from every model call with latency, streaming, token counts when available, model provenance, and error class.

Risk level: High  
Effort level: L  
Suggested validation: fake provider fixture for rate limit, timeout, context overflow, refusal, malformed JSON, stalled stream, and cancellation; assert stable error classes, receipts, and no state mutation from invalid structured output.

### K. Observability and debugging

Status: COMPLETE

What exists today:
- Runtime events and artifacts are persisted in memory and emitted over Tauri through [events/emission.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/events/emission.rs).
- Event builders include command runs, command streams, file edits, code search, browser navigation/snapshot, test runs, and receipt digest events.
- Trace bundle commands exist: `get_trace_bundle`, `compare_trace_bundles`, `export_trace_bundle`, and `export_thread_bundle` in [apps/autopilot/src-tauri/src/kernel/artifacts.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/artifacts.rs).
- Trace bundles include answer, history, events, receipt events, artifacts, interventions, notifications, and assistant workbench activity; UI export presets live in [traceBundleExportModel.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/utils/traceBundleExportModel.ts).
- TS runtime surfaces can load thread events/artifacts via [packages/agent-ide/src/runtime/session-runtime.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-runtime.ts), and retained workbench traces are loaded in [useRetainedWorkbenchTrace.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/hooks/useRetainedWorkbenchTrace.ts).
- A basic trace span viewer exists in [TraceViewer.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/features/Editor/Trace/TraceViewer.tsx).

Weaknesses and risks:
- `build_event` uses random UUID event ids and timestamp ordering, not content-addressed event ids tied to canonical receipt hashes.
- `load_canonical_trace_bundle_source` labels the export as canonical but derives `receipts` by filtering `EventType::Receipt` from memory events, not by loading persisted `SettlementReceiptBundle`/`PolicyDecisionRecord` state keys.
- Trace viewer spans are generic UI models with simplified scaling and are not backed by runtime span ids, parent/child ids, request hashes, policy hashes, or receipt hashes.
- Logs use `println!`, `eprintln!`, `log`, and `tracing` in different subsystems without a visible run-wide correlation id convention.
- “Why did this happen?” is partially visible through events and artifact evidence views, but policy matched rules, approval authority scope checks, and target-specific postconditions are currently missing or weak.

Why it matters:
- Observability becomes part of runtime safety when operators decide whether to approve, retry, export, or trust an artifact. A canonical-looking bundle built from projection events can overstate authority.

Recommended change:
- Rename current exported event bundle to `projection_trace_bundle` or enrich it by loading authoritative state receipts into a `SettlementTraceBundle`.
- Add run/request correlation ids to every event/log/receipt path: `session_id`, `step_id`, `request_hash`, `policy_hash`, `settlement_bundle_hash`, and optional `parent_span_id`.
- Back the trace viewer from persisted spans/receipts rather than mock-shaped local spans.
- Add a “settlement missing” UI state whenever an event receipt has no persisted canonical bundle.

Risk level: High  
Effort level: M  
Suggested validation: export a run containing a settled tool action and assert the bundle contains canonical committed action, policy decision, settlement bundle, and projection events; compare trace bundles after injected divergence.

### L. Security and sandboxing

Status: COMPLETE

What exists today:
- Policy checks cover command allowlists, denied shells, package manager identifiers, allowed domains, allowed paths, GUI app/window checks, workspace filesystem augmentation, PII overlays, and safety ratchets in [crates/services/src/agentic/policy](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy).
- MCP drivers clear ambient env, set limited PATH, do not inherit secrets by default, support production strict mode, require integrity/allowed tools in production, block unverified high-risk tools outside development, and enforce runtime containment on path/network/child-process-like arguments in [crates/drivers/src/mcp](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/mcp).
- Optional dev filesystem MCP is disabled by default and requires `IOI_CHAT_MCP_PROFILE=dev_filesystem` in [apps/autopilot/src-tauri/src/execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs).
- Browser launch uses pinned revision/hash envs and request timeouts in [driver_core.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser/driver_core.rs).
- PII deterministic review docs exist in [docs/security/pii_review_contract.md](/home/heathledger/Documents/ioi/repos/ioi/docs/security/pii_review_contract.md).

Weaknesses and risks:
- The terminal driver README explicitly states security is not enforced in the driver and depends entirely on upstream policy. If any call path reaches the driver outside `desktop_agent` settlement, host command execution becomes ambient authority.
- Agent Studio graph `code`, `browser`, `tool`, and media nodes run through `execute_ephemeral_node`, not the canonical `desktop_agent` settlement path, and use `SimulationSafetyModel` that returns safe/no PII in [execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs).
- Browser README states validator-mode sandboxing is “implementation pending”; `driver_core.rs` can add `--no-sandbox` for CI/root/`NO_SANDBOX` without producing an explicit receipt or user-visible warning.
- MCP `send_request` has a 60s timeout only for initialization; `list_tools` and `call_tool` do not wrap requests in a timeout at the transport boundary.
- Dev MCP uses `npx -y @modelcontextprotocol/server-filesystem` with `DeveloperUnconfined`, network egress, child processes, and unverified package-manager source when explicitly opted in. That is acceptable for dev but must not be reachable in production profiles.
- Plugin trust and connector commands are broad Tauri surfaces; a full plugin/connector threat-model pass was not completed in this audit.

Why it matters:
- A zero-trust hypervisor cannot depend on every caller remembering to enter the safe path. Dangerous drivers must either be uncallable without capability envelopes or self-checking at the boundary.

Recommended change:
- Move driver-level guard assertions into terminal/browser/MCP adapters: reject execution unless a signed `ToolInvocationEnvelope`/capability lease is present.
- Force graph and workflow side effects through the same settlement/policy/receipt service as `desktop_agent`.
- Add production-profile checks that fail startup if `NO_SANDBOX`, dev MCP, unverified MCP, or unconfined plugin modes are enabled.
- Add transport-level timeouts to MCP `list_tools` and `call_tool`.

Risk level: Critical  
Effort level: L  
Suggested validation: direct-driver bypass tests, production profile startup tests, graph code/browser node policy-bypass test, MCP hung call test, no-sandbox environment warning/receipt test, and plugin trust revocation test.

### M. Testing and verification

Status: COMPLETE

What exists today:
- Runtime-focused gate script exists at [scripts/check-agent-runtime.sh](/home/heathledger/Documents/ioi/repos/ioi/scripts/check-agent-runtime.sh) and runs `cargo check -p ioi-api`, `cargo check -p ioi-services`, focused runtime seam tests, and `pii_hard_gates`.
- There is broad Rust coverage across runtime service lifecycle, step, planner, queue, action processing, incident recovery, browser completion, worker results, policy, MCP, terminal, browser, workflows, graph runner, artifacts, chat, and CLI e2e tests.
- CLI tests cover agent trace, swarm, budget, pause/resume, resilience, MCP, browser live runtime, computer-use suite, routing failure/action/refusal contracts, wallet-network session channel, PII review determinism, and workload control.
- TS tests cover session controller, composer, artifact hub models, trace bundle export model, authority/privacy/runtime status copy, and chat shell hooks.
- Browser/computer-use reliability suites and desktop probe scripts exist.

Weaknesses and risks:
- There is no evident golden fixture that reconstructs a full `SettlementReceiptBundle` from persisted state and proves all hashes/child references match.
- Missing tests for `PolicyDecisionRecord.matched_rules` provenance and approval authority `scope_allowlist` enforcement.
- Missing integration test proving Agent Studio graph side effects either produce canonical settlement receipts or are blocked.
- Missing tests for graph node timeout cancellation and MCP `call_tool` timeout.
- Missing projection authority tests where event-level receipts exist but canonical settlement state is absent.
- Missing property tests for canonical JSON/hash stability across action, policy, receipt, and trace bundle structs.
- Artifact swarm/non-swarm provenance parity has a gap: swarm lacks candidate/winner summaries.

Why it matters:
- The repo has lots of tests, but the missing tests line up with the highest-risk runtime invariants. Existing coverage is broad; the next layer must be invariant-focused.

Recommended change:
- Add a `bounded_runtime_invariants` test suite that directly targets policy, approval, receipts, projection authority, graph/workflow bypasses, and timeout/cancellation.
- Add golden receipt fixtures under `crates/types` or `crates/services` for canonical hashing and replay.
- Add simulation/failure-injection tests for hung tools, partial commits, stale UI events, projection rebuilds, and scope-conflicting swarm workers.

Risk level: High  
Effort level: M  
Suggested validation: `./scripts/check-agent-runtime.sh`, plus new focused commands for receipt golden fixtures, graph bypass tests, MCP timeout tests, and TS projection authority tests.

### N. Product/UX integration

Status: COMPLETE

What exists today:
- Chat shell, artifact hub, evidence views, execution route cards, visual evidence cards, approval cards, capability registry surfaces, workflow/runs views, and trace bundle exports are present under [apps/autopilot/src/windows/ChatShellWindow](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow) and [apps/autopilot/src/surfaces](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/surfaces).
- Runtime inspection copy maps artifact verification, validation, delivery, and context into UI summaries in [runtimeInspection.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/runtimeInspection.ts).
- Session projection and retained trace loading are exposed through `@ioi/agent-ide` runtime abstractions.
- Approval/gate UI exists, while desktop policy approval currently fails closed and requires external `ApprovalGrant` submission.

Weaknesses and risks:
- Current product surfaces can show “receipt” counts based on projection/event receipts, but not necessarily canonical settlement receipt bundles.
- Desktop approval UI has affordance tension: users can respond to gates, but normal policy-gate approval cannot be minted locally. Without crisp copy/state reconciliation, this can look broken or misleading.
- Artifact delivery summary says “Winning candidate not recorded yet” for paths where the runtime currently never records a winner, such as swarm artifacts.
- Workflows and graph runs are product-visible but not clearly explainable as either canonical settled runs or lighter local automation.
- There is no first-class operator intervention queue that unifies policy gates, sudo/password gates, workflow failures, graph blocks, and connector step-up prompts under one authority model.

Why it matters:
- UX language is part of safety. If users see “canonical trace” or “receipt” when the underlying object is a projection, they may over-trust incomplete evidence.

Recommended change:
- Introduce explicit UI evidence tiers: `projection event`, `runtime receipt event`, `settlement receipt`, `external approval grant`, `artifact promotion receipt`.
- Make policy gates display “requires external wallet.network approval grant” with request hash, policy hash, scope, and deadline, not a local approve button for normal gates.
- Add an operator intervention queue backed by canonical pending state and authority records.
- Mark graph/workflow runs as `local automation receipts` until they are routed through settlement.

Risk level: Medium  
Effort level: M  
Suggested validation: UI tests for gate copy/state, missing settlement receipts, swarm artifact provenance copy, workflow run evidence labels, and trace export labels.

### O. API and service boundaries

Status: COMPLETE

What exists today:
- Core bounded runtime boundary is the `desktop_agent` blockchain service in [RuntimeAgentService::handle_service_call](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/mod.rs), with codec-decoded methods `start@v1`, `resume@v1`, `step@v1`, `post_message@v1`, approval-authority registration/revocation, and delete session.
- Tauri app exposes a large command surface in [apps/autopilot/src-tauri/src/lib.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/lib.rs), including tasks, governance, connectors, workflows, plugins, artifacts, sessions, graph/workspace surfaces, and observability.
- Workflow commands delegate to `WorkflowManager` in [kernel/workflows/commands.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/workflows/commands.rs).
- Graph execution is a separate local API path through [orchestrator/graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs) and [execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs).

Weaknesses and risks:
- Several Tauri commands can mutate local runtime/product state outside the `desktop_agent` service invariant: workflows, connectors, plugin trust, artifact save/restore, graph execution, task cancel/dismiss/update, and local engine operation promotion.
- Workflow remote trigger command checks workflow trigger type but does not show a signature/idempotency boundary in the traced command path.
- API errors are mostly string errors (`Result<_, String>`) on Tauri boundaries, not typed machine-readable error classes with retry/authority/projection semantics.
- `delete_session@v1` accepts raw params and deletes state; no versioned typed params/tombstone were observed.
- Marketplace-grade reusable services need a compatibility/version story for tool schemas, capability leases, policy records, and receipt manifests beyond ad hoc Tauri commands.

Why it matters:
- If external or UI-facing APIs can bypass settlement, the runtime boundary is porous. Service boundaries should make the safe path easier than the unsafe path.

Recommended change:
- Create a `RuntimeKernelService` facade for all consequential commands; Tauri commands should call it rather than direct drivers/managers.
- Add typed API errors with `error_class`, `authority_state`, `retryable`, and `settlement_ref`.
- Require idempotency keys for workflow remote triggers, connector actions, plugin installs, artifact promotion, and graph runs.
- Version public tool/action schemas and receipt manifests for marketplace compatibility.

Risk level: High  
Effort level: L  
Suggested validation: boundary tests invoking Tauri command handlers for graph/workflow/connector/plugin operations; assert either canonical settlement or explicit non-consequential classification plus idempotency behavior.

### P. Performance and scalability

Status: COMPLETE

What exists today:
- Artifact swarm uses bounded `JoinSet` concurrency and dispatch parallelism caps.
- Graph execution uses `maxSteps` and total `timeoutMs` policy settings.
- Workflow manager uses per-workflow async mutex run locks to prevent concurrent execution of the same workflow.
- Browser and inference HTTP adapters have timeout defaults/env overrides.
- Trace bundles can optionally exclude artifact payloads.
- Command output/diff thresholding spills large outputs to artifacts in [events/emission.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/events/emission.rs).

Weaknesses and risks:
- Some runtime work remains serialized where independent scopes could run in parallel, especially graph nodes with independent parents and main `desktop_agent` queue work.
- Graph timeout is checked between nodes, not around each node, so long-running nodes can exceed declared wall-clock budgets.
- Model calls and MCP tool calls can still dominate runtime latency without per-call cancellation receipts.
- Multiple in-memory mirrors (`AppState`, TS store, event/artifact indexes, memory snapshots) can grow without clear retention/backpressure policy beyond trace/export options.
- Trace bundle export loads events/artifacts and optionally artifact bytes into a zip; large sessions may be memory-heavy.
- Run-level budgets do not appear unified across steps, tokens, wall-clock, tool timeouts, artifact render time, and verification passes.

Why it matters:
- Product-ready long-running agents need predictable resource envelopes. Timeouts and budgets must be enforceable, not just advisory.

Recommended change:
- Add `RunBudget` to canonical session/plan state with wall-clock, step, tool, model-token, artifact-render, and verification budgets.
- Enforce node/tool/model deadlines with cancellation and timeout receipts.
- Stream trace bundle export and cap included payload sizes with a manifest of omitted artifacts.
- Add queue/backpressure policy for events, artifacts, workflow runs, and live previews.

Risk level: Medium  
Effort level: L  
Suggested validation: load tests with large event streams/artifacts, graph independent-node scheduling simulation, hung node/tool timeout tests, and budget-exhaustion tests.

### Q. Documentation and developer ergonomics

Status: COMPLETE

What exists today:
- Strong north-star docs exist: [docs/specs/verifiable_bounded_agency.md](/home/heathledger/Documents/ioi/repos/ioi/docs/specs/verifiable_bounded_agency.md), [docs/specs/wallet_network.md](/home/heathledger/Documents/ioi/repos/ioi/docs/specs/wallet_network.md), [docs/specs/CHAT_CONTRACT_V1.md](/home/heathledger/Documents/ioi/repos/ioi/docs/specs/CHAT_CONTRACT_V1.md), [docs/security/pii_review_contract.md](/home/heathledger/Documents/ioi/repos/ioi/docs/security/pii_review_contract.md), and [docs/specs/formal/canonical-state-and-projection-system-whitepaper.md](/home/heathledger/Documents/ioi/repos/ioi/docs/specs/formal/canonical-state-and-projection-system-whitepaper.md).
- Runtime and policy README files exist at [crates/services/src/agentic/runtime/README.md](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/README.md) and [crates/services/src/agentic/policy/README.md](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/README.md).
- The runtime README documents major seams, state model, validation commands, and maintainability guardrails.
- MCP, terminal, browser, OS, GUI, drivers, plugins, storage, and validator README files exist across the repo.

Weaknesses and risks:
- There is no single current architecture doc that reconciles the implemented `desktop_agent` settlement path with graph execution, workflows, chat artifacts, connectors, plugin trust, and trace bundle exports.
- Policy README describes user popup approval but not the current fail-closed desktop behavior requiring externally issued `ApprovalGrant`.
- No dedicated receipt model guide explains `SettlementReceiptBundle`, child receipt keys, non-authoritative events, trace-bundle limitations, and target-specific evidence requirements.
- No threat model doc for Agent Studio graph execution, workflow remote triggers, connector commands, plugins, dev MCP, and browser sandbox profiles was found.
- Developer guidance does not yet provide a tool-authoring checklist that forces capability lease, policy target, timeout, precondition, postcondition, receipt manifest, and tests.

Why it matters:
- Documentation is an enforcement aid in a fast-moving runtime. Without a current invariant map, new features are likely to pick the easiest API surface and bypass settlement unintentionally.

Recommended change:
- Write `docs/runtime/agentic-runtime-architecture.md` that names authoritative vs projection layers and every consequential execution path.
- Write `docs/runtime/receipt-model.md`, `docs/runtime/tool-authoring.md`, `docs/runtime/graph-workflow-governance.md`, and `docs/security/agentic-runtime-threat-model.md`.
- Update policy README to match external approval-grant reality.
- Add checklist links to PR templates or `AGENTS.md` once an agent-runtime contribution policy exists.

Risk level: Medium  
Effort level: M  
Suggested validation: documentation review checklist plus tests that enforce docs-linked examples compile or match schema fixtures.

## 6. Cross-cutting invariants

Status: COMPLETE

| Invariant | Current Enforcement Status | Where Enforcement Should Live | Tests That Should Prove It | Files Likely Affected |
|---|---|---|---|---|
| No consequential action without policy decision. | Partially enforced for `desktop_agent`; not enforced uniformly for graph/workflow/Tauri command surfaces. | Shared `RuntimeKernelService` facade before every browser/tool/code/connector/workflow/plugin side effect. | Graph/workflow/connector/plugin boundary tests that assert persisted policy decisions or denial. | [RuntimeAgentService](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/mod.rs), [execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs), [workflows](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/workflows), connector/plugin command modules. |
| No approval-gated action without external approval authority. | Partially enforced; desktop gates fail closed, but graph `GovernanceTier::Silent` auto-approves and approval scope is not enforced. | Approval validation in `resume@v1` plus graph/workflow governance facade. | Out-of-scope authority grant, graph silent approval, expired/revoked/replayed grant tests. | [approvals.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/actions/resume/approvals.rs), [governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution/governance.rs), [action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs). |
| No action settlement without required receipt bundle. | Partially enforced after `ToolExecutor` returns in `desktop_agent`; graph/workflow/chat envelopes are separate. | `persist_terminal_settlement` plus a common settlement-root builder for graph/workflow/artifact promotion. | Replay test reconstructing receipt bundle from state; graph/workflow side-effect settlement tests. | [receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs), [action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs), [execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/execution.rs). |
| No UI state treated as authoritative. | Design intent exists; projections/events are still sometimes named/displayed as canonical. | Projection reconciler and UI evidence-tier model. | Event-only receipt export test, stale gate response test, projection replay test. | [state.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/state.rs), [events/emission.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/events/emission.rs), [artifacts.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/artifacts.rs), TS session controller. |
| No tool call without scoped capability. | Partially enforced through policy, worker allowlists, leases, and MCP containment; no single required capability envelope. | `ToolInvocationEnvelope` consumed by all executors/drivers. | Matrix tests across built-in, MCP, dynamic, browser, shell, filesystem, graph, and connector tools. | [action_execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs), [ToolExecutor](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/mod.rs), [mcp](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/mcp). |
| No retry/repair without its own receipt and authority. | Partially enforced in action retry evidence and artifact swarm repair receipts; not unified. | Retry/recovery scheduler that emits `RepairAttemptReceipt` before queued repair action execution. | Deterministic repair retry tests and no-unchanged-retry tests. | [finalize_action_processing.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/phases/finalize_action_processing.rs), [swarm_bundle_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle_finalize.rs). |
| No artifact promotion without validation evidence. | Partially enforced in chat generation; promotion not tied to settlement bundle and swarm lacks winner provenance. | `ArtifactPromotionReceipt` in materialization/promotion path. | Artifact promotion tests for missing render eval, failed validation, swarm/non-swarm provenance parity. | [materialization.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/chat/materialization.rs), [non_swarm_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/non_swarm_finalize.rs), [swarm_bundle_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle_finalize.rs). |
| No model output directly mutates canonical state. | Mostly enforced in `desktop_agent` by tool proposal processing; graph/model/artifact paths need explicit declaration. | Structured proposal parser/validator before state mutation in all runtimes. | Malformed JSON/tool-call/model-output tests asserting no state mutation. | [process_tool_output](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/mod.rs), [http_adapter.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/vm/inference/http_adapter.rs), graph runners. |
| No event stream is authoritative over persisted settlement state. | Partially enforced by non-authoritative event receipt flag, but trace bundles still derive receipts from events. | Trace/export builder that loads settlement records and labels projection events separately. | Trace bundle test with event receipt but missing settlement state. | [artifacts.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/artifacts.rs), [events/emission.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/events/emission.rs). |
| No external side effect without precondition and postcondition evidence. | Partially enforced through generic execution observations; target-specific evidence is weak. | Target-specific `RequiredReceiptManifest` builder and executor postcondition adapters. | Browser/file/network/clipboard/shell/MCP receipt manifest tests. | [receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs), browser/screen/fs/system/MCP executors. |
| No long-running operation without enforceable deadline/cancellation. | Partially enforced for browser, inference HTTP, and terminal; weak for graph nodes, MCP calls, and generic tools. | `RunBudget`/deadline envelope propagated to tool/model/MCP/graph/workflow calls. | Hung graph node, hung MCP, hung non-browser tool, stalled stream tests. | [timeout.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/timeout.rs), [graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs), [transport.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/mcp/transport.rs). |
| No production profile with dev/unconfined runtime capabilities enabled. | Partially enforced for MCP production mode; browser no-sandbox and dev MCP are not globally profile-gated. | Startup profile validator and runtime environment receipt. | Production startup tests with `NO_SANDBOX`, `IOI_CHAT_MCP_PROFILE=dev_filesystem`, unverified MCP, and unconfined plugin modes. | [lib.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/lib.rs), [execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs), [driver_core.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser/driver_core.rs), plugin runtime manager. |

## 7. Critical findings so far

Status: COMPLETE

| ID | Risk | Finding | Evidence | Why It Matters | Validation |
|---|---|---|---|---|---|
| CF-1 | High | Policy decision records omit matched rule provenance. | `PolicyDecisionRecord::build(..., Vec::new(), ...)` in [firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs); `matched_rules` field in [action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs). | Third-party reconstruction can verify the policy hash and verdict, but not which rule produced the decision. This weakens “why did this execute/block?” receipts. | Add policy-engine fixture with two rules; assert persisted `PolicyDecisionRecord.matched_rules == ["rule-id"]`. |
| CF-2 | High | Approval authority scope allowlists are not enforced when validating grants. | `ApprovalAuthority.scope_allowlist` in [action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs); `validate_registered_approval_grant` in [approvals.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/actions/resume/approvals.rs) verifies signature/expiry/policy hash but not target/scope allowlist. | A registered authority intended for narrow scopes can issue a grant for any exact request/policy hash if it can sign the grant. Request hash binding is strong, but registry scope is not. | Unit test registering an authority with a narrow scope and a grant for an out-of-scope `ActionTarget`; expect validation failure. |
| CF-3 | Critical | Agent Studio graph execution uses a separate governance path without canonical committed-action, policy-decision, or settlement receipt persistence. | [graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs) calls `execution::execute_ephemeral_node`; [execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs) dispatches nodes directly; [execution/governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution/governance.rs) maps node policy and can auto-approve in `GovernanceTier::Silent`. | If graph nodes can perform browser, tool, code, media, or network side effects, they bypass the `desktop_agent` settlement invariant. | Integration test running a strict graph browser/tool/code node must assert persisted `PolicyDecisionRecord`, `CommittedAction`, and `SettlementReceiptBundle` or that execution is denied before side effect. |
| CF-4 | High | Non-browser/non-WebResearch tool execution lacks a visible global runtime timeout at the service layer. | `execute_tool_with_optional_timeout` in [timeout.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/timeout.rs) applies timeouts only to WebResearch scope or browser tools; `handle_action_execution` only wraps browser tools. | Long-running shell/system/MCP/model tools can stall a step unless every lower-level executor enforces its own timeout. This weakens resumability and operator trust. | Failure-injection test with a hanging non-browser tool; assert step returns bounded `ERROR_CLASS=TimeoutOrHang` and persists failed settlement. |
| CF-5 | Medium | Desktop gate response is fail-closed for policy gates but mutates local gate mirror before returning the error. | `gate_respond` in [governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/governance.rs) writes `s.gate_response = Some(...)`, then returns `"Desktop UI cannot mint approval authority locally..."`. | This is good from an authority perspective, but stale UI mirrors could mislead operators unless reconciled immediately from committed runtime state. | UI/state test: invoke `gate_respond(approved=true)` without external grant; assert task remains `Gate`/paused with pending hash and no approved visual state. |
| CF-6 | Medium | Swarm artifact finalization omits candidate/winner provenance present in non-swarm artifacts. | [non_swarm_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/non_swarm_finalize.rs) fills `candidate_summaries` and `winning_candidate_id`; [swarm_bundle_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle_finalize.rs) returns `candidate_summaries: Vec::new()` and `winning_candidate_id: None`. | Artifact provenance and UX differ by execution strategy, making replay/explanation weaker for swarm-generated artifacts. | Fixture for swarm HTML artifact should assert candidate or canonical merge provenance is represented in the materialization contract. |
| CF-7 | High | Graph run timeout is not an execution timeout for individual nodes. | `run_local_graph` checks `timeoutMs` before starting each node in [graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs), then awaits `execution::execute_ephemeral_node(...)` without wrapping it in `tokio::time::timeout`. | A browser/code/model/tool node can exceed declared graph budget and block the graph despite timeout policy. | Graph test with a `wait` or hanging tool node; assert node is cancelled/marked timed out within `timeoutMs` and emits a timeout receipt/event. |
| CF-8 | High | Trace bundle export is called canonical but its receipts are projection events, not persisted settlement receipts. | `load_canonical_trace_bundle_source` in [kernel/artifacts.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/artifacts.rs) derives `receipts` from `events.iter().filter(|event| event.event_type == EventType::Receipt)`. | Operators may treat exported “canonical” trace bundles as verifier-grade evidence even when `CommittedAction`, `PolicyDecisionRecord`, and `SettlementReceiptBundle` state were not loaded. | Trace export test for a settled action; assert bundle includes persisted settlement records or is explicitly labeled projection-only. |
| CF-9 | Critical | Agent Studio graph governance uses a simulation safety model with no PII detection. | `SimulationSafetyModel` in [execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs) returns safe intent and empty PII inspection for graph governance. | Graph nodes can evaluate policy without the same PII/safety controls as `desktop_agent`, compounding the settlement bypass. | Graph PII/browser/tool fixture should block or require approval under the same PII policy used by `desktop_agent`. |
| CF-10 | High | MCP tool calls have no transport-level request timeout. | `McpTransport::initialize` wraps initialization in 60s timeout, but `list_tools` and `call_tool` call `send_request` directly in [transport.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/mcp/transport.rs). | A wedged MCP server can block dynamic tool discovery or execution unless higher layers always wrap it; this overlaps with the broader non-browser timeout gap. | MCP fixture that accepts a request and never responds; assert bounded timeout and failed tool receipt. |
| CF-11 | High | Consequential Tauri command surfaces are not consistently routed through the bounded `desktop_agent` service. | [lib.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/lib.rs) registers workflows, connectors, plugin trust, artifacts, graph/workspace, local engine promotion, and task mutation commands directly; `RuntimeAgentService::handle_service_call` covers only `desktop_agent` methods. | Product/runtime actions can mutate state or cause side effects without the same policy decision, approval authority, receipt bundle, idempotency, and replay path. | Boundary integration tests invoking graph/workflow/connector/plugin commands; assert canonical settlement or explicit non-consequential classification. |

## 8. Critical gaps

Status: COMPLETE

1. Critical: Agent Studio graph execution can run browser/code/tool/media nodes outside the canonical `desktop_agent` settlement path. This includes a simulation safety model and `GovernanceTier::Silent` auto-approval. Files: [execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs), [execution/governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution/governance.rs), [graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs).
2. Critical: Approval and policy receipts are not verifier-complete. Approval authority scope is not enforced, and `PolicyDecisionRecord.matched_rules` is empty. Files: [approvals.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/actions/resume/approvals.rs), [firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs), [action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs).
3. High: Trace bundles and UI evidence can look canonical while being assembled from projection events. `load_canonical_trace_bundle_source` gathers receipt events, not persisted settlement bundles. File: [kernel/artifacts.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/artifacts.rs).
4. High: Timeout/cancellation guarantees are uneven. Browser/inference/terminal paths have timeouts, but graph nodes, MCP `call_tool`, and generic non-browser tools lack a uniform runtime deadline and cancellation receipt. Files: [timeout.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/timeout.rs), [transport.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/mcp/transport.rs), [graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs).
5. High: Capability enforcement is split across policy, worker allowlists, leases, MCP containment, and executor prechecks, without a single required invocation envelope consumed by all drivers.
6. High: Receipts are generic for high-risk target categories. Browser, screen, filesystem, network, MCP, clipboard, commerce, and connector actions need target-specific precondition/postcondition evidence.
7. High: Consequential Tauri command surfaces are not consistently routed through bounded settlement. Workflows, connectors, plugins, artifact mutation, local engine promotion, and graph execution need explicit classification or settlement.
8. Medium: Artifact promotion is not tied to a canonical promotion receipt, and swarm artifact finalization lacks winner/candidate provenance.
9. Medium: Inference runtime has good adapter tests but lacks explicit cancellation, retry taxonomy, budget/latency receipts, and universal structured output enforcement.
10. Medium: Documentation has strong north-star specs, but no single current map of authoritative vs projection layers across desktop-agent, graph, workflow, chat artifacts, connectors, plugins, and trace bundles.

## 9. Prioritized roadmap

Status: COMPLETE

### 9.1 Critical fixes

| Title | Summary | Files likely affected | Risk | Effort | Dependencies | Suggested sequence | Validation |
|---|---|---|---|---|---|---|---|
| Route graph side effects through settlement | Make graph browser/code/tool/media nodes use the same policy, approval, committed action, and settlement receipt path as `desktop_agent`, or block them as simulation-only. | [execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs), [execution/governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution/governance.rs), [RuntimeAgentService](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/mod.rs) | Critical | L | Tool invocation envelope, graph node action mapping | Add graph action envelope; replace simulation safety model; persist settlement refs; update UI labels. | Graph browser/code/tool tests asserting settlement or fail-closed denial. |
| Enforce approval authority scope | Validate `ApprovalAuthority.scope_allowlist` against canonical action target/tool/workload before accepting a grant. | [approvals.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/actions/resume/approvals.rs), [wallet_network/validation.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/wallet_network/validation.rs), [action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs) | Critical | M | Canonical target labels | Add scope matcher; apply to both validation paths; add revoked/expired/scope matrix. | Out-of-scope grant fixture must fail. |
| Persist matched policy rules | Store matched rule ids/default-policy reason/PII decision hash in every `PolicyDecisionRecord`. | [engine.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/engine.rs), [firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs), [rules.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/rules.rs) | High | M | Policy evaluation record type | Return `PolicyEvaluationRecord`; persist it; update receipt verification. | Two-rule policy fixture asserts correct matched ids. |
| Fix canonical trace bundle authority | Stop calling event-only exports canonical, or load persisted settlement records into trace bundles. | [kernel/artifacts.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/artifacts.rs), [events/emission.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/events/emission.rs), TS export UI | High | M | Settlement state query helpers | Add settlement loader; separate `projection_receipts` and `settlement_receipts`; update copy. | Export fixture with settled action and event-only receipt. |
| Uniform runtime deadlines | Propagate deadlines/cancellation to graph nodes, MCP calls, generic tools, and model calls; emit timeout receipts. | [timeout.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/timeout.rs), [transport.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/mcp/transport.rs), [graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs), [http_adapter.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/vm/inference/http_adapter.rs) | High | L | RunBudget/deadline envelope | Add envelope deadlines; wrap graph/MCP/tool futures; persist timeout observation. | Hung MCP, hung graph node, hung tool tests. |

### 9.2 High-leverage architecture upgrades

| Title | Summary | Files likely affected | Risk | Effort | Dependencies | Suggested sequence | Validation |
|---|---|---|---|---|---|---|---|
| ToolInvocationEnvelope | Create a canonical envelope containing request hash, capability lease, policy decision, deadline, target-specific manifest, and postcondition requirements; require it at every executor/driver boundary. | [action_execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs), [execution/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/mod.rs), driver adapters | High | L | Policy evaluation record | Introduce type; wire built-ins; then MCP/dynamic/graph; make raw driver calls reject missing envelope. | Tool matrix authorization tests. |
| Target-specific receipt manifests | Replace generic receipt requirements with target-specific evidence contracts for browser, screen, fs, sys, net, model, MCP, connector, clipboard, and commerce actions. | [receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs), [action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs), executors | High | XL | ToolInvocationEnvelope | Define manifest enum; adapt executor outputs; add replay fixtures. | Golden receipt fixtures per target. |
| SettlementTraceBundle | Add replayable trace bundle rooted in settlement bundles, with projection events as secondary evidence. | [kernel/artifacts.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/artifacts.rs), [action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs), trace UI | High | M | Settlement state query helpers | Build loader; expose Tauri command; update export/compare. | Reconstruct settlement from exported zip. |
| RunBudget and cancellation registry | Unify step, wall-clock, model-token, tool, render, and verification budgets. | [types.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/types.rs), [step/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/mod.rs), graph/workflow/inference code | Medium | L | Deadline envelope | Add budget type; decrement on every action/model/render; persist budget exhaustion. | Budget-exhaustion simulations. |
| ScopeLeaseRegistry | Add deterministic scope locks for concurrent workers and graph/workflow nodes. | [swarm_bundle.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle.rs), worker lifecycle paths, graph runner | High | L | Canonical scope labels | Implement read/write leases; reject or serialize overlaps. | Overlapping write-region property tests. |

### 9.3 Product/UX upgrades

| Title | Summary | Files likely affected | Risk | Effort | Dependencies | Suggested sequence | Validation |
|---|---|---|---|---|---|---|---|
| Evidence tier labels | Show whether an item is projection-only, event receipt, settlement receipt, external approval, or artifact promotion evidence. | Chat artifact/evidence components, [runtimeInspection.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/runtimeInspection.ts), trace export UI | Medium | M | Trace bundle authority fix | Add model fields; update copy; add missing-settlement state. | TS snapshot/model tests for labels. |
| External approval grant UX | Replace local approve affordance for policy gates with wallet/network grant instructions and request hash/policy hash/scope/deadline display. | [ChatApprovalCard.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ChatApprovalCard.tsx), [governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/governance.rs), `shield-approval.ts` | High | M | Approval scope enforcement | Update backend response model; update UI copy; add import/submit grant flow. | Gate UI test without external grant. |
| Operator intervention queue | Unify policy gates, sudo/password gates, workflow failures, graph blocks, connector step-ups, and plugin trust decisions. | Notifications, governance, workflow, connector, plugin UI | Medium | L | Canonical pending-state queries | Define intervention model; populate from canonical state; render queue. | Manual UX plus store tests. |
| Artifact provenance parity | Show swarm merge/winner lineage with same clarity as non-swarm candidates. | [swarm_bundle_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle_finalize.rs), artifact hub components | Medium | M | Artifact promotion receipt | Fill winner/provenance fields; update copy. | Swarm artifact model tests. |

### 9.4 Testing upgrades

| Title | Summary | Files likely affected | Risk | Effort | Dependencies | Suggested sequence | Validation |
|---|---|---|---|---|---|---|---|
| Bounded-runtime invariant suite | Focused tests for the highest-risk invariants: policy, approval scope, settlement receipts, graph bypass, trace authority, deadlines. | `crates/services/tests`, graph tests, artifact tests, TS tests | High | M | None | Start with CF-1 through CF-11 fixtures; add to CI/light gate. | `./scripts/check-agent-runtime.sh` plus new invariant suite. |
| Golden receipt fixtures | Canonical JSON/hash fixtures for action request, policy decision, committed action, postcondition, settlement bundle, trace export. | `crates/types`, `crates/services` tests | High | M | Receipt manifest changes | Build fixture helper; assert cross-platform stable hashes. | `cargo test -p ioi-types receipt_golden`. |
| Failure-injection harness | Hung MCP, hung graph node, stale UI projection, lost event, partial settlement, overlapping swarm writes. | Drivers, graph, session controller, runtime service tests | High | L | Deadline and lease registry | Add fake drivers/providers; wire tests. | Deterministic simulations. |
| Artifact render/sandbox fixtures | Validate HTML iframe sandbox/CSP and render regression obligations. | Chat render driver, artifact UI, materialization tests | Medium | M | Promotion receipt | Add minimal malicious HTML fixtures and expected blocks. | Browser/render tests. |

### 9.5 Nice-to-have refactors

| Title | Summary | Files likely affected | Risk | Effort | Dependencies | Suggested sequence | Validation |
|---|---|---|---|---|---|---|---|
| Typed pause status migration | Replace `AgentStatus::Paused(String)` reliance with typed persisted pause state. | [types.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/types.rs), lifecycle/step handlers, UI mappers | Medium | M | Migration plan | Add typed field first; migrate UI; deprecate string parsing. | Pause/resume lifecycle tests. |
| Lifecycle tombstones | Persist terminal/cancel/delete records instead of pure deletion. | [session_delete.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/lifecycle/handlers/session_delete.rs), state/projection | Medium | S | None | Add tombstone type; adjust delete flow. | Delete/tombstone tests. |
| Typed Tauri error model | Replace many `Result<_, String>` command errors with stable error classes. | Tauri command modules, TS runtime bridge | Medium | L | Error schema | Introduce `RuntimeCommandError`; migrate high-risk commands first. | TS/Rust boundary tests. |
| Runtime architecture docs | Consolidate authoritative/projection surfaces and contribution checklists. | `docs/runtime/*`, READMEs | Medium | M | Audit acceptance | Draft docs from this audit; link runtime README. | Doc review checklist. |

## 10. Patch candidates

Status: COMPLETE

### PC-1: Graph settlement boundary

- Proposed branch name: `audit/graph-settlement-boundary`
- Commit title: `Route graph side effects through runtime settlement`
- Exact problem: `execute_ephemeral_node` can run browser/code/tool/media nodes through graph governance without canonical `CommittedAction`, `PolicyDecisionRecord`, or `SettlementReceiptBundle`.
- Minimal implementation plan: add a graph action envelope mapper; for consequential node types call the bounded runtime execution facade or return blocked in strict/product profiles; remove `GovernanceTier::Silent` auto-approval for consequential nodes.
- Acceptance criteria: graph browser/code/tool nodes either persist settlement records or fail before side effects; simulation-only nodes are explicitly labeled non-consequential.
- Tests to add/update: graph runner tests for browser/tool/code nodes under silent/strict/none tiers; PII graph fixture; boundary integration test for settlement refs.
- Rollback risk: Medium. Product graph demos may need updated fixtures if they relied on silent execution.

### PC-2: Approval authority scope enforcement

- Proposed branch name: `audit/approval-scope-enforcement`
- Commit title: `Enforce approval authority scope allowlists`
- Exact problem: `ApprovalAuthority.scope_allowlist` is part of the authority model but is not checked by runtime grant validation.
- Minimal implementation plan: implement canonical scope matching for `ActionTarget`, tool/workload labels, and optional window/session scope; call it from runtime and wallet-network validation; include failure reason in policy/approval receipts.
- Acceptance criteria: an authority registered for a narrow scope cannot approve an out-of-scope exact request even with a valid signature.
- Tests to add/update: out-of-scope grant unit test, in-scope grant test, wildcard/specific target tests, revoked/expired grant regression.
- Rollback risk: Low. Existing broad authorities can use explicit wildcard scopes.

### PC-3: Policy decision provenance

- Proposed branch name: `audit/policy-matched-rules`
- Commit title: `Persist matched policy rule provenance`
- Exact problem: `PolicyDecisionRecord.matched_rules` is always empty in the action execution path.
- Minimal implementation plan: add `PolicyEvaluationRecord`; return matched rule ids/default policy decision/PII decision hash from `PolicyEngine`; pass the record to `PolicyDecisionRecord::build`.
- Acceptance criteria: persisted policy decisions explain which rule/default/PII overlay produced the verdict.
- Tests to add/update: allow/block/require-approval fixtures with multiple rules and PII overlay; receipt hash stability update.
- Rollback risk: Low to Medium if receipt schema/hash fixtures need migration.

### PC-4: Settlement trace bundle

- Proposed branch name: `audit/settlement-trace-bundle`
- Commit title: `Separate projection traces from settlement trace bundles`
- Exact problem: `get_trace_bundle`/export code calls bundles canonical while loading receipt events from memory projections.
- Minimal implementation plan: rename current receipt list to `projection_receipts`; add settlement receipt loader by session/request hashes where available; expose `settlement_receipts` and `missing_settlement_refs`; update export UI copy.
- Acceptance criteria: exported bundle cannot imply settlement authority unless persisted settlement records are included.
- Tests to add/update: trace bundle fixture for event-only receipt, settled action, missing settlement, and export manifest.
- Rollback risk: Medium. UI and external consumers may need field-name compatibility aliases.

### PC-5: Unified deadlines for graph/MCP/generic tools

- Proposed branch name: `audit/runtime-deadlines`
- Commit title: `Apply bounded deadlines to graph, MCP, and generic tool calls`
- Exact problem: graph nodes, MCP `call_tool`, and generic tool calls do not all have enforceable runtime-level timeouts.
- Minimal implementation plan: add `ExecutionDeadline` helper; wrap graph node awaits and MCP `list_tools`/`call_tool`; pass deadline through `ToolInvocationEnvelope` or interim execution params; persist timeout observation.
- Acceptance criteria: hung graph/MCP/non-browser tool returns bounded timeout and does not leave session running indefinitely.
- Tests to add/update: hung MCP fake server, graph wait node timeout, hanging dynamic tool fixture.
- Rollback risk: Medium. Some slow local workflows may need explicit timeout policy.

### PC-6: Target-specific receipt manifests

- Proposed branch name: `audit/target-receipt-manifests`
- Commit title: `Add target-specific evidence manifests`
- Exact problem: `RequiredReceiptManifest` currently requires generic terminal outcome receipts for all targets.
- Minimal implementation plan: create manifest builder keyed by `ActionTarget`; add browser before/after, fs hash diff, shell command/exit, network URL/status, MCP server receipt, and clipboard/window bindings as initial target classes.
- Acceptance criteria: high-risk actions fail settlement if required target-specific observations are missing.
- Tests to add/update: golden fixtures for browser, fs write, shell, MCP, net fetch; replay reconstruction test.
- Rollback risk: High. Executor outputs may need staged adoption behind strict-mode flag.

### PC-7: Artifact promotion receipt

- Proposed branch name: `audit/artifact-promotion-receipts`
- Commit title: `Require artifact promotion receipts`
- Exact problem: artifact promotion is validated by chat-generation contracts but not tied to canonical settlement/promotion evidence; swarm lacks winner provenance.
- Minimal implementation plan: add `ArtifactPromotionReceipt`; populate from non-swarm and swarm finalizers; include validation/render-eval/execution-envelope hashes; fill swarm winner/provenance fields.
- Acceptance criteria: promoted artifacts have validation evidence and strategy-independent provenance.
- Tests to add/update: non-swarm and swarm promotion fixtures; missing render eval status; failed validation blocked promotion.
- Rollback risk: Medium. Existing artifact records may need migration/default evidence status.

### PC-8: Production profile guardrails

- Proposed branch name: `audit/production-profile-guardrails`
- Commit title: `Fail closed on dev/unconfined runtime capabilities in production`
- Exact problem: dev MCP and browser no-sandbox modes are controlled by env/profile flags but are not globally recorded or blocked by production startup policy.
- Minimal implementation plan: add runtime profile validator at app bootstrap; fail or warn with explicit environment receipt for `NO_SANDBOX`, `IOI_CHAT_MCP_PROFILE=dev_filesystem`, unverified/unconfined MCP, and unconfined plugin modes.
- Acceptance criteria: production profile refuses unsafe dev capabilities before runtime starts; dev profile records warning evidence.
- Tests to add/update: startup profile tests with env matrix; MCP dev profile test; no-sandbox warning/receipt test.
- Rollback risk: Low to Medium. CI/root launch paths need explicit dev/test profile.

## 11. Test plan

Status: COMPLETE

Baseline commands already documented by the runtime:
- `./scripts/check-agent-runtime.sh`
- `cargo test -p ioi-services --lib`
- `cargo test -p ioi-services --test envelope_integration`
- `cargo test -p ioi-services --test pii_hard_gates`
- `cargo test -p ioi-api`
- `cargo test -p ioi-cli --test agent_trace_e2e --test agent_swarm_e2e --test agent_resilience_e2e`
- `npm run typecheck`
- `npm run build:ide`

New invariant tests to add:
- Policy provenance: matched rule ids, default-policy fallback, PII overlay hash, and stable receipt hashes.
- Approval authority: out-of-scope grant, expired grant, revoked authority, replay/counter, wrong policy hash, wrong request hash.
- Graph boundary: browser/tool/code/media node side effects require settlement or fail closed; `GovernanceTier::Silent` cannot auto-approve consequential actions.
- Trace authority: event-only receipt export is labeled projection; settled action export includes committed action, policy decision, observation, postcondition, and settlement bundle.
- Deadline/cancellation: hung MCP server, hung graph node, hanging generic tool, stalled stream, and cancelled inference request.
- Receipt manifests: browser before/after, file hash diff, shell command/exit, network URL/status, MCP server identity, clipboard/window binding.
- Artifact promotion: missing validation blocks promotion; swarm/non-swarm provenance parity; render-eval skipped/unavailable labels.
- Projection reconciliation: optimistic start/continue/gate states rehydrate from canonical state after failure or timeout.
- Security profiles: production profile rejects dev MCP, no-sandbox browser, unverified unconfined plugins/connectors.
- Swarm concurrency: overlapping write scopes fail or serialize; lost worker result and conflicting patch produce receipts; repair/replan has separate authority.

Recommended test organization:
- `crates/services/tests/bounded_runtime_invariants.rs` for policy/approval/receipt/deadline invariants.
- `apps/autopilot/src-tauri/src/orchestrator/graph_runner/tests.rs` additions for graph governance/deadlines.
- `crates/drivers/src/mcp/tests.rs` additions for hung tool calls and containment.
- `apps/autopilot/src-tauri/src/kernel/artifacts/tests.rs` additions for trace authority and settlement export.
- `crates/api/src/chat/tests` or existing generation tests for artifact promotion/provenance.
- `packages/agent-ide/src/runtime/session-controller.test.ts` and ChatShell model tests for projection/evidence labels.

## 12. Open questions

Status: COMPLETE — NEEDS VERIFICATION

- RESOLVED FOR AUDIT SCOPE: The primary product surface is the Tauri Autopilot app described in [apps/autopilot/README.md](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/README.md), while `crates/cli` and `packages/agent-ide` are important alternate entrypoints/projections that can exercise or display the same runtime concepts.
- UNCERTAIN: Which deployment profile is authoritative for marketplace-grade services: local-first desktop only, node/service mode, or a combined desktop-plus-network validator mode. Need deeper evidence from `crates/node`, `crates/networking`, and docs.
- UNCERTAIN: Whether any production path already wraps graph/workflow/connector side effects with an external service not visible in the traced files. The local Tauri code does not show that guarantee.
- UNCERTAIN: Whether browser lease release is handled outside the traced snippets. A scoped request-hash lease would make this auditable.

## 13. Appendix: file/function index

Status: COMPLETE

- [apps/autopilot/src-tauri/src/lib.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/lib.rs): Tauri bootstrap, app state, command registration, inference runtime creation.
- [apps/autopilot/src/services/TauriRuntime.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/TauriRuntime.ts): TS invoke/event bridge for runtime operations.
- [packages/agent-ide/src/runtime/session-runtime.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-runtime.ts): `AssistantSessionRuntime` abstraction.
- [packages/agent-ide/src/runtime/session-controller.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-controller.ts): Zustand/session projection controller.
- [packages/agent-ide/src/runtime/shield-approval.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/shield-approval.ts): TS Shield approval parsing/projection helper.
- [crates/cli/src/commands/agent.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/cli/src/commands/agent.rs): CLI start/step loop for `desktop_agent`.
- [crates/services/src/agentic/runtime/service/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/mod.rs): `RuntimeAgentService` service method dispatch.
- [crates/services/src/agentic/runtime/service/step/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/mod.rs): Main agent step loop.
- [crates/services/src/agentic/runtime/service/step/action/processing/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/step/action/processing/mod.rs): Model tool-output processing and action phases.
- [crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs): Tool execution, policy gate call, settlement persistence.
- [crates/services/src/agentic/runtime/service/handler/execution/execution/determinism.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/determinism.rs): Deterministic action request/workload construction.
- [crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs): Policy/lease/approval enforcement and firewall receipt recording.
- [crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs): Action/policy/settlement/evidence persistence helpers.
- [crates/services/src/agentic/runtime/execution/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/mod.rs): `ToolExecutor` and workload receipt emission.
- [crates/services/src/agentic/policy/engine.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/engine.rs): Policy engine.
- [crates/services/src/agentic/rules.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/rules.rs): Rule/default-policy schema.
- [crates/services/src/wallet_network/handlers/approval.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/wallet_network/handlers/approval.rs): Approval authority/grant state handlers.
- [crates/services/src/wallet_network/validation.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/wallet_network/validation.rs): Approval/receipt/channel validation.
- [crates/types/src/app/action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs): Canonical action request and receipt structs/state keys.
- [crates/api/src/vm/inference/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/vm/inference/mod.rs): `InferenceRuntime` and safety model traits.
- [crates/api/src/vm/inference/http_adapter.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/vm/inference/http_adapter.rs): HTTP/OpenAI/Anthropic/Ollama inference adapter.
- [crates/drivers/src/browser/driver_core.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser/driver_core.rs): Browser process/lease/timeout/pinned Chromium driver.
- [crates/services/src/agentic/runtime/execution/browser/handler.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/browser/handler.rs): Browser action execution.
- [crates/services/src/agentic/runtime/execution/screen/dispatch.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/execution/screen/dispatch.rs): Screen/computer-use dispatch.
- [crates/drivers/src/gui/operator.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/gui/operator.rs): Native OS input/capture operator.
- [crates/api/src/chat/generation/runtime_plan.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/runtime_plan.rs): Chat artifact runtime plan.
- [crates/api/src/chat/generation/swarm_plan.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_plan.rs): Chat artifact swarm work-item plan.
- [crates/api/src/execution.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/execution.rs): Swarm/execution graph receipt types.
- [apps/autopilot/src-tauri/src/kernel/state.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/state.rs): App state and task projection persistence.
- [apps/autopilot/src-tauri/src/kernel/events/emission.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/events/emission.rs): Event/artifact registration and memory append.
- [crates/memory/src/lib.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/memory/src/lib.rs): SQLite memory runtime.
- [apps/autopilot/src-tauri/src/kernel/workflows](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/workflows): Workflow manager, commands, types.
- [apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs): Local graph execution.
- [apps/autopilot/src-tauri/src/execution.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution.rs): Agent Studio ephemeral node execution, MCP initialization, simulation safety model.
- [apps/autopilot/src-tauri/src/execution/governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/execution/governance.rs): Graph governance policy synthesis and `GovernanceTier` checks.
- [apps/autopilot/src-tauri/src/kernel/artifacts.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/artifacts.rs): Trace bundle loading/export/compare and artifact content commands.
- [apps/autopilot/src-tauri/src/kernel/governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/governance.rs): Gate response, fail-closed desktop approval path, runtime password submission.
- [apps/autopilot/src-tauri/src/kernel/workflows/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/workflows/mod.rs): Workflow run lock, trigger, run receipts, monitor execution.
- [apps/autopilot/src-tauri/src/kernel/workflows/commands.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/workflows/commands.rs): Tauri workflow command boundary.
- [crates/api/src/chat/generation/swarm_bundle.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle.rs): Chat artifact swarm dispatch, `JoinSet` workers, patch merge.
- [crates/api/src/chat/generation/swarm_bundle_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/swarm_bundle_finalize.rs): Swarm validation, repair, replan, execution envelope, missing winner provenance.
- [crates/api/src/chat/generation/non_swarm_finalize.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/non_swarm_finalize.rs): Non-swarm candidate/winner provenance.
- [crates/api/src/chat/render_eval.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/render_eval.rs): Render evaluation and acceptance obligations.
- [crates/drivers/src/mcp/transport.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/mcp/transport.rs): MCP stdio transport, initialization timeout, unbounded `send_request` use for tool calls.
- [crates/drivers/src/mcp/mod.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/mcp/mod.rs): MCP start policy, integrity, containment, allowed tools, runtime containment.
- [crates/drivers/src/terminal/README.md](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/terminal/README.md): Terminal driver security model and upstream-policy dependency.
- [crates/drivers/src/browser/README.md](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser/README.md): Browser driver security constraints and pending validator sandbox note.
- [crates/services/src/agentic/policy/conditions.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/conditions.rs): Command allowlist, denied shell binaries, domain/app/path conditions.
- [crates/services/src/agentic/policy/filesystem.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/filesystem.rs): Workspace filesystem policy augmentation and path-scope validation.
- [crates/services/src/agentic/policy/ratchet.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/ratchet.rs): Policy monotonicity checks.
- [apps/autopilot/src/services/runtimeInspection.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/runtimeInspection.ts): UI runtime evidence/verification copy model.
- [apps/autopilot/src/windows/ChatShellWindow/utils/traceBundleExportModel.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/utils/traceBundleExportModel.ts): Trace bundle export preset labels.
- [packages/agent-ide/src/features/Editor/Trace/TraceViewer.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/features/Editor/Trace/TraceViewer.tsx): Basic trace span viewer.
- [apps/autopilot/src/hooks/useRetainedWorkbenchTrace.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/hooks/useRetainedWorkbenchTrace.ts): Retained workbench trace loading from event/artifact projections.
- [scripts/check-agent-runtime.sh](/home/heathledger/Documents/ioi/repos/ioi/scripts/check-agent-runtime.sh): Runtime-focused validation script.
- [docs/specs/verifiable_bounded_agency.md](/home/heathledger/Documents/ioi/repos/ioi/docs/specs/verifiable_bounded_agency.md): North-star bounded agency thesis.
- [docs/security/pii_review_contract.md](/home/heathledger/Documents/ioi/repos/ioi/docs/security/pii_review_contract.md): Deterministic PII resume contract.
- [crates/services/src/agentic/runtime/README.md](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/README.md): Runtime service structure and validation commands.
- [crates/services/src/agentic/policy/README.md](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/policy/README.md): Agency Firewall concepts.
