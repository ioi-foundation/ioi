# Agent Workflow Compositor Primitive Taxonomy & UX Audit

Status: audit for next implementation leg
Created: 2026-05-14
Scope: `packages/agent-ide/src/runtime/workflow-node-registry.ts`,
`packages/agent-ide/src/types/graph.ts`,
`packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/`,
`packages/agent-ide/src/features/Workflows/WorkflowRailPanel/`, and
`packages/agent-ide/src/WorkflowComposer/`

## Sprint Doctrine

The workflow compositor should expose a small set of generic, composable
agent-runtime primitives that can be configured to build any worker, harness, or
outcome workflow. Specialized behavior should appear as typed configuration,
ports, policies, inspectors, emitted events, and receipts unless it represents a
distinct execution boundary.

Doctrine to preserve:

- no second runtime;
- no React Flow shadow truth store;
- daemon/runtime contracts first;
- every node maps to a runtime component, adapter, policy, event, receipt, or
  manifest;
- every config field compiles to a canonical runtime/workflow manifest;
- graph activation produces deterministic ids, receipts, and replayable state.

## Current Inventory

The compositor currently has two overlapping vocabularies:

- 49 base `WorkflowNodeDefinition` entries in `WORKFLOW_NODE_DEFINITIONS`;
- 76 creator presets returned by `workflowNodeCreatorDefinitions()`;
- 12 visible groups: Start, Sources, Transform, AI, Tools, Connectors, Flow,
  State, Human, Outputs, Tests, Proposals.

Base node distribution:

| Group | Count | Notes |
| --- | ---: | --- |
| Flow | 18 | Heavy with runtime controls, policies, recovery, usage, and budget nodes. |
| State | 8 | Mixes durable runtime state, repo state, hook state, and generic state. |
| AI | 6 | Mixes model calls, model binding, skills, hooks-adjacent context, parser. |
| Connectors | 5 | GitHub/repo issue/PR nodes plus generic adapter. |
| Tools | 3 | Generic tools plus workflow package import/export. |
| Tests | 2 | Runtime doctor and test assertion. |
| Human | 2 | Review and human gates. |
| Start/Sources/Transform/Outputs/Proposals | 1 each | Mostly clean primitives. |

Creator preset pressure points:

| Area | Presets | Audit read |
| --- | ---: | --- |
| Source/trigger/function/output | 20 | Mostly healthy as creation templates over generic nodes. |
| Model | 3 | Good templates, but model binding and model call should read as one user primitive by default. |
| Skills | 2 | Good evidence that skill discovery/pinning belongs in one `Skills` primitive. |
| Tools/coding tools | 12 | Too many implementation-specific tool presets in the default palette. Better as `Tool`/`Tool Pack` modes. |
| MCP | 11 | Registry/import/server lifecycle actions are manager/config operations, not all authoring primitives. |
| Subagents | 9 | Lifecycle operations are over-expanded as state presets. Worker topology should be simpler. |
| Memory | 7 | Search/list/policy/remember/edit/delete are modes of one memory primitive. |
| State | 4 | Healthy only if kept generic and not used as a drawer for runtime subsystems. |

## Primary Finding

The registry is runtime-complete but authoring-heavy. The current palette tends
to expose runtime subfacets as node choices: status readers, fetchers, import
steps, lifecycle controls, package evidence, budget recovery, and low-level
runtime rows. These are real runtime contracts, but many are not things a
workflow author naturally thinks in.

The next sprint should separate three layers:

1. Default palette: developer-meaningful primitives.
2. Advanced palette: protocol/debug/runtime contract nodes.
3. Inspectors and config: evidence, receipts, policies, manifests, registry
   operations, and runtime internals.

## Proposed Canonical Primitive Taxonomy

Default palette target:

| Primitive | Purpose | Keep as node when |
| --- | --- | --- |
| Trigger | Starts a workflow from manual, schedule, chat, event, or webhook input. | It changes workflow entrypoint semantics. |
| Input | Provides file, media, dataset, manual, or API payload data. | It is a durable authored source. |
| Context | Supplies repo, issue, current conversation, selected run, or retained state context. | It changes what downstream nodes can know. |
| Agent Step | Performs model-backed reasoning over context, tools, memory, and skills. | It invokes a model/agent boundary. |
| Tool Pack | Binds a set of daemon-governed tools such as coding tools, MCP tools, browser tools, or workflow tools. | It grants executable capabilities to an agent or run. |
| Connector | Binds external authority, credentials, or remote service context. | It crosses a provider/secret/authority boundary. |
| Memory | Reads, searches, writes, injects, or governs runtime memory. | It changes memory state or explicit memory context. |
| Skills | Discovers, pins, imports, validates, and injects skill context. | It changes active skill manifest or prompt/tool context. |
| Policy Gate | Blocks, routes, approves, or constrains execution. | It can pause, block, or change allowed action space. |
| Worker | Spawns, joins, resumes, cancels, or pools subagents/workers. | It creates or coordinates child execution. |
| State | Reads/writes deterministic workflow-local or runtime-projected state. | It is authored state, not just a status row. |
| Control Flow | Branches, loops, barriers, subgraphs, retries. | It changes graph topology. |
| Verification | Runs tests, assertions, doctor/readiness, diagnostics, or gates continuation. | It can pass/fail/gate continuation. |
| Recovery | Snapshots, restore, rollback, repair, compaction recovery. | It mutates or guards recovery state. |
| Output | Materializes a file, patch, delivery draft, table, deployment, or final answer. | It creates a deliverable/outcome. |
| Harness / Runtime | Advanced runtime run, event, task, job, checklist, package, and replay primitives. | The user is building/debugging harness/runtime infrastructure. |

This keeps the default language generic while preserving advanced access to all
runtime contracts.

## Collapse Map

| Current surface | Proposed user primitive | Config / inspector destination | Notes |
| --- | --- | --- | --- |
| `skill_context`, `skill`, `skill_pack` | `Skills` | discovery mode, source set, selection mode, injection target, activation behavior, trust/pin policy, active manifest output | Strong collapse candidate. Skill discovery, pinning, import, validation, and prompt audit are one developer concept. |
| `hook`, `hook_policy` | `Hook` plus `Policy Gate` when blocking | hook type, event subscription, authority scopes, side-effect contract, failure policy, invocation ledger | Hook policy is usually config. Keep a gate only when it pauses or blocks execution. |
| `model_binding`, `model_call`, `parser` | `Agent Step` with model/parser sections | model route, reasoning effort, structured output, parser/refinement, tool-use mode, memory/skills attachment | Keep advanced model binding as a port/config object, not a default standalone node. |
| `runtime_usage_meter`, `runtime_context_budget`, `runtime_compaction_policy` | `Policy Gate` or `Context Policy` | telemetry source, thresholds, warn/block/compact actions, approval behavior | Usage read is inspector/status; budget/compaction is a gate when it can block or compact. |
| `runtime_context_compact` | `Recovery` | compaction reason/scope/action receipt | Keep as advanced or recovery mode; not default flow unless it mutates context. |
| `runtime_task`, `runtime_job`, `runtime_checklist` | `Harness / Runtime` advanced | run/task/job/checklist inspector tabs, replay state, status rows | These are projection/state proof nodes, not ordinary authoring primitives. |
| `runtime_operator_interrupt`, `runtime_operator_steer` | `Harness / Runtime` advanced controls | run inspector actions, operator control receipts | Better as controls unless composing an operator-control workflow. |
| `runtime_thread_mode`, `runtime_workspace_trust_gate`, `runtime_approval_request`, `human_gate`, `review_gate` | `Policy Gate` | mode/trust/approval/review sections | Keep a separate gate when execution pauses or authority changes. |
| `runtime_rollback_snapshot`, `runtime_restore_gate`, `runtime_diagnostics_repair`, `runtime_coding_tool_budget_recovery` | `Recovery` | recovery type, restore policy, repair decision, override approval | Distinct enough to keep under Recovery, but not four top-level default names. |
| `workflow_package_export`, `workflow_package_import` | `Harness / Runtime` advanced or workbench action | package manifest, import review, locale preservation, evidence rows | Generally a workbench/package panel action, not a normal workflow node. |
| `repository_context`, `github_context`, `issue_context`, `branch_policy`, `pr_attempt`, `github_pr_create` | `Repository`, `Policy Gate`, `Pull Request` | repo source, issue binding, branch policy, PR dry-run/live mode, authority scopes, artifacts | Collapse to three authoring primitives: Repository, Review/Policy Gate, Pull Request. |
| `plugin_tool` coding presets (`git_diff`, `file_inspect`, `file_apply_patch`, `test_run`, `lsp_diagnostics`, `artifact_read`, `tool_retrieve_result`) | `Tool Pack` | enabled tools, operation mode, dry-run/write, diagnostics, restore, budget, approval | Keep quick-add templates, but default palette should show `Tool Pack`/`Coding Tools`. |
| MCP state presets (`mcp.status`, search/fetch/import/add/remove/enable/disable/serve/invoke) | `Connector` + `Tool Pack` | server registry, source mode, catalog search/fetch, containment, vault refs, invocation input | Server lifecycle belongs in connector config/manager inspector; invocation belongs in Tool Pack. |
| Subagent state presets (`pool`, `role`, `spawn`, `join`, `result`, `input`, `cancel`, `resume`) | `Worker` and `Policy Gate` when join blocks | role, pool constraints, spawn prompt, lifecycle action, output contract, merge policy, cancellation inheritance | Spawn creates execution; join gates merge. The rest are lifecycle controls/inspector actions. |
| Memory state presets (`status`, `policy`, `search`, `list`, `remember`, `edit`, `delete`) | `Memory` | operation, scope, key/query, injection, retention, write approval, subagent inheritance | Strong collapse candidate. |
| `state.read/write/append/reducer/checkpoint` | `State` | state key, reducer, checkpoint/replay/fork | Healthy generic primitive if not overloaded with subsystem-specific state operations. |

## Split / Keep Separate Rules

Do not over-collapse into mega-nodes. Keep a separate node when it represents a
separate execution boundary:

- model/agent invocation;
- tool invocation or capability grant;
- child worker/subagent execution;
- external connector authority or secret boundary;
- approval/review/verification gate that can pause continuation;
- recovery action that mutates workspace or runtime state;
- artifact/output materialization;
- trigger/entrypoint or control-flow topology.

Collapse into config/ports/inspector when the distinction is only:

- discovery vs list vs fetch vs status;
- policy field vs policy node;
- runtime row vs authored workflow step;
- receipt/evidence/debug view;
- one operation variant of the same subsystem.

## User-Facing Naming Pass

Default labels should avoid implementation names:

| Current/internal | User-facing label |
| --- | --- |
| `RuntimeThreadNode`, `RuntimeTurnNode`, runtime rows | Conversation / Agent Run / Runtime State |
| `RuntimeTaskNode`, `RuntimeJobNode`, `RuntimeChecklistNode` | Run State / Job / Checklist in advanced palette |
| `RuntimeDoctorNode` | Readiness Check |
| `AgentgresProjectionNode` | State Projection |
| `Model Binding`, `Model` | Agent Step |
| `Skill Context`, `Skill Pack` | Skills |
| `Hook Policy` | Hook, Policy section, or Policy Gate |
| `Runtime Context Budget`, `Runtime Compaction Policy` | Context Policy |
| `Runtime Diagnostics Repair`, `Runtime Restore Gate` | Recovery |
| `GitHub PR Create` | Pull Request |
| `Plugin Tool` | Tool / Tool Pack |

The advanced inspector should still expose canonical type, component kind,
workflow node id, runtime route, receipt refs, artifact refs, policy refs, graph
id, and event ids.

## Runtime Alignment Matrix

| Proposed primitive | Canonical runtime backing |
| --- | --- |
| Trigger | workflow activation manifest, thread/turn creation, event source refs |
| Input | source payload manifest, sanitizer/MIME policy, input receipts |
| Context | runtime state projection, repo/GitHub/issue context records, retained state |
| Agent Step | model route decision, model call receipt, memory/skills/tool attachment manifests |
| Tool Pack | daemon tool contracts, MCP/tool invocation receipts, primitive capabilities, authority scopes |
| Connector | connector binding, credential readiness, vault refs, authority scopes |
| Memory | memory manager status/validation/mutation receipts, active memory injection evidence |
| Skills | skill discovery/import registry, active skill-set hash, prompt audit refs |
| Hook | hook manifest, invocation ledger, side-effect contract, failure policy |
| Policy Gate | approval manifests, trust warnings, budget gates, branch/review gates |
| Worker | subagent manager lifecycle records, child run ids, output contracts, budget records |
| State | workflow state reducer/checkpoint, runtime projection refs |
| Control Flow | graph execution scheduler, route/loop/barrier/subgraph semantics |
| Verification | doctor/readiness reports, tests, diagnostics, assertions, verifier receipts |
| Recovery | snapshot/restore/repair/compaction/budget-recovery records |
| Output | artifacts, delivery bundles, patch/proposal/deploy manifests |
| Harness / Runtime | task/job/checklist/run/event/replay/package contracts |

## Default Harness Graph Under The Clean Taxonomy

Target default coding-agent harness graph:

1. `Manual Trigger`
2. `Input` with objective payload
3. `Repository` context
4. `Skills` with discovery/pinned policy
5. `Memory` with thread/workspace scope and injection enabled
6. `Tool Pack` with coding tools enabled and policy controls
7. `Agent Step` with model route, tools, memory, and skills attached
8. `Policy Gate` for approvals, trust, and context/cost budget
9. `Worker` only when subagent fan-out is needed
10. `Verification` for tests, diagnostics, doctor/readiness
11. `Recovery` for snapshot/restore/repair paths
12. `Output` for final answer, patch, PR draft, artifact, or delivery bundle

Advanced runtime nodes remain available through an advanced palette and run
inspector: task, job, checklist, event stream, package import/export, replay,
operator steer/interrupt, and raw state projection.

## Implementation Slices

Recommended order:

1. Add taxonomy metadata without changing behavior:
   `canonicalPrimitive`, `paletteVisibility`, `collapseTarget`,
   `advancedLabel`, `configSections`, and `runtimeMapping` on node definitions
   and creator definitions.
2. Add source-contract tests that assert every current node maps to a canonical
   primitive and has a default/advanced palette decision.
3. Introduce palette filtering:
   default palette shows canonical primitives and curated templates; advanced
   palette shows raw runtime/debug/protocol nodes.
4. Build the `Skills`, `Memory`, `Tool Pack`, `Worker`, and `Repository`
   collapsed config sections first because they have the clearest over-expanded
   preset families.
5. Rename user-facing labels while preserving stored node `type` compatibility.
6. Add migration/projection helpers:
   old node type plus old logic projects to new primitive plus config path.
7. Prototype the default coding-agent harness graph under the cleaned taxonomy
   and verify it compiles to the same daemon/runtime contracts.
8. Only then refactor React Flow components and panel layout.

## First Tactical Slice

Add a non-breaking taxonomy layer to `workflow-node-registry.ts`:

- `canonicalPrimitive` enum matching the proposed taxonomy;
- `paletteVisibility: "default" | "template" | "advanced" | "hidden"`;
- `collapseTarget` for old/raw nodes;
- `runtimeMapping` with daemon/API/component/receipt references;
- a contract test that inventories all node definitions and creator presets.

This gives us an executable map before touching UI layout, and it keeps the
next leg honest: no visual polish without a canonical primitive taxonomy.
