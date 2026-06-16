# Runtime Module Map

Status: internal source-tree map; layout-refactor guardrail.
Authority: `docs/architecture/` and accepted ADRs are canonical; this file maps implementation locations only.
Supports: runtime substrate, clients, projections, fixtures, and validation module placement.
Superseded by: canonical architecture docs or ADRs when conflicts arise.
Last alignment pass: 2026-06-16.

This map names architecture-aligned homes for runtime execution, clients,
projections, validation, and compatibility code. It is intentionally concrete:
new runtime work should land in one of these homes rather than creating a
parallel execution path.

## Runtime Execution Homes

| Surface | Home | Role |
| --- | --- | --- |
| Runtime kernel | `crates/services/src/agentic/runtime/kernel/` | State transition, authority, and execution invariants. |
| Runtime service loop | `crates/services/src/agentic/runtime/service/` | Agent loop orchestration over the kernel and tool contracts. |
| Runtime tools | `crates/services/src/agentic/runtime/tools/` | Governed tool contracts, discovery, MCP, skills, and built-ins. |
| Daemon service | `packages/runtime-daemon/` | Public daemon API, runtime-node profile, thread/turn controls, training/evaluation/benchmark/routing jobs, and local v0 substrate for SDK/CLI-headless/GUI/harness validation. |
| Runtime service bridge | `crates/node/src/bin/ioi-runtime-bridge.rs` and `packages/runtime-daemon/src/runtime-api-bridge.mjs` | Bridge from daemon API into `RuntimeAgentService` or equivalent lower-level runtime service loops. |
| Agentgres state | `packages/runtime-daemon/src/index.mjs` for local v0 proof, future `crates/agentgres` or daemon storage crate | Canonical operation log, runs, tasks, training lineage, benchmark state, routing decisions, receipts, scorecards, and projections. |

## Clients And Projections

| Surface | Canonical Home | Must Remain |
| --- | --- | --- |
| `@ioi/agent-sdk` | `packages/agent-sdk/` | Developer client over daemon/substrate contracts. |
| `ioi-cli` / headless | `crates/cli/` | Terminal, scripting, CI, node-ops, and headless client over daemon/public runtime APIs, including training, benchmark, receipt, and routing inspection controls; TUI is an optional presentation over this client. |
| `@ioi/agent-ide` | `packages/agent-ide/` | Workbench and workflow-composer projection over shared contracts. |
| Hypervisor App/Web | `apps/autopilot/` today, future Hypervisor app/web homes as code is renamed | First-class product clients over Hypervisor Core; product shell over Workbench, Foundry, Fleet, chat/assistant surfaces, and daemon/runtime projections. |
| Shared builder substrate | `packages/agent-ide/src/types/graph.ts`, `packages/agent-ide/src/runtime/workflow-schema.ts`, workflow runtime models | Typed graph, schema, and recipe contracts consumed by multiple builder lenses. |
| Workflow compositor | `packages/agent-ide/src/WorkflowComposer/` | Standard graph projection over the shared builder substrate; submits to daemon/domain contracts and never owns canonical run truth. |

## Validation Surfaces

| Surface | Canonical Home | Role |
| --- | --- | --- |
| Runtime conformance | `scripts/conformance/` | Durable conformance commands. |
| Runtime evidence | `scripts/evidence/` | Durable evidence generation commands. |
| Script launchers | `scripts/` | Thin operator wrappers only. |
| JS contract tests | `scripts/lib/*.test.mjs` | Tests and guardrails, not runtime implementation. |
| Hypervisor proofs | `apps/autopilot/src-tauri/src/proofs/` or `apps/autopilot/src-tauri/src/harness/` while the source path is still named `autopilot` | Proof/harness code only; product runtime modules should stay uncluttered. |

## Vocabulary Rules

- `RuntimeSubstrate` means the shared runtime contract, not an HTTP client, UI
  cache, canonical store, or proof harness.
- `RuntimeDaemonClient` means a client that talks to daemon/public runtime APIs.
- `AgentgresRuntimeStateStore` means canonical local v0 state for daemon-backed
  proof runs.
- `RuntimeProjection` means UI/cache/read-model state derived from canonical
  events or traces.
- `RuntimeApiBridge` means a daemon-internal bridge into lower-level runtime
  service code. It is not an SDK client and not an application-domain store.
- `ComputeSession` means a bounded runtime allocation served by a daemon profile
  on local, hosted, provider, DePIN, TEE, customer, or browser/container/VM
  substrate.
- `HypervisorFoundry` means the Hypervisor application surface for Worker
  Training. It is a client/projection over daemon, Agentgres, wallet.network,
  model router, and Agentgres-governed artifact/storage contracts.
- `MoWRouter` means worker routing logic over bounded workers and receipts. It
  is not the model router and must not be implemented as hidden product-surface
  ranking.
- `adaptive work graph` is the public execution-strategy term. `adaptive work graph` is
  legacy/historical vocabulary unless isolated in compatibility or old plan
  material.

## Refactor Rule

When moving runtime code, prefer this order:

1. Add or update the contract/guardrail.
2. Move implementation without semantic changes.
3. Keep temporary compatibility wrappers only if an active public or persisted
   surface requires them.
4. Remove roadmap/proof names from product paths once conformance stays green.
