# Runtime Module Map

Status: canonical source-tree map; layout-refactor guardrail.
Canonical owner: this file for implementation module locations related to runtime substrate, clients, projections, fixtures, and validation.
Supersedes: overlapping source-tree maps in plans/specs when module ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

This map names the canonical homes for runtime execution, clients,
projections, validation, and compatibility code. It is intentionally concrete:
new runtime work should land in one of these homes rather than creating a
parallel execution path.

## Canonical Execution

| Surface | Canonical Home | Role |
| --- | --- | --- |
| Runtime kernel | `crates/services/src/agentic/runtime/kernel/` | State transition, authority, and execution invariants. |
| Runtime service loop | `crates/services/src/agentic/runtime/service/` | Agent loop orchestration over the kernel and tool contracts. |
| Runtime tools | `crates/services/src/agentic/runtime/tools/` | Governed tool contracts, discovery, MCP, skills, and built-ins. |
| Daemon service | `packages/runtime-daemon/` | Local public daemon API for SDK/CLI/GUI/harness validation. |
| Agentgres state | `packages/runtime-daemon/src/index.mjs` for local v0 proof, future `crates/agentgres` or daemon storage crate | Canonical operation log, runs, tasks, receipts, scorecards, and projections. |

## Clients And Projections

| Surface | Canonical Home | Must Remain |
| --- | --- | --- |
| `@ioi/agent-sdk` | `packages/agent-sdk/` | Developer client over daemon/substrate contracts. |
| `ioi-cli` | `crates/cli/` | Terminal/TUI client over daemon/public runtime APIs. |
| `@ioi/agent-ide` | `packages/agent-ide/` | Workbench and workflow-composer projection over shared contracts. |
| Autopilot | `apps/autopilot/` | Product shell over chat, IDE, and daemon/runtime projections. |
| Workflow compositor | `packages/agent-ide/src/WorkflowComposer/` | UI/workflow client that submits to the substrate, not canonical run truth. |

## Validation Surfaces

| Surface | Canonical Home | Role |
| --- | --- | --- |
| Runtime conformance | `scripts/conformance/` | Durable conformance commands. |
| Runtime evidence | `scripts/evidence/` | Durable evidence generation commands. |
| Script launchers | `scripts/` | Thin operator wrappers only. |
| JS contract tests | `scripts/lib/*.test.mjs` | Tests and guardrails, not runtime implementation. |
| Autopilot proofs | `apps/autopilot/src-tauri/src/proofs/` or `apps/autopilot/src-tauri/src/harness/` | Proof/harness code only; product runtime modules should stay uncluttered. |

## Vocabulary Rules

- `RuntimeSubstrate` means the shared runtime contract, not an HTTP client, UI
  cache, canonical store, or proof harness.
- `RuntimeDaemonClient` means a client that talks to daemon/public runtime APIs.
- `AgentgresRuntimeStateStore` means canonical local v0 state for daemon-backed
  proof runs.
- `RuntimeProjection` means UI/cache/read-model state derived from canonical
  events or traces.
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
