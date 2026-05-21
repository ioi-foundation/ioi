# Runtime Package Boundaries

Status: internal package-boundary implementation reference; pre-leg ready.
Authority: `docs/architecture/` and accepted ADRs are canonical; this file is an implementation checklist only.
Supports: package/runtime/client ownership boundary changes.
Superseded by: canonical architecture docs or ADRs when conflicts arise.
Last alignment pass: 2026-05-20.

This document names the execution ownership boundaries that must hold before the
next architecture leg. It is intentionally short so package authors can use it as
a checklist while changing CLI, SDK, IDE, harness, benchmark, compositor, or GUI
code.

## Architecture-Aligned Layers

| Layer | Owns | Must Not Own |
| --- | --- | --- |
| Domain kernel | Runtime, authority, state-transition, and settlement-facing invariants | Product UI or client ergonomics |
| `ioi-daemon` | Hypervisor/control plane for autonomous execution: runtime endpoint, runtime-node profile, thread/turn controls, workflow/worker/tool/model/connector/computer-use supervision, training/evaluation/benchmark/routing jobs, receipts, replay, and daemon-local execution services | Root authority, marketplace truth, independent application state, SDK-owned execution, or workbench-owned execution |
| Agentgres | Canonical operational truth: runs, tasks, artifacts, receipts, policy decisions, training lineage, benchmark state, routing decisions, ledgers, projections | Direct model/tool/training mutation without governed envelopes |
| wallet.network | Identity, secrets, authority scopes, data-use permissions, leases, approvals, revocation, payments | Rich workflow state, run traces, training datasets, or artifact payload bytes |
| `ioi-cli` / TUI | Human terminal and interactive TUI client over daemon/public runtime APIs, including training runs, benchmark jobs, receipts, and routing inspection | Agent runtime semantics, hidden TUI-only state transitions, or a private execution loop |
| `@ioi/agent-sdk` | Developer SDK client over the daemon/substrate | Synthetic runtime as canonical default |
| `@ioi/agent-ide` | UI/workbench/workflow composer client over shared contracts | Canonical run/session/proposal/task truth |
| Autopilot Workbench | IDE-grade operator console hosted in the Electron/VS Code fork; observes, requests, approves, interrupts, debugs, and explains daemon-governed work | Execution authority, connector secrets, durable run truth, or extension-host runtime loops |
| Electron/VS Code fork | Canonical Autopilot app shell for Workbench and Desktop modes; owns shell affordances and daemon supervision | Runtime authority, policy truth, receipts, replay, or connector secrets |
| Autopilot Desktop | Product mode composing private/device automation, chat, IDE, Autopilot Foundry, and local daemon UX | A separate runtime path, marketplace ranking authority, portable headless substrate, or Tauri-owned target shell |
| Shared builder substrate | Typed graph, schema, recipe, and builder-lens contracts used by Foundry, data recipes, evals, benchmarks, deployments, and outcome workflows | A separate runtime, Agentgres replacement, or one forced UI for every builder persona |
| Harness/benchmarks | Deterministic validation over public substrate contracts | Privileged bypasses or fixture-only production routing |
| Adaptive Work Graph | Execution strategy under the generic runtime envelope | Product surface, daemon, SDK, or runtime identity |

See [`runtime-module-map.md`](./runtime-module-map.md) for the concrete source
tree homes that enforce these boundaries.

## Capability Tiers

IOI uses two different authority concepts and must not blur them.

- Primitive execution capabilities are CIRC boundary capabilities. They describe
  permission, isolation, or risk boundaries such as `prim:fs.read`,
  `prim:fs.write`, `prim:sys.exec`, `prim:ui.interact`, `prim:net.request`,
  `prim:model.invoke`, or `prim:connector.invoke`.
- Authority scopes are wallet/provider grants. They describe operation-scoped
	  admission such as `scope:gmail.send`, `scope:calendar.create`,
	  `scope:commerce.order_submit`, or `scope:host.controlled_execution`.

Runtime tools must declare primitive capabilities separately from authority
scope requirements. Do not add compatibility projections that flatten those
tiers back into a generic `capability` field.

## State Ownership

Local files, browser storage, SDK checkpoints, workbench state, GUI test
captures, and harness fixtures are cache/projection/test material unless they are
written through daemon/Agentgres-compatible APIs with receipts.

UI helpers may create non-canonical projections for empty or disconnected states,
but those helpers must be named and documented as projections.

Compute nodes and remote runtime venues boot IOI daemon/runtime-node profiles.
SDK helpers may be available inside worker packages or clients, but they must
not become the execution owner.

Workers, models, tools, connectors, browsers, shells, and computer-use providers
are guest workloads/capabilities from the runtime package boundary. They are
leased, invoked, observed, and receipted through daemon/public runtime APIs.

Training, evaluation, benchmark, and MoW routing state follows the same rule:
product surfaces may project or initiate it, but canonical state must flow
through daemon/Agentgres-compatible APIs with receipts.

## Mock And Fixture Boundary

Mocks and fixtures are allowed for tests, replay, demos, and explicit
development profiles. Production routing must fail closed or require a policy
decision when a mock binding or fixture-backed path would otherwise be used.

## Adaptive Work Graph Naming Boundary

`adaptive work graph` is a strategy term for existing implementation plans, tests, and legacy
operator vocabulary. New public/runtime surfaces should prefer generic execution
terms:

- execution strategy
- work graph
- work item
- worker receipt
- merge receipt
- verification receipt
- adaptive work graph

Persisted legacy fields require an explicit migration before removal; new
compatibility aliases must not be introduced as product/runtime nouns.
