# Runtime Package Boundaries

Status: canonical package-boundary reference; pre-leg ready.
Canonical owner: this file for package/runtime/client ownership boundaries.
Supersedes: overlapping SDK/CLI/agent-ide/harness/compositor boundary prose in plans/specs.
Superseded by: none.
Last alignment pass: 2026-05-13.

This document names the execution ownership boundaries that must hold before the
next architecture leg. It is intentionally short so package authors can use it as
a checklist while changing CLI, SDK, IDE, harness, benchmark, compositor, or GUI
code.

## Canonical Layers

| Layer | Owns | Must Not Own |
| --- | --- | --- |
| Domain kernel | Runtime, authority, state-transition, and settlement-facing invariants | Product UI or client ergonomics |
| `ioi-daemon` | Deployable process hosting the runtime endpoint, runtime-node profile, thread/turn controls, training/evaluation/benchmark/routing jobs, and daemon-local execution services | Root authority, marketplace truth, independent application state, or SDK-owned execution |
| Agentgres | Canonical operational truth: runs, tasks, artifacts, receipts, policy decisions, training lineage, benchmark state, routing decisions, ledgers, projections | Direct model/tool/training mutation without governed envelopes |
| wallet.network | Identity, secrets, authority scopes, data-use permissions, leases, approvals, revocation, payments | Rich workflow state, run traces, training datasets, or artifact payload bytes |
| `ioi-cli` / TUI | Human terminal and interactive TUI client over daemon/public runtime APIs, including training runs, benchmark jobs, receipts, and routing inspection | Agent runtime semantics, hidden TUI-only state transitions, or a private execution loop |
| `@ioi/agent-sdk` | Developer SDK client over the daemon/substrate | Synthetic runtime as canonical default |
| `@ioi/agent-ide` | UI/workbench/workflow composer client over shared contracts | Canonical run/session/proposal/task truth |
| Autopilot Desktop | Product shell composing chat, IDE, Autopilot Foundry, and local daemon UX | A separate runtime path, marketplace ranking authority, or portable headless substrate |
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
  `scope:instacart.order_submit`, or `scope:host.controlled_execution`.

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
