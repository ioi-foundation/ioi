# ADR 0002: Make The IOI Daemon The Canonical Execution Endpoint

- Status: Accepted
- Date: 2026-05-14
- Owners: IOI runtime / Autopilot / SDK / CLI-TUI

## Context

IOI has many operator and developer surfaces: CLI, TUI, SDK, Autopilot Desktop,
agent-ide, harnesses, benchmarks, and browser applications. All of them need to
submit, inspect, control, or visualize work, but consequential Web4 work needs
one execution authority boundary.

Without that boundary, client helpers can become private runtime truth paths
and remote compute nodes can be mistaken for SDK-owned runtimes.

## Decision

The IOI daemon is the universal execution endpoint for canonical Web4 work.

Client surfaces are operators or projections over daemon/domain contracts:

- CLI/TUI is a daemon-backed operator client.
- SDK is a developer client over daemon/substrate contracts.
- Autopilot Desktop is the local product/workbench and may manage a local
  daemon profile.
- agent-ide, harnesses, benchmarks, and browser apps author or inspect work,
  but do not own execution semantics.

Runtime and compute nodes initialize IOI daemon/runtime-node profiles. SDK code
may submit, inspect, control, or embed client helpers, but the SDK is not the
substrate booted on compute nodes.

## Consequences

- No TUI-only, SDK-only, GUI-only, harness-only, or benchmark-only state
  transition is canonical for consequential work.
- Training, evaluation, benchmark, routing, delivery, data recipe, and
  transformation jobs run through daemon-compatible runtime paths.
- Autopilot-compatible workflow packages may run on remote nodes, but the node
  is still an IOI daemon/runtime-node profile.
- Mocks, local helpers, and embedded SDK utilities are test/dev projections
  unless they submit through daemon/domain contracts.

## Canonical References

- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/components/daemon-runtime/api.md`
- `docs/architecture/products/autopilot/local-app-workflow-canvas.md`
- `docs/implementation/runtime-package-boundaries.md`
- `docs/implementation/runtime-module-map.md`
