# ADR 0002: Make The IOI Daemon The Canonical Execution Endpoint

- Status: Accepted
- Date: 2026-05-14
- Owners: IOI runtime / Hypervisor / SDK / ADK / CLI-headless

## Context

IOI has many operator and developer surfaces: Hypervisor App, Hypervisor Web,
CLI/headless, optional TUI presentation, SDK, ADK, Workbench adapter hosts,
agent harness adapters, benchmarks, and browser applications. All of them need
to submit, inspect, scaffold, control, or visualize work, but consequential
Web4 work needs one execution authority boundary.

Without that boundary, client helpers can become private runtime truth paths
and remote compute nodes can be mistaken for SDK-owned runtimes.

## Decision

The IOI daemon is the universal execution endpoint for canonical Web4 work.

Client surfaces are operators or projections over daemon/domain contracts:

- CLI/headless is a daemon-backed operator client. TUI is an optional
  presentation of that client.
- SDK is a low-level developer client over daemon/substrate contracts.
- ADK is an autonomous-system builder framework over SDK and daemon/domain
  contracts.
- Hypervisor App and Hypervisor Web are product clients over Hypervisor Core
  and may manage local or remote daemon profiles.
- Workbench adapter hosts, agent harness adapters, benchmarks, and browser apps
  author or inspect work, but do not own execution semantics.

Runtime and compute nodes initialize IOI daemon/runtime-node profiles. SDK code
may submit, inspect, control, or embed client helpers, but the SDK is not the
substrate booted on compute nodes. ADK code may scaffold workers, service
modules, harnesses, evals, manifests, receipts, and deployment profiles, but it
is not the daemon/runtime substrate.

## Consequences

- No TUI-only, SDK-only, ADK-only, GUI-only, harness-only, or benchmark-only state
  transition is canonical for consequential work.
- Training, evaluation, benchmark, routing, delivery, data recipe, and
  transformation jobs run through daemon-compatible runtime paths.
- Hypervisor-compatible workflow packages may run on remote nodes, but the node
  is still an IOI daemon/runtime-node profile.
- Mocks, local helpers, and embedded SDK utilities are test/dev projections
  unless they submit through daemon/domain contracts.

## Canonical References

- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/components/daemon-runtime/api.md`
- `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
