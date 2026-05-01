# Pre-Next-Leg Cleanup Checklist

Status: pre-leg ready

This checklist records the cleanup baseline that must stay true while executing
the architectural improvements broad leg. It is a guardrail artifact, not a
runtime contract by itself.

## Boundary Status

| Area | Status | Evidence |
| --- | --- | --- |
| Layer taxonomy | Complete | `docs/architecture/operations/runtime-package-boundaries.md` names kernel, daemon, CLI, SDK, agent-ide, Autopilot, harness, benchmarks, Agentgres, wallet.network, and swarm ownership boundaries. |
| Primitive capability vs authority scope split | Complete | `RuntimeToolContract` exposes `primitive_capabilities` and `authority_scope_requirements`; connector docs use `primitive_capabilities` and `authority_scope_required`. |
| Shared runtime action schema | Complete | `docs/architecture/operations/runtime-action-schema.json` is generated into TypeScript and Rust surfaces by `scripts/generate-runtime-action-contracts.mjs`. |
| SDK default substrate | Complete | The SDK default client is daemon-backed and fails closed without a daemon endpoint. |
| SDK mock projection boundary | Complete | Mock/local projection is explicit through the testing subpath and is labeled non-authoritative. |
| Agent IDE boundary | Complete | Agent IDE helper projections are named non-canonical and adapter failures block durable proposal/run truth. |
| CLI/daemon boundary | Complete | CLI agent command handlers are clients of the daemon-hosted runtime service through `CliAgentRuntimeClient`. |
| Mock and fixture boundary | Complete | Production workflow validation blocks explicit mock bindings when live activation is required. |
| Swarm naming migration | Complete | `swarm` is documented as an execution strategy, not a product/runtime surface; active chat strategy wire aliases no longer accept `swarm`. |
| Canonical state vs projections | Complete | Agentgres owns canonical operational truth; SDK checkpoints and IDE projections are cache/export/projection state only. |
| Runtime layout refactor | Complete | `docs/architecture/operations/runtime-module-map.md` names canonical source homes; daemon implementation lives in `packages/runtime-daemon`; durable conformance/evidence commands live under `scripts/conformance` and `scripts/evidence`. |
| Repeatable readiness gate | Complete | `npm run check:pre-next-leg` runs schema drift, package-boundary, mock leakage, SDK default, CLI ownership, capability-tier, vocabulary, and runtime-layout checks. |

## Operating Rule

The next leg may add live daemon, SDK, GUI, workflow, hosted-worker, and
Agentgres behavior, but it must not weaken this baseline. New implementation
should extend the unified runtime substrate rather than creating a second
runtime in the SDK, CLI, GUI, harness, benchmark, compositor, or worker lanes.
