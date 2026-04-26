# Runtime Refactor Boundaries

Status: ACTIVE

This repo is in a clean-break epoch. Refactors should make the runtime easier to reason about and should not preserve legacy product topology for convenience.

## Naming Boundary

Use current names in active APIs, docs, tests, env vars, and UI copy:

- `chat artifact`
- `runtime`
- `graph`
- `workflow`
- `kernel`
- `runtime workbench`

`Studio` is legacy. It is allowed only in historical docs, audit/progress files, or untouched external/protocol artifacts that explicitly document why the old name remains.

## Module Boundary

Large files should move toward directory modules with narrow responsibilities. The target boundaries are:

- Chat/artifact generation: planning, prompt building, candidate materialization, validation, repair, provenance, and export.
- Runtime kernel: intent, policy, approval, capability, deadline, invocation, settlement, trace, projection, profiles, and marketplace schemas.
- Desktop app kernel: session durability, team memory, artifact export, capability catalog, workflow orchestration, connector policy, local engine, and UI projection models.
- Browser/computer-use: DOM capture, accessibility extraction, action planning, evidence receipts, and replay.

## Large File Policy

New active files should normally stay under 2,000 lines. Existing larger files are refactor debt and should be split when touched for substantial work. Temporary exceptions must be documented here with an owner section and a target boundary.

Current large-module exceptions:

- `crates/api/src/chat/html/mod.rs`: split into repair, view controls, detail payloads, layout normalization, interactive validation, and CSS helpers.
- `crates/api/src/chat/payload/mod.rs`: split into schema normalization, direct-authored document extraction, completeness checks, and artifact validation scoring.
- `crates/api/src/chat/domain_topology/mod.rs`: split into topology data, route-contract prompt text, and selector logic.
- `crates/api/src/chat/generation/runtime_materialization/mod.rs`: split into deadlines, stream handling, follow-up repair, candidate settlement, and runtime adapter calls.
- `apps/autopilot/src-tauri/src/models/mod.rs`: split into local engine, capability registry, artifacts/events, chat sessions, notifications/interventions, session durability, plugins, governance, and app state.
- `apps/autopilot/src-tauri/src/kernel/session/mod.rs`: split into session history, compaction, team memory, durability portfolio, rewind, and remote env projection.
- `apps/autopilot/src-tauri/src/kernel/capabilities/mod.rs`: split into catalog entries, governing hints, local engine entries, policy proposals, and Tauri commands.
- `apps/autopilot/src-tauri/src/kernel/artifacts/mod.rs`: split into artifact persistence, trace bundle export, trace bundle diffing, and assistant workbench projection.

## Compatibility Boundary

Runtime compatibility shims are disallowed unless all are true:

- The compatibility is protocol-versioned or generated from an external contract.
- The code fails closed in production/marketplace profiles.
- A guard test names the expiry condition.
- The runtime does not silently migrate old request shapes.

## Validation

Run:

```bash
./scripts/check-runtime-refactor-health.sh
./scripts/check-clean-break-debt.sh
cargo check -p ioi-api
cargo check -p autopilot
npm run typecheck
```

