# Chat/Artifact Runtime Module Map

Status: ACTIVE

This map describes the intended active-code topology after the clean-break refactor. It is intentionally named chat/artifact runtime; `Studio` is legacy wording.

## API Crate

- `crates/api/src/chat.rs`: public chat/artifact API facade and high-level request routing.
- `crates/api/src/chat/html/`: HTML repair, normalization, interaction checks, view controls, and CSS safety helpers.
- `crates/api/src/chat/payload/`: generated artifact payload decoding, normalization, direct-authored document extraction, and validation.
- `crates/api/src/chat/domain_topology/`: artifact domain topology and route-contract prompt construction.
- `crates/api/src/chat/generation/`: candidate generation, runtime materialization, swarm/non-swarm flows, validation preview, and repair prompts.
- `crates/api/src/chat/planning/`: plan and route selection for chat/artifact work.
- `crates/api/src/chat/tests/`: integration-style API tests grouped by behavior.

## Desktop App Kernel

- `apps/autopilot/src-tauri/src/models/`: Tauri-facing runtime data models.
- `apps/autopilot/src-tauri/src/kernel/chat/`: chat/artifact runtime orchestration in the desktop app.
- `apps/autopilot/src-tauri/src/kernel/artifacts/`: artifact persistence, trace export, and evidence bundle commands.
- `apps/autopilot/src-tauri/src/kernel/session/`: session history, compaction, durability, team memory, rewind, and remote projections.
- `apps/autopilot/src-tauri/src/kernel/capabilities/`: capability catalog, governance proposals, and connector/local-engine capability entries.
- `apps/autopilot/src-tauri/src/kernel/workflows/`: workflow state and execution adapters.
- `apps/autopilot/src-tauri/src/kernel/connectors/`: connector policy, subscription state, and connector command surfaces.

## Refactor Rule

When a module grows, split by runtime responsibility before adding new cross-cutting helpers. New names should describe the runtime role, not the legacy UI surface that first hosted the feature.

