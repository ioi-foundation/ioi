# Agent Runtime Parity Plus Refactor And Intuitiveness Report

Date: 2026-06-03

Scope: first refactor leg after the parity-plus audit guide. This pass prioritized behavior-preserving extractions that improve ownership boundaries without changing public command ids, request/response envelopes, data-testids, retry-limit semantics, or generated evidence handling.

## Completed Splits

### Live GUI Proof Harness

- Added `scripts/lib/live-gui-proof-harness/` with shared process, network, bridge, file, Playwright, screenshot, and cleanup helpers.
- Migrated Stage 8 managed-session reconnect proof and Stage 9 historic replay proof to the shared harness.
- Added checked-in Stage 9 replay fixtures so the live replay proof can run from a clean checkout without relying on ignored `docs/evidence` artifacts.
- Kept generated proof outputs ignored under `docs/evidence/`.

### Agent Studio Workbench Extension

- Added `apps/autopilot/openvscode-extension/ioi-workbench/bridge/client.js` for daemon endpoint/token/base-url and JSON request helpers.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/public-text-sanitizer.js` for product-facing assistant/tool text sanitization.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-state.js` for the initial Agent Studio runtime projection shape.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/migration.js` for migration-assistant command registration.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/quick-input.js` for fork-native QuickInput handoff commands.
- Kept compatibility wrappers in `extension.js` where existing tests or local call sites expect the old function names.

Status: `extension.js` is still a composition-heavy file and remains larger than the guide's ideal target. The safe next extractions are Studio projection events, managed-session test hooks, panel lifecycle, and command grouping by Studio/workflows/models/runs.

### Runtime Daemon

- Added `packages/runtime-daemon/src/runtime-request-metadata.mjs`.
- Moved request base URL, runtime event cursor parsing, usage request metadata projection, and usage metadata application out of `index.mjs`.
- Passed `RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION` into the helper explicitly so the module stays decoupled from the daemon constants bundle.

Status: `index.mjs` still owns the large state store and public route composition. Safe next extractions are daemon service lifecycle, thread store/control/replay, managed-session state, and route registration glue.

### Model Mounting

- Added `packages/runtime-daemon/src/model-mounting/environment.mjs`.
- Moved LM Studio discovery gates, internal fixture exposure gates, live catalog/download gates, and catalog/download timeout parsing out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-registry.mjs`.
- Moved catalog provider port ordering and provider status projection out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-entries.mjs`.
- Moved fixture catalog records, local manifest payload normalization, Hugging Face catalog entry shaping, Ollama artifact catalog entry shaping, variant projection, and catalog entry enrichment out of `model-mounting.mjs`.
- Moved model quantization parsing into `catalog-helpers.mjs` so catalog entries and local artifact metadata share one parser.
- Added `packages/runtime-daemon/src/model-mounting/provider-auth.mjs`.
- Moved provider secret input detection, vault ref sanitization, hosted-provider fail-closed checks, provider auth header normalization, and vault-backed provider header resolution out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/oauth-boundary.mjs`.
- Moved OAuth vault-ref construction, PKCE challenge generation, authorization URL redaction, token expiry/refresh predicates, public OAuth session/state projection, OAuth boundary projection, and token response validation out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs`.
- Moved configurable catalog provider checks, catalog provider config updates, source material vault binding, catalog auth scheme normalization, catalog auth header resolution, and request-time catalog auth header construction out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-provider-ports.mjs`.
- Moved fixture, local manifest, Ollama, Hugging Face, and custom HTTP catalog provider port construction plus catalog provider health helpers out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/protocol-responses.mjs`.
- Moved OpenAI chat/completions/responses/embeddings and Anthropic message response shaping plus deterministic embedding vector generation out of `model-mounting.mjs`, while preserving compatibility re-exports from `model-mounting.mjs`.

Status: `model-mounting.mjs` still owns provider drivers, wallet/vault ports, state machine behavior, routes, validation, and some product projection glue. Safe next extractions are provider registry/drivers, validation, routes, and state-machine slices.

### Rust Runtime Hot Spot

- Added `crates/services/src/agentic/runtime/service/decision_loop/retry_limits.rs`.
- Moved the explicit retry failure ceiling and terminal retry-limit status into a named helper module.
- Preserved the important contract: zero budget remains an unset budget and does not trip retry-limit failure before the consecutive-failure ceiling.

## Naming And Vocabulary Decisions

- Kept public/product names stable: Agent Studio command ids, `ioi.*` command ids, data-testids, daemon routes, and request/response envelopes were not renamed.
- Introduced private/module-level names that describe ownership boundaries:
  - `public-text-sanitizer`
  - `runtime-request-metadata`
  - `model-mounting/environment`
  - `model-mounting/provider-auth`
  - `model-mounting/oauth-boundary`
  - `model-mounting/catalog-provider-config`
  - `model-mounting/catalog-provider-ports`
  - `model-mounting/protocol-responses`
  - `decision_loop/retry_limits`
  - `live-gui-proof-harness`
- Deferred disruptive mass renames until after larger ownership modules are extracted and compatibility shims can be added deliberately.

## CLI/TUI Adapter Status

CLI/TUI surfaces were not hardened in this leg because the active parity-plus product proof path remains the OpenVSCode/Agent Studio GUI plus daemon runtime. The CLI/TUI adapters should stay separately gated unless they become active product commitments. If activated, they need the same stream/replay/redaction/policy/managed-session contract checks used by the GUI proof path.

## Remaining Follow-Ups

- Reduce `extension.js` further by moving Studio projection events, managed-session controls, panel lifecycle, and feature command groups.
- Reduce `packages/runtime-daemon/src/index.mjs` by extracting service lifecycle, route registration, thread store/control, replay, and managed-session state.
- Reduce `model-mounting.mjs` further by moving provider registry/drivers, wallet/vault ports, state machine, validation, and routes.
- Continue Rust hot-spot splits around final reply contract, tool outcome classification, finalize action processing, queue facts, filesystem handler, and substrate lifecycle.
- Run longer integrated sessions to watch for retry-limit regressions and replay/reconnect durability under real use.
- Keep watching the product UI for raw trace/tool/path leakage after every projection or panel lifecycle extraction.
