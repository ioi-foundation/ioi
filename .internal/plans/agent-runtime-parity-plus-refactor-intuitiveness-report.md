# Agent Runtime Parity Plus Refactor And Intuitiveness Report

Date: 2026-06-03

Scope: first refactor leg after the parity-plus audit guide. This pass prioritized behavior-preserving extractions that improve ownership boundaries without changing public command ids, request/response envelopes, data-testids, retry-limit semantics, or generated evidence handling.

## Completed Splits

### Live GUI Proof Harness

- Added `scripts/lib/live-gui-proof-harness/` with shared process, network, bridge, file, Playwright, screenshot, and cleanup helpers.
- Migrated Stage 8 managed-session reconnect proof and Stage 9 historic replay proof to the shared harness.
- Added checked-in Stage 9 replay fixtures so the live replay proof can run from a clean checkout without relying on ignored `docs/evidence` artifacts.
- Hardened the Stage 8 managed-session control click path to reacquire the Studio webview frame/card across VS Code webview swaps.
- Renamed the Stage 8 synthetic browser card from a spoof-like login-gate label to a manual authentication handoff fixture so the proof reads as operator-control state, not a fake approval surface.
- Renamed lingering private test/proof fixture ids and reasons from `login_gate` to `manual_auth_handoff`; public data-testids and response envelopes are unchanged.
- Kept generated proof outputs ignored under `docs/evidence/`.

### Agent Studio Workbench Extension

- Added `apps/autopilot/openvscode-extension/ioi-workbench/bridge/client.js` for daemon endpoint/token/base-url and JSON request helpers.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/public-text-sanitizer.js` for product-facing assistant/tool text sanitization.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-state.js` for the initial Agent Studio runtime projection shape.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/migration.js` for migration-assistant command registration.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/quick-input.js` for fork-native QuickInput handoff commands.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-managed-sessions.js` for managed browser/computer session projection, daemon inspection application, and reconnect proof bridge reporting.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-replay.js` for replay-step projection from runtime events and receipts.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/studio-test-hooks.js` for parity-plus/test-hook command registration while preserving public command ids.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/context-snapshot.js` for workbench context snapshots, SCM/task state, diagnostics, and inspection-target index projection.
- Kept compatibility wrappers in `extension.js` where existing tests or local call sites expect the old function names.

Status: `extension.js` is still a composition-heavy file and remains larger than the guide's ideal target. The safe next extractions are Studio projection events, remaining test hooks, panel lifecycle, and command grouping by Studio/workflows/models/runs.

### Runtime Daemon

- Added `packages/runtime-daemon/src/runtime-request-metadata.mjs`.
- Moved request base URL, runtime event cursor parsing, usage request metadata projection, and usage metadata application out of `index.mjs`.
- Passed `RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION` into the helper explicitly so the module stays decoupled from the daemon constants bundle.
- Added `packages/runtime-daemon/src/threads/thread-runtime-controls.mjs`.
- Moved thread mode/approval normalization, initial and normalized runtime controls, request control injection, model-control update shaping, model policy/workflow context projection, reasoning-effort normalization, and model route receipt binding out of `index.mjs`.
- Added `packages/runtime-daemon/src/threads/context-budget-policy.mjs`.
- Moved context-budget telemetry selection, threshold normalization, context-budget evaluation, coding-tool budget policy shaping, and compaction-policy decisions out of `index.mjs`.
- Added `packages/runtime-daemon/src/repository-context.mjs`.
- Moved read-only repository context projection, branch policy projection, GitHub remote context projection, workspace-trust warning projection, git porcelain counting, and remote credential redaction helpers out of `index.mjs`.
- Added focused repository-context tests for porcelain counting, GitHub remote redaction/metadata, read-only branch/GitHub policy projection, and UI trust override ignoring.
- Added `packages/runtime-daemon/src/http/public-runtime-routes.mjs`.
- Moved the public daemon HTTP request dispatcher, CORS preflight handling, top-level route table, delegated thread/agent/run route dispatch, MCP serve thread requirement, and public route error boundary out of `index.mjs`.
- Added focused public-runtime route tests for preflight, top-level daemon projection dispatch, delegated thread subroutes, and MCP serve validation.

Status: `index.mjs` still owns the large state store and public route composition. Safe next extractions are daemon service lifecycle, thread store/control/replay persistence, managed-session state, and route registration glue.

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
- Added `packages/runtime-daemon/src/model-mounting/provider-protocol.mjs`.
- Moved provider request body shaping, provider output extraction, usage normalization, public trace summarization, deterministic fixture text/token helpers, and safe truncation helpers out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/local-system-probes.mjs`.
- Moved public command execution wrappers, LM Studio CLI parsers/projections, local artifact inspection and metadata parsing, hardware snapshots, file readers, executable discovery, and native-local resource estimates out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/provider-driver-helpers.mjs`.
- Moved provider-kind driver mapping, default backend mapping, response-state protocol checks, and deterministic low-variance invocation coalescing helpers out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/load-policy.mjs`.
- Moved load-policy normalization, load-option normalization, runtime-engine default load options, TTL detection, LM Studio CLI load-argument shaping, and loaded-instance expiry calculation out of `model-mounting.mjs`.
- Added focused load-policy tests for string policies, snake/camel aliases, runtime-engine defaults, explicit TTL detection, expiration semantics, and LM Studio public CLI args.
- Added `packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs`.
- Moved native-local query extraction, deterministic native fixture output, native-local JSONL stream record shaping, JSONL stream construction, and deterministic stream delay handling out of `model-mounting.mjs`.
- Added focused native-local fixture tests for query extraction, deterministic embedding/mode output, stream records, stream abort handling, and bounded stream delay overrides.
- Added `packages/runtime-daemon/src/model-mounting/provider-transport.mjs`.
- Moved provider JSON/stream HTTP transport, provider-open retry operation recording, provider HTTP error shaping, and provider command error shaping out of `model-mounting.mjs`.
- Added focused provider-transport tests for local JSON fetch, tolerated HTTP failures, local-only endpoint rejection, provider error redaction, and command stderr hashing.
- Added `packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs`.
- Moved native-local and deterministic fixture provider driver classes out of `model-mounting.mjs`.
- Added focused provider-local-driver tests for fixture invocation, native-local load lifecycle, native-local JSONL streaming, and stream-abort backend logging.
- Added `packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.mjs`.
- Moved the OpenAI-compatible provider driver out of `model-mounting.mjs` while preserving the same driver dispatch seam for hosted-compatible, LM Studio, vLLM, and llama.cpp callers.
- Added focused OpenAI-compatible driver tests for model listing, chat completion invocation, and responses-to-chat fallback.
- Added `packages/runtime-daemon/src/model-mounting/provider-ollama-driver.mjs`.
- Moved the Ollama provider driver out of `model-mounting.mjs` while preserving the same driver dispatch seam.
- Added focused Ollama driver tests for model listing, loaded model projection, chat invocation, embedding invocation, and load/unload probes.
- Added `packages/runtime-daemon/src/model-mounting/provider-openai-backend-drivers.mjs`.
- Moved the vLLM and llama.cpp provider driver wrappers out of `model-mounting.mjs` while preserving the shared OpenAI-compatible driver composition.
- Added focused backend-driver tests for backend URL promotion, supervised load/unload evidence, and loaded instance projection.
- Added `packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs`.
- Moved the LM Studio public CLI provider driver out of `model-mounting.mjs` while preserving OpenAI-compatible invoke/stream composition.
- Added focused LM Studio driver tests for absent CLI fail-closed behavior and public CLI health/start/stop/load/unload lifecycle commands.
- Added `packages/runtime-daemon/src/model-mounting/wallet-authority.mjs`.
- Moved the Agentgres wallet authority capability grant/authorization/revocation adapter out of `model-mounting.mjs`.
- Added focused wallet authority tests for grant creation, authorization, policy denial, revocation, vault-ref redaction, and remote boundary status.
- Added `packages/runtime-daemon/src/model-mounting/vault-port.mjs`.
- Moved the Agentgres local vault port, encrypted keychain vault material adapter, env adapter factory, and vault-ref env alias helper out of `model-mounting.mjs`.
- Added focused vault port tests for encrypted persistence without plaintext, partial env fail-closed status, env alias resolution, public metadata redaction, audit redaction, bind/list/remove behavior, and non-persistent metadata serialization.

Status: `model-mounting.mjs` still owns provider driver classes, wallet/vault ports, state machine behavior, routes, validation, and some product projection glue. Safe next extractions are provider driver class groups, validation, routes, and state-machine slices.

### Rust Runtime Hot Spot

- Added `crates/services/src/agentic/runtime/service/decision_loop/retry_limits.rs`.
- Moved the explicit retry failure ceiling and terminal retry-limit status into a named helper module.
- Preserved the important contract: zero budget remains an unset budget and does not trip retry-limit failure before the consecutive-failure ceiling.

## Naming And Vocabulary Decisions

- Kept public/product names stable: Agent Studio command ids, `ioi.*` command ids, data-testids, daemon routes, and request/response envelopes were not renamed.
- Introduced private/module-level names that describe ownership boundaries:
  - `public-text-sanitizer`
  - `studio/projection-managed-sessions`
  - `studio/projection-replay`
  - `commands/studio-test-hooks`
  - `workbench/context-snapshot`
  - `runtime-request-metadata`
  - `threads/thread-runtime-controls`
  - `threads/context-budget-policy`
  - `repository-context`
  - `http/public-runtime-routes`
  - `model-mounting/environment`
  - `model-mounting/provider-auth`
  - `model-mounting/oauth-boundary`
  - `model-mounting/catalog-provider-config`
  - `model-mounting/catalog-provider-ports`
  - `model-mounting/protocol-responses`
  - `model-mounting/provider-protocol`
  - `model-mounting/local-system-probes`
  - `model-mounting/provider-driver-helpers`
  - `model-mounting/load-policy`
  - `model-mounting/native-local-fixture`
  - `model-mounting/provider-transport`
  - `model-mounting/provider-local-drivers`
  - `model-mounting/provider-openai-compatible-driver`
  - `model-mounting/provider-ollama-driver`
  - `model-mounting/provider-openai-backend-drivers`
  - `model-mounting/provider-lm-studio-driver`
  - `model-mounting/wallet-authority`
  - `model-mounting/vault-port`
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
