# LM Studio-Class Model Mounting Master Guide

Status: remaining-work closeout contract
Last updated: 2026-05-06

This guide is now intentionally pruned. It no longer serves as a historical
crawl transcript or progress journal. Its job is to define exactly what remains
before Autopilot can claim full LM Studio-class model mounting parity.

## Closure Standard

Do not call this guide complete until Autopilot satisfies the full live/product
standard below:

1. Autopilot can operate as its own model mounting workbench without LM Studio.
2. LM Studio remains a first-class provider through public `lms` and `/v1`
   surfaces only.
3. Native API, OpenAI-compatible API, Anthropic-compatible API, CLI, Mounts GUI,
   SDK, MCP, workflow nodes, wallet/vault, Agentgres projections, and receipts
   all use the same governed path:

```text
model capability -> route -> endpoint/provider/backend runtime
-> capability grant -> receipt
```

4. Deterministic fixture coverage remains green.
5. Live/product affordances are implemented and validated, not merely gated.
6. Any truly external dependency is isolated behind an explicit live command
   with exact setup instructions, evidence, and fail-closed behavior.

Deterministic fixture parity is useful, but it is not enough to close this
guide.

## Non-Negotiable Invariants

- Do not make LM Studio the underlying architecture.
- Do not treat "loaded model" as the top-level abstraction.
- Do not allow `/v1/*` compatibility endpoints to bypass IOI policy,
  capability grants, MCP governance, wallet/vault resolution, routing, or
  receipts.
- Do not persist plaintext provider secrets, OAuth tokens, MCP headers, bearer
  tokens, API keys, raw capability tokens, or raw authorization URLs.
- Do not rely on private LM Studio internal files as a stable contract.
- Do not call UI-only, docs-only, fixture-only, or test-stub behavior complete.
- Keep Mounts separate from Capabilities. Mounts may request capabilities, but
  it must not become the Capabilities surface.

## Current Baseline

The current deterministic Autopilot-native path is validated and should be
preserved while closing the live/product gaps.

Validated baseline:

- Mounts activity and dense workbench exist.
- Provider-neutral daemon model mounting subsystem exists.
- Fixture, native-local fixture, LM Studio fixture, llama.cpp, Ollama, vLLM,
  and OpenAI-compatible driver boundaries exist.
- LM Studio discovery and lifecycle use public `lms` commands and `/v1`.
- Native and OpenAI-compatible daemon APIs route through shared registry,
  router, token, MCP, and receipt paths.
- Capability token enforcement, MCP import/invoke, ephemeral MCP fixture paths,
  workflow contract endpoints, CLI commands, Agentgres-style local operation log,
  receipt lookup, and replay exist.
- Mounts desktop GUI validation exists, including OAuth consent controls and
  secret scans.

Latest useful evidence pointers:

- Deterministic model mounting E2E:
  `docs/evidence/model-mounting-e2e/2026-05-05T21-29-49Z/result.json`
- Standalone Mounts GUI validation:
  `docs/evidence/model-mounts-gui-validation/2026-05-06T18-43-40Z/result.json`
- Live LM Studio gate:
  `docs/evidence/model-mounting-live/lm-studio/2026-05-05T18-24-08Z/result.json`
- Live catalog tiny-GGUF gate:
  `docs/evidence/model-mounting-live/model-catalog/2026-05-05T23-07-13Z/result.json`
- Deterministic catalog OAuth fixture gate:
  `docs/evidence/model-mounting-live/model-catalog-oauth/2026-05-06T18-55-17Z/result.json`
- Live wallet boundary gate:
  `docs/evidence/model-mounting-live/wallet/2026-05-05T01-51-23Z/result.json`
- Live Agentgres boundary gate:
  `docs/evidence/model-mounting-live/agentgres/2026-05-05T01-51-23Z/result.json`

These evidence files prove the current baseline. They do not close the guide.

## LM Studio Primitives That Still Matter

Autopilot must match or exceed these observed LM Studio affordances while
preserving IOI-native architecture:

- Dedicated model workbench.
- Global model picker and loader.
- Installed model list with family, parameter count, architecture, size,
  quantization, device, and loaded marker.
- Loaded model list with identifier, status, size, context, parallelism,
  device, and TTL.
- Model search, direct URL import, variant selection, download, import, and
  storage management.
- Runtime engine selection, update/remove, hardware survey, GPU/context/
  parallel/TTL load options, and estimate-only behavior.
- Local server start/stop/status, background/headless service mode, logs, and
  OpenAI-compatible endpoints.
- Native local API, OpenAI-compatible API, Anthropic-compatible API where
  applicable, streaming, cancellation, and stateful continuation.
- Local API tokens and auth toggle ergonomics.
- `mcp.json`, persistent MCP servers, ephemeral per-request MCP integrations,
  and model tool exposure.
- Tokenization, count-tokens, context-fit helpers, benchmark telemetry, request
  logs, and developer diagnostics.
- Remote instance preference, hub artifact workflows, identity flows, and plugin
  development ergonomics.

## Remaining Implementation Work

### 1. Canonical Closeout Evidence And Guide Hygiene

Goal: create a fresh, final evidence bundle after all remaining work lands.

Required implementation:

- Add a single canonical closeout command or script that runs all deterministic
  gates, all configured live gates, GUI screenshot validation, secret scans, and
  projection/replay checks.
- Make the closeout command write one manifest that links every child evidence
  file and records skipped live gates with exact setup blockers.
- Update this guide only with current state, remaining work, and final evidence.
  Do not reintroduce long historical ledgers.
- Add a guide lint/check that fails if the guide claims closure while any
  required live/product gate is skipped, blocked, or stale.

Acceptance:

- A final evidence manifest exists under `docs/evidence/model-mounting-closeout/`.
- The manifest includes GUI screenshots, CLI/API results, live backend results,
  wallet/Agentgres results, secret scan results, and restart replay evidence.
- The guide has no obsolete phase ledger or stale completion claims.

### 2. Compatibility Surface Parity

Goal: make native, OpenAI-compatible, and Anthropic-compatible surfaces feel
complete for real developer clients.

Required implementation:

- Implement true token streaming for:
  - `POST /api/v1/chat`
  - `POST /v1/responses`
  - `POST /v1/chat/completions`
  - `POST /v1/messages`
- Emit stream lifecycle receipts for:
  - stream opened;
  - first token / first output event;
  - prompt processing complete where available;
  - model load wait where available;
  - client cancellation;
  - upstream cancellation;
  - stream completed;
  - provider error.
- Implement stateful continuation for native chat and Responses:
  - `response_id`;
  - `previous_response_id`;
  - persisted conversation state reference;
  - redacted replay;
  - policy-preserving continuation across route fallback.
- Add per-request context controls:
  - context length;
  - truncation policy;
  - tool-use policy;
  - system prompt policy;
  - max input token guard.
- Add tokenizer/count-tokens/context-fit APIs:
  - `POST /api/v1/tokenize`
  - `POST /api/v1/tokens/count`
  - `POST /api/v1/context/fit`
  - OpenAI/Anthropic compatible helper mapping where useful.
- Add SDK and CLI support:
  - `ioi tokens count`
  - `ioi models tokenize`
  - `ioi models context-fit`
  - SDK helpers backed by selected backend or deterministic estimator.
- Extend invocation receipts with:
  - TTFT;
  - tokens per second;
  - generation time;
  - prompt token count;
  - completion token count;
  - stop reason;
  - runtime name/version;
  - backend health snapshot id;
  - selected model metadata;
  - stream event count;
  - cancellation reason where present.
- Improve OpenAI-compatible error shapes without leaking internal policy detail.
- Implement tool-output submission and advanced Responses state needed by
  external clients.
- Expand Anthropic `/v1/messages` compatibility:
  - richer content blocks;
  - provider-native token streaming;
  - tool-use metadata;
  - upstream cancellation;
  - redacted errors.

Acceptance:

- Streaming clients can consume native, OpenAI-compatible, and Anthropic-style
  streams from fixture and at least one live backend.
- Cancellation receipts are visible in API, CLI, GUI, Agentgres replay, and
  workflow run inspection.
- Tokenization/context-fit works against live backends where supported and
  deterministic estimators elsewhere.

### 3. Live Backend Parity

Goal: validate that Autopilot can serve and govern real local model runtimes
with LM Studio-class ergonomics.

Required implementation:

- Keep deterministic backend fixtures as CI baseline.
- Complete live validation for:
  - llama.cpp chat, Responses fallback, streaming, cancellation, unload, logs,
    embeddings with compatible setup, replay, and redaction;
  - Ollama chat, embeddings, streaming, cancellation, loaded-state projection,
    keep-alive unload, replay, and redaction;
  - vLLM chat, Responses fallback, embeddings, streaming, cancellation, loaded
    projection, replay, and redaction.
- Add memory-pressure eviction:
  - hardware survey;
  - model memory estimate;
  - active instance accounting;
  - evictable instance selection;
  - receipt for eviction decision and execution;
  - GUI indication of pressure and evictions.
- Add backend-specific schedulers:
  - default runtime selection;
  - GPU preference;
  - CPU fallback;
  - context defaults;
  - parallel defaults;
  - TTL defaults;
  - estimate-only path;
  - retry/backoff by backend class.
- Add live backend log streaming:
  - bounded raw log tail;
  - redacted argv/env;
  - process status;
  - stale process detection;
  - reconnect/resume where supported.
- Add vLLM live gate setup that works with either:
  - `VLLM_BASE_URL`, or
  - `IOI_VLLM_BINARY`/`vllm` plus `IOI_VLLM_MODEL`.
- Keep live gates opt-in, but do not call parity closed until they pass on an
  operator machine with evidence.

Acceptance:

- Ollama, llama.cpp, and vLLM live gates pass or have a documented hardware
  exclusion approved by product leadership.
- At least one real native backend proves embeddings, streaming, cancellation,
  logs, load/unload, receipts, replay, and GUI reflection.
- vLLM is no longer merely an absent/config blocked path.

### 4. Catalog And Download Production Parity

Goal: make model discovery, download, import, cleanup, and storage management
product-ready.

Required implementation:

- Expand external hub coverage:
  - Hugging Face-compatible search;
  - direct artifact URL;
  - manifest catalog;
  - custom HTTP catalog;
  - Ollama list bridge;
  - future provider hooks.
- Add richer metadata:
  - model family;
  - parameter count;
  - architecture;
  - quantization;
  - file format;
  - license;
  - safety/risk class;
  - context hints;
  - tokenizer hints;
  - embedding/rerank/vision support;
  - backend compatibility score;
  - benchmark readiness.
- Harden download lifecycle:
  - retry/resume policy;
  - bandwidth limits;
  - checksum verification;
  - partial cleanup;
  - poisoned artifact quarantine;
  - confirmed cancel cleanup;
  - orphan scan and removal;
  - storage quota;
  - uninstall confirmation and undo window where possible.
- Harden OAuth/catalog auth:
  - app-specific OAuth scopes;
  - signed installer redirect registration validation;
  - provider-specific OAuth templates;
  - external provider callback validation with real credentials;
  - token refresh/revoke evidence;
  - no raw auth URLs or codes in evidence.
- Add product GUI polish:
  - variant chooser;
  - compatibility filters;
  - download risk summary;
  - download progress and retry;
  - storage usage;
  - destructive action confirmation;
  - receipt drill-down.

Acceptance:

- At least one external hub live flow completes search, authorization if needed,
  download/import, checksum, mount, load, invoke, receipt, replay, GUI display,
  and cleanup.
- Storage quota and destructive cleanup flows are validated by GUI screenshots.
- OAuth deep-link/signed redirect behavior is validated outside fixture mode.

### 5. Production Wallet.Network, Vault, And Agentgres

Goal: move from local/fake boundaries to production-grade IOI persistence,
authority, and replay.

Required wallet/vault implementation:

- Complete remote `WalletAuthorityPort`:
  - `createGrant`;
  - `authorizeScope`;
  - `revokeGrant`;
  - `resolveVaultRef`;
  - `auditEvent`;
  - `recordLastUsed`;
  - cross-device revocation;
  - grant propagation;
  - audit receipt export.
- Complete remote `VaultPort`:
  - provider key refs;
  - MCP header refs;
  - OAuth token refs;
  - BYOK refs;
  - custom HTTP auth refs;
  - redacted resolution evidence.
- Enforce wallet/vault across:
  - native API;
  - `/v1/*`;
  - CLI;
  - GUI;
  - workflow nodes;
  - persistent MCP;
  - ephemeral MCP;
  - provider/catelog auth.

Required Agentgres implementation:

- Complete remote `AgentgresModelMountingStorePort`:
  - append operation log;
  - project canonical model mounting state;
  - replay receipt by id;
  - replay route selection;
  - replay invocation;
  - replay tool receipt;
  - replay lifecycle event;
  - replay workflow run bindings;
  - sync remote projections;
  - settlement/audit pack integration.
- Persist and project:
  - artifacts;
  - endpoints;
  - providers;
  - backends;
  - instances;
  - routes;
  - downloads;
  - grants;
  - vault refs;
  - MCP registrations;
  - lifecycle events;
  - route receipts;
  - invocation receipts;
  - tool receipts;
  - workflow node bindings;
  - workflow run receipt links.

Acceptance:

- Remote wallet and Agentgres live gates pass with no plaintext leakage.
- Cross-device revocation changes authorization outcome without daemon restart.
- Remote replay agrees with local projection after restart.
- Audit/settlement pack contains redacted model mounting receipts.

### 6. MCP Production Lifecycle

Goal: make MCP integration product-complete for persistent and ephemeral use.

Required implementation:

- Complete stdio MCP lifecycle:
  - spawn;
  - health;
  - schema discovery;
  - bounded logs;
  - restart;
  - stop;
  - stale process detection;
  - receipts.
- Complete remote MCP lifecycle:
  - health validation;
  - OAuth-capable auth boundary;
  - vault-ref headers only;
  - schema discovery;
  - allowed-tools narrowing;
  - provider error redaction.
- Complete ephemeral MCP parity in `chat` and `responses` payloads:
  - remote and stdio integrations;
  - vault-only headers;
  - allowed tool narrowing;
  - registration receipt;
  - tool invocation receipt;
  - linked model invocation receipt.
- Add model tool exposure:
  - tool schema projection into model request;
  - tool-call response parsing;
  - tool-output submission;
  - multi-turn tool continuation;
  - denied tool receipts.
- Add GUI controls:
  - import;
  - validate;
  - start/stop stdio server;
  - OAuth connect/revoke;
  - allowed tool editor;
  - test call;
  - tool receipt detail.

Acceptance:

- Persistent and ephemeral MCP flows pass through the same governed runtime
  contract.
- Denied, missing, malformed, and disallowed tools fail closed.
- Tool receipts are linked to model receipts and visible in GUI/CLI/replay.

### 7. Workflow Canvas And Harness Product UX

Goal: make workflow model mounting a real operator surface, not just daemon
contract endpoints.

Required implementation:

- Add visual node forms for:
  - Model Router;
  - Model Call;
  - Structured Output;
  - Planner;
  - Verifier;
  - Embedding;
  - Reranker;
  - Vision;
  - Local Tool/MCP;
  - Receipt Gate.
- Add node fields:
  - `model_id`;
  - `route_id`;
  - `model_policy`;
  - `capability`;
  - `receipt_required`;
  - `required_tool_receipt_ids`;
  - `redaction_class`;
  - `selected_endpoint`;
  - `selected_backend`;
  - continuation state reference where relevant.
- Add Receipt Gate UI:
  - required receipt id;
  - route match;
  - model match;
  - endpoint match;
  - backend match;
  - redaction class match;
  - tool receipt match;
  - workflow run linkage match.
- Add harness replay/inspection:
  - run id;
  - route decision;
  - model invocation;
  - MCP tool receipt;
  - gate pass/fail;
  - replay after daemon restart.
- Add GUI screenshots for node configuration and Receipt Gate replay.

Acceptance:

- A visual workflow can route, invoke, use MCP, emit receipts, gate on receipts,
  fail on mismatches, pass on valid receipts, restart, and replay.
- The same state is visible through API, CLI, GUI, SDK, and Agentgres replay.

### 8. Provider And Product Expansion

Goal: make provider support production credible beyond local fixtures.

Required implementation:

- OpenAI BYOK:
  - vault-ref key only;
  - chat;
  - Responses;
  - embeddings;
  - streaming;
  - cancellation;
  - redacted provider errors;
  - route/cost policy.
- Anthropic BYOK:
  - vault-ref key only;
  - messages;
  - streaming;
  - cancellation;
  - tool-use metadata;
  - redacted provider errors;
  - route/cost policy.
- Gemini BYOK:
  - vault-ref key only;
  - model list;
  - generation;
  - embeddings where available;
  - streaming where available;
  - redacted provider errors;
  - route/cost policy.
- Custom HTTP:
  - vault-ref auth;
  - configurable health endpoint;
  - OpenAI-compatible mode;
  - native JSON mode;
  - request/response schema mapping;
  - fail-closed auth behavior.
- DePIN/TEE:
  - provider profile;
  - attestation requirement;
  - attestation verification;
  - fail-closed routing;
  - attestation receipt;
  - wallet/network grant linkage.
- Remote instance preference:
  - trust model;
  - health;
  - capability discovery;
  - routing preference;
  - revocation;
  - receipts.

Acceptance:

- BYOK providers work with vault refs and no plaintext leakage.
- Custom HTTP can be configured from GUI/API/CLI and fails closed when auth is
  missing or invalid.
- DePIN/TEE routes refuse invocation without valid attestation.
- Remote instance preferences affect routing and are receipted.

### 9. Adjacent LM Studio-Class Developer Primitives

Goal: close the remaining product affordances users expect from a model
mounting workbench.

Required implementation:

- Artifact workflows:
  - clone;
  - push;
  - publish;
  - provenance receipt;
  - model card/metadata editing;
  - IOI artifact registry integration;
  - marketplace handoff where appropriate.
- Identity flows:
  - login;
  - logout;
  - whoami;
  - wallet.network account linkage;
  - scoped session display;
  - audit receipts.
- Plugin development:
  - plugin/dev-server workflow mapped to IOI Tool Registry;
  - MCP harness developer mode;
  - logs;
  - hot reload where feasible;
  - receipts.
- Document/RAG integration decision:
  - either explicitly delegate RAG to workflow/tool surfaces, or
  - add Mounts-owned local RAG index bindings.
- If RAG is added to Mounts, implement:
  - document import;
  - chunking;
  - embedding route;
  - vector store selection;
  - query;
  - receipts for embed/index/query;
  - storage cleanup.
- Benchmarks/evals:
  - scheduled benchmark runs;
  - comparative charts;
  - route recommendation receipts;
  - quality/cost/latency history;
  - model compatibility warnings.
- Headless/service packaging:
  - user service install;
  - start on login;
  - health checks;
  - restart policy;
  - log rotation;
  - production daemon status in GUI.

Acceptance:

- Artifact, identity, plugin-dev, benchmark, and service-mode flows are either
  implemented or explicitly assigned to another IOI surface with receipts and
  product sign-off.
- If delegated, Mounts still shows enough integration state for model operators
  to understand availability, risk, and receipts.

## Required Public Interfaces

These interfaces must remain policy-governed and receipt-producing.

Native API:

```text
GET  /api/v1/server/status
POST /api/v1/server/start
POST /api/v1/server/stop
GET  /api/v1/backends
POST /api/v1/backends/:id/health
POST /api/v1/backends/:id/start
POST /api/v1/backends/:id/stop
GET  /api/v1/backends/:id/logs
GET  /api/v1/models
GET  /api/v1/models/:id
POST /api/v1/models/import
POST /api/v1/models/download
POST /api/v1/models/download/:job_id/cancel
GET  /api/v1/models/download/status/:job_id
POST /api/v1/models/mount
POST /api/v1/models/unmount
POST /api/v1/models/load
POST /api/v1/models/unload
GET  /api/v1/models/loaded
GET  /api/v1/providers
POST /api/v1/providers
PATCH /api/v1/providers/:id
POST /api/v1/providers/:id/health
GET  /api/v1/providers/:id/models
GET  /api/v1/providers/:id/loaded
POST /api/v1/providers/:id/start
POST /api/v1/providers/:id/stop
GET  /api/v1/routes
POST /api/v1/routes
POST /api/v1/routes/:id/test
POST /api/v1/chat
POST /api/v1/responses
POST /api/v1/embeddings
POST /api/v1/rerank
POST /api/v1/tokenize
POST /api/v1/tokens/count
POST /api/v1/context/fit
GET  /api/v1/mcp
POST /api/v1/mcp/import
POST /api/v1/mcp/invoke
POST /api/v1/workflows/nodes/execute
POST /api/v1/workflows/receipt-gate
GET  /api/v1/tokens
POST /api/v1/tokens
DELETE /api/v1/tokens/:id
GET  /api/v1/receipts
GET  /api/v1/receipts/:id
GET  /api/v1/receipts/:id/replay
```

Compatibility APIs:

```text
GET  /v1/models
POST /v1/responses
POST /v1/chat/completions
POST /v1/embeddings
POST /v1/completions
POST /v1/messages
```

CLI:

```text
ioi backends ls|health|start|stop|logs
ioi models ls|get|import|download|cancel-download|mount|load|unload|ps
ioi models provider-models|provider-loaded|tokenize|context-fit
ioi routes ls|test
ioi server start|stop|status
ioi mcp ls|import|validate|invoke|start|stop|schema
ioi tokens create|revoke|ls|count
ioi receipts ls|get|replay
ioi wallet login|logout|whoami
ioi artifacts clone|push|publish
```

SDK contracts:

```text
ModelBackend
ModelBackendDriverState
ModelHardwareEstimate
ModelArtifactMetadata
ModelDownloadJob
ModelMountingEvent
ModelProviderProfile
ModelRoute
WalletGrant
VaultRef
ModelInvocationReceipt
RouteSelectionReceipt
ToolInvocationReceipt
WorkflowReceiptGateResult
TokenizerResult
ContextFitResult
RuntimeTelemetry
RemoteInstanceProfile
AttestationReceipt
```

## Validation Gates Required For Closure

Deterministic gates:

```bash
npm run test:model-mounting
npm run test:daemon-runtime-api
npm test --workspace=@ioi/agent-sdk
npm run test:model-backends
npm run test:model-mounting-workflows
npm run test:model-mounting-gui
npm run validate:model-mounting:e2e
npm run validate:model-mounts-gui:run
AUTOPILOT_LOCAL_GPU_DEV=1 npm run validate:autopilot-gui-harness:run -- --window-timeout-ms 300000
npx tsc -p apps/autopilot/tsconfig.json --noEmit
npm run build --workspace=apps/autopilot
npm run build --workspace=@ioi/agent-ide
cargo check -p ioi-cli --bin cli
cargo build -p ioi-cli --bin cli
git diff --check
```

Live gates:

```bash
IOI_LIVE_LM_STUDIO=1 npm run test:lm-studio-live
IOI_LIVE_LLAMA_CPP=1 npm run test:llama-cpp-live
IOI_LIVE_MODEL_BACKENDS=1 npm run test:model-backends:live
IOI_LIVE_MODEL_CATALOG=1 npm run test:model-catalog-live
IOI_LIVE_MODEL_CATALOG_OAUTH=1 npm run test:model-catalog-oauth-live
IOI_REMOTE_WALLET=1 npm run test:wallet-live
IOI_REMOTE_AGENTGRES=1 npm run test:agentgres-live
```

Fixture fallback gates that must remain green:

```bash
IOI_LIVE_MODEL_CATALOG_OAUTH=1 IOI_MODEL_CATALOG_OAUTH_FIXTURE=1 npm run test:model-catalog-oauth-live
```

Closure requires passing live gates, not just skipped evidence, unless product
leadership explicitly accepts a hardware/service exclusion in the final
closeout manifest.

## End-To-End Closeout Scenario

The final scenario must prove GUI, CLI, API, SDK, registry, router, token, MCP,
workflow, local-native provider, LM Studio provider, live backends, wallet,
Agentgres, and receipts agree.

Required flow:

1. Start daemon against a fresh state directory.
2. Discover providers, backends, hardware, runtime engines, and remote
   instances.
3. Import or download at least one deterministic local model artifact.
4. Search and download from at least one live catalog provider.
5. Complete at least one OAuth-backed catalog flow outside fixture mode.
6. Mount local-native, LM Studio, Ollama, llama.cpp, vLLM, OpenAI-compatible,
   and BYOK/custom provider endpoints where configured.
7. Load local-native and at least two live backends.
8. Call native chat, Responses, embeddings, rerank, tokenize, token count, and
   context-fit.
9. Call OpenAI-compatible chat completions, Responses, embeddings, completions,
   and Anthropic-compatible messages.
10. Validate true streaming and cancellation on native and compatibility
    surfaces.
11. Import persistent `mcp.json`.
12. Run ephemeral MCP inside chat/Responses payloads.
13. Validate stdio MCP lifecycle and remote MCP OAuth boundary.
14. Verify tool receipts link to model invocation receipts.
15. Create scoped capability grants and verify allowed, denied, expired,
    revoked, malformed, and audience-mismatched outcomes.
16. Create and test route policies for privacy, cost, latency, provider
    eligibility, fallback, and remote instance preference.
17. Execute visual workflow nodes for Model Router, Model Call, Embedding,
    Local Tool/MCP, and Receipt Gate.
18. Verify Receipt Gate blocks mismatched receipts and passes valid receipts.
19. Verify Mounts GUI shows the same state with screenshots.
20. Verify CLI and SDK see the same state.
21. Restart daemon from the same state directory.
22. Verify local projection, remote Agentgres projection, and replay by receipt
    id remain stable.
23. Scan persisted state, logs, receipts, CLI output, UI fixtures, and
    screenshots for plaintext secrets.
24. Write the final closeout manifest.

## Final Definition Of Done

This guide can be closed only when all of the following are true:

- The nine remaining implementation areas above are implemented or explicitly
  product-delegated with receipts and acceptance evidence.
- All deterministic gates pass.
- All required live gates pass or have accepted hardware/service exclusions.
- Mounts GUI has desktop and compact screenshots for the final state.
- Native, OpenAI-compatible, and Anthropic-compatible APIs share the same
  policy/capability/MCP/receipt path.
- Token streaming, cancellation, stateful continuation, tokenizer/context
  helpers, and runtime telemetry are implemented and receipted.
- Real local backends and provider adapters have live evidence.
- Catalog search/download/import/OAuth/storage cleanup has live evidence.
- Remote wallet.network/vault and Agentgres replay have live evidence.
- MCP persistent and ephemeral lifecycles are product-complete.
- Workflow canvas/harness has visual configuration, execution, gating, replay,
  and screenshots.
- No plaintext secrets appear in persisted state, logs, receipts, CLI output,
  source fixtures, evidence, or screenshots.

Until then, the correct status is:

```text
Deterministic Autopilot-native model mounting path: validated.
LM Studio-class live/product parity: not closed.
```
