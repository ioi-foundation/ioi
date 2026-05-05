# LM Studio Model Mounting Master Guide

Status: reference crawl, implementation guide, current completion ledger, and parity gap audit
Audit date: 2026-05-05
Reference app: locally installed LM Studio AppImage, observed as `0.4.12+1`
Reference scope: UX ergonomics, local server contract, model lifecycle, MCP, API tokens, TTL/auto-evict, CLI, Anthropic/OpenAI compatibility, tokenization/stats, LM Link, hub/plugin workflows, and local runtime state

## Executive Verdict

LM Studio is the right ergonomic reference for Autopilot's model mounting
surface, but it should not become Autopilot's model architecture or exclusive
runtime dependency.

The useful LM Studio pattern is:

```text
developer opens a local model surface
selects/downloads/loads a model
starts a local server
uses REST or OpenAI-compatible endpoints
optionally adds MCP servers and API tokens
models are unloaded manually or by idle TTL / auto-evict
```

The Autopilot target is:

```text
LM Studio-like UX
-> Autopilot Model Registry
-> Model Router
-> wallet.network permission/capability layer
-> IOI daemon runtime
-> Agentgres receipts/state
-> workflow canvas and harness nodes
```

In other words, Autopilot should borrow the developer experience: model picker,
local server, loaded models, download/load/unload lifecycle, permission tokens,
MCP configuration, logs, and TTL controls. Internally, the core abstraction must
be provider-neutral model capability routing, not a single "loaded local model"
slot.

The product direction is stronger than "integrate LM Studio":

```text
support LM Studio as one provider
and make Autopilot itself an LM Studio-class model mounting workbench
```

That means Autopilot must eventually provide the same developer primitives
without requiring LM Studio:

- local model catalog and import/download lifecycle;
- local server and OpenAI-compatible endpoints;
- model load/unload/TTL/auto-evict controls;
- provider health and routing;
- scoped API tokens;
- MCP configuration and per-request tools;
- dense desktop UI, CLI, logs, and receipts.

LM Studio remains valuable in two roles:

1. Reference UX and API ergonomics.
2. A first-class provider driver for users who already have LM Studio managing
   local GGUF models.

Autopilot owns the registry, router, permission model, receipts, workflow
bindings, and durable state. When an LM Studio endpoint is selected, Autopilot
may delegate physical model load/inference to public LM Studio surfaces
(`lms` and `/v1`), but LM Studio is not the core mounting abstraction.

## Current Implementation Status

Updated: 2026-05-05

### Canonical Completion Ledger

The deterministic Autopilot-native model mounting target path is implemented
and validated end to end. This means Autopilot can operate as its own
LM Studio-class IOI-native model mounting workbench without requiring LM
Studio for the validated local path. LM Studio remains supported as one
provider driver and ergonomic reference, not the underlying architecture.

Canonical validation command:

```text
npm run validate:model-mounting:e2e
```

Latest deterministic evidence bundle:

```text
docs/evidence/model-mounting-e2e/2026-05-05T21-29-49Z/result.json
```

That bundle passed the following acceptance steps in a GUI-skipped deterministic
acceptance run:

- fresh daemon startup with isolated model mounting state;
- fail-closed missing, denied, expired, and revoked token behavior;
- provider/backend discovery for fixture, native-local, LM Studio,
  OpenAI-compatible, llama.cpp, Ollama, vLLM, hosted/BYOK profiles, custom
  HTTP, and DePIN/TEE profile boundaries;
- runtime engine inventory and redacted hardware survey across the Autopilot
  backend registry plus public LM Studio `lms runtime ls/survey` when present;
- selected runtime preference and load-option parity for estimate-only, GPU,
  context length, parallelism, TTL, and identifier across API, CLI, receipts,
  and Mounts controls;
- runtime engine profile parity for get/update/remove, disable/enable,
  operator labels, priority, and default GPU/context/parallel/TTL/identifier
  load options flowing into later model load estimates;
- deterministic backend process supervisor parity for native-local loads,
  including process records, PID hashes, redacted argv, startup-timeout evidence,
  bounded backend logs, stale process detection after daemon restart, and linked
  load/invocation receipts;
- always-reachable Mounts model picker/loader for choosing artifact, provider,
  endpoint, route, and loaded instance through governed load/unload APIs;
- loaded-instance inspector with backend, context, TTL, route, and linked
  receipt evidence in the Mounts desktop GUI;
- selected model detail drawer with artifact metadata, runtime binding,
  lifecycle history, and linked receipt trail in the Mounts desktop GUI;
- route editor for privacy, quality, cost ceiling, latency target, fallback,
  provider eligibility, denied providers, and governed save/test actions;
- token scope editor for audience, expiry, allowed scopes, denied scopes,
  grant metadata, revocation, last-used scope, audit receipts, vault refs, and
  session-only raw token handling;
- deterministic native-local artifact import, mount, load, and invocation;
- native `/api/v1/chat` and `/api/v1/responses`;
- OpenAI-compatible `/v1/chat/completions` and `/v1/embeddings`;
- completed and client-aborted provider-native streams through the
  OpenAI-compatible API, with stream receipts linked to invocation receipts;
- local server stop/restart, redacted log tail, event tail, CLI parity, and
  lifecycle receipts;
- Mounts streaming observability filters for request/response direction,
  category, status, receipt kind, route/endpoint/provider search, live refresh,
  redacted payload preview, server log tail, and replay links;
- deterministic catalog search, URL import, import dry-run/copy modes, storage
  cleanup scan, artifact delete, and download cancel/completion lifecycle;
- gated Hugging Face-compatible catalog search/download activation with
  GGUF/MLX/safetensors format filters, quantization filters, source URL
  hashing, resumable `.part` materialization, checksum verification, storage
  quota summary, and secret redaction;
- persistent `mcp.json` import and governed MCP tool invocation;
- per-request ephemeral MCP integration linked into model invocation receipts;
- route policy creation/test and workflow node execution;
- Receipt Gate blocked mismatch and passed valid linked receipts;
- CLI agreement with the same daemon state for server, backends, runtime
  survey/selection, model load options, routes, MCP, tokens, receipts, and
  replay;
- CLI receipt lookup and replay parity for completed and canceled provider-native
  stream receipts;
- daemon restart with Agentgres-style projection/replay continuity;
- restart projection/replay continuity for completed and canceled stream
  receipts;
- Mounts desktop GUI screenshot bundle with nine real window captures;
- benchmark/results panel with routed benchmark runner, route-quality
  telemetry, latency, token count, backend, endpoint, grant, and receipt rows;
- action readiness and degraded/denied affordances for daemon connectivity,
  token scope, provider/backend health, endpoint capability, route policy, and
  vault-ref requirements;
- secret/token/vault-ref redaction scan across persisted state and evidence.

The current GUI evidence nested under that E2E bundle is:

```text
docs/evidence/model-mounting-e2e/2026-05-05T14-38-24Z/gui/2026-05-05T14-38-55Z/result.json
```

The current standalone Mounts GUI evidence bundle is:

```text
docs/evidence/model-mounts-gui-validation/2026-05-05T21-09-24Z/result.json
```

It captured all Mounts tabs as desktop window screenshots:

- Local Server;
- Backends;
- Models;
- Providers;
- Downloads;
- Tokens & MCP;
- Routing Policies;
- Benchmarks;
- Logs / Receipts.

That standalone GUI bundle also validates the product controls that were still
being closed after the canonical E2E evidence:

- provider and backend health/start/stop/model-list/loaded-list/log controls;
- download open-receipt, cancel, retry, failure, and lifecycle receipt actions;
- token create/revoke, vault health, persistent MCP import, and ephemeral MCP
  model invocation linkage;
- route test, route draft test, workflow probe, Receipt Gate pass, and Receipt
  Gate block actions;
- model import, mount, load, unload, detail drawer metadata, receipt lookup, and
  receipt replay;
- benchmark run, benchmark receipt replay, and benchmark receipt focus in the
  Logs / Receipts surface.
- Mounts-triggered provider-native stream lifecycle probe, including a completed
  chat-completions stream, an intentionally aborted Responses stream, linked
  invocation receipts, projection visibility, and Logs / Receipts screenshot
  evidence.

Treat the deterministic path as complete unless a future change breaks the
canonical command above. Remaining items are live-provider activation,
production hardening, or richer product UX around the validated path.

Live-only validation gates are executable but opt-in. They write evidence under
`docs/evidence/model-mounting-live/*` and must not be treated as CI blockers
unless the corresponding environment flag is explicitly set:

```text
IOI_LIVE_LM_STUDIO=1 npm run test:lm-studio-live
IOI_LIVE_LLAMA_CPP=1 \
  IOI_LLAMA_CPP_SERVER_PATH=/path/to/llama-server \
  IOI_LLAMA_CPP_MODEL_PATH=/path/to/model.gguf \
  npm run test:llama-cpp-live
IOI_LIVE_MODEL_BACKENDS=1 \
  OLLAMA_HOST=http://127.0.0.1:11434 \
  IOI_OLLAMA_CHAT_MODEL=llama3.2:3b \
  IOI_OLLAMA_EMBEDDING_MODEL=nomic-embed-text:latest \
  npm run test:model-backends:live
IOI_LIVE_MODEL_CATALOG=1 npm run test:model-catalog-live
IOI_REMOTE_WALLET=1 npm run test:wallet-live
IOI_REMOTE_AGENTGRES=1 npm run test:agentgres-live
```

The model catalog live gate performs safe live catalog search by default. It
only attempts a network model download when `IOI_LIVE_MODEL_DOWNLOAD=1` plus
either `IOI_MODEL_CATALOG_DOWNLOAD_SOURCE_URL=<explicit URL>` or
`IOI_MODEL_CATALOG_DOWNLOAD_FIRST_RESULT=1` are supplied. Operators can bound
the transfer with `IOI_MODEL_CATALOG_DOWNLOAD_MAX_BYTES` or
`IOI_MODEL_DOWNLOAD_MAX_BYTES`; the gate validates download status, receipt
replay, projection persistence, and secret redaction.

If a live dependency is not configured or is stopped, provider gates record a
truthful `skipped` or `blocked` result instead of pretending live validation
occurred. The wallet.network and Agentgres gates also include deterministic
fake-remote mode when real URLs are absent, so the adapter-boundary,
fail-closed, replay, and redaction contracts can still be validated locally.

Latest live backend stream parity evidence:

```text
docs/evidence/model-mounting-live/model-backends/2026-05-05T22-09-26Z/result.json
```

That run passed against local Ollama with
`OLLAMA_HOST=http://127.0.0.1:11434`,
`IOI_OLLAMA_CHAT_MODEL=llama3.2:3b`, and
`IOI_OLLAMA_EMBEDDING_MODEL=nomic-embed-text:latest`. It validated provider
discovery, mount/load/unload, chat, embeddings, completed provider-native
stream receipts, client-aborted provider-native stream receipts, receipt replay,
and secret redaction against a real local backend rather than a fixture.

### Completed In Repo

The current implementation has moved beyond the original blank Mounts scaffold.
These areas are implemented and covered by focused tests:

- Mounts activity bar entry and live Mounts workbench UI.
- Provider-neutral runtime model mounting subsystem in the JS IOI daemon.
- Shared TypeScript contracts for model artifacts, endpoints, instances,
  providers, routes, tokens, downloads, receipts, and workflow bindings.
- `ModelProviderDriver`-style port with drivers for:
  - deterministic fixture provider;
  - Autopilot native-local provider;
  - LM Studio provider;
  - generic OpenAI-compatible provider.
- Autopilot-owned native-local deterministic serving path that mounts, loads,
  invokes, logs, and receipts a local model artifact without LM Studio.
- IOI state model artifact root with deterministic native-local fixture
  artifact and local-path import support.
- Minimal GGUF-style metadata extraction for family, quantization, format,
  size, checksum, and context where present.
- LM Studio discovery through guarded public commands:
  - `lms server status`;
  - `lms ls`;
  - `lms ps`.
- LM Studio lifecycle delegation through public commands:
  - `lms load <model_id>`;
  - `lms unload <model_id>`;
  - provider start/stop hooks for `lms server start|stop`.
- LM Studio inference delegation through its local OpenAI-compatible `/v1`
  server when an LM Studio endpoint is explicitly selected.
- `/v1/responses` fallback to chat completions for LM Studio-compatible servers
  that do not expose Responses, with `compatTranslation:
  chat_completions` recorded in the model receipt.
- Native API surface for server status, model registry, mount/load/unload,
  provider model/loaded state, import/download/cancel/status, providers,
  routes, chat/responses/embeddings/rerank, tokens, MCP, projections, workflow
  node execution, Receipt Gate, and receipts.
- OpenAI-compatible API surface for models, responses, chat completions,
  embeddings, and completions.
- Capability token enforcement for native and OpenAI-compatible calls,
  including missing, denied, expired, and revoked token behavior.
- Agentgres-shaped model mounting store boundary backed by repo-local durable
  state and operation-log receipts.
- wallet.network-shaped authority boundary backed by Agentgres-style grant
  records, revocation epoch, vault refs, last-used tracking, redacted public
  surfaces, and audit operations.
- `mcp.json` import, remote MCP registration, `allowed_tools` narrowing,
  governed MCP invocation, secret redaction, and tool receipts.
- Per-request ephemeral MCP integrations in native chat/responses payloads,
  compiled into the same governed MCP/tool receipt path and linked from model
  invocation receipts.
- Route selection receipts and model invocation receipts across native,
  compatibility, and workflow execution paths.
- Canonical model mounting projection and receipt replay API for artifacts,
  endpoints, instances, routes, providers, downloads, grants, MCP records,
  workflow bindings, lifecycle receipts, route receipts, invocation receipts,
  and tool receipts.
- Workflow execution contract endpoints:
  - `POST /api/v1/workflows/nodes/execute`;
  - `POST /api/v1/workflows/receipt-gate`.
- Receipt inspection:
  - `GET /api/v1/receipts`;
  - `GET /api/v1/receipts/:id`;
  - `GET /api/v1/receipts/:id/replay`.
- CLI families:
  - `ioi models`;
  - `ioi routes`;
  - `ioi server`;
  - `ioi tokens`;
  - `ioi mcp`;
  - `ioi receipts`.
- Agent IDE workflow node schema and registry defaults include model mounting
  fields for `model_id`, `route_id`, `model_policy`, capability,
  `receipt_required`, selected endpoint, and receipt/tool receipt references.
- Mounts UI contract proving live daemon routes, session-only token handling,
  no token storage, native-local provider controls, download controls,
  ephemeral MCP probe, workflow probe, MCP fixture import, route test, and
  receipt visibility.
- Mounts health operations for provider/vault/backend probes:
  - latest provider and vault health receipt lookup;
  - grouped provider/vault health lanes in Logs / Receipts;
  - Local Server health summary strip derived from receipts;
  - `Run health sweep` action that fans out across vault, providers, and
    backends before refreshing the projection.
- Runtime engine profile management:
  - `GET /api/v1/runtime/engines/:id`;
  - `PATCH /api/v1/runtime/engines/:id`;
  - `DELETE /api/v1/runtime/engines/:id`;
  - `POST /api/v1/runtime/engines/:id/select`;
  - `ioi backends engines|get|engine-update|engine-remove`;
  - Mounts Backends runtime profile editor for label, priority, enable/disable,
    and default load options.
- Dedicated Mounts desktop GUI validation harness with real window screenshot
  capture and secret scan.
- Canonical deterministic end-to-end validation harness covering API, CLI, GUI,
  workflow, MCP, tokens, receipts, replay, and redaction in one command:
  `npm run validate:model-mounting:e2e`.
- Opt-in live-provider validation gate entrypoints for LM Studio, model
  backends, model catalog/download activation, remote wallet.network, and
  remote Agentgres. Wallet and Agentgres gates now have deterministic
  fake-remote coverage when real URLs are absent. These are evidence gates,
  not deterministic CI prerequisites.

Validation that passed during the implementation pass:

```text
npm run validate:model-mounting:e2e
npm run validate:model-mounting:e2e -- --skip-gui
npm run test:model-mounting
npm run test:daemon-runtime-api
npm test --workspace=@ioi/agent-sdk
npm run test:model-backends
npm run test:model-mounting-workflows
npm run test:model-mounting-gui
npm run validate:model-mounts-gui:run
AUTOPILOT_LOCAL_GPU_DEV=1 npm run validate:autopilot-gui-harness:run -- --window-timeout-ms 300000
IOI_LIVE_LM_STUDIO=1 npm run test:lm-studio-live
IOI_LIVE_LLAMA_CPP=1 IOI_LLAMA_CPP_SERVER_PATH=/path/to/llama-server IOI_LLAMA_CPP_MODEL_PATH=/path/to/model.gguf npm run test:llama-cpp-live
OLLAMA_HOST=http://127.0.0.1:11434 IOI_LIVE_MODEL_BACKENDS=1 IOI_OLLAMA_CHAT_MODEL=llama3.2:3b IOI_OLLAMA_EMBEDDING_MODEL=nomic-embed-text:latest npm run test:model-backends:live
npm run test:model-catalog-live
IOI_REMOTE_WALLET=1 npm run test:wallet-live
IOI_REMOTE_AGENTGRES=1 npm run test:agentgres-live
npx tsc -p apps/autopilot/tsconfig.json --noEmit
npm run build --workspace=apps/autopilot
cargo check -p ioi-cli --bin cli
cargo build -p ioi-cli --bin cli
npm run build --workspace=@ioi/agent-ide
npm run check:runtime-layout
git diff --check
```

Latest evidence paths:

```text
Canonical E2E:
docs/evidence/model-mounting-e2e/2026-05-05T21-29-49Z/result.json

Canonical E2E with nested GUI screenshots:
docs/evidence/model-mounting-e2e/2026-05-05T14-38-24Z/result.json

Mounts GUI nested under canonical E2E:
docs/evidence/model-mounting-e2e/2026-05-05T14-38-24Z/gui/2026-05-05T14-38-55Z/result.json

Standalone Mounts GUI with stream lifecycle probe:
docs/evidence/model-mounts-gui-validation/2026-05-05T21-09-24Z/result.json

Broad Autopilot GUI harness:
docs/evidence/autopilot-gui-harness-validation/2026-05-05T01-40-43-545Z/result.json

LM Studio live:
docs/evidence/model-mounting-live/lm-studio/2026-05-05T18-24-08Z/result.json

Ollama live backend with completed/aborted provider-native stream receipts:
docs/evidence/model-mounting-live/model-backends/2026-05-05T22-09-26Z/result.json

llama.cpp live runner attempt:
docs/evidence/model-mounting-live/llama-cpp/2026-05-05T18-27-43Z/result.json

Model catalog live gate command wiring, skipped because the live catalog env was
not enabled:
docs/evidence/model-mounting-live/model-catalog/2026-05-05T13-20-34Z/result.json

wallet.network deterministic fake-remote:
docs/evidence/model-mounting-live/wallet/2026-05-05T01-51-23Z/result.json

Agentgres deterministic fake-remote:
docs/evidence/model-mounting-live/agentgres/2026-05-05T01-51-23Z/result.json
```

Live local provider evidence on 2026-05-05 UTC:

- LM Studio live gate passed through public `lms` plus `/v1` using
  `qwen/qwen3.5-9b`, with a model invocation receipt.
- Ollama live backend gate passed with `OLLAMA_HOST=http://127.0.0.1:11434`,
  listing six provider models, mounting/loading `llama3.2:3b`, invoking chat,
  invoking `nomic-embed-text:latest` embeddings, completing a provider-native
  streamed chat-completions call, intentionally aborting a provider-native
  streamed chat-completions call, and verifying linked invocation, stream,
  replay, backend, and route receipts. The live gate now accepts
  `IOI_OLLAMA_CHAT_MODEL` and `IOI_OLLAMA_EMBEDDING_MODEL` so operators can
  select a responsive installed model instead of relying on provider list order.
- llama.cpp live runner gate reached real `llama-server` spawn, provider
  health, `/v1/models`, native chat, OpenAI-compatible chat, Responses fallback,
  route receipts, and invocation receipts using the local `stories260K` GGUF.
  The run failed only at `/v1/embeddings` because that local model/server
  combination returned provider HTTP 400 for embeddings; remaining live closeout
  is validating a GGUF/server configuration with embeddings support or
  downgrading the live gate to mark embeddings unsupported when the provider
  rejects them cleanly.
- wallet.network live gate passed in deterministic fake-remote mode, validating
  `WalletAuthorityPort` configuration, denied-scope fail-closed behavior, MCP
  plaintext-secret rejection, and secret scans.
- Agentgres live gate passed in deterministic fake-remote mode, validating
  `AgentgresModelMountingStorePort` configuration, projection watermark,
  receipt replay, download persistence, and secret scans.

### Commit Ledger

Feature work is frozen at the current green evidence state. The implementation
has been split into these reviewable commits:

1. `3012db8e8 runtime: add model mounting daemon core`
   - `packages/runtime-daemon/src/model-mounting.mjs`;
   - `packages/runtime-daemon/src/index.mjs`.

2. `f0dd8a4ea autopilot: add Mounts workbench UI`
   - Mounts activity bar icon and shell routing;
   - `MissionControlMountsView.tsx`;
   - `MissionControlMountsView.css`;
   - Mounts command palette and shortcut integration.

3. `8339aeb9f model mounting: add SDK CLI and validation contracts`
   - model mounting SDK contracts and daemon client types;
   - CLI commands for backends, models, routes, server, tokens, MCP, and
     receipts;
   - Agent IDE workflow node model mounting fields;
   - deterministic daemon/UI/e2e/live-gate validation scripts.

The remaining commit for this evidence pass should contain only:

- this master guide;
- `docs/lm-studio-model-mounting-autonomy-prompt.md`;
- `docs/assets/lm-studio-crawl/`;
- latest referenced `docs/evidence/model-mounting-e2e/...` bundle only;
- latest referenced `docs/evidence/model-mounting-live/...` bundles only;
- latest referenced `docs/evidence/model-mounts-gui-validation/...` bundle
  only;
- `docs/evidence/autopilot-gui-harness-validation/2026-05-05T01-40-43-545Z/`.

Do not stage older failed/blocked evidence attempts unless preserving the full
audit trail is explicitly desired.

Review note: the worktree also contains broader conformance/changelog files
from adjacent runtime work (`docs/conformance/agentic-runtime/*`,
`docs/architecture/_meta/changelog/*`, and
`docs/evidence/architectural-improvements-broad/checklist.json`). Keep those in
a separate review slice unless intentionally bundling the runtime conformance
changes with model mounting.

### Completed With Deterministic Local Fixture Coverage

These seams are implemented against deterministic local fixtures when live
external dependencies are unavailable. They are valid execution paths for CI,
offline demos, and local development evidence, but they intentionally do not
claim real third-party inference unless a configured provider is selected:

- Native-local serving uses a deterministic Autopilot backend fixture instead
  of llama.cpp/vLLM/Ollama binaries when those binaries are unavailable.
- Download/import lifecycle supports queued, running, completed, failed,
  canceled, progress, byte counts, checksum, cleanup, and receipts through a
  deterministic local fixture path rather than live model hub downloads.
- Hugging Face-compatible catalog search and live network download are
  implemented behind explicit gates. CI continues to use deterministic fixture
  catalog/download coverage; live download is opt-in and requires an explicit
  source URL or explicit first-result opt-in for the live gate, with optional
  max-byte enforcement.
- Agentgres persistence is an IOI daemon adapter with canonical projections
  and replay APIs, not a remote production Agentgres deployment.
- wallet.network is represented by an Agentgres-backed authority adapter, not a
  remote wallet.network vault/grant service.
- Workflow canvas integration is wired into real Agent IDE node contracts and
  daemon execution endpoints; richer visual node forms remain product work.
- TTL/idle eviction is implemented for local runtime instances, but memory
  pressure eviction, hardware guardrails, context/gpu estimates, and backend
  scheduling remain shallow.
- Generic OpenAI-compatible provider calls work for configured compatible
  endpoints, but BYOK OpenAI/Anthropic/Gemini native adapters and secret
  resolution are not production-complete.

### Local LM Studio Trace, 2026-05-05

The local LM Studio instance was traced through public `lms` and `/v1`
surfaces. This trace updates the parity target and supersedes the older
appendix snapshot where the server was stopped.

Observed public CLI/API state:

- `$HOME/.local/bin/lm-studio.AppImage`, `$HOME/.local/bin/lm-studio`, and
  `$HOME/.lmstudio/bin/lms` are executable.
- `lms --help` exposes the current public command groups:
  - local models: `chat`, `get`, `load`, `unload`, `ls`, `ps`, `import`;
  - serve: `server`, `log`;
  - remote instances: `link`;
  - runtime: `runtime`;
  - develop/publish beta: `clone`, `push`, `dev`, `login`, `logout`,
    `whoami`.
- `lms server status` reports the local server is running on port `1234`.
- `lms ls` reports two installed models:
  - `qwen/qwen3.5-9b`, 9B, `qwen35`, 6.55 GB, local, loaded;
  - `text-embedding-nomic-embed-text-v1.5`, Nomic BERT, 84.11 MB, local.
- `lms ps` reports `qwen/qwen3.5-9b` loaded with:
  - status `IDLE`;
  - context `4096`;
  - parallel `4`;
  - device `Local`;
  - no TTL value currently shown.
- `lms runtime ls` reports installed llama.cpp runtime packs for AVX2, CUDA,
  CUDA12, and Vulkan, with
  `llama.cpp-linux-x86_64-nvidia-cuda12-avx2@2.13.0` selected.
- `lms runtime survey` reports:
  - NVIDIA GeForce RTX 5070 Laptop GPU, CUDA, discrete, 7.53 GiB VRAM;
  - CPU `x86_64` with AVX2/AVX;
  - RAM `93.73 GiB`.
- `GET /api/v1/models` returns rich local catalog entries with publisher,
  display name, format, quantization, loaded instances, context length, vision
  capability, reasoning options, and trained-for-tool-use metadata.
- `GET /api/v0/models` still returns useful developer stats/model detail shape
  for loaded vs unloaded state, max context, compatibility type, quantization,
  and legacy runtime fields.
- `GET /v1/models` returns both installed model identifiers.
- `POST /v1/chat/completions` succeeds against `qwen/qwen3.5-9b`.
- `POST /v1/responses` succeeds against `qwen/qwen3.5-9b`; the older
  fallback-to-chat behavior remains necessary for compatible providers that do
  not expose Responses, but this local LM Studio instance does expose it.
- `POST /v1/messages` succeeds against `qwen/qwen3.5-9b` with an
  Anthropic-compatible response envelope.
- `POST /v1/embeddings` succeeds against
  `text-embedding-nomic-embed-text-v1.5`.
- LM Studio server management remains exposed through `lms server
  start|stop|status`, not through an observed `/api/v1/server/status` HTTP
  endpoint.

This trace identifies concrete parity gaps that are more specific than the
generic hardening list:

- Autopilot now has a user-facing runtime engine inventory, hardware survey,
  selection, get/update/remove profile controls, disable/enable, priority, and
  default load-option scheduling comparable to `lms runtime ls`,
  `lms runtime survey`, and the runtime profile management ergonomics around
  `lms runtime select/get/update/remove`. Remaining parity is applying those
  profiles to real process runners beyond the deterministic/native-local path.
- Autopilot load controls need visible parity with `lms load` options:
  `--gpu`, `--context-length`, `--parallel`, `--ttl`, `--identifier`, and
  `--estimate-only`.
- Autopilot model catalog/download UX now has deterministic catalog search,
  direct URL import, GGUF/MLX/safetensors filters, quantization filtering,
  storage/quota summary, and gated Hugging Face-compatible activation.
  Remaining parity with `lms get` is richer variant-selection polish, scripted
  approval flows, production hub metadata, and live-download retry UX.
- Autopilot import UX needs parity with `lms import`, including move/copy,
  hard-link, symbolic-link, dry-run, and explicit `user/repo` classification.
- Autopilot Logs needs streaming request/response logs comparable to
  `lms log stream`, while preserving IOI redaction and receipts.
- Autopilot now has governed Anthropic-compatible `/v1/messages` support
  through the same router/capability/receipt path, including `x-api-key`
  compatibility for local clients and deterministic Anthropic SSE events for
  `stream: true`. Remaining parity is provider-native token streaming, richer
  content blocks, cancellation, and advanced tool-use event shapes.
- Autopilot now has deterministic OpenAI-compatible chat-completion SSE for
  `/v1/chat/completions` with `stream: true`, final `[DONE]`, and
  receipt/route/tool receipt metadata linked to the governed invocation.
- Autopilot now has deterministic OpenAI-compatible Responses SSE for
  `/v1/responses` with `response.created`, output item/content part, text
  delta, and `response.completed` events that carry receipt/route/tool receipt
  metadata.
- Deterministic SSE streams for `/v1/chat/completions`, `/v1/responses`, and
  `/v1/messages` now record `model_invocation_stream_canceled` receipts when
  the client disconnects before the final frame. Remaining parity is
  provider-native token streaming, transport-level upstream cancellation, and
  advanced Responses state/tool-output submission.
- Autopilot streaming needs to move from filtered receipt/event observability
  to true response streaming where supported: native `/api/v1/chat` token
  streams, OpenAI-compatible SSE streams, Anthropic-compatible SSE events,
  model-load events, prompt-processing events, and interrupt/cancel semantics.
- Autopilot should add a tokenizer/count-tokens/context-fit utility surface.
  LM Studio exposes tokenization through SDKs rather than the core REST table,
  but it is a practical model-integration primitive for route planning,
  context budgeting, RAG, and workflow harness validation.
- Autopilot should decide which LM Studio beta/developer workflows are
  in-scope for Mounts: LM Link remote instance preference, hub artifact
  clone/push, plugin dev server, and login/whoami identity flows. These should
  map to IOI provider registry, Agentgres artifacts, workflow/tool registries,
  and wallet/network identity rather than copying LM Studio account state.

### Remaining Production / Live-Only Gaps

The target end state is now validated for the deterministic Autopilot-native
path and fake LM Studio/OpenAI-compatible provider paths. Remaining work is
production hardening or live-provider activation. These are not blockers for
the deterministic completion gate and should stay behind explicit live/config
gates:

1. Real local inference engines:
   - replace deterministic native-local fixture inference with a live local
     backend when explicitly configured;
   - runtime engine profile management and default GPU/context/parallel/TTL
     scheduling are implemented for the shared path;
   - deterministic process supervision is implemented for the native-local
     fixture path, including persisted process records, redacted argv,
     PID hashes, bounded logs, startup-timeout evidence, health snapshots, and
     stale process detection after daemon restart;
   - `llama.cpp` now has a first real runner boundary: configured
     `IOI_LLAMA_CPP_SERVER_PATH` binaries are spawned by the backend supervisor,
     runtime defaults become redacted `llama-server` args, invocation routes
     through its OpenAI-compatible `/v1`, unload stops the child process, and a
     fake `llama-server` fixture validates the path in CI;
   - an opt-in live `llama.cpp` gate is wired with
     `IOI_LIVE_LLAMA_CPP=1`, `IOI_LLAMA_CPP_SERVER_PATH`, and
     `IOI_LLAMA_CPP_MODEL_PATH`; it validates real spawn, `/v1/models`,
     chat, Responses fallback, embeddings, unload, receipts, replay, and
     token redaction when a local GGUF artifact is supplied;
   - the latest local llama.cpp attempt proved real spawn, health, chat,
     OpenAI-compatible chat, Responses fallback, route receipts, and invocation
     receipts, but failed at embeddings with provider HTTP 400 for the available
     `stories260K` GGUF;
   - Ollama has deterministic process-lifecycle parity: configured
     `ollama serve` binaries are supervised with redacted argv and bounded
     logs, model load/unload uses the public `/api/generate` keep-alive path,
     loaded-state projection uses public `/api/ps`, and the local live gate
     passed with completed and client-aborted provider-native stream receipts
     against `llama3.2:3b`;
   - vLLM has deterministic process-lifecycle parity: configured `vllm serve`
     binaries are supervised with redacted argv and bounded logs, `/v1`
     provider models, chat, Responses fallback, embeddings, loaded projection,
     unload, receipts, and replay all share the OpenAI-compatible daemon path,
     and `npm run test:model-backends:live` can exercise it when
     `IOI_VLLM_MODEL` and either a `vllm` binary on `PATH`,
     `IOI_VLLM_BINARY`, or `VLLM_BASE_URL` are configured;
   - remaining work is validating llama.cpp embeddings with a compatible local
     GGUF/server configuration, running vLLM against live hardware, extending
     live stream parity beyond the passing Ollama gate, memory pressure
     eviction, and backend-specific schedulers.
2. Live catalog/download production hardening:
   - the gated Hugging Face-compatible adapter, format/quantization filters,
     resumable `.part` downloads, checksum verification, source hashing, and
     redaction are implemented;
   - the live catalog gate now validates import-url materialization, download
     status lookup, receipt replay, projection persistence, optional first
     result download, max-byte guards, and no plaintext token/source leakage;
   - remaining work is production catalog breadth, richer benchmark and
     compatibility metadata, approval/retry affordances, bandwidth/storage
     policy controls, and live validation against external hubs when explicitly
     enabled.
3. Remote wallet.network and vault integration:
   - remote wallet.network grants;
   - provider-key vault resolution;
   - MCP header vault resolution;
   - cross-device revocation and audit propagation.
4. Production Agentgres deployment:
   - workflow run linkage;
   - settlement/audit pack integration;
   - remote projection sync.
5. Product-complete workflow/canvas UI:
   - richer node forms for model mounting fields;
   - visual Receipt Gate configuration and replay;
   - replay and validation inside the harness runtime.
6. MCP production lifecycle:
   - stdio MCP process lifecycle;
   - remote OAuth-capable MCP;
   - tool schema discovery and model tool exposure.
7. Product-complete Mounts UI:
   - runtime engine and hardware survey panel plus runtime profile editor are
     implemented for the deterministic path;
   - provider/backend lifecycle controls, model lifecycle controls, token/MCP/
     vault actions, route/workflow probes, benchmark replay, and receipt-focused
     Logs navigation are validated by the standalone GUI harness;
   - remaining work is richer live-backend error/retry affordances and
     provider-specific scheduling hints;
   - existing server start/stop/restart/log-tail controls should stay compact;
   - download queue polish beyond the current progress/cancel/failure/storage
     controls;
   - raw streaming logs for live providers beyond the current server/event tail
     plus filtered request/response receipt stream;
   - compact error details and retry affordances for failed actions.
8. Compatibility and SDK surface parity:
   - Anthropic-compatible `/v1/messages` is implemented for message calls and
     deterministic SSE with `x-api-key`/Bearer auth and governed receipts;
     remaining parity is provider-native token streaming, cancellation, and
     advanced tool-use metadata;
   - OpenAI-compatible `/v1/chat/completions` deterministic SSE is implemented
     with final `[DONE]` and governed receipt metadata;
   - OpenAI-compatible `/v1/responses` deterministic SSE is implemented with
     Responses-style events and governed receipt metadata;
   - deterministic stream cancellation receipts are implemented for
     `/v1/chat/completions`, `/v1/responses`, and `/v1/messages`;
   - true token streaming for `/api/v1/chat`, `/v1/responses`,
     `/v1/chat/completions`, and `/v1/messages`, including model-load and
     prompt-processing events where the native API can express them;
   - stateful chat continuation parity for native chat and Responses
     (`response_id` / `previous_response_id`) through governed receipts;
   - tokenizer/count-tokens/context-fit APIs and SDK helpers;
   - TTFT, tokens-per-second, generation-time, stop-reason, runtime, and model
     info telemetry in invocation receipts and Mounts benchmark/detail views.
9. Remote instance and developer workflow parity:
   - LM Link-style remote instance preference mapped to provider/backend
     routing, with wallet/network grants and receipts;
   - artifact clone/push/publish mapped to IOI artifact registry or
     marketplace flows;
   - plugin dev-server workflows mapped to Tool Registry/MCP/workflow harness
     contracts;
   - identity flows (`login`, `logout`, `whoami`) mapped to wallet.network
     identity rather than LM Studio account files.
10. Provider expansion:
   - Ollama and vLLM have deterministic supervised runner boundaries;
   - Ollama has a passing live backend gate with chat, embeddings, and
     completed/aborted provider-native stream receipts;
   - vLLM has an opt-in live gate that remains config/hardware dependent;
   - remaining work is production BYOK behavior for OpenAI, Anthropic, and
     Gemini through vault refs;
   - custom HTTP auth profile hardening;
   - future DePIN/TEE attested runtime endpoint validation.

### Parity Gap Matrix: Autopilot Mounts vs LM Studio

This table is the current source of truth for remaining model-integration
parity. "Complete" means covered by deterministic CI and focused validation.
"Partial" means the shared Autopilot architecture exists but lacks one or more
LM Studio-class live/product affordances. "Gap" means the capability is not yet
implemented as a product surface.

| Area | LM Studio observed primitive | Autopilot status | Remaining closeout |
| --- | --- | --- | --- |
| Dedicated model surface | Left rail app surface with compact model controls | Complete | Keep Mounts separate from Capabilities while improving product polish |
| Global model picker / loader | Top model picker invites select/load without exposing topology | Complete for deterministic Mounts path | Extend into app-wide header or keyboard model switching only if product direction wants it; keep governed load/unload path |
| Installed models | `lms ls` shows model family, params, arch, size, device, loaded marker | Complete for deterministic Mounts detail path | Add live-provider family/params/arch/device precision and benchmark classification metadata |
| Loaded models | `lms ps` shows identifier, model, status, size, context, parallel, device, TTL | Complete for deterministic Mounts path | Add live-provider TTL/device precision, unload confirmations, and app-wide loaded-instance status if needed |
| Model search/download | `lms get`, direct Hugging Face URL, GGUF/MLX filters, variant select | Complete for deterministic/gated adapter path | Fixture catalog, URL import, variant metadata, gated Hugging Face adapter, checksum/download receipts, and GUI cancel/retry controls exist; add live hub breadth, benchmark metadata, and destructive storage UX polish |
| Model import | `lms import` supports move/copy/hard-link/symlink/dry-run/user-repo | Complete for deterministic local path | Add live provider-specific import UX polish and benchmark/classification metadata |
| Runtime engines | `lms runtime ls/select/get/update/remove` | Complete for deterministic/shared control path | Runtime engine list, survey, selected-runtime persistence, get/update/remove profiles, disable/enable, priority, default load options, deterministic process supervision, llama.cpp runner spawning, Ollama serve supervision, vLLM serve supervision, API, CLI, receipts, E2E, and Mounts Backends editor are implemented; remaining live work is hardware validation and scheduler hardening |
| Hardware survey | `lms runtime survey` reports GPU/VRAM, CPU features, RAM | Complete for deterministic/public CLI path | Keep redacted survey receipts in projection/replay; add scheduling hints and live runtime preference recommendations |
| Load options | `lms load --gpu --context-length --parallel --ttl --identifier --estimate-only` | Complete for deterministic/public driver path | Runtime defaults now flow into redacted process argv for deterministic native-local, configured llama.cpp, Ollama serve, and vLLM serve runners; live tuning recommendations remain future scheduler work |
| Local server | `lms server start|stop|status` and local port `1234` | Complete for deterministic daemon path | Keep start/stop/restart governed by `server.control:*`; package production headless/service supervision |
| OpenAI-compatible API | `/v1/models`, chat completions, Responses, embeddings | Complete for daemon path | Chat-completion and Responses deterministic SSE plus cancellation receipts now exist; GUI/API/CLI/replay parity is validated, and Ollama has passing live provider-native completed/aborted stream receipts; remaining closeout is llama.cpp/vLLM live stream parity, richer OpenAI error shape, tool-output submission, and advanced Responses state |
| Anthropic-compatible API | `/v1/messages` with `x-api-key`/Bearer auth and SSE events | Partial | Message calls, deterministic SSE, and cancellation receipts route through router/capability/MCP/receipt path; add provider-native token streaming, upstream cancellation, richer content blocks, and advanced tool-use compatibility |
| Native model API | LM Studio has public local primitives plus OpenAI-compatible surface | Complete, Autopilot-specific | Keep IOI-native routes authoritative and prevent `/v1/*` policy bypass |
| Stateful/streaming native chat | `/api/v1/chat` supports stateful chat, token streams, model-load events, prompt-processing events, context length in request, and MCP integrations | Partial | Current deterministic observability is receipt/event based; add true streaming transport, stateful continuation, cancel/interrupt, and per-request context-length handling |
| Request/response logs | `lms log stream` | Complete for deterministic Mounts path | Server log/event tail and filtered request/response receipt observability are visible through API/CLI/Mounts; add raw streaming transport parity for live provider/backend logs where supported |
| Tokenization/context utilities | SDK tokenization and count-tokens helpers for loaded LLM/embedding models | Gap | Add tokenizer/count-tokens/context-fit API/SDK/CLI helpers backed by selected backend where available and deterministic estimates where unavailable |
| Inference stats | v0-style TTFT, tokens/sec, generation time, stop reason, runtime/model info | Partial | Receipts contain latency/token counts; add TTFT/tokens-per-second/runtime/model-info fields for streaming and non-streaming invocations |
| API tokens | LM Studio local API tokens/auth toggle | Complete plus stronger IOI policy | Add production wallet.network account linking, cross-device revocation, and richer audit export UX |
| MCP config | Cursor/LM Studio-style `mcp.json` plus API integrations | Partial | Complete stdio lifecycle, OAuth, schema discovery, and model tool exposure through governed receipts |
| Provider support | LM Studio owns local GGUF runtime; external providers are not core | Partial | Keep LM Studio first-class; llama.cpp, Ollama, and vLLM have supervised runner boundaries; Ollama has passing live stream/invocation evidence, while llama.cpp/vLLM live stream parity and BYOK/custom HTTP hardening remain behind the same router |
| Workflow integration | Not a core LM Studio primitive | Autopilot ahead, partial product UX | Build visual node forms, Receipt Gate configuration, replay, and harness run inspection |
| Receipts/audit | Not an LM Studio primitive | Autopilot ahead | Finish production Agentgres sync, settlement/audit packs, and remote replay |
| Secret storage | LM Studio local config/API token ergonomics | Partial, stronger boundary | Wire production wallet.network/vault and cross-device revocation; keep plaintext rejected |
| Headless/background mode | `lms server` and background service ergonomics | Partial | Package IOI daemon service/headless mode, health checks, logs, and restart policy |
| Remote instances | `lms link` manages preferred remote devices/instances | Gap | Add provider/backend remote-instance preference, trust, health, wallet/network grants, and receipts; do not copy LM Studio private link state |
| Hub artifact workflows | `lms clone`, `lms push`, `login/logout/whoami` | Gap | Map clone/push/publish and identity to IOI artifact registry, Agentgres provenance, and wallet.network identity |
| Plugin dev workflows | `lms dev` starts plugin development server | Gap | Map plugin dev ergonomics to IOI Tool Registry/MCP/workflow harness developer mode |
| Model cleanup/storage | LM Studio models folder and import management | Partial | Artifact delete and orphan scan receipts exist; add uninstall confirmations, storage quota, and destructive UX safeguards |
| Document/RAG integration | LM Studio can chat with documents offline and ships retrieval/vector workers | Adjacent gap | Decide whether Mounts owns local RAG index/model bindings or delegates to workflow/tool surfaces; preserve receipts for embedding/index/query steps |
| Benchmarks/evals | LM Studio exposes model metadata and developer feedback loops | Complete for deterministic Mounts path | GUI harness validates benchmark run, replay, Logs focus, chat/responses/embeddings receipts, and backend/grant/latency payloads; add scheduled runs, route recommendation receipts, and comparative charts |
| Attested remote runtime | Outside current LM Studio local focus | Boundary only | Implement DePIN/TEE attestation verification, fail-closed routing, and attestation receipts |

### Priority Closeout Order For Parity

1. Compatibility surface parity:
   - true native/OpenAI/Anthropic streaming with cancellation and event
     receipts;
   - stateful chat/Responses continuation;
   - tokenizer/count-tokens/context-fit utilities;
   - TTFT/tokens-per-second/runtime/model-info telemetry.
2. Catalog/download product hardening:
   - richer GGUF/MLX variant selection polish;
   - hub metadata breadth and benchmark/classification metadata;
   - storage quota and uninstall confirmation UX;
   - live external-hub validation on an operator machine.
3. Product UI parity:
   - compact failed-action retry affordances;
   - receipt drill-down detail polish beyond the current filtered stream and
     replay controls.
4. Remote/developer workflow parity:
   - LM Link-style remote instance preference through IOI providers;
   - clone/push/publish through IOI artifact registry/marketplace;
   - plugin dev-server ergonomics through Tool Registry/MCP/workflow harness;
   - wallet.network identity for login/whoami semantics.
5. Live backend parity:
   - live hardware validation and scheduler hardening for the configured
     `llama.cpp` runner boundary;
   - live Ollama lifecycle is validated for the local `llama3.2:3b` chat model
     and `nomic-embed-text:latest` embedding model, including completed and
     client-aborted provider-native stream receipts;
   - live vLLM/OpenAI-compatible hardware validation;
   - native BYOK OpenAI/Anthropic/Gemini adapters through vault refs.
6. Raw live-log streaming parity:
   - live transport equivalent to `lms log stream` for providers/backends that
     support raw streams;
   - provider/backend log panes beside the current filtered receipt stream.
7. Production IOI hardening beyond LM Studio:
   - production wallet.network grants/vaults;
   - production Agentgres projection sync and settlement packs;
   - stdio/OAuth MCP lifecycle;
   - visual workflow run replay and Receipt Gate configuration;
   - DePIN/TEE attested remote runtimes.

## Screenshot Evidence

### Autopilot Mounts GUI Evidence

Autopilot Mounts desktop evidence is now captured by the canonical deterministic
E2E gate:

```text
npm run validate:model-mounting:e2e
```

Latest passing bundle:

```text
docs/evidence/model-mounting-e2e/2026-05-05T14-38-24Z/result.json
```

Nested GUI bundle:

```text
docs/evidence/model-mounting-e2e/2026-05-05T14-38-24Z/gui/2026-05-05T14-38-55Z/result.json
```

Standalone Mounts GUI bundle with stream lifecycle probe:

```text
docs/evidence/model-mounts-gui-validation/2026-05-05T21-09-24Z/result.json
```

The GUI bundle captured nine desktop window screenshots for the Mounts tabs
and verified the seeded daemon projection exposed:

- 7 backends;
- 12 providers;
- 6 artifacts;
- 19 seeded receipts before action probes;
- completed and client-aborted provider-native stream receipts created from the
  Mounts Logs / Receipts surface;
- no plaintext token or vault-ref findings.

The same bundle verifies action-level GUI parity for provider/backend controls,
model import/mount/load/unload, download cancel/retry/open-receipt, token/MCP/
vault controls, route/workflow/Receipt Gate probes, benchmark run/replay, and
Logs focus for a benchmark invocation receipt.

The screenshots are stored next to the nested GUI result:

- `mounts-server.png`;
- `mounts-backends.png`;
- `mounts-models.png`;
- `mounts-providers.png`;
- `mounts-downloads.png`;
- `mounts-tokens.png`;
- `mounts-routing.png`;
- `mounts-benchmarks.png`;
- `mounts-logs.png`.

### LM Studio Reference Screenshots

The screenshots below were captured from the installed LM Studio AppImage on
2026-05-04. Wayland input automation limited deeper click-through crawling, so
the guide combines local screenshots, CLI/config crawl, AppImage/runtime
inspection, and official LM Studio docs.

#### App Window

![LM Studio app window](../../assets/lm-studio-crawl/lm-studio-app-window.png)

Observed primitives:

- a compact native desktop shell;
- left rail mode navigation;
- global top model picker / loader control;
- chat as the default work surface;
- import/download and panel controls in the top-right area;
- settings and local/device controls in the lower-left rail.

#### Model Picker / Loader Control

![LM Studio model picker control](../../assets/lm-studio-crawl/lm-studio-model-picker-control.png)

This is the key ergonomic primitive to reproduce: an always-reachable model
picker that invites "select a model to load" without making the user understand
the full runtime topology first.

#### Navigation And Chat List

![LM Studio left navigation and chats](../../assets/lm-studio-crawl/lm-studio-left-navigation-and-chats.png)

The Mounts surface should follow the same density: a left rail entry opens a
purpose-built work area, not a marketing page. Model mounting belongs in a
workbench-style view with status, tables, logs, and controls.

## Source Corpus

### Local Evidence

| Evidence | Result |
| --- | --- |
| Installer resolution | `test -x "$HOME/.local/bin/lm-studio.AppImage" || test -x "$HOME/.local/bin/lm-studio"` passed |
| Wrapper | `$HOME/.local/bin/lm-studio` execs `$HOME/.local/bin/lm-studio.AppImage` |
| Running app | AppImage mounted at `/tmp/.mount_lm-stu*/`; process metadata shows LM Studio `0.4.12+1` |
| App data root | `$HOME/.lmstudio` |
| Local server status | Initial 2026-05-04 crawl found the server stopped; fresh 2026-05-05 trace found `lms server status --json` running on port `1234` |
| Local models | `lms ls` reported Qwen3.5 9B and Nomic Embed Text v1.5, 6.63 GB total |
| Loaded models | Initial 2026-05-04 crawl found none loaded; fresh 2026-05-05 trace found `qwen/qwen3.5-9b` loaded with context `4096`, parallel `4`, and local device |
| MCP config | `$HOME/.lmstudio/mcp.json` contains `{ "mcpServers": {} }` |
| Settings | local service enabled; JIT TTL enabled for 3600 seconds; auto-evict previous JIT model enabled |
| Runtime engines | llama.cpp CPU, Vulkan, and CUDA extension packs installed; preferred GGUF backend is CUDA 12 llama.cpp `2.13.0` |
| Bundled app workers | `llmworker`, `embeddingworker`, `mcpbridgeworker`, `mcpoauthworker`, retrieval/image workers, Node, Deno, esbuild, and bundled RAG/code-sandbox plugins |

### Official LM Studio References

| Topic | Reference |
| --- | --- |
| REST API overview | https://lmstudio.ai/docs/developer/rest |
| Local server | https://lmstudio.ai/docs/developer/core/server |
| OpenAI-compatible endpoints | https://lmstudio.ai/docs/developer/openai-compat |
| Anthropic-compatible endpoint | https://lmstudio.ai/docs/developer/anthropic-compat |
| Anthropic Messages endpoint | https://lmstudio.ai/docs/developer/anthropic-compat/messages |
| CLI | https://lmstudio.ai/docs/cli |
| CLI load/unload | https://lmstudio.ai/docs/cli/local-models/load |
| Authentication/API tokens | https://lmstudio.ai/docs/developer/core/authentication |
| Stateful chats | https://lmstudio.ai/docs/developer/rest/stateful-chats |
| Chat endpoint and MCP request shape | https://lmstudio.ai/docs/developer/rest/chat |
| Native streaming events | https://lmstudio.ai/docs/developer/rest/streaming |
| MCP app configuration | https://lmstudio.ai/docs/app/mcp |
| MCP via API | https://lmstudio.ai/docs/developer/core/mcp |
| TTL and auto-evict | https://lmstudio.ai/docs/developer/core/ttl-and-auto-evict |
| Headless/service mode | https://lmstudio.ai/docs/developer/core/headless |
| Model list endpoint | https://lmstudio.ai/docs/developer/rest/list |
| Model load endpoint | https://lmstudio.ai/docs/developer/rest/load |
| Model download endpoint | https://lmstudio.ai/docs/developer/rest/download |
| Model unload endpoint | https://lmstudio.ai/docs/developer/rest/unload |
| Download status endpoint | https://lmstudio.ai/docs/developer/rest/download-status |
| Tokenization/count tokens | https://lmstudio.ai/docs/typescript/tokenization |
| API changelog / parity deltas | https://lmstudio.ai/docs/developer/api-changelog |

## LM Studio Crawl Findings

### UX Primitives To Copy

| LM Studio primitive | Autopilot analogue |
| --- | --- |
| Top model picker | Global Mounts-aware model selector, scoped by current project/lens/workflow |
| Local server toggle/status | IOI daemon local API status with route health and provider health |
| Downloaded models | Model Registry installed artifacts |
| Loaded models | Runtime `ModelInstance` records, not the top-level abstraction |
| Load/unload/download controls | Registry/runtime lifecycle actions with receipts |
| API tokens | wallet.network-backed capability tokens |
| `mcp.json` | Tool Registry import source, policy-bound and receipted |
| Per-request MCP integrations | Ephemeral tool capability requests |
| TTL and auto-evict | load policy: manual, on-demand, keep-warm, idle-evict, memory-pressure-evict |
| CLI | `ioi models`, `ioi server`, `ioi routes`, `ioi mcp`, and `ioi receipts` command families |
| Headless mode | IOI daemon runtime and local server mode |

### Local Install Shape

The local LM Studio install separates:

- the desktop executable under `$HOME/.local/bin`;
- app state under `$HOME/.lmstudio`;
- model artifacts under `$HOME/.lmstudio/models`;
- local settings under `$HOME/.lmstudio/settings.json`;
- MCP declarations under `$HOME/.lmstudio/mcp.json`;
- runtime extension packs under `$HOME/.lmstudio/extensions`;
- internal caches and model indexes under `$HOME/.lmstudio/.internal`;
- server logs under `$HOME/.lmstudio/server-logs`.

Autopilot should preserve this separation conceptually:

```text
~/.ioi/
  models/              downloaded or imported model artifacts
  mounts/              mounted endpoint declarations
  providers/           provider profiles, no plaintext secrets
  mcp/                 imported MCP declarations and generated registry views
  receipts/            local receipts before Agentgres sync
  logs/                local server and router logs
  runtime/             daemon/runtime state, locks, pid files
```

Do not reuse LM Studio's private internal formats. Treat them as a UX and
behavior reference only.

### Local Settings Observed

The redacted local settings show the exact primitives Autopilot needs:

```yaml
downloads_folder: ~/.lmstudio/models
enable_local_service: true
developer:
  unload_previous_jit_model_on_load: true
  jit_model_ttl:
    enabled: true
    ttl_seconds: 3600
  separate_reasoning_content_in_api: true
  api_prediction_history_eviction:
    type: time
    ttl_days: 30
model_loading_guardrails:
  mode: high
  custom_threshold_bytes: 4294967296
```

Autopilot version:

```yaml
local_server:
  enabled: true
  bind_host: 127.0.0.1
  port: 1977
router:
  jit_loading: true
  unload_previous_on_jit_load: policy_controlled
  default_idle_ttl_seconds: 3600
  memory_pressure_evict: true
  expose_reasoning_content: policy_controlled
history:
  retention_policy: project_or_wallet_policy
guardrails:
  memory_threshold_bytes: hardware_profile_default
  allow_override: capability_grant_required
```

### Local Models Observed

`lms ls` reported:

| Model | Type | Local shape |
| --- | --- | --- |
| `qwen/qwen3.5-9b` | LLM | GGUF Q4_K_M, 9B, local, roughly 6.55 GB |
| `text-embedding-nomic-embed-text-v1.5` | embedding | bundled Nomic BERT embedding model, roughly 84 MB |

The internal model index also recorded Qwen aliases such as
`qwen/qwen3.5-9b@q4_k_m` and `qwen3.5-9b`, with `trainedForToolUse: true`,
`arch: qwen35`, `format: gguf`, and a large advertised context length.

Autopilot should capture the same information, but normalize it:

```yaml
ModelArtifact:
  id: artifact.local.qwen3_5_9b_q4_k_m
  source: lmstudio_hub | huggingface | local_file | imported_folder
  family: qwen3.5
  parameter_count: 9B
  format: gguf
  quantization: Q4_K_M
  size_bytes: 6548927017
  max_context_tokens: 262144
  trained_for_tool_use: true
  modalities:
    input: [text]
    output: [text]
  privacy_class: local
```

Then the runtime can mount that artifact as one or more endpoints or instances.

### CLI Surface Observed

The installed `lms` CLI exposes these command groups:

| Group | Commands |
| --- | --- |
| Local models | `chat`, `get`, `load`, `unload`, `ls`, `ps`, `import` |
| Serve | `server`, `log` |
| Remote instances | `link` |
| Runtime | `runtime` |
| Develop/publish | `clone`, `push`, `dev`, `login`, `logout`, `whoami` |

`lms load` supports the critical lifecycle flags:

```text
--gpu
--context-length
--parallel
--ttl
--identifier
--estimate-only
--yes
```

Autopilot CLI should mirror the muscle memory while speaking IOI concepts:

```text
ioi models ls
ioi models get <catalog-id|hf-url|local-path>
ioi models import <path>
ioi models mount <artifact-or-endpoint>
ioi models load <model-or-route> --ttl 3600 --context-length 8192
ioi models unload <instance-id|--all>
ioi models ps
ioi backends engines|engine-get|engine-update|engine-remove|survey|select
ioi routes ls
ioi routes test <route-id>
ioi server start|stop|restart|status|logs|events
ioi mcp ls|import|validate
ioi tokens create|revoke|ls
```

### Runtime Engine Shape Observed

The AppImage and app data include:

- `llmworker.js`;
- `embeddingworker.js`;
- `mcpbridgeworker.js`;
- `mcpoauthworker.js`;
- retrieval and image-processing workers;
- bundled RAG and JavaScript code sandbox plugins;
- Node, Deno, esbuild, and SQLite vector support;
- llama.cpp engine extension packs for CPU, Vulkan, and NVIDIA CUDA variants;
- a backend preference pointing GGUF loads at CUDA 12 llama.cpp `2.13.0`.

Autopilot implication:

```text
Model Registry stores artifacts.
Runtime Engine Registry stores executable backends.
Model Router chooses an endpoint/provider/runtime.
Daemon owns process lifecycle and health.
Receipts bind each invocation to selected route, backend, and policy.
```

Do not hide backend selection. Developers need enough visibility to understand
why a model loaded on CPU, CUDA, Vulkan, Ollama, vLLM, LM Studio, or a hosted
provider.

## Official LM Studio API Contract

### Native REST API

LM Studio's official docs state that the native v1 API lives under
`/api/v1/*` and includes:

```http
POST /api/v1/chat
GET  /api/v1/models
POST /api/v1/models/load
POST /api/v1/models/unload
POST /api/v1/models/download
GET  /api/v1/models/download/status/:job_id
```

Important features for Autopilot:

- stateful chat through `response_id` and `previous_response_id`;
- model auto-load/JIT behavior;
- model load events and prompt-processing events in streaming mode;
- MCP integrations through the chat request body;
- rich model metadata in model list responses;
- separate load/download/unload management endpoints.

### OpenAI-Compatible API

LM Studio also exposes OpenAI-compatible endpoints:

```http
GET  /v1/models
POST /v1/responses
POST /v1/chat/completions
POST /v1/embeddings
POST /v1/completions
```

Autopilot should provide the same compatibility lane because it unlocks
existing clients immediately. It must still route through Autopilot policy,
wallet capabilities, and receipts rather than bypassing the runtime substrate.

### Local Server

The docs describe running the server from the Developer tab or via:

```sh
lms server start
```

Autopilot should expose both:

- GUI: Mounts > Local Server > Start/Stop/Restart;
- CLI: `ioi server start|stop|restart|status|logs|events`;
- API: `GET /api/v1/server/status`, `POST /api/v1/server/start`,
  `POST /api/v1/server/stop`, `POST /api/v1/server/restart`,
  `GET /api/v1/server/logs`, and `GET /api/v1/server/events`.

### Authentication And Tokens

LM Studio supports API tokens and optional authentication enforcement for API
requests. Tokens can be created and permissioned in the Developer page.

Autopilot should use the UX pattern, but replace the security model:

```text
LM Studio: token can call local API
Autopilot: token can call specific model/tool/MCP/connector capabilities
```

Autopilot tokens must be wallet.network capability grants. They should be
revocable, scoped, auditable, and backed by receipts.

### MCP

LM Studio supports MCP in two ergonomic forms:

- persistent MCP servers in `mcp.json`;
- per-request ephemeral MCP integrations in `/api/v1/chat`.

The official chat shape supports plugin integrations and ephemeral MCP
integrations with fields such as `type`, `id`, `server_label`, `server_url`,
`allowed_tools`, and optional `headers`.

Autopilot should keep this request ergonomics but route it through:

```text
mcp.json or API integration
-> Tool Registry
-> Capability Request
-> wallet.network approval if needed
-> RuntimeToolContract
-> tool call receipt
-> model invocation receipt
```

### TTL, JIT Loading, And Auto-Evict

LM Studio documents:

- JIT loading for first request;
- idle TTL for auto-unloading unused models;
- per-request TTL in API payloads;
- `lms load --ttl`;
- auto-evict for previous JIT-loaded models.

Autopilot should support a superset:

```yaml
load_policy:
  mode: manual | on_demand | keep_warm | idle_evict | workflow_scoped | agent_scoped
  idle_ttl_seconds: 900
  memory_pressure_evict: true
  evict_on_route_switch: policy_controlled
  max_loaded_instances: hardware_profile_default
```

### Headless / Service Mode

LM Studio supports running as a background/headless service through `llmster`
or desktop headless mode. The key Autopilot takeaway is not the implementation,
but the operating mode:

```text
desktop UI optional
local server can run continuously
models can load on demand
external clients can call local endpoints
```

For Autopilot, this is the IOI daemon runtime:

```text
Autopilot shell
  talks to
IOI daemon
  owns
Model Registry, Router, Tool Registry, local server, receipts, and Agentgres sync
```

## Autopilot Target Model

### Core Rule

Do not make "loaded model" the top-level abstraction.

LM Studio centers:

```text
local server -> loaded model -> API call
```

Autopilot centers:

```text
model capability -> route -> endpoint/provider/runtime -> invocation receipt
```

Loaded instances still matter, but they are runtime state, not the developer's
primary contract.

### Core Objects

```yaml
ModelArtifact:
  id: artifact.local.qwen3_5_9b_q4_k_m
  source: huggingface | lmstudio_hub | ollama | local_file | custom
  format: gguf | safetensors | mlx | onnx | provider_virtual
  quantization: Q4_K_M
  size_bytes: 6548927017
  checksum: optional
  metadata:
    architecture: qwen35
    params: 9B
    max_context_tokens: 262144
    trained_for_tool_use: true

ModelEndpoint:
  id: local.qwen3_5_9b
  provider: lmstudio | ollama | openai | anthropic | gemini | vllm | custom | ioi_local
  api_format: openai_compatible | native | anthropic | gemini | ioi_native
  base_url: http://localhost:1234/v1
  model_id: qwen/qwen3.5-9b
  artifact_id: artifact.local.qwen3_5_9b_q4_k_m
  capabilities:
    - chat
    - code
    - structured_output
    - tool_use
  privacy_class: local
  load_policy:
    mode: idle_evict
    idle_ttl_seconds: 900

ModelInstance:
  id: instance.local.qwen3_5_9b.20260504T0031
  endpoint_id: local.qwen3_5_9b
  runtime_backend: llama.cpp.cuda12
  status: loaded | loading | unloading | failed | evicted
  context_length: 8192
  gpu_offload: max
  loaded_at: 2026-05-04T00:31:00-04:00

ModelRoute:
  id: route.verifier.high
  role: verifier
  policy:
    privacy: local_or_enterprise
    quality: high
    max_cost_usd: 0.25
  candidates:
    - local.qwen3_5_9b
    - byok.openai.gpt_4_1
  fallback:
    - byok.anthropic.claude

PermissionToken:
  audience: autopilot-local-server
  allowed:
    - model.chat:local.qwen3_5_9b
    - mcp.call:huggingface.model_search
  denied:
    - connector.gmail.send
    - filesystem.write
  expiry: 24h
  wallet_grant_id: grant_...
  revocation_epoch: 12

ModelInvocationReceipt:
  route_id: route.verifier.high
  selected_endpoint: local.qwen3_5_9b
  selected_instance: instance.local.qwen3_5_9b.20260504T0031
  provider: ioi_local
  input_hash: sha256:...
  output_hash: sha256:...
  policy_hash: sha256:...
  capability_grant_id: grant_...
  latency_ms: 1420
  input_tokens: 1200
  output_tokens: 300
  cost_usd: 0
```

### Lifecycle State Machine

```text
unknown
  -> discovered
  -> available_remote
  -> downloading
  -> downloaded
  -> mounted
  -> loading
  -> loaded
  -> serving
  -> idle
  -> evicting
  -> unloaded
```

Error states:

```text
download_failed
load_failed
health_failed
permission_denied
policy_blocked
runtime_unavailable
memory_guardrail_blocked
```

Receipts should record transitions that matter to reproducibility:

- download started/completed/failed;
- mount created/updated/deleted;
- load started/completed/failed;
- route selected/fallback selected;
- invocation completed/failed/cancelled;
- tool/MCP call allowed/denied/executed;
- idle eviction/manual unload/memory pressure eviction.

## Autopilot Mounts UI Target

The activity bar icon now opens a Mounts workbench. The current UI is useful
for daemon snapshots and basic actions, but it should continue evolving into a
full LM Studio-class local model workbench with these top-level tabs.

### Local Server

Controls:

- status: stopped, starting, running, degraded;
- bind host and port;
- OpenAI-compatible base URL;
- native IOI API base URL;
- start, stop, restart;
- require token toggle;
- server logs;
- route health;
- runtime backend health.

Primary rows:

```text
Server           Running on 127.0.0.1:1977
OpenAI API       http://127.0.0.1:1977/v1
Native API       http://127.0.0.1:1977/api/v1
Auth             Required
Receipts         Enabled
Router           Healthy
```

### Models

Subsections:

- Installed;
- Available;
- Mounted Endpoints;
- Loaded Now;
- Downloads;
- Benchmarks.

Columns:

```text
Name
Provider
Type
Capabilities
Format
Quantization
Size
Context
Privacy
Load policy
Status
Actions
```

Actions:

- download;
- import;
- mount;
- load;
- unload;
- route test;
- benchmark;
- reveal receipts;
- remove mount;
- delete local artifact.

### Providers

Provider profiles:

- Local folder;
- LM Studio endpoint;
- Ollama endpoint;
- vLLM endpoint;
- OpenAI-compatible endpoint;
- OpenAI BYOK;
- Anthropic BYOK;
- Gemini BYOK;
- Custom HTTP;
- future DePIN / TEE runtime.

Every provider profile needs:

- health probe;
- auth mode;
- base URL;
- supported API format;
- model discovery strategy;
- secret storage strategy;
- privacy class;
- receipt strategy;
- fallback eligibility.

### Tokens And MCP

Token section:

- create capability token;
- list active tokens;
- revoke token;
- show scopes, expiry, audience, last used;
- export local-only dev token when policy permits.

MCP section:

- import `mcp.json`;
- add remote MCP;
- add stdio MCP;
- validate tool contracts;
- assign risk class;
- scope allowed tools;
- bind headers/secrets through wallet vault;
- test call;
- show MCP receipts.

### Routing Policies

Routing policies should be first-class because workflows should not hardcode
model IDs unless the user explicitly wants that.

Example:

```yaml
model_policy:
  role: verifier
  privacy: local_or_enterprise
  quality: high
  max_cost_usd: 0.25
  fallback:
    - local.qwen3_5_9b
    - byok.openai.gpt_4_1
```

The UI should show:

- policy name;
- role;
- privacy class;
- cost ceiling;
- latency preference;
- candidate routes;
- fallback route;
- last selected model;
- last invocation receipt;
- failure behavior.

## REST API Plan

Autopilot should implement both a native API and compatibility APIs.

### Native API

```http
GET  /api/v1/server/status
POST /api/v1/server/start
POST /api/v1/server/stop
POST /api/v1/server/restart
GET  /api/v1/server/logs
GET  /api/v1/server/events

GET  /api/v1/models
GET  /api/v1/models/:id
GET  /api/v1/models/catalog/search
POST /api/v1/models/catalog/import-url
POST /api/v1/models/download
GET  /api/v1/models/download/status/:job_id
POST /api/v1/models/import
POST /api/v1/models/storage/cleanup
DELETE /api/v1/models/:id
POST /api/v1/models/mount
POST /api/v1/models/unmount
POST /api/v1/models/load
POST /api/v1/models/unload
GET  /api/v1/models/loaded

GET  /api/v1/runtime/engines
GET  /api/v1/runtime/engines/:id
POST /api/v1/runtime/engines/:id/select
PATCH /api/v1/runtime/engines/:id
DELETE /api/v1/runtime/engines/:id
POST /api/v1/runtime/survey
POST /api/v1/runtime/select

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
```

### OpenAI-Compatible API

```http
GET  /v1/models
POST /v1/responses
POST /v1/chat/completions
POST /v1/embeddings
POST /v1/completions
```

Compatibility endpoints should:

- accept OpenAI-compatible clients;
- route through the Model Router;
- apply wallet capability enforcement;
- emit IOI receipts;
- expose compatibility errors without leaking internal policy details;
- support JIT loading where policy allows.

### Anthropic-Compatible API

Autopilot supports message calls and deterministic SSE streaming through the
governed router/capability/receipt path:

```http
POST /v1/messages
```

Remaining work is provider-native token streaming, cancellation, richer
multimodal content blocks, and advanced tool-use events.

## Permission And Secret Model

LM Studio's local API token feature is a good developer primitive. Autopilot
needs stronger authority semantics.

### Rules

1. Provider API keys must not live as plaintext model config.
2. MCP headers and connector secrets must bind to wallet.network vault entries.
3. Local dev tokens may be generated, but every token has an audience, expiry,
   scope, and revocation epoch.
4. Tokens authorize capabilities, not UI sections.
5. Tokens and capability grants must be referenced by receipt IDs.
6. Compatibility endpoints must enforce the same grants as native endpoints.

### Token Example

```yaml
PermissionToken:
  id: token.local.dev.20260504
  audience: autopilot-local-server
  allowed:
    - model.chat:route.chat.local_default
    - model.embed:local.nomic_embed
    - mcp.call:huggingface.model_search
  denied:
    - connector.gmail.send
    - filesystem.write
    - shell.exec
  expiry: 2026-05-05T00:00:00-04:00
  wallet_grant_id: grant.wallet.local_models_dev
  revocation_epoch: 12
```

## MCP Mapping

LM Studio currently follows Cursor-style `mcp.json` notation. Autopilot should
accept that shape as an import format, then compile it into the Tool Registry.

Input:

```json
{
  "mcpServers": {
    "hf-mcp-server": {
      "url": "https://huggingface.co/mcp",
      "headers": {
        "Authorization": "Bearer <vault:wallet/hf-readonly>"
      }
    }
  }
}
```

Compiled Autopilot view:

```yaml
ToolProvider:
  id: mcp/hf-mcp-server
  type: remote_mcp
  server_url: https://huggingface.co/mcp
  risk_class: external_network
  secret_refs:
    Authorization: vault:wallet/hf-readonly
  allowed_tools_default:
    - model_search
  receipts_required: true
```

Per-request API shape:

```json
{
  "model": "route.research.local_first",
  "input": "Find the latest Qwen models",
  "integrations": [
    {
      "type": "ephemeral_mcp",
      "server_label": "huggingface",
      "server_url": "https://huggingface.co/mcp",
      "allowed_tools": ["model_search"]
    }
  ]
}
```

Runtime flow:

```text
request
-> parse integrations
-> resolve MCP server
-> evaluate capability grant
-> expose allowed tool definitions to selected model
-> execute tool call through RuntimeToolContract
-> write tool receipt
-> write model invocation receipt
```

## Workflow Canvas Integration

Model mounts become useful when the workflow canvas can consume them without
hardcoding providers.

Required nodes:

| Node | Uses |
| --- | --- |
| Model Call | general chat/completion/response |
| Structured Output | JSON schema, constrained output |
| Verifier | policy-selected high-quality verification model |
| Planner | planning model role |
| Embedding | document/vector ingestion |
| Reranker | retrieval ranking |
| Vision | image/document interpretation |
| Local Tool/MCP | MCP and tool invocation |
| Model Router | route/policy selection node |
| Receipt Gate | validates invocation/tool receipts before downstream use |

Every node should support:

- `model_id` for explicit selection;
- `model_policy` for routed selection;
- `capability_requirement`;
- privacy and cost constraints;
- receipt emission;
- replay behavior.

## Receipts And Agentgres

Every model call that matters should produce a receipt.

Minimum fields:

```yaml
ModelInvocationReceipt:
  receipt_id: receipt.model.01HX...
  route_id: route.chat.local_default
  selected_endpoint: local.qwen3_5_9b
  selected_instance: instance.local.qwen3_5_9b.20260504T0031
  provider: ioi_local
  api_format: openai_compatible
  runtime_backend: llama.cpp.cuda12
  privacy_class: local
  capability_grant_id: grant.wallet.local_models_dev
  policy_hash: sha256:...
  request_hash: sha256:...
  response_hash: sha256:...
  tool_receipt_ids:
    - receipt.tool.01HY...
  input_tokens: 1200
  output_tokens: 300
  latency_ms: 1420
  cost_usd: 0
  started_at: 2026-05-04T00:00:00-04:00
  completed_at: 2026-05-04T00:00:01-04:00
```

Agentgres should persist:

- model artifacts;
- endpoints;
- provider profiles;
- routes;
- instances;
- lifecycle events;
- download jobs;
- capability grants;
- invocation receipts;
- tool receipts;
- workflow node bindings.

## Implementation Order

### Phase 0: Activity And Shell Entry

Status: complete

- Mounts activity bar icon exists.
- Mounts opens independently from Capabilities.
- Capabilities remains separate.

### Phase 1: Read-Only Registry

Status: complete for fixture, native-local, and LM Studio discovery/import
paths; live remote catalog search remains production work.

Completed:

- Model registry projection exists in the daemon.
- Provider-neutral model metadata exists.
- LM Studio endpoint discovery is one provider profile.
- LM Studio installed models are discovered through public `lms ls`.
- Mounts UI renders registry/provider/route/receipt state.
- Autopilot-native fixture artifact is created under IOI state with checksum
  and GGUF-style metadata.
- Local-path import records artifact path hash, checksum, format, quantization,
  family, and context where present.

Remaining:

- Real remote/catalog search and download metadata.
- Rich model detail pages and benchmark metadata.

### Phase 2: Local Server Status And Logs

Status: complete for deterministic server control and receipted log/event tail;
live streaming logs remain production work.

Completed:

- `GET /api/v1/server/status`.
- `POST /api/v1/server/start`, `POST /api/v1/server/stop`, and
  `POST /api/v1/server/restart`, governed by `server.control:*`.
- `GET /api/v1/server/logs` and `GET /api/v1/server/events`, governed by
  `server.logs:*`.
- Native and OpenAI-compatible base URL display.
- CLI `ioi server status|start|stop|restart|logs|events`.
- Mounts Local Server controls for start, stop, restart, and tail logs.
- Receipted redacted server operation log ring buffer.
- Provider health route and provider model/loaded routes.
- Native-local backend logs are written to daemon state.
- Deterministic backend process supervisor writes bounded backend process logs
  with process IDs, PID hashes, redacted argv hashes, start/stop events, and
  restart-stale detection.

Remaining:

- Real server log streaming / watch mode.
- Per-provider log panes.
- Provider/backend raw streaming log transport for live runners.
- Live hardware validation and scheduler tuning for real llama.cpp/vLLM/Ollama
  binaries.

### Phase 3: Mount And Load Lifecycle

Status: complete for deterministic lifecycle and provider delegation; live
model hub downloads and hardware scheduling remain production work.

Completed:

- mount/unmount;
- load/unload;
- fixture catalog search and URL import with variant metadata;
- local import modes: copy, move, hardlink, symlink, and dry-run;
- deterministic download/import jobs with queued/running/completed/failed/
  canceled states;
- artifact delete and storage cleanup scan receipts;
- progress, byte counts, checksum, target path, cancellation, cleanup, and
  lifecycle receipts;
- idle TTL/auto-evict tests;
- runtime engine selection persisted through the daemon projection;
- load estimate-only path with redacted lifecycle receipts;
- load options for GPU offload, context length, parallelism, TTL, and
  identifier through API, CLI, and Mounts UI;
- lifecycle receipts;
- LM Studio `lms load` and `lms unload` delegation for selected LM Studio
  endpoints, including public CLI load-option argument hashing.

Remaining:

- live network catalog/download jobs;
- memory pressure eviction;
- hardware-backed GPU/context/backend guardrails for real local runners;
- storage quota and destructive confirmation UX.

### Phase 4: OpenAI-Compatible API

Status: complete for current daemon/router path

Completed:

- `/v1/models`;
- `/v1/chat/completions`;
- `/v1/responses`;
- `/v1/embeddings`;
- `/v1/completions`;
- compatibility calls route through capability checks and receipts;
- LM Studio `/v1/responses` fallback to chat completions is receipted.

Remaining:

- streaming parity;
- richer OpenAI error compatibility;
- advanced Responses features such as stateful continuation and tool output
  submission.

### Phase 5: Capability Tokens

Status: complete for local adapter boundary and deterministic fake-remote
wallet.network gate; production wallet.network deployment pending

Completed:

- scoped token creation;
- allowed/denied scopes;
- expiry;
- revoke;
- endpoint enforcement;
- native and compatibility APIs share enforcement;
- token/grant receipts and audit operation-log events.
- last-used tracking;
- vault refs redacted from public token/receipt/MCP surfaces.
- deterministic fake-remote wallet.network gate proving configured adapter
  detection, denied-scope fail-closed behavior, MCP plaintext-secret rejection,
  and token/secret scan redaction.

Remaining:

- production remote wallet.network grant service;
- remote vault-backed provider key resolution;
- revocation propagation across devices.

### Phase 6: MCP

Status: complete for governed import, invoke, and per-request ephemeral MCP
fixture path; stdio/OAuth live lifecycle remains production work.

Completed:

- `mcp.json` import;
- remote MCP registration;
- `allowed_tools` narrowing;
- vault-style secret refs and redaction;
- governed MCP invocation;
- tool receipts.
- per-request ephemeral MCP in chat/response payloads, with linked tool receipt
  IDs in model invocation receipts.

Remaining:

- stdio MCP process lifecycle;
- MCP OAuth;
- tool schema discovery and model tool exposure;
- richer RuntimeToolContract execution beyond the deterministic local path.

### Phase 7: Routing Policies

Status: complete for daemon policy tests and dense Mounts UI controls; richer
benchmarks remain production work.

Completed:

- route schema;
- local-first route;
- hosted fallback blocking by privacy/cost policy;
- route test API/CLI;
- route selection receipts;
- workflow execution endpoint can target policy.
- Mounts UI exposes route test and workflow probe controls.

Remaining:

- provider scoring/benchmarks;
- latency/cost telemetry feedback;
- deeper fallback explanations in the UI.

### Phase 8: Agentgres Persistence

Status: complete for local Agentgres adapter projection/replay and
deterministic fake-remote Agentgres gate; production Agentgres sync pending

Completed:

- `AgentgresModelMountingStore` boundary;
- durable repo-local records;
- operation-log receipts;
- receipt lookup by id;
- model/route/tool/workflow receipt emission.
- canonical model mounting projection;
- receipt replay by id;
- restart continuity tests for receipt lookup and projection replay.
- deterministic fake-remote Agentgres gate proving configured adapter
  detection, projection watermark, receipt replay, download persistence, and
  token/URL secret scans.

Remaining:

- workflow run joins;
- settlement/audit pack integration.

### Phase 9: Remote Runtime Providers

Status: complete for local live-runner boundaries; BYOK/custom/attested remote
providers remain production work

Completed:

- provider profiles for LM Studio, local folder, Ollama, vLLM,
  OpenAI-compatible, OpenAI, Anthropic, Gemini, Custom HTTP, and future
  DePIN/TEE.
- generic OpenAI-compatible driver path.

Remaining:

- BYOK provider keys via wallet vault;
- native OpenAI/Anthropic/Gemini adapters;
- DePIN/TEE runtime endpoint profile;
- remote attestation and settlement receipts.

### Phase 10: Autopilot-Native Local Inference

Status: complete for deterministic Autopilot-native serving path and configured
`llama.cpp`, Ollama, and vLLM runner boundaries; live hardware validation
remains live-provider work.

This is the key phase required for "make Autopilot basically an LM Studio."

Implemented:

- local model artifact root under IOI state;
- local model import/download with checksums;
- GGUF metadata extraction;
- backend registry for llama.cpp/Ollama/vLLM/native runners;
- deterministic native-local backend lifecycle abstraction;
- deterministic backend process supervision with persisted process records,
  PID hashes, redacted argv, startup-timeout evidence, bounded logs, health
  snapshots, and stale process detection after daemon restart;
- configured `llama.cpp` runner boundary using `IOI_LLAMA_CPP_SERVER_PATH` and
  OpenAI-compatible `/v1`, with fake `llama-server` fixture coverage for spawn,
  load, invoke, unload, redacted argv, logs, and receipts;
- opt-in live `llama.cpp` gate (`npm run test:llama-cpp-live`) for real
  binary/GGUF validation when `IOI_LIVE_LLAMA_CPP=1`;
- configured Ollama runner boundary using public `ollama serve`, `/api/tags`,
  `/api/ps`, `/api/generate`, `/api/chat`, and `/api/embeddings`, with fake
  Ollama fixture coverage for serve supervision, loaded projection, load,
  invoke, unload, redacted argv, logs, and receipts;
- configured vLLM runner boundary using public `vllm serve` and
  OpenAI-compatible `/v1`, with fake vLLM fixture coverage for serve
  supervision, Responses fallback, embeddings, loaded projection, load, invoke,
  unload, redacted argv, logs, and receipts;
- resource estimate fixture and backend logs;
- OpenAI-compatible serving from Autopilot without LM Studio;
- lifecycle and invocation receipts with native backend evidence.

Validation:

- Autopilot can load and serve a deterministic local test model without LM
  Studio;
- LM Studio can still be used as an alternate provider;
- fixture, LM Studio, and native local providers all produce the same route and
  receipt shape.

## Non-Goals

Do not:

- copy LM Studio's private app state formats;
- treat LM Studio as the model layer;
- stop at being an LM Studio wrapper; Autopilot must grow its own local
  model serving path;
- put provider secrets in model endpoint YAML;
- make loaded model instances the primary workflow contract;
- let OpenAI-compatible endpoints bypass wallet capability policy;
- make MCP tools available without risk classification and receipts;
- hide route selection from receipts;
- merge this with Capabilities UI. Mounts and Capabilities are adjacent, not the
  same section.

## Open Decisions

| Decision | Default recommendation |
| --- | --- |
| Default local API port | Use an IOI-specific port; show compatibility base URLs clearly |
| Native endpoint prefix | Keep `/api/v1/*` for local server parity |
| Model route vs model endpoint naming | Route is policy; endpoint is provider/runtime target |
| Secrets storage | wallet.network vault only |
| Local dev token | Allow, but scoped, expiring, revocable |
| MCP import | Accept Cursor/LM Studio-style `mcp.json`, compile to Tool Registry |
| Receipts default | Enabled for all non-trivial model and tool invocations |
| Headless mode | IOI daemon owns it; desktop is optional |

## Validation Checklist

Current status:

- Complete: canonical deterministic E2E gate passes with API, CLI, GUI,
  workflow, MCP, token, receipt, replay, and redaction evidence:
  `npm run validate:model-mounting:e2e`.
- Complete: Mounts activity opens independently from Capabilities.
- Complete: Local Server tab shows daemon status and base URLs.
- Complete: Installed model list includes fixture and LM Studio discovery.
- Complete: Mounted endpoints include provider-neutral records.
- Complete: Loaded Now reflects runtime instances.
- Complete: load/unload/import/download fixture actions produce lifecycle
  receipts.
- Complete: TTL and auto-evict behavior are testable.
- Complete: OpenAI-compatible endpoints route through policy and receipts;
  `/v1/chat/completions` supports deterministic SSE with final `[DONE]` and
  linked receipt metadata, and `/v1/responses` supports deterministic
  Responses-style SSE with linked receipt metadata for `stream: true`.
- Complete: Anthropic-compatible `/v1/messages` routes through policy and
  receipts, accepts Bearer or `x-api-key` capability tokens, records invocation
  receipts, supports deterministic Anthropic SSE events with final receipt
  metadata, and fails closed for missing, denied, and revoked tokens.
- Complete: deterministic stream cancellation receipts are emitted when clients
  disconnect before the final SSE frame on `/v1/chat/completions`,
  `/v1/responses`, and `/v1/messages`.
- Complete: provider-native stream lifecycle receipts are validated across
  GUI, API, CLI, receipt replay, and daemon restart projection for the
  deterministic native-local path.
- Complete: local Ollama live backend stream parity passed with completed and
  client-aborted provider-native chat-completion stream receipts, linked
  invocation receipts, route/backend evidence, replay, and redaction evidence.
- Complete: native endpoints return provider-neutral objects.
- Complete: tokens enforce model/tool/MCP capability scopes.
- Complete: Mounts token scope editor creates session-only raw tokens,
  exposes allowed/denied scopes, expiry, grant/audit metadata, last-used
  scope, vault-ref projections, and revocation controls without persisting
  token material.
- Complete: `mcp.json` import does not expose secrets.
- Complete: per-request ephemeral MCP in chat/responses links governed tool
  receipts to model invocation receipts.
- Complete: workflow execution contract can target model policies.
- Complete: Agent IDE node contracts expose model mounting fields for the
  canvas/harness layer.
- Complete: canonical local Agentgres projection and receipt replay survive
  daemon restart.
- Complete: CLI agrees with the same daemon state for server, backends, models,
  loaded instances, routes, MCP, tokens, receipts, and receipt replay.
- Complete: Mounts desktop GUI is validated by screenshots through the
  canonical E2E gate and dedicated GUI harness.
- Complete: provider, vault, and backend health receipts are visible through
  health lookup APIs, the filtered Logs / Receipts observability stream, the
  Local Server health summary strip, and the Mounts `Run health sweep` action.
- Complete: runtime engine inventory and hardware survey are visible through
  `/api/v1/runtime/engines`, `/api/v1/runtime/survey`, `ioi backends survey`,
  runtime survey receipts, projection/replay, and the Mounts Backends panel.
- Complete: selected runtime preference and load options are visible through
  `/api/v1/runtime/select`, `ioi backends select`, estimate-only load receipts,
  LM Studio public load delegation argument hashing, `ioi models load` flags,
  and Mounts model load controls.
- Complete: runtime engine profile management supports get/update/remove,
  disable/enable, priority, operator label, and default GPU/context/parallel/
  TTL/identifier options through API, CLI, receipts, projection/replay, E2E,
  and the Mounts Backends profile editor.
- Complete: deterministic native-local backend process supervision persists
  process records, PID hashes, redacted argv, startup-timeout evidence, health
  snapshots, bounded logs, and stale-recovered state after daemon restart; load
  and invocation receipts link the same backend process evidence.
- Complete: deterministic server/log parity includes governed start, stop,
  restart, log tail, event tail, CLI parity, Mounts Local Server controls, and
  redacted lifecycle receipts.
- Complete: Mounts Logs / Receipts includes streaming observability filters
  for request/response direction, category, status, receipt kind,
  route/endpoint/provider search, live refresh, redacted payload preview,
  server log tail, and replay links.
- Complete: receipts show route, selected endpoint, selected instance, backend,
  policy hash, grant id, token counts, latency, and tool receipt IDs where
  applicable.
- Complete: Mounts benchmark/results panel runs selected route benchmarks
  through governed chat/responses/embeddings calls and displays invocation
  receipt telemetry for latency, tokens, backend, route, endpoint, grant, and
  replay.
- Complete: Mounts action readiness states show degraded/denied reasons for
  daemon connectivity, missing/on-demand tokens, denied or expired scopes,
  provider/backend health, endpoint capability, route privacy/policy blocks,
  and vault-ref requirements before action dispatch.
- Complete: deterministic Autopilot-native local serving path operates without
  LM Studio.
- Complete: deterministic download/import lifecycle includes progress, failure,
  cancel, cleanup, and receipts.
- Complete: deterministic catalog/import parity includes fixture catalog
  search, URL import, variant metadata, import dry-run/copy/move/hardlink/
  symlink modes, artifact delete, and storage cleanup scan receipts.
- Production hardening: replace deterministic native-local fixture with real
  local inference binaries when configured.
- Production hardening: wire production wallet.network and Agentgres services;
  deterministic fake-remote boundary gates now pass locally.
- Production hardening: provider-native BYOK adapters and attested remote
  runtime profiles.

## Immediate Backlog

The deterministic target path is complete. The immediate backlog is now the
parity closeout order from the matrix above:

1. Live catalog/download activation.
2. Product UI parity beyond the validated picker, loaded-instance inspector,
   model detail drawer, route editor, token editor, benchmark/results panel,
   degraded/denied action readiness, and filtered observability stream.
3. Live backend/provider parity: Ollama has passing local live evidence; next
   execute the opt-in live `llama.cpp` and vLLM lifecycle/stream gates on an
   operator machine, then add BYOK hosted adapters.
4. Raw live-log streaming parity for providers/backends with `lms log stream`
   style transports.
5. Production IOI hardening beyond LM Studio.

Keep each backlog item behind the validated daemon/router/capability/receipt
path. The deterministic fixture remains the CI baseline, and live provider
activation remains opt-in until explicitly configured.

## Appendix: Local Command Evidence

Local model list:

```text
You have 2 models, taking up 6.63 GB of disk space.

LLM                            PARAMS    ARCH      SIZE       DEVICE
qwen/qwen3.5-9b (1 variant)    9B        qwen35    6.55 GB    Local

EMBEDDING                               PARAMS    ARCH          SIZE        DEVICE
text-embedding-nomic-embed-text-v1.5              Nomic BERT    84.11 MB    Local
```

Loaded model list:

```text
IDENTIFIER         MODEL              STATUS    SIZE       CONTEXT    PARALLEL    DEVICE    TTL
qwen/qwen3.5-9b    qwen/qwen3.5-9b    IDLE      6.55 GB    4096       4           Local
```

Server status:

```text
The server is running on port 1234.
```

Runtime engine list:

```text
LLM ENGINE                                          SELECTED    MODEL FORMAT
llama.cpp-linux-x86_64-avx2@2.13.0                                  GGUF
llama.cpp-linux-x86_64-avx2@2.10.0                                  GGUF
llama.cpp-linux-x86_64-nvidia-cuda-avx2@2.13.0                      GGUF
llama.cpp-linux-x86_64-nvidia-cuda-avx2@2.10.0                      GGUF
llama.cpp-linux-x86_64-nvidia-cuda12-avx2@2.13.0       yes          GGUF
llama.cpp-linux-x86_64-nvidia-cuda12-avx2@2.12.0                    GGUF
llama.cpp-linux-x86_64-vulkan-avx2@2.13.0                           GGUF
llama.cpp-linux-x86_64-vulkan-avx2@2.10.0                           GGUF
```

Runtime survey:

```text
Survey by llama.cpp-linux-x86_64-nvidia-cuda12-avx2 (2.13.0)
GPU/ACCELERATORS                                      VRAM
NVIDIA GeForce RTX 5070 Laptop GPU (CUDA, Discrete)   7.53 GiB

CPU: x86_64 (AVX2, AVX)
RAM: 93.73 GiB
```

OpenAI-compatible model list:

```json
{
  "data": [
    {
      "id": "qwen/qwen3.5-9b",
      "object": "model",
      "owned_by": "organization_owner"
    },
    {
      "id": "text-embedding-nomic-embed-text-v1.5",
      "object": "model",
      "owned_by": "organization_owner"
    }
  ],
  "object": "list"
}
```

Fresh native catalog probe:

```json
{
  "models": [
    {
      "type": "llm",
      "key": "qwen/qwen3.5-9b",
      "loaded_instances": [
        {
          "id": "qwen/qwen3.5-9b",
          "config": {
            "context_length": 4096,
            "eval_batch_size": 512,
            "parallel": 4,
            "flash_attention": true,
            "offload_kv_cache_to_gpu": true
          }
        }
      ],
      "capabilities": {
        "vision": true,
        "trained_for_tool_use": true,
        "reasoning": {
          "allowed_options": ["off", "on"],
          "default": "on"
        }
      }
    }
  ]
}
```

Fresh legacy stats/model-shape probe:

```json
{
  "id": "qwen/qwen3.5-9b",
  "type": "vlm",
  "compatibility_type": "gguf",
  "quantization": "Q4_K_M",
  "state": "loaded",
  "max_context_length": 262144,
  "loaded_context_length": 4096,
  "capabilities": ["tool_use"]
}
```

Fresh Anthropic-compatible messages probe:

```json
{
  "type": "message",
  "role": "assistant",
  "content": [{ "type": "text", "text": "OK!" }],
  "model": "qwen/qwen3.5-9b",
  "stop_reason": "end_turn",
  "usage": {
    "input_tokens": 15,
    "output_tokens": 3
  }
}
```

Redacted MCP config:

```json
{
  "mcpServers": {}
}
```

Relevant local files:

```text
~/.lmstudio/settings.json
~/.lmstudio/mcp.json
~/.lmstudio/models/lmstudio-community/Qwen3.5-9B-GGUF/Qwen3.5-9B-Q4_K_M.gguf
~/.lmstudio/models/lmstudio-community/Qwen3.5-9B-GGUF/mmproj-Qwen3.5-9B-BF16.gguf
~/.lmstudio/.internal/model-index-cache.json
~/.lmstudio/.internal/backend-preferences-v1.json
~/.lmstudio/server-logs/2026-05/2026-05-04.1.log
```

The `.internal` files above are observational evidence only. Autopilot must not
depend on private LM Studio state formats as stable contracts.
