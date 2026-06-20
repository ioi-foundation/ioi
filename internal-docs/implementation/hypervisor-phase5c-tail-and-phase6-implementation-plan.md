# Hypervisor Phase 5c-tail + Phase 6 Implementation Plan

Status: implementation-grade plan
Owner: Hypervisor Core (crates/services model_mount kernel) / Hypervisor Daemon (crates/node hypervisor-daemon) / Hypervisor App
Primary architecture authority: `docs/architecture/_meta/start-here.md`
Related:
- `internal-docs/implementation/hypervisor-real-environment-and-harness-execution-master-guide.md` (the parent guide; Phases 0–5b/5c-core are done)
- `internal-docs/implementation/hypervisor-model-mount-rust-consolidation-and-deadcode-retirement.md` (the consolidation/retirement plan this executes)
- `docs/architecture/components/hypervisor/providers-and-environments.md` (canon: Environment Status Object)
Last reviewed: 2026-06-20

This plan finishes Phase 5 (make `scripts/validate-model-mounting-e2e.mjs` green
against Rust Core, retire the JS model-mount facade, add the proto) and Phase 6
(the live-Qwen "build a PQC website" loop). It is grounded in the exact contracts
the e2e enforces. Branch in flight: `hypervisor-real-execution-master-guide`.

## 0. Where we are (the gap, precisely)

What the Rust `crates/node/src/bin/hypervisor-daemon.rs` serves today (9 routes):
`GET /healthz`, `GET /readyz`, `GET /v1/hypervisor/dev-replay/status`,
`GET /v1/models`, `GET /v1/model-mount/snapshot` (real `plan_read_projection`),
`POST /v1/model-mount/read-projection`, `POST /v1/model-mount/native-local`
(real `admit_provider_execution`→`invoke_provider`, deterministic + offline),
`POST /v1/chat/completions` (HttpInferenceRuntime), `POST /v1/hypervisor/session-turns`.

What the binding spec drives. `scripts/validate-model-mounting-e2e.mjs` (1,579
lines) is the contract. **It does not talk to the Rust daemon at all today** — it
`import { startRuntimeDaemonService }` (line 10) and boots the **JS** daemon on an
ephemeral port (line 389), then drives ~80 `/v1/model-mount/*` + OpenAI-compat
endpoints with Bearer capability-token auth, a fail-closed matrix, persisted
receipts, server-restart survival, redaction, and a Rust-CLI cross-check.

Why it is red. The JS daemon's `ModelMountingState`
(`packages/runtime-daemon/src/model-mounting.mjs`, 6,326 lines) **builds every
request, owns all daemon state, and produces every camelCase response shape** the
e2e asserts. It delegates *only the kernel computation* to a 49-method
`daemonCoreModelMountApi` object. That object is **never wired** (`= null`
default), so the very first step (`GET /v1/model-mount/server/status` →
`planReadProjection` → `invokeModelMountApi(...)`) throws 502
`model_mount_core_direct_model_mount_api_unconfigured`. (Reads otherwise throw 501
`model_mount_read_projection_rust_core_required`.)

**The architectural fork.** Because the JS facade delegates *only* kernel
computation to that 49-method seam, the contract splits cleanly into two layers:
the **kernel** (`ModelMountCore` — stateless unit struct, all methods `&self,
&Request -> Result<Plan, Error>`; **already done and proven** via the shipped
native-local chain) and the **daemon-owned admission/projection + shaping layer**
(capability-token *records*, receipts, catalog, redaction, restart-survival,
camelCase response shaping — the bulk of the 6,326 JS lines), which the daemon
*admits and projects over Agentgres-recorded truth* (it does not mint truth). The
fork: bolt the JS facade onto the Rust kernel via that seam (cheap, but throwaway
and keeps the split-brain), **or** rebuild that admission/projection layer in Rust
so one Rust daemon owns the whole execution surface. §1 chooses the latter.

## 1. The strategy decision (explicit)

**Decision: go straight to Strategy A — the unified Rust substrate.** The Rust
daemon serves the full `/v1/model-mount/*` + OpenAI-compat surface directly,
owning the **execution + admission/projection + shaping layer** and calling
`ModelMountCore` in-process; the e2e is repointed at the Rust binary; the JS
`model-mounting.mjs` facade is retired. This is the canonical end-state
(`_meta/hypervisor-kernel-substrate-unification-master-guide.md` Authority owner
map + Final Doctrine; consolidation plan §2.5: one Rust true-north daemon, JS
retired), and it is all permanent work.

> **Ownership invariant (canon — baked into every Phase 5c sub-phase).** Per the
> kernel-substrate-unification master guide's Authority owner map and Final
> Doctrine: **the daemon owns *execution semantics*** (what may cross an effect
> boundary); **Agentgres owns *canonical operational truth*** (accepted
> operations, refs, heads, state roots, **receipts**, projections, replay);
> **wallet.network owns *authority*** (capability grants/leases). So everything
> "the daemon owns" below is an **Agentgres-admitted record + projection**, not
> free-standing daemon truth: token mint/revoke and receipts **commit through the
> Rust model_mount record-state admission path** (admit → state-root/head bind →
> commit) *before* they are served, and every capability token is **rooted in a
> wallet.network grant** (the daemon *enforces* the 401/403 gate, it does not
> *decide* the authority). The daemon never authors-and-serves canonical truth —
> doing so is the exact Agentgres-bypass split-brain canon forbids and this
> migration exists to kill.

| | Strategy | What it is | Verdict |
| - | -------- | ---------- | ------- |
| **A** | **Full Rust route surface (CHOSEN)** | Rust daemon owns the admission/projection + shaping layer (capability-token records, receipts, catalog, redaction, restart-survival) **over Agentgres-admitted truth, with wallet.network authority** + exact shapes, calling `ModelMountCore` in-process; e2e spawns the Rust binary; JS facade deleted. | **The substrate end-state. Build this.** |
| ~~B1~~ | ~~`daemonCoreModelMountApi` HTTP bridge~~ | ~~Rust exposes 49 `/core/:method` endpoints; JS bridge forwards; JS keeps owning shapes.~~ | **Rejected — mostly throwaway** (JS bridge deleted by A; the `/core/:method` endpoints are dead once A calls the kernel in-process; keeps the 6,326-line facade A removes). |
| ~~B2~~ | ~~in-process napi bridge~~ | ~~napi binding exposes the 49 methods to JS.~~ | Rejected — same JS-facade dependency; needs napi infra. |

Why A directly (not B1-then-A). The only thing the bridge would validate is "the
kernel produces e2e-acceptable plans" — **already proven** by the shipped
native-local chain (`admit_provider_execution → invoke_provider` returns a
complete real `ModelMountProviderInvocationResult`). So the parity risk that would
justify a bridge is retired; the bridge would be ~2 sub-phases of throwaway.

**What A actually entails.** Not "port the kernel" (it is done) — but **build the
Rust daemon's admission/projection layer the kernel deliberately does not own**:
capability-token *records* (wallet.network-rooted — each bound to a wallet
capability lease/grant; store `token_hash` only, never raw), the receipt log, the
seeded provider catalog (9 kinds + 7 backends), redaction, restart-survival /
per-`bootId` stale recovery, and the exact camelCase response shapes — **each
persisted as an Agentgres-admitted record, not free-standing daemon truth**. That
is the bulk of the 6,326 JS lines, and it is the *right* bulk to move: a unified
substrate means Rust owns **execution + admission/projection**, while **Agentgres
still owns truth and wallet.network still owns authority** — the daemon admits and
projects, it does not mint truth.

**De-risking without a bridge — the e2e as a ratchet.** A one-time harness edit
makes `validate-model-mounting-e2e.mjs` spawn the Rust binary; it then fails at the
*first* unimplemented route. Each route family built in Rust moves the ratchet
forward — incremental green, all permanent. (Escape hatch: B1 is only worth
revisiting under a hard near-term schedule gate that needs the app on Rust Core
before A is complete; absent that, do A.)

## 2. The binding spec (what GREEN requires)

`validate-model-mounting-e2e.mjs`, in order. The daemon-start abstraction must
return `{ endpoint, stateDir, store, close: () => Promise }`
(`runtime-daemon-service.mjs:70-79`).

**Auth / fail-closed matrix.** Mint: `POST /v1/model-mount/tokens`
`{allowed:[scopes], denied:[], expiresAt?, audience?}` → `{id, token, ...}`.
Revoke: `DELETE /v1/model-mount/tokens/:id`. Bearer = `authorization: Bearer <token>`.
- `POST /v1/chat/completions {input}` **no token → 401**.
- denied scope → **403**; `expiresAt` in the past → **403**; revoked id → **403**.

**Route families exercised (~80 endpoints).** server/status (`schemaVersion ===
"ioi.model-mounting.runtime.v1"`), server/{stop→`controlStatus:"stopped"`,
restart→`"running"`, logs?limit→`redaction:"redacted"` + a `server_restart`
record, events}, tokens (POST/DELETE), snapshot, runtime/{engines, survey, select,
engines/:id GET+PATCH}, chat/completions, responses, messages (Anthropic),
embeddings, rerank, completions, models, tokens/{tokenize,count}, context/fit,
artifacts/import, endpoints, instances/load, downloads, mcp/{import,invoke},
routes, catalog/import-url, workflows/{nodes/execute,receipt-gate},
vault/{refs,status,health}, receipts, receipts/:id, projection. Plus the Rust CLI
(`cargo build -p ioi-cli --bin cli` then `cli <cmd> --endpoint <endpoint>`)
cross-checking the same daemon.

**Snapshot (`GET /v1/model-mount/snapshot`).** `providers[].kind` must include all
9: `local_folder, ioi_native_local, lm_studio, ollama, llama_cpp, vllm,
openai_compatible, custom_http, depin_tee`. `backends[].id` must include all 7:
`backend.fixture, backend.hypervisor.native-local.fixture, backend.llama-cpp,
backend.ollama, backend.vllm, backend.lmstudio, backend.openai-compatible`.

**Runtime engines.** one engine id `backend.hypervisor.native-local.fixture`;
`POST runtime/survey` → `receiptId =~ /^receipt_runtime_survey_/`,
`schemaVersion "ioi.model-mounting.runtime.v1"`, numeric `hardware.totalMemoryBytes`;
`runtime/select {engine_id}` echoes `selectedEngineId`; the estimate-only load and
the native engine PATCH persist **`contextLength: 3584, parallel: 3`** (operator
profile defaults, not request-derived).

**Inference.** native-local path: `route.native-local`, provider
`provider.hypervisor.local`, backend `backend.hypervisor.native-local.fixture`,
`output_text` matches `/Hypervisor native local model response/`,
`invocation_hash =~ /^sha256:[a-f0-9]{64}$/`. Streaming (`stream:true`) → OpenAI
`chat.completion.chunk` SSE frames + `[DONE]`; abort-after-first-chunk records a
`stream_canceled` receipt (`reason:"client_disconnect"`). Receipts:
`receipt.kind`, `receipt.details.routeId`, `previousResponseId`,
`continuation.mode`; `pidHash =~ /^[a-f0-9]{16}$/`.

**Redaction.** logs/receipts JSON must NOT contain `~/.lmstudio/bin/lms`,
`~/.local/bin/lm-studio`, the grant `token`, or other secret needles.

## 3. Phase 5c — implementation (Strategy A, e2e-ratcheted)

Build the Rust daemon's stateful layer family by family; each sub-phase advances
the e2e ratchet (it fails at the first unported route). Suggested Rust layout:
`crates/node/src/bin/hypervisor-daemon.rs` (router + main) delegating to a new
`crates/node/src/hypervisor_daemon/` module tree (`state.rs` token+receipt+catalog
stores, `model_mount_routes.rs`, `inference_routes.rs`, `session_routes.rs`) — or a
small `ioi-hypervisor-daemon` crate if the bin grows large. The kernel
(`ModelMountCore`) is called in-process; the daemon owns all state.

### Phase 5c.0 — Point the e2e at the Rust daemon (the ratchet)

| Field | Detail |
| ----- | ------ |
| Goal | `validate-model-mounting-e2e.mjs` drives the Rust binary, failing at the first unimplemented route (the progress marker for 5c.1–5c.5). |
| Work | Replace the harness's daemon abstraction: instead of `startRuntimeDaemonService`, spawn `target/debug/hypervisor-daemon` (build first; bind an ephemeral port via `IOI_HYPERVISOR_DAEMON_ADDR=127.0.0.1:0` reading the chosen port from a startup log line, or pass a fixed test port; fresh `IOI_HYPERVISOR_DATA_DIR=stateDir`), wait for `/healthz`, and return `{ endpoint, stateDir, close: () => kill }`. The restart step re-spawns against the same `stateDir`. Keep EVERY assertion byte-identical. |
| Files | `scripts/validate-model-mounting-e2e.mjs` (daemon abstraction only). |
| Verify | The script runs and fails on the first unported model-mount route (expected); `node scripts/validate-hypervisor-daemon-e2e.mjs` stays green. |
| Commit boundary | The binding spec now measures the Rust daemon. |

### Phase 5c.1 — Capability-token records (wallet-rooted, Agentgres-admitted) + server control + receipts + redaction

| Field | Detail |
| ----- | ------ |
| Goal | Pass e2e steps 1–3 (fail-closed auth, server status/stop/restart/logs/events) — via the canonical admission path, not daemon-local truth (see the Ownership invariant in §1). |
| Work | Every write commits through the model_mount record-state path (admit → state-root/head bind → commit) **before** it is served. **Tokens (wallet-rooted):** `POST /tokens` runs `ModelMountCore.plan_capability_token_control` (op `model_mount.capability_token.create`), binds each grant to a **wallet.network capability lease/grant ref** (`grant_id`/`lease_id` + `policy_hash` + `revocation_epoch`), and persists a redacted Rust-authored Agentgres record under `state_dir` (content-hashed `token_id`; **`token_hash` only**, `plaintext_material_persisted:false`); `DELETE /tokens/:id` revokes via the same path. `authorize(bearer, scope)` projects allowed/denied **from the wallet grant** and the daemon *enforces* **401** (no/empty bearer) / **403** (denied/expired/revoked) — it enforces, it does not *decide* authority. **Server control:** `GET /server/status` → `{schemaVersion:"ioi.model-mounting.runtime.v1", openAiCompatibleBaseUrl, controlStatus:"running"}`; `server/stop`→`"stopped"`, `restart`→`"running"`, `logs?limit`→`{redaction:"redacted", records:[…server_restart…]}`, `events?limit`. **Receipts:** Rust-authored records committed through the record-state/receipt-state admission path (not a free-standing log), served at `GET /receipts` + `/receipts/:id`. A redaction pass over all output (drop secret needles + raw tokens). |
| Verify | e2e advances past the token + server-control steps. |
| Commit boundary | Wallet-rooted fail-closed auth + server control + Agentgres-admitted receipts. |

### Phase 5c.2 — Seeded provider catalog + snapshot/projection family

| Field | Detail |
| ----- | ------ |
| Goal | `GET /snapshot` lists the 9 provider kinds + 7 backends; the read-projection family answers. |
| Work | On first startup author the baseline catalog as **Agentgres-admitted records** (NOT a raw `fs::write` of fixture JSON): commit the 9 provider kinds (`local_folder, ioi_native_local, lm_studio, ollama, llama_cpp, vllm, openai_compatible, custom_http, depin_tee`) + 7 backends (`backend.fixture, backend.hypervisor.native-local.fixture, backend.llama-cpp, backend.ollama, backend.vllm, backend.lmstudio, backend.openai-compatible`) through the same Rust model_mount record-state admission the writes use, so `model-providers`/`model-endpoints`/`model-instances`/`model-artifacts` under `state_dir` are admitted records, not a daemon-local cache. Then the read side replays them: `GET /snapshot|/projection|/providers|/endpoints|/instances|/backends|/routes|/authority|/downloads` → `ModelMountCore.plan_read_projection({projection_kind, state, state_dir})` (Appendix B). `POST /instances/load|unload` → `plan_instance_lifecycle` (admitted write → projected read). `depin_tee` must not be presented as a private route without cTEE/custody (per `daemon-runtime/private-workspace-ctee.md`). |
| Verify | e2e "discover providers and backends" + instance steps pass. |
| Commit boundary | The real kernel replays the Agentgres-admitted catalog over HTTP. |

### Phase 5c.3 — Runtime engines + survey + select + PATCH

| Field | Detail |
| ----- | ------ |
| Goal | Runtime-engine family with operator-profile defaults. |
| Work | `GET /runtime/engines` (one `backend.hypervisor.native-local.fixture`); `POST /runtime/survey` → `{receiptId:/^receipt_runtime_survey_/, schemaVersion:"ioi.model-mounting.runtime.v1", hardware.totalMemoryBytes:<number>, engines:[…]}` (+ a `runtime_survey` receipt; redact `~/.lmstudio/bin/lms` etc.); `POST /runtime/select {engine_id}` echoes `selectedEngineId`; `GET|PATCH /runtime/engines/:id` persisting operator-profile defaults **`contextLength: 3584, parallel: 3`** via `plan_runtime_engine`. |
| Verify | e2e runtime-engine + survey + select + PATCH steps pass. |
| Commit boundary | Runtime engine controls + 3584/parallel-3 defaults are served. |

### Phase 5c.4 — Inference: chat / responses / messages / embeddings / rerank + streaming

| Field | Detail |
| ----- | ------ |
| Goal | The OpenAI-compat surface with the native-local kernel path + real receipts. |
| Work | `POST /v1/chat/completions|/responses|/messages|/embeddings|/rerank|/completions` (Bearer + scope check). For `route.native-local`, reuse the SHIPPED admission→invoke chain (`provider.hypervisor.local`, `backend.hypervisor.native-local.fixture`, `output_text` "Hypervisor native local model response", `invocation_hash` sha256). Non-stream → OpenAI/Anthropic envelope from `ModelMountProviderInvocationResult.output_text` + `token_count`; `stream:true` → `invoke_provider_stream` → `chat.completion.chunk` SSE + `[DONE]`, recording a `model_invocation` receipt (`details.routeId`, `previousResponseId`, `continuation.mode`) and a `stream_canceled` receipt on client disconnect (`reason:"client_disconnect"`); `pidHash` `/^[a-f0-9]{16}$/`. Hosted providers (real Ollama/OpenAI) route through the kernel hosted path or `HttpInferenceRuntime`. |
| Verify | e2e inference + streaming + abort + receipt-shape steps pass. |
| Commit boundary | Real model-mount inference + streaming + receipts over the OpenAI-compat surface. |

### Phase 5c.5 — The remaining families

| Field | Detail |
| ----- | ------ |
| Goal | Everything the e2e still drives. |
| Work | `artifacts/import`, `endpoints`, `downloads/:id/{status,cancel}`, `mcp/{import,invoke}`, `routes`, `catalog/import-url`, `workflows/{nodes/execute,receipt-gate}` (412 on gate mismatch), `vault/{refs,status,health}` (hashed refs), `tokens/{tokenize,count}`, `context/fit`, `GET /v1/models`. Each → the matching `ModelMountCore.plan_*`/`admit_*` method + the daemon shape. Verify the Rust **CLI** (`ioi-cli`) cross-check steps pass against the Rust daemon endpoint. |
| Verify | `node scripts/validate-model-mounting-e2e.mjs` **fully GREEN** against the Rust binary. |
| Commit boundary | The Rust daemon satisfies the entire binding spec. |

### Phase 5c.6 — Retire the JS facade

| Field | Detail |
| ----- | ------ |
| Goal | One Rust true-north daemon; the parallel JS engine is gone. |
| Work | Delete / reduce to a thin shim: `packages/runtime-daemon/src/model-mounting.mjs` + `model-mounting/**` + `openai-compat-routes.mjs` + the model-mount route handlers in `public-runtime-routes.mjs` + the model-mounting `*.test.mjs` suite. Collapse the dev-replay model-mount routes to a thin proxy; **keep** the Phase-0 deterministic turn behind `IOI_HYPERVISOR_REPLAY_MODE` for offline UI tests. **Before deleting `model-mounting.mjs`, migrate any identity token only present there into the Rust kernel sources** (see §5) so `check-runtime-layout` survives. App default stays `:8765` → no app change. |
| Verify | e2e still green; `check-runtime-layout`; `hypervisor-app-shell-contract`; `npm run build`; `cargo test`. |
| Commit boundary | The split-brain facade is gone; Rust owns execution + the admission/projection layer + compute, over Agentgres truth and wallet.network authority. |

### Phase 5c.7 — `ioi.model_mount.v1` proto

| Field | Detail |
| ----- | ------ |
| Goal | A typed RPC surface for the kernel (the canonical transport for non-HTTP callers). |
| Work | Add `crates/ipc/proto/model_mount/v1/model_mount.proto`: `syntax = "proto3"; package ioi.model_mount.v1;` (underscore — matches `ioi.model_mount.provider_execution.v1` etc.; NOT the hyphenated `ioi.model-mounting.runtime.v1` evidence version). `service ModelMount { rpc PlanReadProjection(...); rpc AdmitProviderExecution(...); rpc Invoke(...); rpc Stream(...) returns (stream ...); rpc PlanInstanceLifecycle(...); rpc PlanRuntimeEngine(...); rpc PlanCapabilityTokenControl(...); rpc BindInvocationReceipt(...); ... }` mirroring Appendix A. JSON-string/`bytes` payloads avoid re-modeling 40 structs; no `option java_package`/`go_package` (workspace convention). Register in `crates/ipc/build.rs` (append to the `tonic_build::configure().compile([...], ["proto"])` list). |
| Verify | `cargo build -p ioi-ipc`; `ioi.model_mount.v1` importable. |
| Commit boundary | Typed proto compiles. |

## 4. Phase 6 — the live PQC-website loop

Needs Ollama (absent on the build box; operator setup). The master guide Phase 6
asks specifically for `crates/cli/tests/harness_spawn_e2e.rs` (does not exist yet).

### Phase 6.1 — Local model setup (operator)

```bash
ollama serve &                       # OpenAI-compatible on :11434
ollama pull qwen2.5-coder            # the harness model
export IOI_HYPERVISOR_MODEL_UPSTREAM=http://127.0.0.1:11434/v1
export IOI_HYPERVISOR_MODEL=qwen2.5-coder
```
The Rust daemon (`resolve_inference`) and the `generic-cli-local` shim both read
`IOI_HYPERVISOR_MODEL_UPSTREAM` → real Qwen. With it unset/unreachable, both fall
back to the honest `no_model_route` error (Phase 0), never fake prose.

### Phase 6.2 — Wire the harness lane to a real session turn

| Field | Detail |
| ----- | ------ |
| Goal | A session turn provisions a workspace, runs the model-driven shim, writes real files, and surfaces them. |
| Work | Connect Phases 1–3 end to end through the daemon: session create → `provisionSessionWorkspace` (real `mkdtemp`) → build the admitted spawn contract (`ioi.runtime.harness_session_spawn.v1`, `decision:"admitted"`, `runtimeTruthSource:"daemon-runtime"`) → `executeHarnessSpawnLane({ spawn, intent, model_endpoint })`. The shim drives Qwen, writes `index.html`/`styles.css` into the workspace, prints the `__HYPERVISOR_HARNESS_RESULT__ {json}` sentinel; the executor parses `files_written`. Feed `runtime-workspace-diff-projection` (real `git diff`/walk) → `changed_file_groups`, the transcript → `terminal_events`, and a wallet-gated preview port → `environment_ports`, over the session-events SSE the app already subscribes to. Gate consequential writes via Phase-4 `assertCapabilityLease` + admit receipts. |
| Files | `packages/runtime-daemon/src/runtime-harness-spawn-executor.mjs`, `runtime-hypervisor-session-watcher.mjs` (already built); the daemon session-turn route → run the lane when a model is reachable. |
| Verify | Manual: launch a session for "create a website that explains post-quantum computers" with Ollama up → `index.html` appears in the workspace; the cockpit Changes panel shows the real diff; the Ports panel exposes a preview. |

### Phase 6.3 — The repeatable e2e proof

| Field | Detail |
| ----- | ------ |
| Goal | One test proves the whole loop, reproducibly. |
| Work | `crates/cli/tests/harness_spawn_e2e.rs` (or extend `scripts/validate-hypervisor-daemon-e2e.mjs`): if Ollama is reachable — start the daemon, launch a session, provision a workspace, run the PQC task via the lane, assert `index.html` exists with real PQC content, assert a served preview port responds, assert receipts emitted; if Ollama is absent — assert the honest `no_model_route` path (so the test is green offline too, like the existing daemon e2e). |
| Verify | Green in CI with a local model (or the native-local deterministic lane offline). |
| Commit boundary | The "create a website" task is provably real, gated, and reproducible. |

## 5. Verification gates

```bash
cargo build -p ioi-node --bin hypervisor-daemon
cargo build -p ioi-ipc                                  # 5c.7 proto
node scripts/validate-hypervisor-daemon-e2e.mjs         # offline daemon proof (stays green)
node scripts/validate-model-mounting-e2e.mjs            # THE binding spec (target: green)
node scripts/check-runtime-layout.mjs                   # see identity-token note below
node scripts/hypervisor-app-shell-contract.mjs --evidence .tmp/...
node scripts/check-architecture-docs.mjs
npm run build --workspace=@ioi/hypervisor-app
git diff --check
# Phase 6 (with Ollama): cargo test -p ioi-cli --test harness_spawn_e2e
```

**Identity-token preservation (critical for 5c.3 retirement).**
`check-runtime-layout` concatenates `model-mounting.mjs` +
`validate-model-mounting-e2e.mjs` + the Rust kernel `model_mount/*.rs` and asserts
these tokens are present somewhere: `endpoint.hypervisor.native-fixture`,
`hypervisor:native-fixture`, `hypervisor-local-server`,
`hypervisor_native_local_openai_compatible_serving`,
`hypervisor_native_local_provider_native_stream`,
`hypervisor_native_local_backend_registry`,
`hypervisor_native_local_process_supervisor`,
`fixture://catalog/hypervisor-native-3b-q4`, `hypervisor:map-only`,
`Hypervisor native local model response`, `Hypervisor native fixture e2e`,
`Hypervisor native fixture tuned`. The Rust kernel files are already globbed in, so
these tokens may live there — but verify the assert's file list before deleting
`model-mounting.mjs`, and migrate any token only present in the JS file.

## 6. Risks & sequencing

1. **The e2e is wired to the JS daemon, not the Rust binary.** Making it green
   requires editing its daemon abstraction to spawn `hypervisor-daemon` (Phase
   5c.0) — the one-time change that turns the e2e into the ratchet. State it in the PR.
2. **Build the admission/projection layer, not the kernel — and route it through
   Agentgres + wallet (the §1 Ownership invariant).** The #1 alignment failure mode
   is recreating the split-brain this migration kills: do NOT let the daemon author
   token grants or receipts as free-standing `state_dir` truth. Every write commits
   through the model_mount record-state admission path (admit → state-root/head bind
   → commit); every token is rooted in a wallet.network grant; the daemon *enforces*
   the gate but Agentgres owns truth and wallet owns authority. Canon: kernel-
   substrate-unification master guide Authority owner map + Final Doctrine; migration
   matrix `model-mounting` terminal owner ("Agentgres record-state admission/
   projection/replay, wallet.network authority, receipt/state-root binding").
3. **Reconcile the served routes against `daemon-runtime/api.md`.** the daemon's
   canonical model surface is published there — confirm the `/v1/model-mount/*` +
   OpenAI-compat + session routes the plan builds match (or extend with a doc edit)
   the api.md inventory; keep the `runtime.lifecycle_projection.*` operation_kind
   strings `check-runtime-layout` couples to api.md.
4. **Shape exactness.** the e2e asserts strict camelCase shapes against the JS
   `ModelMountingState` output; the Rust daemon must reproduce them field-for-field
   (snake_case kernel plans need explicit camelCase projection at the route edge).
5. **Redaction.** never persist raw tokens (store `token_hash` only); keep secret
   needles out of logs/receipts — the e2e fails on any leak.
6. **Restart survival = replay of admitted records.** the e2e restarts the daemon
   against the same `stateDir` and asserts receipt/replay continuity — rebuild from
   the Agentgres-admitted records under `state_dir` (checkpoint/replay), not from a
   re-hydrated daemon-local cache; mark stale backend processes on `bootId` mismatch.
7. **Schema-version exactness.** hyphenated `ioi.model-mounting.runtime.v1` for the
   server/runtime/evidence envelopes; underscored `ioi.model_mount.*.v1` for the
   kernel/proto. Do not cross them.
8. **Keep `:8765` + `startRuntimeDaemonService` + the localStorage keys.** the app
   default is `:8765`; retiring must not change `HYPERVISOR_MODEL_MOUNT_DEFAULT_DAEMON_ENDPOINT`
   or `ioi.hypervisor.daemonEndpoint`/`ioi.modelMounts.daemonEndpoint`.

## Appendix A — the 49 `daemonCoreModelMountApi` methods (constant → wire name)

`admitRouteDecision→admitModelMountRouteDecision`,
`planInvocationAuthority→planModelMountInvocationAuthority`,
`admitInvocation→admitModelMountInvocation`,
`admitProviderExecution→admitModelMountProviderExecution`,
`executeProviderInvocation→executeModelMountProviderInvocation`,
`executeProviderStreamInvocation→executeModelMountProviderStreamInvocation`,
`planProviderLifecycle→planModelMountProviderLifecycle`,
`planProviderInventory→planModelMountProviderInventory`,
`planInstanceLifecycle→planModelMountInstanceLifecycle`,
`admitProviderResult→admitModelMountProviderResult`,
`planBackendProcess→planModelMountBackendProcess`,
`planBackendProcessMaterialization→planModelMountBackendProcessMaterialization`,
`superviseBackendProcess→superviseModelMountBackendProcess`,
`planBackendLifecycle→planModelMountBackendLifecycle`,
`planArtifactEndpoint→planModelMountArtifactEndpoint`,
`planStorageControl→planModelMountStorageControl`,
`planMcpWorkflow→planModelMountMcpWorkflow`,
`planServerControl→planModelMountServerControl`,
`planRuntimeEngine→planModelMountRuntimeEngine`,
`planRuntimeSurvey→planModelMountRuntimeSurvey`,
`planTokenizerRequired→planModelMountTokenizerRequired`,
`planTokenizer→planModelMountTokenizer`,
`planConversationState→planModelMountConversationState`,
`planStreamCompletion→planModelMountStreamCompletion`,
`planStreamCancel→planModelMountStreamCancel`,
`planRouteControlRequired→planModelMountRouteControlRequired`,
`planRouteControl→planModelMountRouteControl`,
`planCatalogProviderControl→planModelMountCatalogProviderControl`,
`planProviderControl→planModelMountProviderControl`,
`planProviderAuthMaterialization→planModelMountProviderAuthMaterialization`,
`planCapabilityTokenControl→planModelMountCapabilityTokenControl`,
`planVaultControl→planModelMountVaultControl`,
`planReceiptGate→planModelMountReceiptGate`,
`planAcceptedReceiptHead→planModelMountAcceptedReceiptHead`,
`planAcceptedReceiptTransition→planModelMountAcceptedReceiptTransition`,
`bindInvocationReceipt→bindModelMountInvocationReceipt`,
`planReadProjection→planModelMountReadProjection` (+ the remaining
`plan*Required` guards). Each maps 1:1 to a `ModelMountCore` method
(`model_mount.rs:151-403`); the Rust endpoint deserializes the request, calls the
method, and returns `{ ok: true, result: <plan> }`.

## Appendix B — `plan_read_projection` projection_kinds

`server_status`, `server_logs`, `server_events`, `snapshot`, `projection`,
`providers`, `provider_inventory_records`, `endpoints`, `instances`, `backends`,
`routes`, `authority`, `downloads`, `receipts`, `runtime_engines`,
`runtime_survey`, `catalog_status`, `catalog_search`, `model_conversation_states`,
`open_ai_model_list`, `artifacts`, `product_artifacts`, `runtime_model_catalog`.
Several read Agentgres-shaped JSON under `state_dir`; seed the provider catalog
(9 kinds) + 7 backends there on daemon startup (reuse the `lifecycle.rs` seed
shape) so `snapshot`/`providers`/`backends` list them.
