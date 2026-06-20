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

**The pivotal insight:** the work to make the e2e green is *not* "rewrite 80
routes in Rust." It is "wire the 49-method `daemonCoreModelMountApi` seam to the
real Rust `ModelMountCore`." The JS state/shape/auth/receipt/redaction logic is
reused as-is; only the kernel calls move to Rust — which is exactly what
`ModelMountCore` (a stateless unit struct, all methods `&self, &Request ->
Result<Plan, Error>`) is for.

## 1. The strategy decision (explicit)

Three ways to satisfy the e2e; this plan sequences B1 → A.

| | Strategy | What it is | Cost | When |
| - | -------- | ---------- | ---- | ---- |
| **B1** | **`daemonCoreModelMountApi` HTTP bridge** | Rust daemon exposes 49 thin method-RPC endpoints; JS `daemonCoreModelMountApi` is an HTTP client forwarding each method; injected into `startRuntimeDaemonService`. JS keeps owning shapes/state. | **Low** — each Rust endpoint is ~3 lines (like the existing snapshot handler); no shape rewrite. | **Phase 5c.1 — do first; fastest green; proves kernel parity.** |
| **B2** | `daemonCoreModelMountApi` in-process (napi) | A napi-rs binding exposes the 49 methods in-process to JS. | Medium — needs napi build infra (none today). | Optional hardening of B1 (no second process). |
| **A** | **Full Rust route surface** | Port `ModelMountingState`'s state + shapes (token store, receipts, redaction, projections) into the Rust daemon so it serves all ~80 routes directly; repoint the e2e at the Rust binary; retire `model-mounting.mjs`. | **High** — reproduces 6,326 lines of shape/state logic in Rust. | **Phase 5c.3 — the consolidation end-state; incremental.** |

The consolidation plan (§2.5) marks a *permanent* HTTP bridge a non-goal — its
end-state is A (Rust owns the daemon, JS retired). This plan honors that: **B1 is
the interim that turns the e2e green and proves the Rust kernel satisfies the full
contract (the master guide's "split-brain facade is gone" — the facade now
delegates to Rust, not 502); A is the retirement that removes the JS facade.**
Doing B1 first de-risks A: every route family is validated against the real kernel
before it is reimplemented in Rust.

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

## 3. Phase 5c — implementation

### Phase 5c.1 — Wire `daemonCoreModelMountApi` to Rust Core (e2e GREEN)

| Field | Detail |
| ----- | ------ |
| Goal | `validate-model-mounting-e2e.mjs` green with the Rust kernel as the engine; no 502/501. |
| Work A (Rust) | In `hypervisor-daemon.rs` add a `POST /v1/model-mount/core/:method` family — one handler per the 49 `ModelMountCore` methods, each: `Json(req)` → `ModelMountCore.<method>(&req)` → `Json({ ok: true, result: plan })` (or `Json({ ok:false, error:{ code, message }})` on `ModelMountError`). All request/plan types are `Serialize/Deserialize`, so each handler is ~3 lines (mirror the existing native-local chain). `state_dir`-reading methods (`plan_read_projection`, `plan_provider_lifecycle`, `plan_instance_lifecycle`) receive the JS-built `state` + `state_dir` in the request body — no daemon-side state needed. |
| Work B (JS bridge) | New `packages/runtime-daemon/src/model-mounting/rust-core-bridge.mjs`: `createRustCoreModelMountApi({ endpoint })` returns an object with the **49 wire method names** (Appendix A), each `async (request) => httpPostJson(endpoint + "/v1/model-mount/core/<method>", request)` returning the `{ ok, result, error }` envelope `invokeModelMountApi` already expects (`model-mount-core.mjs:327-336`). `bindInvocationReceipt` rebuilds `{ invocation, result, accepted_receipt_transition, receipt_ref }` (it already does, JS-side). |
| Work C (wiring) | Thread `daemonCoreModelMountApi` into the e2e: spawn the Rust daemon (or reuse a running one), build `createRustCoreModelMountApi({ endpoint: rustDaemonEndpoint })`, and pass it as `startRuntimeDaemonService({ cwd, stateDir, daemonCoreModelMountApi })`. The option already flows: `index.mjs:571 → ModelMountingState{ daemonCoreModelMountApi }`. |
| Files | `crates/node/src/bin/hypervisor-daemon.rs` (49 core routes); new `packages/runtime-daemon/src/model-mounting/rust-core-bridge.mjs`; `scripts/validate-model-mounting-e2e.mjs` (mint the bridge, pass the option; spawn/await the Rust daemon for the core endpoints — keep every assertion identical). |
| Verify | `cargo build -p ioi-node --bin hypervisor-daemon`; `node scripts/validate-model-mounting-e2e.mjs` GREEN; the existing `scripts/validate-hypervisor-daemon-e2e.mjs` stays green. |
| Commit boundary | The JS facade delegates every kernel call to Rust Core; the e2e is green; no 502/501 in the model-mount path. |

Risk to retire here: `modelMountApi(value)` coerces non-object/array/function to
`null` — the bridge MUST be a plain method-bearing object. Each JS wrapper
post-validates via `normalize*ApiResult`; the Rust plan field names must match the
JS expectations (they already do — same kernel types). If a method's plan misses a
field, the JS normalizer throws `model_mount_*_plan_invalid` (502) — fix by
returning the full kernel plan (don't trim fields).

### Phase 5c.2 — `ioi.model_mount.v1` proto

| Field | Detail |
| ----- | ------ |
| Goal | A typed RPC surface for the 49 kernel methods (the canonical transport the bridge/daemon can adopt). |
| Work | Add `crates/ipc/proto/model_mount/v1/model_mount.proto`: `syntax = "proto3"; package ioi.model_mount.v1;` (underscore — matches the kernel schema-version strings `ioi.model_mount.provider_execution.v1` etc.; NOT the hyphenated `ioi.model-mounting.runtime.v1` evidence version). `service ModelMount { rpc PlanReadProjection(...); rpc AdmitProviderExecution(...); rpc InvokeProvider(...); rpc InvokeProviderStream(...) returns (stream ...); rpc PlanInstanceLifecycle(...); rpc PlanRuntimeEngine(...); rpc PlanCapabilityTokenControl(...); rpc BindInvocationReceipt(...); ... }` mirroring Appendix A. Use `bytes`/JSON-string payloads to avoid re-modeling 40 structs in proto, OR generate messages 1:1. No `option java_package`/`go_package` (workspace convention — zero option lines). |
| Build | Register in `crates/ipc/build.rs` — append `"proto/model_mount/v1/model_mount.proto"` to the `tonic_build::configure().compile([...], ["proto"])` list. |
| Files | new proto; `crates/ipc/build.rs`. |
| Verify | `cargo build -p ioi-ipc`; the generated `ioi.model_mount.v1` module is importable. |
| Commit boundary | Typed proto compiles; available for a tonic transport in 5c.3. |

### Phase 5c.3 — Retire the JS facade (the consolidation end-state)

Large; do it per route family, keeping the e2e green at each step (the e2e is the
regression guard). Strategy A: move state + shapes into Rust, repoint the e2e at
the Rust binary, reduce JS to a thin client.

| Field | Detail |
| ----- | ------ |
| Goal | The Rust daemon serves the full `/v1/model-mount/*` + OpenAI-compat surface directly; `model-mounting.mjs` is a thin client shim; the dev-replay model-mount is a thin proxy. |
| Work | Per family (server-control, tokens, snapshot/catalog seed, runtime-engines, inference+streaming+receipts, artifacts/endpoints/instances/downloads, mcp/routes/workflows/vault/tokenize/context-fit, projection): implement the daemon-owned state in Rust (capability-token store keyed by sha256 of the token — never store raw; receipt log; per-`bootId` stale recovery) + the exact camelCase response shapes, calling `ModelMountCore` for kernel work. Seed the provider catalog (9 kinds) + 7 backends into `state_dir` on startup (reuse the `lifecycle.rs` seed-record shape) so `snapshot` lists them. Set runtime-engine operator-profile defaults `contextLength 3584 / parallel 3`. Then change `validate-model-mounting-e2e.mjs`'s daemon abstraction to **spawn `target/debug/hypervisor-daemon`** (endpoint `http://127.0.0.1:8765`, readiness wait, returning `{endpoint, stateDir, close}`), keeping every assertion. Reduce `model-mounting.mjs` + `model-mounting/**` + `openai-compat-routes.mjs` to thin shims (or delete), and collapse the dev-replay model-mount routes to a thin proxy (keep the Phase-0 deterministic turn behind `IOI_HYPERVISOR_REPLAY_MODE`). |
| Files | `crates/node/src/bin/hypervisor-daemon.rs` (+ Rust state modules); `scripts/validate-model-mounting-e2e.mjs` (spawn Rust bin); retire `packages/runtime-daemon/src/model-mounting.mjs` + `model-mounting/**` + `openai-compat-routes.mjs` + model-mount route handlers in `public-runtime-routes.mjs`; thin `scripts/hypervisor-app-dev-replay-server.mjs` model-mount routes. |
| Verify | `node scripts/validate-model-mounting-e2e.mjs` green against the Rust binary; `node scripts/check-runtime-layout.mjs` (see §5 identity-token note); `node scripts/hypervisor-app-shell-contract.mjs`; `cargo test`. |
| Commit boundary | One Rust true-north daemon serves model-mount; the JS facade is gone; the app (default `:8765`) talks to Rust unchanged. |

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
cargo build -p ioi-ipc                                  # 5c.2 proto
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

1. **The e2e is wired to the JS daemon, not `:8765`.** Making it green requires
   editing its daemon abstraction (5c.1 injects the bridge into
   `startRuntimeDaemonService`; 5c.3 spawns the Rust binary). State which in the PR.
2. **B1 keeps the JS daemon.** It is the interim parity validator, not the
   end-state. Don't let it ossify — 5c.3 is the retirement.
3. **Coercion + normalization.** The bridge must be a plain object (else
   `modelMountApi` nulls it); each method's plan must carry every field the JS
   `normalize*ApiResult` checks (return the full kernel plan).
4. **Redaction.** never persist raw tokens (store sha256); keep secret needles out
   of logs/receipts — the e2e fails on any leak.
5. **Restart survival.** the e2e restarts the daemon against the same `stateDir`
   and asserts receipt/replay continuity — daemon state must persist under
   `state_dir` (5c.3) and re-hydrate; mark stale backend processes on `bootId`
   mismatch.
6. **Schema-version exactness.** hyphenated `ioi.model-mounting.runtime.v1` for the
   server/runtime/evidence envelopes; underscored `ioi.model_mount.*.v1` for the
   kernel/proto. Do not cross them.
7. **Keep `:8765` + `startRuntimeDaemonService` + the localStorage keys.** the app
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
