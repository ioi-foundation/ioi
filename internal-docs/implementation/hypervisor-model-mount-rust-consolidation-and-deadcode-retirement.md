# Hypervisor Model-Mount Rust Consolidation And Dead-Code Retirement

Status: implementation-grade plan
Owner: Hypervisor App / Hypervisor Core / runtime-daemon / crates/services
Primary architecture authority: `docs/architecture/_meta/start-here.md`
Related: `internal-docs/implementation/hypervisor-reference-grade-parity-master-guide.md`
Last reviewed: 2026-06-19

This plan has two parts that ship together:

1. **Dead-code & split-brain retirement** — resolve the codebase audit by removing
   verified orphans and recording keep-with-rationale decisions.
2. **Model-mount Rust consolidation (true north)** — make the Rust daemon-core the
   single owner of the model-mount runtime and inference edge, retiring the
   unwired JS facade. This is the **full consolidation** path (option 5), not the
   minimal bridge.

The guiding decision: **the Rust kernel `crates/services/.../model_mount` is true
north.** The JS `packages/runtime-daemon/src/model-mounting.mjs` (6,326 lines) is a
parallel projection/planning implementation whose delegation seam
(`daemonCoreModelMountApi`) is never wired in this repo (`= null` default → 502;
only test mocks). It is the one real architectural split-brain and it gets
retired.

## Part 0: Audit Verdict

The codebase is **fairly consistent; split-brain is low**. The ~5,700 "retired"
and ~4,150 "deprecated/@deprecated" markers are **>90% active guard contracts**
(fail-closed error strings, retired-boundary field names, negative tests asserting
a cut path is rejected) — load-bearing, not dead. Hard cuts (ChatShellWindow,
Tauri `src-tauri`, Autopilot onboarding, OpenVSCode-contained editor) are deleted
and fenced by negative tests, never resurrected.

Real findings are ordinary orphan cleanup (~2.5k lines) plus the single model-mount
facade split-brain. There are **no parallel product surfaces or duplicate shell
windows**.

## Part 1: Dead-Code & Split-Brain Retirement

### 1.1 Removed (verified orphan; zero live references)

Each was adversarially re-grepped for live imports, string references, lazy loads,
and package.json/CI wiring before removal.

| Path | Why |
| ---- | --- |
| `apps/hypervisor/src/services/runtimeChatNavigation.ts` | 13 unused exports; 0 external refs (retired chat-shell navigation). |
| `apps/hypervisor/src/hooks/useLiveValidationSummary.ts` | ~552-line hook; 0 refs. |
| `apps/hypervisor/src/hooks/useRetainedWorkbenchTrace.ts` | Sole consumer `ArtifactHubSidebar.tsx` already deleted; 0 refs. |
| `apps/hypervisor/src/lib/assistantWorkbenchSummary.ts` | 0 refs. |
| `apps/hypervisor/src/lib/operatorWorkbenchSummary.ts` | 0 refs (gmail_reply / meeting_prep variants unused). |
| `apps/hypervisor/src/components/ContextAtlasGraph3D.tsx` | 3D force-graph component; 0 refs. |
| `apps/hypervisor/src/components/WorkGraphViz.tsx` + `WorkGraphViz.css` | 0 refs; CSS imported only by the component. |
| `apps/hypervisor/src/surfaces/Conversation/` | Empty directory (git-cleared placeholder). |
| `scripts/generate-chat-artifact-arena.mjs` | Orphan CLI wrapper; lib stays (used by benchmark generator). |
| `scripts/generate-chat-artifact-corpus-summary.mjs` | Orphan wrapper; **broken import** (`writeChatRuntimeArtifactCorpusIndex` does not exist). |
| `scripts/generate-chat-artifact-distillation.mjs` | Orphan wrapper; **broken import**. |
| `scripts/run-chat-artifact-conformance.mjs` | Orphan wrapper; never invoked. |
| `scripts/run-chat-artifact-release-gates.mjs` | Orphan wrapper; never invoked. |
| `scripts/run-chat-artifact-corpus.ts` | Orphan TS entrypoint; never compiled or invoked. |
| `CODEX.txt` | 4-month-old system prompt; references doc paths that have moved. |
| `test_output.log` | Point-in-time TAP log artifact; never referenced. |
| `crates/services/src/agentic/runtime/host.rs` | `EmbeddedAppHost`; no `mod host` in the tree → never compiled. |

Plus one partial edit: remove the unused `buildHypervisorAppearanceBridgeState`
(Tauri-era OpenVSCode theme bridge) from
`apps/hypervisor/src/services/hypervisorAppearance.ts`; the rest of the file is live.

The `scripts/lib/chat-artifact-*.mjs` **libraries and their `*.test.mjs` are
LIVE** (`apps/benchmarks/scripts/generate-benchmark-data.mjs` imports them via
`collectChatArtifact*` / `writeChatArtifact*`). Only the broken/never-invoked
wrapper entrypoints are removed.

### 1.2 Kept — with rationale (audited, not dead)

| Path | Decision | Rationale |
| ---- | -------- | --------- |
| `apps/hypervisor/src/surfaces/Home/homeCockpitModel.ts` | KEEP | Deliberately-retained projection model backing the `/v1/hypervisor/home-cockpit` daemon route; `check-runtime-layout.mjs` enforces it retains harness-comparison evidence while HomeView stays clean. False positive. |
| `packages/runtime-daemon/src/harness-shims/{claude-code-example,generic-cli-local}.mjs` | KEEP | Live first-session harness adapters wired into launch/spawn/readiness. |
| `scripts/lib/chat-artifact-*.mjs` (+ `*.test.mjs`) | KEEP | Live via the benchmark generator. |
| `docs/conformance/agentic-runtime/CIRC.md`, `CEC.md` | KEEP | Intentional compat redirect stubs wired into `.github/scripts/check_contract_invariants.sh` (CI), ADR-0010, README; `CIRC_CONTRACT_VERSION` lives in Rust. Not removable without a coordinated CI/doc migration. |
| `docs/commitment/tree/mhnsw/README.md` | KEEP | Historical reference for the removed SCS crate. |
| `scripts/check-runtime-refactor-health.sh`, `check-clean-break-debt.sh`, `ollama-benchmark-env.sh` | KEEP | Standalone operator utilities (the Ollama one supports the new model upstream path). **Unwired into CI** — wire or remove as a separate decision. |
| `runtime-daemon-core-direct-invoker-service.test.mjs` | KEEP | Read as a guard fixture by `check-runtime-layout.mjs`. |

### 1.3 Legacy conformance / negative tests policy

The negative tests that fence retired surfaces —
`HomeView.hypervisorHome.test.mjs`, `operatorSubstrateModel.test.ts`,
`HypervisorShellContent.seedIntent.test.ts` — are **active regression guards and
are kept.** They prevent resurrection of the highest-risk hard cuts (Tauri
`src-tauri`, ChatShellWindow, onboarding fat). `seedIntent.test.ts` additionally
carries positive Sessions-cockpit assertions. Redundancy with
`check-runtime-layout.mjs` is acceptable. Optional future cleanup: fold purely
negative assertions into `check-runtime-layout.mjs` rather than deleting the test
files.

## Part 2: Model-Mount Rust Consolidation (True North)

### 2.1 The split-brain

| Layer | Today |
| ----- | ----- |
| Rust kernel `crates/services/.../model_mount` (~37k lines) | Real engine: `plan_read_projection`, `admit_invocation`, `plan_artifact_endpoint`, `plan_backend_process_materialization`, `supervise_backend_process`, `plan_provider_auth_materialization`, `plan_invocation_authority`, provider execution + native-local streaming. |
| JS `packages/runtime-daemon/src/model-mounting.mjs` (6,326 lines) | Parallel projection/planning + the HTTP/contract layer; delegates to `daemonCoreModelMountApi.{planModelMountArtifactEndpoint, planModelMountBackendProcessMaterialization, superviseModelMountBackendProcess, planModelMountProviderAuthMaterialization, bindModelMountInvocationReceipt}` — which is **never constructed** (null → 502; only test mocks). |
| Bridge transport | `crates/ipc` already provides tonic gRPC (`ioi.control.v1` / `ioi.public.v1`) + rkyv. |

The five `daemonCoreModelMountApi.*` methods map **1:1** onto the Rust kernel
`plan_*` / `supervise_*` functions. The JS planning logic is duplicated, unwired,
and is the retirement target.

### 2.2 Target architecture (end state)

```text
Clients (Hypervisor App, Web, agent-sdk, CLI)
  -> HTTP  /v1/model-mount/*  +  /v1/chat/completions, /v1/messages, /v1/responses
       served NATIVELY by the Rust daemon-core HTTP edge
         (reuses crates/.../model_mount kernel + crates/.../vm/inference http_adapter + HttpInferenceRuntime)
  -> wallet.network authorizes; Agentgres records; Core executes.

packages/runtime-daemon (JS): retains ONLY non-model-mount orchestration
  (harness-session recipe/binding/launch/spawn/readiness/terminal-attach projection,
   SSE session streams, evidence/replay) — OR is itself reduced to a thin client.
  All model-mount + inference planning/execution is removed from JS.
```

`model-mounting.mjs` shrinks from a 6,326-line parallel engine to **zero**
model-mount planning (the route family moves to Rust). The retired-boundary guards
(`public_runtime_engine_js_facade_retired`,
`command_transport_backend_process_spawn_retired`,
`binary_bridge_backend_process_spawn_retired`) become live-correct facts rather
than aspirational assertions.

### 2.3 Phases

#### Phase 1 — Publish the kernel as a service

| Field | Detail |
| ----- | ------ |
| Goal | Expose the Rust `model_mount` kernel over a stable RPC surface. |
| Files | `crates/ipc/proto/ioi.model_mount.v1.proto` (new), `crates/node/src/bin/` daemon binary or `crates/services` service module, `crates/services/.../model_mount.rs` (public service wrapper). |
| Work | Define `ioi.model_mount.v1` messages for `plan_read_projection`, `admit_invocation`, `plan_artifact_endpoint`, `plan_backend_process_materialization`, `supervise_backend_process`, `plan_provider_auth_materialization`, `plan_instance_lifecycle`, `plan_provider_*`, `bind_invocation_receipt`, plus `invoke` / `stream`. Implement a tonic service that calls the existing kernel functions. |
| Verify | `cargo build -p ioi-cli`; a Rust integration test that mounts `backend.hypervisor.native-local.fixture` and streams a completion through the new service (mirror `scripts/validate-model-mounting-e2e.mjs`). |
| Commit boundary | Rust service builds and streams a native-local completion. |
| Risks | Proto drift vs the JS contract; keep field names aligned to the existing `/v1/model-mount/*` payloads. |

#### Phase 2 — Rust serves the model-mount + inference HTTP edge

| Field | Detail |
| ----- | ------ |
| Goal | Serve `/v1/model-mount/*`, `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/embeddings` natively from Rust. |
| Files | `crates/node` (or a `crates/services` HTTP host) reusing `crates/.../vm/inference/http_adapter.rs` + `HttpInferenceRuntime`; capability-token + authority gating per the existing `/v1/model-mount/tokens` semantics. |
| Work | Port the route surface the JS daemon currently exposes (model-mount snapshot/artifacts/endpoints/instances/runtime/tokens + openai-compat) onto the Rust kernel. Preserve receipts and wallet/authority gating. |
| Verify | Re-run `scripts/validate-model-mounting-e2e.mjs` against the Rust HTTP daemon (build cargo, start daemon, mount, stream, assert receipts) — it already encodes the full contract. |
| Commit boundary | Rust daemon serves the full model-mount + inference contract; e2e green. |
| Risks | Auth/scope parity (`model.chat:*` etc.); fail-closed token/expiry/revocation behavior must match. |

#### Phase 3 — Point clients at the Rust edge

| Field | Detail |
| ----- | ------ |
| Goal | App, agent-sdk, dev-replay use the Rust daemon for model-mount + inference. |
| Files | `apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorDaemonEndpoint.ts`, `apps/hypervisor/src/dev/hypervisorDevReplayClient.ts`, `scripts/hypervisor-app-dev-replay-server.mjs` (point `IOI_HYPERVISOR_MODEL_UPSTREAM` / `/v1/hypervisor/session-turns` upstream at the Rust daemon), `packages/agent-sdk/src/model-mounts.ts`. |
| Work | The streaming session-turn endpoint added for the functional-query work proxies `/v1/chat/completions` from the Rust daemon when reachable; otherwise the deterministic replay. No app UI change. |
| Verify | Playwright: launch a session, confirm the cockpit conversation streams real completions from the Rust daemon; `npm run build --workspace=@ioi/hypervisor-app`. |
| Commit boundary | A functional query streams from the Rust daemon end to end. |
| Risks | Local model availability — native-local fixture works without Ollama; a real Qwen needs Ollama or a mounted backend per the readiness contract. |

#### Phase 4 — Retire the JS model-mount facade

| Field | Detail |
| ----- | ------ |
| Goal | Delete the duplicated JS planning/projection; keep JS only for non-model-mount orchestration. |
| Files | `packages/runtime-daemon/src/model-mounting.mjs` and `packages/runtime-daemon/src/model-mounting/**`, `packages/runtime-daemon/src/openai-compat-routes.mjs`, `packages/runtime-daemon/src/index.mjs`, `public-runtime-routes.mjs`, the model-mounting `*.test.mjs` contract suite. |
| Work | Remove the JS model-mount route handlers + `ModelMountingState` planning. Remove the `daemonCoreModelMountApi` seam (now served by Rust). Keep/repoint harness-session routes. Update the retired-boundary guards to assert the JS no longer owns model-mount planning. |
| Verify | `node scripts/check-runtime-layout.mjs`; `node scripts/hypervisor-app-shell-contract.mjs`; runtime-daemon test suite; `git diff --check`. |
| Commit boundary | JS no longer contains a model-mount engine; guards green; `model-mounting.mjs` deleted or reduced to a thin client shim. |
| Risks | The shell-contract + runtime-daemon tests assert JS model-mount payloads; migrate those assertions to the Rust contract (the e2e already covers Rust). |

#### Phase 5 — Single-surface cleanup

| Field | Detail |
| ----- | ------ |
| Goal | One model-mount + inference surface (Rust), one HTTP edge, no parallel JS. |
| Work | Remove `IOI_HYPERVISOR_MODEL_UPSTREAM` indirection if the app points at the Rust daemon directly; collapse the dev-replay model-turn to a thin proxy; delete now-dead JS model-mount fixtures and types. Promote the retirement to canon: a short delta into `docs/architecture/components/hypervisor/` stating Rust owns model-mount. |
| Verify | Full gate set below. |
| Commit boundary | The split-brain is gone; the daemon path is the only model-mount path. |

### 2.4 Verification gates (every phase)

```bash
cargo build -p ioi-cli --bin cli
node scripts/validate-model-mounting-e2e.mjs
node scripts/check-runtime-layout.mjs
npm run build --workspace=@ioi/hypervisor-app
node scripts/hypervisor-app-shell-contract.mjs --evidence .tmp/hypervisor-app-shell-contract-$(date +%F).json
git diff --check
```

### 2.5 Non-goals / anti-patterns

1. No second model-mount runtime beside the Rust kernel.
2. JS does not regain model-mount planning after retirement.
3. Hypervisor Core coordinates authority; it does not replace wallet.network
   authority or Agentgres truth.
4. External harnesses (Codex/Claude Code/DeepSeek/Generic CLI) stay adapter
   targets, not clients.
5. No napi/in-process binding shortcut that re-creates a hidden JS model-mount
   engine; the boundary is the gRPC/HTTP contract.

## Part 3: Sequencing

Part 1 (dead-code retirement) ships immediately and independently — it touches no
model-mount runtime. Part 2 lands phase by phase, each behind the verification
gates, with the shell-contract and `check-runtime-layout` kept green throughout.
The functional-query streaming work already in the cockpit becomes "real" the
moment Phase 2/3 land, with no further app change.
