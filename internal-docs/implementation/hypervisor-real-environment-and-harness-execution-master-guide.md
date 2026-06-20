# Hypervisor Real Environment And Harness Execution Master Guide

Status: implementation-grade plan
Owner: Hypervisor Core (crates/services) / Hypervisor Daemon (runtime-daemon) / Hypervisor App
Primary architecture authority: `docs/architecture/_meta/start-here.md`
Related:
- `internal-docs/implementation/hypervisor-model-mount-rust-consolidation-and-deadcode-retirement.md` (model-mount true-north)
- `internal-docs/implementation/hypervisor-reference-grade-parity-master-guide.md` (UX/route parity)
- `docs/architecture/components/hypervisor/providers-and-environments.md` (canon: Environment Status Object)
Shape provenance: the environment/session lifecycle shapes (status object,
component sub-phases, initializer, ports, status stream) follow established
remote-development environment status conventions; reference captures of the
upstream gRPC/SDK and the IOI-adapted projection live under
`internal-docs/reverse-engineering/`. The shape is borrowed; the implementation is
IOI-native — Agentgres truth, wallet.network authority, encrypted-blob state.
Last reviewed: 2026-06-19

## 0. The honest diagnosis

The Hypervisor App today is a **governed UX scaffold over a daemon that does not execute anything**. When you ask it to "create a website that explains post-quantum computers" it returns *prose* because:

- The "Step N of 5 — Building dev container" sequence is a **timed `setInterval` animation** over a hardcoded `HYPERVISOR_SESSION_STARTUP_STEPS` / `HYPERVISOR_SESSION_STARTUP_LOG_LINES` array in [HypervisorShellContent.tsx](apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx). No environment is provisioned.
- The session turn (`POST /v1/hypervisor/session-turns` in [hypervisor-app-dev-replay-server.mjs](scripts/hypervisor-app-dev-replay-server.mjs)) streams a **deterministic canned turn** (`buildDeterministicTurn`) or proxies to an OpenAI-compatible upstream if one is reachable. It never spawns a harness or writes a file.
- The `codex --oss --local-provider ollama --model qwen` in the HARNESS READY card is a **command-contract string**, not a running process; the transcript is a 4-line fixture.
- The model-mount route data is fixture JSON; the JS daemon's `daemonCoreModelMountApi` is `null` → 502.

**But the real machinery exists — it is just disconnected.** This guide is integration, not greenfield.

### What is already REAL

| Capability | Where | What it actually does |
| ---------- | ----- | --------------------- |
| Container execution | [runtime-harness-container-executor.mjs](packages/runtime-daemon/src/runtime-harness-container-executor.mjs) | Real `spawn(docker\|podman run)` with bind mounts, network policy, argv-hash validation, timeout, stdout/stderr capture, exit codes. |
| Harness shims | [harness-shims/generic-cli-local.mjs](packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs), `claude-code-example.mjs` | Real executable entry points: parse `--provider/--model/--cd`, emit `ready`, read commands on stdin. |
| Session lifecycle contracts | `runtime-harness-session-{launch,spawn,readiness,terminal-attach}.mjs` | Real admission chain; readiness actually runs `execFile(harness --help)` + `execFile(ollama list)`. |
| Rust agentic loop | [crates/services/.../decision_loop/mod.rs](crates/services/src/agentic/runtime/service/decision_loop/mod.rs) (`handle_step`) | Real read→plan→edit→run loop: perception → cognition → tool execution → state persistence. |
| Cognition / inference | [decision_loop/cognition/mod.rs](crates/services/src/agentic/runtime/service/decision_loop/cognition/mod.rs) (`think`) | Assembles prompt (history/context/tools), selects tier, calls `execute_inference_streaming`. |
| Tool execution | [execution/mod.rs](crates/services/src/agentic/runtime/execution/mod.rs) (`ToolExecutor`) | Real `shell__run` (TerminalDriver), file ops, browser, MCP; streams `KernelEvent::{WorkloadActivity,AgentThought,AgentAnswerDelta}`. |
| Model streaming | [model_mount/provider_execution/stream.rs](crates/services/src/agentic/runtime/kernel/model_mount/provider_execution/stream.rs) (`invoke_provider_stream`) | Real SSE streaming from Ollama / OpenAI-compatible / vLLM via `reqwest`; native-local deterministic fallback. |
| Workspace surface | [workspace-substrate/src](packages/workspace-substrate/src) (`CodeOssEditor`, `WorkspaceAdapter`, `workspaceEditorBridge.ts`) | Real Monaco editor + diff; the adapter *interface* (readFile/getDiff/terminal/ports). |
| Projection contracts | [hypervisorSessionOperationsModel.ts](apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorSessionOperationsModel.ts) | Real shapes for `terminal_events`, `changed_file_groups`, `tasks`, `ports_services`, `environment_lifecycle_steps`, receipts. |

### What is SIMULATED / MISSING (the wiring gap)

1. **No workspace provisioning** — the spawn pipeline resolves a workspace root but never creates an isolated filesystem (no `mkdtemp`/clone).
2. **Container executor not wired** — `executeHarnessContainerLane()` is exported and tested but called by no route.
3. **No real daemon process** owns and drives execution — the app talks to the dev-replay scaffold; the Rust agentic runtime is not exposed over HTTP/IPC; `daemonCoreModelMountApi` is unwired.
4. **No real signals into projections** — nothing watches PTY/filesystem/git/ports to write real `terminal_events`/`changed_file_groups`/`tasks`/`ports_services`; projections are one-shot fixtures.
5. **The app simulates** — the init animation and the deterministic turn stand in for real provisioning + execution.

## 1. Target architecture

```text
Hypervisor App (client)                Hypervisor Daemon (executes Core)            Hypervisor Core (Rust, true north)
  composer / cockpit            HTTP/SSE   session + environment lifecycle      calls   crates/services agentic runtime
  - launch session  ───────────────────►   - provision workspace (mkdtemp/clone)  ────►   - decision_loop (read→plan→act)
  - subscribe events ◄── SSE projections ─  - select execution LANE                       - cognition → model_mount inference
  - render terminal/diffs/ports/preview     - watch PTY + fs + git + ports                - tool execution (shell/file)
                                            - write projections + Agentgres receipts      crates/.../model_mount kernel
                                                                                          - invoke_provider_stream → Ollama/Qwen
            wallet.network authorizes ▲          Agentgres records truth ▲
```

Two **execution lanes**, both real, selected per session by the harness adapter:

- **Lane B — Hypervisor-native agent (canon-primary).** The Rust `decision_loop` *is* the agent: it perceives the workspace, calls `model_mount` inference for a plan, runs `shell__run`/file tools that mutate the workspace, and streams `KernelEvent`s. No external CLI required.
- **Lane A — external harness adapter (the "Codex OSS / Qwen" path you asked about).** The daemon spawns the real `codex --oss` (or `generic-cli-local` shim) in the provisioned workspace via the container executor / PTY; the harness drives the model and edits files; the daemon watches the PTY + filesystem.

Per canon, external harnesses are **adapter targets / proposal sources**, not clients. The daemon owns the environment and the lane; wallet.network authorizes consequential operations; Agentgres records receipts; Core never replaces wallet authority or Agentgres truth.

## 2. Definition of "works" (the MVP acceptance)

A session for *"create a website that explains post-quantum computers"* is real when:

1. The daemon provisions a **real isolated workspace** (a temp dir, or a cloned repo) — visible path, not a fixture.
2. A **real model** answers (local Qwen via Ollama, or the Rust native-local backend) — token deltas come from inference, not `buildDeterministicTurn`.
3. The agent/harness **writes real files** into the workspace (`index.html`, `styles.css`, content about PQC) and **runs real commands** (e.g. starts a static server).
4. The app renders **real `changed_file_groups`** (the new files with real diffs), **real `terminal_events`** (the transcript of commands), and a **real port/preview** (the served site, openable from the Ports panel).
5. Each operation emits an **Agentgres-shaped receipt**; wallet authority gates anything consequential (filesystem write scope, network, port exposure).
6. The init sequence reflects **real provisioning phases** (workspace_ready, model_ready, harness_spawned), not a 5-step animation.

## 3. Phased implementation

Each phase is independently shippable behind the verification gates. Phases 0–4 give a real MVP without requiring the full Rust daemon; Phase 5 lands the canon true-north consolidation.

### Phase 0 — Real model (remove the prose fallback's reason to exist)

| Field | Detail |
| ----- | ------ |
| Goal | A real local Qwen answers session turns. |
| Work | Run Ollama (`ollama serve`) + `ollama pull qwen2.5-coder`. The session-turn endpoint already proxies to `IOI_HYPERVISOR_MODEL_UPSTREAM`/`:11434` when reachable — make the **deterministic turn a fallback behind an explicit `IOI_HYPERVISOR_REPLAY_MODE` flag**, and otherwise return a clear "start a model" error instead of silently faking. Document local setup (`scripts/ollama-benchmark-env.sh`). |
| Files | [hypervisor-app-dev-replay-server.mjs](scripts/hypervisor-app-dev-replay-server.mjs) (`streamSessionTurn`), README/local-setup. |
| Verify | A composer query streams real Qwen tokens; with no model + no replay flag, the app shows an actionable "no model route" state, not prose. |
| Commit boundary | No silent prose: real model or honest error. |

### Phase 1 — Real environment provisioning

The lifecycle uses the canonical **`HypervisorEnvironmentStatus`** object — a
status object with component sub-phases (`provisioner`, `workspace_content`,
`sandbox`, `secrets`, `automations`, plus IOI-native `model_mount` and `harness`),
each carrying a phase from `pending | creating | initializing | ready | degraded
| failed`, plus a typed `HypervisorWorkspaceInitializer` (context URL or git spec
with custody posture) and structured wallet-gated `HypervisorEnvironmentPort`s.
The **shape follows established remote-development environment status conventions;
the truth is Agentgres, the authority is wallet.network, and the state bytes are
encrypted-blob storage** — see canon
[`providers-and-environments.md` → Environment Status Object](docs/architecture/components/hypervisor/providers-and-environments.md).
This replaces the flat `environment_lifecycle_steps` array and the simulated
`setInterval` step animation.

| Field | Detail |
| ----- | ------ |
| Goal | The daemon creates a real isolated workspace per session and projects a real `HypervisorEnvironmentStatus` with component sub-phases. |
| Work | In the spawn path, add a **workspace provisioner** driven by a `HypervisorWorkspaceInitializer`: resolve `context_url`/`git` spec → `mkdtemp` a session workspace and shallow-clone/copy under the session's `custody_posture` (public_trunk / redacted_projection / cTEE). Replace `environment_lifecycle_steps` with the `HypervisorEnvironmentStatus` object; drive its component phases (`provisioner` → `workspace_content` → `sandbox` → `secrets` → `model_mount` → `harness`) from real transitions, each emitting an Agentgres operation + receipt + state root and persisting workspace bytes as an encrypted-blob `workspace_artifact_ref`. |
| Files | [runtime-harness-session-spawn.mjs](packages/runtime-daemon/src/runtime-harness-session-spawn.mjs), new `runtime-workspace-provisioner.mjs`, `runtime-environment-status-projection.mjs`; [hypervisorSessionOperationsModel.ts](apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorSessionOperationsModel.ts) (add `HypervisorEnvironmentStatus` + `HypervisorWorkspaceInitializer` types). |
| Verify | The session workspace exists on disk; the app's init panel renders `HypervisorEnvironmentStatus` component phases driven by daemon `environment_status` events; `HYPERVISOR_SESSION_STARTUP_STEPS`/`setInterval` is removed from the app. |
| Commit boundary | Real workspace on disk; status object is daemon-projected from Agentgres, not animated. |

### Phase 2 — Real execution lane

| Field | Detail |
| ----- | ------ |
| Goal | Wire one real lane end to end so a turn actually does work. |
| Work (Lane A, MVP-fast) | Wire `executeHarnessContainerLane()` (or a host PTY via `node-pty`) into the session-turn handler: take user intent + the daemon-admitted spawn contract, spawn the harness (`generic-cli-local`/`codex`) in the provisioned workspace bound to Ollama, write the intent to stdin, stream stdout/stderr. New `runtime-harness-spawn-executor.mjs` + `runtime-harness-pty-attach.mjs`. |
| Work (Lane B, canon) | Expose the Rust `decision_loop` over the daemon (Phase 5) and route session-turns to `handle_step` in a loop, streaming `KernelEvent`s. This is the native agent that edits the workspace and runs tools. |
| Files | [runtime-harness-container-executor.mjs](packages/runtime-daemon/src/runtime-harness-container-executor.mjs), [runtime-route-handlers.mjs](packages/runtime-daemon/src/runtime-route-handlers.mjs), new spawn-executor + pty-attach; (Lane B) [crates/services/.../execution/mod.rs](crates/services/src/agentic/runtime/execution/mod.rs). |
| Verify | The turn creates real files in the workspace and the transcript is the harness's real stdout (not canned). For the PQC task, `index.html` exists with real content. |
| Commit boundary | One lane runs real code that mutates the workspace. |

### Phase 3 — Real surfacing (replace every fixture with a live signal)

| Field | Detail |
| ----- | ------ |
| Goal | The app renders live execution: terminal, diffs, tasks, ports, preview. |
| Work | Daemon-side watchers feed the projection and emit the canonical session-events SSE (`event: environment_status \| terminal_chunk \| workspace_change \| receipt_projection \| readiness`): a **PTY reader** → `terminal_events`; a **filesystem/git watcher** → `changed_file_groups` (real `git diff` deltas); a **lifecycle tracker** → `HypervisorEnvironmentStatus` component phase transitions; a **port inspector** (`ss`/netstat in the session ns) → wallet-gated `HypervisorEnvironmentPort`s (`access_policy` + `capability_lease_ref` + `url` + `exposure_state`) with a previewable URL. App side: convert the one-shot projection fetch into an **SSE subscription** (`useHypervisorSessionOperationsProjectionSubscription`) over `/v1/hypervisor/sessions/:id/events`. Render real `terminal_events`/`changed_file_groups`/ports and the `HypervisorEnvironmentStatus` component phases instead of the conversation-only view. |
| Files | new `runtime-hypervisor-session-watcher.mjs`, `runtime-workspace-diff-projection.mjs`, `runtime-port-listener-registry.mjs`; app: new subscription hook; [hypervisorSessionOperationsModel.ts](apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorSessionOperationsModel.ts). |
| Verify | After the PQC turn, the Changes panel shows the real new files with diffs, the Terminal shows real commands, and the Ports panel exposes a working preview of the site. |
| Commit boundary | Every cockpit panel reflects real session state; no projection fixture remains in the live path. |

### Phase 4 — Real governance (receipts + authority)

| Field | Detail |
| ----- | ------ |
| Goal | Real operations are wallet-authorized and Agentgres-recorded, per canon. |
| Work | Emit real Agentgres operations/receipts for each consequential step (workspace write, command exec, port exposure, model invocation) via an Agentgres admission client; gate consequential operations on wallet.network capability leases (the scopes the launch summary already carries). Replace symbolic `receipt://`/`agentgres://` refs with admitted objects. |
| Files | new `runtime-agentgres-admission-client.mjs`, `runtime-harness-receipt-sink.mjs`; Core policy in crates/services. |
| Verify | Receipts/Replay surface shows real receipts/state-roots for the session; an unauthorized scope blocks the operation (step-up), not silently proceeds. |
| Commit boundary | Real receipts; authority actually gates. |

### Phase 5 — Rust daemon true-north (the canonical endpoint)

| Field | Detail |
| ----- | ------ |
| Goal | The Hypervisor Daemon is a Rust service that serves model-mount + inference + the agentic runtime + the projection writers; the app points at it; the JS scaffold is retired. |
| Work | Per the model-mount consolidation plan: stand up the Rust HTTP/IPC daemon (`crates/node` binary) exposing `/v1/model-mount/*`, `/v1/chat/completions`, the session lifecycle, and the agentic `decision_loop` (Lane B). Move the watchers/projection writers into Rust. Point `hypervisorDaemonEndpoint.ts` at it. Retire the dev-replay model-mount + deterministic turn (keep a thin replay only for offline UI tests). |
| Files | new `crates/node/src/bin/hypervisor-daemon.rs`, `crates/ipc/proto/ioi.model_mount.v1.proto`; [model-mounting.mjs](packages/runtime-daemon/src/model-mounting.mjs) (retire/thin); app endpoint config. |
| Verify | `scripts/validate-model-mounting-e2e.mjs` green against the Rust daemon; the app runs entirely against Rust Core; the split-brain facade is gone. |
| Commit boundary | One Rust true-north daemon; the app is a thin client over it. |

### Phase 6 — The e2e proof

| Field | Detail |
| ----- | ------ |
| Goal | A repeatable test proves the whole loop. |
| Work | `crates/cli/tests/harness_spawn_e2e.rs` (or a node e2e): start Ollama+Qwen → launch a session → provision a real workspace → run the PQC task → assert `index.html` exists with real content → assert a served preview port responds → assert receipts emitted. |
| Verify | Green in CI with a local model (or the native-local backend for the deterministic-but-real lane). |
| Commit boundary | The "create a website" task is provably real, gated, and reproducible. |

## 4. Verification gates

```bash
# model + inference
ollama serve & ollama pull qwen2.5-coder
node scripts/validate-model-mounting-e2e.mjs
# environment + execution + surfacing
node scripts/hypervisor-app-shell-contract.mjs --evidence .tmp/...
node scripts/check-runtime-layout.mjs
npm run build --workspace=@ioi/hypervisor-app
# real e2e (Phase 6)
cargo build -p ioi-cli --bin cli && node|cargo test harness_spawn_e2e
git diff --check
```

## 5. Anti-patterns / non-goals

1. **No silent prose.** If no model/lane is available, show an honest, actionable state — never fake an answer or a build sequence.
2. **No second runtime.** The Rust Core agentic runtime + model_mount kernel is the engine; the JS daemon is transport/lifecycle until retired into Rust.
3. **External harnesses stay adapters.** Codex/Claude Code/DeepSeek/Generic CLI are execution lanes/proposal sources, not the product or runtime truth.
4. **Governance is real.** wallet.network authorizes; Agentgres records; Core coordinates. Workspace writes, command exec, and port exposure are capability-gated.
5. **No fixtures in the live path.** Every projection field is fed by a real signal once its phase lands; fixtures survive only behind an explicit offline-UI-test flag.

## 6. Sequencing

Phase 0–2 deliver the first **genuinely real** session (real workspace, real model, real files) on the JS daemon + a real lane — the fastest path to "it actually works". Phase 3 makes the cockpit reflect it. Phase 4 makes it governed. Phase 5 moves the engine to the Rust true-north daemon (and folds in the model-mount consolidation plan). Phase 6 locks it with an e2e proof. Each phase keeps `check-runtime-layout` and the shell-contract green; the app's offline UI tests keep a thin replay behind a flag so they never depend on a live model.
