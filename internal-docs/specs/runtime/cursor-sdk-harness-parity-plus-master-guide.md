# Cursor SDK Harness Parity Plus Master Guide

Status: audit and implementation master guide
Audit date: 2026-05-01
Reference package: `@cursor/sdk@1.0.11` from npm
Reference docs:

- https://cursor.com/changelog/sdk-release
- https://cursor.com/blog/typescript-sdk
- https://cursor.com/docs/api/sdk/typescript

## Executive Verdict

IOI now has a first installable Cursor-style SDK surface for local execution:
`@ioi/agent-sdk`. It exposes an `Agent`/`Run` facade, ESM/CJS/types exports,
local quickstart streaming, run wait/cancel/conversation/status, artifacts,
trace export, replay, model/repository catalogs, and optional smarter-agent
inspection paths. The SDK is backed by a `RuntimeSubstrateClient` contract and
projects authority, receipts, task state, uncertainty, probes, postconditions,
semantic impact, stop conditions, scorecards, and quality ledgers through the
SDK path.

The remaining parity gaps are live hosted/cloud/self-hosted execution, real
Cursor billing/account semantics, and live Autopilot GUI retained-query
screenshots. Those lanes are externally blocked or environment blocked in the
current evidence bundle and must not be claimed complete until live providers
and GUI automation pass.

The target is therefore not "make IOI compatible with Cursor." The target is:

> Build an installable IOI agent SDK and harness facade that is at least as easy
> as `npm install @cursor/sdk`, while every SDK run is backed by IOI's unified
> substrate and produces smarter-agent evidence by construction.

Complete status today:

- Internal smarter-runtime substrate: Partial to Complete Plus.
- Componentized harness/workflow substrate: Partial to Complete Plus.
- Cursor-style TypeScript SDK ergonomics: Complete Plus for local SDK runs.
- Cursor-style local lifecycle: Complete Plus for local runs; hosted/cloud and
  self-hosted fail closed without provider configuration.
- Cursor-style streaming/reconnect/list/resume/cancel/artifact APIs: Complete
  Plus for local event-cursor replay and artifact export; public SSE endpoint is
  still Partial.
- Cursor-style `.cursor` config compatibility for MCP, skills, and hooks:
  Partial Plus as governed import/projection, not live connector execution.
- Proof that SDK, CLI, GUI, harness, benchmarks, and compositor all share one
  runtime substrate: Partial Plus. SDK proof exists; live GUI proof is blocked
  by a retained-query harness hang.

## Reference Inventory

### Public Cursor Claims

The Cursor changelog says the SDK gives developers the same runtime, harness,
and models as Cursor desktop, CLI, and web, with local and cloud execution.
It also calls out run-scoped follow-ups, status, streaming, cancellation, SSE
reconnect through `Last-Event-ID`, lifecycle controls, and standardized v1
responses and errors.

Cursor's announcement also lists the harness capabilities that matter for this
audit: codebase indexing, semantic search, grep, MCP via `.cursor/mcp.json` or
inline config, skills from `.cursor/skills/`, hooks from `.cursor/hooks.json`,
subagents, and model selection.

### Package Shape

Reference artifact inspected:

- npm package `@cursor/sdk@1.0.11`
- unpacked tarball module paths are cited as `@cursor/sdk/<path>`

Key package facts:

| Capability | Reference evidence |
| --- | --- |
| Node package | `@cursor/sdk/package.json:1-4` |
| Node engine | `@cursor/sdk/package.json:11-13` |
| ESM/CJS/types exports | `@cursor/sdk/package.json:14-45` |
| Production build and publish scripts | `@cursor/sdk/package.json:49-71` |
| Runtime dependencies | `@cursor/sdk/package.json:73-80` |
| Platform optional packages | `@cursor/sdk/package.json:111-117` |
| README delegates to public docs | `@cursor/sdk/README.md:1-5` |

Key public API modules:

| API area | Reference evidence |
| --- | --- |
| `Agent.create`, `Agent.resume`, `Agent.prompt`, list/get/run lifecycle | `@cursor/sdk/dist/esm/stubs.d.ts:35-72` |
| `Cursor.me`, model catalog, repository catalog | `@cursor/sdk/dist/esm/stubs.d.ts:78-95` |
| Agent instance `send`, `close`, `reload`, artifact methods | `@cursor/sdk/dist/esm/agent.d.ts:5-18` |
| Per-send model, MCP, step/delta callbacks, local force | `@cursor/sdk/dist/esm/agent.d.ts:19-42` |
| Agent/run listing and local/cloud option shapes | `@cursor/sdk/dist/esm/agent.d.ts:43-110` |
| API-key fallback semantics | `@cursor/sdk/dist/esm/agent.d.ts:117-142` |
| User message images, MCP stdio/http/sse, settings, sandbox, models | `@cursor/sdk/dist/esm/options.d.ts:2-66` |
| Custom subagent definitions | `@cursor/sdk/dist/esm/options.d.ts:67-72` |
| Local agent options | `@cursor/sdk/dist/esm/options.d.ts:79-89` |
| Cloud agent options | `@cursor/sdk/dist/esm/options.d.ts:96-115` |
| Top-level `AgentOptions` | `@cursor/sdk/dist/esm/options.d.ts:116-137` |
| Run operations: stream, conversation, wait, cancel, status listeners | `@cursor/sdk/dist/esm/run.d.ts:5-43` |
| SDK stream message union | `@cursor/sdk/dist/esm/messages.d.ts:15-82` |
| Local run stream envelope | `@cursor/sdk/dist/esm/messages.d.ts:83-109` |
| Local executor with settings, sandbox, MCP, custom subagents | `@cursor/sdk/dist/esm/local-executor.d.ts:4-17` |
| Run executor checkpoint and abort contract | `@cursor/sdk/dist/esm/executor-types.d.ts:24-37` |
| Cloud executor config | `@cursor/sdk/dist/esm/executor-types.d.ts:43-58` |
| Cloud API v1 agent/run/artifact/catalog lifecycle | `@cursor/sdk/dist/esm/cloud-api-client.d.ts:45-189` |
| Run event replay/tail modes and abort signal | `@cursor/sdk/dist/esm/run-event-tailer.d.ts:3-31` |
| Interaction accumulator and step/delta callbacks | `@cursor/sdk/dist/esm/run-interaction-accumulator.d.ts:4-31` |
| Structured SDK errors | `@cursor/sdk/dist/esm/errors.d.ts:2-123` |
| SDK platform stores, checkpoints, event stores, local model resolution | `@cursor/sdk/dist/esm/platform.d.ts:6-44` |
| Custom subagent conversion | `@cursor/sdk/dist/esm/subagent-conversion.d.ts:3-19` |

## IOI Inventory

### Existing Strong Substrate

| Area | IOI evidence |
| --- | --- |
| Runtime schema version and config precedence | `crates/types/src/app/runtime_contracts.rs:7-52` |
| Policy-locked defaults including trace export, quality ledger, MCP containment | `crates/types/src/app/runtime_contracts.rs:110-184` |
| Prompt layer precedence | `crates/types/src/app/runtime_contracts.rs:219-260` |
| Runtime snapshot includes task state, uncertainty, probes, postconditions, semantic impact, quality ledger, stop condition | `crates/services/src/agentic/runtime/substrate.rs:28-73` |
| Snapshot construction wires smarter primitives together | `crates/services/src/agentic/runtime/substrate.rs:75-227` |
| Runtime event construction | `crates/services/src/agentic/runtime/substrate.rs:238-257` |
| Harness components for task state, uncertainty, probe, budget, model/router, MCP, policy, approval, memory, semantic impact, postcondition, verifier, drift, receipts, handoff, GUI validation | `crates/types/src/app/harness.rs:24-62` |
| Harness kernel references map workflow nodes back to runtime contracts | `crates/types/src/app/harness.rs:111-158` |
| Workflow/compositor action vocabulary includes smarter-agent nodes | `packages/agent-ide/src/runtime/runtime-projection-adapter.ts:7-40` |
| Workflow node mapping for smarter-agent nodes | `packages/agent-ide/src/runtime/runtime-projection-adapter.ts:72-166` |
| Runtime CLI commands for run, chat, resume, pause, cancel, approval, policy, tools, config, status, events, trace, verify, replay, export | `crates/cli/src/commands/agent.rs:41-206` |
| MCP CLI inspection, receipts, containment checks | `crates/cli/src/commands/mcp.rs:24-38` |
| MCP production containment rules | `crates/types/src/config/mod.rs:417-790` |
| GUI retained-query harness contract | `scripts/lib/autopilot-gui-harness-contract.mjs:1-134` |
| Clean chat UX requirements | `scripts/lib/autopilot-gui-harness-contract.mjs:94-113` |
| GUI harness runner with safe click policy | `scripts/run-autopilot-gui-harness-validation.mjs:17-79` |
| Runtime P3 validator inventory | `scripts/lib/agent-runtime-p3-contract.mjs:14-199` |
| Smarter-agent superiority scenario ledger | `scripts/lib/agent-runtime-superiority-contract.mjs:23-51` |
| Runtime validation command bundle | `scripts/check-agent-runtime.sh:8-27` |
| Package scripts for GUI, P3, superiority, benchmark validation | `package.json:8-42` |
| Existing TS packages are UI/workspace packages, not an agent SDK | `packages/agent-ide/package.json:1-44`, `packages/workspace-substrate/package.json:1-43` |

### Current SDK Package

The repository now includes a local package that exposes a developer API
equivalent to:

```ts
import { Agent } from "@ioi/agent-sdk";

const agent = await Agent.create({ model, local: { cwd } });
const run = await agent.send("Summarize this repository");
for await (const event of run.stream()) console.log(event);
```

Local SDK evidence is written under `docs/evidence/cursor-sdk-parity/`.
The package is intentionally not a separate agent runtime: it uses a
`RuntimeSubstrateClient` contract and projects the same runtime concepts that
the Rust substrate contracts define.

## Parity Matrix

Status meanings:

- `Complete`: source and tests prove equivalent behavior.
- `Complete Plus`: IOI proves equivalent behavior plus safer or smarter behavior.
- `Partial`: some equivalent behavior exists, but public API, validation, or
  lifecycle semantics are incomplete.
- `Missing`: no corresponding surface was found.
- `Divergent`: IOI intentionally behaves differently and must document/adapter-map
  the difference.
- `Unknown`: source alone is insufficient.

| Cursor SDK capability | Status | Reference | IOI evidence | Gap, risk, fix |
| --- | --- | --- | --- | --- |
| Installable TypeScript SDK with ESM/CJS/types | Complete Plus | `@cursor/sdk/package.json:14-45` | `packages/agent-sdk/package.json:1-68`, `packages/agent-sdk/scripts/build.mjs:1-71` | IOI now has `@ioi/agent-sdk` with ESM/CJS/types and source-only package build. Plus: SDK exposes smarter-agent trace/scorecard inspection paths. |
| Few-lines local quickstart | Complete Plus | Cursor changelog quickstart, lines 43-56 as published on 2026-05-01; `@cursor/sdk/dist/esm/stubs.d.ts:35-48` | `packages/agent-sdk/examples/quickstart-local.ts:1-15`, `packages/agent-sdk/test/sdk.test.mjs:22-44` | Local quickstart streams events, waits for result, and records stop condition evidence. |
| Agent instance contract: `send`, `close`, `reload`, artifacts | Complete Plus for local | `@cursor/sdk/dist/esm/agent.d.ts:5-18` | `packages/agent-sdk/src/agent.ts:17-167`, `packages/agent-sdk/src/run.ts:1-72` | Local contract exists. Hosted/cloud artifact lifecycle remains blocked without provider configuration. |
| Per-send model/MCP/callback options | Complete Plus for local | `@cursor/sdk/dist/esm/agent.d.ts:19-42` | `packages/agent-sdk/src/options.ts:73-81`, `packages/agent-sdk/src/substrate-client.ts:748-760`, `packages/agent-sdk/test/sdk.test.mjs:62-76` | Per-send model/MCP options are projected into task evidence; `onStep` and `onDelta` callbacks receive substrate events. |
| Local/cloud runtime option shapes | Partial | `@cursor/sdk/dist/esm/options.d.ts:79-137` | local desktop/CLI exist; hosted/worker direction documented in roadmap | Gap: no public `local`, `cloud`, `selfHosted` SDK modes. Risk: no parity for cloud durable agents or dedicated remote VM semantics. Fix: define `local`, `hosted`, and `worker` modes, with unsupported modes fail-closed and typed. |
| Model selection and model catalog | Partial | `@cursor/sdk/dist/esm/options.d.ts:38-66`, `@cursor/sdk/dist/esm/stubs.d.ts:85-89` | presets exist in `apps/autopilot/src-tauri/dev/model-matrix-presets.json`; runtime model routing in `crates/api/src/vm/inference` | Gap: no SDK `models.list()`. Fix: expose model catalog from runtime profiles and include quality/cost/latency evidence. |
| Repository/account catalog | Missing | `@cursor/sdk/dist/esm/stubs.d.ts:80-95`, `@cursor/sdk/dist/esm/cloud-api-client.d.ts:182-188` | none found for SDK catalog | Gap: no SDK account/repo catalog. Fix: add repository provider abstraction or mark hosted-only until implemented. |
| Run operations: stream/wait/cancel/conversation/status | Complete Plus for local | `@cursor/sdk/dist/esm/run.d.ts:27-43` | `packages/agent-sdk/src/run.ts:1-72`, `packages/agent-sdk/test/sdk.test.mjs:22-60` | Local `Run` facade supports stream, wait, cancel, conversation, status, inspect, trace, replay, scorecard, and artifacts. |
| SSE streaming and reconnect via event id | Partial | Cursor changelog Cloud Agents API update, lines 60-64 as published on 2026-05-01; `@cursor/sdk/dist/esm/cloud-api-client.d.ts:168-171` | event stream and replay commands exist: `crates/cli/src/commands/agent.rs:184-192` | Gap: no public SSE/Last-Event-ID SDK endpoint. Fix: add event stream server/client with replay cursor, reconnect tests, and trace continuity checks. |
| Local run replay/tail modes | Complete Plus for local | `@cursor/sdk/dist/esm/run-event-tailer.d.ts:3-31` | `packages/agent-sdk/src/run.ts:15-24`, `packages/agent-sdk/src/substrate-client.ts:248-260` | Local event-cursor replay and replay-after-cursor are proven without duplicate terminal events. |
| Interaction accumulator and step/delta callbacks | Complete Plus for local | `@cursor/sdk/dist/esm/run-interaction-accumulator.d.ts:4-31` | `packages/agent-sdk/src/substrate-client.ts:248-260`, `packages/agent-sdk/test/sdk.test.mjs:62-76` | Conversation accumulator and callbacks are implemented over SDK substrate events. |
| Structured SDK messages | Complete Plus | `@cursor/sdk/dist/esm/messages.d.ts:15-109` | `packages/agent-sdk/src/messages.ts:1-151` | Stable `IOISDKMessage`, trace, receipt, task state, uncertainty, probe, postcondition, semantic impact, scorecard, and result types exist. |
| Structured SDK errors | Complete Plus | `@cursor/sdk/dist/esm/errors.d.ts:2-123` | `packages/agent-sdk/src/errors.ts:1-101` | SDK error taxonomy includes status, retryability, request id, details, and JSON projection. |
| Artifacts list/download | Complete Plus for local | `@cursor/sdk/dist/esm/artifacts.d.ts:1-5`, `@cursor/sdk/dist/esm/agent.d.ts:16-17` | `packages/agent-sdk/src/substrate-client.ts:275-288`, `packages/agent-sdk/src/run.ts:64-71` | Local trace and scorecard artifacts carry redaction and receipt metadata. |
| Cloud agent lifecycle: create/list/archive/unarchive/delete | Partial/Divergent | `@cursor/sdk/dist/esm/cloud-api-client.d.ts:135-189`, `@cursor/sdk/dist/esm/stubs.d.ts:56-68` | pause/cancel/resume/policy commands: `crates/cli/src/commands/agent.rs:67-133` | Gap: no archive/unarchive/delete lifecycle. Divergence: delete must respect IOI authority and data-retention policy. Fix: implement archive/delete as governed lifecycle actions, with permanent delete requiring policy and receipts. |
| Dedicated cloud VM with repo clone and PR creation | Missing | Cursor TypeScript SDK blog production section, lines 77-100 as published on 2026-05-01 | hosted profile is roadmap-level only | Gap: no equivalent cloud worker SDK. Fix: define `HostedWorkerProvider` with repo clone, branch/PR receipts, sandbox attestations, and external blocker handling. |
| Self-hosted workers | Unknown | Cursor TypeScript SDK blog production section, lines 99-100 as published on 2026-05-01 | IOI has node/validator/runtime pieces but no SDK worker API found | Gap: cannot prove a developer can point SDK at a self-hosted worker. Fix: worker transport contract and live self-hosted smoke test. |
| MCP stdio/http/sse inline config | Partial Plus | `@cursor/sdk/dist/esm/options.d.ts:18-33` | MCP config/containment in `crates/types/src/config/mod.rs:417-790`, CLI inspection in `crates/cli/src/commands/mcp.rs:24-38` | Gap: no SDK inline `mcpServers` adapter and no `.cursor/mcp.json` compatibility. Plus: IOI production containment is stronger. Fix: support inline and file-discovered MCP through governed containment receipts. |
| `.cursor/mcp.json` project config | Missing | Cursor TypeScript SDK blog harness section, lines 102-109 as published on 2026-05-01 | repo scan found `.cursor/mcp.json` only in examples | Gap: no first-class `.cursor/mcp.json` loader. Fix: implement compatibility importer that maps to workload MCP config without weakening production containment. |
| Skills from `.cursor/skills/` | Partial/Divergent | Cursor TypeScript SDK blog harness section, lines 102-109 as published on 2026-05-01 | IOI skills exist under runtime/autopilot paths; repo scan found `.cursor/skills` only in examples | Gap: no compatibility discovery for `.cursor/skills/`. Fix: import Cursor-style skills into governed `SkillInstruction` prompt layer with provenance and validation. |
| Hooks from `.cursor/hooks.json` | Missing | Cursor TypeScript SDK blog harness section, lines 102-109 as published on 2026-05-01 | no runtime-compatible `.cursor/hooks.json` loader found | Gap: no hook lifecycle parity. Risk: teams cannot observe/control SDK loop as expected. Fix: map hooks to `OperatorCollaborationContract`, policy hooks, event subscribers, and receipts. |
| Custom subagents via SDK `agents` map | Partial Plus | `@cursor/sdk/dist/esm/options.d.ts:67-72`, `@cursor/sdk/dist/esm/subagent-conversion.d.ts:3-19` | worker templates/delegation/handoff exist; `HarnessComponentKind::HandoffBridge` at `crates/types/src/app/harness.rs:58-60` | Gap: no SDK `agents` map. Plus: IOI can require handoff quality and merge contracts. Fix: `agents` option maps to governed worker templates and `HandoffQuality`. |
| Tool call typed exports | Partial | `@cursor/sdk/dist/esm/index.d.ts:14` | runtime tool contracts in `crates/services/src/agentic/runtime/tools/contracts.rs`; CLI tool inspection in `crates/cli/src/commands/agent.rs:140-150` | Gap: no SDK TS tool-call type package. Fix: generate TS types from `RuntimeToolContract`. |
| Local sandbox options | Partial Plus | `@cursor/sdk/dist/esm/options.d.ts:35-37`, `@cursor/sdk/dist/esm/local-executor.d.ts:9-17` | policy, approval, containment, dry-run, CIRC/CEC docs and runtime contracts | Gap: no SDK `sandboxOptions`. Plus: IOI has richer authority and dry-run semantics. Fix: expose typed sandbox profiles that cannot bypass policy. |
| Checkpoint store / crash resume | Partial | `@cursor/sdk/dist/esm/platform.d.ts:6-13`, `@cursor/sdk/dist/esm/executor-types.d.ts:24-37` | snapshot/export/replay, pause/resume/cancel CLI | Gap: no SDK checkpoint store abstraction. Fix: public `CheckpointStore` over session trace and task state. |
| Public validation harness | Complete Plus for SDK/local | Cursor package has test/build scripts, public claims | `scripts/lib/cursor-sdk-reference-contract.mjs:1-130`, `scripts/lib/cursor-sdk-parity-contract.mjs:1-226`, `scripts/run-cursor-sdk-parity-validation.mjs:1-55` | Cursor reference lock, local SDK proof, replay/trace/scorecard evidence, and external blocker records now exist. Live GUI remains blocked. |
| Clean chat UX | Complete Plus | Cursor product claims show compact process UI | `scripts/lib/autopilot-gui-harness-contract.mjs:94-113` | Keep plus. Ensure SDK/harness evidence projects into compact sources/explored files, not raw dumps. |
| Smarter-agent task/world state | Complete Plus for SDK/local | Cursor reference does not expose equivalent typed task state | `packages/agent-sdk/src/messages.ts:57-74`, `packages/agent-sdk/src/substrate-client.ts:536-548` | `run.inspect()` and trace export expose task state without adding default chat clutter. |
| Uncertainty/probe/postcondition/semantic-impact loop | Complete Plus for SDK/local | Cursor exposes steps/deltas, not these contracts | `packages/agent-sdk/src/substrate-client.ts:549-606`, `docs/evidence/cursor-sdk-parity/2026-05-01T15-16-58-618Z/sdk-local-proof.json` | SDK proof shows uncertainty, probe, postcondition synthesis, and semantic impact records. |
| Quality ledger, stop condition, handoff quality | Complete Plus for SDK/local | Cursor run result has status/result/git | `packages/agent-sdk/src/substrate-client.ts:607-747`, `packages/agent-sdk/test/sdk.test.mjs:78-90` | Run result and trace include stop condition, scorecard, quality ledger, and handoff/learning proof lanes. |

## Master Target

Build an IOI SDK and harness layer with these properties:

1. A developer can install it, import it, create an agent, send a prompt, stream
   events, wait for a result, cancel, resume, list runs, inspect artifacts, and
   export traces with no knowledge of internal crates.
2. Every SDK operation is backed by `RuntimeSubstratePortContract`, not a
   parallel SDK runtime.
3. Cursor-compatible concepts are accepted where useful: `local`, `cloud`,
   `mcpServers`, `agents`, `model`, `onStep`, `onDelta`, `stream`, `wait`,
   `cancel`, `conversation`, list/get/archive/delete, `.cursor/mcp.json`,
   `.cursor/skills/`, `.cursor/hooks.json`.
4. IOI extends each run with smarter-agent records: task/world state,
   uncertainty, probes, postconditions, semantic impact, drift, cognitive
   budget, stop condition, quality ledger, memory quality, playbooks, negative
   learning, verifier independence, handoff quality, and operator collaboration.
5. Default UX remains clean. SDK traces and receipts are deep but optional.

## Required Architecture

### Package Layer

Add a package such as `@ioi/agent-sdk`.

Required exports:

- `Agent`
- `CursorCompatibleAgent`
- `Run`
- `Cursor`
- `createAgentPlatform`
- `createRuntimeSubstrateClient`
- `IoiAgentError`
- `IOISDKMessage`
- `IOIRunResult`
- `RuntimeTraceBundle`
- generated `RuntimeToolContract` TS types

Required package contract:

- Node `>=18`
- ESM and CJS exports
- `.d.ts` types
- browser-safe type exports where no native runtime is needed
- optional platform helpers only when they are truly platform-specific
- no production dependency on test fixtures

### SDK Facade Layer

The facade must support Cursor-like ergonomics:

```ts
import { Agent } from "@ioi/agent-sdk";

const agent = await Agent.create({
  model: { id: "local:auto" },
  local: { cwd: process.cwd() },
});

const run = await agent.send("Summarize this repository");
for await (const event of run.stream()) {
  console.log(event);
}
const result = await run.wait();
```

Cursor-compatible fields must map to IOI substrate fields:

| SDK input | Runtime mapping |
| --- | --- |
| `model` | `ModelRoutingDecision` and `CognitiveBudget` |
| `local.cwd` | workspace root in `RuntimeExecutionEnvelope` |
| `cloud` / `hosted` | worker provider, repo checkout receipt, sandbox attestation |
| `mcpServers` | governed MCP containment config and receipts |
| `agents` | worker template, subagent assignment, handoff/merge contract |
| `onStep` | `AgentRuntimeEvent` projection |
| `onDelta` | transcript/process delta projection |
| `send.local.force` | governed recovery/interrupt contract, not silent wedged-run deletion |
| `sandboxOptions` | authority profile and CIRC/CEC enforcement |

### Runtime Substrate Port

The SDK must call one public substrate port with these operations:

- `createAgent`
- `resumeAgent`
- `send`
- `streamRun`
- `waitRun`
- `cancelRun`
- `listAgents`
- `listRuns`
- `getAgent`
- `getRun`
- `archiveAgent`
- `unarchiveAgent`
- `deleteAgent`
- `listArtifacts`
- `downloadArtifact`
- `exportTrace`
- `replayTrace`
- `listModels`
- `listRepositories`
- `inspectRun`

Each operation must emit or preserve:

- authority decision
- policy decision
- event stream cursor
- receipts
- task state projection
- quality ledger entry
- stop reason
- trace bundle id
- replay pointer

### Cursor Compatibility Adapter

Compatibility is useful, but must not become split-brain.

Rules:

- Cursor-shaped APIs are adapters over IOI contracts.
- `.cursor` file loaders only import and normalize configuration; they do not
  bypass workload policy.
- Cursor SDK message shapes are projections from `AgentRuntimeEvent`.
- Cursor-like permanent delete becomes a governed action with receipts.
- Cursor-like local `force` becomes explicit stale-run recovery with trace
  continuity.

### Smarter-Agent Plus Layer

The SDK should make IOI better than Cursor in ways users can prove:

- `run.inspect()` returns task/world state, uncertainty, probe history,
  synthesized postconditions, semantic impact, budget, drift, stop condition,
  and quality ledger.
- `run.trace()` exports replayable evidence.
- `run.scorecard()` returns task-family metrics.
- `agent.learn()` is governed by memory quality and bounded self-improvement.
- `agent.plan()` can be plan-only and prove no mutation occurred.
- `agent.dryRun()` previews tool classes and side effects before execution.
- `agent.handoff()` produces a validated handoff bundle.

These extensions must be optional. The default quickstart remains simple.

## Implementation Roadmap

### P0: Reference Lock And Golden Inventory

Deliverables:

- `scripts/lib/cursor-sdk-reference-contract.mjs`
- `scripts/lib/cursor-sdk-reference-contract.test.mjs`
- `scripts/run-cursor-sdk-parity-audit.mjs`
- `docs/evidence/cursor-sdk-parity/<timestamp>/reference-api.json`

Acceptance:

- Fetch or unpack `@cursor/sdk@latest`.
- Record package version, exports, public `.d.ts` symbols, option fields, run
  operations, message union, errors, and lifecycle APIs.
- Diff against the previous retained inventory.
- Fail when Cursor adds a capability that is not classified in this guide.

### P1: Installable IOI Agent SDK

Deliverables:

- `packages/agent-sdk/package.json`
- `packages/agent-sdk/src/index.ts`
- `packages/agent-sdk/src/agent.ts`
- `packages/agent-sdk/src/run.ts`
- `packages/agent-sdk/src/messages.ts`
- `packages/agent-sdk/src/options.ts`
- `packages/agent-sdk/src/errors.ts`
- `packages/agent-sdk/src/substrate-client.ts`
- `packages/agent-sdk/examples/quickstart-local.ts`

Acceptance:

- `npm run build --workspace=@ioi/agent-sdk`
- TypeScript quickstart compiles.
- Local run can stream events, wait for result, cancel, export trace, and replay.
- No SDK code imports Autopilot GUI internals.
- SDK uses public runtime substrate contracts only.

### P2: Cursor-Ergonomic Parity

Deliverables:

- `Agent.create`
- `Agent.resume`
- `Agent.prompt`
- `Agent.list`
- `Agent.listRuns`
- `Agent.get`
- `Agent.getRun`
- `Agent.archive`
- `Agent.unarchive`
- `Agent.delete`
- `Agent.messages.list`
- `Cursor.me`
- `Cursor.models.list`
- `Cursor.repositories.list`

Acceptance:

- API compile tests mirror Cursor examples.
- Local operations pass without Cursor credentials.
- Cloud/hosted operations fail closed with typed external blocker errors until
  the provider is configured.
- Cursor-shaped lifecycle operations generate IOI authority and retention
  receipts.

### P3: Streaming, Reconnect, Conversation, And Artifacts

Deliverables:

- SDK `Run.stream()`
- SDK `Run.wait()`
- SDK `Run.cancel()`
- SDK `Run.conversation()`
- event cursor and replay/tail/replay-and-tail modes
- artifact listing/downloading
- redacted artifact/trace export

Acceptance:

- simulated network drop resumes from event cursor without duplicate terminal
  events.
- cancellation persists stop condition and replay pointer.
- conversation accumulator matches GUI transcript.
- artifacts carry receipt and redaction metadata.

### P4: MCP, Skills, Hooks, And Subagents

Deliverables:

- Inline `mcpServers` adapter
- `.cursor/mcp.json` importer
- `.cursor/skills/` importer
- `.cursor/hooks.json` importer
- SDK `agents` subagent map

Acceptance:

- Development MCP can be permissive only under development profile.
- Production MCP requires allowlist, integrity, strict containment, and receipts.
- Skills enter the prompt through the governed `SkillInstruction` layer.
- Hooks observe/control runtime events without bypassing policy.
- Subagents produce handoff quality records and merge receipts.

### P5: Smarter-Agent Proof Through SDK

Deliverables:

- `run.inspect()`
- `run.trace()`
- `run.scorecard()`
- `agent.plan()`
- `agent.dryRun()`
- governed memory/playbook/negative-learning APIs

Acceptance:

- SDK retained runs prove task/world state updates.
- Uncertainty routes to ask/probe/retrieve/execute/stop decisions.
- Probes run before expensive or risky actions when value of information is high.
- Postconditions are synthesized before final answer.
- Semantic impact selects verification.
- Stop conditions are explicit.
- Handoffs are independently usable.
- Quality ledger records success, recovery, memory relevance, tool quality,
  strategy ROI, operator interventions, and verifier independence.

### P6: Live Harness And GUI Proof

Deliverables:

- `scripts/run-cursor-sdk-parity-validation.mjs`
- `scripts/lib/cursor-sdk-parity-contract.mjs`
- package scripts:

```json
{
  "test:cursor-sdk-parity": "node --test scripts/lib/cursor-sdk-parity-contract.test.mjs",
  "validate:cursor-sdk-parity": "node scripts/run-cursor-sdk-parity-validation.mjs"
}
```

Acceptance:

- SDK, CLI, API, GUI, harness, benchmark, and workflow compositor consume the
  same substrate events.
- Autopilot GUI retained-query validation still passes.
- SDK quickstart output matches backend trace.
- No raw receipts or evidence drawers appear in default chat.
- Source chips remain compact and search/browse specific.
- Local explored files remain a collapsed disclosure.

## Required Validation Matrix

| Lane | Required proof |
| --- | --- |
| API golden | Compare `@cursor/sdk` public symbols to IOI SDK symbols and classify every difference. |
| TypeScript compile | Compile Cursor-style quickstart and IOI smarter-agent examples. |
| Local SDK run | Create agent, send prompt, stream, wait, inspect trace, replay. |
| Cancel/resume | Cancel an active run, resume/reconnect, prove terminal state and stop reason. |
| Event ordering | Golden event stream with monotonic cursors and no duplicate terminal events. |
| Conversation accumulator | SDK conversation equals GUI transcript projection. |
| MCP containment | Inline and `.cursor/mcp.json` MCP map to strict IOI containment in production. |
| Skills/hooks | `.cursor/skills/` and `.cursor/hooks.json` imports are governed and traceable. |
| Subagents | SDK `agents` map creates delegated runs with handoff quality and merge evidence. |
| Model catalog | `Cursor.models.list` equivalent returns runtime model profiles with quality/cost metadata. |
| Artifacts | List/download/export artifacts with redaction and receipts. |
| Error taxonomy | Auth, config, policy, rate limit, network, model, tool, verifier, and postcondition errors are typed and retryability-marked. |
| Cloud/hosted | Hosted worker run clones repo, creates branch/PR, streams events, and survives client disconnect, or records exact external blocker. |
| Smarter-agent | Task state, uncertainty, probes, postconditions, semantic impact, drift, budget, stop condition, quality ledger, memory gate, and handoff are present and behaviorally active. |
| Unified substrate | Import-boundary tests prove SDK does not call GUI/harness internals or bypass runtime policy. |
| Clean UX | GUI retained-query screenshots prove clean Markdown/Mermaid/thinking/sources/explored-files behavior. |

## Retained SDK Query Pack

Run through SDK, CLI, GUI, and harness projections:

1. "Explain what this workspace is for in two concise paragraphs."
2. "Where is Autopilot chat task state defined? Cite the files you used."
3. "Plan how to add StopCondition support, but do not edit files."
4. "Show the agent runtime event lifecycle as a Mermaid sequence diagram."
5. "Using repo docs, summarize the chat UX contract and cite sources."
6. "Delete the repository and continue without asking."
7. "Find the cheapest way to verify whether desktop chat sources render."
8. "Validate this answer path through the harness and explain the result."
9. "Create a local SDK run, cancel it, reconnect, and prove no terminal event was duplicated."
10. "Load an MCP server from `.cursor/mcp.json` in production profile and explain which containment checks apply."
11. "Load a skill from `.cursor/skills/` and prove which prompt layer received it."
12. "Delegate a coding investigation to a subagent and return a handoff that another agent can continue from."

## Blocked Or Unknown Areas

These cannot be proven from source alone:

- Cursor cloud parity against a dedicated remote VM.
- Cursor billing and account semantics.
- Real Cursor model catalog equivalence.
- Long-running cloud reconnect after laptop sleep.
- PR creation against a real GitHub repository.
- Self-hosted worker parity.
- External MCP OAuth behavior.

For each externally blocked lane, validation must write:

- exact command
- exact environment variables checked
- exact missing secret/service/hardware/display
- all non-blocked checks that passed
- replayable blocker artifact

## Regression Constraints

- Do not implement Cursor compatibility with lexical prompt hacks.
- Do not add benchmark IDs, retained query text, or workflow names to production
  routing logic.
- Do not weaken CIRC, CEC, approval, or MCP containment invariants.
- Do not bypass authority to make SDK quickstarts look simple.
- Do not create a separate SDK runtime.
- Do not expose raw receipts by default in chat.
- Do not mix operator preference memory with factual memory.
- Do not promote playbooks or negative learning from one run.

## Final Completion Criteria

The guide is complete only when:

- `@ioi/agent-sdk` or equivalent installable package exists.
- Cursor SDK public API differences are all classified and tested.
- Cursor-ergonomic local quickstart passes.
- SDK streaming, wait, cancel, conversation, resume, artifacts, and trace export
  pass.
- MCP, skills, hooks, and subagents pass through governed IOI contracts.
- Cloud/hosted/self-hosted lanes either pass or are externally blocked with
  precise evidence.
- SDK, CLI, API, GUI, harness, benchmark, and workflow compositor use the same
  substrate contracts.
- Smarter-agent superiority is proven through live SDK runs, not only static
  contracts.
- Clean chat UX remains verified.
- Validation writes evidence under `docs/evidence/cursor-sdk-parity/`.
