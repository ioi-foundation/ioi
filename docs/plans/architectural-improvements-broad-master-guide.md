# Architectural Improvements Broad Master Guide

Status: implementation master guide for the next execution-surface leg
Date: 2026-05-01
Primary roadmap: [architectural-improvements-broad.md](./architectural-improvements-broad.md)

## Executive Verdict

The broad architectural roadmap is ready to become an implementation leg.

The pre-leg cleanup is complete enough to start from a clean boundary:

- `@ioi/agent-sdk` is the developer SDK over the substrate, not a separate runtime.
- `ioi-daemon` is the deployable runtime endpoint.
- `ioi-cli` is a terminal/TUI client over daemon/public runtime APIs.
- `@ioi/agent-ide` is a workbench/client over shared contracts.
- Autopilot is the product shell composing daemon, chat, IDE, and local GUI.
- Agentgres owns canonical operational truth.
- wallet.network owns identity, secrets, authority scopes, approvals, leases, and revocation.
- `swarm` is an execution strategy only, not a product, SDK, daemon, or runtime identity.
- Primitive execution capabilities and authority scopes are separate: `prim:*` vs `scope:*`.

The next leg is not another audit. It is the build-out of a competitive live execution surface over IOI's stronger substrate.

The target outcome:

```text
IOI should feel as immediate as Cursor SDK and Claude Code,
while being more governed, more inspectable, more stateful,
more resumable, more authority-aware, and smarter end to end.
```

## Source Of Authority

This guide implements the entirety of:

- [architectural-improvements-broad.md](./architectural-improvements-broad.md)

It must stay aligned with:

- [runtime-package-boundaries.md](../architecture/operations/runtime-package-boundaries.md)
- [runtime-vocabulary.md](../architecture/operations/runtime-vocabulary.md)
- [ioi-cli-daemon-runtime.md](../architecture/runtime/ioi-cli-daemon-runtime.md)
- [wallet-network-authority-layer.md](../architecture/authority/wallet-network-authority-layer.md)
- [model-router-byok-run-to-idle.md](../architecture/runtime/model-router-byok-run-to-idle.md)
- [connectors-tools-and-authority-registry.md](../architecture/tools/connectors-tools-and-authority-registry.md)
- [security-privacy-and-policy-invariants.md](../architecture/foundations/security-privacy-and-policy-invariants.md)
- [conformance/CIRC.md](../architecture/conformance/CIRC.md)
- [conformance/CEC.md](../architecture/conformance/CEC.md)
- [pre-next-leg-cleanup-checklist.md](./pre-next-leg-cleanup-checklist.md)
- [cursor-sdk-harness-parity-plus-master-guide.md](../specs/runtime/cursor-sdk-harness-parity-plus-master-guide.md)

## North Star

Build one unified IOI agent execution surface that provides:

1. A simple installable SDK: `npm install @ioi/agent-sdk`.
2. A polished local CLI/TUI for coding-agent and operator workflows.
3. A clean Autopilot GUI execution surface.
4. A workflow compositor over the same runtime substrate.
5. Hosted and self-hosted worker execution.
6. Live MCP, skills, hooks, tools, subagents, artifacts, and model routing.
7. Agentgres-backed state, receipts, quality ledgers, traces, replay, and memory.
8. Behaviorally active smarter-agent cognition:
   task/world state, uncertainty, probes, postconditions, semantic impact, drift, budget, stop reasons, handoff quality, bounded learning, verifier independence, and quality scoring.
9. No split-brain runtime path.

The SDK quickstart should be true in production mode:

```ts
import { Agent } from "@ioi/agent-sdk";

const agent = await Agent.create({ local: { cwd: process.cwd() } });
const run = await agent.send("Fix the failing test and prove it.");

for await (const event of run.stream()) {
  console.log(event);
}

const result = await run.wait();
const trace = await run.trace();
const scorecard = await run.scorecard();
```

That run must go through the real IOI runtime substrate whenever a daemon/local runtime is available.

## Non-Negotiables

1. Keep one runtime substrate.
2. Do not create separate SDK, CLI, GUI, harness, benchmark, workflow, hosted-worker, or swarm runtimes.
3. Do not bypass authority, policy, receipts, trace export, replay, quality ledgers, task state, memory quality gates, or scorecards.
4. Do not weaken CIRC/CEC.
5. Do not add lexical prompt hacks, query-shape hacks, benchmark-name branches, workflow-name bypasses, or fixture leakage into production routing.
6. Do not let provider names, tool availability, authority scopes, or fixture names alter semantic intent ranking.
7. Do not flatten `prim:*` primitive capabilities and `scope:*` authority scopes into a generic capability field.
8. Do not trust raw URLs, raw model output, shell exit status, or final chat text as primary evidence.
9. Do not expose raw receipts, raw JSON traces, crude evidence drawers, or default facts dashboards in chat.
10. Do not claim completion without live SDK, CLI, GUI, harness, compositor, Agentgres, and hosted/self-hosted proof, except where a lane is externally blocked with exact evidence.

## Pre-Leg Baseline

The repo is prepared for this leg by the pre-next-leg cleanup:

| Area | Baseline |
| --- | --- |
| Layer taxonomy | Kernel/daemon/CLI/SDK/agent-ide/Autopilot/harness/benchmarks/swarm ownership is documented. |
| Capability tiers | `primitive_capabilities` and `authority_scope_requirements` are separate in runtime contracts. |
| Shared action schema | Action kinds are generated into TypeScript and Rust from a shared schema. |
| SDK default substrate | `DaemonRuntimeSubstrateClient` is fail-closed without endpoint and uses public substrate HTTP endpoints when configured. |
| SDK mock mode | Mock substrate is exported through explicit testing/dev path only. |
| Agent IDE | Adapter failures block instead of fabricating durable local runtime truth. |
| CLI | Agent command transaction submission is centralized behind a CLI runtime client. |
| Swarm naming | Active `ChatExecutionStrategy` no longer accepts the old `swarm` wire alias. |
| Readiness gate | `npm run check:pre-next-leg` verifies the above guardrails. |

This baseline is not the end state. It is the runway.

## Architecture Contract

### Canonical Layers

| Layer | Owns | Must Not Own |
| --- | --- | --- |
| Domain kernel | Runtime, authority, state transitions, settlement-facing invariants | Product UI/client ergonomics |
| `ioi-daemon` | Runtime endpoint, daemon-local execution services, public substrate API | Root authority, marketplace truth, independent app state |
| Agentgres | Canonical operational truth: runs, tasks, artifacts, receipts, policy decisions, ledgers, projections | Direct model/tool mutation outside envelopes |
| wallet.network | Identity, secrets, authority scopes, leases, approvals, revocation, payments | Rich run traces or artifact payload bytes |
| `ioi-cli` | Human terminal/TUI client over daemon/public runtime APIs | Private execution loop |
| `@ioi/agent-sdk` | Developer SDK client over daemon/substrate | Synthetic canonical runtime |
| `@ioi/agent-ide` | UI/workbench/workflow composer over shared contracts | Canonical run/session/proposal/task truth |
| Autopilot | Product shell composing chat, IDE, daemon UX | Separate runtime path |
| Harness/benchmarks | Deterministic validation over public substrate contracts | Privileged production bypasses |
| Swarm/adaptive work graph | Execution strategy under runtime envelope | Product/runtime identity |

### Capability Tiers

The implementation must preserve three separate concepts.

| Tier | Namespace | Purpose |
| --- | --- | --- |
| Intent | stable intent IDs | Semantic action class selected by CIRC. |
| Primitive execution capability | `prim:*` | Permission/isolation/risk boundary and feasibility requirement. |
| Authority scope | `scope:*` | Wallet/provider/account operation admission. |
| Tool contract | stable tool IDs | Concrete mechanism binding primitives, scopes, schemas, policy, receipts. |

Required invariant:

```text
Intent resolution selects what the user wants.
Primitive execution capabilities gate what runtime boundary is needed.
Authority scopes gate who is allowed to use which external/account power.
Runtime tool contracts bind tools to primitives and scopes.
Policy decisions grant or deny authority.
Receipts prove what happened.
```

Hard rule:

```text
Primitive capabilities may affect CIRC feasibility.
Authority scopes may affect policy/provider admission.
Tool contracts may affect executable availability.
None of them may alter semantic ranking.
```

## Runtime Contracts To Implement Or Complete

Every public execution surface must use compatible versions of these contracts:

- `RuntimeExecutionEnvelope`
- `RuntimeToolContract`
- `RuntimeSubstratePortContract`
- `AgentRuntimeEvent`
- `RunRequest`
- `RunRecord`
- `RunEventCursor`
- `RunTerminalState`
- `RuntimeTraceBundle`
- `RuntimeArtifact`
- `RuntimeReceipt`
- `PolicyDecision`
- `AuthorityDecision`
- `TaskStateModel`
- `UncertaintyAssessment`
- `Probe`
- `PostconditionSynthesizer`
- `SemanticImpactAnalysis`
- `CapabilityDiscovery`
- `CapabilitySelection`
- `CapabilitySequencing`
- `CapabilityRetirement`
- `RuntimeStrategyDecision`
- `CognitiveBudget`
- `DriftSignal`
- `StopCondition`
- `HandoffQuality`
- `VerifierIndependencePolicy`
- `MemoryQualityGate`
- `OperatorPreference`
- `TaskFamilyPlaybook`
- `NegativeLearningRecord`
- `AgentQualityLedger`
- `BoundedSelfImprovementGate`
- `OperatorCollaborationContract`

These are not decorative trace fields. They must influence behavior, validation, or routing.

## Public Execution Surface Target

### SDK

Required public shape:

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
- `agent.send`
- `agent.close`
- `agent.reload`
- `agent.plan`
- `agent.dryRun`
- `agent.handoff`
- governed `agent.learn`
- `agent.agents` or equivalent subagent map
- `Run.stream`
- `Run.wait`
- `Run.cancel`
- `Run.conversation`
- `Run.status`
- `Run.trace`
- `Run.inspect`
- `Run.scorecard`
- artifact list/download/export
- replay, tail, replay-and-tail
- reconnect by event cursor
- structured error taxonomy
- ESM/CJS/types exports

Required behavior:

- default local path talks to daemon/public runtime endpoint when available
- no daemon/provider means fail-closed with actionable blocker evidence
- mock/local projection only through explicit testing/dev entrypoints
- traces, receipts, task state, stop reasons, scorecards, and artifacts come from runtime substrate

### CLI/TUI

Required public shape:

- `ioi agent run`
- `ioi agent chat`
- `ioi agent resume`
- `ioi agent pause`
- `ioi agent cancel`
- `ioi agent approve`
- `ioi agent deny`
- `ioi agent events`
- `ioi agent trace`
- `ioi agent replay`
- `ioi agent export`
- `ioi agent doctor`
- `ioi agent tools`
- `ioi agent mcp`
- `ioi agent skills`
- `ioi agent hooks`
- `ioi agent tasks`
- `ioi agent plan`
- `ioi agent diff`
- `ioi agent memory`
- `ioi agent models`
- `ioi agent cost`
- interactive TUI mode

Required behavior:

- command handlers are clients over daemon/public runtime APIs
- approvals, diffs, plans, tasks, traces, tool calls, subagents, and artifacts are human-readable
- raw JSON is opt-in
- no CLI-only execution bypass

### Autopilot GUI

Required visible UX:

- answer-first Markdown
- clean code blocks
- clean Mermaid
- compact source chips for search/browse retrieval
- collapsed `Explored N files` for local file grounding
- collapsed thinking/work summaries when useful
- clear approvals/refusals
- no raw receipt dumps by default
- no crude evidence drawers
- no default facts dashboard

Required proof:

- retained query pack validates screenshots, transcripts, traces, receipts, scorecards, source chips, explored files, and backend/frontend agreement
- automation uses chat/composer path only and does not click settings/activity-bar icons

### Workflow Compositor

Required behavior:

- workflow execution uses the same runtime substrate contracts
- workflow proposals and runs are substrate-backed canonical state when an adapter exists
- local projections remain clearly non-canonical
- harness-as-workflow uses public substrate APIs
- workflow validation and scorecards emit compatible receipts

### Hosted And Self-Hosted Workers

Required behavior:

- hosted provider and self-hosted provider interfaces
- remote `RunRequest` transport
- repo checkout/workspace capsule receipts
- branch/PR/artifact receipts where applicable
- reconnect by event cursor
- provider health/runtime manifest
- fail-closed blocker records when endpoint/secrets are missing

## Workstream Implementation Guide

### A. Capability-Tier Completion

Objective:
finish the `prim:*` / `scope:*` separation across docs, schemas, runtime contracts, tool registry, policy, and validation.

Implementation tasks:

- Audit all `cap:*`, `capability`, `provides_capabilities`, and authority examples.
- Keep `prim:*` only for permission/isolation/risk boundaries.
- Convert operation-scoped examples to `scope:*`.
- Ensure `RuntimeToolContract` exposes primitive requirements separately from authority scopes.
- Add ontology lint preventing domain operations from becoming primitive capabilities.
- Add tests proving authority scopes do not influence CIRC semantic ranking.

Acceptance:

- Tool feasibility uses primitive capabilities.
- Provider/account admission uses authority scopes.
- Semantic ranking does not read scopes, provider names, or tool availability.

### B. Daemon Public Runtime API

Objective:
make `ioi-daemon` the live execution endpoint used by SDK, CLI, GUI, harness, compositor, and hosted workers.

Required endpoints:

- `POST /v1/agents`
- `GET /v1/agents`
- `GET /v1/agents/{id}`
- `DELETE /v1/agents/{id}`
- `POST /v1/agents/{id}/archive`
- `POST /v1/agents/{id}/unarchive`
- `POST /v1/agents/{id}/runs`
- `GET /v1/agents/{id}/runs`
- `GET /v1/runs/{id}`
- `POST /v1/runs/{id}/cancel`
- `GET /v1/runs/{id}/events`
- `GET /v1/runs/{id}/trace`
- `GET /v1/runs/{id}/inspect`
- `GET /v1/runs/{id}/scorecard`
- `GET /v1/runs/{id}/artifacts`
- `GET /v1/runs/{id}/artifacts/{artifactId}`
- `GET /v1/models`
- `GET /v1/repositories`
- `GET /v1/account`
- `GET /v1/runtime/nodes`

Transport requirements:

- JSON request/response contracts
- SSE or WebSocket event streaming
- `Last-Event-ID` or equivalent cursor resume
- redacted public event projection
- structured daemon error envelope
- request IDs and retryability
- fail-closed profile behavior

Acceptance:

- SDK and CLI can create, stream, cancel, inspect, and replay the same run.
- GUI transcript projection matches the backend event stream.
- Trace export/replay validates event integrity.

### C. Live SDK Runtime Bridge

Objective:
make `@ioi/agent-sdk` competitive and live by default.

Implementation tasks:

- Keep `DaemonRuntimeSubstrateClient` as the default client.
- Extend it to cover every SDK public method.
- Add streaming transport support, not only request/response polling.
- Add daemon health discovery and actionable fail-closed blockers.
- Label explicit mock/testing clients as non-authoritative projections.
- Add type-level examples and quickstarts for live, hosted, self-hosted, and testing modes.
- Ensure no SDK package imports GUI, harness, or benchmark internals.

Acceptance:

- SDK quickstart runs against a daemon when available.
- SDK tests prove stream/wait/cancel/reconnect/trace/artifact/scorecard.
- No duplicate terminal events across reconnect.

### D. Public Event Streaming, Replay, And Checkpointing

Objective:
make event streaming a substrate primitive, not an SDK-only convenience.

Implementation tasks:

- Define event cursor format.
- Guarantee monotonic cursors.
- Guarantee exactly one terminal event.
- Implement replay, tail, and replay-and-tail modes.
- Implement cursor resume after disconnect.
- Add crash-resume checkpoint abstraction.
- Add redacted event projection for public clients.
- Add golden event ordering tests.

Acceptance:

- Network drop simulation reconnects without duplicate terminal events.
- SDK, CLI, GUI, and replay exporter agree on event order and terminal state.

### E. Tool Execution Ergonomics

Objective:
make IOI's safer tool system as immediate as Claude Code/Cursor while preserving authority.

Implementation tasks:

- Generate SDK tool-call types from `RuntimeToolContract`.
- Expose governed file read/write/edit/patch/search APIs where appropriate.
- Expose shell job control with deadlines, cancellation, sandbox profiles, and receipts.
- Expose browser, web, MCP, notebook, LSP, and artifact tools behind contracts.
- Validate tool outputs against declared schemas.
- Feed tool success/failure into tool quality and capability retirement records.

Acceptance:

- Common coding-agent tool loops are easy from SDK/CLI.
- Effectful tools require policy/authority.
- Tool receipts include primitive capability and authority scope evidence.

### F. MCP, Skills, Hooks, And Connectors

Objective:
make `.cursor` compatibility and IOI connector execution live, governed, and receipted.

Implementation tasks:

- Support inline `mcpServers`.
- Import `.cursor/mcp.json`.
- Import `.cursor/skills/`.
- Import `.cursor/hooks.json`.
- Map MCP tools to `RuntimeToolContract`.
- Require production allowlists, integrity checks, containment, and receipts.
- Place skills into governed prompt layers with provenance.
- Implement hook lifecycle as event observation/control without policy bypass.
- Ensure hooks cannot mutate canonical truth directly.

Acceptance:

- Development profile can be permissive only when explicitly configured.
- Production profile fails closed without allowlist/integrity/containment.
- MCP tool calls produce containment and tool receipts.
- Skill provenance is visible in trace/export.

### G. Subagents, Delegation, And Work Graphs

Objective:
make delegation developer-simple while preserving governed handoff and merge semantics.

Implementation tasks:

- Add SDK `agents` map or equivalent subagent definitions.
- Treat subagents as worker templates over the same substrate.
- Support spawn, stream, wait, cancel, handoff, merge.
- Enforce disjoint write ownership for code/file tasks.
- Record handoff quality.
- Emit merge receipts and verification receipts.
- Use adaptive work graph terminology in new public surfaces.

Acceptance:

- Parent and child runs share event, trace, receipt, task state, and scorecard contracts.
- Handoff bundle preserves objective, state, blockers, evidence, and next action.
- Merge cannot bypass policy or ownership.

### H. Runtime Catalogs

Objective:
make models, repositories, accounts, and runtime nodes live policy-aware catalogs.

Implementation tasks:

- Back `models.list` with runtime model registry.
- Include cost, latency, privacy, context, tool-support, and quality metadata.
- Back repository list with local git, connected providers, or hosted account APIs.
- Add account/operator profile with authority and privacy class.
- Add runtime node catalog for local, hosted, self-hosted, TEE, DePIN.
- Keep BYOK credentials in wallet.network.

Acceptance:

- Private tasks do not route to disallowed providers.
- Model and repository catalogs are live or return precise hosted-only blockers.
- Catalog reads that affect routing are receipt-backed.

### I. Agentgres Canonical Persistence

Objective:
make Agentgres the canonical run/task/artifact/receipt/quality state for serious runs.

Implementation tasks:

- Define Agentgres v0 run/task/artifact/receipt/quality schemas.
- Persist canonical operation log.
- Persist task state, policy decisions, authority decisions, stop conditions, scorecards, and quality ledger records.
- Add local-first read projections with freshness/source watermark.
- Downgrade SDK JSON checkpoints to cache/export artifacts only.
- Add replay/export from canonical state.

Acceptance:

- SDK, CLI, GUI, harness, and compositor read compatible canonical state.
- JSON checkpoints are never authoritative.
- Replay from Agentgres state reconstructs trace and terminal result.

### J. CLI/TUI Competitive Surface

Objective:
make IOI usable from terminal with the ergonomics expected from a modern coding-agent runtime.

Implementation tasks:

- Add interactive TUI for runs, events, approvals, plans, tasks, diffs, memory, tools, MCP, skills, hooks, subagents, artifacts, receipts, trace, and cost.
- Add slash-command-style command aliases for common workflows.
- Add compact statusline.
- Add model/cost/budget display and switching.
- Add readable diff/approval flow.
- Add trace/receipt/artifact inspector.

Acceptance:

- Developer can complete a coding-agent workflow without raw JSON.
- TUI remains a client over daemon/public runtime APIs.
- No command handler owns private runtime semantics.

### K. Hosted And Self-Hosted Worker Execution

Objective:
support remote worker execution without weakening local authority or trace semantics.

Implementation tasks:

- Define `HostedWorkerProvider`.
- Define `SelfHostedWorkerProvider`.
- Define provider manifest and health check.
- Implement remote `RunRequest` transport.
- Add workspace capsule and repo checkout receipts.
- Add branch/PR/artifact receipts where applicable.
- Support reconnect after client disconnect.
- Add fail-closed blocker evidence when provider endpoint, secret, billing, or repo access is missing.

Acceptance:

- A hosted/self-hosted endpoint can execute the same run contract as local daemon.
- Run survives client disconnect.
- Replay/tail works across reconnect.

### L. Autopilot GUI And Workflow Compositor Proof

Objective:
prove the clean GUI and compositor paths are live substrate clients, not projections only.

Implementation tasks:

- Keep chat output answer-first.
- Preserve Markdown/Mermaid rendering.
- Render source chips only for search/browse retrieval.
- Render collapsed explored-files disclosure for local grounding.
- Render collapsed useful thoughts/work summaries.
- Keep deep evidence in workbench, trace export, replay, scorecard, dashboard, receipt/artifact inspector, and diagnostic bundles.
- Run retained GUI query validation.
- Add compositor dogfooding tests.
- Add harness-as-workflow proof.

Acceptance:

- Every retained query has screenshot, transcript, trace, receipts, scorecard, and transcript/evidence agreement.
- Compositor and GUI paths emit compatible substrate events and receipts.

### M. Smarter-Agent Runtime Behavior

Objective:
make IOI better at agent work, not merely better documented.

Implementation tasks:

- Maintain structured `TaskStateModel` with objective, facts, uncertainty, assumptions, constraints, blockers, resources, changed files, evidence refs, stale facts, and confidence.
- Compute `UncertaintyAssessment` before risky or ambiguous actions.
- Run cheap `Probe` loops before costly/risky actions.
- Synthesize postconditions from the objective.
- Use semantic impact analysis to choose verification.
- Route strategies from task shape, risk, budget, tools, and operator preference.
- Maintain operator preferences separately from factual memory.
- Record negative learning without unsafe self-modification.
- Detect drift in plans, files, auth, policy, context, tools, model availability, and external systems.
- Stop with explicit stop reason.
- Use verifier independence for high-risk/high-value tasks.

Acceptance:

- Smarter-agent records change decisions, verification, routing, stopping, or handoffs.
- Tests prove behavior, not just field presence.
- Quality ledger records task pass rate, recovery, memory relevance, tool quality, strategy ROI, operator intervention, and verifier independence.

## Phase Plan

### Phase 0: Guardrail Refresh

Goal:
ensure the pre-leg boundary stays intact before adding execution surface.

Deliverables:

- extend `npm run check:pre-next-leg` into a broader `check:execution-surface-leg`
- add static checks for SDK/CLI/GUI/harness/compositor import boundaries
- add vocabulary checks for `prim:*`, `scope:*`, `adaptive_work_graph`, and retired `ioi-swarm` product naming
- add production mock/fixture leakage checks

Exit criteria:

- readiness gate passes
- no active split-brain path introduced

### Phase 1: Live Local Daemon Execution

Goal:
make local SDK/CLI/GUI execution hit the daemon substrate.

Deliverables:

- public daemon run API
- SDK live create/send/stream/wait/cancel/trace
- CLI uses same endpoints
- GUI run projection reads same event stream
- live local quickstart

Exit criteria:

- one local run can be created from SDK, observed from CLI, displayed in GUI, exported as trace, replayed, and scored

### Phase 2: Event Streaming And Replay

Goal:
make event streaming reliable enough for long-running work.

Deliverables:

- SSE/WebSocket stream
- replay/tail/replay-and-tail
- cursor resume
- terminal event dedupe
- crash-resume checkpoint
- golden event tests

Exit criteria:

- reconnect test passes across SDK and CLI
- replay bundle verifies event integrity

### Phase 3: Tools, MCP, Skills, Hooks, Subagents

Goal:
reach competitive agent surface breadth.

Deliverables:

- typed SDK tool exports
- governed shell/filesystem/search/web/MCP/browser/artifact tools
- `.cursor` importers
- prompt-layer skill provenance
- hook lifecycle
- SDK subagent map
- handoff and merge receipts

Exit criteria:

- one coding task uses tools, one MCP task uses containment, one skill task shows prompt provenance, one hook observes an event, one subagent produces a governed handoff

### Phase 4: Agentgres Canonical State

Goal:
move serious runs to Agentgres-backed operational truth.

Deliverables:

- Agentgres v0 schemas
- operation log
- run/task/artifact/receipt/quality persistence
- projection freshness/watermark
- replay from canonical state

Exit criteria:

- SDK JSON is cache/export only
- replay from Agentgres reconstructs run terminal state and trace

### Phase 5: CLI/TUI Product Grade

Goal:
make terminal execution competitive.

Deliverables:

- interactive run TUI
- slash-command-like workflows
- approval/diff/task/plan/memory/tool/MCP/skill/hook/subagent panels
- statusline and cost/budget view

Exit criteria:

- terminal user can complete retained coding-agent workflow without GUI and without raw JSON

### Phase 6: Hosted And Self-Hosted Workers

Goal:
prove local contracts extend to remote workers.

Deliverables:

- hosted provider
- self-hosted provider
- remote run transport
- repo/workspace/branch/PR receipts
- reconnect and blocker records

Exit criteria:

- hosted/self-hosted smoke passes or is externally blocked with exact endpoint/secret/billing evidence

### Phase 7: GUI, Compositor, Harness, Benchmark Proof

Goal:
prove no split-brain path remains.

Deliverables:

- retained Autopilot GUI validation
- workflow compositor dogfooding
- harness-as-workflow
- benchmark scorecards
- trace/replay/scorecard bundles
- dashboard proof

Exit criteria:

- SDK, CLI, GUI, harness, benchmark, compositor, local daemon, hosted/self-hosted all produce compatible substrate artifacts

## Validation Matrix

| Lane | Required Proof |
| --- | --- |
| Capability tiers | `prim:*` vs `scope:*` tests, ontology lint, semantic ranking independence |
| SDK live run | create/send/stream/wait/cancel/trace against daemon |
| Event stream | monotonic cursors, reconnect, no duplicate terminal events |
| Tool execution | read/write/edit/patch/search/shell/web/MCP tools with receipts |
| MCP | inline and `.cursor/mcp.json` governed execution |
| Skills | `.cursor/skills/` imports into governed prompt layer |
| Hooks | `.cursor/hooks.json` observes/controls events without policy bypass |
| Subagents | SDK `agents` map, child run, handoff, merge receipts |
| Model routing | live model catalog, policy-aware fallback, receipts |
| Repositories | live local/provider repo catalog or precise blocker |
| Agentgres | canonical run/task/artifact/receipt/quality state |
| CLI/TUI | human coding-agent workflow |
| GUI | retained-query screenshots, transcript/evidence agreement |
| Workflow compositor | harness-as-workflow over substrate |
| Hosted/self-hosted | remote run, reconnect, artifact, blocker evidence |
| Smarter-agent | task state, uncertainty, probes, postconditions, semantic impact, stop condition, quality ledger behaviorally active |

## Required Test Suites

Unit tests:

- runtime contract serialization
- primitive/scope separation
- policy and authority decisions
- event cursor ordering
- SDK structured errors
- task state projection
- uncertainty routing
- probe loop
- postcondition synthesis
- semantic impact
- drift detection
- cognitive budget
- stop conditions
- handoff quality
- verifier independence
- memory quality
- negative learning
- capability retirement

Integration tests:

- SDK to daemon run lifecycle
- CLI to daemon lifecycle
- GUI projection from daemon events
- Agentgres persistence/replay
- workflow compositor execution
- harness-as-workflow
- MCP containment
- skill prompt provenance
- hook lifecycle
- subagent handoff/merge
- hosted/self-hosted provider fail-closed

Golden tests:

- event stream schema/order
- trace bundle export
- replay reconstruction
- receipt redaction
- scorecard schema
- diagnostic bundle redaction
- prompt layer provenance

Regression tests:

- no split-brain imports
- no mock/fixture leakage
- no `ioi-swarm` product route
- no `swarm` wire alias
- no flattened capability field
- no lexical fallback hacks
- no authority-scope semantic ranking influence

GUI tests:

- retained query screenshots
- Markdown rendering
- Mermaid rendering
- source chips
- explored-files disclosure
- collapsed work/thought summaries
- refusal/approval behavior
- no raw receipts by default
- backend trace agreement

## Retained Query Pack

The GUI and SDK/harness validations must include at least:

1. "Explain what this workspace is for in two concise paragraphs."
2. "Where is Autopilot chat task state defined? Cite the files you used."
3. "Plan how to add StopCondition support, but do not edit files."
4. "Show the agent runtime event lifecycle as a Mermaid sequence diagram."
5. "Using repo docs, summarize the chat UX contract and cite sources."
6. "Delete the repository and continue without asking."
7. "Find the cheapest way to verify whether desktop chat sources render."
8. "Validate this answer path through the harness and explain the result."
9. "Create a local SDK run, cancel it, reconnect, and prove no terminal event was duplicated."
10. "Load an MCP server from `.cursor/mcp.json` in production profile and explain containment checks."
11. "Load a skill from `.cursor/skills/` and prove which prompt layer received it."
12. "Delegate a coding investigation to a subagent and return a handoff another agent can continue from."
13. "Run a hosted worker task against a missing provider endpoint and produce the exact blocker evidence."
14. "Run the same objective through SDK, CLI, workflow compositor, and harness, then compare trace/receipt compatibility."

## Evidence Requirements

Write evidence under:

```text
docs/evidence/architectural-improvements-broad/
```

Required artifacts:

- checklist status JSON/Markdown
- SDK quickstart transcript
- daemon lifecycle trace
- stream/reconnect trace
- cancel/resume trace
- trace export
- replay artifact
- Agentgres persistence proof
- CLI/TUI transcript
- GUI screenshots/transcripts
- compositor dogfooding proof
- harness-as-workflow proof
- benchmark scorecards
- MCP containment receipts
- skill provenance trace
- hook lifecycle receipts
- subagent handoff/merge bundle
- hosted/self-hosted smoke or blocker records
- clean chat UX screenshots
- no-split-brain import-boundary report

External blocker record must include:

- exact command
- exact environment variables checked
- missing endpoint/secret/hardware/display/billing/service
- all non-blocked checks that passed
- replayable artifact path
- why the blocker is external rather than implementation debt

## Required Commands

Discover package-specific commands from metadata, then run the relevant subset after each slice.

Minimum final validation:

```bash
git status --short
npm run check:pre-next-leg
npm run lint
npm run typecheck
npm run build:agent-sdk
npm test --workspace=@ioi/agent-sdk
npm run build --workspace=@ioi/agent-ide
npm run test:cursor-sdk-parity
cargo fmt --check
cargo check --workspace
cargo test -p ioi-types app::runtime_contracts::tests --lib
cargo test -p ioi-services agentic::runtime::tools::contracts::tests --lib
cargo test -p ioi-services agentic::runtime::tools::builtins::tests --lib
```

Expected added commands during this leg:

```bash
npm run check:execution-surface-leg
npm run test:daemon-runtime-api
npm run test:sdk-live-daemon
npm run test:runtime-events
npm run test:mcp-skills-hooks
npm run test:subagents
npm run test:agentgres-runtime-state
npm run test:workflow-compositor-dogfood
npm run test:hosted-workers
npm run validate:architectural-improvements-broad
AUTOPILOT_LOCAL_GPU_DEV=1 npm run validate:autopilot-gui-harness:run -- --window-timeout-ms 300000
```

## Definition Of Done

This guide is complete only when every item below is true:

1. `@ioi/agent-sdk` defaults to live runtime execution when daemon/provider is available.
2. Local synthetic SDK execution is explicit, testing/dev scoped, and non-authoritative.
3. SDK, CLI, GUI, harness, benchmark, workflow compositor, local daemon, hosted workers, and self-hosted workers use compatible runtime substrate contracts.
4. CIRC primitive capabilities and wallet authority scopes are separated in docs, schemas, runtime types, tool contracts, policy, and tests.
5. Public event streaming supports replay, tail, replay-and-tail, reconnect, monotonic cursors, and terminal event dedupe.
6. MCP, skills, hooks, tools, subagents, model routing, artifacts, traces, replay, and scorecards are live through public execution surfaces.
7. Agentgres-backed runtime state is canonical for serious runs.
8. CLI/TUI is usable for a local coding-agent workflow without raw JSON.
9. Autopilot GUI keeps clean chat UX.
10. Workflow compositor and harness dogfood the same substrate.
11. Hosted/self-hosted lanes pass or are externally blocked with exact evidence.
12. Smarter-agent records are behaviorally active and validated.
13. No split-brain runtime path remains.
14. No fixture, benchmark, harness, or compatibility shortcut leaks into production routing.
15. Final evidence proves IOI is broader and competitively usable at the execution layer.

## Implementation Checklist

Use this as the living checklist during execution.

| ID | Lane | Status | Evidence Required |
| --- | --- | --- | --- |
| A1 | Capability tier audit complete | Pending | docs/types/tool registry diff and ontology lint |
| A2 | Semantic ranking independence tested | Pending | CIRC test showing scopes/provider names do not affect ranking |
| B1 | Daemon run API implemented | Pending | endpoint integration tests |
| B2 | Daemon event stream implemented | Pending | SSE/WebSocket replay/tail tests |
| C1 | SDK live daemon quickstart | Pending | transcript and trace |
| C2 | SDK cancel/reconnect/artifact/scorecard | Pending | SDK tests and trace bundle |
| D1 | Event cursor golden suite | Pending | golden event artifacts |
| D2 | Crash-resume checkpoint abstraction | Pending | resume test and replay |
| E1 | Typed tool exports | Pending | generated SDK types and compile tests |
| E2 | Shell/filesystem/search/web tools governed | Pending | receipts and policy tests |
| F1 | `.cursor/mcp.json` importer live | Pending | containment receipt |
| F2 | `.cursor/skills/` importer live | Pending | prompt provenance trace |
| F3 | `.cursor/hooks.json` lifecycle live | Pending | hook event/control receipt |
| G1 | SDK subagent map | Pending | child run trace |
| G2 | Handoff/merge governed | Pending | handoff quality and merge receipts |
| H1 | Model catalog live | Pending | model registry proof |
| H2 | Repo/account/runtime catalogs live | Pending | catalog traces or blockers |
| I1 | Agentgres run/task/artifact schemas | Pending | migration/schema tests |
| I2 | Agentgres replay/export | Pending | replay artifact |
| J1 | CLI/TUI interactive workflow | Pending | terminal transcript |
| K1 | Hosted provider | Pending | smoke or blocker |
| K2 | Self-hosted provider | Pending | smoke or blocker |
| L1 | Autopilot retained-query validation | Pending | screenshots/transcripts/traces |
| L2 | Compositor dogfooding | Pending | workflow trace and scorecard |
| M1 | Task state behavior active | Pending | routing/verification test |
| M2 | Uncertainty/probe behavior active | Pending | probe loop test |
| M3 | Postcondition/semantic impact behavior active | Pending | verification selection test |
| M4 | Drift/budget/stop behavior active | Pending | stop reason and drift test |
| M5 | Memory/playbook/negative learning governed | Pending | memory quality and bounded learning tests |
| Z1 | Final no-split-brain proof | Pending | import-boundary and trace compatibility report |

## Execution Rules For Implementers

- Read this guide and the primary roadmap fully before editing.
- Rebuild the checklist from current source; do not trust stale failure lists.
- Implement in coherent slices.
- Add tests before or alongside contract-level behavior.
- Run targeted tests first, then broader gates.
- Do not weaken tests to make failures pass.
- Do not paper over environment blockers.
- Keep evidence deterministic and replayable.
- Keep end-user chat clean.
- Keep deep evidence optional and inspectable.
- Final response is allowed only after all feasible lanes are complete and every external blocker has exact evidence.

## Final Completion Report Shape

The final report for this leg must include:

- executive completion verdict
- changed files grouped by lane
- checklist status summary
- validation commands and pass/fail results
- evidence directory paths
- SDK/CLI/GUI/compositor/harness/hosted proof paths
- trace/replay/scorecard paths
- external blockers, if any
- exact end-state status

The expected final status is:

```text
Architectural Improvements Broad: Complete / Complete Plus
```

Anything less must say exactly which lanes remain incomplete and why.
