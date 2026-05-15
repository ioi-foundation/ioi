# Architectural Improvements Broad

Status: canonical roadmap for the next execution-surface leg
Date: 2026-05-01
Scope: IOI agent runtime, SDK, CLI, Autopilot, workflow compositor, hosted workers, Agentgres persistence, CIRC/CEC invariants, and developer/operator execution ergonomics

Implementation guide: [architectural-improvements-broad-master-guide.md](./architectural-improvements-broad-master-guide.md)

## Executive Truth

IOI has a stronger substrate than Cursor SDK or Claude Code, but it must also expose a competitive execution surface.

The architecture is broader by design: IOI L1 settles rights and trust, Agentgres remembers operational truth, Autopilot and the IOI daemon execute work, wallet.network authorizes power, Filecoin/CAS stores payloads, and marketplaces discover workers and sell outcomes. That substrate can exceed Cursor SDK and Claude Code because it treats autonomous work as stateful, authority-scoped, receipted, inspectable, and settleable.

The next leg is not to prove that the architecture is philosophically broader. The next leg is to make the execution surface feel as immediate and capable as Cursor SDK and Claude Code while preserving IOI's stronger authority, receipts, memory, and operational clarity.

Bottom line:

```text
Substrate: stronger.
Ontology: stronger if capability tiers are separated.
Local SDK facade: promising but not live enough.
Cloud/hosted/IDE/TUI/tool ergonomics: still behind.
Next target: competitive live execution surface over the unified substrate.
```

## Source Of Authority

This roadmap is grounded in:

- [docs/architecture/README.md](../architecture/README.md)
- [docs/architecture/_meta/vocabulary.md](../architecture/_meta/vocabulary.md)
- [docs/architecture/foundations/domain-kernels.md](../architecture/foundations/domain-kernels.md)
- [docs/architecture/components/agentgres/doctrine.md](../architecture/components/agentgres/doctrine.md)
- [docs/architecture/products/autopilot/local-app-workflow-canvas.md](../architecture/products/autopilot/local-app-workflow-canvas.md)
- [docs/architecture/components/daemon-runtime/doctrine.md](../architecture/components/daemon-runtime/doctrine.md)
- [docs/architecture/components/wallet-network/doctrine.md](../architecture/components/wallet-network/doctrine.md)
- [docs/architecture/components/model-router/doctrine.md](../architecture/components/model-router/doctrine.md)
- [docs/architecture/components/connectors-tools/doctrine.md](../architecture/components/connectors-tools/doctrine.md)
- [docs/architecture/domains/marketplace-neutrality.md](../architecture/domains/marketplace-neutrality.md)
- [docs/architecture/foundations/security-privacy-policy-invariants.md](../architecture/foundations/security-privacy-policy-invariants.md)
- [docs/implementation/runtime-package-boundaries.md](../implementation/runtime-package-boundaries.md)
- [docs/conformance/agentic-runtime/CIRC.md](../conformance/agentic-runtime/CIRC.md)
- [docs/conformance/agentic-runtime/CEC.md](../conformance/agentic-runtime/CEC.md)
- [docs/specs/runtime/cursor-sdk-harness-parity-plus-master-guide.md](../specs/runtime/cursor-sdk-harness-parity-plus-master-guide.md)

## Canonical Product Target

Build a better agent runtime that offers:

1. A simple installable SDK surface.
2. A polished local CLI/TUI execution surface.
3. A clean Autopilot GUI execution surface.
4. A workflow compositor over the same runtime substrate.
5. A hosted/self-hosted worker execution surface.
6. Live MCP, skills, hooks, tools, subagents, artifacts, and model routing.
7. Agentgres-backed state, receipts, quality, traces, replay, and memory.
8. Stronger smarter-agent behavior: task state, uncertainty, probes, postconditions, semantic impact, drift, budget, stop reasons, handoff quality, bounded learning, and verifier independence.
9. No split-brain runtime path.

The developer/operator should be able to:

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

That surface must call the real IOI runtime substrate, not a parallel SDK runtime.

## Architectural Clarification: Capability Tiers

There is a real architectural tension around the word `capability`.

CIRC correctly says capabilities must stay primitive and boundary-oriented. They must not encode domain operations such as `timer.create`, `math.eval`, or `gmail.send`.

The broader architecture also uses operation-scoped authority examples such as:

```text
cap:model.openai.chat
cap:gmail.read
cap:gmail.send
cap:calendar.create
cap:instacart.order_submit
```

These are not the same thing. IOI must explicitly separate them.

### Tier 1: Primitive Execution Capability

Use this for CIRC feasibility and primitive runtime boundaries.

Recommended namespace:

```text
prim:fs.read
prim:fs.write
prim:fs.patch
prim:sys.exec
prim:sys.env_read
prim:ui.interact
prim:net.request
prim:model.invoke
prim:secret.use_scoped
prim:artifact.write
prim:agent.delegate
```

Properties:

- generic
- provider-agnostic
- domain-neutral
- permission, isolation, or risk boundary oriented
- eligible for CIRC hard feasibility checks
- never a business operation
- never a connector-specific action

### Tier 2: Authority Scope / Scope Lease

Use this for wallet.network grants, connector permissions, account scopes, payment permissions, and operation-level external authority.

Recommended namespace:

```text
scope:gmail.read
scope:gmail.draft
scope:gmail.send
scope:calendar.create
scope:slack.post
scope:github.comment
scope:instacart.cart_create
scope:instacart.order_submit
scope:model.openai.chat
scope:model.anthropic.messages
```

Properties:

- operation-specific
- account/provider-aware
- issued, denied, revoked, or narrowed by wallet.network/policy
- tied to exact request hashes for sensitive actions
- affects provider admission and execution authority
- never affects semantic intent ranking
- produces authority receipts

### Tier 3: Tool Contract

Use this for concrete execution mechanisms.

Example:

```yaml
RuntimeToolContract:
  id: gmail.send
  provides_primitives:
    - prim:net.request
    - prim:secret.use_scoped
  requires_authority_scopes:
    - scope:gmail.send
  risk_domain: external_message
  effect_class: external_write
  approval_scope_fields:
    - recipient
    - subject
    - body_hash
  evidence_required:
    - send_receipt
```

### Required Invariant

```text
Intent resolution selects what the user wants.
PrimitiveExecutionCapability gates what kind of runtime boundary is needed.
AuthorityScope gates who is allowed to use which external/account power.
RuntimeToolContract binds concrete tools to primitives and scopes.
PolicyDecision grants or denies authority.
Receipt proves what happened.
```

Hard rule:

```text
Primitive capabilities may affect CIRC feasibility.
Authority scopes may affect policy/provider admission.
Tool contracts may affect executable availability.
None of them may alter semantic ranking.
```

### Migration Rule

Existing `cap:*` examples in architecture docs should be interpreted as authority scopes, not CIRC primitive capabilities.

Going forward:

- use `prim:*` for CIRC primitive execution capabilities
- use `scope:*` for wallet.network authority scopes
- use `tool:*` or stable tool IDs for concrete runtime tools
- use `intent:*` or canonical intent IDs for semantic actions
- reserve `capability` in prose only when the tier is unambiguous

This removes the contradiction without weakening either CIRC or the wallet/network authority model.

## Competitive Execution Surface Gap Analysis

### 1. Live SDK Execution

Current shape:

- `@ioi/agent-sdk` exists.
- It exposes `Agent`, `Run`, `Cursor`, `createRuntimeSubstrateClient`, structured messages, structured errors, traces, scorecards, artifacts, and smarter-agent projections.
- Local SDK runs are currently produced by a TypeScript local substrate client that synthesizes checkpointed events/traces.

Gap:

- The SDK facade is not yet the default live bridge into the Rust/Autopilot daemon runtime.

Risk:

- IOI appears SDK-competitive but does not yet prove live execution parity through the same runtime path.

Required target:

- Add a daemon-backed `RuntimeSubstrateClient`.
- Make live daemon execution the default when the local runtime is available.
- Keep synthetic/local fixture clients only for tests, offline examples, and explicit mock mode.
- Prove SDK events, traces, artifacts, receipts, task state, stop reasons, and scorecards come from real runtime execution.

Acceptance:

- SDK quickstart starts a real run through the daemon.
- `run.stream()` streams live runtime events.
- `run.wait()` waits on actual terminal state.
- `run.cancel()` cancels through runtime authority and preserves trace continuity.
- `run.trace()` exports the real session trace bundle.
- No SDK path imports GUI internals or bypasses runtime policy.

### 2. Cloud, Hosted, And Self-Hosted Execution

Current shape:

- Local mode exists.
- Hosted/cloud/self-hosted options exist as SDK shapes.
- Non-local modes fail closed when no provider endpoint is configured.

Gap:

- No competitive hosted/cloud worker execution surface equivalent to Cursor cloud agents.
- No developer-proof self-hosted worker transport.
- No remote repo clone, branch, PR, artifact, reconnect, or long-running worker proof.

Required target:

- `HostedWorkerProvider`
- `SelfHostedWorkerProvider`
- remote `RunRequest` transport
- repo checkout and workspace capsule receipts
- branch/PR artifact receipts where applicable
- reconnect by event cursor
- fail-closed provider configuration
- hosted and self-hosted smoke tests

Acceptance:

- A developer can point the SDK at a hosted/self-hosted worker endpoint.
- A run can survive client disconnect.
- Event replay/tail works across reconnect.
- Repository checkout and mutation receipts exist.
- Cloud blockers are precise when provider secrets or endpoints are missing.

### 3. Public Event Streaming And Reconnect

Current shape:

- Local event cursor replay exists in the SDK facade.
- CLI can inspect events/traces from substrate snapshots.

Gap:

- No public SSE/WebSocket event endpoint with `Last-Event-ID` semantics.
- No live event tailing server/client proof across CLI, SDK, GUI, hosted workers, and replay.

Required target:

- `/v1/runs/{id}/events`
- replay, tail, and replay-and-tail modes
- monotonic event cursors
- exactly one terminal event
- reconnect without duplicate terminal events
- redacted event projection for public clients

Acceptance:

- SDK reconnect tests simulate network drop.
- CLI and SDK read the same event stream.
- GUI transcript projection matches backend event stream.
- replay/export verifies event integrity.

### 4. MCP, Skills, Hooks, And Connectors

Current shape:

- IOI has stronger containment and policy concepts.
- SDK can summarize `.cursor/mcp.json`, `.cursor/skills/`, and `.cursor/hooks.json` names.
- Runtime contains MCP and connector-related modules.

Gap:

- SDK `.cursor` compatibility is not yet live governed execution.
- Hooks are not yet a full observe/control runtime extension surface.
- Skills do not yet visibly enter the governed prompt layer through SDK paths.
- MCP is not yet demonstrated as inline/file imported, contained, receipted, and executable through SDK.

Required target:

- inline `mcpServers`
- `.cursor/mcp.json` importer
- `.cursor/skills/` importer
- `.cursor/hooks.json` importer
- connector and MCP tool admission via `RuntimeToolContract`
- production containment receipts
- prompt-layer provenance for skills
- hook lifecycle mapped to operator collaboration, policy hooks, event subscribers, and receipts

Acceptance:

- Development profile may be permissive only when explicitly configured.
- Production profile requires allowlist, integrity, containment, and receipts.
- Skills enter `SkillInstruction` prompt layer with provenance.
- Hooks cannot bypass policy or mutate canonical truth directly.
- MCP tool calls produce tool receipts and containment evidence.

### 5. Subagents And Delegation

Current shape:

- IOI has handoff quality, worker templates, delegation concepts, and substrate records.
- SDK exposes `agent.handoff()`.

Gap:

- No competitive `agents` map that spins real subagents through SDK execution.
- No developer-simple subagent lifecycle comparable to Cursor/Claude execution ergonomics.

Required target:

- SDK `agents` map
- subagent definitions as worker templates
- spawn, stream, wait, cancel, merge, handoff
- disjoint write ownership where applicable
- handoff quality scoring
- merge receipts

Acceptance:

- SDK user can delegate a subtask to a named subagent.
- Parent and child runs share substrate contracts.
- Handoff bundle preserves objective, state, blockers, evidence, and next action.
- Merge is governed and receipt-backed.

### 6. CLI/TUI Operator Ergonomics

Current shape:

- IOI CLI has serious substrate operations: run, chat, resume, pause, cancel, approve, deny, contract, tools, config, policy, doctor, status, events, trace, verify, replay, export.

Gap:

- The CLI feels more like an admin/debug substrate than a polished coding-agent execution surface.
- Claude Code exposes a richer interactive command surface: memory, skills, MCP, hooks, review, diff, IDE, tasks, cost, context, theme, vim, model, status, resume, share/export, and more.

Required target:

- Human TUI for runs, events, approvals, tool calls, tasks, plans, diffs, memory, receipts, artifacts, and subagents.
- Slash-command style operator layer for common coding-agent workflows.
- Compact statusline, cost/budget view, model selection, MCP/skills/hooks management, and task list.
- Better defaults for local coding workflows.

Acceptance:

- A developer can use IOI from terminal with minimal ceremony.
- Approvals, diffs, plans, tasks, and traces are visible without raw JSON.
- TUI remains backed by the same runtime substrate.
- No CLI-only execution bypass exists.

### 7. Tool Execution Ergonomics

Current shape:

- IOI has runtime tool contracts and many tool modules.
- Tool safety metadata is stronger than competing surfaces.

Gap:

- Public SDK/CLI tool execution is less immediate than Claude Code's direct Bash/read/edit/write/grep/glob/web/MCP/task surfaces.

Required target:

- First-class SDK tool-call types generated from `RuntimeToolContract`.
- Direct but governed file read/edit/write/patch/search APIs where appropriate.
- Shell job control with deadlines, cancellation, receipts, and sandbox profile.
- Notebook, LSP, browser, web, MCP, and artifact tool surfaces.
- Tool discovery that is registry-backed, not prompt-hacked.

Acceptance:

- Tool calls are discoverable, typed, permissioned, and easy to use.
- Effectful tools require policy/authority.
- Tool outputs validate against declared schemas.
- Tool quality feeds routing.

### 8. Model, Repository, Account, And Runtime Catalogs

Current shape:

- SDK exposes a model and repository list.
- These are currently local/simple projections.
- Model routing substrate exists in broader runtime architecture.

Gap:

- Not yet a real model/account/repository/runtime catalog surface comparable to Cursor.

Required target:

- `Cursor.models.list` equivalent backed by runtime model registry.
- repository catalog backed by local git, connected providers, or hosted account APIs.
- account/operator profile with authority level and privacy class.
- runtime node catalog: local, hosted, self-hosted, TEE, DePIN.
- model quality/cost/latency/privacy metadata.

Acceptance:

- Catalogs are live, policy-aware, and receipt-backed where consequential.
- Private tasks do not route to disallowed external providers.
- BYOK credentials remain in wallet.network.

### 9. Agentgres-Backed Persistence

Current shape:

- Agentgres architecture owns runs, tasks, receipts, artifacts, quality ledgers, projections, and operational truth.
- SDK local facade persists JSON checkpoints.

Gap:

- SDK and local execution do not yet prove Agentgres-backed canonical run state.

Required target:

- Agentgres v0-backed run/task/artifact/receipt state.
- local-first read path with projection freshness and source watermark.
- checkpoint/export/replay backed by canonical operation log and artifact refs.
- migration away from SDK-only JSON as authoritative local state.

Acceptance:

- Runs settle through Agentgres-compatible state.
- JSON checkpoints, if retained, are cache/export artifacts, not canonical truth.
- Agentgres records quality, contribution, receipts, and projection state.

### 10. Live Autopilot GUI Validation

Current shape:

- Clean chat UX contract exists.
- Retained query harness exists.
- Prior evidence records indicate GUI validation can be environment-blocked.

Gap:

- Live GUI proof is not consistently available as end-to-end validation.

Required target:

- deterministic GUI retained-query validation
- no accidental settings/activity-bar clicks
- transcript/backend trace agreement
- Markdown and Mermaid rendering
- compact source chips for search/browse
- collapsed explored-files disclosure for local grounding
- collapsed useful thoughts/work summaries
- no raw receipt dumps or crude evidence drawers

Acceptance:

- Every retained query produces screenshot, transcript, trace, receipts, scorecard, and UX assertions.
- GUI visible answer matches backend evidence.
- Failures identify whether the issue is runtime, projection, renderer, or automation.

## Smarter-Agent Execution Requirements

The execution surface must not merely expose more knobs. It must prove better agent behavior.

Every live run should be able to project, when relevant:

- task/world state
- known facts
- uncertain facts
- assumptions
- constraints
- blockers
- evidence refs
- stale facts
- uncertainty assessment
- value-of-information decision
- probe history
- postcondition synthesis
- semantic impact analysis
- capability discovery, selection, sequencing, and retirement
- model routing and cognitive budget
- drift detection
- stop condition
- dry-run safety
- handoff quality
- verifier independence
- memory quality gate
- operator preference
- playbooks
- negative learning
- bounded self-improvement gate
- quality ledger

These records must be behaviorally active, not decorative trace fields.

## UX Doctrine

End-user chat must stay clean.

Default chat should show:

- answer-first Markdown
- clean code blocks
- clean Mermaid
- compact source chips only for search/browse retrieval
- collapsed "Explored N files" for local file grounding
- collapsed thinking/work summary when useful
- clear approvals and refusal messages

Default chat must not show:

- raw receipt dumps
- crude evidence drawers
- default facts dashboards
- full trace JSON
- noisy runtime ledger details
- scattered file path source spam

Deep evidence belongs in:

- workbench
- trace export
- replay bundle
- scorecard
- dashboard
- receipt/artifact inspector
- diagnostic bundle

## Phased Roadmap

### P0: Capability-Tier Cleanup

Deliver:

- spec update distinguishing `PrimitiveExecutionCapability` from `AuthorityScope`
- namespace convention: `prim:*` and `scope:*`
- tool contract fields: `provides_primitives`, `requires_authority_scopes`
- migration note for existing `cap:*` examples
- lint preventing domain operations from becoming CIRC primitives
- tests proving scopes do not affect semantic ranking

### P1: Live SDK To Runtime Daemon

Deliver:

- daemon-backed `RuntimeSubstrateClient`
- live local run creation
- live event stream
- live cancel/resume
- live artifact and trace export
- fallback explicit mock mode for tests only

### P2: Event Streaming, Replay, And Checkpointing

Deliver:

- public run event API
- SSE/WebSocket transport
- replay/tail/replay-and-tail
- monotonic cursors
- no duplicate terminal events
- crash-resume checkpoint abstraction

### P3: Tool, MCP, Skills, Hooks, And Subagents

Deliver:

- governed `.cursor` importers
- inline MCP server execution
- skills into prompt layers
- hook event lifecycle
- SDK subagent map
- typed tool exports
- tool quality feedback loop

### P4: Agentgres Runtime State

Deliver:

- Agentgres v0 for runs/tasks/artifacts/receipts/quality
- local-first projection read path
- canonical operation log
- trace/replay from state substrate
- SDK/CLI/GUI all reading compatible state

### P5: CLI/TUI Competitive Surface

Deliver:

- interactive TUI
- slash-command-like command set
- plans, tasks, diffs, approvals, memory, skills, MCP, hooks, model, cost/budget
- artifact and receipt inspection
- polished local coding-agent workflow

### P6: Hosted And Self-Hosted Workers

Deliver:

- hosted worker provider
- self-hosted worker provider
- repo clone/branch/PR receipts
- reconnect after disconnect
- provider health and runtime manifest
- fail-closed blocker records

### P7: GUI And Workflow Compositor Proof

Deliver:

- retained-query GUI validation
- compositor dogfooding over same substrate
- harness-as-workflow live proof
- no split-brain workflow path
- clean chat UX retained

## Non-Negotiables

1. Do not create a separate SDK, GUI, workflow, benchmark, or hosted runtime.
2. Do not bypass authority, policy, receipts, trace export, replay, or quality ledgers.
3. Do not weaken CIRC/CEC invariants.
4. Do not add lexical prompt hacks, benchmark branches, workflow-name bypasses, or fixture leaks.
5. Do not let tool availability or provider names alter semantic ranking.
6. Do not let authority scopes masquerade as primitive execution capabilities.
7. Do not trust raw URLs, raw model output, exit status, or final chat text as primary evidence.
8. Do not expose raw receipts by default in chat.
9. Do not make the default harness cannibalize marketplace workers.
10. Do not claim superiority without live SDK/CLI/GUI/harness/compositor proof.

## Validation Matrix

| Lane | Required Proof |
| --- | --- |
| Capability tiers | `prim:*` vs `scope:*` tests, ontology lint, semantic ranking independence |
| SDK live run | create/send/stream/wait/cancel/trace against real daemon |
| Event stream | monotonic cursors, reconnect, no duplicate terminal events |
| Tool execution | read/write/shell/search/web/MCP tools through contracts and receipts |
| MCP | inline and `.cursor/mcp.json` governed execution |
| Skills | `.cursor/skills/` imports into `SkillInstruction` layer |
| Hooks | `.cursor/hooks.json` observes/controls events without policy bypass |
| Subagents | SDK `agents` map, child run, handoff, merge receipts |
| Model routing | live model catalog, policy-aware fallback, receipts |
| Repositories | live local and provider-backed repo catalog |
| Agentgres | canonical run/task/artifact/receipt/quality state |
| CLI/TUI | human operator flow for coding-agent work |
| GUI | retained-query screenshots, transcript/evidence agreement |
| Workflow compositor | harness-as-workflow over same substrate |
| Hosted/self-hosted | remote run, reconnect, artifact, failure blocker evidence |
| Smarter-agent | task state, uncertainty, probes, postconditions, semantic impact, stop condition, quality ledger behaviorally active |

## Completion Definition

This leg is complete when:

1. `@ioi/agent-sdk` defaults to live runtime execution when available.
2. Local mock/synthetic SDK execution is explicit and test-only.
3. CLI, SDK, GUI, harness, benchmarks, workflow compositor, and hosted/self-hosted workers all use the same runtime substrate contracts.
4. CIRC primitive capabilities and wallet authority scopes are separated in docs, types, tool contracts, and tests.
5. MCP, skills, hooks, tools, subagents, model routing, artifacts, traces, replay, and scorecards are live through the public execution surface.
6. Agentgres-backed runtime state replaces local JSON as canonical truth for serious runs.
7. Clean chat UX remains intact.
8. Live validation proves IOI is not only broader than Cursor SDK and Claude Code, but competitively usable at the execution layer.

## Open Facets For Subsequent Refinement

The following facets may be adjusted by future questions without changing the central truth of this roadmap:

- exact namespace names for `prim:*` and `scope:*`
- whether external adapters still need explicit one-way migrations from older
  `cap:*` labels into `scope:*`
- SDK default behavior when daemon is unavailable
- how much Cursor compatibility remains public versus adapter-only
- how aggressively the CLI mimics slash-command ergonomics
- hosted/self-hosted provider priority
- Agentgres v0 migration order
- GUI evidence/dashboard placement

The central truth should not change:

```text
IOI wins only when the stronger substrate is exposed through a competitive live execution surface.
```
