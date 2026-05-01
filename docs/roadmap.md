# IOI Product And Runtime Roadmap

Last updated: 2026-04-29
Status: synthesized from `docs/roadmap_context.md` plus a repo architecture probe

## Executive Thesis

IOI should ship the digital-worker category by turning its existing workflow,
runtime, wallet, memory, and marketplace pieces into one staged product path:

```text
product-grade workflow builder
-> componentized harness
-> typed model/tool/connector registries
-> wallet-backed capability authority
-> persistent worker roster
-> worker API and inter-agent protocol
-> Agentgres-backed canonical state
-> aiagent.xyz and sas.xyz marketplaces
```

The immediate wedge is not "build Agentgres first" and not "build My Agents as
chatbots." The immediate wedge is:

> Make Autopilot Workflows the reliable construction and execution language for
> bounded agent work, then promote stable workflows into persistent workers.

The long-term doctrine remains:

> Models expose completions. Workers expose responsibilities.

And the system boundary should stay crisp:

```text
Autopilot runs workers and workflows.
wallet.network authorizes capabilities and secrets.
ioi-memory retains local product memory, checkpoints, and evidence blobs.
Agentgres settles canonical state changes and queryable projections.
sas.xyz productizes repeatable worker services.
aiagent.xyz discovers, compares, installs, or procures worker services.
ioi.ai is the hosted intent/use surface.
Forge instantiates sovereign domains.
```

## Current Architecture Read

The repo is farther along on workflow and runtime substrate than a greenfield
roadmap would assume.

| Facet | Current status | Roadmap implication |
| --- | --- | --- |
| Workflow canvas | `agent-ide` has typed node definitions for source, trigger, function, model binding, model call, parser, adapter, plugin tool, state, decision, loop, barrier, subgraph, human gate, output, tests, and proposals. | Treat workflow canvas as v1 hardening and productization, not as a fresh build. |
| Workflow validation | TypeScript and Rust validators check bindings, schemas, connection classes, approval gates, subgraphs, mock bindings, activation readiness, and policy issues. | Next work should close parity gaps: node detail UX, pinned fixtures, replay, activation checklist, and live runtime behavior. |
| Workflow runtime | Local graph execution, model binding resolution, caching, timeouts, governance tiers, and node execution are present. Some workflow node kinds still fall through or remain partially simulated. | Prioritize runtime parity for visible nodes and remove "looks runnable but skips" behavior. |
| Workflow projects | Git-backed project bundles, tests, proposals, checkpoints, runs, binding manifests, packages, imports, and evidence APIs exist in Autopilot Tauri commands. | The package/proposal substrate can become the promotion path into worker packages. |
| Agent runtime | `RuntimeAgentService` owns session lifecycle, step/resume, pending action state, approvals, PII, execution queue, transcript continuity, worker templates, and playbooks. | Componentize the harness around explicit workflow-compatible primitives before making persistent agents rich. |
| My Agents | Current dashboard is a thin live catalog over playbooks/templates. It is not yet a durable employee roster with schedules, standing orders, inbox, memory, receipts, and tool grants. | Build minimal persistent agent state before expanding the GUI. |
| Model runtime | Local Engine registry state, model binding preflight, local GPU dev profiles, and model record surfaces exist. Full model router, BYOK key brokerage, policy routing, and run-to-idle lifecycle are not complete. | Build a real Model Registry/Router after workflow execution contracts are stable enough to consume it. |
| Connectors | Mail and Google Workspace connector surfaces exist with wallet-backed auth, policy memory, actions, and subscriptions. General workflow connector/tool registry is still early and many live side effects are gated or unavailable. | Make connectors typed, permissioned, and receipted before adding high-risk commerce connectors. |
| wallet.network | Chain-service primitives exist for identities, session grants, approval authorities, approvals, revocation epochs, connector auth, secret injection, leases, replay windows, and audit events. | Build wallet-core-lite into Autopilot as the capability and BYOK authority before persistent workers can act safely. |
| Memory and state | `ioi-memory` is the product memory layer for transcripts, checkpoints, archival memory, artifacts, and enrichment jobs. Agentgres is currently a strong spec, not the live canonical application-state fabric. | Agentgres v0 should start by replacing Autopilot workflow/agent/run canonical state, not by replacing every database concept. |
| Markets | `sas.xyz` and `aiagent.xyz` specs and prototype surfaces exist, but portable worker packaging and runtime-backed marketplace installation are not yet mature. | Defer marketplace scale until worker manifests, install flow, API surface, receipts, and wallet grants are real. |

## Roadmap Correction

The provided context has the right strategic order, but the architecture probe
changes the wording:

```text
Before:
  Workflow Canvas -> Harness Componentization -> ...

After:
  Workflow Canvas v1 hardening -> Workflow runtime parity -> Harness-as-Workflow -> ...
```

The canvas already has the bones. The priority is now to make it operationally
trustworthy and product-grade.

## Phase 0: Workflow Canvas V1 Hardening

Goal: make Autopilot Workflows a professional, n8n-class builder with IOI's
stronger policy, testing, proposal, and output model.

Build:

- graph-aware warnings instead of global warnings that fire before relevant nodes exist
- understandable right rail with labels, tooltips, empty states, and panel context
- operational empty canvas with Add node, source/trigger affordances, and drop targets
- node-specific configuration modals for every node kind
- pinned fixtures and sample data for node replay
- per-node input/output panes, schema validation, dry-run output, and fixture diff
- activation readiness checklist: triggers, live credentials, tests, mocks, policy gates, expected value, MCP review
- execution timeline with node IO, retry/error paths, checkpoints, interrupts, and sub-run lineage
- strict block for unsupported or partially implemented runtime nodes

Exit criteria:

- A user can create, validate, run, debug, and package a non-trivial workflow from primitive nodes without dogfood-only affordances.
- Every visible primitive has a typed config surface and an honest runtime status.
- Mock/sandbox/live state is obvious at the node, workflow, and activation levels.

## Phase 1: Workflow Runtime Parity

Goal: align the visible canvas ontology with the Tauri/Rust runtime so workflow
execution is not merely present but dependable.

Build:

- shared node execution contract across TypeScript registry, Rust validation, Rust execution, tests, and harness tools
- concrete runtime behavior for trigger, parser, adapter, plugin tool, state, loop, barrier, subgraph, human gate, output, test assertion, and proposal nodes
- workflow tool binding backed by subgraph execution, including argument schema, result schema, timeout, retry, and child run lineage
- resumable human-gated tool calls with approve, reject, edit, and resume from checkpoint
- output materialization and delivery targets with policy gates
- runtime event schema that can support future receipts and Agentgres patch records

Exit criteria:

- If the UI lets a user place a node, runtime validation can explain exactly how it runs or why it is blocked.
- Subgraphs can be called as tools by model or agent nodes.
- Approval gates interrupt and resume the same run rather than acting only as static validation warnings.

## Phase 2: Harness Componentization

Goal: expose the agent harness as reusable primitives that can be represented,
tested, and eventually edited as workflows.

Componentize:

- planner
- model router call
- tool router call
- connector call
- policy/firewall gate
- wallet capability request
- memory read/write
- verifier
- artifact/output writer
- receipt writer
- retry policy
- repair loop
- merge/judge
- completion gate

Each component needs:

- input schema
- output schema
- error schema
- timeout and cancellation behavior
- retry behavior
- required capability scope
- approval semantics
- emitted events/evidence
- UI representation

Exit criteria:

- Core harness steps can be described as workflow-compatible action frames.
- Runtime tests can target components without driving the whole chat/session path.
- The default harness can be rendered as a read-only graph.

## Phase 3: Harness-as-Workflow

Goal: make the default agent harness a blessed workflow template that advanced
users can inspect first and fork later.

Build:

- read-only "Default Agent Harness" graph view
- editable fork path gated behind validation
- model, tool, verifier, approval, and output policy slots
- workflow-level model policy
- workflow-level tool grant policy
- node-level logs and replay
- proposal-only self-mutation for AI-authored workflow edits

Exit criteria:

- A persistent worker can point to a harness workflow by id.
- A user can inspect why the harness made a planning, routing, approval, or verification decision.
- Forking the harness creates a packageable workflow with tests and activation gates.

## Phase 4: Registry Layer

Goal: make models, tools, connectors, and capabilities routable through typed
registries instead of hardcoded provider paths.

### Model Registry And Router

Support:

- OpenAI-compatible endpoints
- OpenAI, Anthropic, Gemini, and custom HTTP providers
- LM Studio, Ollama, vLLM, llama.cpp, and local OpenAI-compatible endpoints
- embeddings, rerankers, vision, speech, image, video, and code models
- BYOK provider accounts
- model health checks
- model capability metadata
- privacy, cost, latency, locality, context length, tool-use, and structured-output flags

Objects:

```text
ModelProvider
ModelEndpoint
ModelCapability
ModelPolicy
ModelRoute
ModelInvocation
ModelReceipt
ComputeProvider
ComputeLease
ModelWarmPool
```

### Connector And Tool Registry

Support:

- typed tool name
- input schema
- output schema
- risk class
- auth scopes
- credential readiness
- approval requirement
- rate limits
- idempotency key
- receipt behavior
- workflow availability
- agent availability
- marketplace exposure eligibility

### wallet-core-lite

Build the Autopilot-facing slice of wallet.network:

- local encrypted secret store
- model provider key vault
- connector credential vault
- capability request API
- short-lived session grants
- approval tokens
- revocation
- audit receipt
- step-up hooks

Exit criteria:

- Workflow nodes call "model capability" or "tool capability," not provider-specific branches.
- BYOK keys and connector secrets are brokered through wallet.network-shaped authority.
- Live connector and model actions have explicit grant, policy, and receipt metadata.

## Phase 5: Early Connector Expansion

Goal: prove Autopilot can operate real production software safely without
jumping straight to money-moving commerce.

Build first:

- filesystem and Git read/write with proposal-first mutation
- browser/computer-use hardening
- local shell/sandbox hardening
- Blender connector
- FreeCAD/CAD connector
- read-only Google Workspace and mail improvements
- draft-only email/calendar/doc outputs

Defer until later:

- Instacart order submission
- travel booking
- invoice payment
- funds transfer
- high-risk external publication

Connector risk tiers:

| Tier | Examples | Approval posture |
| --- | --- | --- |
| 1: safe read/local output | file read, Git read, browser inspect, Blender render/export, FreeCAD export, read-only Drive/Gmail/Calendar | Usually no approval. |
| 2: reversible local write/draft | file write, Git patch proposal, Blender scene edit, CAD edit, email draft, cart draft | Preview plus confirmation. |
| 3: external communication | send email, post Slack, GitHub issue/comment, calendar invite | Usually approval required. |
| 4: commerce/irreversible | submit grocery order, book travel, pay invoice, transfer funds | Mandatory approval, budget, and receipts. |

Exit criteria:

- Blender/CAD workflows can generate, preview, validate, and export outputs through typed tools.
- External communication remains draft-first unless wallet approval is explicitly present.
- Commerce tools cannot execute without one-shot approval and receipt binding.

## Phase 6: Minimal Persistent Workers And My Agents

Goal: make agents persistent workers, not chat personas.

Introduce an Agentgres-shaped state model before building a rich GUI:

```text
AgentDefinition
AgentInstall
AgentRun
AgentMemoryRef
AgentToolGrant
AgentModelPolicy
AgentSchedule
AgentInboxItem
AgentStandingOrder
AgentOutput
AgentReceipt
```

Build My Agents around:

- installed worker roster
- worker detail page
- role and responsibility
- harness workflow
- model policy
- tool grants and connector permissions
- schedules and standing orders
- inbox/escalations
- recent runs
- memory/context references
- outputs
- receipts

Exit criteria:

- A worker can be installed, granted tools, scheduled, run, paused, inspected, and revoked.
- The roster answers "who works for me, what can they do, what are they doing, and what proof did they leave?"
- No persistent worker relies on ambient secrets or unbounded app-local authority.

## Phase 7: Agent Office And Project Rooms

Goal: give long-running workers a coordination space for objectives, decisions,
plans, risks, and spawned bounded runs.

Objects:

```text
ProjectRoom
Mission
Objective
Decision
Plan
PlanRevision
StandingOrder
StatusUpdate
Risk
Blocker
TaskRequest
RunSpawn
Digest
ExternalSignal
```

Distinctions:

```text
My Agents = who exists
Agent Office / Project Room = what workers own over time
Run Room = bounded task execution
Workflow Canvas = how work is orchestrated
```

Exit criteria:

- A worker can own a recurring responsibility and emit digests, task requests, risks, and decisions over time.
- Project state is not stored in Slack, GitHub, Gmail, or chat transcripts as authority. Those are signals and adapters.

## Phase 8: Worker API And Inter-Agent Protocol

Goal: expose workers as responsibility-bearing services, while retaining model
compatibility for adoption.

Minimum public API:

```http
GET  /.well-known/ai-agent.json
POST /v1/agent/tasks
GET  /v1/agent/tasks/{id}
GET  /v1/agent/tasks/{id}/events
GET  /v1/agent/tasks/{id}/outputs
GET  /v1/agent/tasks/{id}/receipts

GET  /v1/worker/profile
GET  /v1/worker/status
GET  /v1/worker/objectives
POST /v1/worker/objectives
GET  /v1/worker/standing-orders
POST /v1/worker/standing-orders
GET  /v1/worker/inbox
GET  /v1/worker/runs

POST /v1/interagent/message
POST /v1/interagent/task-offer
POST /v1/interagent/task-accept
POST /v1/interagent/handoff
POST /v1/interagent/capability-query
POST /v1/interagent/evidence-request

GET  /v1/outputs/{id}
GET  /v1/receipts/{id}

POST /v1/chat/completions
POST /v1/responses
POST /v1/embeddings
```

Compatibility endpoints are adapters. The real worker value lives in task,
worker, inter-agent, output, and receipt endpoints.

Exit criteria:

- A buyer or another worker can offer a task, negotiate capabilities, hand off context, receive events, and inspect outputs/receipts.
- OpenAI-compatible endpoints exist without reducing workers to stateless chatbots.

## Phase 9: Agentgres V0

Goal: make Autopilot's own workflow, worker, run, project, decision, output, and
receipt state canonical through Agentgres before expanding Agentgres outward.

Start with:

```text
Agent definitions
Agent installs
Workflow bundles
Workflow runs
Standing orders
Project rooms
Tasks
Decisions
Outputs
Receipts
Patch/change records
Tool grants
Schedules
Inbox items
```

Lifecycle:

```text
Intent -> Scope -> Patch -> Validate -> Merge -> Settle -> Project -> Query -> Retain
```

Boundary:

- `ioi-memory` remains product memory for transcripts, checkpoints, archival recall, local evidence blobs, and enrichment jobs.
- wallet.network remains the authority for secrets, approvals, grants, leases, and revocation.
- Agentgres owns canonical application state, patches, relations, projections, receipts, and settled truth.

Exit criteria:

- Autopilot dogfoods Agentgres for its own worker/workflow/run state.
- Consequential agent state changes are proposed as patches before becoming truth.
- Local-first UI reads from verified projections and wakes authority only when needed.

## Phase 10: aiagent.xyz And sas.xyz

Goal: turn stable workers and workflows into portable market objects.

### sas.xyz

sas.xyz is the provider OS for productizing repeatable worker delivery.

Package includes:

- manifest
- service contract
- worker definition
- harness workflow
- connector/tool requirements
- model policy
- wallet grant requirements
- standing order templates
- memory schema
- output schema
- receipt policy
- deployment profiles
- billing policy
- tenant controls

### aiagent.xyz

aiagent.xyz is the discovery and procurement layer.

It should support two distinct loops:

- productized worker services: browse, compare, buy, install, run, or call
- bespoke procurement: post need, receive proposals, contract provider, deliver outcome

Exit criteria:

- A worker package can be published by a provider, discovered by a buyer, installed into Autopilot, granted bounded authority through wallet.network, and run with outputs/receipts.
- aiagent.xyz routes demand. sas.xyz owns provider productization and operations.

## Phase 11: Hosted, Hybrid, And Compute Marketplace Runtime

Goal: support local, hosted, and hybrid digital workers without changing the
worker contract.

Deployment modes:

| Mode | Shape | Best for |
| --- | --- | --- |
| Local | Autopilot Desktop/CLI + local kernel + local memory/tools/models | private files, code, browser, offline-first workflows |
| Hosted | worker package + hosted IOI runtime + Agentgres + sandbox + connectors | always-on services, monitoring, customer ops, research workers |
| Hybrid | local private execution + hosted coordination/schedules/receipts | enterprise privacy, local models, shared project state |

Compute evolution:

```text
foundational APIs
-> BYOK
-> local model mounting
-> run-to-idle local/server model lifecycle
-> hosted open-model pools
-> ComputeProvider adapters
-> decentralized/cloud GPU marketplace
```

Exit criteria:

- Autopilot does not care whether a model is OpenAI, local LM Studio, tenant BYOK, vLLM on a sleeping GPU, or a decentralized provider. It calls a model capability through policy.
- Decentralized compute is an adapter behind the router, not the early core.

## Near-Term Execution Plan

### Sprint 1: Workflow Product Hardening

Deliver:

- graph-aware warnings
- right rail labels/tooltips/empty states
- operational empty canvas
- node-specific config pass for visible primitives
- hidden dogfood/test-only affordances
- per-node validation actions

### Sprint 2: Runtime Parity And Fixtures

Deliver:

- pinned fixtures and node replay
- per-node IO panes
- workflow tool/subgraph binding
- activation readiness panel
- stricter unsupported-node blocking
- run timeline improvements

### Sprint 3: Harness Components

Deliver:

- component inventory and schemas
- read-only default harness graph
- model/tool/policy/verifier/output components
- proposal-only harness fork path
- seam-level tests for core components

### Sprint 4: Registries And wallet-core-lite

Deliver:

- model registry/router MVP
- BYOK key references through wallet-core-lite
- connector/tool registry schema
- credential readiness and approval receipt binding
- local OpenAI-compatible endpoint mount

### Sprint 5: Minimal Persistent Workers

Deliver:

- AgentDefinition and AgentInstall
- basic My Agents roster/detail
- harness workflow binding
- tool grants
- schedule/standing-order skeleton
- run history
- inbox/escalation skeleton

## Things To Avoid

- Do not build My Agents as a list of chat personas.
- Do not expose only `/v1/chat/completions` and call it a worker API.
- Do not make Slack, Gmail, GitHub, or connector stores canonical project state.
- Do not build full universal Agentgres before product surfaces generate real state pressure.
- Do not delay all Agentgres-shaped state until after persistent workers are already built on ad hoc tables.
- Do not add high-risk commerce connectors before wallet approval, budget, policy, and receipt infrastructure is dependable.
- Do not make decentralized GPU/resource marketplaces the early model story. Build the router and provider interface first.

## Dependency Graph

```text
Workflow Canvas V1
  -> Workflow Runtime Parity
  -> Harness Componentization
  -> Harness-as-Workflow

Harness-as-Workflow
  -> Model Registry / Router
  -> Connector / Tool Registry
  -> wallet-core-lite capabilities

Registries + wallet-core-lite
  -> safe live connectors
  -> BYOK
  -> local model mounting
  -> Minimal Persistent Workers

Minimal Persistent Workers
  -> My Agents
  -> Agent Office / Project Rooms
  -> Worker API

Worker API + persistent state pressure
  -> Agentgres v0
  -> aiagent.xyz portable worker packages
  -> sas.xyz outcome/service packaging

Model router + wallet + Agentgres receipts
  -> hosted/hybrid workers
  -> run-to-idle model pools
  -> ComputeProvider marketplaces
```

## Final North Star

IOI wins if a worker can be authored as a workflow, run under Autopilot,
authorized by wallet.network, remembered and settled by Agentgres, packaged by
sas.xyz, discovered through aiagent.xyz, and invoked by another worker or user
through responsibility-bearing APIs.

The product path is therefore:

```text
Canvas that can run
-> Harness users can inspect
-> Registries users can trust
-> Workers users can delegate to
-> State users can audit
-> Markets users can buy from
```

## Architecture Probe Sources

Primary implementation surfaces checked while synthesizing this roadmap:

- `packages/agent-ide/src/runtime/workflow-node-registry.ts`
- `packages/agent-ide/src/runtime/workflow-validation.ts`
- `packages/agent-ide/src/WorkflowComposer.tsx`
- `packages/agent-ide/src/runtime/workflow-harness-tools.ts`
- `apps/autopilot/src-tauri/src/project/`
- `apps/autopilot/src-tauri/src/orchestrator/graph_runner.rs`
- `apps/autopilot/src-tauri/src/execution.rs`
- `apps/autopilot/src-tauri/src/runtime_projection.rs`
- `crates/services/src/agentic/runtime/`
- `crates/services/src/wallet_network/`
- `crates/memory/src/lib.rs`
- `docs/architecture/state/agentgres-state-substrate.md`
- `docs/architecture/marketplaces/aiagent-xyz-worker-marketplace.md`
- `docs/architecture/marketplaces/sas-xyz-service-marketplace.md`
- `docs/audits/workflow-gui-product-audit.md`
- `docs/audits/workflow-node-ontology-audit.md`
- `docs/audits/n8n-parity-workflow-orchestrator-audit.md`
