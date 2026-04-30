Yes — if **aiagent.xyz** sells **portable persistent digital workers** rather than ephemeral chatbots, then the endpoint surface should be **more than a model-mounting endpoint**.

A model endpoint like LM Studio/OpenAI-compatible `/v1/chat/completions` is useful, but it is too low-level. It exposes a model. It does not expose a worker.

A persistent digital worker needs identity, memory, tools, state, policies, receipts, schedules, tasks, inboxes, artifacts, and inter-agent coordination.

So the right answer is:

> **Expose both: model-compatible endpoints for interoperability, and a higher-level inter-agent / worker API for actual digital employee behavior.**

---

# 1. The key distinction

## Model endpoint

A model endpoint answers:

> “Given this prompt, produce tokens.”

Example:

```http
POST /v1/chat/completions
```

Useful for:

* LM Studio compatibility
* OpenAI SDK compatibility
* local model mounting
* simple chat clients
* fallback inference
* benchmarking
* tool wrappers

But insufficient for:

* persistent workers
* recurring duties
* project ownership
* task spawning
* memory
* agent-to-agent handoff
* receipts
* policy-bound tool use
* durable state
* marketplace execution guarantees

## Worker endpoint

A worker endpoint answers:

> “Given this objective or task, can this agent accept responsibility, operate over time, use tools, coordinate, retain state, and produce verified outputs?”

That is what aiagent.xyz should sell.

A digital worker is closer to:

```text
identity
+ capabilities
+ standing orders
+ memory
+ tools
+ policies
+ schedules
+ workspace
+ inbox
+ receipts
+ artifacts
+ settlement
```

not just a model behind an HTTP endpoint.

---

# 2. Recommended endpoint layers

aiagent.xyz agents should expose a **multi-surface interface**.

```text
L0. Discovery / manifest endpoint
L1. Model-compatible inference endpoint
L2. Agent task endpoint
L3. Persistent worker endpoint
L4. Inter-agent protocol endpoint
L5. Artifact / receipt / state endpoint
L6. Admin / observability endpoint
```

Not every agent needs every layer, but serious digital workers should.

---

# 3. L0 — Agent manifest endpoint

Every marketplace agent should have a manifest.

```http
GET /.well-known/ai-agent.json
```

or:

```http
GET /agent/manifest
```

The manifest declares:

```json
{
  "agent_id": "aiagent://research.ops.worker",
  "name": "Research Operations Worker",
  "version": "1.2.0",
  "publisher": "ioi://publisher/acme",
  "description": "Persistent research worker for market scans, source monitoring, and report generation.",
  "worker_type": "persistent",
  "capabilities": [
    "web_research",
    "document_summary",
    "weekly_digest",
    "source_monitoring",
    "task_spawning"
  ],
  "interfaces": {
    "chat_completions": "/v1/chat/completions",
    "task": "/v1/agent/tasks",
    "worker": "/v1/worker",
    "interagent": "/v1/interagent",
    "artifacts": "/v1/artifacts",
    "receipts": "/v1/receipts"
  },
  "state_profile": {
    "persistent_memory": true,
    "agentgres_required": true,
    "portable_state": true,
    "receipt_support": true
  },
  "policy_profile": {
    "requires_capability_lease": true,
    "supports_human_approval": true,
    "tool_scope_required": true
  },
  "runtime_requirements": {
    "kernel": "ioi-agent-kernel",
    "agentgres": ">=2.0",
    "tools": ["browser", "files", "email_optional", "slack_optional"]
  }
}
```

This is the marketplace contract.

The buyer should know:

* what the agent can do
* what it needs
* what endpoints it exposes
* whether it is ephemeral or persistent
* whether it supports receipts
* whether it can run locally, on hosted infrastructure, or both
* what kernel/runtime it requires

---

# 4. L1 — OpenAI/LM Studio-compatible model endpoint

Yes, support it.

```http
POST /v1/chat/completions
POST /v1/responses
POST /v1/embeddings
```

This matters because developers expect compatibility.

But this should be labeled:

> **Inference compatibility surface**

not the true agent API.

Use cases:

* “talk to this worker”
* “mount the worker in an OpenAI-compatible client”
* “benchmark the underlying model”
* “use worker as a tool inside another orchestrator”
* “simple chat mode”

However, if the agent is persistent, calls to `/v1/chat/completions` should be able to run in one of two modes:

```json
{
  "persistence": "none"
}
```

or:

```json
{
  "worker_session": "session_123",
  "persistence": "worker_memory"
}
```

Otherwise people will accidentally treat persistent workers like stateless chatbots.

---

# 5. L2 — Agent task endpoint

This is the minimum real agent endpoint.

```http
POST /v1/agent/tasks
GET /v1/agent/tasks/{task_id}
POST /v1/agent/tasks/{task_id}/cancel
GET /v1/agent/tasks/{task_id}/events
GET /v1/agent/tasks/{task_id}/artifacts
GET /v1/agent/tasks/{task_id}/receipts
```

Example:

```json
{
  "objective": "Audit the latest runtime failures and propose hardening tasks.",
  "context_refs": [
    "agentgres://project/autopilot",
    "git://repo/ioi",
    "slack://channel/runtime"
  ],
  "constraints": {
    "max_budget_usd": 5,
    "deadline": "2026-04-29T18:00:00Z",
    "requires_human_approval_for": ["code_write", "email_send"]
  },
  "output_contract": {
    "type": "report_plus_task_requests",
    "required_artifacts": ["summary", "evidence_bundle", "proposed_tasks"]
  }
}
```

Response:

```json
{
  "task_id": "task_abc",
  "status": "accepted",
  "worker_id": "worker_research_ops",
  "run_room": "agentgres://runroom/task_abc",
  "events": "/v1/agent/tasks/task_abc/events"
}
```

This is where the buyer says:

> “Do this job.”

Not:

> “Complete this prompt.”

---

# 6. L3 — Persistent worker endpoint

This is the digital employee interface.

It should support:

```http
GET /v1/worker/profile
GET /v1/worker/status
GET /v1/worker/objectives
POST /v1/worker/objectives
GET /v1/worker/standing-orders
POST /v1/worker/standing-orders
GET /v1/worker/inbox
POST /v1/worker/inbox/{item_id}/respond
GET /v1/worker/memory
GET /v1/worker/digests
POST /v1/worker/schedule
GET /v1/worker/runs
```

This is where persistent workers differ from chatbots.

They have:

* standing orders
* recurring checks
* project memory
* inbox items
* responsibilities
* escalation rules
* active tasks
* owned projects
* review cadence
* human approval queue

Example standing order:

```json
{
  "title": "Weekly Autopilot Runtime Audit",
  "cadence": "weekly",
  "scope": {
    "project": "autopilot",
    "repos": ["ioi"],
    "sources": ["recent_runs", "git_changes", "open_failures"]
  },
  "instructions": "Review runtime failures, patch drift, and agent harness regressions. Propose hardening tasks.",
  "outputs": ["digest", "risk_updates", "task_requests"],
  "approval_required_for": ["code_changes", "external_messages"]
}
```

This is not a model endpoint. It is a **worker management endpoint**.

---

# 7. L4 — Inter-agent protocol endpoint

This is important.

For persistent workers to coordinate, you need an inter-agent standard that is higher-level than chat.

Possible endpoints:

```http
POST /v1/interagent/message
POST /v1/interagent/task-offer
POST /v1/interagent/task-accept
POST /v1/interagent/handoff
POST /v1/interagent/capability-query
POST /v1/interagent/status-request
POST /v1/interagent/patch-proposal
POST /v1/interagent/evidence-request
POST /v1/interagent/decision-request
```

This should support structured messages like:

```json
{
  "type": "handoff",
  "from": "agent://planner",
  "to": "agent://runtime_auditor",
  "project": "agentgres://project/autopilot",
  "reason": "Need targeted audit of Git overlay adapter risk.",
  "context_refs": [
    "agentgres://decision/git_overlay_first",
    "agentgres://task/runtime_hardening"
  ],
  "expected_output": {
    "type": "audit_report",
    "deadline": "2026-04-30T12:00:00Z"
  }
}
```

Or:

```json
{
  "type": "capability_query",
  "requester": "agent://planner",
  "capability": "postgres_migration_audit",
  "constraints": {
    "needs_receipts": true,
    "max_budget_usd": 10
  }
}
```

This is the “inter-agent standard” you’re pointing at.

It should not be just freeform text. It should be structured, receiptable, and policy-bound.

---

# 8. L5 — Artifact, receipt, and state endpoints

Digital workers need outputs that are verifiable and portable.

Endpoints:

```http
GET /v1/artifacts/{artifact_id}
GET /v1/artifact-bundles/{bundle_id}
GET /v1/receipts/{receipt_id}
GET /v1/state/roots
GET /v1/state/checkpoints
GET /v1/projections/{projection_id}
```

Artifacts include:

* reports
* patches
* screenshots
* notebooks
* datasets
* generated code
* summaries
* evidence bundles
* validation logs
* receipts
* exported documents

Receipts include:

* task acceptance receipt
* tool-use receipt
* validation receipt
* merge receipt
* execution receipt
* policy decision receipt
* delivery receipt

This is what makes a marketplace worker trustworthy.

A buyer should be able to ask:

> What did this worker do?
> What evidence supports the output?
> Which tools did it use?
> Which policy allowed it?
> Which state did it read?
> Which artifacts did it produce?

---

# 9. L6 — Admin and observability endpoints

For serious deployments:

```http
GET /v1/admin/health
GET /v1/admin/capabilities
GET /v1/admin/budgets
GET /v1/admin/policy
GET /v1/admin/queues
GET /v1/admin/runs
GET /v1/admin/errors
GET /v1/admin/audit
```

Operators need to see:

* active runs
* stuck tasks
* budget usage
* policy denials
* tool failures
* queue depth
* memory growth
* recurring job status
* external connector health
* receipt completeness

A digital worker without observability is not a serious worker.

---

# 10. Does this require Autopilot CLI and IOI kernel on the server?

For persistent digital workers: **yes, practically.**

You need a runtime somewhere.

There are three deployment modes.

---

## Mode A — Local worker

Runs on user machine.

```text
Autopilot Desktop / CLI
  -> local IOI kernel
  -> local Agentgres store
  -> local tools/connectors
  -> optional local model via LM Studio/Ollama
```

Good for:

* private desktop assistant
* local file work
* local code agent
* local browser/computer use
* private data
* offline-first workflows

The marketplace agent package installs locally and runs under Autopilot.

---

## Mode B — Hosted worker

Runs on provider or IOI infrastructure.

```text
aiagent.xyz worker package
  -> hosted Autopilot/IOI runtime
  -> Agentgres state
  -> tool sandbox
  -> model endpoint(s)
  -> connectors
  -> receipts/artifacts
```

Good for:

* always-on digital employees
* cron/async workers
* monitoring
* research agents
* customer ops agents
* project coordinators
* marketplace services

This likely requires an **Autopilot server runtime** or **IOI agent kernel**.

---

## Mode C — Hybrid worker

Local/private execution plus hosted coordination.

```text
local Autopilot runtime
  -> private tools/files/models

hosted Agentgres/IOI coordination
  -> schedules, receipts, tasks, projections, marketplace identity
```

Good for:

* private data
* enterprise deployments
* local model execution
* cloud scheduling
* human approvals
* shared project state

This is probably the best long-term model.

---

# 11. What exactly does the IOI kernel do?

The IOI kernel / Autopilot runtime should provide:

```text
agent identity
capability leases
policy checks
tool sandbox
connector access
memory/state access
Agentgres storage
task scheduling
standing orders
run execution
artifact capture
receipt generation
model routing
human approval queue
inter-agent messaging
settlement anchoring
```

A model endpoint alone cannot do these.

So if aiagent.xyz sells real persistent workers, the listing should specify:

```text
Runtime requirement:
  Requires Agentgres-compatible worker runtime

Supported runtimes:
  - Autopilot Desktop
  - Autopilot Server
  - IOI Hosted Runtime
  - Bring-your-own Agentgres Kernel
```

The worker package should be portable across compatible runtimes.

---

# 12. What does aiagent.xyz actually sell?

It should sell **agent packages**, not just prompts or model endpoints.

An agent package contains:

```text
manifest
role definition
capabilities
tool requirements
model preferences
memory schema
standing order templates
task handlers
inter-agent handlers
policy requirements
UI surfaces
artifact schemas
receipt modes
billing model
deployment profile
```

Example package:

```json
{
  "name": "Runtime Hardening Planner",
  "package": "aiagent://ioi/runtime-hardening-planner",
  "version": "1.0.0",
  "type": "persistent_worker",
  "handlers": {
    "task": "handlers/task.ts",
    "standing_order": "handlers/standing_order.ts",
    "interagent": "handlers/interagent.ts"
  },
  "requires": {
    "runtime": "agentgres>=2.0",
    "tools": ["git_read", "file_read", "run_tests", "web_optional"],
    "connectors": ["github_optional", "slack_optional"]
  },
  "models": {
    "default": "provider:any/reasoning",
    "local_supported": true
  },
  "state": {
    "memory_schema": "schemas/memory.yaml",
    "projection_schema": "schemas/projections.yaml"
  },
  "receipts": {
    "task": true,
    "tool_use": true,
    "validation": true
  }
}
```

This is far more valuable than selling “access to a chatbot.”

---

# 13. Should aiagent.xyz expose a model-mounting endpoint?

Yes, but as one adapter.

The API stack should look like:

```text
/v1/chat/completions        compatibility/chat mode
/v1/responses               compatibility/chat/tool mode
/v1/agent/tasks             task execution
/v1/worker/*                persistent worker management
/v1/interagent/*            agent-to-agent coordination
/v1/artifacts/*             outputs
/v1/receipts/*              proof/evidence
/v1/admin/*                 observability
```

Model-compatible endpoints help adoption.

Worker/inter-agent endpoints create the new category.

---

# 14. The inter-agent standard should be the real moat

The marketplace becomes more powerful if agents can discover and call each other.

Example:

A project planner agent asks:

```http
POST /v1/interagent/capability-query
```

```json
{
  "need": "audit Rust codebase for storage engine risks",
  "constraints": {
    "requires_code_read": true,
    "requires_receipts": true,
    "deadline": "2026-04-30"
  }
}
```

aiagent.xyz returns compatible workers.

Then:

```http
POST /v1/interagent/task-offer
```

Worker accepts, runs, returns artifacts/receipts.

That becomes the Service-as-Software marketplace.

Not:

> “Here is a chatbot endpoint.”

But:

> “Here is a worker that can accept scoped responsibility and return verified work.”

---

# 15. How sas.xyz fits

I’d separate the two:

## aiagent.xyz

Marketplace for agent packages and workers.

Sells:

* digital employees
* specialist workers
* reusable agent capabilities
* tool-using agents
* inter-agent services

## sas.xyz

Service-as-Software portal.

Sells outcomes:

* “weekly runtime audit”
* “customer support resolution”
* “generate sales lead report”
* “migrate Postgres to Agentgres”
* “monitor competitor launches”

Under the hood, sas.xyz may compose many aiagent.xyz workers.

So:

```text
aiagent.xyz = worker marketplace
sas.xyz = outcome marketplace
```

---

# 16. What endpoints should a persistent worker expose publicly?

Minimum serious profile:

```http
GET  /.well-known/ai-agent.json
POST /v1/agent/tasks
GET  /v1/agent/tasks/{id}
GET  /v1/agent/tasks/{id}/events
GET  /v1/agent/tasks/{id}/artifacts
GET  /v1/agent/tasks/{id}/receipts

GET  /v1/worker/profile
GET  /v1/worker/status
POST /v1/worker/standing-orders
GET  /v1/worker/inbox

POST /v1/interagent/message
POST /v1/interagent/task-offer
POST /v1/interagent/handoff
POST /v1/interagent/capability-query

GET  /v1/artifacts/{id}
GET  /v1/receipts/{id}

POST /v1/chat/completions
```

The `/v1/chat/completions` endpoint is there for compatibility, but the worker’s real value lives in `/v1/agent`, `/v1/worker`, and `/v1/interagent`.

---

# 17. Best concise doctrine

> **Models expose completions. Workers expose responsibilities.**

That is the key.

aiagent.xyz should not merely list models.

It should list portable digital workers that expose:

```text
tasks
standing orders
capabilities
state
memory
artifacts
receipts
inter-agent handoffs
policy-bound tools
```

And yes, to run them persistently, you need an **Agentgres/Autopilot/IOI kernel runtime** somewhere: local, hosted, or hybrid.

The final architecture:

```text
aiagent.xyz
  sells portable worker packages

Autopilot CLI/Desktop/Server
  runs worker packages

IOI kernel
  provides identity, policy, tools, receipts, settlement

Agentgres
  retains state, patches, memory, projections, artifacts

Model endpoints
  provide inference

Inter-agent endpoints
  provide worker-to-worker coordination

sas.xyz
  composes workers into paid outcomes
```


Yes — given your current status, I would **not jump straight into full Agentgres before My Agents**, but I also would **not defer all Agentgres thinking until after My Agents**.

The right move is:

> **Build the workflow canvas and harness componentization first. Then introduce a thin Agentgres-shaped state/event/receipt substrate underneath My Agents before building persistent digital workers deeply.**

In other words:

```text
Workflow Canvas
→ Componentized Harness
→ Harness-as-Workflow
→ Model Mounting
→ Connector/Tool Abstraction
→ Minimal Agent State + Agent Registry
→ My Agents GUI
→ Agent API / Worker Runtime
→ Agentgres v0 / Persistent Agent State
→ aiagent.xyz Portable Worker Marketplace
→ sas.xyz Outcome Marketplace
```

The key is sequencing. **Agentgres should not block the first My Agents GUI**, but **persistent workers should not be built on ad hoc state**. So you want a minimal Agentgres foundation before agents become serious.

---

# Recommended chronological roadmap

## Phase 0 — Stabilize the current harness foundation

**Goal:** make the existing agent harness reliable enough that every later layer can use it.

Before expanding horizontally, finish hardening:

* run lifecycle
* file(s) generation
* planner/executor boundaries
* retries
* validation
* receipts/events
* cancellation
* model call abstraction
* tool call abstraction
* error reporting
* run history

This does not need to be “perfect,” but the harness needs stable internal contracts.

**Output:**

```text
A reliable Run model:
Run → Plan → WorkItems → ToolCalls → Artifacts → Validation → Result
```

This becomes the primitive that the workflow canvas, agents, and Agentgres all build on.

---

## Phase 1 — Workflow Canvas first

Your instinct is right: **finish workflow canvas first**.

This should be the visible product wedge. It gives users something tangible before the deeper Agentgres substrate exists.

Target:

> Workflow canvas should become at least n8n-grade for orchestration and move toward Palantir AIP-style operational control.

Priorities:

* visual nodes/edges
* triggers
* tool nodes
* model nodes
* connector nodes
* approval nodes
* branch/condition nodes
* validation nodes
* artifact output nodes
* human intervention nodes
* run timeline
* node-level logs
* retry/replay
* saved workflows
* workflow templates
* workflow import/export

Do not overbuild agent persistence yet. Make the canvas execute reliable bounded workflows.

**Why first:** it becomes the user-facing control plane for everything else.

---

## Phase 2 — Componentize the entire agent harness

Once the canvas works, componentize the harness so every internal capability can become a canvas node.

This is critical.

You want the harness to stop being a monolith and become a set of composable runtime primitives:

```text
Planner
Executor
Tool Router
Model Router
Validator
Artifact Writer
Receipt Writer
Memory Reader
Connector Caller
Approval Gate
Retry Policy
Merge/Judge
Repair Loop
```

Each should have:

* input schema
* output schema
* error schema
* receipt/event emission
* cancellation behavior
* retry behavior
* permissions/capability requirements
* UI representation

This is what lets users later modify the default harness in the canvas.

**Output:**

```text
Every major harness step can be represented as a node.
```

This is a major unlock.

---

## Phase 3 — Harness-as-Workflow

After componentization, dogfood the harness itself as a workflow.

This is the architectural pivot.

Instead of:

```text
hardcoded agent harness
```

you get:

```text
default agent harness = editable workflow template
```

That means users can eventually customize:

* planning style
* model routing
* verifier behavior
* approval gates
* artifact generation
* parallel candidate generation
* swarm behavior
* repair loop
* tool policies
* output formatting
* validation strictness

The default harness should remain blessed and safe, but advanced users can fork it.

**Important:** do this before full My Agents. Persistent agents should be defined partly by **which harness workflow they use**.

Example:

```yaml
agent:
  name: Runtime Auditor
  harness: workflows/runtime-audit-harness.v1
  tools:
    - git_read
    - cargo_test
    - file_write_scoped
  schedule: weekly
```

That is powerful.

---

## Phase 4 — Node/tool abstraction for connectors

This should happen around the same time as Harness-as-Workflow.

The connector system should not just expose “Google connector” or “mail connector.” It should expose **capability-bearing tools** that can be mounted into workflows and agent harnesses.

Example connector capabilities:

```text
gmail.search
gmail.read_thread
gmail.create_draft
gmail.send_with_approval
calendar.find_availability
calendar.create_event
drive.search_docs
drive.read_doc
github.open_issue
github.comment_pr
slack.post_message
slack.import_thread
```

Each connector tool should declare:

* name
* input schema
* output schema
* auth scopes
* risk class
* approval requirement
* rate limits
* receipt behavior
* whether it can be used by agents
* whether it can be used in workflows
* whether it can be exposed to marketplace workers

This is the beginning of the real tool economy.

**Rule:**

> Connectors should add tools to the harness through a registry, not through hardcoded calls.

---

## Phase 5 — Model mounting interface

Then add model mounting, LM Studio-style.

This is the right time because by now the harness and canvas have a model-router abstraction.

Do not bolt model mounting directly into random flags. Add a real **Model Registry**.

Model registry should support:

```text
local OpenAI-compatible endpoints
LM Studio
Ollama
OpenAI
Anthropic
Gemini
custom HTTP models
specialized embedding models
rerankers
vision models
code models
```

Each mounted model should declare:

* endpoint
* model id
* context length
* modalities
* tool-call support
* structured-output support
* cost
* latency
* privacy class
* local/remote
* default use cases
* health check
* benchmark profile

Then harness nodes can say:

```yaml
model_policy:
  planner: reasoning_high
  executor: local_fast
  verifier: strict_reasoning
  summarizer: cheap
```

This lets local models become first-class without changing workflows.

**Why after componentization:** model mounting is much cleaner once model calls are already abstracted into nodes/services.

---

## Phase 6 — Minimal Agent State Foundation

Before building a rich My Agents GUI, add a minimal persistent agent substrate.

Not full Agentgres yet. A simple Agentgres-shaped foundation.

Objects:

```text
AgentDefinition
AgentInstall
AgentRun
AgentMemoryRef
AgentToolGrant
AgentSchedule
AgentInboxItem
AgentStandingOrder
AgentArtifact
AgentReceipt
```

This gives you enough state to make agents persistent without committing to the full Agentgres architecture.

An agent should have:

```yaml
agent:
  id: runtime_auditor
  name: Runtime Auditor
  role: "Audits Autopilot runtime regressions"
  harness_workflow: runtime_audit_harness.v1
  model_policy: reasoning_high
  tools:
    - git_read
    - file_read
    - test_runner
  connectors:
    - github
    - slack_optional
  schedules:
    - weekly
  memory:
    project: autopilot
  approval_policy:
    code_write: human_required
```

This is the bridge to My Agents.

---

## Phase 7 — My Agents GUI

Now build **My Agents**.

At this point, My Agents has something real to manage:

* installed agents
* roles
* schedules
* tools
* connector permissions
* model policies
* harness workflows
* memories
* standing orders
* recent runs
* inbox/escalations
* artifacts
* receipts

The GUI should not be a chatbot list. It should be a **digital employee roster**.

Surfaces:

```text
My Agents
  → Agent Roster
  → Agent Detail
  → Standing Orders
  → Tool Grants
  → Model Policy
  → Schedule
  → Memory/Context
  → Runs
  → Inbox
  → Artifacts
  → Receipts
```

This is where the product becomes more than workflow automation.

---

## Phase 8 — Agent Office / Project Rooms

After My Agents, add the higher-level persistent coordination layer.

This is for long-duration planner agents, cron agents, and autonomous digital employees.

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

This gives persistent agents a place to coordinate over time.

Important distinction:

```text
My Agents = who exists
Agent Office / Project Room = what they are working on long-term
Run Room = bounded task execution
Workflow Canvas = how work is orchestrated
```

This is the right topology.

---

## Phase 9 — Agent API

Then expose the API.

Do not expose only `/chat/completions`.

Expose:

```http
GET  /v1/agents
POST /v1/agents/{id}/tasks
GET  /v1/agents/{id}/runs
GET  /v1/agents/{id}/inbox
POST /v1/agents/{id}/standing-orders
GET  /v1/artifacts/{id}
GET  /v1/receipts/{id}
POST /v1/interagent/message
POST /v1/interagent/task-offer
POST /v1/interagent/handoff
```

Also support model compatibility:

```http
POST /v1/chat/completions
POST /v1/responses
```

But the real agent API should be task/worker/inter-agent oriented.

**Doctrine:**

> Models expose completions. Workers expose responsibilities.

---

## Phase 10 — Agentgres v0

Now build Agentgres properly.

By this point, you have enough real product pressure to know what Agentgres must support.

Agentgres v0 should not try to be the full universal substrate immediately.

Start with:

```text
Agent definitions
Agent installs
Standing orders
Runs
Tasks
Project rooms
Decisions
Artifacts
Receipts
Patch/change records
Tool grants
Schedules
Inbox items
```

And the lifecycle:

```text
Intent → Scope → Patch/Change → Validate → Settle → Project → Query
```

This lets you migrate from ad hoc app state into Agentgres-backed state.

Do not start with “replace all Postgres.” Start with:

> replace Autopilot’s own agent/workflow/run state.

That is the correct dogfood path.

---

## Phase 11 — aiagent.xyz portable worker packages

Once My Agents + Agent API + Agentgres v0 exist, aiagent.xyz can sell real portable workers.

Package includes:

```text
manifest
agent definition
harness workflow
tool requirements
connector requirements
model policy
standing order templates
memory schema
artifact schemas
receipt policy
billing policy
deployment profile
```

aiagent.xyz should sell:

* specialist agents
* persistent workers
* task handlers
* project planners
* auditors
* customer ops workers
* coding workers
* research workers
* workflow templates

Not just prompts.

---

## Phase 12 — sas.xyz outcome marketplace

After aiagent.xyz worker packages are real, sas.xyz can compose them into service outcomes.

Examples:

```text
Weekly runtime audit
Customer support resolution
Lead enrichment
Market research digest
Codebase hardening sprint
Website conversion improvement
Postgres-to-Agentgres migration audit
```

sas.xyz sells the outcome.

aiagent.xyz supplies the workers.

Autopilot/Agentgres runs and governs the work.

---

# Recommended immediate order

If I were ordering the next 12–18 months, I’d do this:

## Milestone 1 — Workflow Canvas v1

Ship:

* visual workflows
* triggers
* model/tool/approval/artifact nodes
* run timeline
* saved templates
* basic connector nodes

**Do this first.**

## Milestone 2 — Harness Componentization

Refactor harness into reusable runtime components.

Every core harness step becomes node-compatible.

## Milestone 3 — Default Harness as Editable Workflow

Represent the default agent harness as a workflow template.

Users can inspect it first, edit/fork later.

## Milestone 4 — Connector Tool Registry

Make connectors expose typed tools into workflows/harnesses.

Add permissions, approval gates, and receipts.

## Milestone 5 — Model Mounting

Build LM Studio-style model registry and model router.

Support local endpoints cleanly.

## Milestone 6 — Minimal Persistent Agents

Create AgentDefinition, AgentInstall, StandingOrder, AgentRun, AgentInboxItem.

No full Agentgres yet, but use Agentgres-shaped objects.

## Milestone 7 — My Agents GUI

Build digital employee roster and agent detail pages.

Tie agents to harness workflows, tools, schedules, model policies, and runs.

## Milestone 8 — Project Rooms / Agent Office

Add persistent project coordination for planner agents.

Support decisions, plans, objectives, digests, spawned runs, and external signals.

## Milestone 9 — Agent API

Expose task, worker, artifact, receipt, inter-agent, and compatibility endpoints.

## Milestone 10 — Agentgres v0

Move Autopilot’s agent/workflow/run/project state into Agentgres-backed canonical state.

## Milestone 11 — aiagent.xyz Worker Marketplace

Package, install, run, update, and govern portable workers.

## Milestone 12 — sas.xyz Outcome Marketplace

Compose workers into paid service outcomes.

---

# The main dependency graph

```text
Workflow Canvas
  depends on: stable harness primitives

Harness-as-Workflow
  depends on: componentized harness

Connector Tool Registry
  depends on: node/tool abstraction

Model Mounting
  depends on: model router abstraction

My Agents
  depends on: harness workflows + model registry + connector tools + minimal agent state

Agent Office
  depends on: My Agents + persistent project state

Agent API
  depends on: My Agents + runs + artifacts + receipts

Agentgres
  depends on: real state pressure from workflows/agents/runs

aiagent.xyz
  depends on: agent package format + runtime + API + install model

sas.xyz
  depends on: reliable workers + billing + receipts + outcome packaging
```

This is why I would not build Agentgres first in full. But I would also not build My Agents without at least minimal Agentgres-shaped state.

---

# What to avoid

## Avoid building My Agents as just chatbots

If My Agents is just a list of chat personas, it will be underpowered.

Each agent should be:

```text
role + harness + tools + model policy + memory + schedule + inbox + runs + receipts
```

## Avoid making model mounting too early

If model mounting comes before the harness/model-router abstraction, it becomes flags and UI plumbing.

Better after componentization.

## Avoid making Slack/connector state canonical

Slack, GitHub, Gmail, etc. should be signals/adapters.

Canonical agent/project/run state should live in your runtime.

## Avoid full Agentgres too early

If you try to build the universal substrate before the product surfaces exist, it may become theoretical.

Dogfood it from actual workflow/agent/run requirements.

## Avoid delaying all Agentgres until too late

If persistent workers are built on random app tables/state blobs, migrating later will be painful.

So introduce minimal canonical objects early.

---

# Practical near-term sprint framing

## Next sprint

Focus:

```text
Workflow Canvas Hardening
+ Harness component boundary audit
```

Deliverables:

* node execution contract
* node input/output schema
* run event model
* artifact output contract
* approval node
* tool node
* model node
* validation node
* run timeline

## Sprint after

Focus:

```text
Harness-as-Workflow prototype
```

Deliverables:

* default agent harness rendered as graph
* read-only first
* then fork/edit
* node-level logs
* replay from node
* replace model/tool nodes

## Sprint after

Focus:

```text
Connector Tool Registry + Model Registry
```

Deliverables:

* connectors expose tools
* model endpoints mountable
* workflow nodes use model/tool registry
* local model health checks

## Sprint after

Focus:

```text
Minimal Agents
```

Deliverables:

* AgentDefinition
* My Agents basic roster
* schedule/standing order
* run history
* tool grants
* model policy

---

# My final recommendation

The best chronological order is:

```text
1. Workflow Canvas
2. Harness Componentization
3. Harness-as-Workflow
4. Connector Tool Registry
5. Model Mounting
6. Minimal Agent State
7. My Agents GUI
8. Project Rooms / Agent Office
9. Agent API
10. Agentgres v0
11. aiagent.xyz portable workers
12. sas.xyz service outcomes
```

The key strategic rule:

> **Use the workflow canvas to productize execution, componentization to expose the harness, model mounting to make inference portable, My Agents to make workers persistent, and Agentgres to make their state canonical.**

That order avoids building too much theory too early while still steering everything toward the full Agentgres/portable-worker/Web4 architecture.


I would schedule **Blender/CAD connectors earlier than Instacart-style commerce connectors**, but not before the workflow canvas, harness componentization, connector tool registry, and model mounting foundation are in place.

The practical rule:

> **Add connectors when the harness can expose them as typed, permissioned, receipted tools — not as one-off integrations.**

So the order is:

```text
Workflow Canvas
→ Harness Componentization
→ Connector Tool Registry
→ Model Mounting
→ Low-risk local creation connectors: Blender / FreeCAD / CAD
→ My Agents + Agent API
→ Higher-risk commerce/action connectors: Instacart, purchasing, booking, payments
```

## Why Blender/CAD can come earlier

Blender and CAD connectors are mostly **local creative/production tools**. They can run in a sandbox and produce artifacts without spending money or taking external irreversible actions.

Blender has a mature Python API, and FreeCAD exposes Python/API automation surfaces as well, making both good candidates for tool-style connectors. ([Blender Documentation][1])

These are ideal after the connector registry exists because they prove that Autopilot can orchestrate non-web, non-chat, non-email software.

Good early connector set:

```text
blender.open_project
blender.create_scene
blender.run_python
blender.render_preview
blender.export_model
blender.inspect_objects

freecad.open_document
freecad.create_part
freecad.run_python
freecad.export_step
freecad.export_stl
freecad.generate_preview
```

This supports:

* product visualization
* 3D asset generation
* CAD drafting
* simulation prep
* marketplace agent demos
* “agent as production worker” use cases

These are high-signal, low-regret connectors.

## Why Instacart should come later

Instacart is different because it crosses into **commerce, food preferences, availability, substitutions, delivery windows, payment, and irreversible purchasing**.

Instacart does now have developer APIs for shopping experiences, recipe functionality, local retailer catalog/product availability, and fulfillment capabilities like delivery/pickup/order tracking. ([Instacart Docs][2])

But that should only come after you have stronger:

* approval flows
* cart preview
* budget limits
* substitution policy
* dietary/preference memory
* connector permissions
* receipts
* human confirmation before purchase
* error handling for out-of-stock items
* stateful standing orders
* recurring schedule logic

Instacart-like flows are not just “call an API.” They are an **agentic purchasing workflow**.

A safe grocery agent workflow looks like:

```text
standing order: plan groceries weekly
→ read household preferences / diet / budget
→ create meal plan
→ generate recipe list
→ map ingredients to products
→ check availability/prices
→ produce cart draft
→ ask human approval
→ submit order only after approval
→ track substitutions/delivery
→ retain receipt and update preferences
```

That requires My Agents and Agentgres-style persistent state much more than Blender does.

## Recommended placement in roadmap

### Phase A — Now / near-term

Finish:

```text
Workflow Canvas
Harness Componentization
Harness-as-Workflow
Connector Tool Registry
```

No big Blender/CAD/Instacart work yet except design stubs.

### Phase B — Immediately after connector registry

Build **local artifact-production connectors**:

```text
Blender
FreeCAD / CAD
filesystem
browser/computer-use
local shell/sandbox
```

These are great because they exercise:

* tool schemas
* artifact outputs
* previews
* validation
* local execution
* workflow canvas nodes

They also make Autopilot feel powerful.

### Phase C — After model mounting

Enhance Blender/CAD with model-driven generation:

```text
prompt → plan → script → render/export → validate artifact
```

This is where local models become useful:

```text
Local model drafts Blender Python
Autopilot runs script
Blender renders preview
Verifier checks output
User approves/export
```

### Phase D — After minimal My Agents

Build **personal recurring planning connectors**:

```text
recipe planning
calendar
email
notes/docs
shopping-list generation
```

But stop before purchase submission.

At this stage, the grocery agent can produce:

```text
meal plan
recipe list
grocery list
cart draft
price estimate
substitution preferences
```

### Phase E — After Agent API / Agentgres v0

Build **commerce connectors**:

```text
Instacart cart creation
availability lookup
delivery window selection
order tracking
human-approved order placement
```

Because now the system can retain:

* preferences
* budgets
* recurring orders
* approvals
* receipts
* household state
* prior substitutions
* failed order handling

## Connector risk tiers

I’d classify connectors like this.

### Tier 1 — Safe read / local artifact connectors

Build early.

```text
filesystem read
Git read
browser screenshot
Blender render/export
FreeCAD generate/export
local docs
read-only Drive/Gmail/Calendar
```

Risk: low.
Approval: usually not required except file writes.

### Tier 2 — Local write / reversible connectors

Build after tool registry and approval gates.

```text
file write
Git patch
Blender scene modify
CAD document modify
draft email
create calendar draft
create cart draft
```

Risk: moderate.
Approval: preview + confirm.

### Tier 3 — External communication connectors

Build after My Agents basics.

```text
send email
post Slack
create GitHub issue
comment PR
send calendar invite
```

Risk: higher.
Approval: usually required.

### Tier 4 — Commerce / money / irreversible action connectors

Build after Agentgres v0 and strong approvals.

```text
Instacart order
book travel
buy supplies
pay invoice
ship package
purchase SaaS
```

Risk: high.
Approval: mandatory, budget-bound, receipt-bound.

## Where recipe/grocery fits

The **recipe planner** can come much earlier than the **Instacart orderer**.

Split them:

```text
Meal Planner Agent
  low risk
  creates recipes, weekly plan, grocery list

Cart Builder Tool
  medium risk
  maps grocery list to products/prices

Order Submitter Tool
  high risk
  requires human approval and commerce connector
```

So you can ship value earlier:

### Early grocery workflow

```text
“Create a weekly meal plan and grocery list”
```

No external purchasing.

### Mid-stage workflow

```text
“Create an Instacart cart draft for approval”
```

No order placement.

### Late-stage workflow

```text
“After I approve, place the order and track delivery”
```

Requires strong policy/receipt infrastructure.

## Best sequence for these specific connectors

My recommended order:

```text
1. Blender connector
2. FreeCAD/CAD connector
3. Browser/computer-use connector hardening
4. Recipe/meal-planning workflow without commerce
5. Shopping-list/cart-draft abstraction
6. Instacart catalog/search/cart integration
7. Human-approved checkout/order tracking
```

The Blender/CAD path helps validate Autopilot as a **production harness**.

The Instacart path helps validate Autopilot as a **digital life/work assistant**, but it needs more trust infrastructure first.

## How connectors should mount into the harness

Each connector should add typed tools to the registry:

```yaml
tool: instacart.create_cart_draft
risk_class: medium
requires_approval: false
inputs:
  grocery_items: array
  store_preference: optional
  budget_limit: optional
outputs:
  cart_draft_id: string
  estimated_total: money
  unavailable_items: array
  substitutions: array
receipts:
  - cart_draft_receipt
```

Then:

```yaml
tool: instacart.submit_order
risk_class: high
requires_approval: true
inputs:
  cart_draft_id: string
  delivery_window: string
  payment_profile: token_ref
outputs:
  order_id: string
  tracking_url: string
receipts:
  - purchase_receipt
```

That distinction matters.

No agent should be able to call `submit_order` without explicit policy.

## My final recommendation

Add Blender/CAD **soon after the connector tool registry** because they are safe, visual, and show off the canvas.

Add Instacart-style commerce **later**, after My Agents and minimal Agentgres/approval/receipt state exist.

The clean timeline:

```text
Workflow Canvas
→ Harness Componentization
→ Connector Tool Registry
→ Model Mounting
→ Blender/CAD connectors
→ My Agents basic persistent workers
→ Recipe/meal-planning workflows
→ Agent API + Agentgres v0
→ Instacart cart draft
→ Human-approved ordering
```

The doctrine:

> **Creative/local production connectors can come early. Money-moving connectors come after persistent state, approvals, and receipts.**

[1]: https://docs.blender.org/api/current/index.html?utm_source=chatgpt.com "Blender Python API"
[2]: https://docs.instacart.com/developer_platform_api/?utm_source=chatgpt.com "Introduction | Instacart Docs"


Yes — **both in harmony**, but with a clear order and separation of concerns.

The near-term product should support **foundational model API calls inside workflows** immediately. The deeper runtime should evolve toward **BYOK + run-to-idle + pluggable compute backends**, including local models, customer-owned keys, hosted APIs, and eventually decentralized/cloud GPU marketplaces.

The right doctrine:

> **Workflows should call models through a model router, not through hardcoded providers.**
> **The model router should support hosted APIs now, local model endpoints next, and run-to-idle/BYOK compute over time.**

## The short answer

Yes, focus on both — but not equally at the same time.

Chronological order:

```text
1. Model API support in workflows
2. Model registry / model router
3. BYOK provider accounts
4. Local model mounting: LM Studio, Ollama, OpenAI-compatible endpoints
5. Runtime model policies: cost, latency, privacy, quality
6. Run-to-idle local/server model serving
7. GPU/provider marketplace adapters
8. Decentralized compute settlement and verification
```

So the immediate target is not “decentralized model cloud.” The immediate target is:

> **model calls are abstracted, configurable, and routable everywhere in the harness/canvas.**

Once that is true, BYOK and run-to-idle are natural backend options.

---

# 1. Foundational model API support should come first

You need workflows to call:

* OpenAI-compatible APIs
* Anthropic
* Gemini
* local OpenAI-compatible servers
* LM Studio
* Ollama
* custom HTTP inference endpoints
* embeddings
* rerankers
* vision models
* code models
* small local utility models

This should be exposed as canvas nodes:

```text
Model Call
Structured Output
Embedding
Rerank
Vision Analyze
Transcribe
Summarize
Judge/Verifier
Planner
Code Generator
```

But every node should call through a **Model Router**.

Do not hardcode:

```text
workflow node -> OpenAI
```

Use:

```text
workflow node -> model policy -> model router -> provider/local endpoint
```

This is the foundation that makes everything else possible.

---

# 2. BYOK is important and should come early

BYOK should be an early capability because it lowers friction for power users and enterprises.

BYOK means:

```text
user brings OpenAI key
user brings Anthropic key
user brings Gemini key
user brings Together/Fireworks/etc key
user brings local endpoint
organization brings shared keys
```

The model registry should support:

```yaml
provider: openai
auth_mode: byok
key_ref: vault://user/openai
models:
  - gpt-5.5
  - gpt-5.5-thinking
```

BYOK gives you:

* lower platform liability
* user-controlled costs
* enterprise trust
* easier provider coverage
* faster model support
* less need to resell inference immediately

But BYOK alone is not enough. It needs model policy.

Example:

```yaml
model_policy:
  planner:
    preferred: reasoning_high
    fallback: reasoning_medium
  executor:
    preferred: local_fast
  verifier:
    preferred: reasoning_strict
  private_data:
    allowed_providers:
      - local
      - enterprise_byok
    disallowed:
      - public_shared_api
```

---

# 3. Run-to-idle is a major architectural moat

Run-to-idle matters because local/open models are expensive to keep hot.

You want:

```text
model not needed -> idle / unloaded / scaled to zero
model needed -> spin up / warm / serve
model idle again -> unload / sleep / release GPU
```

This maps perfectly to your zero-to-idle philosophy.

The model runtime should expose states:

```text
unavailable
cold
warming
ready
busy
draining
idle
sleeping
failed
```

A workflow can then say:

```yaml
model_requirement:
  type: local_or_private
  latency_tolerance: cold_start_allowed
  max_warmup_seconds: 120
```

For server deployments, modern inference platforms already lean into this pattern. KServe, for example, describes request/concurrency-based autoscaling, GPU-backed scaling, and scale-to-zero via Knative for cost control. ([KServe][1]) vLLM also documents Kubernetes deployment for scalable model serving. ([vLLM][2])

So run-to-idle is not speculative. It is aligned with where inference infrastructure is already moving.

---

# 4. Local model mounting should be the practical bridge

Before decentralized GPU marketplaces, add local model mounting.

Support:

```text
LM Studio
Ollama
vLLM local server
llama.cpp server
OpenAI-compatible endpoint
custom HTTP endpoint
```

The user should be able to add:

```text
Name: Local Qwen Coder
Endpoint: http://localhost:1234/v1
API format: OpenAI-compatible
Context: 128k
Tool calling: false/true
Privacy: local
Use for: code, drafts, cheap execution
```

Then the workflow canvas can use it as a normal model.

This gives you the LM Studio-style experience without making Autopilot itself a model host immediately.

---

# 5. Then add hosted run-to-idle model pools

After local mounting, support managed model servers:

```text
Autopilot Server model pool
vLLM workers
KServe workers
GPU node pool
model cache
autoscaler
```

This is where open-source models become programmable infrastructure.

Useful backend stack:

```text
vLLM / llama.cpp / TGI
KServe / Knative / Kubernetes
GPU scheduler
model artifact cache
model registry
Agentgres receipts/billing
```

You do not need to build all this from scratch. KServe exists specifically as a distributed AI inference platform on Kubernetes, and its ecosystem supports scalable model serving. ([GitHub][3])

---

# 6. Decentralized cloud marketplaces should be adapter targets, not the core first

Yes, eventually you want resource marketplaces:

```text
Akash-like GPU providers
io.net-like GPU providers
Render/Vast/Lambda-style providers
community GPU nodes
enterprise idle GPU pools
IOI-native compute providers
```

But treat them as **ComputeProvider adapters** behind the same model router.

The interface should be:

```yaml
ComputeProvider:
  quote(model, hardware, duration, privacy, region)
  provision(job_spec)
  health()
  stream_logs()
  stop()
  receipt()
```

Then the model router can choose:

```text
local endpoint
hosted API
customer BYOK
Autopilot server pool
decentralized GPU provider
enterprise private GPU
```

The key is that workflows should not care where the model runs.

They should specify intent:

```yaml
needs:
  privacy: private
  max_cost: 2.00
  latency: medium
  model_class: code_reasoning
  run_to_idle: true
```

The router chooses the backend.

---

# 7. Foundational API calls and decentralized compute are not competing strategies

They serve different needs.

## Foundational APIs

Best for:

* best quality
* reliability
* fast start
* low operational burden
* reasoning-heavy tasks
* broad modality support
* low initial infra complexity

## Local/open models

Best for:

* privacy
* cost control at scale
* offline use
* customization
* deterministic deployment
* customer trust
* tool-heavy execution
* coding assistance near files

## Decentralized/market compute

Best for:

* burst capacity
* sovereignty story
* marketplace economics
* open model serving
* lower-cost experimentation
* user/provider-owned resources

So support all through one router.

The product line should be:

> **Use the best model available. Run it where policy, cost, privacy, and latency allow.**

---

# 8. Recommended model runtime abstraction

Add these objects:

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
ModelArtifact
```

Example:

```yaml
model_endpoint:
  id: local_lmstudio_qwen
  provider: lmstudio
  base_url: http://localhost:1234/v1
  api_format: openai_compatible
  models:
    - qwen3-coder-30b
  privacy: local
  run_to_idle: manual
```

Hosted run-to-idle:

```yaml
model_endpoint:
  id: qwen_coder_serverless
  provider: autopilot_gpu_pool
  model_artifact: hf://Qwen/...
  serving_engine: vllm
  autoscale:
    min_replicas: 0
    max_replicas: 4
    idle_timeout_seconds: 300
  privacy: tenant_private
```

Foundational API:

```yaml
model_endpoint:
  id: openai_reasoning
  provider: openai
  auth: byok
  privacy: external_api
  capabilities:
    - reasoning
    - tool_calling
    - structured_output
```

---

# 9. Receipts matter for model calls

Every model call in a serious workflow should optionally emit a receipt:

```yaml
model_invocation_receipt:
  model_route: planner_high
  provider_class: external_api
  model_id: gpt-...
  input_hash: ...
  output_hash: ...
  tool_policy: ...
  privacy_class: ...
  cost_estimate: ...
  latency_ms: ...
```

For privacy, you may not store raw prompts by default, but you should store hashes, model route metadata, and policy decisions.

This is important for Agentgres/Autopilot auditability.

---

# 10. Where this fits in the roadmap

Given your existing roadmap, place it like this:

```text
1. Workflow Canvas
2. Harness Componentization
3. Connector Tool Registry
4. Model Router / Model Registry
5. BYOK
6. Local Model Mounting
7. Harness-as-Workflow model policies
8. My Agents basic
9. Run-to-idle server model pools
10. Agent API
11. Agentgres v0
12. Decentralized compute provider adapters
13. aiagent.xyz worker packages with model/runtime requirements
```

I would slightly move model mounting earlier than previously discussed if the harness componentization is far enough along, because model routing becomes a dependency for serious workflow customization.

---

# 11. Should decentralized compute be a core early feature?

Not yet as a full marketplace.

Do early:

```text
model router
compute provider interface
local endpoint mounting
BYOK
run-to-idle abstraction
```

Defer:

```text
marketplace settlement
provider reputation
decentralized GPU bidding
cross-provider attestation
deep verification
multi-provider scheduling
```

But design the interfaces so they can support it.

That avoids overbuilding while preserving the Web4 moat.

---

# 12. Final recommendation

Yes, pursue both in harmony, but in this order:

## Immediate

```text
Foundational API support in workflows
Model router
BYOK
Local OpenAI-compatible endpoint mounting
```

## Next

```text
Run-to-idle model lifecycle
Local/server open-model serving
Model policies for privacy/cost/latency
```

## Later

```text
Decentralized compute provider adapters
GPU resource marketplace
Model-serving receipts
Provider reputation and settlement
```

The core doctrine:

> **Autopilot should not care whether a model is OpenAI, local LM Studio, tenant BYOK, vLLM on a sleeping GPU, or a decentralized cloud worker. It should call a model capability through policy.**

That is the winning architecture.

And the stronger Web4 line:

> **The app runs locally. The runtime wakes when needed. The model runs wherever policy permits. The chain settles what matters.**

[1]: https://kserve.github.io/website/blog/cloud-native-ai-inference-kserve-llm-d?utm_source=chatgpt.com "Cloud-Native AI Inference at Scale using KServe and llm-d"
[2]: https://docs.vllm.ai/en/stable/deployment/k8s/?utm_source=chatgpt.com "Using Kubernetes - vLLM"
[3]: https://github.com/kserve/kserve?utm_source=chatgpt.com "KServe"


No — based on this spec, **wallet.network should not be abandoned**. It is actually the missing control plane that makes the rest of the architecture safe.

The clean answer:

> **Agentgres owns state/change/receipts. Autopilot owns execution. wallet.network owns authority.**

Or sharper:

> **Autopilot runs agents. Agentgres remembers and settles what changed. wallet.network decides what agents are allowed to do.**

That division is very strong.

## Where wallet.network fits

In the uploaded spec, wallet.network is defined as the **foundational Identity & Access Management control plane and native Web4 custodian**, not merely a wallet app. It owns root secrets, session authority, policy enforcement, approvals, audit lineage, and connector credentials; wrapped apps and agents are explicitly only capability clients and never key custodians. 

That means wallet.network is the authority layer for:

* user identity
* agent identity grants
* API keys
* OAuth refresh tokens
* connector secrets
* session keys
* approval tokens
* capability leases
* policy envelopes
* revocation
* step-up approvals
* emergency stop / panic controls
* high-risk on-chain/off-chain actions

Agentgres should **not** hold raw secrets or be the root IAM authority.

Agentgres should hold:

* state
* patches
* relations
* projections
* receipts
* task/run history
* decisions
* artifacts
* policy decision records

wallet.network should issue and revoke the power to act.

## Correct system topology

I would frame the stack like this:

```text
wallet.network
  Authority, identity, secrets, capability grants, approvals, revocation

Autopilot Runtime / IOI Guardian
  Executes agent runs, tools, workflows, connectors, model calls

Agentgres
  Retains state, patches, plans, decisions, receipts, projections, artifacts

aiagent.xyz
  Discovers, installs, and sells portable workers

sas.xyz
  Composes workers into outcome services

IOI Chain / Kernel
  Anchors roots, receipts, policies, namespaces, settlement commitments
```

The important line:

> **wallet.network is upstream of Agentgres writes whenever those writes imply authority.**

For example, an agent may propose a patch in Agentgres, but if that patch would send an email, place an order, transfer funds, widen a policy, reveal a secret, or invoke a sensitive connector, wallet.network must authorize the capability.

## It is not redundant with Agentgres

Agentgres and wallet.network could sound overlapping because both discuss policy, receipts, grants, and state. But they own different things.

| System             | Owns                                                                                  | Does not own                                             |
| ------------------ | ------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| **wallet.network** | secrets, identity, grants, approvals, step-up, revocation, connector credentials      | full project state, workflow projections, patch branches |
| **Agentgres**      | state lifecycle, patches, relations, projections, receipts, artifacts, project memory | raw secrets, root keys, ultimate user authority          |
| **Autopilot**      | execution, tools, workflows, agents, model calls, connector actions                   | root custody, canonical long-term state by itself        |

wallet.network is the **capability minting and enforcement root**.

Agentgres is the **state retention and settlement substrate**.

Autopilot is the **execution harness**.

## How it works in practice

### Example 1: Agent wants to send an email

```text
Agent proposes action in Autopilot
→ Agentgres records intent/patch
→ Autopilot asks wallet.network for gmail:send capability
→ wallet.network evaluates policy envelope
→ if allowed, issues short-lived capability/session grant
→ Guardian executes through connector without exposing raw secret
→ Agentgres records execution receipt and resulting state
```

The uploaded spec explicitly says agents request capabilities, not raw secrets, and the preferred mode is that Vault/Guardian executes the operation internally rather than exposing the secret to the agent. 

That is exactly right.

### Example 2: Agent wants to place an Instacart order

```text
Meal planner creates grocery cart draft
→ Agentgres stores cart draft + evidence
→ Human approves in wallet.network
→ wallet.network issues one-shot ApprovalToken
→ Autopilot submits order through connector
→ receipt stored in Agentgres
→ wallet.network audit lineage records capability execution
```

Commerce actions should not be governed by Agentgres alone. They require wallet.network approval/capability issuance.

### Example 3: Agent wants to call a paid model API

```text
Workflow node requests model call
→ Model router selects provider
→ Autopilot asks wallet.network for cap:openai.chat or equivalent
→ wallet.network releases operation-scoped capability/token
→ model invocation receipt emitted
→ Agentgres records cost/route/result metadata
```

This is how BYOK works safely. wallet.network stores the user’s OpenAI/Anthropic/Gemini keys; Autopilot gets operation-scoped capability, not raw long-lived secrets.

## wallet.network should be the “wallet of agency”

The current spec’s best line is effectively:

> The Vault owns both assets and agency.

That should stay.

This means wallet.network is not just:

```text
crypto wallet
```

It is:

```text
Sovereign IAM
+ secret vault
+ policy engine
+ approval authority
+ session issuer
+ connector credential broker
+ agent capability controller
+ emergency revocation layer
```

That is essential for digital workers.

Without wallet.network, persistent agents become dangerous because they either:

* hold raw API keys,
* rely on app-local secrets,
* require constant human prompts,
* or execute with ambient authority.

wallet.network solves that with bounded sessions and step-up triggers.

## Where it fits into the roadmap

I would not build the full wallet.network product before workflow canvas. But I would absolutely preserve it and implement a minimal version early as the **capability control plane**.

Recommended order:

```text
1. Workflow Canvas
2. Harness Componentization
3. Connector Tool Registry
4. Model Registry / BYOK interface
5. Minimal wallet-core capability vault
6. Model/API key brokerage through wallet.network
7. Connector OAuth token brokerage through wallet.network
8. My Agents
9. Standing orders + schedules
10. Agentgres v0
11. Full wallet.network desktop/mobile approval flows
12. Marketplace worker delegation through aiagent.xyz
```

The earliest wallet.network slice should be:

```text
local encrypted secret vault
capability request API
policy envelope
short-lived session grants
approval token
revocation
audit receipt
```

You do not need PQ/MPC/mobile fortress on day one, but the **API shape** should assume it.

## Minimal wallet.network v0

For Autopilot near-term, build:

```text
wallet-core-lite
  encrypted local secret store
  connector credential vault
  model provider key vault
  capability request API
  simple policy engine
  approval prompts
  session grants
  revocation
  audit log
```

Capabilities:

```text
cap:model.openai.chat
cap:model.anthropic.messages
cap:gmail.read
cap:gmail.draft
cap:gmail.send
cap:calendar.read
cap:calendar.create
cap:slack.post
cap:github.comment
cap:instacart.cart_create
cap:instacart.order_submit
```

Risk classes:

```text
read
draft
write_reversible
external_message
commerce
funds
policy_widening
secret_export
```

This gives you a safe foundation for connectors and model BYOK.

## How wallet.network and Agentgres interact

They should exchange objects, not blur responsibilities.

wallet.network emits:

```text
PolicyEnvelope
RootGrant
SubGrant
ApprovalToken
CapabilityLease
RevocationEvent
SecretExecutionReceipt
StepUpReceipt
```

Agentgres records:

```text
Intent
Patch
Run
Task
Decision
ExecutionReceipt
ArtifactBundle
PolicyDecisionRecord
SettlementReceipt
Projection
```

Shared binding fields:

```text
actor_id
agent_id
grant_id
lease_id
policy_hash
capability_set
constraints
expiry
revocation_epoch
approval_ref
receipt_ref
```

The wallet spec already mandates fields like `issuer_id`, `subject_id`, `policy_hash`, `policy_version`, `capability_set`, `constraints`, `delegation_rules`, `expiry`, `revocation_epoch`, and hybrid signatures for grants/policies. 

Those should become the shared authority envelope that Autopilot and Agentgres respect.

## Marketplace flow

For aiagent.xyz:

```text
User installs worker
→ worker requests capability envelope
→ wallet.network shows requested powers
→ user approves bounded RootGrant
→ worker runs in Autopilot runtime
→ Agentgres records work/state/receipts
→ wallet.network controls renewal, widening, revocation
```

This is exactly aligned with the uploaded marketplace delegation flow, where an agent requests a session/capability and wallet.network prompts the user to authorize a policy envelope before issuing bounded autonomy. 

That is not abandoned. That is the heart of safe portable workers.

## Does wallet.network need to be always-on?

For full persistent digital workers: yes, at least one authority endpoint must be available.

But this can be profile-based:

```text
Local desktop profile:
  wallet-core runs on user machine/tray

Hosted worker profile:
  hosted wallet authority or delegated enterprise vault

Hybrid profile:
  local wallet approves high-risk actions
  hosted runtime operates under preapproved session grants

Mobile profile:
  phone acts as step-up approver and panic control
```

The spec already targets Desktop primary, browser extension as bridge, and mobile as notifier/approver. 

That split still makes sense.

## My recommendation

Do **not** abandon wallet.network.

But simplify its near-term role:

> **wallet.network is the capability and secret authority for Autopilot and Agentgres.**

Do not start by trying to ship the full “Post-Quantum MPC Fortress” product. Start with the part every agent needs:

```text
safe connector credentials
BYOK model key storage
capability grants
session leases
approval tokens
revocation
audit receipts
```

Then evolve upward into:

```text
mobile approval
MPC/passkeys
hybrid signatures
on-chain smart account modules
policy commitments anchored to IOI
connector marketplace
```

Final doctrine:

> **Agentgres remembers what happened. Autopilot does the work. wallet.network decides what power the work is allowed to use.**


Yes — that is exactly the right frictionless entry path.

You can abstract the **wallet.network layer** so that:

> **“Sign in with Google,” “Sign in with GitHub,” or “Connect Web3 Wallet” silently creates a native wallet.network account behind the scenes.**

The user experiences normal account creation. Underneath, you create a **Web4 identity / wallet.network vault profile** with a low-security initial authority tier.

The important caveat:

> It should not be framed as “one shard forever.” It should be framed as **Level 1 custody / single-factor authority**, upgradeable later into stronger multi-factor / multi-shard custody.

That matches the current wallet.network “frictionless-to-fortress” model, where users can start with Web2-style login and later upgrade to biometric/passkey/YubiKey/MPC-style higher security. 

## The right abstraction

User sees:

```text
Sign in with Google
Sign in with GitHub
Connect MetaMask
Continue with Passkey
```

System creates:

```text
wallet.network identity
+ vault account
+ initial key material / managed shard
+ policy profile
+ recovery path
+ capability control plane
```

So the user is not asked to “create a wallet” at first.

They are just onboarded.

Internally:

```text
Google/GitHub/OIDC/Web3 wallet
→ authentication factor
→ wallet.network account
→ native Web4 identity
→ default policy envelope
→ capability vault
```

This is the Trojan horse: people think they are creating an account, but they are actually getting a sovereign IAM vault.

## How to think about “one shard”

For the initial frictionless tier, yes, you can conceptualize it as:

```text
one managed account factor / one managed shard / one recovery path
```

But I would avoid saying it is literally “just one shard” in the product model unless the implementation really uses MPC from day one.

Better language:

```text
Level 1: Frictionless Account
- Google/GitHub/OIDC or Web3 login
- native wallet.network identity created automatically
- low-risk capability profile
- managed recovery
- limited spend / limited autonomy
- upgrade required for high-risk actions
```

Then:

```text
Level 2: Trusted Device
- passkey / biometric / device factor
- higher limits
- stronger approval authority
```

Then:

```text
Level 3: Sovereign Vault
- multiple factors / MPC / hardware key
- high-value assets
- policy widening
- institutional autonomy
```

The uploaded spec already describes this kind of tiering: Level 1 frictionless login, Level 2 trusted device, and Level 3 fortress with configurable MPC/approval thresholds. 

## Web3 wallet login should be an auth/linking factor, not the identity itself

For MetaMask or another Web3 wallet, I would keep your existing spec’s principle:

> legacy wallets can authenticate or link, but they should not *be* the Web4 identity.

The spec says wallet.network should always generate a native Web4 identity and use legacy Web3 wallets as onboarding factors and liquidity sources rather than inheriting their cryptographic/security limitations. 

So:

```text
Connect MetaMask
→ sign SIWE message
→ prove control of 0x address
→ link address as auth factor / liquidity source
→ create native wallet.network identity
```

Not:

```text
MetaMask key = wallet.network root key
```

That distinction matters.

## Why this is strategically important

This reduces onboarding friction to almost zero.

A user can install Autopilot or an aiagent.xyz worker and click:

```text
Continue with Google
```

Then immediately get:

* agent account
* capability vault
* model BYOK storage later
* connector credential storage
* default policies
* approval prompts
* audit receipts
* upgrade path

They do not need to understand:

* shards
* MPC
* post-quantum keys
* policy envelopes
* capability leases
* wallet custody
* Agentgres
* IOI kernel

All of that can be progressive disclosure.

## The key safety design

The Level 1 account should be intentionally constrained.

For example, with only Google/GitHub login:

Allowed:

```text
read-only connectors
local workflows
draft creation
low-risk model calls
low-risk agent tasks
store noncritical preferences
```

Require step-up for:

```text
send email
place orders
spend money
transfer assets
publish externally
policy widening
raw secret export
high-value marketplace workers
long-duration autonomous delegation
```

So the low-friction account is not dangerous.

The user can begin immediately, but the system naturally says:

> “This action requires upgrading your wallet.network security.”

## Recommended onboarding flow

### 1. User signs in

```text
Continue with Google / GitHub / MetaMask
```

### 2. wallet.network creates native account

```text
native Web4 identity
default policy envelope
vault profile
account recovery metadata
```

### 3. User can use low-risk Autopilot

```text
workflows
chat
read-only connectors
local model calls
drafts
```

### 4. User connects first sensitive capability

Example:

```text
Connect Gmail
```

wallet.network stores the OAuth refresh token and grants Autopilot operation-scoped capabilities instead of giving raw tokens to agents.

### 5. User attempts high-risk action

Example:

```text
Send this email
```

System prompts:

```text
Upgrade security with passkey/phone approval to enable external sends.
```

### 6. Later, user upgrades to fortress

```text
add passkey
add mobile approver
add hardware key
enable MPC/shards
raise limits
allow persistent workers
```

This is the right “frictionless-to-fortress” ladder.

## Product wording

Avoid:

> “Create your Web4 wallet.”

Use:

> “Create your Agent Account.”

or:

> “Continue to Autopilot.”

or:

> “Create your secure workspace.”

Then later reveal:

> “Your wallet.network vault protects your agents, connectors, keys, and approvals.”

This prevents wallet friction while still giving you the wallet/network substrate.

## Architecture wording

I would add this to the spec:

```md
## Frictionless Account Abstraction

wallet.network accounts may be created through ordinary authentication factors
such as Google, GitHub, passkeys, or linked Web3 wallets.

A frictionless login creates a native wallet.network identity and a Level 1
authority profile automatically.

The external login provider is an authentication factor, not the root identity.

Level 1 accounts may use managed recovery and restricted capability limits.
High-risk actions require step-up into stronger authority profiles such as
trusted device, passkey, mobile approver, hardware key, MPC shard, or
institutional policy.

This allows users to begin with normal account creation while preserving a
migration path toward sovereign custody and agentic authority.
```

## Final answer

Yes.

That is the right abstraction:

> **Every login creates a wallet.network account. Every wallet.network account starts frictionless. Every high-risk capability asks the user to upgrade security only when needed.**

This makes wallet.network invisible at first and indispensable later.

The doctrine:

> **Do not make users create a wallet. Let them create an account that can grow into a vault.**
