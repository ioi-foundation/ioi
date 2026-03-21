# Autopilot Internal Product Spec

**Version:** 1.2
**Status:** Proposed revision
**Audience:** Product, design, Studio UI, Spotlight UI, runtime, orchestration, policy, capability, connector, and platform teams

## 1. Vision-State Product Definition

**Category:** Autonomous action runtime and operator shell
**Differentiator:** Private, sovereign, and verifiable by design

Autopilot is the private and sovereign operator shell for autonomous, local-first, and verifiable software workers.

Today the dominant domain is bounded software action. Over time, the same runtime model should be able to extend to broader autonomous systems, including devices or embodied workers, wherever the same guarantees can be preserved.

At its end state, Autopilot is not just a private desktop assistant, a workflow builder, or a copilot. It is a zero-trust hypervisor for generative AI that lets an individual or organization run bounded digital workers across the desktop, browser, APIs, and external software systems while preserving operator control, policy enforcement, provenance, and replayable evidence.

The long-term progression is:
gen-AI hypervisor -> software worker runtime -> swarm coordinator -> embodied action runtime

Autopilot should not be marketed as a robot runtime first. It should be described as the runtime and operator shell for bounded autonomous action, starting with software and extending outward only when the same policy, approval, evidence, and authority guarantees can be maintained.

Within the broader IOI surface map, Autopilot is where workers are operated privately and locally. When stable local work should become a provider-facing product with deployment presets, billing, tenants, and marketplace publication, the promotion path continues into `sas.xyz`.

**Doctrine:** Autopilot stabilizes work; `sas.xyz` productizes it.

Autopilot overlaps with `sas.xyz` in the shared authoring layer, but that overlap is the private/local lens: operate, refine, stabilize, and promote. Formal packaging, deployment presets, serving posture, tenancy, billing, and distribution live in `sas.xyz`.

Autopilot should unify six things that are usually split apart:

* computer use
* connector-based automation
* worker orchestration
* bounded recursive improvement
* local-to-service promotion
* verifiable execution under sovereign control

The product should start from the user’s machine and trust boundary, but grow into a company-scale orchestration layer for fleets of digital workers.

---

## 2. Product Definition

### One sentence

Autopilot is the private/local operator shell and execution runtime for running sovereign, verifiable software workers across your desktop, apps, and connected systems with governed capabilities.

### One paragraph

Autopilot is the operating layer for software workers: a zero-trust hypervisor and execution runtime that can understand goals, decompose work, spawn and supervise worker swarms, act through a unified capability surface spanning computer use, connected systems, tools, and reusable skills, and promote stable workflows into durable service candidates. It is private by default, sovereign in control, and verifiable in execution, so every meaningful action can be gated, audited, simulated, replayed, and improved without surrendering authority to a black-box cloud agent. Today that action is mostly software; over time the same governance model can extend to broader autonomous and embodied systems where the same guarantees can still be preserved.

---

## 3. End-State Vision

### 3.1 For an individual

A private desktop assistant that can:

* read and write across local files, browser tabs, apps, email, docs, and terminals
* manage long-running personal workflows
* schedule, monitor, and supervise recurring tasks
* act with least privilege and ask for approval at the right boundaries
* show exactly what it did, why, and under what authority

### 3.2 For a builder or operator

A worker orchestration studio that can:

* define workers, workflows, capabilities, triggers, policy posture, memory, and models
* route work across specialist workers
* monitor runs, failures, artifacts, receipts, and approvals
* convert successful ad hoc tasks into durable service candidates
* preview service-candidate characteristics before promotion without owning live provider presets
* evolve and improve workflows under bounded controls

### 3.3 For a company

A digital workforce control plane that can:

* run fleets of workers across internal and external systems
* support function-specific workers for research, support, GTM, finance, ops, legal, recruiting, and engineering
* use capabilities spanning connections, APIs, computer use, and browser automation together
* provide a durable Inbox for interventions, approvals, exceptions, and result review
* let leadership supervise outcomes, not prompt transcripts

### 3.4 For the broader ecosystem

A service-as-software substrate where stable workflows become reusable digital services that are:

* discoverable
* composable
* monitorable
* governed
* priced
* verified
* portable across operators and environments

---

## 4. Core Thesis

The market has converged on two weak shapes:

* chat assistants that can answer but not reliably operate
* automation tools that can operate but cannot flexibly reason, adapt, or supervise themselves

Autopilot should collapse that distinction.

The winning product is not AI chat and not workflow automation in isolation, but a sovereign orchestration layer where natural language, structured workflows, reusable skills, computer use, and connected systems all feed one kernel, one worker model, and one governance model.

That system must be:

* private enough to handle real personal and company work
* sovereign enough that the operator retains authority
* verifiable enough that outcomes can be trusted
* composable enough to build durable services
* bounded enough to allow safe recursive improvement

---

## 5. Product Pillars

### 5.1 Sovereign execution

The user or organization defines the trust boundary.

Autopilot should support:

* local-first execution
* vault-backed secrets and delegated capability leases
* operator-owned policy and approval rules
* selectable workers, models, and providers
* explicit control over where data and artifacts can go
* human authority over irreversible actions

The user is not prompting a cloud agent. They are operating a software worker under their own control.

### 5.2 Universal reach

Autopilot should reach work wherever it lives:

* desktop apps
* browser surfaces
* terminals
* filesystems
* APIs
* SaaS tools
* internal systems
* documents and spreadsheets
* connected communication systems

This requires both:

* computer use
* connections

Neither is sufficient alone.
Over time, both should live inside one capability surface alongside reusable skills and installable extensions.

### 5.3 Orchestrated autonomy

The unit of value is not a single model response. It is a worker system.

Autopilot should:

* decompose work into sub-goals
* assign work to specialized workers
* coordinate parallel branches
* run durable workflows
* escalate ambiguity and risk
* resume long-lived execution
* supervise multi-step outcomes over time

### 5.4 Verifiable execution

Every meaningful action should be inspectable and attributable.

Autopilot should produce:

* evidence
* artifacts
* provenance
* policy decisions
* execution receipts
* capability actions
* source references
* replayable traces where possible

The operator should be able to ask:

* what happened
* why
* under whose authority
* with what inputs
* against which policy
* producing which outputs

### 5.5 Bounded recursive improvement

Autopilot should not merely run workflows. It should improve them.

Workers should be able to:

* propose better prompts or instructions
* refine plans
* create reusable sub-workflows
* generate tests
* improve routing heuristics
* suggest policy changes within allowed bounds
* create better tools or templates
* suggest service extraction from repeated successful work

Workers should not be able to:

* expand their own authority without explicit policy
* silently change trust boundaries
* self-replicate without governance
* mutate critical operating rules invisibly
* exfiltrate data under the guise of self-improvement

### 5.6 Service candidate promotion

A successful workflow should be promotable into a durable service candidate.

Operators should be able to:

* turn repeatable workflows into named workers and service candidates
* version them
* assign inputs, outputs, and SLAs
* monitor them
* approve them
* prepare them for internal use or downstream provider exposure
* prepare promotion metadata and preview deployment characteristics when needed

Autopilot should own the local promotion path and pre-product validation. Provider packaging, tenant operations, billing, and publication should continue in `sas.xyz`.
**Doctrine:** Autopilot stabilizes work; `sas.xyz` productizes it.
Autopilot may preview service shape or deployment implications, but `sas.xyz` is the source of truth for provider manifests, deployment presets, readiness posture, tenant setup, billing, and publication.

---

## 6. What Autopilot Should Ultimately Be

Autopilot should be all of the following at once:

* a private desktop assistant
* a workflow and worker studio
* a worker supervision surface
* a human decision surface
* a zero-trust hypervisor for generative AI
* a bounded digital worker operating system
* a local promotion surface for service candidates

---

## 7. Canonical Product Objects

Autopilot should be designed around durable objects, not vague assistant metaphors.

### Operator

The human authority center:

* identity
* preferences
* approval posture
* trust boundary
* delegation model

### Worker

A reusable software worker with:

* role
* capabilities
* memory model
* policy scope
* budget
* model configuration
* specialization profile

### Capability

A grantable surface a worker can use directly, or an installable package that adds such surfaces.

Capability forms include:

* connections
* skills
* tools
* extensions

### Workflow

A graph of work across:

* triggers
* workers
* actions
* logic
* approvals
* policies
* evidence checkpoints
* queues

### Run

A specific execution instance with:

* timeline
* state
* artifacts
* evidence
* receipts
* approvals
* costs
* failures
* next steps

### Connection

An authenticated reachable external system with:

* auth
* scopes
* health
* policy binding
* trust posture
* recent activity

### Skill

A reusable higher-level procedure or packaged operating pattern with:

* an intended outcome
* underlying tools and connections
* versioning and promotion paths
* policy compatibility
* reuse boundaries

### Tool

A concrete callable operation with:

* an action contract
* a parameter schema
* execution constraints
* observability and receipts
* escalation semantics when required

### Extension

An installable capability package that adds one or more of:

* adapters
* connections
* skills
* tools
* worker backends
* local app integrations
* MCP surfaces
* custom capability wrappers

### Policy

Rules that govern:

* reads
* writes
* external sends
* purchases
* automation creation
* artifact egress
* worker authority
* model and provider allowlists
* escalation thresholds

### Artifact

A human-meaningful output or intermediate:

* email draft
* document
* website preview
* code
* SVG
* PDF
* screenshot
* report
* structured result

### Evidence

Grounding and verification material:

* source excerpt
* retrieval result
* DOM snapshot
* screenshot
* connection record
* file reference
* trace excerpt
* policy decision

### Receipt

A structured proof or record of execution:

* action taken
* parameters
* hashes
* timestamps
* authority and policy context
* redactions where necessary

### Inbox item

A human-facing decision object:

* approval
* clarification
* result ready
* anomaly
* digest
* escalation

### Service

A promoted worker or workflow exposed as a durable unit of work with:

* interface
* policy
* pricing and budget
* SLA
* monitoring
* ownership

### Kernel

The underlying runtime substrate that enforces:

* workloads
* capability leases
* policies
* receipts
* adapters
* replay semantics
* event streaming

**Terminology note:** “Runtime” refers to the underlying kernel and should not be used interchangeably with worker backends, models, or extensions.

---

## 8. Core Operating Loop

Autopilot’s product loop should be:

1. **Instruct**
   The operator defines an outcome in chat or selects an existing service or workflow.

2. **Plan**
   The system forms an execution plan or selects a known one.

3. **Delegate**
   Work is split across workers and capabilities such as skills, tools, connections, and computer-use actions.

4. **Execute**
   Workers act across apps, browser, terminal, docs, and connected systems.

5. **Verify**
   Evidence, artifacts, receipts, and policy events are produced.

6. **Intervene**
   The system escalates approvals, ambiguity, or anomalies to the Inbox.

7. **Review**
   The operator reviews outcomes, approves actions, or resolves blockers.

8. **Improve**
   The system proposes workflow extraction, refinement, new tests, or serviceization.

9. **Productize**
   Repeated successful work becomes a durable service candidate that can be promoted into `sas.xyz`, where formal packaging, deployment presets, tenancy, billing, and distribution become provider source-of-truth concerns.

That loop is the core of the product.

---

## 9. Product Surfaces

The UI should reflect the operating loop and the ontology.

### Chat

Natural language control surface used to instruct, inspect, redirect, and resolve.

### Workflows

Visual and structured authoring surface used to define durable worker systems and stabilize service candidates in the private/local lens.

### Runs

Operational surface used to observe live and historical execution.

### Inbox

Durable decision surface used for approvals, clarifications, results, anomalies, and digests.

### Capabilities

Surface used to manage the systems, skills, and installable extensions available to workers.

Primary subsections should be:

* Connections
* Skills
* Extensions
* Tools in advanced or builder mode when needed

### Policy

Governance surface used to define authority, approvals, budgets, allowlists, leases, and egress rules.

This is primarily **local/operator policy**:

* local worker authority
* local file/browser/app permissions
* local approvals
* egress rules
* local capability leases
* trust boundary rules

Service-level operating envelopes, tenant-facing approvals, hosted execution restrictions, deployment-specific policy profiles, exposure limits, and billing enforcement belong in `sas.xyz`.

### Settings

Configuration surface used to define worker defaults, models, providers, system identity, diagnostics, storage, and environment preferences.

### Artifact and Evidence Atlas

Unified inspection surface for outputs, evidence, previews, receipts, and provenance.

### Catalog and Services

Surface for reusable workers, promoted workflows, local installs, and service candidates. It overlaps with `sas.xyz` through the shared Builder engine, but provider publication, deployment presets, tenant ops, and commercial distribution should continue in `sas.xyz`.

### Home and Mission Control

High-signal dashboard for active objectives, urgent work, system health, and worker fleet state.

---

## 10. The Worker Model

Autopilot should support multiple worker types.

### Ephemeral workers

Spawned for one objective or subtask.

### Durable workers

Long-lived workers assigned to recurring workflows or domains.

### Specialist workers

Role-bound workers such as:

* researcher
* planner
* verifier
* drafter
* negotiator
* operator
* classifier
* reviewer
* scheduler
* coding worker
* architecture worker

### Supervisory workers

Workers that evaluate or coordinate other workers.

### Service workers

Workers exposed as durable software services with defined inputs and outputs.

### Improvement workers

Workers that analyze runs and propose improvements to prompts, routing, capabilities, or workflows.

The orchestration layer should let these workers collaborate while remaining bounded by policy and authority.

---

## 11. The Capability Surface

The strongest version of Autopilot must treat capabilities as the full surface a worker can use.

### Capability surface includes

* reach through connections to external systems
* action through tools and computer use
* reusable know-how through skills

Computer use is a first-class capability domain composed of typed action surfaces, not merely a single generic tool.

### Computer use covers

* browser navigation
* desktop application interaction
* terminal execution
* file manipulation
* vision-based grounding
* document and UI handling when no native API exists

### Connections cover

* email
* calendar
* docs
* drive and storage
* CRM
* chat and work apps
* data warehouses
* project tools
* custom APIs
* internal enterprise systems

### Skills cover

* inbox triage
* research brief generation
* repo audit
* expense categorization
* investor update drafting

### Key principle

Use connections where possible, computer use where necessary, and skills where recurring work deserves a reusable named behavior. Unify all three behind one capability model.

The operator should not need to care whether the worker achieved the outcome via:

* Gmail API
* browser automation
* filesystem manipulation
* a terminal command
* a local app interaction
* a packaged inbox triage skill

They should care that:

* it worked
* it was allowed
* it was proven
* it can run again

---

## 12. Capabilities, Extensions, Workers, and Models

Autopilot must distinguish clearly between product ontology and implementation substrate.

### Capabilities

Capabilities are what workers use.
The operator-facing umbrella should group connections, skills, and extensions together, while low-level tools surface more directly in advanced or builder contexts.

### Extensions

Extensions are installable packages that add one or more capabilities. They may install:

* connections
* skills
* adapters
* tools
* wrappers
* worker backends
* MCP integrations
* local app integrations

Extensions are installable packaging and distribution units; they are not the primary user-facing ontology for daily operation.

### Workers

Workers are the user-facing software labor units that do the work.
A worker has a role, a model configuration, a policy scope, and a set of capabilities.

### Models

Models are subordinate worker configuration, not the primary product abstraction. A worker may be powered by:

* OpenAI models
* Anthropic models
* Bedrock-hosted models
* Vertex-hosted models
* local OSS models
* future provider-specific backends

### Product rule

Workers are actors. Models are cognitive backends. Capabilities are what workers can use. Policy defines what workers are allowed to do. The kernel and runtime are the substrate that enforces those rules.
Extensions may introduce new worker backends or new capabilities, but workers remain the primary product object. Models power workers; they are not peers to workers in the user-facing ontology.

---

## 13. Swarm Orchestration

Autopilot should eventually support true worker swarms, not just linear flows.

That means:

* planner, executor, and verifier topologies
* parallel branches
* quorum or review patterns
* fallback strategies
* retry and circuit-breaker behavior
* policy-aware coordination
* shared and scoped memory
* leader-worker relationships
* cost and budget awareness
* handoff semantics between workers and human operators

This should feel less like multi-agent theater and more like a real workforce orchestration engine.

The goal is not many agents for their own sake. The goal is composable distributed cognition with bounded authority.

---

## 14. Bounded Recursive Self-Improvement

This is a defining long-range differentiator.

Autopilot should support workers that improve workflows and services over time, but only within a strict envelope.

### Allowed improvement domains

* better decomposition
* prompt and instruction refinement
* tool choice improvements
* capability routing improvements
* skill extraction and reuse
* test generation
* policy suggestions
* reusable sub-workflow extraction
* error recovery improvements
* service packaging suggestions

### Improvement mechanisms

* post-run analysis
* failure clustering
* success pattern mining
* simulation and replay
* user acceptance feedback
* policy simulation before rollout
* draft changes gated through approval

### Hard bounds

No self-improvement should bypass:

* policy
* approval rules
* trust boundary
* secrecy boundary
* observability
* versioning

The right framing is bounded operational self-improvement under sovereign control.

---

## 15. Trust, Security, and Hypervisor Model

Autopilot should be fundamentally designed as a zero-trust hypervisor and governed execution runtime for bounded autonomous action, starting with software systems first.

This should scale conceptually from:

* hypervising generative AI
* to software worker execution
* to worker swarms
* and eventually to broader autonomous or embodied runtimes

without changing the higher-order model of capability bounds, policy mediation, approvals, receipts, and authority separation.

### Precise cryptographic claim

Autopilot should make strong claims precisely.

It should not claim that it can cryptographically prove the physical world changed in the way a runtime reported unless it also controls and trusts the relevant sensor, attestation, and actuator chain.

What it can cryptographically guarantee much earlier is:

* the policy that governed the action
* the identity of the actor or runtime
* the command that was issued
* the non-equivocation of the execution record
* the sequence of approvals and commitments
* the integrity of the receipt chain
* the boundedness of the authorized action envelope
* what evidence was observed and committed

That is the right bridge from software action today to broader autonomous action later.

### Least privilege by default

Workers receive capability-specific rights, not ambient access.

### Delegated capability leases

Connections, credentials, and other sensitive capabilities are mediated through durable, revocable grants.

### Explicit authority boundaries

Important actions require:

* policy resolution
* approval when necessary
* evidence and receipts

### Local-first secret handling

Secrets and delegated tokens are bound to the user’s trust boundary wherever possible.

### Artifact and egress control

Autopilot must know:

* what data entered a run
* what artifacts were produced
* what is permitted to leave the boundary

### Provider independence

The system should support multiple models and providers without making any one of them the root authority.

### Evidence-first irreversibility

Irreversible or externally consequential actions should have durable evidence and policy context.

This is what turns AI assistant into infrastructure.

---

## 16. Product Doctrine

Autopilot should follow these doctrines.

1. Authority is never implied by intelligence.
   A smart model does not get to act freely.

2. Reach is separate from authority.
   Capability access and permission to act are distinct.

3. Progress beats opacity.
   Workers should surface plan, status, blockers, and next steps in structured form.

4. Evidence is a first-class product object.
   Artifacts, sources, previews, and receipts are core UX, not debug exhaust.

5. Human intervention is a feature, not a failure.
   A great system knows when to escalate.

6. Durable work should become durable software.
   Repeated work should promote into service candidates locally and into provider services through `sas.xyz`.

7. Improvement must be governed.
   Optimization without bounds becomes loss of sovereignty.

8. The system should scale from one operator to an organization.
   The same core primitives should work for personal, team, and company modes.

9. Product ontology must reflect operator meaning, not just implementation details.
   A worker uses capabilities; a model powers a worker; an extension packages capabilities; the kernel and runtime enforce the boundary.

---

## 17. What Autopilot Is Not

Autopilot should explicitly not become:

* just a chat app
* just an automation builder
* just an RPA tool
* just an API wrapper
* an opaque cloud agent
* a generic agent marketplace shell
* the primary provider monetization or tenant-ops console
* assistant suggestions as the main UX

Chat is a surface, not the product. The core UX is control, outcomes, and decision surfaces.

---

## 18. End-State User Stories

### Personal operator

“Run my life admin privately across email, files, browser, and calendar, while asking me only when it truly matters.”

### Builder

“Take something I did in chat, extract it into a skill or workflow, attach approvals and policy, test it, and promote it into a durable worker.”

### Team operator

“Coordinate a fleet of workers across support, ops, and research, and intervene only on exceptions, approvals, and results worth review.”

### Executive

“Show me what needs my attention, what completed, where risk exists, and what the workers are doing for the business.”

### Enterprise integrator

“Bind internal systems and SaaS tools into worker capabilities without surrendering secrets, policy, or auditability.”

### Service creator

“Package a reliable workflow into a service candidate locally, then promote it into a provider service with an interface, budget, monitoring, and verifiable execution.”

---

## 19. Ultimate End-State Outcome

At maturity, Autopilot should make it possible to say:

> A user or company can run an entire layer of sovereign autonomous action under their own authority, starting with software labor across local and connected systems, with capabilities spanning computer use and APIs, with worker swarms coordinated under policy, and with enough evidence and replayability to trust and continuously improve the system over time.

That is the end state.

---

## 20. North-Star UX Statement

Autopilot should feel like:

* a private desktop assistant when the task is personal and immediate
* a workflow and worker studio when the task needs durable structure
* an operational supervision surface when the task is live and ongoing
* a human intervention queue when the task needs judgment
* a zero-trust hypervisor when the task crosses trust boundaries
* a promotion surface into provider services when the task becomes repeatable software labor

One shell. One ontology. One control plane.

Today the dominant action surface is software. Over time, the architecture should be capable of extending to devices or embodied systems without changing the higher-order governance model.

---

## 21. Final Product Statement

Autopilot should strive to become the runtime and operator shell for sovereign autonomous action: private, sovereign, and verifiable by design, starting with software workers across desktop, browser, files, APIs, and connected systems, then extending over time to broader autonomous and embodied systems wherever the same capability, policy, approval, evidence, and authority guarantees can be preserved.

That is the product.
