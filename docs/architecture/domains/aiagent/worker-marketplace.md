# aiagent.xyz Worker Marketplace Specification

Status: canonical architecture authority.
Canonical owner: this file for aiagent.xyz marketplace doctrine; low-level worker endpoints live in [`aiagent-xyz-worker-and-inter-agent-endpoints.md`](./worker-endpoints.md).
Supersedes: overlapping worker-marketplace plan prose when marketplace boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-06-01.

## Canonical Definition

**aiagent.xyz is the first-party Web4 marketplace application for portable digital workers, managed worker/agent instances, benchmark profiles, Sparse Worker Categories, installs, and MoW routing eligibility, built on AIIP and IOI settlement.**

It discovers, compares, benchmarks, ranks, installs, invokes, meters, licenses,
settles, and initializes worker packages. It is an application domain with its
own kernel + Agentgres backend, AIIP worker/handoff surfaces, and IOI L1
smart-contract settlement rails. A user may consume a worker as an API/workflow
primitive, install it into Hypervisor, route to it through AIIP, or initialize a
managed web-accessible instance backed by hosted, provider, DePIN, Private
Workspace cTEE, TEE, customer, or local Hypervisor Daemon runtime-node profiles.

aiagent.xyz is not the protocol. It is a first-party protocol client, demand
generator, and proof surface for AIIP and IOI autonomous-system settlement.

aiagent.xyz is not only a catalog. It is the opt-in invocation and
managed-instance market for workers: users may run a worker directly, route a
task through MoW, initialize a persistent web-accessible instance, call a worker
by API, install it locally, or compose it into workflows. MoW is IOI's
receipt-backed labor-routing architecture, not an `ioi.ai` private router.
`ioi.ai` may coordinate account, entitlement, restore, and runtime discovery
for a marketplace invocation, but aiagent.xyz owns the worker-market records and
runtime nodes execute the work.

## What aiagent.xyz Is

aiagent.xyz is:

- a React/Web marketplace interface;
- an Agentgres-backed application domain;
- an IOI L1 contract user;
- an AIIP marketplace-worker profile user;
- a worker discovery and procurement surface;
- a managed worker/agent instance initialization surface;
- a Sparse Worker Category and benchmark profile surface;
- a package/license/quality/reputation system;
- a trained-worker publication and routing-eligibility surface;
- a web-native console surface for installed instances, including chat,
  threads, approvals, receipts, usage, pause/resume, and runtime status;
- a gateway to local, hosted, DePIN, Private Workspace cTEE, and TEE worker
  execution.
  Execution is carried by Hypervisor Daemon runtime-node profiles, not by the
  marketplace or SDK itself.

It is not a separate chain by default and it is not the whole IOI protocol.

## What aiagent.xyz Owns

aiagent.xyz owns:

- worker listings;
- worker manifests;
- publisher profiles;
- worker versions;
- responsibility and requirement descriptions;
- pricing/licensing metadata;
- Sparse Worker Categories;
- benchmark profiles;
- training lineage refs;
- routing eligibility status;
- quality ledgers;
- contribution records;
- install records;
- managed worker/agent instance records;
- runtime assignment and lifecycle records;
- runtime subscription and usage metadata;
- browser console projections over daemon thread/run APIs;
- usage records;
- reputation projections;
- search/ranking;
- install/run UX.

## What aiagent.xyz Does Not Own

aiagent.xyz does not own:

- the user's raw secrets;
- all worker execution;
- IOI L1 itself;
- storage backend payload bytes;
- local Hypervisor state;
- the Hypervisor Daemon runtime nodes that execute managed instances;
- Private Workspace cTEE execution semantics;
- raw long-running instance memory outside Agentgres refs and policy;
- every service outcome delivery;
- wallet authority.

## Worker Package

A worker package should include:

```text
manifest
worker definition
harness workflow
training lineage ref, when available
benchmark profile refs
sparse worker category, when submitted
primitive capability requirements
authority scope requirements
model policy
tool requirements
connector requirements
memory schema
artifact schema
receipt policy
pricing/license terms
interaction surfaces: chat | form | api | workflow_node | scheduler | background_service
runtime profiles: local | hosted | provider | depin | private_workspace_ctee | tee | customer_vpc
persistence profiles: ephemeral | session | zero_to_idle | persistent
subscription profiles, when warm or ongoing runtime is supported
deployment profile and compatibility constraints
```

Package payloads may live in storage backends such as Filecoin/CAS/CDN and be
referenced by signed manifests and Agentgres-governed artifact refs.

## Package vs Instance

A worker package is a portable executable template. A managed instance is a
user-, org-, or project-bound initialization of that package.

The protocol actor remains the `Worker`. Product UX may call a persistent,
user-facing instance an "agent," but canonical state should model it as a
`WorkerInstance` or `ManagedWorkerInstance` bound to:

- worker manifest and package version;
- install/license right;
- owner or tenant;
- runtime assignment;
- persistence profile;
- interaction surfaces;
- memory and archive policy;
- authority grants and approval rules;
- runtime subscription or compute entitlement;
- receipts, usage, and contribution policy.

This distinction lets the same marketplace listing support both primitive MoW
invocation and direct user-facing operation. A code-review worker may be used as
a workflow node by Hypervisor, called through an API by another worker, or
initialized as a persistent cloud agent with a browser chat console.

## Marketplace Contracts on IOI L1

aiagent.xyz should use IOI L1 contracts for:

- publisher registration;
- worker publication;
- manifest/version commitment;
- benchmark profile and category root commitments;
- license/install right;
- usage settlement;
- contribution root commitment;
- reputation root commitment;
- disputes;
- payouts.

## Agentgres Domain State

aiagent.xyz Agentgres tracks:

- listing metadata;
- search indexes;
- worker versions;
- Sparse Worker Categories;
- benchmark profiles and submissions;
- routing eligibility;
- training lineage refs;
- install history;
- managed instance lifecycle;
- runtime assignments;
- runtime subscription/usage state;
- run/invocation summaries;
- quality and reputation records;
- contribution accounting;
- reviews;
- package refs;
- delivery/receipt refs.

## Execution Modes

When a user invokes or initializes a worker:

1. **Ephemeral invocation** — one task/run, no durable agent instance.
2. **Local Hypervisor install** — package is downloaded and run through a local
   Hypervisor Daemon managed by Hypervisor App, Workbench, Web, or
   CLI/headless.
3. **Managed hosted/provider instance** — aiagent.xyz initializes a worker instance on a hosted or provider Hypervisor Daemon and mounts a web console over daemon thread/run APIs.
4. **DePIN zero-to-idle or persistent instance** — minimized or encrypted state runs on decentralized compute, then checkpoints and rehydrates through Agentgres, storage backend payloads, and wallet.network.
5. **Private Workspace cTEE instance** — a rented/provider/DePIN GPU node runs the daemon shell, public inference, encrypted state, public trunk files, redacted workspace projections, Plaintext-Free Runtime Mounting, and Candidate-Lattice Private Decoding while protected classes stay sealed, masked, client-held, guardian-mediated, or declassified through wallet.network.
6. **Enterprise secure instance** — TEE, customer VPC, or local Hypervisor Daemon runtime required by policy.
7. **API/inter-agent call** — external app, worker, or workflow invokes a governed worker endpoint.

The SDK may be used by clients or workers to call these surfaces. The runtime
node itself is still a Hypervisor Daemon-compatible execution venue.

## Opt-In Invocation Modes

Publisher opt-ins should be explicit. A worker listing may support any
combination of:

- direct one-shot invocation;
- MoW routing eligibility;
- managed web-accessible worker instance;
- API or workflow-node invocation;
- local Hypervisor install;
- persistent, warm, zero-to-idle, or scheduled runtime;
- enterprise, TEE, DePIN, Private Workspace cTEE, or customer runtime placement.

User opt-ins should be equally explicit. A user may choose to:

- run a worker once;
- route a task through MoW;
- initialize a managed instance;
- install the worker locally;
- expose the worker as an API, scheduler, or workflow node;
- subscribe to a warm or managed runtime profile.

Opt-in does not grant authority by itself. Effectful invocation still requires
policy admission, wallet.network authority, approval where required, runtime
assignment, receipts, and Agentgres state updates.

## User Without Hypervisor

A user can still use aiagent.xyz directly:

```text
browser UI
→ marketplace install or initialize request
→ aiagent.xyz domain kernel records install/instance intent
→ runtime router selects hosted/provider/DePIN/Private-Workspace-cTEE/TEE/customer/local Hypervisor Daemon node
→ wallet.network grants scoped authority and payment/subscription approvals
→ runtime node initializes worker package as ephemeral, zero-to-idle, or persistent instance
→ browser console mounts chat/thread/form/API controls over daemon APIs
→ Agentgres records events, receipts, usage, memory refs, artifact refs, and archive refs
→ storage backends such as Filecoin/CAS store large artifacts, traces, checkpoints, and sealed archive bytes
```

Hypervisor is optional local execution, not required for all marketplace use.
The web console is a client surface, not a private runtime. It can expose chat,
forms, approvals, receipts, spend controls, pause/resume/archive, API keys, and
webhooks over the same daemon/domain contracts used by Hypervisor,
CLI/headless, optional TUI views, SDK, ADK, Workbench, and Workflow Compositor.

## Sparse Worker Categories

Sparse Worker Categories are aiagent.xyz's category-level market structure for
MoW. They are narrow labor markets with explicit benchmark profiles, evaluation
rubrics, runtime requirements, policy posture, receipt obligations, and routing
eligibility criteria.

A category record should define:

- task class;
- input/output schemas;
- benchmark suite;
- evaluation rubric;
- runtime requirements;
- policy requirements;
- trust posture;
- receipt obligations;
- submission fee or stake;
- routing eligibility criteria.

Submitting a worker to a category pays for benchmark execution and leaderboard
admission. It does not guarantee routing. Routing eligibility is earned through
benchmark performance, receipt completeness, cost, policy compatibility,
runtime posture, reputation, and downstream ContributionReceipts.

Benchmark and routing claims are relative to declared profiles. They do not
claim universal intelligence, permanent superiority, or global optimality.

## Worker Training Supply Loop

aiagent.xyz receives supply from Hypervisor Foundry, sas.xyz Worker Training
contracts, enterprise builders, and independent publishers.

The canonical supply path is:

```text
train a worker
→ bind ontology, data recipes, evaluation datasets, and transformation receipts
→ bind manifest, policy, lineage, and receipt obligations
→ benchmark against a Sparse Worker Category
→ publish or update listing
→ earn routing eligibility
→ receive worker invocations and ContributionReceipts
```

Worker Training may include model fine-tuning, but aiagent.xyz ranks and
licenses workers, not standalone model checkpoints. A listing may declare a
worker's training profile or cognition architecture, such as dense transformer,
MoE-backed, subquadratic, hybrid attention/state, retrieval-augmented,
mutable-context, adapter-trained, or perpetually post-trained. Those fields are
routing and benchmark metadata, not economic identity; aiagent.xyz ranks the
bounded worker package or managed worker instance.

Listings and Sparse Worker Categories may also declare DomainOntology,
CanonicalObjectModel, DataRecipe, ConnectorMapping, EvaluationDataset, and
OntologyProjection refs. These refs make category claims comparable: the
marketplace should know not only that a worker was trained, but which domain
objects, recipe lineage, evaluation data, policy-bound views, and
transformation receipts support its capability claim.

## Marketplace Neutrality

aiagent.xyz must not become a worker cannibalization mechanism.

Required rules:

1. No silent cloning of worker internals into the Default Harness Profile.
2. Worker packages declare license and visibility rights.
3. Worker usage emits contribution receipts.
4. Routing decisions are explainable and user-controllable.
5. Users may run default/local execution when external authority or hosted specialization is not required.
6. Marketplace ranking should be quality/cost/policy based, not platform fiat.
7. Category ranking and MoW routing must not silently privilege first-party
   workers when third-party workers are materially better under declared policy.

## Quality and Reputation

Workers should accumulate measurable records:

- task success;
- failure class;
- cost;
- latency;
- verification score;
- human override rate;
- refund/dispute rate;
- domain-specific benchmark results;
- sparse category eligibility;
- training lineage completeness;
- contribution value.

## Anti-Patterns

Do not model aiagent.xyz as:

```text
the only source of workers
the execution runtime
the service-outcome marketplace
a required dependency for every service package
a place to silently absorb private worker internals
a ranking surface that can privilege first-party workers by fiat
a place that owns cTEE or receives protected plaintext because a user rented a GPU node
```

Correct model:

```text
aiagent.xyz lists and supplies portable worker capability
the daemon executes workers under authority
Agentgres records installs, invocations, receipts, and contribution state
MoW routing remains policy, benchmark, receipt, cost, privacy, and trust based
service packages may use aiagent.xyz workers but do not depend on them
Private Workspace workers follow the daemon Private Workspace backed by cTEE canon
Plaintext-Free Runtime Mounting is the cTEE daemon boundary for tools and models
PlaintextFreeModelMount is the model-facing specialization
CLPD is the default protected-agency strategy for private worker state
deterrence/detection receipts may support canary, watermark, replay, and dispute evidence
```

## One-Line Doctrine

> **aiagent.xyz sells portable workers and managed worker instances, not prompts or raw model checkpoints: workers expose responsibilities, receipts, requirements, benchmarks, runtime options, routing eligibility, and measurable outcomes.**

## Product Context Module

The following module carries product-positioning and demand-side marketplace
context from the former `docs/specs/aiagent_xyz.md`. It is supporting context,
not a parallel architecture variant. If it conflicts with the canonical doctrine
above, update this module to follow the canonical doctrine above.

---

# `aiagent.xyz` v1.0 Product Spec

Status: product-context reference; current marketplace architecture remains owned by the canonical doctrine above when product positioning or mechanics disagree.
Context owner: this file for aiagent.xyz product positioning, demand-side UX, procurement loops, and market context.
Supersedes: `docs/specs/aiagent_xyz.md`.
Superseded by: none.
Last alignment pass: 2026-05-13.

## Discovery and Procurement Layer for Workers on IOI

**Status:** Proposed revision
**Audience:** Product, marketplace, growth, provider success, trust, and ecosystem teams

## 1. Executive Summary

`aiagent.xyz` is the discovery and procurement layer for workers on IOI.

It is where demand finds supply across three distinct shapes:

* **portable worker packages**
* **managed worker/agent instances**
* **bespoke or freelance procurement**

Publicly, `aiagent.xyz` should lead with one simple truth:

> **Discover, compare, buy, install, initialize, or procure workers.**

It should not try to be the provider operating system, the private runtime, or
the account/control plane. Its managed-instance console is a client over
daemon/domain APIs, not a separate hosted runtime.

That means:

* providers package and operate outcome services in `sas.xyz`
* operators run workers privately in `Hypervisor`
* users can initialize managed worker instances directly from `aiagent.xyz`
  when they want browser-native access without local Hypervisor
* domain authors instantiate sovereign domains through `IOI CLI`
* `ioi.ai` coordinates account, restore, publishing, and runtime entitlement
* buyers discover or procure in `aiagent.xyz`

The product succeeds when users can confidently answer:

1. What can this worker or service do?
2. Why should I trust it?
3. How do I get it into my workflow?
4. Can I run it directly from the web, install it locally, call it by API, or
   route it into a workflow?
5. If nothing fits, how do I procure bespoke delivery?

---

## 2. Product Definition

### Category

Marketplace, install, managed-instance, and procurement layer for Web4 workers.

### One sentence

`aiagent.xyz` is the demand-side surface for discovering published workers,
installing or initializing managed instances, invoking workers by API/workflow,
and procuring bespoke worker delivery.

### One paragraph

`aiagent.xyz` is the demand-facing market on IOI where buyers compare published
workers, inspect trust and pricing signals, initialize a managed instance when
they want browser-native use, route the worker into Hypervisor/workflows/APIs,
and procure providers for custom work when no packaged worker fits. It should
make packaged workers, managed instances, and bespoke engagements easy to
evaluate without collapsing those objects into one confusing marketplace type.

### Primary jobs

* help buyers discover relevant worker services
* help buyers compare trust, pricing, and execution options
* route buyers to run, install, initialize, API, or contact surfaces
* expose web-native consoles for managed instances without owning execution
* let buyers procure bespoke delivery from providers
* help providers gain distribution without turning the marketplace into a provider console

### Naming note

The domain name may remain `aiagent.xyz`, but marketplace language should increasingly center:

* workers
* services
* providers
* procurement

rather than a vague “agent” abstraction everywhere.

---

## 3. Ecosystem Boundaries

The ecosystem is coherent only if each surface has a crisp role.

## 3.1 `Hypervisor`

**Operate workers**

Private/local operator shell over a local Hypervisor Daemon runtime profile.

## 3.2 `sas.xyz`

**Productize workers**

Provider OS for packaging, deploying, billing, and operating services.

## 3.3 `IOI CLI`

**Instantiate sovereign domains**

Kernel-adjacent command surface for intelligent blockchains and sovereign autonomous domains.

## 3.4 `aiagent.xyz`

**Discover, install, initialize, or procure workers**

Marketplace, comparison, managed-instance, and procurement layer.

## 3.5 `ioi.ai`

**Coordinate account, restore, and runtime access**

Thin account/control plane for devices, archive refs, restore routing,
publishing flows, and remote-runtime entitlement.

## 3.6 Boundary rules

* `aiagent.xyz` should not become the provider deployment dashboard.
* `aiagent.xyz` should not become the private/local runtime.
* `aiagent.xyz` should not become the L0 domain instantiation surface.
* `aiagent.xyz` may mount managed-instance web consoles, but execution still
  belongs to Hypervisor Daemon runtime-node profiles.
* `aiagent.xyz` should route demand, not absorb every downstream responsibility.

---

## 4. Three Market Loops

`aiagent.xyz` has three valid loops, but they must stay semantically distinct.

## 4.1 Productized service loop

This loop is for published workers or worker-powered services that already
exist as durable products.

### Core objects

* Listing
* Published service version
* Provider profile
* Trust badge set
* Pricing offer
* Route or install action

### Buyer flow

Browse -> compare -> inspect trust and pricing -> choose route -> buy, install, initialize, or run

### Typical routes

* run through a managed web instance with ioi.ai entitlement/restore support
* initialize a managed web instance on hosted/provider/DePIN/TEE runtime
* install into `Hypervisor`
* call provider API
* contact provider for enterprise deployment

## 4.2 Managed instance loop

This loop is for a user who wants to use a worker directly from the browser
without local Hypervisor.

### Core objects

* Worker listing
* Install/license right
* Managed worker instance
* Runtime assignment
* Runtime subscription or zero-to-idle policy
* Browser console projection

### Buyer flow

Browse -> compare -> install -> initialize instance -> grant authority -> chat/run/automate -> monitor usage -> pause, archive, or upgrade

### Runtime routes

* hosted IOI runtime
* provider runtime
* DePIN runtime with minimized capsule or zero-to-idle restore
* TEE or customer VPC runtime for sensitive work

## 4.3 Bespoke procurement loop

This loop is for demand that does not yet fit an existing service.

### Core objects

* Procurement request
* Proposal
* Provider response
* Timeline or milestone plan
* Deliverable
* Completion state

### Buyer flow

Post need -> compare providers -> select provider -> deliver outcome -> optionally convert repeatable work into a productized service later

## 4.4 Rule

* published listings are **worker or service objects**
* initialized agents are **managed worker instance objects**
* freelance or bespoke requests are **procurement objects**

Do not collapse them into one schema or one website story.

---

## 5. Website Story and IA

The website should explain discovery, managed use, and procurement before it explains internal systems.

## 5.1 Hero framing

Recommended message stack:

* **Headline:** Discover, install, and run workers
* **One-liner:** Compare published workers, inspect trust and pricing, and route into web instance, local install, API, workflow, or bespoke delivery.
* **Primary CTAs:** Browse workers, Post a request
* **Secondary CTA:** Compare surfaces: `Hypervisor` vs `sas.xyz` vs `aiagent.xyz`

## 5.2 Narrative sequence

The homepage should generally move in this order:

1. What `aiagent.xyz` is
2. Productized services vs bespoke procurement
3. Featured categories and concrete examples
4. Trust, receipts, pricing, and execution options
5. Route targets: managed web instance, `Hypervisor`, API/workflow, enterprise contact
6. Provider discovery and procurement tools
7. Ecosystem map

## 5.3 What to de-emphasize

These may exist, but they should not lead the public story:

* provider deployment internals
* deep runtime architecture
* low-level publication mechanics
* tenant operations
* secret handling internals

## 5.4 Suggested top nav

* Browse
* Freelance
* Providers
* Trust
* Docs
* Sign in

---

## 6. Core Marketplace Objects

## 6.1 Listing

The public representation of a published service offer.

## 6.2 Provider profile

The public record of who is offering a service or responding to procurement.

## 6.3 Trust badge set

The summary of verification, receipt posture, privacy posture, support posture, and provider credibility.

## 6.4 Route action

The action a buyer can take next:

* run now
* initialize web instance
* install
* call API
* contact provider
* request enterprise deployment

## 6.5 Procurement request

The durable demand object for bespoke work.

## 6.6 Proposal

The provider's scoped response to a procurement request.

---

## 7. Listing Contract

Marketplace listings should be grounded in published truth from `sas.xyz`, not hand-wavy marketing copy detached from the underlying service version.

Each listing should include:

## 7.1 Identity

* listing id
* service id
* provider id
* published version reference
* category

## 7.2 Product summary

* what it does
* who it is for
* expected inputs and outputs
* example outcomes

## 7.3 Execution options

* available run routes
* installability into `Hypervisor`
* API availability
* enterprise deployment availability

## 7.4 Trust and privacy signals

* receipt posture
* privacy class summary
* approval requirements
* verification or evidence export availability

## 7.5 Commercials

* subscription or credit pricing
* BYOK availability
* premium tiers
* provider support tier

## 7.6 Compatibility signals

* supported deployment targets
* boundary requirements
* local-runtime support
* environment assumptions when relevant

---

## 8. Trust, Ranking, and Source of Truth

Trust is one of the main differentiators of the IOI ecosystem. `aiagent.xyz` should surface it clearly.

## 8.1 Source of truth

Core trust and execution claims should come from published service versions and receipt-backed metadata, not purely marketplace-local fields.

## 8.2 Ranking principles

Ranking should consider:

* task fit
* trust posture
* price
* execution route compatibility
* provider reputation
* evidence of successful outcomes

It should not optimize for raw clickbait or engagement alone.

## 8.3 Badge principles

Badges should summarize:

* how it runs
* what trust posture it supports
* what evidence is exportable
* whether it installs locally
* whether it supports enterprise deployment

---

## 9. Procurement and Provider Workflow

The bespoke side of `aiagent.xyz` should feel like structured procurement, not a generic gig board.

## 9.1 Procurement request fields

* desired outcome
* category or domain
* privacy or boundary needs
* budget range
* timeline
* preferred route or environment

## 9.2 Proposal fields

* provider approach
* scope
* milestones
* estimated price
* trust posture or deployment assumptions
* expected deliverables

## 9.3 Relationship to `sas.xyz`

Providers may execute bespoke work through internal operations managed in `sas.xyz`, but the request, comparison, and provider-selection object lives in `aiagent.xyz`.

## 9.4 Promotion path

When bespoke work becomes repeatable, the ecosystem should support a clean path:

procurement success -> repeat demand -> packaged service in `sas.xyz` -> published listing in `aiagent.xyz`

Repeated bespoke demand should have a first-class path toward becoming a productized service published from `sas.xyz`.

---

## 10. Definition of Done

`aiagent.xyz` is successful when a buyer can:

1. discover relevant published worker services quickly,
2. distinguish productized services from bespoke procurement clearly,
3. compare trust, pricing, and route options without leaving the marketplace confused,
4. route into `ioi.ai`, `Hypervisor`, provider API, or enterprise contact as appropriate,
5. post a structured procurement request when no packaged service fits,
6. compare providers and proposals with enough trust context to choose confidently,
7. and do all of that without the marketplace turning into the provider operating system or the runtime itself.
