# `sas.xyz` v1.2 Product Spec

## Provider Operating System for Service-as-Software on IOI

## 1. Executive Summary

`sas.xyz` is the **provider operating system** for building, packaging, deploying, governing, monetizing, and distributing **service-as-software** on IOI.

It is the provider-side surface where a team turns:

* a local/private workflow,
* a recurring assistant behavior,
* an OSS model pipeline,
* a BYOK-enabled service,
* a proprietary hosted model product,
* or a hybrid human+agent delivery stack

into a **portable service package** that can be:

* listed on `aiagent.xyz`,
* invoked from `ioi.ai`,
* installed into `Autopilot`,
* embedded into the provider’s own website or API,
* or deployed into a customer boundary (VPC / on-prem / local runtime).

The core thesis of `sas.xyz` is:

> **Build once, package once, deliver across execution targets and trust presets.**

A service is defined once, then exposed through one or more:

* execution targets,
* inference sources,
* trust postures,
* pricing models,
* and distribution surfaces,

under one common model for:

* policy,
* approvals,
* receipts,
* context slicing,
* deployment,
* and billing.

---

# 2. What `sas.xyz` Is

## 2.1 Product definition

`sas.xyz` is a **provider operating system**, not just a control plane and not just a deployment dashboard.

It owns the provider lifecycle for productized services:

* service authoring
* packaging and versioning
* deployment and runtime governance
* public and white-label API exposure
* tenant/customer operations
* billing and monetization
* receipts and evidence exports
* marketplace publication
* internal operations for managed delivery

## 2.2 What `sas.xyz` is not

It is not:

* the demand-side freelance marketplace
* the end-user intent UX
* the local runtime itself
* or the only place services can be used

Those roles belong to:

* `aiagent.xyz` for marketplace discovery and freelance procurement
* `ioi.ai` for intent and execution UX
* `Autopilot` for private local runtime and power-user building

---

# 3. Product Surfaces and Their Roles

## 3.1 `ioi.ai`

**Intent and execution UX**

The user says what they want.
`ioi.ai` selects, recommends, or dispatches the right service and execution preset, collects approvals, and shows outcomes plus receipts/evidence.

It is a user-facing **demand ingress**.

## 3.2 `aiagent.xyz`

**Marketplace**

The demand-side market for two distinct categories:

### A. Productized services

Install, run, buy, compare, or subscribe to packaged agent services.

### B. Freelance / bespoke procurement

Post work, solicit operator/provider responses, and choose a provider for custom delivery.

Important distinction:

* productized service listings are **service objects**
* freelance postings are **procurement objects**

`aiagent.xyz` owns the procurement/discovery layer, not provider operations.

## 3.3 `Autopilot`

**Local runtime + power-user builder + marketplace install surface**

Autopilot is the private local runtime. It can:

* run services locally
* use local GPU
* access desktop/browser/local files/apps
* hold local context and receipts
* install services from the marketplace
* and let power users build and fork workflows/services

Autopilot is where “private desktop assistant” and “local service runtime” meet.

## 3.4 `sas.xyz`

**Provider operating system**

The provider uses `sas.xyz` to:

* build/package services
* define contracts and deployment support
* configure execution targets and trust presets
* expose APIs
* manage customers and tenants
* manage receipts and compliance artifacts
* price and bill
* publish to marketplace
* and run provider-side delivery operations

---

# 4. Core Corrections Incorporated in v1.2

This spec incorporates the major corrections needed from prior discussion.

## 4.1 Agent IDE and Agent API are distinct

This is a key correction.

### Agent IDE

The Agent IDE is the **authoring engine**:

* compose workflows
* define services
* add models/tools/connectors
* package reusable graphs

### Agent API

The Agent API is the **invocation surface**:

* run a packaged service
* stream outputs
* retrieve receipts
* embed a service into a provider app or third-party platform

So:

> **Agent IDE builds services. Agent API exposes services.**

The Agent API is not “for the IDE.”

## 4.2 Private AI is a product surface, not a single lane

“Private AI” is not one execution method. It is a **user-facing surface** that can route into different execution targets and trust presets.

In practice, to avoid cold starts and poor UX, the default private AI product will often run on a **protocol-native hosted stack** with:

* API gateway/admission
* warm inference capacity
* distributed execution workers
* bounded kernel/coordinator plane
* receipts and policy enforcement

Then it can escalate into:

* local Autopilot
* BYOK
* clean-room execution
* confidential execution
* customer VPC
  when needed.

So “Private AI” is best understood as:

> **a privacy-first intent and execution surface over IOI-native infrastructure**

not as a single confidential or local-only lane.

## 4.3 Two loops are separate

There are two ecosystem loops:

### A. Productized Service Loop

Used by `sas.xyz` natively:

* build
* package
* deploy
* publish
* invoke
* bill
* support

### B. Bespoke Engagement Loop

Owned by `aiagent.xyz` procurement:

* demand posted or requested
* provider/operator responds
* delivery occurs via provider stack
* outcome delivered as bespoke work

Providers may use `sas.xyz` internally to help deliver freelance work, but freelance demand itself is **not** a `sas.xyz` service object.

## 4.4 Internal runtime model is axis-based, not lane-only

Lanes still exist in UX and commerce, but operationally the system is modeled by three axes:

1. **Where it runs**
2. **How inference is sourced**
3. **What trust/privacy posture applies**

Lanes are derived presets over these axes.

## 4.5 Scaling is multi-plane

The spec now explicitly assumes the hosted/default product path scales horizontally across planes:

* API / edge admission plane
* inference plane
* execution worker plane
* bounded kernel/coordinator/settlement plane

The kernel is **not** modeled as the place where every token of inference must happen.

---

# 5. Product Principles

## 5.1 Build once, deliver many ways

A provider should not need to rebuild a service to support:

* local use
* BYOK
* hosted OSS
* proprietary hosted
* confidential
* customer VPC

The packaging model should make these delivery modes configurable, not fundamentally separate products.

## 5.2 Local is first-class

Local Autopilot execution and local GPU are first-class targets.

## 5.3 Published truth must be portable

Drafts can be mutable and centralized. Published versions must be portable and verifiable through the IOI publication/trust layer.

## 5.4 Receipts are product

Receipts must be first-class because they power:

* trust
* debugging
* export
* compliance
* disputes
* marketplace differentiation

## 5.5 Privacy claims are execution-dependent

The same service may offer multiple privacy classes depending on execution target and trust posture. This must be explicit.

---

# 6. One Agent IDE Engine, Multiple Lenses

## 6.1 Canonical engine

There is one shared **Agent IDE engine**.

It supports:

* graph composition
* stateful execution
* resumable runs
* subgraphs
* approvals
* policy nodes
* context slicing
* model/tool nodes
* receipts
* deployment metadata

This one engine is rendered through multiple lenses.

## 6.2 Lens A — Autopilot lens

Optimized for:

* private local workflows
* recurring tasks
* local models and local GPU
* browser/desktop/app control
* marketplace install/run
* power-user to builder progression

Prominent concepts:

* tasks
* schedules
* local context
* local tools
* playbooks/lenses
* local inference choices
* local approvals
* marketplace install

De-emphasized:

* pricing
* public API contracts
* tenant ops
* SLA
* marketplace listing metadata

## 6.3 Lens B — `sas.xyz` lens

Optimized for:

* packaging a reusable service
* contract exposure
* API shape
* deployment support
* pricing
* tenant ops
* billing
* marketplace publication
* receipts export

Prominent concepts:

* service contract
* deployment matrix
* execution presets
* target support
* privacy/trust declarations
* pricing
* versions
* customers
* white-label APIs

De-emphasized:

* local-only task UX
* one-off private automations
* purely personal local memory views

## 6.4 Formats

The same engine supports several formats:

### Workflow format

General orchestration graph.

### Playbook format

Browser/desktop/app-control-centric graph, usually as receipted subgraphs or reusable artifacts.

### Service format

Workflow plus product contract:

* input schema
* output schema
* invocation model
* deployment support
* billing
* receipts profile

### API format

Public service exposure:

* request/response
* streaming
* auth model
* evidence export behavior

## 6.5 Promotion path

A private local graph can become a service.

**Autopilot private workflow**
→ stabilized graph
→ converted into Service format
→ opened in `sas.xyz` lens
→ configured for targets/pricing/publishing
→ published to marketplace or exposed as API

This is the intended path from power user to service provider.

---

# 7. Two Ecosystem Loops

## 7.1 Productized Service Loop

This is the primary `sas.xyz` loop.

### Core objects

* Service
* Manifest
* Version
* Deployment
* Tenant
* Listing
* Endpoint
* Run

### Flow

Author → package → configure targets/trust → deploy → publish → run → monetize → operate

### Examples

* cabin plans service
* docs agent
* Gmail executive assistant
* customer support agent
* legal review assistant
* coding/repo service

## 7.2 Bespoke Engagement Loop

This is demand-side procurement.

### Core objects

* Freelance request
* Proposal / response
* Provider/operator
* Deliverable
* Milestones
* Completion state

### Flow

Buyer posts need → provider responds → provider delivers outcome via their own internal stack

`aiagent.xyz` owns this loop.
`sas.xyz` may assist providers operationally, but does not define the demand object.

---

# 8. Core Object Model

## 8.1 Service

A reusable productized capability package with:

* contract
* runtime requirements
* trust declarations
* billing metadata
* distribution settings

## 8.2 Manifest

The canonical declaration for a service version.

## 8.3 Version

Immutable publishable snapshot of a service.

## 8.4 Project

Top-level grouping for services, deployments, environments, secrets, customers, and billing.

## 8.5 Deployment

A concrete instantiated runtime support configuration for a service version.

## 8.6 Tenant

Customer-specific config:

* policy overrides
* secrets bindings
* deployment target bindings
* lane entitlements
* sponsor rules

## 8.7 Run

A single execution instance of a packaged service.

## 8.8 Evidence Bundle

Portable export package:

* receipts
* policy refs
* approvals
* artifacts
* receipt roots
* allowed logs

---

# 9. Internal Execution Axes

This is the real operational model.

## 9.1 Axis 1 — Where it runs

* Local Autopilot
* Customer boundary (VPC/on-prem)
* Provider-hosted

## 9.2 Axis 2 — How inference is sourced

* Local model
* BYOK
* Provider OSS model
* Provider proprietary model

## 9.3 Axis 3 — Trust posture

* Standard
* Private
* Confidential
* Verified

## 9.4 Derived presets (lanes)

### Fast

Usually:

* local + local/BYOK
* hosted + BYOK
* hosted + warm worker
* standard/private posture

### Private

Usually:

* local
* customer boundary
* OSS clean-room
* private posture

### Confidential

Usually:

* hosted or customer-boundary with confidential support

### Verified

An overlay requiring stronger receipts/proofs.

---

# 10. Execution Targets

Each service declares supported targets.

## 10.1 Local Autopilot

Use when:

* local files/apps/browser are needed
* local GPU is beneficial
* strongest sovereignty is desired
* or customer wants no hosted execution dependency

## 10.2 BYOK

Use when:

* low-latency chat or interactive loops matter
* customer already has provider keys/contracts
* provider wants lower compute burden

## 10.3 Provider-hosted OSS clean room

Use when:

* jobs are batch or artifact oriented
* privacy is important
* cold starts are acceptable
* provider wants to monetize compute

## 10.4 Provider-hosted proprietary model

Use when:

* the service depends on proprietary weights or hosted model IP
* local distribution is not possible
* provider controls execution

## 10.5 Confidential hosted

A trust overlay on hosted targets, used when stronger remote privacy guarantees are offered.

## 10.6 Customer VPC / on-prem

Use when:

* compliance/residency/internal integrations matter
* enterprise wants managed service inside its own boundary

---

# 11. Privacy Classes

Every service + target + trust posture combination must declare:

## P0 — Execution-private, inference-visible

IOI governs tools, secrets, and side effects, but the hosted model provider/operator may see authorized prompt/context.

## P1 — Confidential remote

Customer data is protected from infrastructure operators, and possibly service operators, via confidential execution.

## P2 — Boundary-private

Data remains within local Autopilot, customer VPC, or on-prem boundary.

These must be shown accurately per execution preset.

---

# 12. Proprietary Model Policy

For proprietary-model services, `sas.xyz` requires explicit declarations for:

* hosted support
* BYOK support
* confidential support
* local support
* customer VPC support
* retention policy
* training/logging policy
* operator visibility

### Important rule

Heavy proprietary models should generally be exposed as:

* hosted
* confidential hosted
* BYOK
* or customer-boundary hosted

not as “local sealed wasm” except for small helper components.

---

# 13. Deployment Architecture

## 13.1 Four planes

The hosted system must be modeled as multiple planes.

### Plane A — API / admission / edge

Handles:

* auth
* rate limiting
* request normalization
* routing
* session admission
* load balancing

Horizontally scalable.

### Plane B — Inference plane

Handles:

* cheap models
* reasoning models
* embeddings
* rerankers
* local/open-source model workers
* BYOK routing

Horizontally scalable by pool.

### Plane C — Execution / service worker plane

Handles:

* workflow steps
* tool execution
* browser/runtime jobs
* connector calls
* artifact generation
* receipt emission

Horizontally scalable with queues and idempotent scheduling.

### Plane D — Kernel / coordinator / settlement plane

Handles:

* canonical state transitions
* policy commitments
* approvals
* receipt roots
* publication state
* execution checkpoints
* final truth/auditability

Capacity-governed. Not treated like stateless web workers.

## 13.2 Coordinator role

The **Coordinator** is the always-on runtime control role. It holds:

* run state
* policy bundles
* tenant config
* receipts
* secrets references
* SCS strategy selection
* worker dispatch state

It is the **execution control role**, not the SaaS UI.

## 13.3 Coordinator ownership modes

### Managed Coordinator

Hosted by provider or provider-managed infra.

### Boundary Coordinator

Runs inside customer VPC/on-prem boundary.

### Local Coordinator

Embedded inside Autopilot.

## 13.4 Customer VPC rule

For customer-boundary execution, `sas.xyz` must not directly orchestrate raw workers across the open boundary. Instead, a boundary coordinator is deployed inside the customer environment. `sas.xyz` interacts with it through an authenticated control channel.

---

# 14. Publication and AIIP

## 14.1 Publication states

### Draft

Mutable, only visible in `sas.xyz`.

### Preview

Sharable, installable for testing, may still depend on `sas.xyz` APIs.

### Published immutable

Canonical service version, published to IOI’s immutable publication layer.

## 14.2 Source of truth

* Drafts and previews: `sas.xyz`
* Published immutable versions: AIIP/canonical publish layer

## 14.3 AIIP mapping

Each published service version maps to an AIIP-style identifier:
`ai://<authority>/<service>/<version>`

The record resolves to:

* manifest hash/CID
* artifact refs
* target/trust declarations
* optional marketplace metadata refs

## 14.4 Install token behavior

`/install-token` is an authorization envelope, not the canonical manifest.

### Published services

Autopilot should:

1. receive token
2. resolve AIIP version
3. fetch manifest/artifacts
4. verify signatures/hashes
5. install locally

### Draft/preview installs

Token may point to preview APIs until publication.

---

# 15. Artifact Delivery Pipeline

## 15.1 `sas.xyz` role

`sas.xyz` is primarily a **registry manager and control plane**, not necessarily the permanent blob host.

## 15.2 Artifact hosting modes

### Mode A — `sas.xyz` managed pinning/hosting

`sas.xyz` uploads or pins artifact blobs.

### Mode B — Provider-hosted artifacts

Provider stores artifacts externally and supplies immutable hashes/pointers.

### Mode C — Hybrid

Portable/public parts via `sas.xyz`; proprietary/private artifacts provider-hosted.

## 15.3 Proprietary hosted model rule

For proprietary hosted models, `sas.xyz` does not need raw weights. It stores:

* endpoint descriptors
* version identity
* trust/privacy declarations
* attestation requirements
* optional bootstrap metadata

---

# 16. Sovereign Context Strategy

SCS is for agent/user considerations and execution context, not the same thing as product/control-plane storage.

Three modes are supported.

## 16.1 Local SCS

Used by:

* Autopilot
* boundary/private deployments
* local GPU/private assistants

## 16.2 Tethered SCS / TFEC

Default for private remote execution.

Workers receive:

* context slices
* retrieval artifacts/proofs
* ephemeral indices as needed

This is the private-remote default.

## 16.3 Managed Tenant SCS

Provider-hosted tenant-scoped SCS for low-latency recurring services.

Used by:

* docs assistants
* support agents
* managed recurring copilots
* API-first services needing warm context

### Default posture

* Fast hosted: managed tenant SCS
* Private remote: tethered slices / TFEC
* Local: local SCS

---

# 17. White-Label Execution Boundary

Each white-label run must track four identities.

## 17.1 Principal

Who authorizes the work / access.

## 17.2 Sponsor

Who pays.

## 17.3 Provider

Who offers the service.

## 17.4 Guardian

Who signs execution boundary and non-equivocation receipts.

### Rule

The Guardian is always the coordinator/kernel that actually mediated execution:

* local coordinator,
* boundary coordinator,
* or managed coordinator.

It is not merely the frontend or provider web server.

## 17.5 Liability and billing implications

Every white-label run must record:

* `principal_id`
* `sponsor_id`
* `provider_id`
* `guardian_id`

This separates:

* who approved
* who paid
* who ran
* who breached policy, if applicable

---

# 18. Secrets and Credential Flow

## 18.1 Secret classes

### Customer-owned

* BYOK model keys
* connector credentials
* internal tenant secrets

### Provider-owned

* proprietary model endpoint creds
* provider infra secrets
* provider webhooks

## 18.2 Source of truth

### Customer-owned secrets

Must originate from:

* wallet.network
* Autopilot local vault
* customer boundary vault

### Provider-owned secrets

Must originate from:

* provider vault
* or boundary-specific provider deployment vault

## 18.3 Injection by target

### Local

Secrets injected locally.

### Customer boundary

Secrets leased inside boundary by boundary coordinator.

### Confidential hosted

Secrets sealed to attested runtime if supported.

### Standard hosted

Secrets may still be sourced from wallet/network bindings, but this does not imply provider-blind visibility unless the lane supports it.

## 18.4 BYOK nuance

BYOK is not one privacy class.

* local BYOK: strong privacy
* customer VPC BYOK: strong
* confidential hosted BYOK: strong remote posture
* standard hosted BYOK: fast, but not fully provider-blind unless explicitly designed so

---

# 19. Information Architecture

## 19.1 Top-level nav

* Overview
* Services
* Agent IDE
* Deployments
* Customers
* Receipts
* Billing
* Marketplace
* Settings

## 19.2 Overview

Shows:

* service inventory
* target usage
* trust posture usage
* lane usage
* deployment health
* cold-start pressure
* receipts errors
* cost by target/lane
* revenue trends

## 19.3 Services

Each service page includes:

* manifest
* versions
* contract
* target matrix
* trust/posture matrix
* pricing
* APIs
* listing state

## 19.4 Agent IDE

Shared engine in `sas.xyz` lens.

Key panels:

* graph canvas
* service contract panel
* execution preset matrix
* target support matrix
* privacy/trust declaration panel
* deployment preview
* listing publication controls
* endpoint/API config

## 19.5 Deployments

* environments
* rollout controls
* version pinning
* secrets
* boundary deployment packages
* confidential settings
* rollback

## 19.6 Customers

* tenants
* orgs
* secret bindings
* policy overrides
* lane/target entitlements
* sponsor rules
* residency rules

## 19.7 Receipts

* run explorer
* receipt timeline
* evidence bundle export
* proof viewer
* dispute prep

## 19.8 Billing

* subscriptions
* credits
* execution fees
* confidential premiums
* take rates
* invoices

## 19.9 Marketplace

* listing editor
* trust/privacy badge preview
* installability matrix
* public metadata preview
* white-label redirect config

---

# 20. Agent IDE Builder Spec

## 20.1 Philosophy

Workflow-first. Browser/desktop/app control appears as typed actions or playbook/lens artifacts.

## 20.2 Node families

### Triggers

* API/webhook
* schedule
* event
* manual/test
* marketplace install/run trigger
* Autopilot trigger

### Control

* route
* condition
* retry/recover
* fanout
* aggregate
* subgraph
* human gate

### Context

* load slices
* retrieval
* redact/minimize
* persist context
* summarize

### Agent/model

* prompt
* model call
* structured extraction
* planner
* evaluator

### Action

* browser
* filesystem
* exec
* connectors
* service call / agent-as-tool call
* artifact export

### Verification

* assert postcondition
* emit receipt
* receipt root checkpoint
* export evidence bundle

## 20.3 Lens-specific palettes

### Autopilot

Emphasizes:

* local tools
* browser/desktop
* playbooks
* local models/GPU
* schedules/tasks
* marketplace install/run

### `sas.xyz`

Emphasizes:

* service contract
* API endpoints
* target/trust selection
* billing nodes
* tenant nodes
* deployment nodes
* listing metadata

---

# 21. Service Manifest v1.2

Each service manifest must include:

## 21.1 Identity

* `service_id`
* `provider_id`
* `name`
* `version`
* `description`
* `category`

## 21.2 Contract

* `input_schema`
* `output_schema`
* `run_modes`
* `artifact_types`

## 21.3 Capabilities

* `action_targets`
* `connectors_required`
* `desktop_required`
* `domain_allowlists`
* `approval_requirements`
* `spend_limits`

## 21.4 Execution support

* supported execution targets
* supported inference sources
* supported trust postures
* derived supported lanes
* local hardware requirements
* proprietary model constraints

## 21.5 Privacy contract

* privacy class per target/posture
* retention policy
* training/logging policy
* operator visibility
* minimum context policy

## 21.6 Verification contract

* RRS-I profile
* optional RRS-A requirements
* proof/retrieval mode
* artifact commit mode
* evidence export formats

## 21.7 Commercials

* subscription support
* credit pricing
* BYOK fees
* confidential premium
* take rate
* public pricing terms

## 21.8 Distribution

* marketplace publishable?
* discoverable via `ioi.ai`?
* installable into Autopilot?
* white-label API enabled?

---

# 22. Example Service Patterns

## 22.1 Cabin Plans AI

May already exist as:

* local workflow
* BYOK app
* hosted generation pipeline

`sas.xyz` should allow:

* white-label provider site/API
* local Autopilot install
* provider clean-room generation
* marketplace listing

Typical presets:

* Fast: BYOK ideation
* Private: local or OSS clean-room final generation
* Verified: final deliverable with evidence export

## 22.2 Documentation Agent

Distinct product variants:

1. tradable capability / market product
2. interactive docs chat
3. per-tenant isolated indexing and retention
4. API-first docs service

All should be expressible without forcing a single deployment model.

## 22.3 Gmail Executive Assistant

Can support:

* local Autopilot
* BYOK
* managed hosted
* customer boundary

## 22.4 Customer Support Agent

Likely:

* Fast + BYOK or hosted warm workers
* managed tenant SCS
* optional private deployments

## 22.5 Coding / Repo Agent

Strong fit for:

* local Autopilot
* team automation
* CI/VPC deployment

## 22.6 Proprietary Vertical Copilot

Likely supports:

* hosted
* confidential hosted
* BYOK
  not necessarily local.

---

# 23. API Surface

## 23.1 Run API

* `POST /runs`
* `GET /runs/:id`
* `GET /runs/:id/stream`
* `GET /runs/:id/receipts`
* `GET /runs/:id/evidence-bundle`

## 23.2 Service API

* `GET /services`
* `GET /services/:id`
* `GET /services/:id/manifest`
* `POST /services/:id/install-token`

## 23.3 Tenant API

* `POST /tenants`
* `POST /tenants/:id/policies`
* `POST /tenants/:id/secret-bindings`
* `GET /tenants/:id/usage`

## 23.4 Listing API

* `POST /listings`
* `PATCH /listings/:id`
* `POST /listings/:id/publish`
* `GET /listings/:id/badges`

---

# 24. Billing and Monetization

## 24.1 Pricing primitives

### Subscription

For:

* seats
* retention
* deployment quotas
* support tiers

### Credits

For:

* runs
* worker minutes
* artifact generation
* proof premium
* confidential premium

### Take rate

For marketplace or embedded commerce participation.

## 24.2 Preset-aware billing

* Fast: low-friction, often BYOK or warm worker pricing
* Private: worker/artifact based
* Confidential: premium
* Verified: proof/export premium

---

# 25. Observability and Compliance

## 25.1 Observability

`sas.xyz` must expose:

* run logs
* receipts timeline
* queue depth
* target/lane cost
* worker saturation
* cold-start pressure
* deployment health
* approval bottlenecks

## 25.2 Compliance

Must support:

* RBAC
* SSO/SAML
* secret scoping
* tenant isolation
* retention controls
* evidence exports
* policy-change audit logs

---

# 26. Best-Practice Defaults

## 26.1 Publication

* drafts in `sas.xyz`
* immutable published versions in AIIP/canonical publish layer

## 26.2 Secrets

* customer secrets from wallet.network / Autopilot / customer vault
* provider secrets from provider vault
* no raw secrets in publish layer

## 26.3 Context

* local lane: local SCS
* private remote: tethered slices / TFEC
* fast hosted: managed tenant SCS

## 26.4 IDE

* one engine
* different lenses
* workflow-first
* promote private graphs into services

## 26.5 Marketplace relation

* services publish from `sas.xyz`
* freelance remains procurement in `aiagent.xyz`
* providers may use `sas.xyz` operationally for bespoke work, but that is internal ops, not marketplace demand definition

---

# 27. Definition of Done

`sas.xyz` v1.2 is complete when a provider can:

1. author a graph once in the shared Agent IDE engine,
2. switch between Autopilot and `sas.xyz` lenses without changing runtime semantics,
3. package that graph as a service,
4. declare execution targets, inference sources, trust postures, and derived lane presets,
5. deploy it in managed, local, or customer-boundary environments,
6. publish immutable versions into the canonical publication layer,
7. expose the service through marketplace, `ioi.ai`, Autopilot install, and/or white-label API,
8. manage tenants, secrets, billing, receipts, and evidence in one provider OS,
9. and do all of that while keeping privacy claims accurate to the actual execution target and trust posture.