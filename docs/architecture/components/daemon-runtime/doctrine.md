# IOI CLI / Daemon Runtime Specification

Status: canonical architecture authority.
Canonical owner: this file for daemon/CLI ownership boundaries and IOI CLI operator-surface positioning; low-level daemon endpoints live in [`ioi-daemon-runtime-api.md`](./api.md).
Supersedes: older CLI/daemon wording that implies the CLI owns runtime semantics or is primarily a chain/domain generator.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Canonical Definition

**The IOI daemon is the universal execution endpoint for canonical Web4 work.**

**`ioi-cli` is the canonical local/operator interface to IOI runtimes,
domains, manifests, receipts, authority scopes, and mainnet/application-domain
interactions.**

The IOI CLI is a terminal/TUI client over daemon/public runtime APIs and the
broader canonical Web4 stack. It may mirror daemon commands, render operator
workflows, resolve natural-language intent into inspectable plans, and
administer domain/settlement/authority surfaces. The CLI must not own a separate agent runtime or execution loop.

Through daemon APIs, it launches workflows, agents, workers, tools, models,
connectors, and artifact-producing jobs across local, hosted, provider, DePIN,
TEE, and enterprise environments.

## CLI Operator Surface

The CLI should feel like the structured operator shell for the whole IOI/Web4
stack, not primarily like a chain/domain generator.

One-line positioning:

> **`ioi-cli` resolves operator intent into inspectable plans, invokes IOI
> daemon runtimes, manages Agentgres domains, binds wallet.network authority
> scopes, publishes `ai://` manifests, verifies receipts, and interacts with
> IOI L1 settlement contracts.**

The CLI can be natural-language capable, but structured plans, canonical
commands, manifests, receipts, and replayable execution remain durable truth.

### Core Command Families

```text
ioi runtime
  local/hosted/depin/tee node operations

ioi agent
  worker install/run/status/inspect

ioi service
  sas.xyz service order/delivery/acceptance/dispute

ioi domain
  Agentgres domain init/status/migrate/export/import

ioi agentgres
  query/project/receipt/projection/admin

ioi wallet
  authority scope request/grant/revoke/approve

ioi ai
  ai:// resolve/register/publish/verify

ioi l1
  contract calls, escrow, license, dispute, bond, settlement

ioi artifact
  inspect/verify/materialize/fetch/publish

ioi receipt
  inspect/verify/export/bundle

ioi model
  mount/list/route/benchmark

ioi connector
  bind/list/test/revoke

ioi forge
  advanced domain/kernel scaffolding only
```

`forge` remains an advanced namespace for domain/kernel scaffolding. It is not
the primary identity of the CLI.

### Intent Resolution Contract

Natural-language CLI input must resolve into:

```text
operator intent
→ candidate plan
→ explicit execution path
→ preview/dry-run when mutation is possible
→ canonical command/envelope
→ authority/policy decision
→ daemon/domain/L1 action
→ receipts, trace, and replay/export
```

The CLI should surface local/BYOK/managed/TEE/DePIN routing, model/key/provider
availability, privacy, cost, latency, and authority implications before it
crosses trust boundaries.

### Autopilot Bridge

Autopilot may emit typed artifacts, manifests, receipts, evidence plans, and
CLI-compatible workflow/domain packages. The CLI may inspect, validate,
materialize, promote, publish, route, or verify them through daemon and
Agentgres APIs. The CLI does not become the Autopilot runtime.

## Runtime Role

The daemon executes work. It does not own root authority or global marketplace state.

It is responsible for:

- starting runs;
- pausing/resuming/canceling runs;
- executing workflow nodes;
- invoking model router;
- calling tools/connectors;
- producing artifacts;
- emitting events and receipts;
- enforcing policy/firewall gates;
- requesting wallet authority scopes;
- syncing outputs to Agentgres;
- fetching packages from Filecoin/CAS;
- streaming status to apps.

## Deployment Targets

1. **Local Autopilot daemon** — desktop/private execution.
2. **Hosted IOI daemon** — always-on hosted workers/services.
3. **Provider daemon** — service provider infrastructure.
4. **DePIN daemon** — Akash-like public compute.
5. **TEE-verified daemon** — enterprise secure mode.
6. **Customer VPC daemon** — enterprise private runtime.

## Public Runtime API

Minimum API surface:

```http
GET  /v1/runtime/manifest
GET  /v1/runtime/health
POST /v1/workers/install
GET  /v1/workers/{id}
POST /v1/runs
GET  /v1/runs/{id}
GET  /v1/runs/{id}/events
GET  /v1/runs/{id}/artifacts
GET  /v1/runs/{id}/receipts
POST /v1/runs/{id}/pause
POST /v1/runs/{id}/resume
POST /v1/runs/{id}/cancel
GET  /v1/deliveries/{id}
```

CLI surface should mirror the API:

```bash
ioi agent run <goal>
ioi agent status <run_id>
ioi agent events <run_id>
ioi agent trace <run_id>
ioi agent export <run_id>
ioi agent verify <run_id>
ioi agent approve <run_id> <request_hash>
ioi agent cancel <run_id>
ioi runtime doctor
ioi tools list
ioi models list
```

CLI command handlers should stay thin: they may submit runtime requests, stream
events, render traces, and collect approvals, but daemon/runtime code owns
execution semantics, policy gates, receipts, replay, and canonical state updates.

## Runtime Envelopes

The daemon should use stable envelopes:

```text
RunRequest
TaskCapsule
RuntimeToolContract
AgentRuntimeEvent
AuthorityScopeRequest
PolicyDecision
ModelInvocationReceipt
ToolExecutionReceipt
ArtifactRef
ReceiptBundle
DeliveryBundle
QualityRecord
```

These envelopes must be stable across local, hosted, marketplace, CLI, UI, workflow, and benchmark surfaces.

## Event Model

The daemon should emit typed replayable events:

```text
session.started
turn.started
context.prepared
model.requested
model.completed
tool.proposed
policy.decided
approval.requested
tool.started
tool.progress
tool.completed
artifact.created
receipt.emitted
run.completed
run.failed
run.cancelled
```

Events are not canonical by themselves; persisted settlement state and receipts are authoritative.

## Relationship to Agentgres

The daemon writes/updates domain state through Agentgres-compatible APIs:

- run state;
- artifacts;
- receipts;
- delivery bundles;
- quality ledgers;
- worker invocations;
- contribution receipts.

The daemon must not maintain a separate canonical state store for application truth.

## Relationship to wallet.network

The daemon requests authority scopes from wallet.network.

It must not receive raw long-lived secrets where a scoped authority grant or operation-internal execution is possible.

Sensitive actions require:

- policy decision;
- authority lease;
- approval token when needed;
- exact request hash;
- expiry;
- revocation epoch.

## Runtime Privacy Modes

1. **Local/private** — local Autopilot, customer machine.
2. **Mutual Blind** — no TEE; redacted/minimized capsules, no final authority.
3. **Enterprise Secure** — TEE-attested node; sealed secret release.
4. **Hosted trusted** — IOI/provider-managed runtime under contractual trust.

## Invariants

1. No effectful tool execution without a tool contract and risk class.
2. No sensitive action without a persisted policy decision.
3. No policy-required approval without exact-scope approval token.
4. No raw secret exposure to agents.
5. No final effect from untrusted DePIN nodes without trusted verification/settlement.
6. No split runtime path for workflow vs agent vs benchmark vs CLI execution.
7. No long-running job without deadline, cancellation, and progress events.

## One-Line Doctrine

> **The IOI daemon is where Web4 work executes; Agentgres remembers it, wallet.network authorizes it, and IOI L1 settles what matters.**

## Preserved Partially Superseded CLI Spec Module

The following module preserves the detailed `IOI CLI` v1.1 product-spec context from the former `docs/specs/ioi-cli.md`. It is retained for command-family, natural-language-to-plan, artifact, evidence, receipt, policy, publish, and execution-path details. Its old chain/domain-generator framing is partially superseded: the canonical doctrine above wins wherever this preserved module implies that the CLI is primarily an intelligent-blockchain or sovereign-domain creation surface.

---

# `IOI CLI` v1.1 Product Spec

## Canonical Command Line for the Web4 L0

**Status:** Proposed revision
**Audience:** Kernel, protocol, developer tooling, publication, identity, settlement, and ecosystem teams

## 1. Executive Summary

`IOI CLI` is the canonical command line for authoring, instantiating, publishing, upgrading, and inspecting intelligent blockchains and other sovereign execution domains on IOI.

It should not feel like a narrow chain-deployment tool.

It should feel like the canonical toolchain for:

* bootstrapping a sovereign execution network
* translating high-level operator intent into kernel-native objects
* defining the trust, policy, and identity roots of that network
* publishing worker and service classes into that network
* constraining machine labor through capability, approval, and evidence rules
* inspecting receipts, traces, and settlement-linked outcomes
* upgrading the domain over time without losing continuity or authority

The current implementation should begin **command-line first**, stay close to the kernel, identity, publication, and settlement layers, and grow into a natural-language-capable surface without abandoning explicit structured commands. The present `crates/cli` surface is the natural starting point for this direction.

`forge` still matters inside this system, but it should be treated as:

* a command namespace
* a verb
* a capability family
* a tagline for domain creation

It should not be the primary product name for the whole surface.

`IOI CLI` should likely become natural-language capable, but it should not become natural-language only.

The right shape is:

* natural language for ergonomic intent capture
* explicit plans for inspection and confirmation
* canonical commands, manifests, and receipts as the durable truth

> **`IOI CLI` is the canonical command line for the Web4 L0. It should make it natural to express intent in plain language or structured commands, resolve that intent into inspectable plans and manifests, instantiate a sovereign execution network, prove what happened, and settle verified machine labor under explicit policy.**

---

## 2. Why Web4 Changes the CLI

Web3 mostly made value and state programmable.

Web4 should make action programmable, governable, and economically native.

That changes what a chain is for.

The chain is no longer only:

* a replicated state machine
* a transaction settlement layer
* a ledger with programmable contracts

It becomes:

* a replicated state machine
* plus a governed execution fabric
* plus an evidence and liability system
* plus a marketplace for verifiable machine labor

The CLI should therefore optimize for a different primitive:

> **instantiate an economy of verifiable workers and services around a state machine**

That means `ioi chain init` or `ioi forge init` should conceptually be closer to:

* bootstrap consensus
* define trust and identity roots
* define action policy and approval semantics
* define worker and service classes
* define evidence and receipt requirements
* define settlement for digital labor

It should not stop at “make ledger.”

---

## 3. Naming Doctrine

Use `IOI CLI` as the primary name, and use `forge` inside it.

This naming is stronger because it is:

* blunt and clear about the interface
* architecturally consistent with `Autopilot` and `sas.xyz`
* extensible as the command surface grows
* less ambiguous than spending the top-level product name on a single metaphor

`IOI CLI` should read like the canonical interface to the underlying Web4 L0 system, not like a separate semi-mythical developer brand.

That gives room for strong command families such as:

* `ioi forge`
* `ioi chain`
* `ioi worker`
* `ioi service`
* `ioi policy`
* `ioi evidence`
* `ioi publish`
* `ioi verify`

---

## 4. Product Definition

### Category

Canonical command-line surface for Web4 L0 domain authoring, intelligent blockchain instantiation, and sovereign execution-network operations.

### One sentence

`IOI CLI` is the kernel-adjacent command surface for creating intelligent blockchains as sovereign execution networks that govern, verify, and settle programmable machine labor under explicit policy through both structured commands and natural-language intent resolution.

### One paragraph

`IOI CLI` is the builder and operator surface for creating durable sovereign execution domains when a workflow or worker system needs more than service packaging. It owns domain scaffolding, policy roots, authority and delegation structure, worker and service classes, capability and evidence constraints, publication behavior, kernel-native commitments, settlement-linked receipts, upgrade semantics, and the translation of user intent into canonical kernel-native plans. It should feel closer to an execution-economy toolchain than to a thin chain deployer: developer-grade, protocol-aware, scaffolding-heavy, and rooted in the kernel's actual publication, identity, evidence, settlement, and execution-path semantics.

### Current implementation posture

`IOI CLI` should begin as:

* command-line first
* natural-language capable
* kernel-adjacent
* identity-aware
* publication-aware
* evidence-aware
* previewable before mutation
* auditable after execution
* structured underneath for truth
* developer/operator facing

Later, it may grow richer IDE or visual surfaces, but the canonical first interface should stay close to `ioi` and the underlying kernel.

---

## 5. Ecosystem Role

The ecosystem becomes cleaner when the fifth distinct surface is named `IOI CLI`, with `forge` treated as a command namespace inside it.

## 5.1 `Autopilot`

**Operate and stabilize**

Private/local operator shell for workers, workflows, approvals, receipts, evidence, and service candidates.

## 5.2 `IOI CLI`

**Author at the kernel boundary**

Kernel-adjacent L0 surface for intelligent blockchains, sovereign execution networks, labor-market primitives, identity roots, policy bundles, evidence thresholds, publication, upgrades, and natural-language intent resolution over canonical command families.

`forge` is one of its major command families, not a separate product.

## 5.3 `sas.xyz`

**Productize and serve**

Provider OS for packaging, deploying, serving, and commercializing worker services, including intelligent-blockchain-backed services when those domains are exposed as provider products.

## 5.4 `aiagent.xyz`

**Discover or procure**

Discovery and procurement surface for productized worker services and bespoke demand.

## 5.5 `ioi.ai`

**Use through hosted demand UX**

Intent ingress and hosted execution UX.

## 5.6 Boundary rules

* `Autopilot` is where worker systems are built, operated, supervised, and stabilized privately.
* `IOI CLI` is where sovereign domains and intelligent blockchains are formally instantiated as execution economies.
* `forge` is a major namespace within `IOI CLI`, not the name of a separate top-level surface.
* `sas.xyz` is where services, including intelligent-blockchain-backed services, are packaged, deployed, served, and commercialized.
* Not every stabilized worker system should become an intelligent blockchain.
* Not every intelligent blockchain should be commercialized through `sas.xyz`.

**Doctrine:** `IOI CLI` creates the sovereign execution object. `Autopilot` refines the worker system. `sas.xyz` serves and commercializes it when it becomes a provider product.

---

## 6. When to Use `IOI CLI`

Use `IOI CLI` when a system needs to become a durable sovereign execution domain rather than just a service candidate or provider service.

Typical reasons include:

* durable sovereign state matters
* publication and continuity matter
* policy roots must be explicit and durable
* identity and delegation trees need durable definition
* many workers, providers, or participants need coordination
* evidence, dispute, or liability semantics are first-class
* settlement for verified digital labor must be explicit
* the system is becoming a protocolized autonomous domain
* external action surfaces must be governed beyond a single local shell

Do **not** make every workflow or service candidate an intelligent blockchain by default.

---

## 7. Product Ladder and Promotion Paths

The weight of a sovereign domain should be preserved.

## 7.1 Base ladder

1. Workflow
2. Stable worker or service candidate
3. Provider service in `sas.xyz` when service packaging and commercialization are the right move
4. Intelligent blockchain / sovereign execution domain in `IOI CLI` when durable domain semantics, labor coordination, or settlement semantics are needed

## 7.2 Practical branch model

In practice, the ladder is not a strict one-way chain. A stable worker system may branch:

* into `sas.xyz` for provider-grade packaging and serving
* into `IOI CLI` for intelligent-blockchain or execution-domain instantiation
* and, if an `IOI CLI` domain later needs provider exposure, back into `sas.xyz` as an intelligent-blockchain-backed service

## 7.3 Promotion doctrine

`Autopilot` workflows may absolutely compile toward `IOI CLI`-compatible artifacts.

That does **not** mean `Autopilot` should be the primary product for creating intelligent blockchains. `IOI CLI` is the heavier L0-native surface for that act.

---

## 8. Core Thesis

The core experiential shift should be:

### Web3 CLI

* deploy a chain
* deploy contracts
* send transactions
* query state

### Web4 CLI

* deploy a sovereign execution network
* publish workers and services into it
* define who or what may act
* prove what happened
* settle verified outcomes
* continuously govern machine labor

In that model:

* chain creation becomes labor-market creation
* smart contracts evolve into service contracts
* app deployment becomes digital-workforce deployment
* wallets evolve into sovereign IAM and labor control centers
* block explorers evolve into evidence explorers
* rollups evolve into execution domains
* tokens evolve into trust-coordination and labor-routing primitives
* DAOs evolve into operational sovereigns
* marketplaces evolve into agent and service economies

---

## 9. Command Model, Intent Resolution, and Why CLI-First Is Right

This surface is closer to:

* kernel semantics
* publication roots
* identity and delegation trees
* evidence contracts
* protocol topology
* domain instantiation
* settlement machinery
* upgrade and continuity semantics

than to consumer or operator UX.

A CLI-first interface is therefore the correct first expression.

The command hierarchy should spend clarity at the top level and reserve metaphorical names for the right subcommands.

It should support two equivalent entry modes:

* explicit structured commands for repeatable expert use
* natural-language intent capture for discovery, scaffolding, repair, and plan generation

Structured CLI remains the canonical truth even when the session begins in natural language.

## 9.1 Natural-language front door

The CLI should become natural-language capable, but not natural-language only.

Natural language is especially valuable for:

* bootstrapping
* scaffolding
* command discovery
* explaining intent
* manifest and config generation
* interactive repair and debugging
* translating product intent into kernel-native objects

Illustrative natural-language invocations may look like:

* `ioi "spin up an intelligent blockchain for a private docs worker with local GPU and publishable receipts"`
* `ioi "create a private coding worker with a local OSS model"`
* `ioi "publish this service candidate to sas-ready format"`
* `ioi "initialize this project and bind a local GPU profile"`

These should feel ergonomic, but they must still compile down to explicit plans, canonical commands, manifests, config, and receipts.

## 9.2 Three-layer resolution model

The correct architecture is:

### Layer 1: Intent surface

The user may enter:

* natural-language requests
* partially structured prompts
* canonical CLI commands

### Layer 2: Resolved plan

The CLI resolves the request into a plan that is:

* inspectable
* confirmable
* editable when appropriate
* explicit about dependencies and trust posture
* explicit about files, manifests, or state it will create or mutate

### Layer 3: Canonical execution

Execution happens through:

* explicit subcommands
* manifests and config files
* deterministic planners and generators where possible
* receipts, traces, and evidence bundles

The core doctrine is:

* natural language is the front door for intent
* structured commands and manifests are the system of record
* execution must be previewable before mutation
* mutations must be auditable and replayable afterward

Natural-language requests should therefore compile down to:

* deterministic commands where possible
* explicit plans when interpretation is required
* previewable changes
* auditable manifests
* replayable execution

## 9.3 Command families

Illustrative command families should eventually include:

### Chain bootstrapping

* `ioi forge init`
* `ioi chain init`
* `ioi chain preset`
* `ioi chain genesis`
* `ioi chain upgrade`

Purpose:

* bootstrap consensus
* choose trust, privacy, and evidence defaults
* configure sovereign domains
* configure settlement and identity roots

### Worker and service authoring

* `ioi worker init`
* `ioi service init`
* `ioi manifest generate`
* `ioi capability bind`
* `ioi approval define`

Purpose:

* scaffold worker manifests
* scaffold service contracts
* attach capabilities and execution scopes
* define approval paths and escalation behavior

### Artifact contracts

* `ioi artifact inspect`
* `ioi artifact validate`
* `ioi artifact materialize`
* `ioi artifact route`
* `ioi artifact query`
* `ioi artifact generate`
* `ioi artifact judge`
* `ioi artifact compose-reply`

Purpose:

* inspect typed Studio artifact manifests, including whether the primary Studio
  stage should open in `render` or `source`
* validate renderer contracts and presentation quality against real files so
  thin placeholder outputs do not pass as successful surfaced artifacts
* materialize reproducible repo/package outputs from artifacts, including
  truthful blocked/error envelopes that surface evidence without pretending a
  render succeeded
* prove routing decisions through local inference fixtures when inference is
  part of the contract lane only
* run the shared Studio router through a localhost inference runtime when
  `--local` and a local OpenAI-compatible endpoint are provided
* allow `ioi artifact route` / `ioi artifact query` to accept `--refinement`
  evidence so under-specified follow-up prompts route against the active
  artifact's real renderer and continuity state instead of drifting into a new
  artifact family
* allow `ioi artifact route` / `ioi artifact generate` to accept repeatable
  `--selected-target-json` values so artifact-local render or source
  selections remain typed continuity state instead of being reparsed from
  free-form prompt text
* run the shared Studio generator and typed judging loop through the contract
  lane, with any `--mock` usage confined to non-product contract/unit proof and
  never counted as live Studio parity
* surface production and acceptance provenance separately; `ioi artifact generate
  --local` may use `--acceptance-api-url`, `--acceptance-api-key`, and
  `--acceptance-model-name`, and it must emit a typed
  `inference_unavailable`/generation failure instead of silently collapsing the
  acceptance judge into production when no distinct acceptance runtime exists
* inspect typed judge results, winning candidates, and refinement continuity
  from generated artifact evidence bundles
* compose verification-backed replies from artifact state rather than worker
  prose

### Governance and policy

* `ioi policy init`
* `ioi policy bundle`
* `ioi delegation init`
* `ioi budget define`
* `ioi dispute init`

Purpose:

* define ActionRules and policy bundles
* define delegation trees
* define budgets and spend thresholds
* define approval and arbitration modules

### Evidence and simulation

* `ioi run simulate`
* `ioi replay run`
* `ioi evidence inspect`
* `ioi receipt export`
* `ioi verify`

Purpose:

* dry-run worker plans
* test approval paths
* inspect evidence bundles and traces
* verify receipt completeness and settlement compliance

### Publishing and namespace operations

* `ioi publish service`
* `ioi publish domain`
* `ioi namespace reserve`
* `ioi marketplace register`
* `ioi package promote`

Purpose:

* reserve namespace or domain identity
* publish service manifests
* register pricing, SLA, trust posture, and update policy
* move stable packages toward network distribution

### Operations and observability

* `ioi query`
* `ioi trace`
* `ioi evidence atlas`
* `ioi settlement inspect`
* `ioi domain status`

Purpose:

* inspect runs and state
* trace action lineage
* inspect policy decisions and evidence
* replay receipts and verify postconditions

### Identity and external reach

* `ioi keys`
* `ioi identity init`
* `ioi lease issue`
* `ioi connector bind`
* `ioi environment attest`

Purpose:

* manage operator, machine, and team identity
* issue revocable capability leases
* bind browser, desktop, API, and enterprise surfaces
* record trust posture for execution environments

## 9.4 Current implementation bridge

The present `crates/cli` command set already contains important foundations:

* `init`
* `scaffold`
* `artifact`
* `node`
* `query`
* `keys`
* `policy`
* `trace`
* `verify`

The spec should not require an immediate rename of everything.

Instead, those commands should be understood as the current kernel-adjacent substrate from which the stronger Web4-oriented command hierarchy can emerge.

They should also remain valid even as a natural-language surface grows above them. The structured command tree is the stable substrate that natural-language resolution targets, not something to be replaced by chatty ambiguity.

---

## 10. Core Objects

## 10.1 Domain

A sovereign autonomous execution domain rooted in IOI semantics.

## 10.2 Intelligent blockchain

A durable sovereign execution domain with explicit policy, participant, publication, continuity, and settlement semantics.

## 10.3 Service contract

A contract that can commission, constrain, verify, and pay for real work rather than only expressing state transitions.

## 10.4 Worker manifest

A typed declaration of a worker's role, capabilities, trust posture, allowed execution lanes, preferred execution path, fallback posture, evidence obligations, and settlement-facing behavior.

## 10.5 Service manifest

A typed declaration of a service's interface, pricing, SLA, evidence profile, update policy, supported worker topology, and allowed execution dependency posture.

## 10.6 Policy bundle

A versioned package of ActionRules, approval thresholds, budgets, delegation semantics, dispute rules, and egress constraints.

## 10.7 Capability lease

A revocable, policy-scoped grant allowing a worker or service to use a tool, connector, environment, or other capability under explicit bounds.

## 10.8 Evidence profile

A durable statement of what evidence, receipts, observations, traces, or proofs are required before outcomes may be accepted or settled.

## 10.9 Settlement profile

A durable statement of how verified outcomes, failures, rewards, slashing, disputes, and arbitration map into economic consequences.

## 10.10 Delegation model

The durable statement of who may authorize, upgrade, operate, approve, or participate.

## 10.11 Publication metadata

The canonical publication, namespace, identity, and upgrade-facing metadata for the domain.

## 10.12 Upgrade package

The bounded, publishable change unit for domain evolution.

## 10.13 Evidence and receipt inspector

The surface for inspecting action traces, evidence bundles, receipt chains, policy decisions, publication records, and settlement-linked commitments.

---

## 11. Chain Presets and Execution Domains

`IOI CLI` should eventually support presets that acknowledge labor partitioning, not only state partitioning.

Illustrative presets include:

* private enterprise chain
* public service network
* agent marketplace chain
* regulated evidence-heavy chain
* edge or local-first chain

Each preset may choose defaults for:

* consensus profile
* privacy mode
* evidence density
* approval thresholds
* settlement semantics
* arbitration modules
* identity and delegation posture

These presets should make it easier to express execution domains specialized for different trust and labor regimes.

---

## 12. Execution Path Resolution and Dependency Posture

`IOI CLI` should not assume one universal dependency model.

Whether a workload needs local hardware, provider credentials, or managed infrastructure depends on:

* the requested worker or service
* the privacy and sovereignty posture
* the required model or execution lane
* the user's available local hardware
* the presence or absence of provider keys
* whether a managed fallback is allowed by policy

The CLI should make this explicit rather than hiding it behind implicit failures or magical defaults.

## 12.1 Supported execution paths

The user should be able to satisfy execution prerequisites through one of three broad paths:

### Local-first path

The user has:

* local CPU or GPU
* local models
* local runtime support
* strongest sovereignty and privacy posture

This path should not require a mandatory API key for local execution.

### BYOK/API path

The user has:

* provider API keys or hosted inference credentials
* access to hosted models or external execution infrastructure
* potentially lighter local hardware requirements

This path trades some sovereignty for easier setup or broader model access.

### Managed path

The user has:

* neither strong local hardware nor a personal model stack necessarily
* a provider-managed or cloud execution option

This path should be explicit about the trust boundary, cost posture, and provider dependency.

## 12.2 Resolution behavior

When a user issues a natural-language request or a high-level structured scaffold command, the CLI should resolve and surface:

* whether suitable local hardware was found
* whether a local model/runtime is configured
* whether provider keys are configured
* whether managed execution is available
* which path is recommended: local, BYOK, or managed
* what the implications are for privacy, cost, latency, and portability

The CLI should not silently cross execution boundaries when the user's request implies a specific posture.

For example:

* if the user asks for local execution and no suitable local path exists, the CLI should say so and propose alternatives
* if the CLI wants to fall back from local to cloud, it should surface that change clearly and ask for confirmation when policy or trust posture changes
* the chosen execution path should be visible in generated manifests, plans, and receipts where relevant

## 12.3 Example UX

For a request such as:

> "Create a local coding worker."

The CLI should be able to answer in a shape like:

```text
Interpreted intent:
- create coding worker
- prefer local execution

Environment checks:
- local GPU found: yes
- local model configured: no
- provider key found: yes
- managed fallback available: yes

Recommended path:
- BYOK, unless the user installs a local model/runtime

Implications:
- local: highest privacy, hardware dependent, lower recurring cost
- BYOK: faster setup, provider dependency, external cost
- managed: easiest setup, lowest sovereignty, provider-managed execution
```

This execution-path resolution should be part of the product, not an afterthought.

---

## 13. Core Lifecycle

The core `IOI CLI` domain-authoring loop should be:

1. Capture intent through structured commands or natural-language requests
2. Resolve the request into an inspectable plan
3. Initialize domain scaffold or preset
4. Define trust, identity, and delegation roots
5. Define policy bundles, approval matrices, and budget rules
6. Define worker, service, and participant topology
7. Define capability leases, execution paths, and external execution surfaces
8. Define evidence, receipt, dispute, and settlement profiles
9. Generate kernel-native scaffolds, manifests, and publication metadata
10. Simulate execution paths and verify policy or evidence behavior locally
11. Instantiate the sovereign domain
12. Publish and inspect commitments, receipts, and namespace state
13. Upgrade the domain over time without breaking continuity

This is heavier than normal serviceization and should feel heavier.

---

## 14. Relationship to `Autopilot`

`Autopilot` is the private/local shell where worker systems are:

* built
* stabilized
* supervised
* refined
* promoted into service candidates

`IOI CLI` is where those stabilized systems may be turned into sovereign execution domains when the weight of a real intelligent blockchain is warranted.

`Autopilot` can therefore be:

* a source surface
* a feeder
* an exporter of `IOI CLI`-compatible artifacts

But it should not be the sole home of intelligent blockchain creation.

One important bridge is a typed artifact contract:

* `Autopilot` and Studio may emit typed artifact manifests, verified replies, receipts, and evidence plans
* `IOI CLI` should be able to inspect, validate, materialize, and promote those artifacts
* `IOI CLI` should also be able to query/route artifact outcomes and compose the verified reply that Studio would show
* repo or workspace generation is one artifact materialization mode, not the identity of every artifact

This keeps Studio as the control plane while making artifact and repo generation reproducible from a CLI-first, kernel-adjacent surface.

---

## 15. Relationship to `sas.xyz`

`sas.xyz` is not just cloud routing. It is the provider-side packaging, deployment, serving, and commercialization layer.

That means the relationship is:

* `IOI CLI` creates the sovereign execution object
* `sas.xyz` serves and commercializes it when it becomes a provider product

Some intelligent blockchains will be:

* internal
* infrastructure-facing
* protocol-native
* not meant to be sold as marketplace products

Others will back:

* worker services
* APIs
* installable offerings
* enterprise deployments

Only the latter need `sas.xyz` as the provider-serving and commercial surface.

---

## 16. Definition of Done

`IOI CLI` is successful when a developer or operator can:

1. express a new intelligent blockchain or sovereign execution-domain request through either structured commands or natural language,
2. inspect the resolved plan before mutation,
3. choose a trust, identity, evidence, settlement, and execution-path posture rather than only a ledger template,
4. define policy roots, authority and delegation rules, and worker or service topology explicitly,
5. generate worker manifests, service contracts, policy bundles, capability leases, and publication metadata from canonical command surfaces,
6. understand whether the workload is using local hardware, BYOK/API, or managed execution and why,
7. simulate execution paths, approval behavior, and evidence requirements before publication,
8. instantiate the domain as a kernel-native execution object,
9. publish, inspect, replay, and upgrade that domain through canonical IOI semantics,
10. inspect receipts, traces, evidence bundles, and settlement-linked outcomes locally,
11. import or promote stabilized worker logic from `Autopilot` when relevant,
12. use `forge` and adjacent command families without needing a separate product identity,
13. and hand the resulting domain off to `sas.xyz` when it needs to become a deployable, billable, distributable provider service.

## 16.1 Litmus test

The CLI should make the following feel natural:

> `ioi "spin up a new sovereign chain, publish a procurement worker, restrict it to approved vendors and budget bands, require browser receipts and policy proofs for purchases, route expensive reasoning to cloud models, keep secrets local, and settle only verified outcomes."`

If that feels natural, the CLI is no longer just chain tooling.

It is the operating toolchain for intelligent blockchains.

If the request then resolves into an explicit plan, canonical commands, generated manifests, a surfaced execution path, and auditable receipts, the product shape is correct.
