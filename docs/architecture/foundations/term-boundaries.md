# Term Boundaries

Status: canonical term-boundary authority.
Canonical owner: this file for the `Term | Canonical Meaning | Must Not Mean` boundary of every protected core term, for each term's ontological category, and for the alias and forbidden-alias register.
Supersedes: the `Terminology Boundary Table` that was carried as an H3 subsection under `Package Release And Live-System Genesis` inside the single-file `common-objects-and-envelopes.md`; scattered restatements of these boundaries in owner docs when wordings drift.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: mixed (a terminology contract over subjects at every maturity level; the deprecated-alias register is enforced by `npm run check:architecture-docs`)
Implementation refs:
  - `scripts/check-architecture-docs.mjs`
  - `scripts/lib/architecture-docs-integrity.mjs`
Last implementation audit: 2026-07-25

## Purpose

Most architecture defects in this canon have been naming defects: one term
carrying two object categories, two terms carrying one concept, or a UI label
hardening into a durable object. This file is the single place that says what a
protected term means, what it must not mean, and which category it belongs to.

Three files divide the naming job and must not restate each other:

```text
term-boundaries.md   what a protected term means and must not mean  (this file)
vocabulary.md        the full name register, one entry per named thing
canonical-enums.md   the exact member sets of enumerated values
```

Scope of this file's authority, stated narrowly on purpose: it owns the
`Term | Canonical Meaning | Must Not Mean` rows, each term's ontological
category, the alias register, and the retained-identifier register. Where a
boundary row and a loose description elsewhere disagree, the row wins.

It does **not** own subject doctrine. Everything outside those registers —
including the layering section below — is a navigational restatement of what the
subject owners already say, and the subject owner wins on any point of
substance. Where this file summarizes a boundary owned elsewhere, it names that
owner inline so the reader can go check.

## Ontological Categories

Every canonical name belongs to exactly one category. The category answers
"what kind of thing is this?" before any reader looks at fields.

| Category | Question it answers | Examples |
| --- | --- | --- |
| `substrate` | What operates the fabric? | Hypervisor Core, Hypervisor Daemon, Agentgres, storage backend |
| `product` | What does someone buy, install, or open? | Hypervisor App, Goal Space, HypervisorOS |
| `protocol` | What crosses a sovereignty boundary? | AIIP, MCP binding, IOI L1 commitment |
| `definition` | What describes work without doing it? | WorkflowTemplate, SkillManifest, GoalRunProfile, DataRecipe |
| `durable object` | What has identity, state, and a lifecycle? | System, GoalRun, WorkRun, OutcomeRoom, Session |
| `authority` | What permits an effect? | AuthorityGrant, CapabilityLease, scope |
| `evidence` | What proves something happened? | Receipt, artifact, evidence bundle, trace |
| `projection` | What is a policy-filtered read of truth owned elsewhere? | Systems workspace, Work workspace, MemoryProjection |
| `faculty` | What is a UI or conversational affordance with no durable identity? | contextual assistance, Mission presentation profile, chat |

A name whose category cannot be determined from its owner doc is a defect. A
name that changes category between docs is a blocker.

## Protected Core Terms

This table is normative. `Must Not Mean` entries are the failure modes actually
observed in this canon and its implementation records.

| Term | Category | Canonical Meaning | Must Not Mean |
| --- | --- | --- | --- |
| Autonomous System Package | definition | The reusable developer-facing build artifact binding worker responsibility, topology, capabilities, authority requirements, memory/state/artifact contracts, evals, profile templates/constraints, and receipt obligations. | A raw workflow file, connector config, daemon process, live system identity, or node membership. |
| AutonomousSystemManifest | definition | The immutable release-manifest contract that makes an Autonomous System Package deterministic, portable, evaluable, and receipted. | A live system, second runtime, or React Flow truth store. |
| AutonomousSystemGenesis | durable object | The one-time binding of a selected package release to a new `system_id`, constitution, initial active profiles, authority decision, and cryptographic initial state. | A package publication, ordinary upgrade, node join, or network enrollment. |
| System | durable object | One logical bounded autonomous institution with a stable `system_id`, constitution, membership, lifecycle, and authority, possibly spanning several Hypervisor Nodes. | A node, a process, a workspace tab, a project, or anything Sessions/Projects/Automations require in order to exist. |
| Systems | projection | The policy-filtered context/read model for one admitted `system_id`. | System identity, membership, lifecycle, or admission truth. |
| Project | durable object | Stable project/workspace identity under Hypervisor, scoping files, environments, sessions, and work. | A System, a GoalRun, or an authority boundary. |
| Session | durable object | Bounded interactive, headless, or supervisory context. Current interaction or run context. | Long-term memory, package identity, durable pursuit, standing behavior, collective pursuit, or execution-attempt truth. |
| Automation | durable object | Standing activation over one exact WorkflowTemplate revision (`AutomationSpec`), its scope binding, and its runs. | A generic background mission, a daemon execution truth, or an adaptive pursuit. |
| Assistant | faculty | Contextual, Session-backed help rendered in a product surface. | A durable object. There is no `Assistant` identity, state, lifecycle, authority, budget, receipt, or projection. When durable delegated labor is meant, the term is Worker; when a configured product record is meant, it is Agent. |
| Facilitation | faculty | Optional ioi.ai help in drafting, synthesis, and presentation over work a Hypervisor deployment already owns. | Ambient authority over Hypervisor state, an admission path, a competing operational source of truth, or any claim on route, worker, harness, verifier, or materialization truth. |
| Worker | durable object | Durable protocol actor, responsibility boundary, package identity, routing target, and event/receipt subject. The accountable labor actor. | Merely a UI label for a chat agent; a model; a harness. |
| Agent | product | Product-facing configurable record for a delegated actor or user-facing worker experience, and a compatibility alias that may be worker-backed. It stays subordinate to Worker. | The canonical low-level actor when Worker is required; an accountable labor actor in its own right. |
| WorkRun | durable object | One execution attempt bound to a typed work subject. | Its parent GoalRun, AutomationRun, OutcomeRoom, or queue lifecycle; a universal state machine over every kind of work. |
| Run | — | Not a canonical standalone term. Every run names its kind: WorkRun, GoalRun, AutomationRun, TransformationRun, FoundryRunPlan, TrainingPipelineRun. | A generic durable object. A bare `Run` in new prose or a new schema is a defect. |
| Work request | durable object | The typed request for bounded work: objective, class, output contract, constraints, and required capabilities and authority scopes. Public copy calls it Request for Worker (RFW). | An execution attempt, a claim, an assignment, or an authority grant. |
| Task | — | Not a canonical standalone term. It survives only as retained wire identity (`task://`, `task_id`) and in the external-protocol sense of an MCP task handle. | A durable IOI object. New prose uses work request, WorkRun, work frontier item, or work claim. |
| WorkflowTemplate | definition | Immutable, versioned Workflow-Compositor definition of directed graph shape, typed steps, dependencies, review points, acceptance, and delivery. | A trigger-bearing AutomationSpec, a live run, adaptive pursuit state, a harness loop, or React Flow canvas state. |
| Workflow | durable object | Proposed or admitted executable graph materialized from a WorkflowTemplate or authored directly under the same compositor contracts. | Hidden product state, a standing activation, or the React Flow canvas itself. |
| GoalRunProfile | definition | Immutable, content-addressed composition describing how a class of adaptive goals should converge. | A GoalRun, orchestration super-object, executable, authority grant, workflow graph, campaign database, or domain-state owner. |
| GoalRun | durable object | Durable state of one admitted adaptive pursuit, driven by the loop-native Goal Kernel. | A global collaboration graph, permanent memory, or a runtime. |
| OutcomeRoom | durable object | The durable shared-pursuit bounded-DAS instance created from a reusable package through genesis; it may coordinate many GoalRuns. | A runtime, global graph, marketplace, or authority plane. |
| Campaign | durable object | `ImprovementCampaign`: an optional multi-epoch improvement domain lifecycle coordinating GoalRuns and evidence. | A runtime, truth store, evaluator, promoter, or anything that can self-promote its own result. |
| EvaluationEpoch | durable object | One protected evaluation regime inside a Campaign, with its own exposure ledger and cutoff. | A benchmark run, a scorecard, or something Search may redefine. |
| Attempt | durable object | One participant's bounded try at a claimed frontier item inside a collaborative pursuit. | A WorkRun, a GoalRun iteration, or a receipt. |
| Finding | durable object | A reported result of an Attempt, including negative, inconclusive, invalid, and exploit findings. | Verified truth, acceptance, or settlement. |
| VerifierChallenge | durable object | A typed challenge against a Finding or mapping decision. | An authority action, a policy, or a dispute settlement. |
| WorkResult | durable object | The generic result contract of bounded work. `ImplementationResultPayload` is its software profile. | A coding-specific contract; files, diffs, and tests never enter the universal shape. |
| HarnessProfile | definition | Daemon-executed or daemon-mediated resolver for one scoped assigned step. | High-level workflow topology, reusable goal pursuit, a peer runtime, or persistent memory owner. |
| Harness | substrate | The step-resolution machinery a HarnessProfile selects and the daemon mediates. | An accountable labor actor, an authority holder, or a runtime beside the daemon. |
| Capability | authority | Primitive/model/tool feasibility and contract reference (`prim:*`). | Authority, secret possession, or policy permission. |
| Authority | authority | wallet.network grant or lease over resource, provider, identity, budget, approval, secret, and expiry for delegated machine power (`scope:*`). | A capability flag, UI readiness badge, or every app-local permission. |
| Lease | authority | A bounded, expiring, revocable grant of participation, context, resource, capability, or budget with scope, TTL, and heartbeat. | Ownership, a durable object's identity, or an implicit renewal. |
| Binding | authority | A typed link that narrows or scopes an existing object to an owner, revision, or surface. | A new authority, a new identity, or a widening. |
| Policy | authority | Admission and behavior rules over authority, risk, approval, privacy, retention, evidence, and execution posture. | Tracing, telemetry, or run history. |
| Decision | evidence | A recorded selection among admitted options, attributable to a deciding owner. | The effect itself, or authority to perform the effect. |
| Tool | definition | Executable capability with schema, risk, primitive capability requirements, authority scopes, approval requirements, and receipt behavior. | Ambient connector access. |
| Connector | substrate | External system adapter exposing tools. | Runtime truth, authority owner, or untyped API access. |
| SkillManifest | definition | Immutable, versioned instruction/resource/procedure and support-asset package that can influence context and reference admitted tools. | Authority grant, secret, executable tool by itself, marketplace listing, mutable installation, or active run snapshot. |
| Recipe | definition | Product-facing or package-facing label for an owner-qualified reusable composition. | A generic canonical `RecipeEnvelope`, untyped `run-recipe:` identity, or excuse to erase DataRecipe, environment, session-launch, workflow, automation, or GoalRun-profile ownership. |
| Profile | definition | An owner-qualified reusable configuration or resolver. Always qualified: HarnessProfile, DeploymentProfile, OracleEvidenceProfile, EcosystemAssuranceProfile. | A bare canonical `Profile` object. An unqualified `Profile` in new prose or a new schema is a defect. |
| Envelope | definition | The shared serialization shape of an object crossing a component boundary. | The object's identity, lifecycle, or authority. An envelope name is not a second object. |
| State | — | Scoped serializable working data. | Canonical domain truth unless settled through Agentgres/contracts. |
| Memory | durable object | Governed long-term recall or retrieval surface owned by MemorySpace and Agentgres admission. | Unbounded hidden context; anything the selected model, harness, or local cache owns. |
| Artifact | evidence | Materialized output, evidence, or deliverable. | A receipt by itself. |
| Event | evidence | Observation that something happened. | Durable proof of correctness. |
| Trace | evidence | Ordered diagnostic/observability path through runtime behavior. | Policy decision or authority grant. |
| Receipt | evidence | Durable proof of an action, decision, verification, artifact, authority use, or promotion outcome. | A log line, a UI-only status, or automatic correctness, verification, acceptance, adjudication, settlement, or payout. |
| Projection | projection | A policy-filtered read over truth owned elsewhere. | An operational source of truth, an authority, or a place where work can be admitted. |
| Runtime | substrate | Daemon/runtime execution contract and event/receipt producer. | React Flow, a provider SDK, or a model-owned loop. |
| Substrate | substrate | The shared operating fabric beneath products: control, authority, receipt, replay, and state. | A product, a deployment posture, or a synonym for "backend". |
| Product | product | What a person buys, installs, or opens. | The substrate it runs on. Hypervisor is both a product family and a substrate; prose must say which. |
| Protocol | protocol | A contract carried across an independently governed boundary. | An internal API, a transport library, or same-system coordination. |
| Domain | — | Overloaded and always qualified. `bounded execution domain` is a sovereignty boundary; `Domain Ontology` is a semantic namespace; `domain object` is the owner of actual artifact/campaign/fleet/business state; `docs/architecture/domains/` holds product and application domains. | A bare `Domain` in normative prose. |
| Service | product | A purchasable outcome or capability exposed through a service endpoint. | The runtime that executes it, or the authority that permits it. |
| Provider | substrate | A replaceable supply adapter for compute, models, or capacity. | The product moat, the sole trust boundary, or an excuse to ignore underlying terms. |
| Facilitator | — | Not a canonical term. The concept is Facilitation (a faculty); the acting parties are named Worker, Agent, or the ioi.ai product surface. | A durable object or an authority holder. |

## Session, GoalRun, and OutcomeRoom Are Three Different Things

These three are the most frequently conflated names in the canon, and the
conflation is dangerous because it crosses the substrate/product boundary. They
are distinct objects at distinct layers, and none of them contains another.

```text
OutcomeRoom   collective pursuit. A durable bounded-DAS instance created from a
              reusable package through genesis. May coordinate many GoalRuns.

GoalRun       one admitted bounded pursuit loop, driven by the Goal Kernel.
              May stand alone or participate in exactly one OutcomeRoom.

WorkRun       one execution attempt bound to a typed work subject.

Session       a bounded interactive, headless, or supervisory context. It binds
              participants, context, tools, environment/access posture, and
              selected adapters around work. It may support a GoalRun,
              AutomationRun, OutcomeRoom, or WorkRun — or exist directly for
              exploratory work with none of them.
```

Directional rules, all of which are testable:

- A GoalRun spans **zero or more** Sessions. Closing, replacing, or restoring a
  Session cannot *silently* close, fork, accept, or rewrite its GoalRun; an
  explicit, authorized, receipted transition still can. A Session is not a
  GoalRun's transcript and a GoalRun is not a long Session.
- A Session may exist with no GoalRun, no OutcomeRoom, and no System. Creating
  a Session never requires creating any of them.
- An OutcomeRoom is above GoalRun, never beside or inside a Session. Room
  machinery — participants, frontier, claims, offers, contribution lineage —
  appears only when collective pursuit is actually admitted.
- None of the three is a runtime. In the hosted case the Hypervisor Daemon
  admits, schedules, executes or mediates, receipts, and fails closed for all of
  them. Under an OutcomeRoom's `federated_admission` mode, `admission_owner_ref`
  names the versioned federation policy or adjudicator path instead; each domain
  still keeps local truth. See
  [`collaborative-pursuit.md`](./objects/collaborative-pursuit.md).

### Which layer owns which

Two different questions get confused here, so keep them apart:

- **Who owns the object's identity, admission, and lifecycle?** The substrate.
- **Who owns the doctrine for how the pattern should behave?** Named per subject
  in [`source-of-truth-map.md`](../_meta/source-of-truth-map.md), and for
  `OutcomeRoom` that is jointly an ioi.ai domain doc and a foundations doc.

| Layer | Owns | Objects |
| --- | --- | --- |
| Hypervisor substrate | object identity, admission, lifecycle, execution, authority, receipts, truth | Session, WorkRun, GoalRunProfile, GoalRun, OutcomeRoom, AutomationSpec/Run |
| ioi.ai product | pre-admission drafts, read projections, room and workstream UX, synthesis, subscription and budget controls, connector-auth escalation requests | `IoiAiGoalDraft`, `IoiAiGoalProjection`, `IoiAiOutcomePlanProjection`, `IoiAiAttemptSummary`, `IoiAiCrossSessionOutcomeGraph`, `IoiAiConnectorAuthEscalation` |

Doctrine ownership does not follow the layer split and must be read from the
map: `OutcomeRoom` and `CollaborationTerms` doctrine is owned by
[`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md)
**and** [`governed-autonomous-systems.md`](./governed-autonomous-systems.md);
GoalRun admission and execution doctrine is owned by
[`daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md).

The canon's own formulation, which this section only restates:
`ioi.ai` "dogfoods Hypervisor rather than receiving privileged substrate
semantics. Pre-admission goal copy is `intent://` draft state; GoalRun solely
owns admitted `goal://` identity and lifecycle." The consequences that matter:

- ioi.ai facilitation is optional and never becomes ambient authority over
  Hypervisor state. An `IoiAiGoalDraft` is pre-admission intent; it acquires no
  lifecycle, authority, budget, or evidence until the daemon admits a GoalRun.
- An ioi.ai projection is a projection. It must not become a competing
  operational source of truth, and it must not be the only place a fact exists.
- The **target** contract is that a compatible local deployment creates,
  admits, runs, and replays this work through its own contracts without an
  `ioi.ai` account, with unavailable connected capabilities typed unavailable
  rather than becoming hidden prerequisites.
  [`control-plane.md`](../domains/ioi-ai/control-plane.md) records that the
  current product **has not yet passed** that end-to-end standalone contract, and
  that is the honest present-tense position. Consult
  [`implementation-matrix.md`](../_meta/implementation-matrix.md) before making
  any built/partial/planned claim about it.

Naming a product surface after an object does not transfer ownership of the
object. "Goal Space" is the ioi.ai subscription and surface; `GoalRun` is the
substrate object it reads.

## Deprecated and Forbidden Aliases

`npm run check:architecture-docs` fails closed on these outside an explicit
alias, legacy, historical, migration, or watchlist context.

| Forbidden | Use instead | Why |
| --- | --- | --- |
| `cap:*`, `capgrant`, `capability_grant`, `capability_policy`, `capabilities_required`, `CapabilityEnvelope`, "capability grant", "capability request", "scoped capabilities" | `prim:*` for primitive capability, `scope:*` for authority | Capability is feasibility; authority is permission. Collapsing them was the canon's most consequential naming defect. |
| `Providers / Environments` | `Environments` | The product surface is Environments; the pair name implied two surfaces. |
| Request for Agent, RFA | Request for Worker, RFW | The acting party in public copy is the Worker. |
| `HypervisorMission` | GoalRun or OutcomeRoom, optionally rendered as a Mission presentation profile | The generic Mission object is retired; typed physical mission contracts remain valid. |
| `Workbench` (as owner name) | Developer Workspace | Retained as a compatibility alias only. |
| Work Ledger | Provenance | Legacy family name for the Provenance application. |

## Retained Wire Identifiers

These identifiers are protocol- or API-visible and are **not** renamed. The
canonical display term differs from the wire term; the wire term must not spawn
a second concept.

| Wire identifier | Canonical term | Where it is fixed |
| --- | --- | --- |
| `run://`, `run_id`, `/v1/runs/{run_id}` | WorkRun | daemon run routes and generated architecture contracts |
| `task://`, `task_id` | work request | generated architecture contracts and physical-action intent fixtures |
| `goal://` | GoalRun | daemon GoalRun routes |
| `agent://` | Worker, when it denotes the accountable actor | principal ref namespace |

The read-side legacy ref-scheme aliases are registered in
[`legacy-ref-scheme-aliases.json`](../_meta/schemas/legacy-ref-scheme-aliases.json)
and are read-only: no machine schema may write them.

## Related Canon

- [`vocabulary.md`](../_meta/vocabulary.md) — the full name register.
- [`canonical-enums.md`](./canonical-enums.md) — exact enumerated member sets.
- [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md) — the shared-object family index.
- [`invariants.md`](./invariants.md) — cross-cutting invariant wording.
- [`../_meta/source-of-truth-map.md`](../_meta/source-of-truth-map.md) — subject ownership.
