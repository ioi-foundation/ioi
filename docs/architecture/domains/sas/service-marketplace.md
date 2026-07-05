# sas.xyz Service-as-Software Marketplace Specification

Status: canonical architecture authority.
Canonical owner: this file for sas.xyz service marketplace doctrine; low-level service endpoints live in [`sas-xyz-service-endpoints.md`](./service-endpoints.md).
Supersedes: overlapping service-marketplace plan prose when outcome/service boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-06-01.
Doctrine status: canonical
Implementation status: planned (outcome marketplace design; order/escrow/delivery/dispute loop is specification)
Last implementation audit: 2026-07-05

## Canonical Definition

**sas.xyz is the first-party Web4 marketplace application for autonomous service outcomes, including Worker Training as Service-as-Software, built on AIIP and IOI settlement.**

It lets users order outcomes produced by workers, workflows, providers, and
runtime nodes under escrow, SLA, receipts, and delivery acceptance. Its first
MoW-native wedge is training a specialized worker for a defined business
outcome.

sas.xyz is not the protocol. It is a first-party protocol client, demand
generator, and proof surface for AIIP outcome-service profiles and IOI
autonomous-system settlement.

## What sas.xyz Is

sas.xyz is:

- a React/Web service marketplace interface;
- an Agentgres-backed application domain;
- an IOI L1 smart-contract user;
- an AIIP outcome-service profile user;
- an outcome-ordering and delivery system;
- a workflow/worker composition surface;
- a Worker Training contract surface;
- a service escrow and SLA layer.

It is not a separate chain by default and it is not the whole IOI protocol.

## Difference From aiagent.xyz

```text
aiagent.xyz = marketplace for workers/capabilities
sas.xyz     = marketplace for delivered outcomes/services
```

aiagent.xyz publishes, benchmarks, ranks, installs, and routes reusable digital
workers. sas.xyz sells packaged services such as Worker Training engagements,
weekly audits, report generation, support resolution, research deliverables,
CAD artifacts, or workflow automation outcomes.

## What sas.xyz Owns

sas.xyz owns:

- service listings;
- provider profiles;
- service manifests;
- Worker Training contracts;
- order lifecycle;
- outcome workspaces;
- runtime assignments and compute-session refs;
- SLA terms;
- delivery bundles;
- acceptance/dispute state;
- provider/customer messaging;
- service quality ledgers;
- service reputation;
- outcome packaging;
- workflow composition references;
- worker-training template refs.

## What sas.xyz Does Not Own

sas.xyz does not own:

- user raw secrets;
- all runtime compute;
- Private Workspace cTEE execution semantics;
- local Hypervisor execution;
- IOI L1 itself;
- storage backend payload bytes;
- aiagent.xyz worker marketplace state except through refs/integrations;
- training datasets, traces, or artifacts as raw payload bytes.

## Service Order Lifecycle

```text
User orders service
→ sas.xyz Agentgres creates ServiceOrder operational state
→ OutcomeWorkspace is initialized for task/run/delivery state
→ IOI L1 contract locks escrow / records order commitment
→ runtime router creates RuntimeAssignment and ComputeSession
→ isolated runtime node boots a Hypervisor Daemon profile
→ worker/workflow executes through the daemon using task capsules and authority leases
→ artifacts and receipts are produced
→ delivery bundle recorded in sas.xyz Agentgres
→ user accepts, rejects, or disputes
→ IOI L1 contract releases payout / refund / slashing
```

## Worker Training Contract

Worker Training is a Service-as-Software outcome. The buyer does not purchase a
raw model checkpoint; the buyer purchases a trained, benchmarked, policy-bound
worker capable of performing a scoped task under receipt obligations.

A Worker Training order should define:

- target workflow or recurring task;
- DomainOntology and CanonicalObjectModel refs, when the task requires domain
  semantics;
- DataRecipe, ConnectorMapping, and PolicyBoundDataView refs for source
  material used in training or evaluation;
- input and output contract;
- source documents, examples, corrections, or prior traces;
- privacy and training-data handling policy;
- allowed training/configuration methods;
- evaluation rubric;
- benchmark profile or Sparse Worker Category;
- deployment target;
- ownership, license, and contribution terms;
- acceptance criteria and dispute path.

Deliverables may include:

- WorkerManifest;
- policy envelope;
- ontology, recipe, mapping, and evaluation dataset refs;
- TransformationReceipt set;
- TrainingReceipt set;
- BenchmarkReceipt set;
- evaluation report;
- deployment package;
- optional aiagent.xyz listing;
- optional sas.xyz outcome wrapper.

Settlement releases only when the trained worker satisfies the acceptance rubric
and emits the required evaluation receipts. If the worker fails benchmark,
policy, privacy, or delivery requirements, the order follows the same
deterministic arbitration path as other service outcomes.

## IOI L1 Contract Interactions

sas.xyz should use IOI L1 contracts for:

- service publication;
- service order commitment;
- escrow lock;
- SLA bond;
- delivery acceptance;
- payout release;
- refunds;
- disputes;
- provider bond slashing;
- reputation root commitments.

## Agentgres Domain State

sas.xyz Agentgres tracks:

- rich service metadata;
- Worker Training specs and contracts;
- training lineage refs;
- dataset commitments;
- benchmark and evaluation receipt refs;
- service search/ranking projections;
- order state;
- run state;
- delivery artifacts;
- evidence bundles;
- user/provider messages;
- receipts;
- quality records;
- support/dispute evidence;
- operational billing projections.

## User Without Hypervisor

Users can interact directly with sas.xyz in a browser:

```text
browser order
→ hosted/provider/DePIN/Private-Workspace-cTEE/TEE IOI runtime executes
→ delivery bundle appears in sas.xyz UI
→ wallet.network handles approvals/payment
```

Hypervisor is optional for users who want local/private execution, local
workflow editing, or local connector/model control. Sensitive managed outcomes
may also request Private Workspace backed by cTEE when a persistent rented GPU
should do public or redacted work without receiving protected plaintext. In
that profile, Candidate-Lattice Private Decoding is the default protected-agency
strategy: the service node expands candidates, while the private head,
guardian, or wallet policy selects, denies, declassifies, or signs.

## Managed vs Local Service

sas.xyz may support two modes:

### Local Install/Run

The service workflow is installed into Hypervisor and run locally.

### Managed Outcome

A provider/hosted IOI runtime executes and delivers the outcome.

Both modes should emit receipts and delivery bundles.

## MoW Service Composition

sas.xyz composes workers into outcomes. A service may route through one worker,
a planner/executor/verifier graph, or a larger MoW composition. Routing choices
should be receipt-backed when they affect cost, quality, settlement,
reputation, or disputes.

For worker-powered services, the delivery bundle should include contribution
refs that let payouts, royalties, and reputation updates flow by verified
contribution instead of raw token usage, attention, popularity, or hidden
platform preference.

Composed services should emit a `ServiceCompositionReceiptBundle` when a
delivery depends on nested workers, service modules, provider jobs, private
workspace execution, or verifier graphs. The bundle must bind:

```text
composition graph ref
routing receipts
worker/service/provider contribution receipts
verifier and quality receipts
policy and approval receipts
private-data posture
artifact and evidence refs
dispute evidence refs
Agentgres operation refs and state root
```

This makes contribution, privacy posture, verification, acceptance, dispute,
and settlement inspectable without making sas.xyz the execution runtime or
storage backend. The bundle is evidence for the delivery; Agentgres remains the
operational truth substrate, wallet.network remains the authority layer, and
storage backends hold payload bytes.

When a service outcome spans multiple organizations or sovereign domains, the
service order should reference a `MultiPartyCollaborationContext`. The context
names the buyer/customer, data owner, worker provider, compute provider,
auditor/regulator/verifier, and settlement counterparty roles as needed; binds
per-party authority refs and revocation refs; names allowed shared refs,
restricted views, redacted summaries, evidence bundles, contribution refs, and
settlement intents; and preserves historical receipts even when a party is
removed. It is the collaboration policy/proof wrapper around the service
delivery, not a replacement for delivery bundles, AIIP packets, Agentgres truth,
or audience-specific audit exports.

## Delivery Bundle

A service delivery should include:

```text
delivery update refs and milestone/partial/final status
output artifacts
evidence bundle
execution receipts
service composition receipt bundle, when nested workers/providers are used
worker contribution refs
verifier refs
private-data posture
validation results
policy/capability summary
quality summary
acceptance, revision, and dispute metadata
settlement intent refs
dispute evidence refs
```

## Anti-Patterns

Do not model sas.xyz as:

```text
the execution runtime
the only place service packages can exist
a mandatory wrapper around aiagent.xyz workers
a raw software-tool marketplace
a model-checkpoint storefront
a replacement for daemon authority, Agentgres truth, or wallet.network approvals
a privacy authority layer for rented GPU nodes
a contribution oracle based on token usage or hidden platform preference
a dispute process based on provider logs instead of receipt/evidence refs
```

Correct model:

```text
sas.xyz contracts and lists verifiable service outcomes
service packages can run locally, privately, hosted, in VPCs, through TEEs, or
through Private Workspace cTEE nodes or marketplace orders
the daemon executes service engines under the Default Harness Profile
Agentgres records delivery, evidence, receipts, and settlement state
L1 settlement appears when contracts, escrow, rights, disputes, or public trust
require it
```

## One-Line Doctrine

> **sas.xyz does not sell software tools or raw model checkpoints. It sells verifiable autonomous outcomes, including trained workers delivered under acceptance rubrics.**

## Product Context Module

The product-positioning and provider-OS module (a former `docs/specs`
import) is archived verbatim at
[`../../_archive/specs/sas-service-marketplace-product-context.md`](../../_archive/specs/sas-service-marketplace-product-context.md).
The canonical doctrine above owns sas.xyz; the archived module is
positioning context and must follow it.
