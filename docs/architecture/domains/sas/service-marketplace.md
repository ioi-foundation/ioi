# sas.xyz Service-as-Software Marketplace Specification

Status: canonical architecture authority.
Canonical owner: this file for sas.xyz service marketplace doctrine; low-level service endpoints live in [`sas-xyz-service-endpoints.md`](./service-endpoints.md).
Supersedes: overlapping service-marketplace plan prose when outcome/service boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-07-15.
Doctrine status: canonical
Implementation status: planned (outcome marketplace design; order/escrow/delivery/dispute loop is specification)
Last implementation audit: 2026-07-05

## Canonical Definition

**sas.xyz is the first-party Web4 marketplace application for autonomous
service outcomes, including Worker Training as Service-as-Software, built on
AIIP, local contracting truth, and explicitly selected settlement services.**

It lets users order outcomes produced by workers, workflows, providers, and
runtime nodes under escrow, SLA, receipts, and delivery acceptance. Its first
MoW-native wedge is training a specialized worker for a defined business
outcome.

sas.xyz is not the protocol. It is a first-party protocol client, demand
generator, and proof surface for AIIP outcome-service profiles and the shared
profile-neutral settlement contract. IOI L1 is one optional service for
explicitly enrolled orders.

## What sas.xyz Is

sas.xyz is:

- a React/Web service marketplace interface;
- an Agentgres-backed application domain;
- an optional IOI L1 smart-contract user when the order's active enrollment and
  settlement profile select that service;
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
- `WorkflowTemplate` and `GoalRunProfile` refs for deterministic or adaptive
  service fulfillment respectively;
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
→ declared settlement profile reserves local invoice, bilateral/external
  escrow, external-chain, or enrolled IOI L1 commitment when required
→ runtime router creates RuntimeAssignment and ComputeSession
→ isolated runtime node boots a Hypervisor Daemon profile
→ worker, admitted WorkflowTemplate materialization, or GoalRun executes
  through the daemon using task capsules and authority leases
→ artifacts and receipts are produced
→ delivery bundle recorded in sas.xyz Agentgres
→ user accepts, rejects, or disputes
→ selected settlement rail releases payout, refund, or slashing disposition
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
- DomainOntology, DataRecipe, ConnectorMapping, and EvaluationDataset refs;
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

## Optional IOI Network Services And Settlement Profile

An active connected/secured enrollment may independently select named IOI
Network services. The adapter gates each invocation by its exact `service_kind`,
terms, and public-commitment policy:

- `registry`: service publication and selected order/delivery commitments;
- `rights`: contractual service or artifact rights;
- `reputation`: provider and outcome reputation-root commitments;
- `dispute`: selected challenge/adjudication service;
- `escrow` or `settlement`: escrow locks, SLA bonds, payouts, refunds, and
  adjudicated slashing through the selected economic service.

Registry, rights, reputation, and public-finality invocations use
`NetworkServiceInvocationEnvelope`; they do not become settlement actions.
`settlement_mode: ioi_l1` is required only when IOI L1 is selected as the
economic settlement rail. Delivery acceptance remains a separate admitted
decision consumed by settlement; the adapter never authors it.

Local invoice, bilateral, external-escrow, and external-chain modes implement
the same lifecycle through their declared adapters. No sas.xyz order is forced
onto IOI L1 merely because it uses AIIP or Agentgres.

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
refs that let payouts, royalties, and reputation updates flow by accepted or
adjudicated contribution under the declared assurance state instead of raw
token usage, attention, popularity, self-report, or hidden platform preference.

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

When a service outcome needs persistent collective pursuit, the service order
may bind an `OutcomeRoom` whose CollaborativeWorkGraph carries frontier items,
participant and claim leases, resource offers, positive and negative attempts,
findings, verifier challenges, generic results/deltas, contribution lineage,
and replay. When independently governed organizations or sovereign domains are
admitted, that room must also bind a `MultiPartyCollaborationEnvelope` naming
the buyer/customer, data owner, worker provider, compute provider,
auditor/regulator/verifier, and settlement counterparty roles as needed;
per-party authority and revocation; allowed shared refs; restricted views;
evidence; contribution; settlement; ordering; and admission topology.

The service order remains the commercial owner for its separately funded
budget, escrow, SLA, delivery, acceptance, dispute, and payout. It must not
silently consume a user's ordinary ioi.ai seat allowance for independent
network labor. The OutcomeRoom is the work-coordination object and the
MultiPartyCollaborationEnvelope is the cross-party policy/proof context; neither
replaces service orders, delivery bundles, AIIP packets, per-domain Agentgres
truth, or audience-specific audit exports.

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
a replacement for daemon admission/execution, Agentgres truth, or authority-provider approvals
a privacy authority layer for rented GPU nodes
a contribution oracle based on token usage or hidden platform preference
a dispute process based on provider logs instead of receipt/evidence refs
```

Correct model:

```text
sas.xyz contracts and lists verifiable service outcomes
service packages can run locally, privately, hosted, in VPCs, through TEEs, or
through Private Workspace cTEE nodes or marketplace orders
the daemon executes admitted ServiceEngine and ServiceModule invocations directly
a selected HarnessProfile resolves only a scoped agent step when the service graph requires one
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
