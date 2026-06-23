# Domain Ontologies and Data Recipes

Status: canonical architecture authority.
Canonical owner: this file for Domain Ontologies, Data Recipes, canonical object models, connector mappings, policy-bound data views, distilled ontology datasets, evaluation datasets, ontology-aware projections, and ontology-to-worker generation.
Supersedes: product, training, connector, or storage docs when they treat raw files, connector payloads, or ad hoc schemas as sufficient domain truth for Worker Training.
Superseded by: none.
Last alignment pass: 2026-06-20.

## Canonical Definition

**Domain Ontologies and Data Recipes are the semantic data plane for IOI.**

They turn source systems, documents, traces, connector outputs, workflow schemas,
policies, examples, and evaluations into trainable, queryable, receipted domain
truth.

```text
Ontology = what the domain means.
Data Recipe = how raw sources become ontology-bound runtime, training, and evaluation data.
Distilled Ontology Dataset = compact, high-signal training/evaluation data derived from ontology-bound source truth.
```

This layer is required for serious Worker Training. Without it, a training
workflow can ingest documents and produce examples, but it cannot reliably
explain what those examples mean, which source produced them, which policy
permitted them, which evaluator can compare them, or which Agentgres projection
should serve them.

## Core Doctrine

Workers train on ontology-bound data, not raw blobs. For efficient specialist
workers, the best substrate is often **distilled ontology-bound data**:
compact examples, counterexamples, verifier assertions, tool traces, canonical
object transitions, rubric judgments, and failure regressions derived from
ontology-bound source material.

```text
raw sources
→ ConnectorMapping
→ DataRecipe
→ TransformationRun
→ canonical ontology-bound objects
→ PolicyBoundDataView
→ DistilledOntologyDataset / EvaluationDataset / WorkerTraining / OntologyProjection
→ WorkerManifest, MoW routing, service outcomes
```

Agentgres stores ontology state, recipe definitions, transformation runs,
object heads, projection definitions, distilled dataset refs, evaluation
dataset refs, receipts, lineage, and artifact refs. Storage backends such as
Filecoin/CAS store large payload bytes by hash/CID. Domain governance and
authority providers control source access, training-data use, evaluation use,
export, decryption, and connector authority; wallet.network supplies that path
when portable delegated authority, secrets, decryption leases, external account
access, or high-risk approval is required.

## What This Layer Is

This layer is:

- the semantic contract between raw sources and worker behavior;
- the source of canonical domain object definitions;
- the repeatable path from source data to training/evaluation data;
- the path that turns examples, role tracks, solution diagrams, and domain app
  templates into ontology-bound recipes instead of static demos;
- the mapping layer between connectors and canonical domain objects;
- the distillation layer that turns ontology-bound source truth into compact
  training and evaluation signal;
- the mapping layer that turns work analytics, tool analytics, feedback
  annotations, rollout observations, and support/review signals into
  policy-bound datasets, projections, and evaluation material when authorized;
- the basis for ontology-aware Agentgres projections;
- the input to Worker Training, benchmark profiles, and service templates;
- the provenance layer for transformed data and generated examples.

This layer is not:

- a centralized data warehouse;
- a blob store;
- a generic feature store;
- a replacement for Agentgres;
- a replacement for wallet.network authority;
- a claim that raw connector schemas are canonical domain truth;
- a permission to train on data without policy-bound authority.

## First-Class Concepts

| Concept | Role |
|---|---|
| `DomainOntology` | Defines domain entities, relationships, events, actions, states, roles, and invariants. |
| `CanonicalObjectModel` | Typed object definitions: IDs, schemas, lifecycle states, constraints, privacy class, authority needs, and projection hints. |
| `DataRecipe` | Repeatable pipeline from source data, traces, work analytics, tool analytics, feedback, or connector payloads to normalized ontology-bound objects, training datasets, evaluation datasets, or projections. |
| `ConnectorMapping` | Maps provider fields, events, files, and actions into canonical domain objects and authority scopes. |
| `WorkflowSchema` | Typed workflow contract: inputs, outputs, node IO, state transitions, evidence requirements, and domain object refs. |
| `PolicyBoundDataView` | Governed data lens defining who or what may read, train, evaluate, export, publish, or route over a subset of data. |
| `TransformationRun` | Execution record for extraction, normalization, redaction, dedupe, validation, and mapping. |
| `TransformationReceipt` | Proof of what transformed, from which source, under which policy, into which object, dataset, or projection. |
| `DistilledOntologyDataset` | Compact high-signal training/evaluation corpus distilled from ontology-bound data, traces, corrections, verifier judgments, and examples while preserving provenance. |
| `EvaluationDataset` | Golden cases, holdouts, adversarial examples, regressions, rubric bindings, benchmark refs, and provenance commitments. |
| `OntologyProjection` | Agentgres projection generated from ontology relationships, canonical object models, recipes, and policy-bound views. |
| `OntologyToWorkerPlan` | Plan that turns ontology, recipes, workflow schemas, tools, policies, evals, and benchmarks into a WorkerManifest. |

## Lifecycle

1. **Declare Domain Ontology**
   A builder, domain owner, service provider, or organization defines the
   domain entities, relationships, events, roles, states, and invariants.

2. **Bind Canonical Object Models**
   The ontology is grounded in typed object models with IDs, schemas,
   constraints, lifecycle states, privacy classes, authority requirements, and
   projection hints.

3. **Map Connectors**
   ConnectorMappings bind external fields, files, events, and actions to
   canonical objects. A Gmail thread, CRM opportunity, GitHub issue, PDF plan,
   spreadsheet row, or CAD export should not become domain truth until it maps
   through an explicit connector mapping.

4. **Authorize Policy-Bound Views**
   Hypervisor, Data / Knowledge, Ontology, domain apps, org governance, or
   Agentgres-backed project policy define the PolicyBoundDataView that
   specifies which data may be read, transformed, used for training, used for
   distillation, used for evaluation, exported, published, or retained.
   wallet.network supplies authority refs only when the view requires
   delegated power such as decryption, connector access, external provider
   credentials, model-provider keys, spend, provider-trust acceptance,
   publication, export, or cross-domain reuse.
   Sensitive traces, connector outputs, documents, or feedback must then bind a
   `TrainingEvidenceEligibility` record before Foundry may use them as
   training, distillation, evaluation, benchmark, simulation, or conductor
   material. A policy-bound view is necessary but not sufficient for training
   use; eligibility records admit or exclude the evidence for the stated
   purpose.

5. **Run Data Recipe**
   A DataRecipe extracts, redacts, normalizes, dedupes, validates, links, and
   maps raw sources into ontology-bound objects, datasets, or projections.

6. **Record Transformation Receipts**
   Each TransformationRun emits receipts that bind inputs, outputs, recipe
   version, ontology refs, policy hash, authority grants, source refs, and
   artifact refs.

7. **Distill Ontology-Bound Signal**
   Data recipes, verifier workers, teacher workers, deterministic gates, and
   human reviewers may distill ontology-bound source truth into compact
   high-signal datasets for training and evaluation. Distillation may compress
   raw source volume, but it must not erase provenance: distilled datasets bind
   source commitments, recipe versions, policy-bound data view refs,
   transformation receipts, teacher/verifier refs when used, and rubric or
   benchmark bindings.

8. **Build Evaluation Datasets**
   Golden cases, holdouts, adversarial cases, failure regressions, and rubric
   bindings are generated or curated from ontology-bound data. Evaluation
   datasets are not just folders of examples; they are receipted benchmark
   inputs with domain meaning.

9. **Generate Ontology Projections**
   Agentgres projections can be generated from ontology relationships and
   canonical object models. Query and UI surfaces should read from these
   projections with visible freshness, policy, and source watermarks.

10. **Create Ontology-to-Worker Plan**
   The ontology, data recipes, workflow schemas, policy-bound data views,
   distilled datasets, tools, evals, benchmarks, and routing category combine
   into a plan for Worker Training or worker/package generation.

11. **Train, Benchmark, Publish, and Route**
    Hypervisor Foundry, daemon jobs, or sas.xyz training engagements use the
    plan to produce a WorkerManifest, policy envelope, lineage refs,
    evaluation receipts, benchmark receipts, and MoW routing metadata.

## Product and Domain Roles

Hypervisor should expose `Data / Knowledge` and `Ontology` as first-party
Applications catalog entries, Open Application views, or contextual
project/session panels over this semantic data plane.

`Data / Knowledge` owns product-level views for:

```text
source inventory
connector mappings
data recipes
policy-bound data views
transformation runs
distilled ontology datasets
evaluation datasets
memory and knowledge refs
freshness, lineage, quality, and access posture
```

`Ontology` owns product-level views for:

```text
domain ontologies
canonical object models
objects, actions, events, states, roles, and invariants
ontology projections
schema health
used-by relationships across workers, automations, connectors, and apps
```

Hypervisor Foundry consumes these surfaces for training, evaluation,
simulation, worker/package generation, and capability improvement. Foundry may
author or propose ontology and recipe changes, but Agentgres-backed semantic
truth, wallet/network data authority, and transformation receipts remain the
canon boundaries.

Guided views should come first. Advanced users may open the same ontology,
data, training, evaluation, benchmark, deployment, or outcome recipe in the
Workflow Compositor when graph-level editing is useful.

Patterns / Examples / Training consumes this layer whenever an example becomes
launchable. A useful example should identify the DomainOntology,
CanonicalObjectModel, DataRecipe, ConnectorMapping, PolicyBoundDataView,
EvaluationDataset, and TransformationReceipt posture needed to run, replay,
evaluate, package, or sell the pattern. Without that binding, the example is a
learning artifact, not a portable autonomous-system package.

aiagent.xyz uses this layer to evaluate, rank, and route workers inside Sparse
Worker Categories. A worker category should declare the ontology, object models,
workflow schemas, benchmark profile, and evaluation datasets that make claims
comparable.

sas.xyz uses this layer to sell worker-training and worker-composed outcomes.
A service provider should deliver not only a trained worker, but also the
ontology, recipes, policy-bound data views, distilled ontology datasets,
evaluation datasets, and transformation receipts that make the outcome
repeatable.

ioi.ai may coordinate cross-device restore, publishing, remote-runtime
entitlement, and archive references for ontology packs and recipe outputs, but
it should not become the canonical data warehouse.

## Example: Construction Estimating

A construction estimating worker should not train on "PDFs and quotes" as
unstructured blobs. It should train against a domain ontology with objects such
as:

```text
Project
PlanSheet
Room
Material
LaborRate
LineItem
Estimate
Quote
ChangeOrder
Approval
```

Connector mappings can map Drive PDFs, email threads, spreadsheets, CRM
records, and prior quotes into those objects. Data recipes can extract plan
sheet metadata, normalize material names, dedupe line items, redact private
customer data, distill high-signal line-item examples and counterexamples,
produce golden estimate examples, and build evaluation datasets. Agentgres can
then project estimates by project, material, room, quote state, approval
status, and policy-bound visibility.

## Agentgres Boundary

Agentgres owns the canonical state of:

```text
DomainOntology
CanonicalObjectModel
DataRecipe
ConnectorMapping
PolicyBoundDataView
TransformationRun
TransformationReceipt refs
DistilledOntologyDataset refs
EvaluationDataset refs
OntologyProjection
OntologyToWorkerPlan
```

Agentgres does not own raw connector credentials, decryption keys, or large
payload bytes. It records refs, commitments, object heads, projection
watermarks, receipts, and lifecycle state.

## Authority Boundary

Policy-bound data access is mandatory.

Training, evaluation, export, publication, connector mapping, and recipe
execution must bind to authority grants when they touch private, customer,
regulated, licensed, or organization-owned data.

```text
training improves capability
policy grants power
data recipes need permission
```

## Storage Boundary

Storage backends such as Filecoin/CAS may store ontology packs, recipe payloads,
source snapshots, transformation outputs, distilled ontology datasets,
evaluation datasets, trace bundles, projection checkpoints, and sealed archives
by hash/CID.

Those bytes are not the canonical live database. Agentgres stores the
operation-backed truth that says what the bytes are, which recipe produced
them, which policy permitted them, and whether they may be restored, reused,
trained on, published, or challenged.

## Non-Negotiables

1. Workers train on ontology-bound data, not raw blobs, whenever a domain
   ontology or object model exists.
2. A connector payload is source material, not canonical domain truth, until a
   ConnectorMapping and DataRecipe bind it.
3. DataRecipe runs must emit transformation receipts for consequential
   training, evaluation, projection, or service outcomes.
4. PolicyBoundDataViews gate read, transform, distill, train, evaluate,
   export, publish, and route use of private or governed data.
5. Distillation must preserve provenance. A distilled dataset must bind source
   commitments, recipe versions, policy-bound data views, transformation
   receipts, and teacher/verifier refs when used.
6. EvaluationDatasets must bind ontology refs, rubric refs, benchmark refs,
   source commitments, and policy.
7. OntologyProjections are serving views over Agentgres truth. They must expose
   freshness, recipe version, policy, and source watermark.
8. OntologyToWorkerPlan can propose workers, tools, schemas, evals, and
   manifests, but it cannot grant authority.
9. The semantic data plane connects Worker Training to the IOI stack; it does
   not replace compute markets, Agentgres, wallet.network, storage backends,
   MoW, service composition, settlement, or disputes.

## One-Line Doctrine

> **Domain Ontologies say what the work means; Data Recipes prove how source data became trainable, evaluable, queryable worker truth.**
