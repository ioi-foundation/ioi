# Domain Ontologies and Data Recipes

Status: canonical architecture authority.
Canonical owner: this file for locally canonical and optionally federated Domain Ontologies, semantic assertions and mappings, executable ontology actions, Data Recipes, canonical object models, connector mappings, policy-bound data views, distilled ontology datasets, evaluation datasets, ontology-aware projections, the Ontology Development Kit, ontology-aware surface descriptors, and ontology-to-worker generation.
Supersedes: product, training, connector, or storage docs when they treat raw files, connector payloads, or ad hoc schemas as sufficient domain truth for Worker Training.
Superseded by: none.
Last alignment pass: 2026-07-13.
Doctrine status: canonical
Implementation status: partial (ODK draft object plane exists; optional cross-domain semantic negotiation, provenance-bearing assertions, executable ontology actions, and most of the semantic data plane are planned)
Last implementation audit: 2026-07-05

## Canonical Definition

**Domain Ontologies and Data Recipes are IOI's locally canonical semantic world
plane. Explicit versioned mappings permit selected meanings and actions to
interoperate across sovereign domains when the expected benefit exceeds
semantic loss, disclosure, verification, and coordination costs—without
requiring one global ontology or database.**

They turn source systems, documents, traces, connector outputs, workflow schemas,
policies, examples, and evaluations into trainable, queryable, receipted domain
truth.

When material can contribute to institutional memory, evaluation, analytics,
training, distillation, or reusable capability, its Data Recipe resolves the
effective `InstitutionalLearningBoundaryProfile` as well as source-specific
license, consent, retention, export, provider-use, customer-use, and
`LearningEvidenceEligibilityEnvelope` refs. Training-specific consumers use its
`training_compatibility` profile; the boundary profile is a scope ceiling, not
blanket permission, and ontology mapping never launders rights.

```text
Ontology = what one governed domain means under a namespaced, versioned contract.
Data Recipe = how raw sources become ontology-bound runtime, training, and evaluation data.
Distilled Ontology Dataset = compact, high-signal training/evaluation data derived from ontology-bound source truth.
Ontology Development Kit = how semantic contracts become repeatable builders, generated surfaces, domain apps, evals, workers, and packages.
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

Local canonicality is the default. An organization or autonomous-system domain
may canonically define its own objects, actions, assertions, and policies.
Cross-domain work uses namespaced versions, explicit compatibility ranges,
crosswalks, mapping decisions, and policy-bound projections. AIIP negotiates
semantic profiles and carries permitted refs; it does not create a universal
schema authority or move raw source data by default.

For a bounded autonomous system, the active constitution sits above the
ontology. An ontology may evolve the system's model of its world; it may not
semantically redefine constitutional purpose, prohibitions, authority ceilings,
amendment rules, or terminal obligations through an ordinary mapping or schema
change. Ontology and action roots named by the constitution are versioned
protected refs.

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
| `DomainOntology` | Defines namespaced domain entities, relationships, events, actions, states, roles, invariants, and compatibility policy. |
| `OntologyVersion` | Immutable version and compatibility/deprecation contract for one ontology namespace or overlay. |
| `OntologyOverlay` | Local extension or policy-specific view that preserves its base ontology and namespace lineage. |
| `OntologyCrosswalk` | Explicit mapping between ontology/object/action versions, including loss, ambiguity, scope, and verifier requirements. |
| `SemanticMappingDecision` | Challengeable, receipted application of a crosswalk or adapter to a concrete handoff, query, object, or action. |
| `CanonicalObjectModel` | Typed object definitions: IDs, schemas, lifecycle states, constraints, privacy class, authority needs, and projection hints. |
| `ProvenanceAssertion` | Time-, source-, confidence-, scope-, evidence-, supersession-, and dispute-bearing claim about an ontology-bound property or relationship; admission records the assertion without making it universally true. |
| `OntologyActionContract` | Executable semantic action binding a target object and typed IO to state pre/postconditions, capabilities, authority, risk, idempotency, compensation, verifier, evidence, receipt, and physical-safety obligations. |
| `DataRecipe` | Immutable, content-addressed pipeline definition from source data, traces, work analytics, tool analytics, feedback, or connector payloads to declared ontology-bound object/dataset/projection contracts. Its content hash commits an exact semantic-component snapshot; concrete outputs belong to TransformationRun and dataset/artifact owners. |
| `ConnectorMapping` | Immutable successor-versioned mapping of provider fields, events, files, and actions into canonical domain objects and authority scopes, with an exact semantic-component snapshot. |
| `WorkflowSchema` | Typed workflow contract: inputs, outputs, node IO, state transitions, evidence requirements, and domain object refs. |
| `PolicyBoundDataView` | Governed data lens defining who or what may read, train, evaluate, export, publish, or route over a subset of data. |
| `TransformationRun` | Execution record for extraction, normalization, redaction, dedupe, validation, and mapping. |
| `TransformationReceipt` | Attestation binding what transformed, from which source, under which policy, into which object, dataset, or projection. |
| `DistilledOntologyDataset` | Compact high-signal training/evaluation corpus distilled from ontology-bound data, traces, corrections, verifier judgments, and examples while preserving provenance. |
| `EvaluationDataset` | Golden cases, holdouts, adversarial examples, regressions, rubric bindings, benchmark refs, and provenance commitments. |
| `OntologyProjection` | Agentgres projection generated from ontology relationships, canonical object models, recipes, and policy-bound views. |
| `OntologyToWorkerPlan` | Plan that turns ontology, recipes, workflow schemas, tools, policies, evals, and benchmarks into a WorkerManifest. |
| `OntologyDevelopmentKitManifest` | Builder-kit manifest that packages ontology refs, object models, recipes, connector mappings, policy-bound views, surface descriptors, workflow schemas, eval refs, and conformance expectations for repeatable surface/domain-app/worker construction. |
| `OntologySurfaceDescriptor` | Object-aware surface descriptor for generated or builder-authored views, editors, graphs, forms, review queues, consoles, dashboards, and domain apps over the ontology. |

These names use three canonical envelope/storage families rather than six
parallel schemas:

| First-class semantic object | Canonical envelope and Agentgres registration |
| --- | --- |
| `DomainOntology` | Aggregate lineage for the `DomainOntologyEnvelope` family. |
| `OntologyVersion` | Immutable `DomainOntologyEnvelope` with `ontology_record_profile: ontology_version`. |
| `OntologyOverlay` | `DomainOntologyEnvelope` with `ontology_record_profile: ontology_overlay` and explicit base-version refs. |
| `ProvenanceAssertion` | `OntologyAssertionEnvelope` / `OntologyAssertion` with `assertion_profile: provenance_assertion`. |
| `OntologyCrosswalk` | `OntologyMappingEnvelope` / `OntologyMapping` with `mapping_record_profile: ontology_crosswalk`. |
| `SemanticMappingDecision` | Applied `OntologyMappingEnvelope` / `OntologyMapping` with `mapping_record_profile: semantic_mapping_decision`, target refs, challenge refs, and a decision receipt. |

The shared envelope fields are owned by
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md#domainontologyenvelope).
Agentgres registers each semantic profile, but it does not persist a second
profile-specific schema beside the mapped base envelope.

## Lifecycle

1. **Declare A Namespaced Domain Ontology**
   A builder, domain owner, service provider, or organization defines entities,
   relationships, events, roles, states, invariants, namespace ownership,
   version, compatibility range, deprecation policy, and permitted overlays.

2. **Bind Canonical Object Models And Assertions**
   Typed object models declare IDs, schemas, constraints, lifecycle states,
   privacy classes, authority requirements, and projection hints. Claims about
   their properties and relationships use provenance-bearing assertions with
   valid time, transaction time, source and observation context, confidence or
   uncertainty, supporting and contradicting evidence, applicability, causal or
   counterfactual context when relevant, supersession, and dispute state.

3. **Bind Executable Action Contracts**
   Consequential ontology actions compile into `OntologyActionContract`
   definitions. The action contract binds target objects and typed inputs/
   outputs to preconditions, postconditions, invariants, expected transitions,
   runtime/tool/automation capabilities, risk, local policy, `prim:*` and
   `scope:*` requirements, approvals, revocation, dry-run, idempotency, retry,
   effect recovery class (`replayable`, `checkpointable`, `compensatable`,
   `reconciliation_required`, or `non_retryable`), ambiguous-effect
   reconciliation, compensation, verification, evidence, receipts, and
   physical-safety profiles where applicable.

4. **Map Sources And Connectors**
   `ConnectorMapping` binds external fields, files, events, and actions to
   canonical objects. A mail thread, CRM opportunity, GitHub issue, PDF plan,
   spreadsheet row, CAD export, or provider event remains source material until
   an explicit mapping and DataRecipe admit its semantic projection.

5. **Declare Crosswalks And Negotiate Semantic Profiles**
   Cross-domain handoffs declare input/output ontology and action-schema
   profiles. Explicit crosswalks or semantic adapters resolve compatible
   versions, local overlays, unmapped fields, lossy conversions, ambiguity, and
   verifier obligations. Each applied mapping emits a challengeable mapping
   decision; silent field equivalence is forbidden.

6. **Authorize Policy-Bound Views**
   Hypervisor, ODK, Domain Apps, organization governance, or Agentgres-backed
   project policy define which data may be read, transformed, queried across a
   federation, trained on, distilled, evaluated, exported, published, or
   retained. wallet.network supplies authority refs when delegated decryption,
   connector/provider credentials, external accounts, spend, provider-trust
   acceptance, publication, export, or cross-domain reuse is required.
   Sensitive evidence also needs `TrainingEvidenceEligibility` before Foundry
   may use it for training, distillation, evaluation, benchmarking, simulation,
   or conductor material; a permitted view alone is not training consent.

7. **Run Data Recipes**
   A recipe extracts, redacts, normalizes, deduplicates, validates, links, and
   maps raw sources into ontology-bound objects, assertions, datasets, or
   projections. Admission resolves the exact recipe revision/hash and the same
   semantic-component snapshot/hash committed by that recipe; it never follows
   current ontology, mapping, object-model, schema, or policy-view heads.
   Progressive adoption is canonical: a domain may start with the minimal
   object/action contracts around consequential boundaries and infer candidate
   schema from real work rather than model its entire world first.

8. **Record Transformation And Mapping Receipts**
   Each transformation binds inputs, outputs, recipe and ontology versions,
   policy hash, authority grants, source refs, artifact refs, and any semantic
   mapping decision. A receipt attests those boundary facts; it does not by
   itself make the transformed assertion universally correct.

9. **Distill Ontology-Bound Signal**
   Recipes, verifier workers, teacher workers, deterministic gates, and human
   reviewers may produce compact examples, counterexamples, verifier
   assertions, tool traces, object transitions, rubric judgments, and failure
   regressions. Compression must preserve source commitments, recipe versions,
   policy-bound views, transformation receipts, teacher/verifier refs, and
   rubric or benchmark bindings.

10. **Build Evaluation Datasets**
    Golden cases, holdouts, adversarial cases, failure regressions, and rubric
    bindings become receipted benchmark inputs with domain meaning rather than
    ungoverned folders of examples.

11. **Generate Ontology Projections**
    Agentgres projections are derived from ontology relationships, assertions,
    object models, crosswalks, recipes, and policy-bound views. Query and UI
    surfaces expose freshness, ontology/recipe version, policy, source
    watermark, mapping posture, and unresolved disagreement.

12. **Compile ODK Surface And Package Descriptors**
    ODK compiles semantic refs, object/action models, recipes, connector
    mappings, policy-bound views, projections, workflow schemas, authority and
    receipt obligations, and conformance checks into reusable object views,
    editors, graphs, forms, review queues, dashboards, consoles, domain apps,
    eval packs, worker/package manifests, and marketplace-ready ontology packs.

13. **Propose And Govern Evolution**
    Observed gaps and candidate schemas become versioned proposals. Compatibility
    tests, replay, affected-view analysis, policy review, and mapping challenges
    precede promotion. Changes never silently rewrite historical semantics.

14. **Create Ontology-To-Worker Plans**
    Ontologies, action contracts, recipes, workflow schemas, policy-bound views,
    distilled datasets, tools, evals, benchmarks, and routing categories combine
    into a plan for Worker Training or worker/package generation.

15. **Train, Benchmark, Publish, And Route**
    Hypervisor Foundry, daemon jobs, or sas.xyz training engagements produce a
    `WorkerManifest`, policy envelope, lineage refs, evaluation and benchmark
    receipts, and MoW routing metadata. Publication and routing still require
    their owning admission, authority, marketplace, and settlement paths.

## Local Semantic World Planes And Optional Federation

Federation is an optional mapping and exchange posture: sovereign definitions
plus explicit, policy-bound interoperation for selected objects, claims, or
actions. Domains with no positive interoperation case remain complete local
semantic systems. Each participating domain keeps canonical local objects,
assertions, action contracts, and private context. Other domains receive only
authorized projections, proofs, summaries, derived objects, or query results.

An ontology-bound `OutcomeRoom` may use a shared collaboration schema for
objectives, frontier items, claim leases, hypotheses, attempts, findings,
artifacts, evaluations, verifier challenges, resource leases, contribution
claims, and decisions. The room schema remains namespaced and versioned. The
declared hosted or federated admission policy decides which room updates become
shared-room state; no room turns local Agentgres domains into one mutable graph.

Operational truth and semantic belief remain distinct. Agentgres can
canonically record that a domain admitted an assertion, observation, mapping,
or decision. That records who asserted what, when, under which evidence and
policy; it does not make the proposition universally true. Contradiction,
uncertainty, applicability, supersession, and dispute are therefore first-class
semantic state rather than exceptions hidden in narrative text.

External facts such as death, incapacity, legal identity, title, delivery,
payment, sensor state, or contractual notice enter as provenance-bearing
evidence and assertions under the system's `OracleEvidenceProfileEnvelope`.
The profile defines authorized sources, freshness, independence, aggregation,
uncertainty, contradiction, challenge, and adjudication. A signature proves a
source, and consensus proves agreement under a declared model; neither makes
the external proposition true by itself (`INV-25`).

Durable-purpose systems make the limit especially visible. A protocol intended
to constrain the use of funds after a creator's death needs legal-code
co-design, a constitution, qualified death/incapacity evidence, beneficiaries,
successor or guardian governance, spending and purpose ceilings, challenge
windows, dispute and court/off-chain enforcement interfaces, and dissolution or
residual-asset rules. An ontology and smart contract can make the mandate
legible and enforceable within their reach; they cannot eliminate jurisdiction,
oracle, custody, or real-world enforcement risk.

## Product and Domain Roles

Hypervisor exposes **Ontology** and **Data** as the first-party Applications
catalog entries, Open Application views, or contextual
Project/System/Work/Session panels
over this semantic data plane; **ODK** is the developer kit beneath them
(CLI, templates, scaffolds, generated SDKs, conformance), not the catalog
entry. `Data / Knowledge`, `Data Studio`, `Ontology Studio`, `Workshop`, and
`Domain Blueprints` remain architectural family aliases that resolve to the
Ontology and Data applications, not separate final product apps.

The Data application owns product-level views for:

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

The Ontology application owns product-level views for:

```text
domain ontologies
canonical object models
objects, actions, events, states, roles, and invariants
ontology projections
ontology namespaces, versions, overlays, crosswalks, and mapping challenges
provenance assertions, uncertainty, contradictions, supersession, and disputes
ontology action contracts, previews, state transitions, compensation, and verifier bindings
schema health
used-by relationships across workers, automations, connectors, and apps
```

Hypervisor Foundry consumes these surfaces for training, evaluation,
simulation, worker/package generation, and capability improvement. Foundry may
author or propose ontology and recipe changes, but Agentgres-backed semantic
truth, wallet/network data authority, and transformation receipts remain the
canon boundaries.

The Ontology Development Kit is the builder kit over this layer. It should make
the breadth of Hypervisor surfaces scalable by generating or validating
ontology-bound descriptors for:

```text
object views and object editors
list/detail surfaces
graphs and relationship explorers
forms and guided wizards
review queues and approval inboxes
monitoring consoles and dashboards
data-recipe builders
connector-mapping editors
domain apps and vertical consoles
eval, benchmark, and worker-package skeletons
operator-plane and MCP contract manifests
```

ODK output is scaffolding and conformance material. It can create descriptors,
templates, generated UI, package manifests, and test fixtures, but it does not
own runtime execution, semantic truth, authority, raw data, training consent,
marketplace ranking, or settlement. Generated surfaces must still register as
`extension_application` surfaces with publisher origin, creation method,
distribution, admission, installation, and serving state kept independent;
pass local Packages admission; and bind their package release, surface
descriptor, installation, organization, and—before effectful System
launch—admitted System/context refs. They must also
bind daemon APIs, Agentgres refs, policy-bound views, allowed actions, authority
preview requirements, receipts, replay, and conformance profiles. Optional
Marketplace discovery or commerce never substitutes for local package or
installation admission.

Guided views should come first. Advanced users may open the same ontology,
data, training, evaluation, benchmark, deployment, or outcome recipe in the
Workflow Compositor when graph-level editing is useful.

Learning / Patterns / Examples / Training facets consume this layer whenever an
example becomes launchable. A useful example should identify the DomainOntology,
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

ioi.ai Goal Spaces and Hypervisor Work / Rooms may project an ontology-bound
OutcomeRoom over this layer. They may render frontier objects, findings,
evidence, mappings, and action previews, but shared-room admission remains with
the declared governed host or federation policy; execution remains with the
daemon; authority remains with local/domain governance and portable authority
providers; operational truth remains with each Agentgres domain.

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
DomainOntology aggregate and envelope family
OntologyVersion profile of DomainOntology
OntologyOverlay profile of DomainOntology
OntologyCrosswalk profile of OntologyMapping
SemanticMappingDecision profile of OntologyMapping
CanonicalObjectModel
ProvenanceAssertion profile of OntologyAssertion
OntologyActionContract
DataRecipe
ConnectorMapping
PolicyBoundDataView
InstitutionalLearningBoundaryProfile admission refs and effective snapshots
TransformationRun
TransformationReceipt refs
DistilledOntologyDataset refs
EvaluationDataset refs
OntologyProjection
OntologyToWorkerPlan
OntologyDevelopmentKitManifest
OntologySurfaceDescriptor
```

Agentgres does not own raw connector credentials, decryption keys, or large
payload bytes. It records refs, commitments, object heads, projection
watermarks, receipts, and lifecycle state.

## Authority Boundary

Policy-bound data access is mandatory.

Training, evaluation, export, publication, connector mapping, and recipe
execution must bind to authority grants when they touch private, customer,
regulated, licensed, or organization-owned data.

Policy composition must be deterministic and inspectable: precedence,
intersection, conflicts, exceptions, continuous obligations, and the selected
decision path remain receipted. Revoking source or training eligibility must
propagate through an impact graph covering derived views, distilled/evaluation
datasets, caches, models, workers, packages, releases, and exports. The owning
policy then blocks future use, rotates access, recalls affected artifacts, or
requires re-evaluation; a prior transformation receipt is not perpetual
permission.

### Source Rights And Derivative Constraints

Every governed source contributes constraints to every derived view, dataset,
eval, memory candidate, model artifact, worker, package, route policy, or
export. Composition uses the most restrictive intersection of the active
institutional boundary, source/participant rights, consent, license, provider
route rights, retention, destination scope, and individual eligibility. Union,
majority permission, material transformation, aggregation, de-identification,
or an ontology mapping cannot silently widen a prohibited use.

Transformation lineage preserves both derivation and obligation edges. When a
source right expires, is withdrawn, or is superseded, the impact graph
identifies every known dependent artifact and the owning policy chooses a
receipted disposition: continue under a surviving basis, block future use,
quarantine, recall, re-evaluate, rebuild or retrain from eligible sources, or
delete eligible stored payloads. Historical receipts remain immutable evidence
of past actions; they are not permission for future use.

Recall, quarantine, deletion, and retraining are distinct observable actions.
None proves that a trained model or an external provider has forgotten the
source. A verified-unlearning claim requires a declared property, method,
evaluation, verifier, and assurance result scoped to the affected artifact.
Likewise, a provider receipt or contractual posture can record disclosed terms
and routed bytes but cannot prove hidden provider retention, internal training,
or deletion behavior.

Ontology semantics never grant execution power. An `OntologyActionContract`
describes a typed action and its requirements; the daemon still performs
admission, local/domain governance still applies, and wallet.network supplies
portable delegated or high-risk authority where required. An action contract
that can affect the physical world must bind the Physical Action Safety profile
before any actuator command is eligible.

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

A provider-native thread, vector store, prompt history, fine-tuning service,
hosted eval store, or model endpoint must not be the only durable copy of
institution-owned ontology mappings, corrections, evals, accepted memory,
datasets, or derivative lineage. Customer/IOI-governed canonical refs and
policy-permitted exports must remain sufficient to reconstruct or migrate the
institutional state independently of that provider. This does not grant rights
to export provider-owned weights or hidden state.

## Non-Negotiables

1. Workers train on ontology-bound data, not raw blobs, whenever a domain
   ontology or object model exists.
2. A connector payload is source material, not canonical domain truth, until a
   ConnectorMapping and DataRecipe bind it.
3. Every TransformationRun binds the exact `data-recipe://.../revision/...`
   ref and content hash plus the exact semantic-component snapshot/hash already
   committed by that revision. DataRecipe revisions contain output contracts,
   never concrete run outputs. A changed ontology, ConnectorMapping, object
   model, schema, or policy-bound view requires a successor recipe; runs must
   emit transformation receipts for consequential training, evaluation,
   projection, or service outcomes.
4. PolicyBoundDataViews gate read, transform, distill, train, evaluate,
   export, publish, and route use of private or governed data.
5. Every governed learning use binds the effective
   `InstitutionalLearningBoundaryProfile`, individual evidence eligibility, and
   applicable source/teacher/model-route rights. Their most restrictive
   intersection controls the derivative.
6. Distillation must preserve provenance. A distilled dataset must bind source
   commitments, recipe versions, policy-bound data views, transformation
   receipts, and teacher/verifier refs when used.
7. EvaluationDatasets must bind ontology refs, rubric refs, benchmark refs,
   source commitments, and policy.
8. OntologyProjections are serving views over Agentgres truth. They must expose
   freshness, recipe version, policy, and source watermark.
9. OntologyToWorkerPlan can propose workers, tools, schemas, evals, and
   manifests, but it cannot grant authority.
10. Ontology Development Kit descriptors can scaffold surfaces, domain apps,
   evals, workers, and packages, but they cannot become runtime truth,
   permission truth, semantic truth, or marketplace truth by themselves.
11. Every ODK-generated surface must declare owning ontology refs, object-model
   refs, data-recipe refs where applicable, policy-bound data view refs,
   authority requirements, daemon/API dependencies, receipt obligations, and
   conformance expectations before it becomes durable product inventory.
12. The semantic data plane connects Worker Training to the IOI stack; it does
    not replace compute markets, Agentgres, wallet.network, storage backends,
    MoW, service composition, settlement, or disputes.
13. No network-wide ontology, crosswalk, or room schema may silently override a
    domain's canonical local ontology. Namespace, version, compatibility, and
    mapping posture must remain explicit.
14. No admitted assertion may be presented as universal truth merely because it
    is canonical operational state in one domain. Provenance, time,
    uncertainty, contradiction, applicability, supersession, and dispute must
    survive projection.
15. No consequential ontology action may remain an untyped action-name array.
    It must bind typed IO, state-transition semantics, capability, authority,
    risk, idempotency, ambiguous-effect and compensation behavior, verification,
    evidence, and receipt obligations.
16. No ontology program may require exhaustive enterprise modeling before
    useful work begins. Minimal consequential object/action contracts and
    governed evolution from observed work are first-class.
17. No ontology or mapping update may rewrite a protected constitution through
    semantic indirection. Constitutional amendments use their own declared gate.
18. No external-world assertion may become an effect trigger merely because it
    is signed, repeated, receipted, or consensual; the declared oracle/evidence,
    policy, authority, and challenge path must admit the consequence.
19. No ontology mapping or federation is required merely because schemas are
    compatible. Cross-domain semantic exchange proceeds only under accepted
    terms when its expected operational value exceeds mapping loss, disclosure,
   verification, coordination, and downstream-action risk (`INV-30`).
20. No provider-native store may be the sole durable copy of
    institution-owned ontology, correction, evaluation, memory, or learning
    lineage needed for provider-independent operation.
21. A receipt proves only its declared transformation, policy, routing,
    deletion, recall, or verification fact. It does not prove hidden provider
    behavior or model unlearning by implication.

## One-Line Doctrine

> **Domain Ontologies say what work and action mean locally and, when selected,
> how meanings map across sovereign domains; Data Recipes attest how source data
> became ontology-bound runtime, training, evaluation, and query material; ODK
> turns those contracts into repeatable surfaces, domain apps, evals, workers,
> and packages without owning truth, authority, or execution.**
