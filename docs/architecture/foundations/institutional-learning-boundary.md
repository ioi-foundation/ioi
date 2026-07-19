# Institutional Learning Boundary

Status: canonical architecture owner.
Canonical owner: this file for the Enterprise Learning Boundary product
contract, `InstitutionalLearningBoundaryProfile` composition semantics,
institutional-intelligence portability, model-independence doctrine, and the
boundary between private institutional improvement and external or
cross-tenant learning.
Supersedes: prose that treats provider privacy terms, model selection, a private
workspace, or data ownership alone as a complete institutional-learning
boundary.
Superseded by: none.
Last alignment pass: 2026-07-13.
Doctrine status: canonical.
Implementation status: planned cross-cutting profile over partial underlying
primitives; do not claim end-to-end enforcement until the golden conformance
profile passes.

## Canonical Definition

**Enterprise Learning Boundary** is the product label for the institution's
governed boundary around the material and mechanisms through which its
intelligence compounds.

`InstitutionalLearningBoundaryProfile` is the versioned, machine-readable
contract behind that label. It compiles source rights, ontology and data-use
policy, model-route rights, runtime custody, Agentgres lineage, Foundry
eligibility and derivative disposition, retention, export, revocation, and
receipt obligations into one fail-closed decision context.

The enterprise thesis is:

> Foundation models are replaceable cognition supply. The institution's
> ontology, memory, corrections, evaluations, workflows, evidence, policies,
> lineage, and eligible derived capability are durable institutional
> intelligence governed by the institution's declared boundary.

This is the clearest enterprise reason for Ontology, Hypervisor, Agentgres,
Foundry, Private Workspace, and model-neutral routing to exist as one system.
It is not the whole IOI category thesis: the broader architecture remains an
open operating stack for bounded autonomous institutions, including individual,
public, physical, and multi-party systems.

## One Promise, Existing Owners

```text
                   Enterprise Learning Boundary
                    compiled policy overlay
                              |
       +---------------+------+-------+----------------+
       |               |              |                |
 Ontology/Data      Hypervisor     Agentgres      Learning consumers
 meaning and use   admission and    lineage and   Foundry / Improvement /
                    egress proof       state         Evaluations
       |               |              |                |
       +---------------+------+-------+----------------+
                              |
                Private Workspace + model router
                    custody + cognition supply
```

The profile composes, but does not absorb, the existing owners:

- Domain Ontologies, Data Recipes, Connector Mappings, and
  `PolicyBoundDataView` own meaning, transformation, and permitted data use.
- Hypervisor Daemon owns runtime admission, effect mediation, egress
  enforcement, and execution receipts.
- Agentgres owns admitted operational state, provenance, lineage, impact-graph
  state, and receipt references. It does not grant source or training rights.
- Foundry owns governed dataset and candidate-asset construction, training,
  packaging, and admitted experiment execution. Evaluations owns frozen
  judgment contracts and evaluator validity. Improvement coordinates optional
  Campaign state and target-owner proposal handoff. Governance and the target
  owner alone decide promotion, activation, rollback, recall, containment, and
  compensation. None of these projections grants execution power.
- Private Workspace owns its declared workspace/runtime custody disciplines.
- The model router owns route eligibility, provider/model contract binding,
  fallback admission, and invocation decisions.
- wallet.network or another declared authority provider owns portable grants,
  consent, credentials, decryption, spend, publication, and high-risk export
  authority when required.
- A bounded autonomous system's constitution and upgrade process own changes to
  the profile revision pinned by that sovereign system.

The learning boundary is **not** a new authority plane, truth store, runtime,
fifth scaling plane, privacy tier, or legal-right generator. It is a
cross-cutting policy compilation over those owners.

## Profile Scope, Inheritance, And Sovereignty

The canonical narrowing path is:

```text
organization default
  -> project profile
    -> bounded-system profile
      -> immutable session / GoalRun / model-invocation /
         transformation / Foundry-run snapshot
```

Rules:

1. Each child profile may narrow, but may not silently widen, every applicable
   parent restriction. Effective policy is the most-restrictive deterministic
   intersection. A conflict, missing required contract, or indeterminate right
   denies the disputed use.
2. An organization or project profile governs future compilation. It is not an
   ambient administrative back door into a sovereign bounded autonomous system.
3. At genesis or a governed upgrade, a bounded system pins an exact profile
   revision and compiled policy hash under its constitution and deployment
   profile. A later parent change becomes an upgrade input; it does not mutate
   the live system by implication.
4. A run, model invocation, transformation, or Foundry job uses an immutable
   effective snapshot. Mid-run policy changes may stop or quarantine future
   effects, but must not rewrite the receipts for effects already admitted.
5. Widening a system-bound profile requires the system's ordinary or protected
   upgrade path as classified by its constitution, plus any external rights or
   authority that the new use requires. A worker, model, provider, Foundry job,
   or organization default cannot self-grant the widening.
6. Emergency revocation, legal hold, safety stop, credential revocation, or
   source-rights invalidation may narrow or stop use immediately under already
   declared authority. It cannot widen another use.

## Protected Learning Material

The profile can govern any declared subset of:

- source documents, records, connector payloads, database projections, and
  ontology assertions;
- prompts, completions, tool calls, tool results, work graphs, traces, receipts,
  and normalized observations;
- human corrections, reviewer judgments, approvals, rejections, preferences,
  and escalation decisions;
- private evaluations, rubrics, holdouts, canaries, benchmarks, and failure
  cases;
- Agent Wiki entries, context mutations, memory projections, procedures,
  workflows, skills, packages, and route knowledge;
- Data Recipes, datasets, embeddings, indexes, synthetic and distilled data;
- adapters, checkpoints, weights, verifier models, route policies, and promoted
  worker or capability packages;
- model-router, authority, governance, and verifier policy refinements;
- product analytics, telemetry, crash/support material, security signals, and
  embodied sensor, actuator, mission, operator, or fleet traces.

Hidden model scratchpads or provider-internal state that IOI neither receives
nor is entitled to obtain are not silently reclassified as institution-owned
material. The boundary governs material IOI can identify, contract for, admit,
observe, or prove.

## Source Rights Before Learning Rights

Creation inside an enterprise boundary does not by itself establish a right to
train, distill, commercialize, publish, or transfer the material. Employee,
contractor, customer, patient, partner, vendor, licensed, purchased, public,
synthetic, provider-output, and machine-generated sources may have different
rights.

`LearningSourceRightsClaimEnvelope` records the asserted basis, rights holders,
permitted and prohibited uses, evidence, validity, and derivative disposition
for governed material. It is a policy input and auditable claim, not a court,
title registry, patent, copyright license, or automatic finding of ownership.

The default posture is:

```text
unknown, expired, conflicting, or unsupported source rights
  -> no training, distillation, cross-tenant learning, publication, or export
```

Operational inference may still be allowed when its separate access and use
rights are established. Inference permission never implies improvement rights.

## Directional Learning Rights

Every external cognition route must answer two independent questions:

1. What may the institution do with outputs produced for its work, including
   retention, evaluation, replay, fine-tuning, distillation, competing-model
   training, packaging, commercialization, export, and publication?
2. What may the provider or intermediary do with institutional material,
   including transient inference, service logging, human review, abuse/security
   analysis, support, retention, service improvement, provider-model training,
   cross-customer aggregation, and publication?

Missing rights fail closed for the affected use. Compare, ensemble, cascade,
and synthesized outputs inherit the intersection of every contributing source
and route. An aggregator is a route adapter, not a new rights or privacy
boundary.

Provider secondary use and cross-customer learning are denied by default for
protected material. A provider's account-level opt-in, broad service default,
or changed terms cannot silently override the effective profile.

## Runtime And Custody Quadrants

`Standard` versus `Private` describes execution and provider-trust posture.
Managed versus self-hosted describes who operates the runtime. They are
orthogonal:

| Runtime operator | `Standard` | `Private` |
| --- | --- | --- |
| IOI-managed | IOI-managed private-native substrate where available; disclosed, policy-qualified provider-trust model routes may receive admitted plaintext. | IOI-managed or brokered custody-proven runtime plus a no-provider-trust model route; the claim requires current custody and route evidence. |
| Customer/local/self-hosted | Customer-operated runtime; external provider-trust routes remain possible when explicitly admitted. | Customer boundary, local/open model, customer VPC, approved TEE/cTEE, or equivalent custody-proven route in which protected plaintext is not sent to a disallowed provider. |

Neither self-hosting nor `Private` proves source rights. Neither a `Standard`
route nor a zero-retention promise proves that the provider did not learn.
Contractual no-training and retention promises are valuable provider-trust
controls; no-provider-plaintext and attested private compute are stronger
custody claims. Receipts must state which claim is actually supported.

## Governed Improvement Loop

The canonical institutional loop is:

```text
work and observations
  -> source-rights and policy classification
  -> LearningEvidenceEligibility decision
  -> PolicyBoundDataView + DataRecipe transformation
  -> Agentgres lineage and receipt admission
  -> Foundry dataset, candidate/evaluator assets, and admitted experiment jobs
  -> Evaluations frozen judgment, exposure, challenge, and validity
  -> direct UpgradeProposal or optional ImprovementCampaign handoff
  -> regression, rights, privacy, target-owner authority, and recovery gates
  -> activated memory, worker, model, route, package, or other successor
  -> monitored work and new eligible evidence
```

No raw exhaust enters Foundry merely because it was observable. Every admitted
input binds the effective learning-boundary profile, source-rights claims,
privacy and retention policy, intended use, and eligibility decision. Every
derived artifact retains those refs or a deterministic aggregate commitment to
them.

`LearningEvidenceEligibility` is the general decision for admitting a Finding,
OutcomeDelta, production observation, correction, trace, artifact, or other
evidence into a later improvement process. `TrainingEvidenceEligibility` is its
training-oriented compatibility profile for datasets, evaluation generation,
distillation, and model or worker training; it is not the only permitted
learning use. Same-boundary campaign synchronization binds eligibility plus the
applicable access and custody evidence without fabricating an egress event.
`LearningEgressReceipt` is required only when an institutional boundary is
actually crossed or a crossing is blocked before egress.

The learning boundary governs capability improvement, not operational power.
A promoted model, route, memory mutation, skill, or worker remains subject to
ordinary manifest, policy, authority, verifier, and runtime admission.

## Derived Rights, Revocation, And Honest Unlearning

Rights and restrictions travel through transformations. Agentgres must be able
to traverse an impact graph from a governed source through views, recipes,
datasets, embeddings, checkpoints, models, workers, packages, routes, releases,
exports, and public commitments.

When a source right, consent, eligibility decision, route contract, or boundary
profile becomes invalid, the owning policy may:

- block future read, training, evaluation, routing, export, or publication;
- quarantine or revoke a dataset, checkpoint, model, worker, package, or route;
- require re-evaluation, clean reconstruction, retraining, or redeployment;
- recall an installed/exported artifact where the applicable terms and
  authority support recall;
- preserve a minimum audit commitment under declared retention or legal-hold
  policy.

A revocation or impact record does not prove that a trained model has forgotten
the source. IOI may claim removal from future datasets, clean retraining,
verified unlearning, or deletion only when the corresponding evidence exists.
Past recipients and irreversible public disclosures must remain visible as
residual exposure, not be erased from the ledger narrative.

## Cross-Tenant And Ecosystem Learning

Seller, provider, marketplace, network, and cross-customer improvement are
default-deny. Buyer-bound worker memory and corrections remain with the buyer's
declared owner scope unless an explicit export is admitted.

An opt-in aggregate-learning program must independently bind:

- eligible material and source-rights claims;
- participating tenant and beneficiary scopes;
- exact aggregation, redaction, privacy, and non-reconstruction controls;
- permitted model, worker, package, or public-good destination;
- contribution attribution, consideration, benefit-sharing, and exit terms
  where applicable;
- retention, revocation, residual exposure, and receipts.

Anonymization language alone does not authorize cross-tenant reuse. Differential
privacy or another aggregation control can reduce exposure; it cannot create
missing rights.

## Portability And Model Independence

`InstitutionalIntelligenceExportBundleEnvelope` is the governed export manifest
for rights-eligible institutional intelligence. It may include:

- ontology versions, object models, Data Recipes, mappings, and policy-bound
  views;
- Agent Wiki and memory archives/projections;
- evaluations, rubrics, canaries, datasets, and lineage commitments;
- workers, workflows, skills, tools, packages, adapters, checkpoints, and
  weights when licensed for transfer;
- route, verifier, governance, retention, revocation, and promotion policy;
- receipts, state roots, source-rights claims, exclusions, and residual
  obligations.

Payload bytes remain encrypted artifacts or customer-directed exports. The
bundle is an Agentgres-admitted manifest with authority, integrity, destination,
retention, and receipt bindings; it is not a raw database dump.

Import never activates the bundle by possession. The receiving domain verifies
integrity and source-rights evidence, recompiles the bundle against its own
effective boundary and authority, admits only eligible objects through their
canonical owners, and records imported, excluded, quarantined, transformed,
and unsupported entries plus receipts. Export permissions remain ceilings;
import cannot widen them.

Every enterprise profile must define a **Model Independence Test**:

1. establish a task/evaluation baseline using Model A;
2. disable Model A, its provider-native thread state, hidden memory, and
   provider-only tools;
3. mount a policy-qualified Model B through the same Hypervisor contracts;
4. restore only institution-controlled, rights-eligible state and artifacts;
5. execute the declared evaluation suite and publish the delta, unsupported
   dependencies, and threshold verdict.

Passing proves operational continuity above the declared threshold. It does
not prove that all models are equivalent or that every provider-specific
feature is portable.

## Product Projection

Enterprise Learning Boundary is one cross-surface object, not another top-level
application:

- **Governance** authors scope, rights, retention, secondary-use, export,
  revocation, and cross-tenant rules.
- **Ontology and Data** show eligible, excluded, disputed, and expiring source
  material and its allowed uses.
- **Models and routing** show not only cost and quality but where prompts,
  outputs, corrections, and telemetry may be retained or learned from.
- **Private Workspace and Environments** show runtime operator, custody claim,
  provider-trust boundary, proof freshness, and unmet Private requirements.
- **Foundry** shows admitted evidence, derived-rights constraints, candidate
  disposition, promotion eligibility, recall, and clean-rebuild state.
- **Provenance and Agentgres** show lineage, egress, derivative impact,
  exclusions, residual exposure, and receipts.
- **Goal Space and managed-worker setup** let the accountable party choose
  whether a run may improve only this session, worker, project, organization,
  seller, eligible cohort, or public ecosystem; choices broader than the
  effective profile remain unavailable.

The route selector must make **where learning goes** legible alongside where
inference runs.

## Public Settlement Boundary

Institutional learning contents, private traces, datasets, memory, weights, and
eval cases do not go to IOI L1 by default. A system may optionally settle sparse
hash commitments, rights/version commitments, contribution allocations,
disputes, or revocation markers under its explicit network enrollment and
settlement profile. A public commitment proves only the scoped commitment; it
does not prove legal ownership, semantic truth, model forgetting, or private
custody.

## Golden Conformance Demo

The flagship enterprise proof must be automated and adversarial:

1. seed a confidential correction and private evaluation with a unique canary;
2. bind a profile that permits project-private improvement but denies provider
   training, external plaintext, seller learning, and cross-tenant reuse;
3. attempt a disallowed provider route and prove it is blocked before network
   egress with a learning-egress decision receipt;
4. admit a custody-qualified route, build an eligible dataset, improve a private
   candidate through Foundry, and retain complete lineage;
5. disable Model A and demonstrate Model B continuity above the declared
   Model Independence threshold using only exported or mounted
   institution-controlled state;
6. prove seller and second-tenant requests cannot obtain the correction,
   evaluation, memory, or derivative;
7. authorize an export, verify its manifest and omissions, then revoke one
   source and prove impact propagation blocks future affected use and marks any
   irreversible residual exposure honestly;
8. use packet capture or an equivalent mock transport assertion to prove the
   canary never crossed the prohibited boundary.

The normative pass/fail contract is
[`../../conformance/hypervisor-core/institutional-learning-boundary.md`](../../conformance/hypervisor-core/institutional-learning-boundary.md).

## Claims And Non-Claims

When the conformance profile is not yet passing end to end, the accurate claim
is:

> IOI is designed to make institutional learning governable, portable, and
> provider-substitutable across ontology, runtime, state, improvement, custody,
> and routing boundaries.

After a specific deployment passes, IOI may claim only the measured profile and
evidence for that deployment.

The architecture does not claim that:

- using an external provider is cryptographically private;
- a contract proves a provider did not learn;
- IOI automatically owns employee, customer, provider, public, or generated
  material;
- source deletion automatically removes learned influence from weights;
- model substitution preserves every capability;
- a receipt proves off-platform recipient behavior;
- a public-chain commitment proves the underlying material or ownership claim;
- `Private`, self-hosted, encrypted, or zero-retention are interchangeable
  labels.
