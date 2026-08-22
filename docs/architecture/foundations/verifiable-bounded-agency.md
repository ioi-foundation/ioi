# Verifiable Bounded Agency and Execution-Boundary Alignment

Status: canonical architecture authority.
Canonical owner: this file for IOI's alignment-security thesis, verifiable bounded agency, and execution-boundary alignment doctrine.
Supersedes: the retired docs/specs/verifiable_bounded_agency.md (removed 2026-08-12) and product prose that claims IOI solves alignment by model cognition, prompt compliance, or one required proof backend.
Superseded by: none.
Last alignment pass: 2026-08-12.
Doctrine status: canonical
Implementation status: mixed (execution-boundary gating built in the daemon;
the inference-computation-proof subsection is durable claim hygiene with no
product profile or path admitted, and broader proof/zk continuity remains
speculative)
Last implementation audit: 2026-07-05

## Canonical Definition

**Verifiable bounded agency is IOI's alignment-security thesis: autonomous
workers may reason probabilistically, propose actions, and improve capabilities,
but consequential effects cross into reality only through daemon-mediated,
policy-checked, authority-scoped, receipt-bearing execution.**

Short form:

> **Intelligence may be probabilistic. Authority must be bounded, explicit, and verifiable.**

This is an execution-boundary claim. IOI does not need to prove that a model's
private cognition is perfectly aligned before the model can be useful. IOI
constrains what autonomous actors can do by separating:

- cognition and proposal;
- authority grants and approvals;
- deterministic effect admission;
- operational truth;
- payload availability;
- public settlement.

The model, worker, or agent may generate candidate actions. It is not the final
authority boundary for real-world effects.

Bounded does not mean benevolent. A constitution can make a harmful purpose
explicitly bounded, and a well-intentioned purpose can still be implemented
unsafely. IOI's claim is that declared power, change, persistence, and effects
can be constrained and audited; purpose legitimacy remains the responsibility
of accountable principals, affected-party governance, law, and domain-specific
assurance.

## Claim Boundary

IOI's canonical safety claim is **execution-boundary alignment**, not total
cognitive alignment.

This means IOI addresses the operational alignment problem:

```text
Can an autonomous actor produce a consequential effect only when that effect is
inside a delegated policy envelope, bound to authority, recorded as evidence,
and challengeable or settleable when needed?
```

It does not claim to fully solve every model-internal alignment problem:

```text
Can we prove a neural network's private goals, latent objectives, or future
reasoning will always be safe?
```

The architecture still values model evaluation, Worker Training, verifier
quality, routing quality, prompt hardening, red-team work, and interpretability
research. Those improve capability and reduce risk. They do not replace the
deterministic authority boundary.

### Optional Inference-Computation Proofs

An inference-computation proof is optional stronger evidence for one model
invocation. Under a named, versioned statement and verifier profile, it may
establish only that the admitted verifier accepted a proof binding the declared
model-execution commitment, invocation and input, execution configuration and
randomness where applicable, and output.

That result does not establish semantic truth, quality, safety, authority,
provider identity, model approval, custody or confidentiality, absence of other
computation or egress, external-world occurrence, or billing correctness. It
does not upgrade cTEE or RATS evidence and does not replace Evaluations. No
prover, proof system, vendor, quantization, circuit encoding, security parameter,
or performance envelope is canonical by default.

An invocation proof may be linked into a service delivery's evidence graph, but
composition never widens its proposition. It does not prove the enclosing agent
trajectory, workflow, service outcome, artifact semantics, deliverable,
acceptance criteria, SLA, or settlement condition.

This subsection is durable claim hygiene for any present or future computation-
proof evidence; it is not a product commitment, route admission, schema promise,
or implementation mandate. An accountable adverse research disposition may
retain the product targets dormant, narrow them to exact supported profiles, or
withdraw the unimplemented Router, receipt, and Foundry targets. Failure of one
exact proof profile defaults to narrowing or retiring that profile, not erasing
this generic proposition/nonclaim boundary.

## Root Difference

Most agent systems pursue risk reduction through supervision:

- prompt rules;
- tool allowlists;
- confirmation dialogs;
- sandboxing;
- snapshots and undo;
- human review after the fact.

These controls matter, but they often preserve the same basic shape:

> the model has broad access, and the system tries to persuade or supervise it
> into not misusing that access.

IOI rests on a different premise:

> **authority is reduced by architecture, not merely moderated by supervision.**

The transition is from:

```text
the model has access, but we hope it behaves
```

to:

```text
the actor never had that authority in the first place, except under explicit,
bounded, receipted, and revocable conditions
```

## Alignment-Security Model

IOI separates the autonomous stack into distinct responsibility planes:

```text
cognition/proposal
  model calls, planning, synthesis, ranking, tool-use proposals

execution admission
  daemon policy checks, deterministic effect boundary, approvals, risk classes

authority
  wallet.network scopes, grants, leases, secrets, payments, revocation

operational truth
  Agentgres operations, object heads, receipts, projections, quality ledgers

payload/evidence availability
  storage backend payloads, packages, evidence bundles, checkpoints, archives

optional shared public trust and settlement
  selected services such as IOI L1 registries, rights, escrows, disputes,
  roots, and governance
```

The same doctrine can be stated in the repo's core sentence:

> **Hypervisor Daemon executes. Authority is granted by local/domain governance
> or wallet.network according to risk boundary. Agentgres remembers. MoW routes.
> Selected settlement services settle; IOI L1 is optional. Clients compose.
> Evidence proves.**

## What Bounded Power Looks Like

### No Ambient Authority

Workers do not inherit broad standing power merely because they are active.

Authority appears as explicit artifacts: leases, approvals, session grants,
authority scopes, and equivalent delegated credentials. Those artifacts are
narrow by construction:

- scoped to specific resources;
- scoped to specific operations;
- scoped to explicit budgets;
- scoped to clear time windows;
- revocable;
- bound to policy identity;
- bound to evidence duties where relevant.

The meaningful shift is from:

```text
this agent can touch the repo
```

to:

```text
this worker may edit only these paths
this worker may not delete protected files
this worker may call this connector only under this policy hash
this worker may spend only within this budget class
this worker may act only until this lease expires or is revoked
```

Raw secrets and root authorities remain outside the model-facing runtime in
wallet.network or an equivalent authority plane.

### Probabilistic Cognition, Deterministic Authority

Autonomous intelligence is probabilistic. Authority cannot be.

IOI contains probabilistic work before the point of effect:

- intent inference;
- planning;
- candidate action generation;
- payload synthesis;
- dry-run and lint loops;
- verifier and reviewer proposals.

Once an operation reaches the effect boundary, the daemon requires deterministic
admission:

- loaded contract;
- required primitive capabilities;
- required authority scopes or grants;
- policy decision;
- exact request hash when approval is required;
- committed action or payload;
- receipt and verification obligations.

This aligns with the conformance split:

- `CIRC` collapses
  semantic uncertainty into deterministic intent state.
- `CEC` governs
  deterministic effect execution, evidence, verification, remediation
  boundaries, and terminal completion.

### Evidence-First Irreversibility

Soft actions tolerate mistakes. Sealed effects do not.

Once the action is deleting production data, rotating credentials, wiring
money, publishing a release, merging a breaking change, changing policy, or
reconfiguring infrastructure, the safety model can no longer rest on "we can
undo it later."

Bounded power expresses irreversibility through visible conditions:

- explicit policy match;
- valid effect commitment;
- correct authority provenance;
- bounded scope;
- approval or challenge windows;
- receipt generation;
- deterministic verification before completion;
- settlement or dispute hooks when needed.

The question is no longer whether the model seems careful. The question is
whether the action can cross the boundary at all.

### Governed Improvement Instead of Self-Escalation

Recursive improvement matters only if the improvement loop is itself
governable.

Within bounded autonomy, improvement remains possible:

- better prompts and instructions;
- stronger workflows;
- generated tests;
- routing and model upgrades;
- better decompositions;
- better tools and verifiers;
- reusable service candidates;
- trained or configured workers.

But the actor can improve inside the lane without silently widening or moving
the lane.

Canonical self-upgrade invariant:

> **A worker may propose changes to logic, package, policy requirements,
> training profile, model route, tool use, or workflow topology, but it may not
> grant itself broader authority.**

The protected boundary is broader than authority alone. Ordinary improvement
may not commit changes to constitutional purpose or prohibitions, amendment
rules, authority/effect ceilings, ordering/finality, oracle/evidence policy,
verifier independence, emergency stop, lifecycle continuity, succession,
dissolution, decommission, or revocation. Those changes use the distinct
decision path named by the active constitution (`INV-21`). The same actor or
coalition must not control proposal, verification, constitutional amendment,
and final admission when the profile claims independent assurance.

Self-preservation is not a privileged objective. Replication, node admission,
code propagation, resource acquisition, successor activation, and recovery are
governed effects bounded by membership, budget, purpose, external revocation,
and terminal shutdown (`INV-28`). The system may recover from a failed machine;
it may not spread to an unadmitted machine to avoid being stopped.

Policy widening requires an external authority path: user approval,
wallet.network grant, organization policy, domain governance, IOI L1 governance,
or another explicitly authorized control plane.

Continuity proofs, formal checks, zkVM proofs, attestations, regression gates,
and policy-subset proofs are all valid implementation strategies for stronger
upgrade assurance. No single proving backend, including SP1, is canonical by
default for all IOI upgrades.

### Proposal-Mediated Autonomous-System Upgrades

Bounded recursive improvement is not an agent directly rewriting itself.

The governed-autonomous-system form is:

```text
observe limitation
-> draft upgrade proposal
-> bind target module, workflow, policy, tool, model route, schema, or contract
-> simulate, evaluate, benchmark, or dry-run
-> review under policy and authority
-> approve, reject, escalate, or roll back
-> commit accepted operation through daemon/Agentgres
-> emit receipts and optional IOI L1 roots
```

That direct proposal path remains the ordinary low-complexity default. When an
improvement process adaptively generates or compares many candidates, rotates
evaluators, consumes sealed holdouts, spans multiple evaluation epochs, or
targets the method that produced earlier improvements, it must bind the
optional `ImprovementCampaign` protocol rather than hide the research history
inside one proposal. A GoalRun coordinates that campaign; an immutable
`EvaluationEpoch` fixes what counts as evidence; statistical eligibility may
produce an upgrade proposal but never authority; and the target owner alone
activates a successor for a declared future scope.

Recursive order is an evidence coordinate, not an authority multiplier. Every
admitted campaign has a finite target path, target-order ceiling, active-depth
ceiling, budget, deadline, learning boundary, evaluator posture, and recovery
contract. Creating a child campaign or relabeling a target cannot reset
inherited resource, statistical-risk, holdout-exposure, authority, or
learning-rights ceilings. See
[`bounded-recursive-improvement.md`](./bounded-recursive-improvement.md).

Canonical upgrade invariant:

> **Agents do not self-modify directly. Autonomous systems propose upgrades to
> governed modules, and only policy-bound, receipted governance makes those
> upgrades canonical.**

Canonical evaluation invariant:

> **A candidate cannot define or alter the evidence, meter, evaluator,
> promotion authority, or recovery path that makes the same candidate
> canonical. Evaluator successors begin only in a later frozen epoch, and old
> verdicts remain bound to the evaluator versions that issued them.**

Mutable upgrade targets should be concrete governable units:

- policy modules;
- service modules;
- workflow graphs;
- contracts;
- tool bindings;
- model routes;
- memory or projection schemas;
- settlement rules;
- dispute rules;
- authority envelopes.

Constitution, deployment/membership, ordering/finality, oracle/evidence,
lifecycle, and IOI Network enrollment are governable targets but not ordinary
mutable upgrade targets. A proposal may address them only through their
constitutionally declared high-assurance path. A system cannot remove its own
kill switch or dissolution path merely because an eval score improved.

The agent may be intelligent upstream of the boundary. Commitment remains
deterministic at the boundary.

### Credential Isolation

Unbounded agents become dangerous when root secrets, refresh tokens, wallets,
SSH keys, cloud credentials, or provider API keys are placed inside their
environment.

IOI's rule is:

> **The actor cannot leak what it never possesses.**

wallet.network owns root secrets, authority grants, payment approvals,
connector credentials, BYOK keys, decryption leases, and revocation epochs. The
daemon requests operation-scoped authority and receives only what the operation
requires, preferably without exposing raw long-lived secrets to the worker or
model-facing runtime.

For effectful connector and payment flows:

```text
worker proposes action
→ daemon constructs ActionRequest / AuthorityScopeRequest
→ wallet.network evaluates policy and grant state
→ approval is collected when required
→ daemon or guarded connector executes under scoped authority
→ Agentgres records operation, receipts, and refs
→ IOI L1 receives a sparse commitment only when an explicit enrollment and
  settlement profile selects it
```

### Deterministic Harnesses and Controlled Environments

Conformance harnesses should make execution as deterministic as the risk class
requires. Depending on the task, this may include:

- fixed seeds;
- controlled clocks;
- deterministic fixtures;
- dry-run providers;
- replayable task capsules;
- schema-checked tool contracts;
- single-shot effect execution;
- typed verification receipts;
- sandboxed filesystem, browser, shell, or network profiles.

These are harness and runtime profile techniques, not a universal claim that
all physical or remote environments become perfectly deterministic. The
canonical requirement is narrower and stronger:

> **Consequential completion must be admitted, executed, and verified through
> typed contracts, policy, authority, receipts, and replayable evidence.**

## Separation of Powers

The safest multi-actor system is not one super-agent with all keys.

It is a composition of bounded principals:

- planner;
- researcher;
- verifier;
- executor;
- publisher;
- supervisor;
- wallet authority;
- domain kernel;
- settlement contract.

Each principal can carry different leases, budgets, evidence duties, approval
rights, and escalation powers. This turns autonomy from a shared blob of power
into a legible system of compartmentalized authority.

An OutcomeRoom preserves this separation at collective scale. Participants
join through identity/eligibility and visibility policy; receive bounded
context, authority, resource, budget, tool, and work-claim leases; execute in
isolated domains; publish attributable attempts and findings; and cross shared
state only through hosted or federated admission. Messages, artifacts,
ontology mappings, verifier suggestions, and executable results from any
participant remain tainted proposals until admitted. Consensus among agents is
evidence, never authority or truth by itself.

Multi-model, multi-worker, multi-node, and multi-party are not synonyms. Many
workers or clouds controlled by one operator remain one authority/risk/truth
principal. Independent-party verification requires a separately accountable
principal with disclosed affiliation, its own authority and revocation path,
and the declared verification/adjudication role.

## Governed Effect Claim Manifest

Every public governed-effect certificate or evidence bundle MUST carry a typed
`GovernedEffectClaimManifest`. The manifest binds an exact certificate subject,
its source basis, and a named protection profile to an exhaustive vocabulary of
demonstrated claims and bounded nonclaims. A claim marked `demonstrated` MUST
name at least one durable evidence reference. A claim without such evidence
MUST be `not_demonstrated`, `indeterminate`, or `not_applicable` and MUST explain
the limitation. Claim status is evidence-derived; a publisher cannot promote it
through prose or by changing only the manifest.

The canonical claim identifiers are:

- `governed_infrastructure_lifecycle`;
- `workload_readiness`;
- `workload_result_binding`;
- `logical_policy_mediation`;
- `workload_bound_isolation_enforced`;
- `worker_secret_non_possession_tested`;
- `separate_verifier`;
- `independently_reproduced`;
- `third_party_verified`;
- `provider_neutrality`;
- `bare_metal_placement`.

These identifiers are deliberately non-substitutable. A separate verifier
binary is not an independent reimplementation; an independent implementation
is not third-party operation; daemon policy mediation is not workload-bound
isolation; and secret custody outside model context is not an adversarial test
of worker secret non-possession. The manifest names one of four protection
profiles: `development_cooperative`, `trusted_host_hostile_guest`,
`unattested_remote_host_bounded_authority`, or
`attested_confidential_worker`. A stronger protection profile cannot be inferred
from a weaker one.

The registered wire contract is
`schema://ioi/components/hypervisor/governed-effect-claim-manifest/v1`.

## Relying-Party Acceptance

A certificate is evidence, not acceptance. `RelyingPartyAcceptancePolicy`
names the accountable audience, accepted certificate and result schemas, trust
roots, freshness and revocation posture, required demonstrated claims,
tolerated nonclaims, environment/honesty classes, verifier profile, and the
single durable transition that acceptance may perform. Unknown schemas,
claims, trust roots, audiences, verifier profiles, or stale inputs fail closed.

The first relying party is the AFT measured-results registry. Its only admitted
transition promotes one verified U1 measurement row into the measured-cost
registry. Verification failure or policy mismatch writes a
`CertificateAcceptanceReceipt` with typed failures and leaves the target state
hash unchanged. Acceptance writes the accepted object/revision and binds the
state-before and state-after hashes. The receipt also binds the certificate,
policy, verifier identity/build, exact trust-input hashes, observation time,
and validity horizon. A producer cannot self-declare registry acceptance by
embedding an `accepted` field in its own certificate.

`AftU1CampaignResult` is the closed aggregate emitted by the fixed U1
measurement protocol. `AftMeasuredResultRow` is the promoted object binding
that result to the accepting C8 v3 certificate, immutable workload and source,
environment, provider, honesty class, and verdict. `AftMeasuredResultsRegistry`
is the compare-and-set target containing an ordered set of accepted row
ref/hash pairs, a monotonic revision, the prior state hash, and its own state
commitment. Row bodies remain separately portable and schema-verifiable rather
than being copied into registry state.

`VerifierIndependenceProfile` declares the ADR 0032 axes individually. The
first-party AFT verifier may claim `separate_binary`, `separate_codegen`, and
`separate_transport` only with evidence for each, and must leave
`separate_authoring_party` false until a disclosed external principal authors
and maintains an implementation. `C8PortableEvidenceBundle` is the filesystem
framing used by that verifier: every JSON object and trust input is named by a
safe relative filename plus its schema ref, object ref, and canonical hash.

The registered contracts are:

- `schema://ioi/foundations/relying-party-acceptance-policy/v1`; and
- `schema://ioi/foundations/certificate-acceptance-receipt/v1`;
- `schema://ioi/aft/u1-campaign-result/v1`;
- `schema://ioi/aft/measured-result-row/v1`; and
- `schema://ioi/aft/measured-results-registry/v1`;
- `schema://ioi/foundations/verifier-independence-profile/v1`; and
- `schema://ioi/components/hypervisor/c8-portable-evidence-bundle/v1`.

External witnessing initially composes the registered `ReceiptCheckpoint` and
`ReceiptProofBundle` contracts over the acceptance receipt and C8 outcome root.
No separate `ExternalWitnessCommitment` contract is introduced until a concrete
external witness protocol requires response semantics those contracts cannot
express. A locally emitted checkpoint is not external witnessing.

## Verifiability Instead of Vendor Trust

The difference between a platform promise and a durable guarantee is evidence.

Conventional systems can log actions. Bounded sovereign systems make the action
path attributable, policy-bound, evidence-carrying, and challengeable.

The stronger trust surface is:

- policy-addressable;
- authority-scoped;
- receipt-bearing;
- replayable;
- independently auditable;
- portable across runtimes and providers;
- challengeable when sealed effects are contested.

This changes the core question from:

```text
do we trust the platform?
```

to:

```text
can the actor prove it operated only inside the delegated envelope?
```

## Why the Fractal Blockchain Kernel Matters

This thesis does not depend on the weak claim that blockchain somehow makes all
safety possible.

Capability scoping, approvals, sandboxing, least-privilege execution, and
receipts can exist inside conventional trusted systems.

The stronger claim is that the **full guarantee surface** depends on a
blockchain-grade kernel substrate when bounded authority must survive outside a
single trusted machine, company, cloud, or vendor trust domain.

That substrate anchors:

- policy identity;
- capability provenance;
- portable delegated authority;
- revocation state;
- tamper-evident receipts;
- challengeable irreversible effects;
- multi-party trust across organizations and runtimes.

Without that layer, bounded agency can still exist inside a trusted operator
environment.

With that layer, bounded agency becomes:

- sovereign rather than platform-captive;
- portable rather than vendor-local;
- independently verifiable rather than dashboard-asserted;
- challengeable for sealed effects rather than merely logged after the fact;
- durable across provider, runtime, and organizational boundaries.

Clean formulation:

> **Blockchain is not what makes bounded agency possible at all. It is what
> makes bounded agency sovereign, portable, and independently verifiable.**

In IOI's language:

> **The fractal blockchain kernel lets bounded authority survive outside a
> single trusted machine or vendor trust domain while remaining
> policy-addressable, receipted, and challengeable.**

## Category

Primary category:

- **Sovereign Agent Infrastructure**

Secondary category:

- **Verifiable Autonomous Systems**

Strategic framing:

> **IOI provides the execution and authority model required for safe, bounded
> autonomy at scale.**

This is not a "safe AGI" slogan. It is a claim about the authority and
execution model required for increasingly capable autonomous systems to remain
trustworthy when they act.

## Product Promise

IOI is not fundamentally selling:

- agents;
- model access;
- infrastructure in the abstract;
- blockchain branding.

IOI is selling:

> **the ability to give software real authority without losing control.**

Everything else is implementation detail.

## Non-Claims

Canonical architecture must not overstate this doctrine.

Verifiable bounded agency does not mean:

1. IOI proves every model's private goals are safe.
2. Prompting, Worker Training, evaluation, model routing, and verifier quality no
   longer matter.
3. Any single zkVM, proof system, deterministic fixture strategy, TEE, MPC, FHE,
   sandbox, or runtime profile is mandatory for every path.
4. A worker can never become more powerful; externally authorized policy
   widening is allowed.
5. Local sandbox determinism proves remote providers, physical hardware, or
   third-party systems are perfectly deterministic.
6. Logs alone are sufficient evidence.
7. UI approval dialogs alone are sufficient authority.

## Canonical Framing

The following statements capture the thesis cleanly:

- **IOI is sovereign agent infrastructure for verifiable autonomous systems.**
- **IOI is a zero-trust operating fabric for autonomous actors, where intelligence is probabilistic but authority is explicit, bounded, and verifiable.**
- **The root moat is verifiable bounded agency under sovereign control.**
- **Other systems offer agent safety by best-effort supervision. IOI grounds safety in bounded authority and evidence-gated effects.**
- **The fractal blockchain kernel anchors these guarantees so they remain portable and independently verifiable across environments.**
- **This is how intelligent systems become trustworthy: not through supervision alone, but through structure.**
- **The winner will be the system that lets actors become powerful without ever giving them unbounded power.**

## One-Line Doctrine

> **IOI aligns autonomous action at the execution boundary: workers may propose,
> but only bounded, authorized, receipted effects may cross into reality.**
