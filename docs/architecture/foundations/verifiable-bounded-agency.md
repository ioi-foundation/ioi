# Verifiable Bounded Agency and Execution-Boundary Alignment

Status: canonical architecture authority.
Canonical owner: this file for IOI's alignment-security thesis, verifiable bounded agency, and execution-boundary alignment doctrine.
Supersedes: `docs/specs/verifiable_bounded_agency.md` and product prose that claims IOI solves alignment by model cognition, prompt compliance, or one required proof backend.
Superseded by: none.
Last alignment pass: 2026-05-24.

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

public trust and settlement
  IOI L1 registries, rights, escrows, disputes, roots, governance
```

The same doctrine can be stated in the repo's core sentence:

> **Hypervisor Daemon executes. Authority is granted by local/domain governance
> or wallet.network according to risk boundary. Agentgres remembers. MoW routes.
> IOI L1 settles. Clients compose. Evidence proves.**

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

- [`CIRC`](../../conformance/hypervisor-core/intent-resolution.md) collapses
  semantic uncertainty into deterministic intent state.
- [`CEC`](../../conformance/hypervisor-core/effect-execution.md) governs
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

But the actor can improve inside the lane without silently widening the lane.

Canonical self-upgrade invariant:

> **A worker may propose changes to logic, package, policy requirements,
> training profile, model route, tool use, or workflow topology, but it may not
> grant itself broader authority.**

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

Canonical upgrade invariant:

> **Agents do not self-modify directly. Autonomous systems propose upgrades to
> governed modules, and only policy-bound, receipted governance makes those
> upgrades canonical.**

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
→ IOI L1 receives sparse commitment when public trust or settlement requires it
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

## Verifiability Instead of Vendor Trust

The difference between a platform promise and a durable guarantee is evidence.

Conventional systems can log actions. Bounded sovereign systems make the action
path itself proof-carrying.

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
