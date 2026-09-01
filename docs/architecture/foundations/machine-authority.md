# Machine Authority

Status: canonical architecture authority.
Canonical owner: this file for the Machine Authority category definition, its
completeness contract, role boundary, lifecycle distinctions, and claim ladder.
Supersedes: the machine-authority category definition previously embedded in
[`web4-and-ioi-stack.md`](./web4-and-ioi-stack.md) and unqualified reuse of the
category name as a product, protocol, or stack name.
Superseded by: none.
Last alignment pass: 2026-08-30.
Doctrine status: canonical
Implementation status: mixed (the category and completeness contract are
canonical; registered request, review, grant, key, revocation, and admission
contracts plus a portable grant verifier and one qualified served SCM
admission/finalizer path exist, while a stable public protocol profile,
independently runnable conformance release, fully portable delegation closure,
portable receipt-signature closure, and profile-complete effect coverage remain
incomplete)
Last implementation audit: 2026-08-30

## Canonical Definition

**Machine Authority is independently verifiable, bounded, delegated, and
revocable power exercised by a machine over consequential effects, with
content-bound admission, controlled consumption, and attributable outcome
evidence.**

Short form:

> **Machines receive bounded power, not ambient access. Every consequential
> effect is admitted against the power actually granted.**

This definition names a category independent of any IOI product. IOI's target
is to define and incrementally implement an open, complete instance of the
category through the
[`IOI Authority Protocol`](./ioi-authority-protocol.md), without making the
category depend on one hosted service, runtime, database, wallet, chain, or
model provider. No complete profile is currently released.

Machine Authority begins where identity, authentication, capability, policy,
and consent stop. Those inputs may be necessary; none alone gives a machine
power over an effect. Authority exists only when a trusted issuer conveys a
bounded grant to an exact holder and a policy-enforcement point verifies that
grant against the actual effect immediately before invocation.

## Owns

This file owns:

- the meaning and completeness boundary of Machine Authority;
- the abstract roles that a conforming authority system must keep legible;
- the lifecycle distinctions from proposal through reconciliation;
- the minimum properties required for a complete Machine Authority claim; and
- the claim ladder separating component compatibility, action authorization,
  delegated authority, governed effects, and complete Machine Authority.

It does not own:

- individual wire fields or schema versions, which stay with their object and
  receipt owners;
- wallet.network product or authority-provider doctrine;
- Hypervisor Daemon execution semantics;
- Agentgres operational truth;
- AIIP cross-sovereign work semantics;
- settlement, certification, or marks; or
- the exact release manifest of a named IOI Authority Protocol profile.

## What Machine Authority Must Not Mean

Machine Authority is not:

- authentication, account access, identity proof, or session establishment;
- possession of a raw credential, secret, token, key, or provider connection;
- a capability declaration describing what a runtime can physically do;
- a model/tool selection, policy recommendation, or risk score;
- a signed proposal, decision, or human-consent record by itself;
- a tool-call schema, gateway log, execution trace, or generic receipt;
- a payment signature or settlement commitment; or
- a process that can widen its own authority because its capability, score, or
  confidence increased.

Those artifacts may participate in the lifecycle. None may silently elevate
itself into a grant, effect admission, or execution right.

## Abstract Roles

A conforming implementation may combine roles inside one deployment, but its
contracts and evidence keep the roles distinguishable:

| Role | Responsibility | Cannot Claim By Itself |
| --- | --- | --- |
| Principal | Source of the power being delegated or the party accountable for it | That an actor authenticated as the principal received effect authority |
| Proposer | Describes a requested action or bounded authorization subject | Permission to execute it |
| Policy decision point | Evaluates policy, risk, and required escalation | That a grant was issued or an effect was admitted |
| Approval surface | Presents the reviewed representation and collects required evidence | That presentation was understood, or that the eventual effect matched it |
| Authority issuer | Signs a scoped grant under an admitted policy and trust root | That the grant is current or has been consumed correctly |
| Holder | Receives and may exercise or narrowly delegate the grant | Custody of the principal's raw secrets or a right to widen the grant |
| Revocation authority | Publishes current key and grant disposition | Execution truth or retroactive erasure of a historical effect |
| Policy-enforcement point | Revalidates current authority against the daemon- or resource-derived actual effect | That the downstream invoker performed the effect |
| Final invoker | Performs the external or protected state-changing operation | That its own invocation was authorized without the admission evidence |
| Receipt issuer | Binds one declared boundary fact to attributable evidence | Correctness, acceptance, adjudication, or settlement beyond that fact |
| Reconciler | Resolves uncertain, duplicated, partial, or externally observed effects | Authority to invent a missing outcome or rewrite earlier evidence |
| Verifier | Recomputes a named claim from locally trusted inputs | Trust in inputs that the verifier's profile does not establish |

In IOI's first-party stack, wallet.network implements the authority-provider
roles, the Hypervisor Daemon implements the PEP and final-invoker mediation
roles, and Agentgres implements the admitted-truth role. These are current
first-party role assignments, not a formal reference-release designation and
not protocol prerequisites.

## Canonical Lifecycle

The lifecycle is ordered but branched; denial, escalation, and refusal do not
fall through into grant or invocation:

```text
action proposal
  -> canonical reviewed representation
  -> policy decision
       deny    -> terminal refusal evidence
       step_up -> challenge + continuation -> reviewed representation
       approve -> qualified approval evidence
                    -> signed authority grant
                    -> optional strictly attenuating delegation
                    -> current key/time/revocation/budget/continuity verification
                    -> actual effect derived by the enforcing domain
                    -> final-PEP decision
                         refuse -> terminal effect-refusal evidence; no invocation
                         admit  -> atomic consume-or-replay
                                      replay   -> return the prior recorded
                                                  disposition/evidence; never invoke
                                      consumed -> proved non-invocation, or
                                                  -> final invocation
                                                       -> execution/outcome evidence
                                                       -> reconciliation if ambiguous
                                                       -> optional acceptance/adjudication/settlement
```

Every arrow is a boundary. A pointer can connect stages; it cannot collapse
them. Later evidence may refer to an earlier fact, but it cannot retroactively
turn that fact into a different one.

## Machine Authority Completeness Contract

A system may claim complete Machine Authority only when every requirement below
is satisfied over the named profile and declared effect surface.

**MAC-1 — Canonical request identity.** The proposed authorization subject and
its reviewed representation have deterministic identities. Field, encoding,
schema, representation, destination, session, origin, or subject substitution
is detected rather than normalized away after review.

**MAC-2 — Attributable decision and escalation.** Approval, denial, editing,
and step-up are typed, attributable outcomes bound to the request and policy.
Silence, timeout, UI state, or an imported `approved` flag is not a decision.

**MAC-3 — Signed bounded grant.** Authority is conveyed only by a signed grant
binding issuer, holder, holder key where required, audience, authorization
subject, scopes, resources, purpose/caveats, risk limits, validity, budget,
usage, and revocation coordinates.

**MAC-4 — Provable attenuation.** Every delegated child is issued by an
authorized parent holder, preserves verifiable ancestry, and can only narrow
authority. Cycles, missing ancestors, widened dimensions, unauthorized
re-delegation, or incomplete allocation evidence fail closed.

**MAC-5 — Currentness and revocation.** Admission uses locally trusted key and
revocation evidence under an explicit temporal profile. Absence of revocation
data is never proof of non-revocation; authentic historical evidence is not
silently promoted to current evidence.

**MAC-6 — Consumable bounds.** Calls, budget, resource allocations, and
single-use subjects are consumed atomically under stable idempotency identity.
Concurrent requests cannot overspend a shared bound, and replay returns the
same recorded disposition rather than performing the effect again.

**MAC-7 — Domain-derived actual effect.** The enforcing domain derives the
actual payload, destination, resource, amount, and effect identity. A caller-
asserted effect hash, copied grant field, or trusted proposal cannot substitute
for that derivation.

**MAC-8 — Final-PEP admission.** Current grant, delegation, key, revocation,
time, budget, resource, and policy evidence is revalidated immediately before
the final invoker. Admission proves exact equality, committed-batch membership,
or satisfaction of a bounded standing constraint.

**MAC-9 — Invocation separation.** Admission and invocation are separate
facts. An admitted request may still prove non-invocation; an invocation with no
matching admission is an authority failure even if the effect later succeeds.

**MAC-10 — Outcome and ambiguity.** Execution, refusal, timeout, partial
completion, unknown external disposition, compensation, and reconciliation are
typed. A network timeout is not interpreted as non-execution, and a later
observation does not rewrite the pre-effect admission record.

**MAC-11 — Independently verifiable evidence.** A verifier can recompute the
named integrity, validity-as-of, authority, admission, consumption, and outcome
claims from a frozen profile and locally selected trust roots without calling a
mandatory IOI-hosted service.

**MAC-12 — Portable implementation and exit.** A conforming implementation may
replace the profile's designated authority provider, PEP, invoker, truth store,
transport, and verifier while preserving the named behavior. Compatibility
requires no IOI account, token, network enrollment, chain, or continuing hosted
dependency. This is a profile requirement, not a claim that today's wallet-
bound served routes already expose replaceable-provider adapters.

Missing one of MAC-1 through MAC-12 narrows the permitted claim. It does not
make the implementation useless; it makes the claim precise.

## Claim Ladder

The claim ladder prevents a useful narrow component from being marketed as the
whole category:

| Claim | Minimum Meaning | Explicitly Does Not Mean |
| --- | --- | --- |
| Component compatible | One named schema, signature, or verifier behavior matches | A complete action boundary or authority lifecycle |
| Action-authorization conformant | Proposal, canonical review, decision, escalation, and approval evidence interoperate | Delegated power, current revocation, final-PEP enforcement, or execution truth |
| Delegated-authority conformant | Signed grants, holder/audience binding, attenuation, currentness, revocation, and consumable limits interoperate | That a requested effect was the effect admitted or executed |
| Governed-effect conformant | Actual-effect derivation, final-PEP admission, atomic consumption, invocation, and outcome evidence interoperate | A complete portable grant/delegation lifecycle unless paired with it |
| Machine Authority conformant | The named surface passes MAC-1 through MAC-12 | Correctness of the actor's reasoning, success of the effect, legal enforceability, acceptance, adjudication, or settlement |

Conformance is behavioral and profile-bound. Reusing IOI names, schemas, or
code does not confer a claim, and passing one profile does not imply another.

## Relationship To The IOI Stack

Machine Authority is the security substrate beneath IOI's broader architecture:

```text
Machine Authority                  category and completeness boundary
  -> IOI Authority Protocol        portable protocol family
     -> wallet.network             first-party authority-provider implementation
     -> Hypervisor Daemon          first-party PEP and execution mediation
     -> Agentgres                  first-party admitted operational truth
     -> AIIP                       optional cross-sovereign work extension
     -> IOI L1                     optional shared-finality extension
```

Web4 uses Machine Authority to make consequential autonomous action governable.
The Internet of Intelligence uses it to make cross-sovereign delegated work
contractible. Neither category changes this file's completeness boundary.

## Current Honest Boundary

The registered estate already contains substantial MAC-1 through MAC-8
material, including request/review/ceremony schemas and fixtures, signed-grant,
key-set, and signed-revocation schema/fixture/verifier material, a Rust grant-
chain verifier, exact-effect admission construction, and exact grant-hash-keyed
consumption. Production review emission and grant minting are not implied. The
current estate does **not** yet establish a stable complete Machine Authority
conformance claim:

- the v3 delegated-chain verifier still requires a locally trusted closed-world
  allocation closure not carried by a registered portable signed object;
- the qualified live SCM path persists, revalidates, and fences the exact v2
  admission before its finalizer, but broader profile-complete effect and
  outcome coverage is not established;
- production admission emission exists on that qualified path, while its
  portable outer-signature profile remains incomplete;
- the complete public profile manifest and outsider-runnable release do not
  exist;
- current served portable-delegation routes remain wallet.network-bound, with
  no alternate-provider adapter or interoperability proof; and
- organizationally independent implementations and structural governance
  separation are not yet demonstrated.

These are release blockers for the complete claim, not reasons to weaken the
definition.

## Related Canon

- [`ioi-authority-protocol.md`](./ioi-authority-protocol.md) — the IOI protocol
  family, profiles, release manifest, and conformance entitlements.
- [`objects/authority-and-access.md`](./objects/authority-and-access.md) —
  authority request, ceremony, grant, key-set, and revocation object shapes.
- [`../components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md)
  — first-party authority-provider doctrine.
- [`../components/daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md)
  — first-party PEP, final-invoker, and execution boundary.
- [`../components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  — admission, execution, outcome, and reconciliation evidence.
- [`protocol-governance-neutrality.md`](./protocol-governance-neutrality.md) —
  specification, reference-implementation, and certification separation.
- [`invariants.md`](./invariants.md) — cross-owner rules that implementations
  must preserve.
