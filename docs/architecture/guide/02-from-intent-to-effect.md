# 02 — From Intent To Effect

Status: architecture guide chapter (non-owning synthesis).
Canonical owner: this file for the reading order and narrative sequencing of
one action's path across the effect boundary only; every subject is owned by
the linked owner doc, which wins on any point of substance.
Supersedes: none (originates no doctrine).
Superseded by: none.
Last alignment pass: 2026-08-16.
Doctrine status: canonical
Implementation status: mixed (narrative over built, partial, planned, and
speculative subjects; status truth lives in
[`canon-to-code-delta.md`](../_meta/canon-to-code-delta.md) and the
[`work-items/`](../_meta/work-items/) records)
Last implementation audit: 2026-08-16

## One Action, End To End

This chapter is the guide's spine. Everything later — institutions, nodes,
federation, products — is a widening of this one path.

The setting is deliberately a **local deployment**: one machine running a
Hypervisor client, the Hypervisor Daemon, and a local Agentgres posture, with
no ioi.ai account anywhere in the loop. That is not a simplification for
teaching. Per [ADR 0022](../../decisions/0022-goal-orchestration-application-layer-and-clean-slate.md),
goal orchestration is an openly packaged domain application deployable on any
Hypervisor — locally and offline — and the target standalone contract requires
this whole arc to run without a first-party managed dependency. Managed
products enter the story in chapter 06, as optional hosting of what you are
about to watch run locally.

The path, stated once by the corpus and reproduced here as the spine:

```text
intent or room claim
  -> worker/model/harness proposes
  -> semantic and capability checks
  -> policy and authority providers authorize
  -> Hypervisor Daemon admits, schedules, executes or mediates
  -> environment/provider/actuator performs
  -> observations, receipts, artifacts, and state deltas return
  -> verifier and acceptance paths classify assurance
  -> Agentgres admits local operational truth
  -> AIIP handoff or L1 commitment only when policy triggers it
```

## Walking The Path

**Intent.** A person or system expresses what should happen. Pre-admission
intent is draft state (`intent://`); it acquires no lifecycle, authority,
budget, or evidence until admission. Owner:
[`term-boundaries.md`](../foundations/term-boundaries.md) and the goal
orchestration application's own docs under
[`domains/ioi-ai/`](../domains/ioi-ai/).

**Proposal.** A model, Worker, or harness reasons about it and proposes
concrete work. Cognition here is probabilistic and unprivileged — planning,
candidate actions, payload synthesis. The proposer is not the authority
boundary. Owner:
[`verifiable-bounded-agency.md`](../foundations/verifiable-bounded-agency.md).

**Semantic and capability checks.** What does the proposal *mean*, and what
would it *require*? A consequential ontology action compiles to an
`OntologyActionContract`; feasibility is expressed as primitive capabilities
(`prim:*`), which are never permission. Owners:
[`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md)
and [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
for the two-tier `prim:*` / `scope:*` split.

**Policy and authority.** Authority scopes (`scope:*`) are requested from the
applicable providers — wallet.network for portable delegated authority and the
designated high-risk external actions, local/domain policy and governance where
canon permits. What comes back is a scoped, expiring, revocable lease or grant,
never a raw secret. Owner:
[`doctrine.md`](../components/wallet-network/doctrine.md).

**Admission and mediation.** The Hypervisor Daemon is the deterministic gate.
It validates the loaded contract, required capabilities, authority, policy
decision, and evidence before anything crosses; its admission discipline
(INV-37) accepts only evidence the admission core resolves or independently
verifies. The daemon does not invent authority. Policy and authority providers
authorize; the daemon admits, enforces, executes or mediates, receipts, and
fails closed. Owner:
[`doctrine.md`](../components/daemon-runtime/doctrine.md).

**Performance.** An environment, runtime, provider, connector, tool, or —
under the physical-safety envelope — an actuator performs the admitted effect.
Guest output remains an untrusted proposal until admitted. Owners:
[`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md),
[`physical-action-safety.md`](../foundations/physical-action-safety.md).

**Return.** Observations, receipts, artifacts, and state deltas come back as
typed objects, not as trusted side effects. Owner:
[`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).

**Verification and acceptance.** Receipt assurance is staged:

```text
attested -> evidenced -> verified -> accepted -> adjudicated -> settled
```

A receipt proves only its bound event or claim. It is not automatically proof
of correctness, truth, acceptance, or settlement. Ordinary work may verify
through deterministic conductor-run evidence; independent verifiers are
policy-triggered escalations for high-risk classes. Owners:
[`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md),
[`evaluations.md`](../components/hypervisor/evaluations.md).

**Admitted truth.** Agentgres records the operational fact that this domain
admitted this change under declared policy — operation-backed, head-addressed,
replayable. All state changes are patches; accepted patches become domain
operational truth. "Truth" here is admission truth: it does not turn a model
judgment or external-world claim into universal fact. Owner:
[`doctrine.md`](../components/agentgres/doctrine.md).

**Optional crossings.** Only when policy and enrollment select it does anything
leave the domain: an AIIP handoff to an independently governed system, or a
sparse IOI L1 commitment. Chapters 04 and 05 own that widening.

## When The Effect Is Not Clean

External-effect recovery is explicit, not hopeful:

```text
replayable | checkpointable | compensatable |
reconciliation_required | non_retryable
```

A timeout after a possible external effect is ambiguous, not safely retryable.
Environment restore and outcome reconciliation are separate operations —
restoring the machine that sent a wire transfer does not un-send it. Owners:
[`invariants.md`](../foundations/invariants.md),
[`doctrine.md`](../components/daemon-runtime/doctrine.md).

## Why This Shape Is Load-Bearing

Once this path is understood, nearly every subsystem has an obvious reason to
exist: wallet.network because authority must be an artifact; the daemon because
admission must be deterministic; Agentgres because an institution needs
admitted memory; receipts and staged assurance because attribution precedes
trust; recovery postures because the world is not transactional. The next
chapter widens the frame from one action to the durable institution the action
runs inside.

## Owners For This Chapter

- [`doctrine.md`](../components/daemon-runtime/doctrine.md) — the daemon, the
  execution boundary, and admission discipline.
- [`doctrine.md`](../components/wallet-network/doctrine.md) — authority,
  leases, approvals, and revocation.
- [`doctrine.md`](../components/agentgres/doctrine.md) — admitted operational
  truth.
- [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  — events, receipts, and delivery evidence.
- [`verifiable-bounded-agency.md`](../foundations/verifiable-bounded-agency.md)
  — the cognition/authority separation this path enforces.
- [ADR 0022](../../decisions/0022-goal-orchestration-application-layer-and-clean-slate.md)
  — why the spine runs without a managed service.
