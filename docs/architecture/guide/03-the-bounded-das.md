# 03 — From A Run To An Institution: The Bounded DAS

Status: architecture guide chapter (non-owning synthesis).
Canonical owner: this file for the reading order and narrative sequencing of
the run-to-institution progression only; every subject is owned by the linked
owner doc, which wins on any point of substance.
Supersedes: none (originates no doctrine).
Superseded by: none.
Last alignment pass: 2026-08-16.
Doctrine status: canonical
Implementation status: mixed (narrative over built, partial, planned, and
speculative subjects; status truth lives in
[`canon-to-code-delta.md`](../_meta/canon-to-code-delta.md) and the
[`work-items/`](../_meta/work-items/) records)
Last implementation audit: 2026-08-16

## One Bounded Pursuit: GoalRun

Chapter 02 followed one action. Real work is a *pursuit*: many actions under
one objective, verified and course-corrected until done. That durable pursuit
object is the `GoalRun`, and its generic loop is:

```text
orient -> plan -> implement/act -> observe -> verify -> course-correct
       -> continue, escalate, hand off, reconcile, or close
```

The kernel should be generic and loop-native. It should not be a global swarm,
a hard-coded coding loop, or a chat transcript. Simple work collapses to one
direct path. Hard or uncertain work may fan out across models, workers,
verifiers, sessions, or parties when expected value justifies the added cost.

`WorkResult` and `OutcomeDelta` are the generic result seam.
`ImplementationResultPayload` is only the software-implementation profile —
files, diffs, and tests never enter the universal shape.

Every admitted GoalRun freezes exactly one immutable `GoalRunProfile` revision
— the reusable definition of how that class of pursuit should converge — so
reusable method and live state never blur. Three neighbors are constantly
confused with it, and [`term-boundaries.md`](../foundations/term-boundaries.md)
owns the distinctions: a **Session** is a bounded interactive, headless, or
supervisory context (a GoalRun spans zero or more of them); a **WorkRun** is
one execution attempt; an **OutcomeRoom** sits *above* GoalRuns, never beside
or inside a Session. Per
[ADR 0022](../../decisions/0022-goal-orchestration-application-layer-and-clean-slate.md),
the whole goal/room family belongs to the openly packaged ioi.ai orchestration
application — an application-layer domain over the substrate, not substrate
itself.

## Collective Pursuit: OutcomeRoom

An `OutcomeRoom` is the durable shared-pursuit bounded-DAS instance created
from the reusable room package through genesis. Its `CollaborativeWorkGraph`
records admitted participants, offers, frontier items, leased claims, attempts,
findings, verifier challenges, contribution lineage, discussion projections,
and replay. Goal Space workstreams and Hypervisor Work / Rooms are projections
over this same graph.

Room machinery appears only when a durable shared frontier, multiple attempts,
dynamic participants, or independent verification actually justifies its cost;
ordinary goals collapse to one GoalRun with no room at all. Owners:
[`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md)
and
[`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md).

## The Institution: A Bounded DAS

Runs and rooms happen *inside* something durable: a **bounded distributed
autonomous system** — one logical institution with a stable `system_id` whose
constitution, identity, state, authority, lifecycle, and evidence survive
individual model changes, node changes, upgrades, and recovery. The owner is
[`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md);
its substrate classification, in one minute:

An intelligent blockchain is the ordered state-machine substrate of a bounded
autonomous institution. It can use one authority/PoA-1, replicated authority,
threshold authority, BFT consensus, or external-chain finality. Consensus is a
deployment profile, not what makes the system intelligent or bounded.

Every durable system declares a constitution, executable manifest, desired
deployment, observed member nodes and roles, ordering/finality, external-fact
oracle/evidence policy, lifecycle continuity, and optional network enrollment.
One stable logical identity may span several nodes. Joining a node never
silently grants authority or changes finality. A promoted/replacement
single-writer requires catch-up, root verification, a new writer epoch, and
fencing; a deliberately single-node system may fail closed or restore under its
declared proof contract; threshold, BFT, and external-finality systems use
their profile-native recovery proofs instead.

Three identities stay separate: a `package://` release can instantiate many
systems; genesis mints one `system://` identity binding constitution and
profiles; nodes later join through governed membership. The constitution is
declared **before** durable autonomy — purpose and prohibitions, ceilings,
amendment thresholds, the self-improvement boundary, emergency stop,
succession, and dissolution — because a system without an enforceable change
boundary is an automated application, not yet a safely bounded autonomous
institution. Lifecycle is part of correctness: "runs forever" is not a
governance policy.

Intelligence stays upstream of this substrate exactly as in chapter 02:
workers, models, and people propose; the institution's declared ordering,
policy, authority, oracle/evidence, and receipt paths decide what becomes
canonical.

## How This Is Proven, In Order

```text
one hosted durable OutcomeRoom instance (one room system)
  -> the same logical DAS across two failure domains with controlled failover
     and useful distributed work across active member nodes or embodied units
  -> two sovereign DASs interoperating over AIIP
  -> productized Goal Space and open challenge network
  -> optional shared-trust and public-economic commitments
```

The reusable OutcomeRoom package and each durable room-system instance are the
flagship reference DAS, not the definition of L0. A React or other generated
domain app will often be the leading user interface; it remains a projection
over the system's constitution, authority, state, deployment, and receipts.
Sequencing and gate ownership:
[`execution-horizons.md`](../_meta/execution-horizons.md).

## Owners For This Chapter

- [`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md)
  — the bounded-system contract, constitution, lifecycle, and Hypervisor Nodes.
- [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
  — the shared object families and ID conventions behind every name here.
- [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md)
  — OutcomeRoom and collaboration doctrine.
- [`term-boundaries.md`](../foundations/term-boundaries.md) — Session vs
  GoalRun vs OutcomeRoom vs WorkRun, ruled once.
- [`execution-horizons.md`](../_meta/execution-horizons.md) — the proof order.
