# ADR 0022: Make Goal Orchestration An Application Layer And Strip Compatibility Machinery

- Status: Accepted
- Date: 2026-07-25
- Owners: product identity / ioi.ai domain / Hypervisor core surfaces / daemon runtime / goal pursuit and collaborative pursuit objects
- Refines: ADR 0013, ADR 0014, ADR 0015, ADR 0016, ADR 0017
- Amends: ADR 0019, ADR 0020 (placement only; their contracts stand)
- Unaffected: ADR 0021 (the first proof instantiates the openly packaged
  orchestration application locally; nothing here changes that)
- Confidence: settled for both rulings (owner-ruled during interactive review
  of the 2026-07-25 maximal-ceiling pass); working_ruling for each named
  untangling below.

## Context

The maximal-ceiling pass placed the product-crossing object and the unified
GoalRun admission contract in Hypervisor substrate canon. Owner review
surfaced a conflation the pass had inherited from the canon itself:
**"must live below ioi.ai-the-managed-service" and "must live inside
Hypervisor-the-substrate" are not the same place.** The canon has a third
place — the application/package layer — and had already half-built it:
`OutcomeRoom` is "a reusable package instantiated through genesis,"
explicitly "ioi.ai's package" and "the flagship reference DAS, **not the
definition of L0**"; the DomainApp/ODK plane exists; the product-surface
registration family exists so applications contribute surfaces. Meanwhile
Hypervisor's own product identity is session-centric — bounded,
provider-agnostic, plug-and-play execution contexts — and its shell history
(Missions retired, application-UX backlog deferred) repeatedly caught
orchestration product surfaces overreaching into the substrate's identity.

The same review issued a second ruling: the estate has **zero downstream
users**, and its habit of paying compatibility costs anyway — alias
registers, deprecated spellings kept as exports, compatibility routes,
legacy-scheme read machinery, migration adapters — is noise that makes every
subsequent change more expensive for nobody's benefit.

## Decision 1 — The three-layer allocation

```text
Hypervisor — substrate and its own product identity
  Session, WorkRun, HarnessInvocation, ContextCell/Lease/Handoff,
  environments, automations machinery, authority, receipts, Agentgres
  truth, packages, and the generic result seam (WorkResult / OutcomeDelta).
  Its surfaces and API namespace speak session vocabulary. Goal runs and
  rooms are not Hypervisor surfaces.

ioi.ai orchestration application — the productized loops
  GoalRun, GoalRunProfile, Goal Kernel, GoalGroundingLoop, OutcomeRoom,
  the room object family (participation requests/leases, resource and
  capability offers, frontier items, work claims, attempts, findings,
  verifier challenges), and GoalRunActivation are ITS domain objects.
  The layer is an openly packaged domain application in the reference
  stack, deployable on any Hypervisor — locally and offline, with no
  ioi.ai account. Its truth is admitted through daemon + Agentgres in its
  bounded domain; every consequential step still crosses daemon admission,
  leases, and receipts. The managed service at ioi.ai is the hosted
  offering of this same application.

Protocol — what an external party speaks
  AIIP packet families plus the room package's admitted contracts. The
  cross-party grammar is protocol + package level, never one product's
  private schema and never a substrate favor.
```

Consequential sub-rulings:

1. **Dogfooding is literal.** ioi.ai orchestrates intelligence and
   productizes the loops as an application built on Hypervisor. It holds no
   privileged substrate semantics and steals no authority; it owns domain
   truth, not execution.
2. **The naming question dissolves.** Inside the application's own domain,
   goal vocabulary is correct — the interim `PursuitRun`/`PursuitRoom`
   display-rename proposal is withdrawn. `goal://` is retained as the
   application's canonical ref scheme; the `/v1/hypervisor/` route namespace
   was the defect, not the word.
3. **Routes re-home by deletion, not aliasing.** The goal/room planes move
   from `/v1/hypervisor/*` to the application's namespace and the old
   routes are deleted (Decision 2). Callers and verifiers update in the
   same cut.
4. **Shell surfaces reassign.** Work / Goals and Work / Rooms cease to be
   Hypervisor-owned surfaces; they are surfaces the orchestration
   application contributes through the product-surface registration family.
   Work remains a policy-filtered projection over typed subjects, which may
   include application-contributed subjects.
5. **The open-reference invariant is load-bearing.** The orchestration
   application ships in the open reference stack. If it ever became
   account-gated or closed, sovereign-local completeness and the adoption
   calculus would both fail; this is an explicit invariant of the ruling.
6. **Substrate-generic guarantees stay substrate.** INV-37, the
   `ReceiptObligation` element, idempotent receipted crossings, and the
   admission-evidence discipline of ADR 0020 are the substrate's rules that
   the application's admissions must satisfy.

## Decision 2 — Clean slate: strip compatibility machinery

With no downstream users, live backwards-compatibility surface is deleted
rather than aliased, estate-wide, under one classification rule:

```text
DELETE  live compatibility with zero consumers
        deprecated spellings kept as exports, compatibility routes and
        route aliases, legacy ref-scheme read machinery, legacy migration
        adapters and quarantine lanes, legacy wire shapes, alias registers
        whose only job is to police retained legacy names

KEEP    immutable history
        docs/architecture/_archive/**, docs/evidence/**, dated snapshots,
        attestation digests — never rewritten, refs left as-is in history

KEEP    real runtime-state contracts
        HypervisorChangePlan, backups/restore, cleanup obligations,
        succession/recovery machinery — product function, not compat debt
```

Gates are updated in the same cut a deletion lands: a deleted name or route
fails outright instead of surviving inside an alias-context allowance.
Deletion is the strengthening of the gate, never its weakening. Historical
documents citing deleted names remain valid history; the term-boundaries
register records deleted vocabulary as **forbidden**, not as aliases.

This decision deliberately supersedes, for the current no-consumer estate,
the earlier posture that shipped wire identifiers and deprecated aliases are
retained by default. When external consumers exist, retention discipline
returns for surfaces they consume; that boundary is crossed by a future ADR,
not by drift.

## Named Untanglings (each a working_ruling with an owner)

- **ImprovementCampaign coupling** — foundations doctrine currently
  coordinates GoalRuns. Either generalize the campaign spine to typed work
  subjects or bind it to the application's objects explicitly. Owner:
  `foundations/bounded-recursive-improvement.md`.
- **Automations activation** — `HypervisorGoalRunActivationContract`
  becomes a cross-application integration contract. Owner:
  `components/hypervisor/core-clients-surfaces.md` with the application
  domain docs.
- **Work workspace subject registry** — which subjects are core vs
  application-contributed. Owner:
  `components/hypervisor/core-clients-surfaces.md`.
- **Proof wording** — SLC and north-star language restated as "instantiate
  the packaged application locally" / "AIIP + package contracts"; substance
  unchanged. Owner: `_meta/execution-horizons.md`, `docs/conformance/`.

## Non-Goals

- No new runtime: the application executes only through daemon admission.
- No AIIP change: the packet families already sit at the right layer.
- No account requirement anywhere in the local path.
- No history rewriting: archives, evidence, and receipts are untouched.

## Consequences

- ADR 0019 and ADR 0020 carry dated refinements: their contracts stand;
  their objects' placement follows this ADR.
- The convergence pass executing this ADR performs the canon re-homing
  sweep, the compatibility purge, and the route re-home as its own legs,
  each gated; `canon-to-code-delta.md` carries the alignment rows.
- M2 begins from the resulting clean baseline.

## Cost Of Being Wrong And Reversal

Decision 1 is a placement ruling, not a shape ruling: every envelope, rule,
and conformance case is identical in either placement; reversal is re-homing
docs and routes back — mechanical and bounded. Decision 2's deletions are
reversible from git history at any time; the irreversible-looking part
(third parties depending on deleted surface) cannot occur because the
premise of the ruling is that no third parties exist yet. The cost of being
wrong is churn, not lost guarantees.

## Canonical References

- [`../architecture/domains/ioi-ai/collaborative-outcome-pattern.md`](../architecture/domains/ioi-ai/collaborative-outcome-pattern.md)
- [`../architecture/domains/ioi-ai/control-plane.md`](../architecture/domains/ioi-ai/control-plane.md)
- [`../architecture/foundations/objects/goal-pursuit.md`](../architecture/foundations/objects/goal-pursuit.md)
- [`../architecture/components/daemon-runtime/doctrine.md`](../architecture/components/daemon-runtime/doctrine.md)
- [`../architecture/components/hypervisor/core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
- [`../architecture/_meta/execution-horizons.md`](../architecture/_meta/execution-horizons.md)
- [`../architecture/foundations/term-boundaries.md`](../architecture/foundations/term-boundaries.md)
