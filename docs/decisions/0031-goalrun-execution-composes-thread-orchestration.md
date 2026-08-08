# ADR 0031: GoalRun Execution Composes Thread Orchestration

- Status: Accepted
- Date: 2026-08-01
- Owners: ioi.ai orchestration application / daemon runtime / Hypervisor core
  surfaces / harness adapters
- Refines: ADR 0017, ADR 0022, ADR 0029, ADR 0030
- Confidence: settled by owner ruling

## Context

ADR 0022 placed GoalRun and OutcomeRoom in the ioi.ai application domain. ADR
0030 then removed the room family's parallel admission, receipt, sequence, and
root spine because those guarantees already belonged to bounded Systems and
Agentgres. The same defect class remains on the execution side: an application
object may select and project work, but it must not mint a second orchestration
substrate beside the daemon-owned thread, fork, session, and harness controls.

The gap is measurable. Across the current GoalRun execution paths
`runtime_goal_pursuit.rs` and `goalrun_routes.rs`, references to each existing
kernel owner are exactly zero:

```text
runtime_thread_event                                0
runtime_thread_fork_control                         0
runtime_managed_session_control                     0
runtime_harness_session_binding_admission           0
runtime_hypervisor_session_launch_recipe_admission  0
```

Those primitives already exist and are independently owned. Meanwhile
`runtime_goal_pursuit.rs` carries GoalRun-local lifecycle, receipt checkpoint,
branch, result, and effect mechanics. Some of those shapes remain valid
application coordination vocabulary, but the absence of any binding to the
five daemon primitives means current GoalRun execution cannot prove that its
threads, forks, managed sessions, or harness launches are the canonical ones.

GoalRun identity itself is not the defect. A GoalRun is durable application
state that can outlive every Session and can exist before or without managed
execution. The defect begins only when actual execution is orchestrated through
a GoalRun-local path instead of the kernel primitives.

## Decision

**GoalRun remains an ioi.ai application-domain object. Whenever a GoalRun
executes work, its execution semantics compose the daemon-owned thread,
fork, managed-session, launch-recipe, and harness-binding primitives. GoalRun
does not own a second orchestration spine.**

```text
KEEP AS APPLICATION VOCABULARY
  GoalRun, GoalRunProfile, GoalGroundingLoop, RoleTopology,
  OrchestrationPlan, ContextCell, ContextLease, ContextHandoff,
  Attempt, Finding, WorkResult and OutcomeDelta associations

COMPOSE FROM DAEMON/KERNEL OWNERS
  RuntimeThreadEvent                         event truth and replay
  RuntimeThreadForkControl                   bounded agent/thread delegation
  RuntimeManagedSessionControl               managed execution lifecycle
  HypervisorSessionLaunchRecipeAdmission     admitted launch intent
  HarnessSessionBindingAdmission             exact harness/session binding
  terminal attach/readiness/launch records   executable harness chain

REMOVE AS AN APPLICATION OWNERSHIP CLAIM
  any GoalRun-local event stream, fork graph, managed-session lifecycle,
  harness launch/binding truth, or receipt/replay path that competes with the
  named kernel owner
```

A GoalRun may decide that a role, plan, attempt, verifier, or course correction
is needed. Carrying out that decision must create or reference the exact kernel
records. GoalRun state stores typed refs and derived status; it does not recreate
their lifecycle or infer execution from application-local receipts.

### Consequential sub-rulings

1. **Zero Sessions remains valid.** Drafting, grounding, waiting, and durable
   pursuit state do not require a Session. The composition rule applies when
   execution, delegation, managed control, or harness launch actually occurs.
2. **Harness-to-harness orchestration is explicit.** A harness may request a
   bounded fork, subagent, managed session, or successor harness binding through
   daemon contracts. It may not directly confer authority, create another
   harness's runtime truth, or maintain a private peer event graph.
3. **GoalRun survives execution turnover.** Thread, Session, WorkRun, worker,
   model, or harness replacement does not replace GoalRun identity. The
   application projects continuity from their admitted refs and receipts.
4. **OutcomeRoom does not absorb the seam.** A room coordinates shared GoalRun
   work through its graph and Agentgres/System truth. It owns neither GoalRun
   execution nor the kernel orchestration primitives.
5. **Application plans remain legitimate.** Goal grounding, topology selection,
   orchestration plans, attempt comparison, and course correction remain ioi.ai
   semantics. Their execution effects cross the kernel seam exactly once.
6. **The context family re-homes to the application layer (owner ruling,
   2026-08-07).** `ContextCell`, `ContextLease`, and `ContextHandoff` appear in
   this ADR's keep-list while
   [ADR 0022](./0022-goal-orchestration-application-layer-and-clean-slate.md)
   Decision 1 still lists them in the Hypervisor substrate block. That was an
   unstated move, and it left two accepted ADRs assigning the same three objects
   to opposite layers. **The owner ruling is that this ADR governs: the goal
   family is ioi.ai productization, and its execution composes daemon-owned
   thread orchestration primitives.** The context family is therefore application
   vocabulary; ADR 0022 Decision 1's substrate line is amended accordingly and
   carries a pointer here.

   Two boundaries survive the move intact. First, the composition rule of this
   Decision still applies to their execution effects — an application-owned
   context object may not mint thread, fork, managed-session, launch, or harness
   truth. Second, `WorkResult` and `OutcomeDelta` are **not** re-homed: ADR 0022
   sub-ruling 7 keeps those objects in foundations carrying only generic
   work-subject and bounded-System fields, and this ADR's keep-list deliberately
   claims their *associations* rather than the objects.

   Consequence for contract identity: per ADR 0022 sub-ruling 7 these three take
   `schema://ioi/applications/ioi-ai/*` when they are registered. None of the
   three is registered today, so no existing `$id` changes and no alias is
   created.
7. **No ambient authority from composition.** A thread, fork, Session, harness
   binding, or terminal attachment is execution truth, not authority to mutate a
   GoalRun or room. Existing admission, scope, policy, and receipt gates remain.

## Stage Sequencing

This ruling does not change M4's exit contract. M4 proves OutcomeRoom package
genesis, bounded-System/Agentgres admission, room CAS, lineage, replay, and
read-only projections. It deliberately does not certify GoalRun execution
semantics. The M4 stage text must state that exclusion so its two literals
cannot be read as proof of this seam.

The runtime seam is a distinct successor cut after M4 closes and before M5
participant execution builds on GoalRun. That cut must bind the five named
kernel owners and prove that a GoalRun-coordinated harness can request another
bounded worker/harness only through daemon-owned fork/session/launch contracts.

ADR 0031 is the final architecture correction admitted before M4's literals.
Further findings are recorded for their owning successor stage and do not
expand M4 unless they invalidate an existing M4 exit clause.

## Non-Goals

- No deletion or renaming of GoalRun, OutcomeRoom, or Goal Space.
- No requirement that every GoalRun create a Session.
- No change to M4's admission, truth, replay, projection, or literal thresholds.
- No claim that the current five primitives form a completed end-to-end harness
  chain; the implementation matrix already records missing launch consumption.
- No permission for harnesses or agents to bypass daemon, authority, isolation,
  receipt, or Agentgres gates when orchestrating one another.

## Consequences

- GoalRun execution code is nonconforming until it consumes and projects the
  five named kernel primitives instead of remaining reference-free.
- M4 may close on its unchanged truth/projection contract after canon and stage
  text make this exclusion explicit.
- M5 gains a first, independently reviewable orchestration-seam cut. Its
  participant/frontier execution cuts depend on that cut.
- Hypervisor and ioi.ai may expose typed thread/fork/session/harness refs and
  derived status, but neither product surface owns the underlying execution
  truth.
- Harnesses can coordinate other harnesses only through the same public kernel
  contracts available to other bounded clients.

## Cost Of Being Wrong And Reversal

If GoalRun requires a private orchestration protocol for semantics the kernel
cannot express, the missing capability must first be stated as a substrate
requirement. Reversal would explicitly add that capability to the kernel or
authorize a narrowly named application protocol with separate ownership and
interop consequences. Retaining an implicit second spine is not a reversal
path.

## Canonical References

- `../architecture/domains/ioi-ai/goal-run-execution.md`
- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/components/hypervisor/core-clients-surfaces.md`
- `docs/architecture/domains/ioi-ai/control-plane.md`
- `docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md`
- `docs/architecture/_meta/implementation-matrix.md`
