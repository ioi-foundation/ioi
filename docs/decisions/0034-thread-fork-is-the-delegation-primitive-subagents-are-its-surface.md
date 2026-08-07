# ADR 0034: Thread Fork Is The Delegation Primitive; Subagents Are Its Surface

- Status: Accepted
- Date: 2026-08-07
- Owners: daemon runtime / Hypervisor core surfaces / harness adapters
- Refines: ADR 0031, ADR 0022
- Confidence: high on the defect; the ruling is agent-proposed under standing
  program authority and is owner-reversible (see Reversal)

## Context

Canon documents two thread-delegation surfaces and never states their
relationship.

**Surface A — the primitive.** ADR 0031 names `runtime_thread_fork_control` as
the owner of "bounded agent/thread delegation" and lists it among the five
kernel primitives that GoalRun execution must compose.
`docs/architecture/components/daemon-runtime/api.md:2192` documents
`POST /v1/threads/{thread_id}/fork`.

**Surface B — the product API.**
`docs/architecture/components/daemon-runtime/api.md:2753` defines a Subagent API
of nine documented routes and states:

> Subagents are delegated work items under the same runtime substrate. They must
> inherit thread/run authority posture, budget limits, output contracts,
> cancellation behavior, and receipt requirements.

Measured on `1a93a47b2c827595ad8014d24d4e8a382c6f7a81`:

```text
/v1/threads/:id/fork          documented in canon, NOT registered in the daemon
/v1/threads/:id/subagents     8 routes registered and live
```

The live surface implements none of the inheritance canon requires of it:

```text
delegation depth limit                 absent
fanout / concurrency cap               absent
descendant-inclusive accounting        absent
ancestor-limit admission               absent
max_subagents-class symbols            0 repo-wide outside generated code
cancellation                           one level deep, opt-in (see below)
```

Cancellation deserves precision, because a weaker earlier claim was wrong.
Propagation exists: `handle_subagents_propagate_cancel` reads subagent records
filtered on `parent_thread_id == thread_id` and issues a run-cancel per child.
But it descends exactly one level, it is a separate endpoint the caller must
invoke, and `handle_thread_cancel` contains no child reference — so cancelling a
parent thread succeeds without touching its children. INV-35 requires derived
cancellation fanout over the work-owning graph and forbids parent success until
relevant child effects are terminal or fenced.

An unstated relationship between two surfaces for one concept is how a system
acquires two mechanisms. The defect is not that either surface is wrong; it is
that neither is declared subordinate, so bounding logic has no single home.

## Decision

**`runtime_thread_fork_control` is the delegation primitive. The Subagent API is
the product surface composed over it. Subagent spawn is a fork client and owns
no delegation semantics of its own.**

```text
PRIMITIVE (kernel, owns the semantics)
  runtime_thread_fork_control          bounded thread/agent delegation
  + WorkLifecycle ancestor admission   depth, fanout, narrowing, reservations,
                                       cancellation fanout, non-release

SURFACE (product API, owns naming and projection only)
  /v1/threads/:id/subagents and its lifecycle routes

FORBIDDEN
  any delegation bound, budget check, depth check, fanout cap, or cancellation
  descent implemented at the subagent handler or any other call site
```

The subagent surface keeps its name, its routes, and its projections. It loses
the right to write delegation records directly.

### Consequential sub-rulings

1. **One bounding site.** Delegation bounds live in the kernel admission path
   and nowhere else. A bound added at a call site is a defect, not a stopgap,
   including a temporary one. This generalizes ADR 0031's "no second
   orchestration spine" from GoalRun to every delegating caller.
2. **`POST /v1/threads/{id}/fork` is retired from canon as a public route.**
   Fork is the internal primitive, reached through the surface that already
   exists. Documenting an unwired public route for the same concept is what
   created the ambiguity. `api.md:2192` must be removed and the Subagent API
   section must state that it composes fork.
3. **Inheritance is structural, not advisory.** `api.md:2755`'s "must inherit"
   is satisfied by the child's admission narrowing from the parent's record, not
   by the caller passing correct values. A caller that omits a bound gets the
   parent's, narrowed; it cannot widen.
4. **Cancellation is derived, not invoked.** Parent cancellation must fan out
   over the descendant graph through the kernel. The opt-in one-level endpoint
   is superseded and is deleted when the client is re-homed, not left beside the
   new path.
5. **The surface owns the child object; it does not own the delegation edge.**
   *(Corrected 2026-08-07. This sub-ruling first read "the surface owns no
   records… the direct `subagents` record write is deleted." That overreached,
   and canon contradicts it: `child_reference.child_ref` is a `typed_ref`, and
   `work-results-and-lifecycle.md` states that reference mutations "never mutate
   the child object; they only append or retire the owning object's typed index
   entry." The child object is therefore separate and owned elsewhere by
   design.)*

   A subagent's domain state — prompt, status, role, run ref — is the child
   object and legitimately persists on the subagent surface. What the surface
   may not own is the **delegation edge**: the parent→child work-owning relation
   and its bounds. That edge is a `child_reference` attach in the work-owning
   graph, admitted by the kernel.

   Consequences: the child object is written only *after* admission succeeds, so
   a refused delegation leaves no agent, run, or subagent record. Any projection
   that answers "what are this parent's children?" reads the graph, not a
   `parent_thread_id` scan. Projections that answer "what is this child's
   status?" read the child object by ref.
6. **This ADR adds no object, plane, runtime, or vocabulary.** It assigns
   ownership between two things canon already names.

## Non-Goals

- No rename or removal of the Subagent API, its routes, or its projections.
- No claim that every delegation must be recursive, or that subagents must be
  used at all.
- No change to ADR 0031's five-primitive composition rule; this applies it.
- No authorization for a model to select, widen, or bypass a delegation bound.
- No implementation status, stage, or gate is closed by this ADR.

## Consequences

- The subagent spawn path is nonconforming until it admits through
  `runtime_thread_fork_control` plus WorkLifecycle ancestor admission.
- The WorkLifecycle mechanism gains its first and highest-exposure client, which
  sets its client interface.
- `api.md` requires two edits: remove the unwired fork route, and state the
  composition on the Subagent API section.
- Until the kernel exists, the live subagent surface remains unbounded in depth
  and fanout. This ADR does not authorize a call-site guard to close that gap in
  the interim; the correct sequence is to build the kernel and re-home.
- An adaptive or model-driven proposer becomes safe to admit only after this
  composition lands, because refusal becomes structural rather than dependent on
  caller restraint.

## Cost Of Being Wrong And Reversal

If subagents and forks are genuinely distinct concepts — for instance if a
subagent must outlive its parent thread in a way a fork may not — then this
ruling wrongly collapses them. The reversal is to state that distinction
explicitly, name the semantics each surface owns, and give each its own
admission path under the same WorkLifecycle kernel. Reversal does **not** mean
returning to two surfaces with an unstated relationship, and does not mean
letting either own its own bounding logic.

This ADR was proposed and adopted by an agent under standing program authority
for the WorkLifecycle Admission Convergence program, so that the program could
sequence without stalling. It is owner-reversible on review. Everything
downstream in that program composes on it, so it should be reviewed before the
kernel's client interface freezes.

Number collision note: `0034` was the next free number on this tree
(`1a93a47b2`, no other worktrees). If `0034` is claimed by another tree, renumber
this file; no content depends on the number.

## Canonical References

- [`0031-goalrun-execution-composes-thread-orchestration.md`](./0031-goalrun-execution-composes-thread-orchestration.md)
- [`0022-goal-orchestration-application-layer-and-clean-slate.md`](./0022-goal-orchestration-application-layer-and-clean-slate.md)
- `../architecture/components/daemon-runtime/api.md` (Subagent API)
- `../architecture/components/daemon-runtime/doctrine.md`
- `../architecture/foundations/invariants.md` (INV-35)
- `../architecture/_meta/canon-to-code-delta.md` (WorkLifecycle row)
