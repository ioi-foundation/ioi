# ADR 0020: Unify GoalRun Admission And Require Resolved Admission Evidence

- Status: Accepted
- Date: 2026-07-25
- Owners: daemon runtime / goal pursuit objects / evidence and receipts / conformance
- Refines: ADR 0002, ADR 0017
- Confidence: settled for the unification and the resolved-evidence rule
  (INV-37); working_ruling for the exact field names added to
  `GoalRunEnvelope`, which the object owner may rename before any schema
  registration.

## Context

`term-boundaries.md` names `daemon-runtime/doctrine.md` as the owner of
GoalRun admission doctrine. Until this pass, that file contained no GoalRun
admission contract at all. Meanwhile canon and code enforced two nearly
disjoint contracts:

- The object family required the profile-resolution closure — exact revision +
  content hash, resolved-component snapshot + hash, resolution receipt before
  `active` — and code checked none of it.
- The running admission core required `scope:goal.run.orchestrate`, a real
  target session/project, `receipt_required: true`, and a
  `state_root_ref` — and canon defined no field for any of them on
  `GoalRunEnvelope`.

Worse, the enforcement that existed was structurally hollow: the route
verified the session itself but then supplied the policy string, scope list,
receipt flag, and a fabricated prefix-shaped state-root ref in the request it
submitted to the pure admission core — which then "checked" the constants the
route had just written. The persisted record dropped the state root entirely,
and the receipt obligation was a boolean that cannot say which receipt binds
which boundary.

## Conflicting Readings

1. **This is an implementation bug, not a canon defect.** Fix the Rust; leave
   canon alone.
2. **This is a canon defect the code inherited.** Canon never stated that
   admission preconditions must be discharged from resolved, independently
   verifiable evidence, so a conforming implementation was free to launder
   constants through its own route. The same class of defect had already
   appeared elsewhere (loopback posture laundering; a non-executing MCP invoke
   reporting `executed`).

## Decision

Reading 2. Three moves, all additive:

1. **The unified admission contract** now lives in its named owner
   (`daemon-runtime/doctrine.md`): profile-resolution closure, activation
   binding (ADR 0019), daemon-verified source context, daemon-resolved
   authority, retained admitted state root, typed receipt obligations, and
   declared bounds — all required together before `active`.
2. **INV-37 — Admission evidence is resolved, never asserted** — joins the
   invariant registry: no route, client, or projection may satisfy an
   admission precondition by writing the value the admission core checks; an
   admission over self-supplied constants is void for conformance purposes.
   This is deliberately general because the failure class is general.
3. **`ReceiptObligation`** becomes the shared element type
   (`objects/evidence-and-delivery.md`) behind every `receipt_obligations`
   array, replacing boolean and untyped-string obligations; `GoalRunEnvelope`
   gains `activation_ref`, `source_context_binding`,
   `admitted_state_root_ref`, `authority_scope_refs`, and
   `receipt_obligations`, and the durable record retains them.

## Invariants

- INV-37 (new), applied by the daemon doctrine and API owners.
- INV-8/INV-12: the retained state root names an admitted Agentgres root;
  replay verifies against it; availability or prefix shape proves nothing.
- INV-9: obligations are discharged only by receipts of the named registered
  type binding the named facts.

## Rejected Alternatives

- **Code-only fix.** Leaves the next implementation free to reintroduce the
  pattern; the canon would still contain no rule against it.
- **A new admission super-object.** Nothing here needs a new runtime object;
  the correction strengthens existing contracts and adds one shared element
  type. Inventing an "AdmissionEnvelope" would violate the no-new-objects-for
  -completeness rule.
- **Weakening canon to match code** (dropping the resolution closure to bless
  the current narrow admission). Never — that trades the stronger guarantee
  away.

## Surfaces Affected

`foundations/invariants.md` (INV-37), `daemon-runtime/doctrine.md`,
`objects/goal-run-execution.md`, `objects/evidence-and-delivery.md`,
`canon-to-code-delta.md` (admission-bindings row), and the conformance target
`goal-run-admission-and-activation.md` (GRA-1..GRA-4).

## Cost Of Being Wrong And Reversal

If INV-37 proves too strict for some legitimate pattern (for example, a
trusted composition layer that genuinely owns a precondition), the reversal is
to narrow the invariant's wording to name the exempted layer explicitly — not
to delete it. The envelope field additions are unregistered target fields; they
can be renamed or restructured freely until the first schema registration,
after which ordinary successor-revision rules apply. Removing the unified
contract would return the canon to a state where its named admission owner
states no admission contract, which no reading supported.

## Canonical References

- [`../architecture/foundations/invariants.md`](../architecture/foundations/invariants.md)
- [`../architecture/components/daemon-runtime/doctrine.md`](../architecture/components/daemon-runtime/doctrine.md)
- [`../architecture/foundations/objects/goal-run-execution.md`](../architecture/foundations/objects/goal-run-execution.md)
- [`../architecture/foundations/objects/evidence-and-delivery.md`](../architecture/foundations/objects/evidence-and-delivery.md)
- [`../conformance/hypervisor-core/goal-run-admission-and-activation.md`](../conformance/hypervisor-core/goal-run-admission-and-activation.md)
