# ADR 0019: Adopt GoalRunActivation As The Product-Crossing Admission Contract

- Status: Accepted
- Date: 2026-07-25
- Owners: goal pursuit objects / daemon runtime / ioi.ai control plane / Hypervisor core surfaces
- Refines: ADR 0015, ADR 0016, ADR 0017
- Confidence: working_ruling — the owner can overturn the naming and ownership
  placement from this record alone; the correlation-is-not-admission rule
  itself is settled doctrine already implied by term-boundaries and INV-17.

## Context

The canon's registered gap register carried, verbatim: "The
Hypervisor-to-ioi.ai crossing has no contract." Rich handoffs existed out of
ioi.ai (`IoiAiGoalChatHandoff`), but no envelope, route, or receipt family
moved work from an existing Hypervisor context — a Session, WorkRun, work
item, room claim, automation step, or gateway adapter context — into an
admitted GoalRun. Nothing prevented a future implementation from treating a
correlation id as admission, and the runtime already carried the hazard: GoalRun
creation persisted an untyped `activation_evidence` blob and derived
`creation_provenance: explicit_activation` from its mere presence.

The nearest existing shape was `HypervisorGoalRunActivationContract`
(`core-clients-surfaces.md`), which covers only the AutomationSpec
workflow-step lane with `activation_mode: create | join_existing`.

## Conflicting Readings

1. **Product-owned crossing.** The gap register named
   `domains/ioi-ai/control-plane.md` first among resolving owners, and the
   crossing is most visible as a product gesture ("promote this session into a
   goal"), so the object could live at the ioi.ai layer.
2. **Substrate-owned crossing.** Term-boundaries fixes the layer split: the
   substrate owns object identity, admission, and lifecycle; ioi.ai owns
   pre-admission drafts and projections and must never become an admission
   path. A product-layer admission object would be the first product object
   with admission power — precisely the boundary failure the canon defends
   against.
3. **Extend the automation contract.** Widen
   `HypervisorGoalRunActivationContract` to every source kind rather than
   defining a new object, keeping one name.

## Decision

Reading 2, with reading 3's *shape* but not its ownership: adopt
**`GoalRunActivationEnvelope`** as a substrate object owned by
`foundations/objects/goal-pursuit.md`, admitted only by the daemon, drafted
and projected by products. It binds exactly one typed source context
(`ioi_goal_draft | hypervisor_session | work_run | work_item |
outcome_room_claim | automation_workflow_step | gateway_adapter_context`),
`create | join_existing` mode, a daemon-resolved authority decision, an
idempotency key, non-grants, and an activation receipt. The normative rule:
**correlation is not admission** — pointer fields, `origin_surface` tags,
subscriptions, facilitator selections, and untyped `activation_evidence`
payloads never create or join goal identity.

Consequential sub-rulings:

- `HypervisorGoalRunActivationContract` keeps its owner and lane; its
  resolution admits through this family as
  `source_kind: automation_workflow_step`. One crossing contract, not two
  admission paths.
- The attach lane graduates through the same family
  (`gateway_adapter_context`), so the Authority Gateway migration debt is paid
  by one object rather than a parallel one.
- The name deliberately avoids "Handoff": `ContextHandoff` (intra-run) and the
  AIIP `HandoffPacket` (cross-sovereign) already carry two distinct handoff
  semantics, and a third would conflate boundaries. A term-boundaries row now
  fixes the qualified-handoff rule.
- The direct creation lane (`api | hypervisor_new_session`) is retained and
  needs no activation object — there is no source context to carry.

## Invariants

- Products draft; the daemon admits (INV-37 for how it admits).
- Activation widens nothing: no authority, visibility, custody, retention, or
  budget changes by activation alone (INV-16); carried input stays tainted
  until admitted (INV-17).
- Admission mints an activation receipt binding source, authority decision,
  and admitted `goal://` identity; resubmission under the same idempotency key
  converges; a changed body under a reused key refuses.

## Rejected Alternatives

- **A product-layer admission object** — makes ioi.ai an admission path,
  contradicting the Facilitation boundary row.
- **Typing `activation_evidence` in place without an object** — leaves the
  crossing unaddressable, unauditable, and non-idempotent; a field cannot
  carry a lifecycle, receipt, or refusal.
- **A third "Handoff" name** — see naming sub-ruling above.

## Surfaces Affected

`objects/goal-pursuit.md`, `objects/goal-run-execution.md`
(`activation_ref`), `daemon-runtime/doctrine.md` (admission contract),
`domains/ioi-ai/control-plane.md` and `collaborative-outcome-pattern.md`
(product lane), `term-boundaries.md`, `vocabulary.md`,
`canon-to-code-delta.md`, and the new conformance target
`goal-run-admission-and-activation.md` (GRA-5..GRA-9).

## Cost Of Being Wrong And Reversal

The contract is additive: no wire identifier, route, or existing object is
renamed or removed, and the direct creation lane is untouched. If the owner
prefers product-layer ownership or a widened automation contract, reversal is:
move the envelope section to the chosen owner, repoint the six referencing
docs above, and keep the correlation-is-not-admission rule (which predates
this ADR in spirit and must survive any reversal). Nothing shipped consumes
the object yet; the recorded delta row marks it not started.

## Canonical References

- [`../architecture/foundations/objects/goal-pursuit.md`](../architecture/foundations/objects/goal-pursuit.md)
- [`../architecture/components/daemon-runtime/doctrine.md`](../architecture/components/daemon-runtime/doctrine.md)
- [`../architecture/domains/ioi-ai/control-plane.md`](../architecture/domains/ioi-ai/control-plane.md)
- [`../architecture/foundations/term-boundaries.md`](../architecture/foundations/term-boundaries.md)
- [`../conformance/hypervisor-core/goal-run-admission-and-activation.md`](../conformance/hypervisor-core/goal-run-admission-and-activation.md)
