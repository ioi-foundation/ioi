# GoalRun Admission And Activation Conformance Contract

Status: target conformance contract. No current admission evaluator, activation
route, or crossing receipt exists; the current runtime enforces a narrower
admission subset whose preconditions are partly satisfied by route-supplied
constants, which this contract exists to forbid.
Canonical inputs:
[`../../architecture/foundations/objects/goal-run-execution.md`](../../architecture/foundations/objects/goal-run-execution.md)
(the orchestration application's admission contract and `GoalRunEnvelope`
admission bindings; placement per ADR 0022),
[`../../architecture/components/daemon-runtime/doctrine.md`](../../architecture/components/daemon-runtime/doctrine.md)
(admission-evidence discipline),
[`../../architecture/foundations/objects/goal-pursuit.md`](../../architecture/foundations/objects/goal-pursuit.md)
(`GoalRunActivationEnvelope`),
[`../../architecture/foundations/objects/evidence-and-delivery.md`](../../architecture/foundations/objects/evidence-and-delivery.md)
(`ReceiptObligation`),
[`../../architecture/foundations/invariants.md`](../../architecture/foundations/invariants.md)
(INV-8, INV-12, INV-16, INV-17, INV-37).
Last audited: 2026-07-25.

## Scope and honest implementation posture

This contract tests one end-to-end proposition:

> Goal identity is created or joined only through daemon admission over
> resolved, independently verifiable evidence — a frozen profile resolution,
> a verified source context, a retained admitted state root, typed receipt
> obligations, and (when any originating context is claimed) exactly one
> admitted `GoalRunActivationEnvelope` — and never through a correlation id,
> pointer field, origin tag, subscription, facilitator selection, untyped
> `activation_evidence` payload, or route-supplied constants.

Honest posture: current master admits GoalRuns through
`runtime_goal_run_admission.rs` with a boolean receipt flag, a prefix-checked
state-root string the durable record drops, session verification performed
only in the route, and admission-core checks whose inputs the route itself
writes. None of the cases below passes today, and no product surface may claim
this profile.

## Cases

Verdicts are `pass | fail | blocked`. Unavailable substrate is `blocked`,
never skipped or passed.

- **GRA-1 — Resolved evidence, not asserted (INV-37).** With the admission
  core intact, a harness that supplies admission preconditions from the route
  layer (policy string, scope list, receipt flag, fabricated state-root ref)
  must yield an admission decision that this contract's evaluator classifies
  as void; the conforming path resolves the authority decision, session
  record, and state root itself. Fail: a route-authored constant satisfies any
  precondition.
- **GRA-2 — Profile resolution closure.** Admission without the exact profile
  revision + content hash, resolved-component snapshot + hash, and resolution
  receipt refuses; an admitted run replays its dependency closure from the
  receipt alone.
- **GRA-3 — Retained state commitment.** The durable record retains
  `admitted_state_root_ref`; replay verifies against the admitted Agentgres
  root; a prefix-shaped string with no admitted root behind it refuses
  (INV-8, INV-12).
- **GRA-4 — Typed receipt obligations.** Admission binds a `ReceiptObligation`
  set whose receipt types are registered; an obligation naming an unregistered
  type refuses; discharge requires a receipt of the named type binding the
  named facts, and a boolean or log line discharges nothing.
- **GRA-5 — Correlation is not admission.** Setting `goal_run_ref` on a
  Session, work item, WorkRun, or projection row; writing `origin_surface`;
  passing an untyped `activation_evidence` blob; or citing an AIIP
  `correlation_ref` creates or joins no goal identity and mutates no GoalRun.
- **GRA-6 — Activation crossing.** A creation claiming any originating
  context admits exactly one `GoalRunActivationEnvelope` with agreeing
  `source_kind`/`source_ref`, a daemon-resolved authority decision, and an
  activation receipt binding source, authority, and admitted `goal://`
  identity. `create` and `join_existing` field rules enforce; a join never
  rewrites the target's admission tuple.
- **GRA-7 — Idempotent crossing.** Resubmitting the same activation
  (`idempotency_key` + body) converges on the same admitted result; a changed
  body under a reused key refuses.
- **GRA-8 — Non-widening carry-over.** Carried context refs become lease
  candidates only; no authority, visibility, custody, retention, or budget
  widens by activation (INV-16), and carried participant input remains tainted
  until admitted (INV-17). Gateway-lane graduation
  (`source_kind: gateway_adapter_context`) grants no scope the run-on lane did
  not itself request.
- **GRA-9 — Products draft, daemon admits.** An ioi.ai surface, subscription,
  entitlement, or facilitation path can produce only `draft`/`submitted`
  activations; the transition to `admitted` is available solely through daemon
  admission.

## Open live gates

- No admission evaluator or `goal-run-admission` conformance tier exists.
- `GoalRunActivationEnvelope` has no registered schema, route family, store,
  or receipt type.
- The activation receipt type is unregistered in the receipt registry.
- The current GoalRun record neither retains a state root nor carries typed
  receipt obligations; the delta is recorded in
  [`../../architecture/_meta/canon-to-code-delta.md`](../../architecture/_meta/canon-to-code-delta.md).
