# GoalRun Admission And Activation Conformance Contract

Status: `active_invariant` for the selected M4 `create` +
`ioi_goal_draft` slice only. Registered activation, admitted-state,
execution-ceiling, and activation-receipt schemas, adversarial fixtures,
generated projections, daemon owner paths, and a count-pinned 44-assertion
fresh-process verifier make violations fail an executable gate. `join_existing`,
every other source kind, and the broader unified-admission cases remain target
behavior. This document does not own retained stage evidence, M4 status, or
product and release claims.
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
Last audited: 2026-07-30.

## Scope and honest implementation posture

This contract tests one end-to-end proposition:

> Goal identity is created or joined only through daemon admission over
> resolved, independently verifiable evidence — a frozen profile resolution,
> a verified source context, a retained admitted state root, typed receipt
> obligations, and (when any originating context is claimed) exactly one
> admitted `GoalRunActivationEnvelope` — and never through a correlation id,
> pointer field, origin tag, subscription, facilitator selection, untyped
> `activation_evidence` payload, or route-supplied constants.

Honest posture: the M4 activation path is judged by these cases, not by route
presence or schema acceptance. A green fresh isolated run proves the applicable
evaluator, retained state, typed obligations, idempotency, authority,
receipt-profile conformance, access control, and recovery behavior together for
this one lane. Only the implementation-program owner may retain that result or
use it in an M4 status decision. No broader admission or product-surface claim
follows.

## Active selected M4 slice

The isolated runner
`apps/hypervisor/scripts/verify-m4-goalrun-activation-plane.mjs` is intentionally
narrow. It exercises `activation_mode: create` from
`source_kind: ioi_goal_draft` under the daemon-resolved source owner, the
immutable built-in research profile, and an independently resolved and consumed
wallet authority grant for the exact reviewed activation. Its positive path
retains a non-granting draft before goal identity, requires explicit review over
the exact draft hash, obtains current wallet admission for
`scope:goal.run.create`, admits one GoalRun, binds the activation, authority
admission, state root, lifecycle head, profile closure, and three receipt
classes, then reconstructs those bytes after restart.

The same runner refuses caller profile injection, changed content under a reused
idempotency key, missing approval, stale reviewed bytes, durable source
substitution, daemon-resolved authority substitution, absent or expired wallet
authority, malformed or duplicate GoalRun registry truth, cross-owner
projection/lifecycle access, cross-owner result/delta mutation, and exposed
anonymous read/mutation. It also injects durability uncertainty at the GoalRun
write, refuses the uncertain success, and requires fresh-process recovery to
converge on the same identity. A green fresh run is implementation proof for
this slice; it is not a retained M4 literal or stage transition.

This slice does not implement or prove `join_existing`,
`hypervisor_session`, `work_run`, `work_item`, `outcome_room_claim`,
`automation_workflow_step`, or `gateway_adapter_context`. It also does not by
itself close GRA-1 through GRA-4 for every GoalRun admission source or establish
a shipped conversation surface. The activation-created GoalRun is durable
admitted identity/state/receipt truth; it does not provision a Session and is
not independently runnable through `/start` in this slice.

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

- This active invariant is not a general `goal-run-admission` conformance tier;
  it covers only the create-mode ioi.ai-draft source lane.
- The broader GoalRun admission path does not yet freeze every GRA-1 through
  GRA-4 profile-resolution and typed-`ReceiptObligation` requirement across all
  sources; that delta remains recorded in
  [`../../architecture/_meta/canon-to-code-delta.md`](../../architecture/_meta/canon-to-code-delta.md).
- `join_existing` and all six non-`ioi_goal_draft` source kinds remain
  unimplemented and unproven.
- No M4-stage, product-release, or conversation-surface claim follows from this
  focused verifier alone; those claims require their own retained evidence and
  owning gates.
