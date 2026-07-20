# Platform operability conformance

Status: target conformance contract with a canonical machine-readable fault
matrix. No current cross-plane operability evaluator, recovery kernel, or live
fault-injection tier is claimed.
Canonical input:
[`platform-operability.md`](../../architecture/components/daemon-runtime/platform-operability.md).
Last audited: 2026-07-20.

## Scope and honest implementation posture

This profile specifies the behavior of a future cross-plane operability
evaluator, recovery kernel, version/key-transition validator, and protected
observability projection. It also specifies the operability refusal boundary
that durable resource-cleanup and active-head owners must consume. The
canonical fault matrix is a target fixture corpus. Current master does not
execute it and therefore proves no operation disposition, stable reason code,
bounded-cache decision, unknown-effect refusal, persistent cleanup,
forward-only activation, reconstructed root, upgrade decision, signer
rotation, or protected field minimization.

A future executable gate must consume authentic owner-produced observations
immediately before the relevant effect. Fixture rows alone cannot establish
freshness, recovery, rotation, reconciliation, load shedding, or correlated
failure survival.

## Required behavior

### CPO-1 — Required-plane refusal

For the selected operation, a missing, stale, unavailable, or
split-brain-suspected required plane must fail closed. A degraded required plane
may return an explicit degraded result only when it binds a nonempty degraded
contract that lists the exact operation class as allowed. A missing contract or
a contract scoped to another operation fails closed with a recovery duty.

### CPO-2 — Failure only narrows

The effective assurance posture may remain equal or narrow. A fallback posture
stronger than the asserted posture is invalid input. Stale or unavailable
attestation blocks portable assurance export.

### CPO-3 — Unknown effects

An unknown effect must return `fail_closed`, preserve attempt/effect evidence,
and require reconciliation before retry, compensation, or success.

### CPO-4 — Bounded cache

Only `cached_read` may use bounded stale state. Cache age at or below the
declared maximum plus a nonempty exact source head returns `degraded` with a
source-head evidence duty; a missing head, missing age/bound, or older cache
fails closed.

### CPO-5 — Physical continuation

Remote-plane loss may leave `physical_bounded_continuation` degraded only when
the admitted local supervisor remains available. Otherwise it fails closed into
the declared minimum-risk or safe-stop state.

### CPO-6 — Billing and settlement separation

Billing loss blocks new paid work and finalization. Public-settlement loss may
degrade unrelated local work while retaining a later-settlement duty, but it
must block a public-settlement operation.

### CPO-7 — Stable machine codes

Plane-qualified reason and obligation codes use canonical snake-case plane
slugs. They must not depend on Rust debug formatting or presentation labels.

### CPO-8 — Exact checkpoint recovery

Checkpoint entries plus every ordered suffix mutation must reproduce the
declared root at each sequence and the expected final root. Gap, reorder,
previous-root mismatch, mutation tamper, or final-root mismatch fails closed.

### CPO-9 — Mixed-version and key-epoch safety

Mixed peers select the highest mutually supported schema version. No overlap
returns a typed upgrade requirement, and consequential unknown fields may not
be lost. Key rotation admits exactly one successor signing epoch, retains the
declared verification window, and requires current revocation state plus
distribution receipts.

### CPO-10 — Privacy-safe observability projection

Each field must be allowlisted and retain a contract-valid
`InformationFlowLabel`. Confidential, private, or restricted values may enter
the projection only as a governed ref or SHA-256 hash, never raw content.

### CPO-11 — Typed temporal validity and rollback limits

Every operation requiring temporal claims binds an exact
`TemporalVerificationProfile` and recomputable
`TemporalValidityEvaluation`. Each requested claim returns
`established`, `indeterminate`, `failed`, or `unavailable`; the evaluation
cannot make the operability or final effect decision.

The executable matrix must prove:

- lower/upper interval evaluation under the owner's exact activation/expiry
  operators, with overlap never rounded toward admission;
- challenge freshness separately from source-fact recency;
- same-boot elapsed continuity with explicit suspend, pause, drift, reset, and
  reboot behavior;
- owner-scoped version/epoch floors without interpreting them as time;
- whole-state rollback refusal unless the relevant floor survives outside the
  declared rollback domain or fresh independent evidence re-anchors it;
- historical integrity and valid-as-of conclusions without a false currentness
  claim;
- bounded-offline holdover, revocation exposure, effect budget, and reconnect
  behavior; and
- final resource fencing independently of clock or lease freshness.

Where a matrix case reaches a resource fence, it records Platform
Operability's expected disposition separately from the final PEP disposition.
Fresh temporal/plane evidence may yield `available` while the owner-derived
stale fence still yields a final fail-closed result and zero invoker calls.

### CPO-12 — Persistent cleanup and forward-only activation

Cleanup obligations survive deletion of their originating owner and remain
open while the provider is unreachable, a deletion effect is unknown, or a
provider `not found` result lacks the exact namespace and resource-identity
binding. An unknown deletion returns Platform Operability's `fail_closed`
disposition while the cleanup owner retains a `reconciling` lifecycle state;
the disposition and the durable lifecycle state are not competing
vocabularies.

Failed, unadjudicated-partial, unknown, and late-superseded activation
executions cannot advance or reclaim an active release, route, restore,
migration, rollback, writer, or other owner head. The prior head and generation
remain unchanged. A superseded execution's late success observation remains
evidence, but it cannot reactivate the older target.

## Canonical matrix

The canonical target matrix is
[`platform-fault-matrix.v1.json`](./platform-fault-matrix.v1.json). New planes,
operation classes, or fallback rules require positive and adversarial scenarios
in this matrix before their conformance claim is promoted.

Current master has no `operability` conformance tier. The matrix must remain
valid JSON, retain `status: target_fixture_only`, and match the reviewed
32-scenario roster and semantic fingerprint enforced by
`check:conformance-docs`. That documentation/fixture evidence must not be
reported as an executable platform pass.

The older v1 rows that use only `{plane: clock, state: healthy}` exercise coarse
cross-plane dependency handling; that flag is not temporal proof. They must be
augmented with owner-produced temporal evaluation inputs before an executable
operation-readiness or effect-admission claim is made. The dedicated temporal
rows below state the new refusal boundary.

## Open live gates

- the cross-plane evaluator and stable reason/obligation implementation;
- deterministic checkpoint/suffix recovery, mixed-version, key-epoch, and
  privacy-safe observability kernels with adversarial tests;
- owner-signed or owner-rooted plane-observation fixtures;
- registered temporal profile/evaluation contracts, source adapters, and
  portable receipt wrapper;
- outside-rollback-domain continuity floors or fresh re-anchor adapters plus
  interval, reboot, restore, and holdover fault injection;
- daemon/scheduler admission immediately before real effects;
- provider-unreachable, unknown-delete, and identity-ambiguous `not found`
  cleanup reconciliation that survives owner teardown;
- monotonic active-head compare-and-swap fault injection proving failed,
  partial, unknown, and late-superseded executions cannot advance or reclaim
  the head;
- correlated failure injection across shared failure domains;
- live checkpoint/backup restore using each plane's actual persistence engine;
- key distribution/revocation across real signer and verifier processes;
- deployed mixed-version rollout and rollback;
- quote/usage/debit/refund and receipt/checkpoint reconciliation;
- saturation/backpressure/load-shed behavior; and
- end-to-end observability canaries proving protected content cannot enter
  disallowed telemetry or learning sinks.

The operability cut is not production-complete until these live gates either
pass or carry explicit deferred dispositions without stronger claims.
