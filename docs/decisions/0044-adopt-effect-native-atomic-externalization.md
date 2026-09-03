# ADR 0044: Adopt Effect-Native Atomic Externalization

- Status: Accepted and implemented for the M5 modeled-resource boundary
- Date: 2026-09-03
- Owners: AFT assurance, Agentgres recognized effects, adapter execution
- Refines: ADR 0041 externalization coordinates
- Confidence: state-machine, formal, crash, duplicate, and negative gates pass;
  arbitrary endpoints remain outside the theorem

## Context

Ledger consensus can prove that an effect was authorized without proving what
happened at an external database, service, or physical resource. A network
timeout is compatible with both “the resource mutated and the reply was lost”
and “the request never arrived.” Retrying an ordinary non-idempotent endpoint
can duplicate an irreversible consequence; refusing to retry can omit it.

AFT therefore needs a consequence theorem with an explicit resource boundary,
not a relabeling of ledger finality.

## Decision

### 1. Every consequence starts from `EffectManifestV1`

The manifest commits the exact resource and conflict domain, complete read and
write footprint, stable idempotency key, request/predecessor/intent/expected-
outcome roots, adapter/resource profile, guarantee requirements, height or
authority fence, and reconciliation policy. Sets are canonical and duplicate-
free. A manifest is bound to a runtime-v3 recognized effect before Agentgres
linearization; it cannot be attached after admission.

### 2. At-most-once is a resource-contract claim

Only atomic put-if-absent, compare-and-set, or a precisely equivalent
idempotency register can advertise `at_most_once=true`. An unsupported adapter
advertises best-effort externalization. An irreversible policy requiring
at-most-once refuses it.

### 3. Claim precedes invocation

The durable state machine is:

```text
Authorized -> Claimed -> InFlight -> Executed -> Reconciled
                              \----> Unknown  -> Reconciled
```

`Claimed` and `InFlight` are file- and directory-flushed before the sole
external mutation call. A crash or ambiguous response at `InFlight` can only
enter `Unknown`. `Unknown`, `Executed`, and restart recovery expose same-key
lookup, never mutation replay. Reconciliation attempts are bounded and expiry
does not mint retry authority.

### 4. Attribution requires endpoint-verifiable evidence

A contradictory resource record is transferable fault evidence only if its
bytes verify under the exact committed resource profile. A timeout, missing
reply, or inconclusive lookup is recorded as local ambiguity and names no
violator.

## Consequences

- AFT can state T10 over a modeled atomic external resource and pair it with
  L-X, the ambiguous-response retry lower bound.
- Adapters without the contract remain usable for reversible/best-effort work,
  but cannot satisfy an irreversible at-most-once policy.
- Receipts become larger because they carry the manifest, state trace, resource
  record, and reconciliation commitment.
- This ADR does not assert that arbitrary HTTP APIs or physical devices expose
  the modeled contract. Their profiles must prove it separately.

## Rejected alternatives

### Retry after timeout

Rejected because the first invocation may already have mutated the resource.

### Treat a local outbox marker as external occurrence

Rejected because it proves only local intent or transport progress.

### Attribute an ambiguous timeout

Rejected because the same observation exists in honest network-failure and
post-mutation reply-loss executions.
