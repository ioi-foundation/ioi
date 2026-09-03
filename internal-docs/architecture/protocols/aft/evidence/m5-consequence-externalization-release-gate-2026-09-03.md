# M5 consequence externalization release gate — 2026-09-03

Status: **PASS for the declared atomic-idempotency resource model**. This
closes M5 and establishes T10/L-X. It does not claim at-most-once behavior for
an arbitrary HTTP API, physical action, or adapter that lacks the exact
resource contract.

## End-to-end boundary

`EffectManifestV1` commits:

- exact resource and conflict-domain identities;
- sorted, duplicate-free and disjoint read/write sets;
- stable idempotency key;
- request, predecessor, intent, and expected-outcome roots;
- exact adapter/resource profile and PQ posture;
- `GuaranteeRequirementsV1`;
- protocol-height/configuration or authority-epoch/snapshot fence; and
- reconciliation policy.

A prepared runtime-v3 recognized effect binds the manifest root before the
Agentgres linearization point. `AcceptedEffectAuthorizationV1` can then be
constructed only by reverifying that committed runtime bundle and rebinding
its achieved guarantee root, Agentgres record/root/sequence, manifest, and
authority snapshot. The consequence store rejects a substituted token,
manifest, assurance root, profile, configuration, height, or authority fence.

## Resource and state-machine model

`ExternalResourceV1` exposes the exact committed profile, one atomic mutation
method, same-key lookup, and a profile-specific evidence verifier. Only atomic
put-if-absent, compare-and-set, or equivalent profiles advertise
`at_most_once=true`; unsupported profiles advertise best effort and fail an
irreversible at-most-once policy.

The durable state machine is:

```text
Authorized -> Claimed -> InFlight -> Executed -> Reconciled
                              \----> Unknown  -> Reconciled
```

Every transition is JCS-committed in a generation-checked trace and persisted
with file fsync, atomic rename, and directory fsync. A lifetime file lock
prevents concurrent local clone invocation. `Claimed` and `InFlight` are
durable before the one resource call. A restart from `InFlight` always enters
`Unknown`; neither `Unknown` nor `Executed` exposes a mutation transition.
Reconciliation performs only same-key lookup and is bounded by the manifest.

## Crash, duplicate, and attribution evidence

The executable campaign injects a crash after each boundary:

1. authorization persistence;
2. claim persistence;
3. in-flight persistence;
4. resource return before local outcome persistence;
5. executed persistence;
6. unknown persistence;
7. reconciliation lookup before persistence; and
8. reconciled persistence.

Every path reopens from disk, reaches a valid terminal or safely absent
reconciliation, performs at most one invocation, and produces at most one
modeled mutation. The most adverse path mutates the resource and then crashes
while durable local state still says `InFlight`; restart changes that to
`Unknown` and resolves by lookup without calling mutation again.

Duplicate execution and reconciliation deliveries are idempotent or typed
refusals. Three inconclusive reconciliation observations exhaust the policy
without becoming mutation authority.

Ordinary invocation/lookup ambiguity produces no attribution object. A
contradictory record produces `ResourceViolationEvidenceV1` only when its
evidence verifies under the exact committed resource profile. A forged
evidence commitment is rejected as unattributed.

## Mutation calibration

The `InFlight -> Unknown` restart guard was temporarily disabled. The focused
post-resource-call crash test failed with exit 101 because restart exposed
`InFlight` instead of `Unknown`. The guard was restored before clean runs.

## Formal and trace-conformance evidence

`AtMostOnceExternalization.tla` models pre-call durable claim, one atomic
register call, reply loss, crash at `InFlight`, and lookup-only reconciliation.
TLC result: **PASS**, 66 generated / 42 distinct states, complete depth 8, no
errors. Invariants cover at-most-one mutation, at-most-one invocation,
claim-before-call, and mutation/register consistency.

Rust tests pin both modeled traces byte-for-phase:

```text
Authorized, Claimed, InFlight, Executed, Reconciled
Authorized, Claimed, InFlight, Unknown, Reconciled
```

## Clean verification

```text
cargo test -p ioi-types consequence::tests --lib
cargo test -p agentgres consequence::tests --lib
cargo test -p agentgres --lib
cargo test -p agentgres runtime_v3_effect_linearizes_recovers_and_replays_on_the_agentgres_spine --lib
java -cp "$(git rev-parse --show-toplevel)/.internal/formal-cache/tools/tla/tla2tools.jar" tlc2.TLC -cleanup -deadlock -config AtMostOnceExternalization.cfg AtMostOnceExternalization.tla
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/check_aft_theorem_assumes.sh
bash .github/scripts/check_aft_claim_discipline.sh
git diff --check
```

Observed results:

- consequence manifest/profile types: **4 passed / 0 failed**;
- consequence runtime/adversarial subset: **11 passed / 0 failed**;
- complete Agentgres library: **98 passed / 0 failed** in 129.69 seconds;
- committed runtime-v3 manifest-binding path: **1 passed / 0 failed**;
- formal model: **66 generated / 42 distinct**, depth 8, no errors;
- formal census: **38 modules = 25 executed + 13 explicitly manual**;
- theorem-assumption, claim-discipline, formatting and whitespace gates:
  **PASS**.

## Honest limitations

- At-most-once is conditional on the declared atomic endpoint contract. The
  client cannot manufacture that property from local durability.
- Reconciliation may terminate as safely absent or exhaust its observation
  budget; T10 is a safety theorem, not guaranteed external occurrence.
- Transferable attribution requires endpoint-verifiable evidence under the
  committed profile. Network ambiguity is never blamed.
- Portable air-gapped authentication of the complete consequence receipt is
  M7 work; integrated production rollout and mixed-domain demonstration remain
  M8 work.
