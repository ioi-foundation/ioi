# M17Q R2 — validator delayed-timer regression + per-principal waiting bound (2026-09-06)

Repair slice against R1 findings QUV-M17Q-003 (runtime delayed-timer window) and
QUV-M17Q-010 (one caller occupying every queued slot). Worktree HEAD 24a9888e3,
dirty (other agents editing other files concurrently). This slice touches only
the validator orchestration files listed below. Nothing here closes either
finding as a whole; see "Nonclaims".

## Files changed

| file | sha256 (after) |
|---|---|
| `crates/validator/src/standard/orchestration/quv.rs` | `f55a7b76783f319da0f3e9bec9206bdb67d6ae87bbee1c9144bd83676513ce44` |
| `crates/validator/src/standard/orchestration/quv/admission.rs` | `78f32d145a21da0a716d94e7770c8f0ae871c66f2330def2b009db38b83c30c6` |
| `crates/validator/src/standard/orchestration/mod.rs` | `50ad839f42b9665b704001f9a9727b6951d1a5803454a67430fa639c1aabab56` |
| `crates/validator/src/standard/orchestration/grpc_public.rs` | `165021ac2ab824274bebc5d22a367cf43bec526e2ba5b73f313811dfeeb79f4e` |

`cargo fmt -p ioi-validator --check` clean. mod.rs and grpc_public.rs changes are
one call-site argument each (`candidate.authorizer`) to `receipt_access`.

## 1. Runtime delayed-timer regression (finding 003, validator side)

Refactor (behaviour-preserving): the decision inside `finish_operation`'s
`dispatch.finish(..)` closure — `operation.finish(&cv, &rv)?` followed by the
`service_deadline` expiry cap — is extracted into

```rust
fn finalize_operation_at_deadline<V, R>(
    operation: QuvOnlineOperationV0,
    service_deadline: Option<Instant>,
    candidate_validator: &V,
    reply_verifier: &R,
) -> Result<QuvOnlineAuthorizationV0>
where V: QuvCandidateValidatorV0, R: QuvReplyVerifierV0
```

The production closure still builds the rooted validators inside
`dispatch.finish` (same error ordering) and then calls this function; the
timer task is unchanged (`sleep(wait)` then `finish_operation`).

New test `standard::orchestration::quv::tests::late_timer_wake_cannot_admit_a_reply_observed_after_the_rooted_deadline`
(quv.rs). Both arms use interval 200 ms and a timer that fires at 600 ms, and
run the production sequence on a real `PendingQuvOperationV0` table entry:
`handle_reply` (production reply entry) → table removal → `dispatch.finish(||
finalize_operation_at_deadline(..))` → `finish_active_service` →
`QuvAdmittedAuthorizationV0::new` → completion channel.

- Negative arm: the singleton reply is observed after the deadline (asserted
  `started.elapsed() > interval` before `handle_reply`), then the late timer
  finalizes. Delivered result is `Err` whose `downcast_ref::<QuvError>()` is
  `NoValidReplies`; the accepted-history branch is unreachable (outcome is
  `Err` before it); no continuation value is delivered; the admission permit
  is back at 1.
- Positive arm: the reply is observed inside the interval (asserted
  `started.elapsed() < interval` after `handle_reply`), then the timer
  finalizes at 600 ms (late). The continuation is delivered and its
  `candidate_hash`/`verifier_nonce` match; the admission permit is held until
  `with_continuation` returns.

## 2. Per-principal queued-waiter bound (finding 010, admission side)

`admission.rs`:

```rust
pub(crate) const WAITING_PER_PRINCIPAL: usize = 1;

// before: reserve_foreground(&self, domain: QuvHash)
pub(super) fn reserve_foreground(&self, domain: QuvHash, principal: AccountId)
    -> Result<QuvWaitingForegroundV0>

// before: receipt_access(&self, domain: QuvHash)
pub(crate) async fn receipt_access(&self, domain: QuvHash, principal: AccountId)
    -> Result<OwnedSemaphorePermit>

// unchanged: owned_receipt_access(&self), preparation(&self)
```

Principal = `request.candidate.authorizer` (`AccountId`). For the foreground
reservation it is taken after `validate_candidate` in
`reserve_online_authorization` (quv.rs). For `receipt_access` it is the
candidate's claimed authorizer at the executor entry points (mod.rs
`execute_quv_effect` path, grpc_public.rs `execute_aft_quv_effect`); that
field is validated later by the same request's `reserve_online_authorization`.

Semantics: on top of the existing per-domain / historical lane bounds, a
principal holds at most `WAITING_PER_PRINCIPAL` queued **foreground** waiter
across all enrolled domains, and separately at most `WAITING_PER_PRINCIPAL`
queued **receipt** waiter across all domain lanes plus the shared historical
lane. Lane permit is taken first; if the principal check refuses, that permit
is dropped in the same call — nothing is retained (typed `anyhow` error
`"QUV principal already has a waiting {foreground|receipt} request"`). The
principal share is released with the lane permit: on admission to the active
lane, or on cancellation (drop). The principal table is a counted
`BTreeMap<AccountId, usize>` whose membership is bounded by the lane
capacities (every entry's holder owns a lane permit).

Tests (admission.rs):
- `per_principal_waiting_bound_refuses_second_queued_request_and_releases_on_cancel`
- `per_principal_receipt_waiting_bound_spans_domain_and_historical_lanes`

Existing admission tests are unchanged in semantics; the two that call
`reserve_foreground`/`receipt_access` directly now pass distinct principals so
they still exercise only the lane bounds. Test helper `foreground(domain)` uses
`AccountId(domain)`.

### Removed-rule control

Mutant: in `QuvPrincipalWaitersV0::try_acquire`, the
`if count >= WAITING_PER_PRINCIPAL { return Err(..) }` block was replaced by
`let _ = lane;` (bound removed, counting kept). Command:

```
cargo test -p ioi-validator --features consensus-aft --lib \
  standard::orchestration::quv::admission::tests::per_principal
```

Transcript (`control-mutant-principal-bound-removed.txt`):

```
test ...::per_principal_waiting_bound_refuses_second_queued_request_and_releases_on_cancel ... FAILED
test ...::per_principal_receipt_waiting_bound_spans_domain_and_historical_lanes has been running for over 60 seconds
```

The receipt test hangs under the mutant because the call the test expects to
be refused instead queues on the single active receipt permit forever; the run
was terminated by the shell timeout. Both tests are non-passing under the
mutant. The rule was restored exactly: admission.rs sha256 before mutation and
after restore are both
`78f32d145a21da0a716d94e7770c8f0ae871c66f2330def2b009db38b83c30c6`.

## 3. Push refusal ACK (coordinator add-on)

`dispatch_push_query` (quv.rs): the "already has durable work in flight" drop
branch now drops the context lock and sends
`SwarmCommand::CompleteQuvPush { requester, nonce }` like the neighbouring
membership and quota refusal branches, so the transport's deferred ACK is
released for the dropped request. Not unit-asserted (see nonclaims).

## Commands and counts (after restore)

```
cargo test -p ioi-validator --features consensus-aft --lib standard::orchestration::quv::
  -> 30 passed; 0 failed   (quv-suite-after-restore.txt)
cargo test -p ioi-validator --features consensus-aft --lib standard::orchestration::grpc_public::
  -> 19 passed; 0 failed   (grpc-public-suite.txt)
cargo check --locked -p ioi-cli --tests --features consensus-aft,vm-wasm,state-iavl
  -> Finished, exit 0      (ioi-cli-check.txt)
```

The first attempt at the ioi-cli check failed with three errors inside
`crates/cli/tests/aft_e2e.rs` (lifetime / moved-value errors, a file dirty
from another agent's concurrent work, none referencing the validator API
changed here); the immediate retry with no change to this slice's files
passed. The retry is the recorded result.

## Nonclaims

- This is a bound on queued waiters per principal, not wall-clock fairness,
  worst-case service, rate control, or any ordering guarantee between
  principals; FIFO among admitted waiters is unchanged.
- `WAITING_PER_PRINCIPAL` lives in `admission.rs`; it is not part of
  `QuvConsequenceAdmissionProfileV0::ROOTED_FIELDS` (types crate, not owned by
  this slice) and therefore not committed to policy-root v7.
- The principal key at `receipt_access` is the candidate's claimed authorizer;
  a forged authorizer can spend a different principal's queue slot until the
  request's own candidate validation refuses it. Ownership/authority is never
  granted by the key.
- The historical lane keeps `WAITING_HISTORICAL = 1` total; the principal
  keying adds that a principal already queued in a domain lane cannot also
  take that one slot (and vice versa). It does not add capacity.
- The delayed-timer test cannot hit the exact `elapsed == decision_interval`
  boundary: `QuvOnlineOperationV0::observe_reply_at`/`started` are private to
  the consensus crate. The equal-boundary case is covered there
  (`reply_observed_after_deadline_cannot_authorize_or_pass_audit` and
  neighbours in `crates/consensus/src/aft/query_unanimity.rs`), not here.
- The test drives the production decision path on a real table entry but not
  the spawned timer task itself, nor the rooted validators (fixture verifiers
  accept every candidate/signature) nor the accepted-history store write.
- Finding 010's other remediation items (claimable-phase reservation before
  QUV, rejecting terminal receipts before the full-deadline wait, qualifying
  terminal replay against a concurrent singleton) are untouched.
- The `CompleteQuvPush` addition in the in-flight drop branch is compile- and
  symmetry-verified only: no orchestration test constructs a
  `MainLoopContext`, so the branch is not unit-observable in this crate.


## Join-time principal share (2026-09-07)

The clean R2 attempt on `b4fb23106` refused the consecutive-readiness
fixture's unrelated same-principal effect with `QUV principal already has a
waiting foreground request` while the principal's child slot was waiting out
its readiness delay. The per-principal share is now acquired in
`QuvWaitingForegroundV0::enter` (the active-queue join) instead of
`reserve_foreground`; a readiness-waiting reservation holds only its domain
permit. `per_principal_waiting_bound_refuses_second_queued_request_and_releases_on_cancel`
now asserts that a second reservation succeeds, the join is refused with the
typed error, and the domain permit is released on that refusal. Runtime suite
30/30 on the repaired source.
