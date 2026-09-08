# M17Q r2 — PQ carrier squatting, silent-recipient outbox, stale-record ACK (findings 007 / 011 / 012)

Repair slice against HEAD `24a9888e3` on a dirty worktree (large in-progress
AFT QUV remediation by other agents; `git diff --stat` numbers below are
cumulative for the dirty tree, not this slice alone). Date: 2026-09-06.

This slice implements the NETWORKING half plus the validator's
`PqEnrollmentLost` answer. Nothing here is claimed to close a finding as a
whole; each finding also names process-level / sole-correct-member
qualification that this slice does not perform (see "Open").

Source of the findings:
`internal-docs/architecture/protocols/aft/evidence/m17q-r1-import-2026-09-04/review-output/M17Q-quv-independent-review-daybreak-2026-09-04.md`
(QUV-M17Q-007 lines 531-597, -011 lines 722-761, -012 lines 763-804) and the
retained `carrier-squat-reproduction.patch` in the same directory.

## Files changed (owned by this slice)

| file | change |
|---|---|
| `crates/networking/src/libp2p/pq_channel.rs` | tests only: 5 new tests + 6 test helpers (no production change; the eviction rules `disconnect` L1310, `authenticate_carrier` L1085 already existed and are now pinned) |
| `crates/networking/src/libp2p/swarm.rs` | deferred push ACK (`PendingQuvPushAcks`, `PqRecordAdmission`, `complete_quv_push`, hold expiry on the retry tick, clear on reconfiguration); `recover_pq_peer_after_failure` + `pq_enrollment_lost_report` replacing the four blind `disconnect`+`start_pq_handshake` sites; `release_nacked_pq_record` (sender side of NACK); 8 new tests incl. two live multi-swarm tests |
| `crates/networking/src/libp2p/types.rs` | `NetworkEvent::PqEnrollmentLost { peer }`, `SwarmInternalEvent::PqEnrollmentLost(PeerId)` |
| `crates/networking/src/libp2p/mod.rs` | forwarder mapping for the new event |
| `crates/validator/src/standard/orchestration/events.rs` | `NetworkEvent::PqEnrollmentLost` → `peer_management::handle_pq_enrollment_lost` |
| `crates/validator/src/standard/orchestration/peer_management.rs` | `handle_pq_enrollment_lost`: for a known (connected) peer, `SendStatusRequest(peer)`; re-enrollment then flows only through the existing status path (`sync.rs` status handler), never from a retained claim |
| `crates/validator/src/standard/orchestration/sync.rs` | NOT changed by this slice (its dirty diff pre-dates this slice) |
| `crates/validator/src/standard/orchestration/quv.rs` | NOT changed (read only, see §6) |
| `crates/networking/src/libp2p/sync.rs` | NOT changed (outside ownership) — required `PqChannelNack` variant handed over as `required-networking-sync-nack-patch.diff` |

Events/commands added: `NetworkEvent::PqEnrollmentLost`,
`SwarmInternalEvent::PqEnrollmentLost`. No new `SwarmCommand`; the deferred
ACK is keyed on the existing `CompleteQuvPush { requester, nonce }`.
Pending (diff only): `SyncResponse::PqChannelNack`.

## 1. (007) Squatter tests — pq_channel.rs

Rules pinned (all pre-existing in production code):
- `disconnect` (pq_channel.rs L1310) erases enrollment, capability and
  provisional stamp for a peer that never authenticated;
- `authenticate_carrier` (L1085) evicts every other carrier enrolled for the
  proven account, including their pending KEM state;
- `peer_for_account` routes only to an application-ready session.

New tests:
- `unproven_squatter_disconnect_releases_account_for_genuine_carrier` — (a)
  squatter claims C, holds pending initiator state, is never routable;
  `disconnect` leaves nothing (`assert_peer_fully_forgotten`);
  `peer_for_account(C) == None`; genuine handshake → `Some(genuine)`.
- `handoff_only_unproven_claim_cannot_squat_or_route` — (b) via
  `enroll_handoff_peer`: unproven staged-successor claim is not drainable
  (`pending_peers` empty, `seal` refused); after disconnect the genuine
  handoff-only successor takes the account, keeps the handoff-only capability
  boundary (PUSHQUERY in, no consensus), and later unproven claims are refused.
- `genuine_proof_evicts_squatter_pending_handshake_state` — (c) one squatter
  with pending initiator state and one stale carrier of the same key with
  pending responder state (valid client hello accepted); the genuine proof
  leaves both fully forgotten, `provisional_enrollments` empty, routing to the
  genuine peer, and late `complete`/`finish` for the evicted carriers refused.
- Swarm level (d), `live_squatter_enrollment_never_authenticates_and_genuine_carrier_routes`
  (swarm.rs): two real TCP swarms running `run_swarm_loop`, both
  `ConfigurePqChannels`; `EnrollPqPeer` for a squatter PeerId claiming the
  genuine account, then for the genuine carrier; `PqCarrierAuthenticated` is
  observed only for the genuine peer (the helper panics on any other), and a
  `QueueQuvPushQuery` for that account arrives at the genuine member's QUV lane.

## 2. (007) Retry after handshake failure

Before: the `OutboundFailure` arm (and the server-hello-refused, ack-refused,
ack-persist-failed arms) called `manager.disconnect` then blindly
`start_pq_handshake`, which cannot succeed once `disconnect` erased a
provisional enrollment (`start` → `enrollment()` → "no rooted PQ channel
enrollment"); recovery then depended on a redial.

Now (`recover_pq_peer_after_failure`, swarm.rs L326): after `disconnect`, a
still-enrolled peer (authenticated, or provisional and live) retries exactly
as before. An erased provisional enrollment is reported as
`SwarmInternalEvent::PqEnrollmentLost(peer)` when the peer is still
connected (disconnected peers are re-derived by the reconnect status path).
The validator answers with `SendStatusRequest(peer)`; the status response
re-enrolls through the unchanged status handler.

Bounds: reports are capped at `PQ_ENROLLMENT_LOST_REPORTS_PER_CONNECTION = 4`
per connection (`pq_enrollment_lost_report`, L152; counter cleared on
ConnectionClosed, on authentication, and on reconfiguration). Every
re-enrollment still passes `enroll_peer_with_capability` (L770): 30 s
provisional lifetime, 4 provisional carriers per account, 4096 global — none
weakened.

Tests: `enrollment_loss_reports_are_bounded_per_connection_and_skip_disconnected_peers`,
`recovery_keeps_authenticated_enrollment_and_erases_provisional_claims`, and
the live test
`live_outbound_failure_on_unproven_enrollment_reports_loss_and_status_reenrollment_recovers`:
a verifier swarm dials an unconfigured "impostor" swarm (refuses every client
hello → dropped stream → `OutboundFailure::Io` at the initiator), enrolls it
as the genuine account, observes `PqEnrollmentLost(impostor)`; replays the
status-driven re-enrollment 5 times and observes exactly 4 reports (the 5th
attempt emits nothing within 2 s); then dials the genuine carrier, enrolls
it, and observes `PqCarrierAuthenticated(genuine, account)`; any
authentication event for the impostor panics.

## 3. (011) Silent recipient tests — pq_channel.rs

- `silent_recipient_never_accumulates_more_than_one_live_push_across_operations`
  — 24 operations against a never-ACKing recipient, in the validator's order
  (`retire_stale_quv_pushes(nonce_k)` = BeginQuvOperation, then
  `enqueue_for_account`); restart (drop + reopen from disk) at k = 12; after
  every operation exactly one live QUV record for the recipient, QUV bytes ≤
  `QUV_OUTBOX_RESERVED_BYTES_PER_RECIPIENT_V0`, no enqueue error, an
  unrelated never-ACKed normal record survives, outbox stays usable.
- `connected_silent_recipient_cannot_make_push_enqueue_fail` — same across
  20 operations over an established session where each front record is
  sealed (sent) and opened by the member but never acknowledged; then
  `retire_quv_operation(last)` (CompleteQuvOperation) leaves no QUV record
  and a reopen from disk confirms it (the "retired record gone after
  reopen" test; `completed_quv_operation_retires_unacknowledged_requests_durably`
  already pinned the same for the non-session case).

## 4. (011) Residual: can a persistence-healthy silent recipient still make the verifier abort?

Verifier side (quv.rs, read only; line numbers as of this tree):
`BeginQuvOperation` L2519 → per-recipient `QueueQuvPushQuery` loop L2588-2633
aborting on `Err` (L2601, L2615, L2620, L2627) → local self-delivery only
afterwards (L2635).

Networking side, path of one push enqueue for recipient R
(`queue_pq_consensus_for_account` → `enqueue_for_account` L1189 →
`enqueue_with_retired` L485 → `commit` → `commit_with` L396):

1. `require_usable` L377 — errors only after a prior persist failure
   (`persistence_failed`), i.e. a quarantined outbox.
2. rooted-scope / local-account checks — configuration, not recipient
   behaviour.
3. `message_id` size checks — bounded by the wire shapes
   (`bounded_quv_wire_shapes_fit_reserved_frame_budget`).
4. duplicate `message_id` → `Ok` (idempotent).
5. capacity: `total_for_recipient >= 1026`. QUV records per recipient are at
   most one push (BeginQuvOperation retired every push with another nonce,
   `retire_quv_pushes_except` L646, for ALL recipients) plus at most one
   reply (supersession in `enqueue_with_retired`), and normal records are
   capped at 1024 independently. So the QUV push never trips the count.
6. `validate_outbox_byte_profile` in `commit_with`: the "lane already
   occupied" error (`OutboxByteUsage::observe` L53) needs two pushes for one
   recipient, impossible after (5); bytes are ≤ 2 × 16 KiB = the reserved
   budget by construction.
7. `persist` — an I/O error or a `NormalCapacityRefusal` (normal lane only).
   An I/O error sets `persistence_failed` and is the only remaining source.

Conclusion: with a healthy outbox, silence (never ACKing, holding the
transport stream, opening records and never replying) cannot produce an
`enqueue` error; the only reachable cause of the verifier's abort in that
loop is a quarantined / persistence-failed outbox (or the `BeginQuvOperation`
retire failing for the same reason, which drops the oneshot and aborts).
That abort is the correct closed behaviour: a quarantined outbox cannot carry
any recipient. Pinned by `connected_silent_recipient_cannot_make_push_enqueue_fail`
(20 operations, connected-and-silent).

Note on the verifier's loop order (not changed here, quv.rs owner): it still
aborts before local self-delivery on a quarantined outbox; that is
persistence failure, not Byzantine silence.

## 5. (012) Receiver-side tests — swarm.rs

- `stale_reply_is_acked_without_holding_the_current_operation_lane` — (a)
  reply N0 while `active_quv_operation = N1` → `Ok(AckNow)`,
  `quv_reply_inflight` empty, not forwarded; the same member's N1 reply IS
  forwarded; (c) duplicate N1 reply → `Ok(AckNow)`, not forwarded twice.
- `current_push_is_refused_without_ack_while_a_stale_push_holds_the_lane`
  — (b) push N0 admitted (`AckAfterDurablePush`), push N1 from the same
  requester → `Err` (no ACK, nothing forwarded, lane still N0); after
  `complete_quv_push(N0)` (= `CompleteQuvPush`) N1 is admitted and forwarded.

## 6. (012) Push ACK after durable processing

Design landed (networking half): `deliver_pq_record` (swarm.rs L451) now
returns `PqRecordAdmission`. A forwarded QUV PUSHQUERY (and a retried
duplicate of a push still in the lane) returns `AckAfterDurablePush {
requester, nonce }`; the loop stores the `ResponseChannel` in
`PendingQuvPushAcks` (L53) keyed by `(requester, nonce)` instead of sending
`PqChannelAck` (L1202). `CompleteQuvPush { requester, nonce }` (L689) calls
`complete_quv_push` (L113): releases the lane and sends the withheld ACK.
Holds lapse after `quv_push_ack_hold_lifetime()` (L39; mirrors the sender's
request timeout `IOI_AFT_REQUEST_TIMEOUT_SECS`, floor 10 s, default 60 s)
on the retry tick (L923): the channel is dropped, the requester sees a failed
request and keeps its durable record. All holds are cleared on
`ConfigurePqChannels`. Replies and all non-QUV records are still ACKed at
once (unchanged).

Validator check — is a quv.rs change required? No. `CompleteQuvPush` is
already sent at every terminal point of a push the swarm forwarded:
- quv.rs L1842 — requester outside admitted old/handoff membership (closed
  refusal; the ACK correctly lets the requester delete a record this member
  will never answer);
- quv.rs L1881 — after `handle_push_query` returns, i.e. after
  `store.process_push` ran in `spawn_blocking` (durable member work);
- quv.rs L1909 — same, other branch;
- lifecycle.rs L533 — admission-overflow drop.

So no `required-validator-quv-patch.diff` is emitted. One residual for the
quv.rs owner (recommendation, NOT required for this design): the branch at
quv.rs L1889-1897 ("already has durable work in flight") returns without
`CompleteQuvPush`; it is reachable only when the swarm lane was cleared
underneath in-flight work (reconfiguration), and it already left the swarm
lane stuck before this slice. With deferred ACKs it additionally holds the
ACK until the hold lapses (requester retries; nothing is lost). Sending
`CompleteQuvPush` there would ACK a push that was dropped, so the right fix
is on the validator side (do not drop; queue or refuse closed), which is out
of this slice.

NACK: `SyncResponse::PqChannelNack` needs a variant in
`crates/networking/src/libp2p/sync.rs` (outside ownership). The complete,
verified patch is `required-networking-sync-nack-patch.diff` (sync.rs
variant + swarm.rs: send NACK on the refusal path, and on receipt call
`release_nacked_pq_record` so the durable record is kept and resent on a
later tick without the current session teardown). `nack-patch-verification.txt`
shows it applied, `cargo check -p ioi-networking --tests` clean, the three
NACK-sensitive tests passing, both files restored byte-exact (sha256), and
`git apply --check` OK on the restored tree. Until it lands, a refusal drops
the channel: the requester gets `OutboundFailure::Io` immediately (libp2p
request-response 0.26.3 `ResponseOmission`), keeps its record, and today
also tears its PQ session down and re-handshakes (pre-existing behaviour,
unchanged).

Tests: `push_ack_is_withheld_until_durable_completion` (no ACK after
forward; duplicate replaces the held channel and is not re-forwarded; a
60 s-fresh hold survives the tick; `CompleteQuvPush` releases exactly the
latest channel and the lane; a lapsed hold is dropped without ACK),
`nack_keeps_the_senders_durable_record` (NACK for another request leaves the
attempt in flight; matching NACK ends only the attempt, `pending_front`
still returns the record), and the two existing/extended admission tests.

## 7. Commands and results

```
cargo check  -p ioi-networking --tests                              # clean, 0 networking warnings
cargo test   -p ioi-networking --lib -- pq_channel swarm::tests     # 52 passed, 0 failed  (test-run-networking-final.txt)
   includes: cargo test -p ioi-networking --lib pq_channel                                   (40 tests)
             cargo test -p ioi-networking --lib protected_payload_routes_only_after_aead_and_type_agreement
cargo check  -p ioi-validator --features consensus-aft              # Finished, no errors
cargo fmt    -p ioi-networking                                      # only pq_channel.rs / swarm.rs changed
rustfmt --check crates/validator/.../{peer_management,events}.rs    # clean (cargo fmt -p ioi-validator NOT run: it would reformat other agents' dirty files)
bash scratchpad/mutation_controls.sh                                # mutation-controls.txt
bash scratchpad/nack_patch.sh                                       # nack-patch-verification.txt + required-networking-sync-nack-patch.diff
```

Counts: 52 tests in the two suites (40 `pq_channel` incl. submodules, 12
`swarm::tests`); 13 new tests in this slice (5 pq_channel, 8 swarm, of
which 2 live multi-swarm over 127.0.0.1 TCP, ~25 s wall total).

## Removed-rule controls (`mutation-controls.txt`)

| rule | mutation | named test | under mutation | restored |
|---|---|---|---|---|
| disconnect eviction | `disconnect`: `if !authenticated` → `if !authenticated && false` | `unproven_squatter_disconnect_releases_account_for_genuine_carrier` | FAILED at `assert!(!manager.enrollments.contains_key(peer))` | sha256 equal, `git diff --stat` unchanged |
| deferred push ACK | `deliver_pq_record`: `Some(nonce) if admitted_quv_push` → `… && false` (ACK now) | `push_ack_is_withheld_until_durable_completion` | FAILED at first `assert_eq!` (got `AckNow`) | sha256 equal |
| stale-before-lane | reply branch: `if active_quv_operation != Some(nonce)` → `… && false` | `stale_reply_is_acked_without_holding_the_current_operation_lane` | FAILED at `assert!(reply_lane.is_empty())` | sha256 equal |

All three named tests pass again on the restored tree (same transcript).

## sha256 (final tree)

```
b815941cd64db8ac44d8dbddeb5e9adad6c81bc74752a4246a0d258e843b9bd9  crates/networking/src/libp2p/pq_channel.rs
5a149dfbc39dcfabf8ab6520a3f73552701cd2d676083452f708381d865b7a13  crates/networking/src/libp2p/swarm.rs
33a34967336206e509141720ed784861c32a2556f143bfbda704406a5b865b39  crates/networking/src/libp2p/types.rs
9f14936240b688b1c1d3782daecbd930a72e06616f30b8748e0015abebaba984  crates/networking/src/libp2p/mod.rs
01f041d51401a5f47ebb026005d4f465882ac532edbaf27332a7bed28c86b2fb  crates/validator/src/standard/orchestration/events.rs
a0efe46474ea69fe3af6449c6f63878ae6fa3f89f28155997984cae15315b72b  crates/validator/src/standard/orchestration/peer_management.rs
a8df1f1885ba917dec44558e66f397d4b271d2a15661fc7315fa1ea51a7d6168  crates/networking/src/libp2p/sync.rs   (untouched, for the diff's baseline)
0a5f1ae63fc09748c7f85cee35af3790543812e5e568a7727c7a754dc2e119c1  required-networking-sync-nack-patch.diff
```

## Open (not done here)

- Process-level qualification: none of this is exercised in a multi-process
  AFT cluster with real crash windows (member crash between mpsc forward and
  `process_push`; verifier crash mid-campaign). The findings' "sole-correct
  process regression" (007) and "saturation, abort, restart, later correct
  singleton progress" (011) remain open at process level.
- `SyncResponse::PqChannelNack` must be landed by the `sync.rs` owner from
  the diff; until then refusals cost the requester a session teardown.
- Deferred ACK adds head-of-line delay for the single in-flight record per
  peer: other protected traffic to that member waits for its durable push
  processing (bounded by the hold lifetime). Not measured here.
- `quv_push_ack_hold_lifetime()` duplicates the env parsing of the private
  `transport::aft_request_timeout`; a shared helper needs `transport.rs`.
- Validator: the "already has durable work in flight" drop (quv.rs L1889)
  leaves the swarm lane and now the held ACK to lapse; owner decision.
- The `PqEnrollmentLost` answer is a status re-request only; it is not a
  proof step and adds no authority — routing still requires the strict-PQ
  handshake to prove the rooted ML-DSA key.

## Deferred push ACK reverted (2026-09-06)

Section 6 above ("Push ACK after durable processing") is superseded. The
member now acknowledges an admitted QUV `PUSHQUERY` on the transport
immediately after the mpsc forward (`PqRecordAdmission::AckNow`), as it did
before this slice. The head-of-line cost listed under "Open" was not
theoretical.

### Why

Process qualification (c5 campaign, nonce `5240ee38…`, member 21100 →
verifier 21000) showed the withheld ACK serializing a member's QUV *reply*
behind that verifier's own outstanding push on the same single-in-flight
peer lane. Under four-way saturation the reply was sent at 13:01:12.362 and
admitted at 13:01:15.739 — 3.4 s late — and missed the rooted 5 s decision
cutoff. The verifier aborted an operation whose reply was already on the
wire.

The hold bought no safety in exchange. A member that crashes between the
transport ACK and `process_push` is, for that operation, outside the
theorem's timely-correct-member premise: the verifier does not hear from
it, aborts at its deadline and mints no authority from the loss. Withholding
the ACK only moved *when* the requester deletes its durable copy; it did not
change what the verifier can decide.

### Kept

- Requester timing lane `quv_push_inflight`, occupied by exactly one nonce
  per requester and released only by `CompleteQuvPush { requester, nonce }`.
- `SyncResponse::PqChannelNack` for refused records (lane occupied by
  another nonce, nonce-stale, decode/type/capability refusals): the
  requester keeps its durable record without a session teardown.
- Stale-reply-before-lane admission: a reply for a retired operation is
  ACKed and never enters the current operation's per-member slot.
- Duplicate handling: a retried duplicate of the admitted push is ACKed now
  and not forwarded a second time.
- The validator is unchanged: `CompleteQuvPush` is still sent at every
  terminal point (5 send sites in `orchestration/quv.rs` and
  `orchestration/lifecycle.rs`); it now releases only the lane.

### Removed (`swarm.rs`)

- `PqRecordAdmission::AckAfterDurablePush` (the enum keeps only `AckNow`).
- `PendingQuvPushAcks` and its `hold` / `release` / `expire` / `clear`.
- `quv_push_ack_hold_lifetime()` and the hold expiry on the 500 ms retry
  tick (this also closes the "duplicates `transport::aft_request_timeout`
  parsing" item under "Open").
- The held-channel release in the `CompleteQuvPush` handler.
  `complete_quv_push(lane, requester, nonce) -> bool` now returns only
  whether a lane was released.
- Imports that existed only for the hold (`std::time::Instant`,
  `libp2p::request_response::ResponseChannel`).

### Tests

- Removed: `swarm::tests::push_ack_is_withheld_until_durable_completion`
  (it exercised only the hold and its expiry).
- Added: `swarm::tests::admitted_push_is_acked_on_admission_and_completion_releases_lane`
  — first push → `AckNow`, forwarded once, lane held by its nonce; duplicate
  of the same nonce while held → `AckNow`, not forwarded twice; a different
  nonce while held → `Err` (NACK path), nothing forwarded, lane unchanged;
  `complete_quv_push` releases the lane exactly once; the next push is
  admitted and forwarded.
- Adjusted (expectations only where they asserted the withheld ACK):
  `current_push_is_refused_without_ack_while_a_stale_push_holds_the_lane`
  now expects `AckNow` for the admitted stale push and for the later
  current push, and asserts the lane by `push_lane` contents.
- Unchanged and passing: `nack_keeps_the_senders_durable_record`,
  `stale_reply_is_acked_without_holding_the_current_operation_lane`.
- The "deferred push ACK" row of the removed-rule controls table above no
  longer applies; its named test no longer exists.

### Commands and results

```
cargo fmt    -p ioi-networking                                      # swarm.rs only
cargo test   -p ioi-networking --lib -- pq_channel swarm::tests --test-threads=2
                                                                    # 52 passed, 0 failed, 167.6 s; 0 networking warnings
cargo check  -p ioi-validator --features consensus-aft              # Finished, no errors; no validator file edited
```

A first full run at default parallelism under the running process campaign
(load average ~12) failed three timing-sensitive tests
(`delayed_server_hello_cannot_destroy_current_handshake`,
`genuine_proof_evicts_squatter_pending_handshake_state`,
`live_outbound_failure_on_unproven_enrollment_reports_loss_and_status_reenrollment_recovers`)
on timeouts; all three pass in isolation (28.8 s) and in the
`--test-threads=2` run above. None of them touch the push-ACK path.

```
2dfe444348ef81801e9594bf43e0bc52b6d8591c6dbd6a903725ad8c5c8038c8  crates/networking/src/libp2p/swarm.rs
```

### Finding 012 residual, restated

The ACK-before-durable-processing window of finding 012 is now a documented
**liveness-only boundary**, not a safety claim: a member that crashes after
the transport ACK and before `process_push` misses that one operation; the
requester's durable copy is gone, the verifier hears nothing from that
member, aborts by its deadline, and never mints authority from the loss.
No verifier decision can be reached on a push the member did not process.
The next operation begins from a fresh nonce and a fresh durable record.
