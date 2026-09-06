# M17Q R2 — Agentgres consequence store: stable-key claim guard, claim-time clock, substituted-receipt and fenced-Authorized tests (2026-09-06)

Scope: one repair slice inside `crates/agentgres/src/consequence*` only.
Base commit at hand-back: `24a9888e3` (dirty worktree; `consequence.rs`,
`consequence/tests.rs` and `crates/types/src/app/consequence.rs` already carried
uncommitted edits from other in-progress work when this slice started, so
`git diff HEAD` on those files is not exclusively this slice). No validator,
consensus, networking, cli or `docs/architecture` file was touched.
`crates/types/src/app/consequence.rs` was NOT edited by this slice (no new type
or error variant was needed there; `ConsequenceError` lives in agentgres).

This README records what was built and measured. It does not claim to close
any review finding; each item below names the residual it leaves.

## Files changed by this slice

| File | Change |
| --- | --- |
| `crates/agentgres/src/consequence.rs` | claim guard wiring, clock injection, error variants, crash point, doc comments |
| `crates/agentgres/src/consequence/claim_index.rs` | NEW: durable per-store claim index (record, validate, reserve, commit) |
| `crates/agentgres/src/consequence/resource_reservation.rs` | `prepare_charged` / `commit_charged` (size-parameterised); existing `prepare`/`commit` are unchanged wrappers at the PQ record charge |
| `crates/agentgres/src/consequence/tests.rs` | 7 new tests + helpers (appended; no existing test modified) |

SHA-256 at hand-back: see `sha256.txt` in this directory.

## A. Stable-key claim guard (finding 001 residual: distinct `resource_id`, one QUV slot)

Mechanism (`consequence.rs`):

- `claims/<sha256-hex(query_unanimity_idempotency_key)>.claim` per store, only
  for `OnlineQueryUnanimityV0` manifests (`claim_index::key_for` returns
  `None` for `Portable`). Record = canonical JCS
  `{schema, idempotency_key, effect_id, manifest_root, record_root}` with a
  domain-separated self hash; fixed reservation `MAX_BYTES = 4096`.
- Reservation (before QUV, allocation-free thereafter): `prepare_online_storage`
  (reached from `prepare_online_effect_checked`) proves the encoded record fits
  and stages `.<name>.claim.prepared` through
  `resource_reservation::prepare_charged` (fallocate + full space padding +
  fsync + ancestry sync), exactly like the endpoint record. Post-QUV
  `prepare_online_effect` only *reads* the index.
- Durable claim: `install_claim` inside `execute_after_online_authorization`,
  immediately before the `Claimed` persist (new crash point
  `AfterClaimIndexed` sits between them); reserved profile publishes by
  in-place overwrite of the initialized staging + fsync + rename + dirsync
  (`commit_charged`), adapters outside the reserved profile use the same
  write/fsync/rename path their receipts already use. `install_claim` is
  re-proved again at `Claimed -> InFlight` on retries.
- Refusal rule (`claim_guard`, read-only): existing claim naming a different
  `effect_id` → `ConsequenceError::ConflictSlotAlreadyClaimed { effect_id,
  claimed_by }`; same `effect_id` but different `manifest_root` →
  `ReplayConflict`; same effect and manifest → proceed (crash retry). The
  guard runs in `authorize_inner` (so `authorize`, `prepare_online_effect`,
  `inspect_online_effect`, `prepare_online_effect_checked` all refuse before
  any per-effect state is created) and at the top of
  `execute_with_online_authorization` before `consume()` so a refused effect
  neither consumes its continuation nor installs an audit (zero mutation).
- Recovery: `open` creates and syncs `claims/` and never deletes an entry. A
  claim whose effect has no receipt or a still-`Authorized` receipt is the
  crash window "claim written, Claimed not persisted" and stays owned by that
  effect. Entries are validated when consulted (`claim_index::read`): absent
  directory entry is the only absent state; symlink (`ELOOP` under
  `O_NOFOLLOW`), hard link (`nlink != 1`), non-regular, oversize,
  non-canonical, wrong schema/key, or hash mismatch → `CorruptClaimIndex`
  (reuses `resource_reservation::private_open`).

New error variants (agentgres `ConsequenceError`): `ConflictSlotAlreadyClaimed
{ effect_id, claimed_by }`, `CorruptClaimIndex`. New crash point:
`ConsequenceCrashPoint::AfterClaimIndexed`.

Tests:

1. `stable_key_claim_guard_refuses_second_effect_for_same_conflict_slot_before_invocation`
   — real `DurablePqAtomicRegisterV1`, two manifests same domain/slot 7,
   `resource://test/a` vs `/b`; both admitted and reserved pre-QUV; first
   → `Executed`; second → `ConflictSlotAlreadyClaimed{effect_id:"slot-claim-b",
   claimed_by:"slot-claim-a"}`, register invocations stay 1, one record file,
   second receipt bytes unchanged and still `Authorized`; inspect / checked
   prepare / plain prepare of the loser all refuse; winner readmission fine.
2. `claim_index_crash_before_claimed_persist_binds_slot_to_that_effect_across_reopen`
   — crash at `AfterClaimIndexed`; receipt `Authorized`, claim names A;
   reopen; B refused on execute and inspect (0 invocations, bytes unchanged);
   A retries with a fresh continuation → `Executed`; reopen again, B still
   refused.
3. `corrupt_or_aliased_claim_index_refuses_execution_without_mutation`
   — symlink, hard link, garbage, oversize, wrong-key claim files →
   `CorruptClaimIndex` on execute and inspect, 0 invocations, receipt bytes and
   the planted entry/fixture untouched; removing the plant restores execution.
4. `portable_manifests_do_not_touch_the_claim_index` — two portable manifests
   same slot, distinct resources both execute (unchanged behaviour), `claims/`
   empty.

Removed-rule control: the two refusals inside `claim_guard` were replaced by
`Ok(Some(record))` (guard never refuses), test 1 re-run, then the exact text
restored. Result: test 1 FAILED at `tests.rs:2513` — `called
Result::unwrap_err() on an Ok value: ConsequenceReceiptV1 { ... effect_id:
"slot-claim-b" ... }` i.e. the second effect for the same slot executed.
Excerpt: `control-removed-guard-excerpt.txt`. Restoration verified by
`cmp` against a pre-control copy and identical SHA-256
`9f707883812cbf1d609597bc4a2b4d1cdae928f2b4eb4defa9ec0c05dae2328d`.

Residuals (not closed):

- The rooted storage profile (`QuvConsequenceStorageProfileV0::ROOTED_FIELDS`,
  policy-root v7) does not include the claim-index charge (one 4 KiB active +
  one 4 KiB staging entry per claimed slot, times `FILE_PHYSICAL_FACTOR`).
  Changing rooted fields is outside this slice; the whole-store storage
  envelope (finding 006) must be re-derived by whoever owns the profile.
- The guard is per consequence store (single executor). It does not bind the
  QUV member store or the durable per-domain head (the remaining 001
  remediation in consensus/validator).
- `open` does not scan `claims/`; validation is lazy at consult time.
- A legacy `Claimed` receipt with no claim entry gets one installed on its
  next retry; under the reserved profile that requires the pre-QUV staging
  from `prepare_online_effect_checked` (a direct `execute_*` retry without it
  refuses `ResourceCapacityNotPrepared` and quarantines the store, as receipts
  already do).

## B. Claim-time clock (finding 009)

- `ConsequenceStore.now: fn() -> Instant` (default `Instant::now`),
  `#[cfg(test)] set_clock`. Both reads in the claim transition (before the
  `Claimed` persist and before `InFlight`) use it. Comparison kept as
  `now() > expires_at` (equality accepted), matching the consensus
  `consume()` at `crates/consensus/src/aft/query_unanimity.rs:787/858/1579`.
- Test `continuation_deadline_is_inclusive_and_rechecked_after_claimed_persist`
  (scripted thread-local clock): `[expires, expires]` → `Executed`;
  `[expires, expires+1ms]` → `InvalidOnlineAuthorization`, state `Claimed`,
  0 invocations, then a fresh continuation retry completes;
  `[expires+1ms]` → refused before `Claimed`, no claim entry.
- Residual: the audit is still installed and persisted before the first
  deadline read (unchanged ordering); the consumed token still carries the
  deadline only process-locally.

## C. Substituted receipt file (finding 013)

Test `substituted_receipt_for_unadmitted_manifest_is_refused_before_quv_and_invocation`:
for each phase `Authorized`, `Claimed`, `Executed`, a canonical self-consistent
receipt for M' (same `effect_id`, same PQ resource profile; `conflict_slot` 1
vs 2, different `request_root`/`predecessor_root`) is produced in a scratch
store and written at M's effect path through `atomic_write` +
`receipt_reservation::prepare` (valid AFTCR001 envelope; `load` accepts it).
For M: `inspect_online_effect`, `prepare_online_effect_checked`,
`prepare_online_effect` → `ReplayConflict`; `execute_with_online_authorization`
with a continuation bound to M → `InvalidOnlineAuthorization` for
`Authorized`/`Claimed`, `WrongState(Executed)` for `Executed`
(state check precedes `consume()` by design — see
`nonexecutable_online_retry_preserves_audit_without_consuming_continuation`).
0 register invocations, bytes unchanged, no record under either key.

Residual: `online_retry_result(effect_id, resource)` is manifest-blind by
signature; in the validator flow it is preceded by `prepare_online_effect(M)`
which refuses, but that ordering is the caller's, not the store's. The
validator-side "reconstruct admission on every call" remediation is not in
this slice.

## D. Fenced `Authorized` receipt (finding 008 wording)

Doc comments added on `ConsequenceStateV1::Authorized` and `validate_fence`.
Test `cached_authorized_receipt_beyond_fence_is_refused_on_inspect_prepare_and_execute`:
receipt admitted at height 10; at heights 9, 11, 1000 inspect / checked
prepare / plain prepare / execute all → `FenceExpired`; `recover` leaves it
`Authorized`; bytes unchanged; 0 invocations; no claim entry. The existing
`online_effect_rechecks_height_fence_after_live_quv` was left untouched.
Residual: the validator entry points' existence fast path is unchanged.

## E. Commands and counts

```
cargo fmt -p agentgres                                   # clean (--check passes)
cargo test -p agentgres consequence::tests               # 41 passed; 0 failed (34 pre-existing + 7 new)
cargo check -p ioi-validator --features consensus-aft    # Finished, no errors (validator-check.log)
```

Test names and result line: `final-suite-names.txt`. Warning noise in the
build log is pre-existing (`ioi-types` snake-case fields,
`agentgres/src/event_stream.rs:229` unused doc comment) and not from this slice.
