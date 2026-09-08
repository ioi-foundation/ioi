# M17Q R2 — consensus-crate identity/custody regressions (QUV-M17Q-001, QUV-M17Q-002 slices)

Date: 2026-09-06. Worktree: `/home/heathledger/Documents/ioi/repos/ioi`, HEAD `24a9888e3`, dirty
with a large uncommitted in-progress AFT QUV remediation from other agents. This directory records
one repair slice in `crates/consensus/src/aft/query_unanimity.rs` and
`crates/consensus/src/aft/query_unanimity/{head.rs,journal/tests.rs}` only. No finding is
described as closed here; the R1 review remains the ledger of record
(`../m17q-r1-import-2026-09-04/review-output/M17Q-quv-independent-review-daybreak-2026-09-04.md`).

## What changed (source)

No production code path changed. All edits are `#[cfg(test)]` test additions plus one pre-existing
test extension:

- `crates/consensus/src/aft/query_unanimity.rs` (tests module)
  - `unauthenticated_one_generation_ahead_handoff_cannot_mint_activation_gate` (line 5091) —
    exact R1 002 handoff trace, mirroring the retained
    `repro_unauthenticated_one_generation_ahead_handoff_mints_activation_gate` construction
    (`../m17q-r1-import-2026-09-04/review-output/core-four-reproductions.patch`), built from
    `handoff_install_fixture()`. Genuine generation-0 store + authenticated anchor; ordinary
    generation-1 state with `previous_head` = protected head and `installed = Some(<structurally
    valid gate>)`, tag zeroed and, separately, tag copied from generation 0. Asserts `open` →
    `CorruptStore`, anchor bytes unchanged (still generation 0), state bytes unchanged; no store
    value exists so `permits_exact_activation` is unreachable. Control inside the test: the identical
    contents under the custody-key tag pass `validate_handoff_store`, recover as the genuine
    one-generation crash window, and only then satisfy `permits_exact_activation`.
  - `installed_handoff_fixture` (helper, line 5178) — one genuine schema-3 install through
    `prepare_install_capacity` + live grant + `install`.
  - `authenticated_handoff_state_and_anchor_cover_every_byte` (line 5224) — applies the existing
    every-byte helpers `assert_state_corruption_is_rejected` (non-directory branch) to the installed
    schema-3 handoff state file under both the generation-1 anchor and the generation-0
    pending-transition anchor, then `assert_anchor_corruption_is_rejected` to the anchor. Between
    passes the authentic bytes recover and the pending anchor advances to byte-identical anchor bytes.
  - `handoff_installed_fields_cannot_change_under_a_retained_tag` (line 5253) — 15 per-field
    substitutions of `InstalledQuvHandoffV0` (`local_successor` to another genuine successor member,
    `successor_configuration_root`, `candidate_hash`, `payload_hash`, and `handoff.{network_id,
    old_configuration_root, successor_set, activation_height, old_authority_expiry_height,
    predecessor_candidate_hash, state_height, state_block_hash, state_root, boundary_qc.view,
    boundary_qc.signatures}`) with the original tag retained → `CorruptStore` under both anchors,
    state and anchor bytes unchanged.
  - `handoff_member_refuses_candidate_with_unexpected_predecessor` (line 5379) — see item 5 below.
  - `predecessor_substitution_shares_one_conflict_slot` (line 4478) EXTENDED at line 4519: after the
    shared slot holds two candidates (saturated), a third candidate with a substituted predecessor
    must still be refused with `UnexpectedHead` and no reply, bytes unchanged. Reason: control B
    finding below.
- `crates/consensus/src/aft/query_unanimity/journal/tests.rs`
  - `initial_record_head_and_scope` (helper, line 732).
  - `valid_mac_record_with_foreign_scope_is_refused_before_replay` (line 744) — generation-1 record
    with a valid custody-key MAC sealed under a different scope (other provisioning root; same root
    with different limits) → `ProvisioningMismatch`, zero replay calls, snapshot unchanged, anchor
    still generation 0 at the initial head. Control: the same payload under the provisioned scope
    recovers and is replayed once.
  - `valid_mac_record_with_mismatched_generation_field_is_refused` (line 802) — internal generation
    `0`, `2`, `u64::MAX` at filename generation 1 → `CorruptStore`, replay callback never invoked,
    anchor unchanged.
  - `fully_valid_record_at_scratch_name_is_deleted_not_replayed` (line 838) — a fully valid next
    record at `00000000000000000001.quv.tmp` is removed on recovery, never replayed, anchor and head
    unchanged; the next append reuses generation 1 with its own payload, and reopen replays only that.
- `crates/consensus/src/aft/query_unanimity/head.rs` — unchanged (hash identical before/after).

## Commands and counts

```sh
# baseline (before this slice's edits; tail retained in baseline-test-run-tail.txt)
cargo test -p ioi-consensus --features aft --lib aft::query_unanimity
#   test result: ok. 85 passed; 0 failed; 1 ignored; 230 filtered out; 226.83s

# final (after edits + cargo fmt; grep-filtered transcript in final-test-run.txt)
cargo test -p ioi-consensus --features aft --lib aft::query_unanimity
#   test result: ok. 92 passed; 0 failed; 1 ignored; 230 filtered out; 183.93s
#   (85 + 7 new tests; the extended test is counted once)

cargo fmt -p ioi-consensus
cargo check -p ioi-validator --features consensus-aft
#   Finished `dev` profile; 0 error lines (pre-existing unused-import warnings only)
```

One intermediate full run (pre-fmt) reported 91 passed / 1 failed:
`journal_replay_tests::typed_journal_replay_matches_live_member_across_three_slots_and_reopens`
panicked with `ExpiredAuthorization` at `member_delta_tests.rs:93` while the baseline run, this run
and other agents' builds shared the box. It passed in the baseline run, passed in isolation
(`1 passed; 7.92s`), and passed in the final full run. Recorded as a load-induced wall-clock
continuation-deadline flake in a pre-existing test, not investigated further (nonclaim below).

## Removed-rule controls (`controls/`)

Exact mutant text: `controls/MUTATIONS.md`. Each control: apply with Edit, run the named test,
restore the exact original text with Edit, compare `sha256sum` before/after.

| Control | Mutation | Named test | Result | Restore |
|---|---|---|---|---|
| A | re-add `predecessor` to `QuvConflictSlotV0` + `From<&QuvSlotV0>` | `predecessor_substitution_shares_one_conflict_slot` | **FAILED** at line 4503 `assert_eq!(QuvConflictSlotV0::from(&x.slot), QuvConflictSlotV0::from(&y.slot))` (`controls/controlA-output.txt`) | `d3feb1b3…27d98` before = after (`controlA-restored.sha`) |
| B (first attempt) | remove `self.check_expected_slot(&request.candidate.slot)?` from `process_push_with_byte_limit` | `predecessor_substitution_shares_one_conflict_slot` (pre-existing body) | **PASSED — finding, see below** (`controls/controlB-output.txt`); alternate `accepted_history_refuses_conflicting_or_expired_grants_without_mutation` also passed (`controlB-alternate-test-output.txt`; it never touches `process_push`) | `d3feb1b3…27d98` before = after (`controlB-restored-first-attempt.sha`) |
| B (second attempt) | same mutant | `predecessor_substitution_shares_one_conflict_slot` (extended at line 4519) | **FAILED** at line 4527, the saturated-slot assertion (`controls/controlB-output-second-attempt.txt`) | `2105812f…3d22` before (`controlB-baseline-after-test-extension.sha`) = after (`controlB-restored.sha`) |
| C | remove `\|\| slot.predecessor != self.expected_predecessor(slot.slot)?` from `QuvAcceptedHistoryV0::check_slot` (head.rs) | `accepted_history_derives_scope_and_preserves_historical_predecessors` | **FAILED** at line 4125 `history.check_slot(&changed).is_err()` (`controls/controlC-output.txt`) | `5db76932…7a16` before = after (`controlC-restored.sha`) |

### Control B finding (reported, not hidden)

With `check_expected_slot` deleted from `process_push_with_byte_limit`, the pre-existing test still
passed because a second enforcement point exists: `prepare_member_delta` in
`crates/consensus/src/aft/query_unanimity/member_delta.rs` (lines 109-114) re-runs
`domain.check_slot(&candidate.slot)` for every `InsertCandidate` before the journal append, and the
test only exercised the insertion path. The mutant is nevertheless **not** behaviour-equivalent:
when a conflict slot is already saturated (`STORE_MAX_CANDIDATES_PER_SLOT = 2`) or the candidate is
already present, `process_push_with_byte_limit` skips `persist_delta` and signs a reply over the
retained snapshot; without the `process_push`-level check a substituted-predecessor candidate would
obtain a signed reply on that path. The named test was extended to cover exactly that path
(line 4519 onward); under the same mutant it now fails at line 4527, and it passes on intact source.
The first-attempt transcripts are retained unchanged. Consequence for the estate: the
`process_push` check is load-bearing only for the no-insertion reply path; the insertion path is
doubly enforced. This is a coverage gap in the R2 regression set that was found by the control,
not a production defect.

## Item 5 — HandoffBoundary member-side predecessor (no code change)

Question: can a member be pushed a handoff candidate whose predecessor differs from the locally
derivable `quv_handoff_initial_predecessor(...)`?

Answer for the production member path: **no**; the push is refused before the member store is
reached. Enforcement points (line numbers as of this worktree state, read-only files):

1. `crates/validator/src/standard/orchestration/quv.rs:1651-1655` (`process_push`): for a
   `HandoffBoundary` policy the pushed `query.candidate` must equal
   `context.aft_quv_handoff_envelope.candidate`, the locally provisioned source envelope
   (installed only from the configured `aft_quv_handoff_source` file after
   `validate_handoff_source`, `quv.rs:477-516`; on restart from `lifecycle.rs:913`).
2. `quv.rs:1708-1716` re-runs `validate_handoff_source` for the live request, which calls
   `validate_quv_handoff_candidate` (`quv.rs:393`) → `crates/consensus/src/aft/query_unanimity.rs:188-212`
   (`candidate.slot.predecessor != handoff.predecessor_candidate_hash` refused at line 206) and
   `validate_quv_handoff_payload` (lines 132-186; `handoff.predecessor_candidate_hash !=
   quv_handoff_initial_predecessor(network, old_root, activation_height, state_height,
   state_block_hash, state_root)` refused at line 159).
3. `quv.rs:1717-1735`: `require_exact_handoff_boundary` (`quv.rs:428-449`) matches the envelope's
   `state_height`/`state_block_hash`/`state_root` to this member's own executed block, and the
   verified QC to that state. Together with (2) this pins the predecessor to the value derivable from
   the member's local executed boundary, not to a value nominated by the source.
4. Only then `store.process_push` (`quv.rs:1755`) → `DurableQuvMemberV0::process_push_with_byte_limit`
   → `check_expected_slot` → `QuvMemberDomainV0::check_slot` (`head.rs:299-312`), which for
   `HandoffBoundary` requires only a nonzero predecessor.

Why the domain itself cannot compare equality: the exact handoff predecessor is a commitment to the
final old-root state (`state_block_hash`, `state_root` at `activation_height - 1`), which does not
exist when the domain is enrolled from configuration. Storing it in the provisioned bootstrap
witness would require the boundary block before provisioning; the estate instead derives it at push
time from local executed history (points 2-3). No consensus-crate code change was made.

Test added: `handoff_member_refuses_candidate_with_unexpected_predecessor` proves the consensus-crate
half of that wrapping — `validate_quv_handoff_candidate` refuses a wrong predecessor against the
exact source, against a source that nominates the same wrong value, and refuses the original
candidate against a different executed boundary; `DurableQuvHandoffV0::prepare_install_capacity`
and `install` refuse the wrong predecessor without touching either file — and records as a fact
that the enrolled `HandoffBoundary` domain's `check_slot` accepts any nonzero predecessor and
refuses only the zero placeholder.

## SHA-256 of changed owned files (final, post-`cargo fmt`)

See `SHA256SUMS`:

```
1c0dddb808f1c0088a27cb8eb5f83f0bc7af249e3bd62ead066f7cc98a3d3c8f  crates/consensus/src/aft/query_unanimity.rs
5db7693220aff2d6c16987c94639ed752416be5327e1001b5ab205ade2337a16  crates/consensus/src/aft/query_unanimity/head.rs
0d91c85348ea2687d2a051a64c6d03dfd46ce03533fb122f9b0ebcac5c730f1f  crates/consensus/src/aft/query_unanimity/journal/tests.rs
```

The control-phase hashes of `query_unanimity.rs` (`d3feb1b3…`, `2105812f…`) predate `cargo fmt`;
the only later change to that file is formatting. `git diff --stat` for `query_unanimity.rs`
reflects the whole in-progress remediation of other agents plus this slice, not this slice alone.

## Nonclaims

- Nothing here closes QUV-M17Q-001 or QUV-M17Q-002. The member-state half of 002
  (`repro_unauthenticated_one_generation_ahead_state_erases_conflict`) is covered by pre-existing
  tests (`unauthenticated_crash_window_state_cannot_advance_member_anchor`,
  `authenticated_member_state_covers_every_byte_and_pending_recovery`), not re-verified here.
- The validator-side enforcement in item 5 is cited by line, not tested in this slice: no
  `ioi-validator` test was added (file ownership). The existing validator test around
  `quv.rs:3492-3550` exercises `validate_handoff_source` but not a wrong-predecessor push through
  `process_push`; that remains an open regression for the validator owner.
- The executor/T10 half of 001 (Agentgres binding, entry points) is outside this slice.
- The every-byte handoff coverage is over one fixture state (one install, two successor members,
  32-byte state root); it is not a proof over all encodings.
- The intermediate `ExpiredAuthorization` flake was attributed to load, not root-caused.
- Timing figures are from a shared, heavily loaded box and qualify nothing.
