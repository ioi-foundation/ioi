# M17Q r2 — process-level evidence for QUV-M17Q-007 (PQ carrier squatting via status identity)

Slice against HEAD `24a9888e3` on a dirty worktree (large in-progress AFT QUV
remediation by other agents; `git diff --stat` numbers are cumulative for the
dirty tree, not this slice). Date: 2026-09-06.

This slice adds ONE process-level qualification case to the M16Q
single-correct campaign. It does not close finding 007; see "Scope" for what
it does and does not exercise.

Finding text: `../m17q-r1-import-2026-09-04/review-output/M17Q-quv-independent-review-daybreak-2026-09-04.md`
§ "QUV-M17Q-007". Networking-half repair notes:
`../m17q-r2-pq-carrier-outbox-2026-09-06/README.md` §1–2.

## Files changed by this slice

| file | change |
|---|---|
| `crates/validator/src/standard/orchestration/sync.rs` | `testing_status_claimed_account_override()` + `parse_testing_status_claimed_account()`; applied in `handle_status_request` to the `validator_account_id` field of `SwarmCommand::SendStatusResponse` only; one unit test `testing_status_claimed_account_override_accepts_only_exact_64_hex` |
| `crates/cli/src/testing/backend.rs` | `ProcessBackend::clear_orchestration_restart_env(key)` — records `(key, None)` so the child is restarted with the key explicitly unset |
| `crates/cli/src/testing/validator.rs` | `Validator::clear_orchestration_restart_env(key)` (ProcessBackend only, like `set_orchestration_restart_env`) |
| `crates/cli/tests/aft_e2e.rs` | `NetworkEventLog` / `parse_network_event` (retains selected `target="network"` diagnostics across restarts); new domain `domain://aft-e2e/m16q/byzantine-status`, manifest `effect-m16q-byzantine-status` (endpoint = position 0's key, discriminator 61), registered in the initial batch (`registered_manifest_count` 19 → 20); new case `byzantine_status_claim` after `expired_result` in `test_aft_quv_m16q_each_single_correct_member_and_conflict_isolation` |
| `.github/scripts/check_aft_m16q_process_evidence.py` | `validate_status_claim` (log rule), `validate_status_claim_components` (component-log rule, run under `--components`), `status_claim_self_test`; `byzantine_status_claim` appended to the required phase order. The script is UNTRACKED in this worktree (another agent's uncommitted file), so there is no git baseline diff; a full copy is under `sources/` |

`sources/` holds byte copies of all five files as run.

## The override: `IOI_TESTING_AFT_STATUS_CLAIMED_ACCOUNT_HEX`

Read in `handle_status_request` (sync.rs) at the point where the response's
`validator_account_id` has been chosen from
`aft_pq_local_account_id → local_validator_account_id → Ed25519-derived`.

- Unset (every production configuration): the block is byte-inert; the genuine
  account is reported exactly as before.
- Set to exactly 64 ASCII hex characters: the response reports THAT account.
  A WARN is logged with `target = "network"`,
  `event = "testing_status_account_override"`, `local_peer`,
  `claimed_account`, `local_account`.
- Set to anything else (empty, 62/66 chars, whitespace, `0x` prefix, non-hex):
  the account hint is withheld (`None`) and a WARN
  `testing_status_account_override_invalid` is logged. This is the
  fail-closed direction: a misconfigured campaign can never pass as an honest
  cluster, because the process then claims NO account rather than falling
  back to its real one.

Guard: the same pattern as `IOI_TESTING_AFT_QUV_HANDOFF_CRASH_AFTER_STATE_MARKER`
in `crates/consensus/src/aft/query_unanimity.rs` — a plain
`std::env::var_os("IOI_TESTING_…")` read whose `IOI_TESTING_` name keeps it
outside every production configuration surface (no config field, no CLI
flag, no feature). It touches nothing but the reported field: the local
ML-DSA identity, `aft_pq_local_account_id`, the enrollment decision in
`handle_status_response`, and `peer_accounts_ref` (populated only by
`PqCarrierAuthenticated`) are unchanged.

## The case (fixture)

Members are sorted by account; `members[i] = (account, process_index, key)`.
In this run position 0 (C) is process 2 (port 20200) and position 1 (B) is
process 3 (port 20300).

1. Print `[M16Q-STATUS-CLAIM-EXPECT] member_position=0 account=<C> claimant_position=1 claimant_process=<B idx> claimant_account=<B> claimant_peer=<B PeerId>`.
2. Kill B's orchestration process, set the override to C's account hex on
   B's restart environment, restart B; `wait_for_height(B, height(C)+1)`.
3. `wait_for` (≤ 90 s) until the retained network events show ≥ 1
   `testing_status_account_override` on B with `claimed_account == C` and
   `local_peer == B's PeerId`, AND ≥ 1 `pq_peer_enrollment_refused` for B's
   PeerId on a process other than B. Without this the case would measure an
   honest cluster.
4. Fresh live effect on C's executor (process 2) for the new manifest on the
   new unowned domain; `require_executed_nonportable_quv_receipt(&response,
   &configured, &configured)` — ALL four configured members' replies present.
5. Require override_warnings ≥ 1, claim_refusals ≥ 1, zero override records
   on any process other than B, zero `…_invalid` records; print the row.
6. Kill B, `clear_orchestration_restart_env`, restart B, `wait_for_height`
   again so the cluster is honest for teardown.

## Observed evidence line

```
[M16Q-STATUS-CLAIM-EXPECT] member_position=0 account=519fa13af1ae075b1998a8e46ad465b9806d0e96405ac529b9e33502e16abcab claimant_position=1 claimant_process=3 claimant_account=8fc5a9c370f34346092710cbac73c112767ff3c618e99e13071166bef2d11a49 claimant_peer=12D3KooWBoBRVKb4JQxCUzPVT1TY8y7SZiqdCvB8QNW4bfrM3hWt
[M16Q-QUV] case=byzantine_status_claim claimed_account=519fa13af1ae075b1998a8e46ad465b9806d0e96405ac529b9e33502e16abcab claimant_process=3 claimant_peer=12D3KooWBoBRVKb4JQxCUzPVT1TY8y7SZiqdCvB8QNW4bfrM3hWt members_valid=4 override_warnings=15 claim_refusals=15 elapsed_ms=7903 max_valid_reply_elapsed_ms=1066 qualified_envelope_ms=4500 result=executed
```

Component-log corroboration (`components/`, all timestamps UTC 2026-09-06):

| log | process | override WARNs | refusals of B's PeerId | refusal reason |
|---|---|---|---|---|
| validator-20300-orch.log | B (claimant) | 15 (19:20:09.27 → 19:20:15.64) | 0 | — |
| validator-20200-orch.log | C (position 0, executor) | 0 | 5 (19:20:10.05 → 19:20:15.90) | `PQ peer enrollment aliases the local endpoint` |
| validator-20000-orch.log | genuine | 0 | 5 | `PQ authenticated enrollment change requires reconfiguration` |
| validator-20100-orch.log | genuine | 0 | 5 | `PQ authenticated enrollment change requires reconfiguration` |

No `testing_status_account_override_invalid` record anywhere. The three
`pq_provisional_enrollment_lost` records in the run are at 19:14:45–19:15:10
(sole-correct restart phase), outside the claim window (B disconnected from C
at 19:20:02.28, reconnected 19:20:03.46; honest restart 19:20:19.48/20.40).

What the receipt shows: the operation on C's executor collected all four
configured replies (`members_valid=4`, max valid reply 1066 ms) while every
status response from B claimed C. C's own reply was neither lost nor routed
to B; B's genuine carrier still delivered B's reply.

## Scope — what this case does and does not exercise

- It exercises the claim against carriers that ALREADY hold an authenticated
  enrollment for B (B ran honestly before the restart; `disconnect` in
  `pq_channel.rs` retains authenticated enrollments). The refusal reasons
  above show exactly that: on C's process the claim is refused as an alias
  of the local endpoint; on the other two it is refused because B's
  authenticated enrollment cannot be changed by a status hint. B's reconnect
  handshake then re-proves B's own ML-DSA key against the retained
  enrollment, which is why B's reply is still present.
- It does NOT exercise the finding's minimized trace step 1 ("B connects
  first", i.e. a first-contact claim on a peer with no prior authenticated
  enrollment for B), nor step 4 (genuine C arriving AFTER a squatter's
  provisional enrollment on a third peer). Those need a fresh-process or
  reconfiguration variant and remain open at process level. The unit and
  live multi-swarm tests in `../m17q-r2-pq-carrier-outbox-2026-09-06/`
  cover the first-contact shape at the networking layer only.
- Timing fields in the new row are recorded, not enforced against the
  qualified envelope (the checker requires numeric shape only); routing,
  not latency, is the claim of this case.

## Checker rule

`validate_status_claim(text, solo)` (called from `validate`, so it is part
of every non-flood evaluation):

- exactly one `[M16Q-QUV] case=byzantine_status_claim` row, appended as the
  last phase of the required order;
- `result=executed`, `members_valid=4`, numeric `elapsed_ms`,
  `max_valid_reply_elapsed_ms`, `qualified_envelope_ms=4500`;
- `claimed_account` is 64-hex and equals `account` of the single
  `[M16Q-STATUS-CLAIM-EXPECT] member_position=0 …` row (the sole_correct
  rows do not print accounts, so the fixture prints the expectation);
- `claimant_account` 64-hex and ≠ `claimed_account`; `claimant_position ≠ 0`;
- `claimant_process` ∈ 0..3, equals the expectation, and differs from the
  `process_index` of the `sole_correct member_position=0` row;
- `claimant_peer` is a base58 PeerId (≥ 40 chars) equal to the expectation;
- `override_warnings ≥ 1`, `claim_refusals ≥ 1`.

`validate_status_claim_components(text, dir)` (under `--components`):
`testing_status_account_override` records appear in exactly one of the four
`*-orch.log` files, at level WARN, with `claimed_account` and `local_peer`
equal to the row; count ≥ the row's `override_warnings`; no
`testing_status_account_override_invalid` anywhere; at least one OTHER log
holds a `pq_peer_enrollment_refused` record whose `peer` is the claimant's
PeerId.

Self-test (`--self-test`, `checker-self-test.txt`):
`{"flood": {"negative_cases": 54, "positive_cases": 2}, "negative_cases": 85, "no_push": {"negative_cases": 9, "positive_cases": 1}, "overlap": {"negative_cases": 38, "positive_cases": 1}, "positive_cases": 2, "status_claim": {"negative_cases": 10, "positive_cases": 1}}`
— top-level negatives grew from 69 to 85 (16 new: dropped EXPECT row,
dropped claim row, duplicate claim row, `members_valid=3`, `result=aborted`,
claimed = claimant account, EXPECT position 1, claimant account = claimed,
claimant position 0, claimant process mismatch ×2 (EXPECT side), claimant
process = position 0's process (row side), altered peer id, non-base58 peer,
`override_warnings=0`, `claim_refusals=0`, truncated hex); plus the 10
component negatives listed in `status_claim_self_test`.

## Commands, exit codes, elapsed

```
cargo check -p ioi-validator --features consensus-aft                                  # exit 0 (validator-check.txt)
cargo check --locked -p ioi-cli --tests --features consensus-aft,vm-wasm,state-iavl    # exit 0 (cli-check.txt; the one aft_e2e warning is pre-existing in aft_e2e_parts/quv_flood.rs:386)
cargo test -p ioi-validator --features consensus-aft --lib testing_status_claimed_account_override_accepts_only_exact_64_hex
                                                                                        # 1 passed (sync-unit-test.txt)
rustfmt --edition 2021 --check sync.rs backend.rs validator.rs                           # clean (aft_e2e.rs not formatted: it is not rustfmt-clean in the dirty tree)
python3 .github/scripts/check_aft_m16q_process_evidence.py --self-test                  # exit 0 (checker-self-test.txt)
IOI_AFT_BENCH_TRACE_DIR=<this dir>/components IOI_TEST_ORCH_RUST_LOG=info,quv=debug,network=debug \
  cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
  test_aft_quv_m16q_each_single_correct_member_and_conflict_isolation -- --nocapture > single.log 2>&1
                                                                                        # exit 0 (single.exit.txt); started 19:01:14Z, finished 19:20:21Z; test 1147.34 s; one run, no retry
python3 .github/scripts/check_aft_m16q_process_evidence.py single.log --components components
                                                                                        # exit 0 (checker-output.json)
```

The campaign was launched detached (`setsid nohup`) so no tool timeout could
interrupt it; a first launch under the tool's 10-minute ceiling was stopped
12 s in, during compilation, before any cluster existed, and its partial log
was discarded.

Registration: `[M16Q-REGISTRATION] manifests=20 last_committed_height=85 admitted_height=87`;
expiry fence 96 + 4·20 = 176 → `expiry_height=177 observed_height=178`
(the expired-result wait took 182 s of the run). All pre-existing phases
unchanged and passing (sole_correct 6180/5921/5598/5600 ms; saturation
max reply 2869 ms; conflict accepts=1; unrelated 8795 ms).

## sha256

Changed files (final tree):

```
9457f2d21023612257d48e8cb4883fe773e20e6371fdd9d1f9108a092c6c6adc  crates/validator/src/standard/orchestration/sync.rs
9223b2386962e4bea1848e3209e9062beeb3d1a77b2251f1a51c36092e79aa28  crates/cli/tests/aft_e2e.rs
ca965cf58f15c556798b2dd40bf08ac3314ea69901f1fff99e0a2a9e4847b306  crates/cli/src/testing/backend.rs
61a3ddf919c09c0ea020489a025aacca7cfa161df1cc9011553d0c17f9d8ffe2  crates/cli/src/testing/validator.rs
27210bf9901180031fe10f3c7f8fa28a12bd298adb7a45b158c78b02515482fe  .github/scripts/check_aft_m16q_process_evidence.py
```

Retained logs:

```
77dc249560d3df2caad454dca7cfbe7280cd82e5eaf116488c2d629c800924fd  single.log
4a4377602c2f5fbaaa69f0281477e5e9ad9bd58433982cae83cfeae31ccd6f81  components/validator-20000-orch.log
74bc9b11ff4d668521753fa8a1a2114fad4d313e0f86dfdb7f45baf22db10c2d  components/validator-20100-orch.log
efb563ee21b186ffda16e16943a5907a7621c176faeed66bf021a26f0466c4ad  components/validator-20200-orch.log
3a6811085240bf82852d28eb980a3b16fdd2bc1b6446958980ad6e0c346515c6  components/validator-20300-orch.log
```

## Open

- First-contact squat (no prior authenticated enrollment for B on the
  receiving peers) and genuine-C-after-squatter on a third peer are not
  exercised at process level by this case.
- Finding 007 is not closed by this slice.

---

# Follow-up: first-contact trace (`quv_status_squat`), 2026-09-06

Coordinator follow-up in the same slice: cover the finding's minimized trace
step 1 ("B connects first"), i.e. a claim on peers that hold NO prior
authenticated enrollment for B. This section supersedes the "Scope" caveat
above for the first-contact shape.

## Additional files changed

| file | change |
|---|---|
| `crates/cli/src/testing/validator.rs` | `launch(..)` gains `orchestration_env: BTreeMap<String,String>` (after `workload_env`), applied to `orch_cmd` BEFORE `remember_orchestration_command`, so the binding is present at first launch and inherited by restarts until `clear_orchestration_restart_env` |
| `crates/cli/src/testing/cluster.rs` | builder field `validator_orchestration_env: BTreeMap<usize, BTreeMap<String,String>>`, `with_validator_orchestration_env(index, key, value)`, captured at all three launch sites (index 0 / `i`) |
| `crates/validator/src/standard/orchestration/events.rs` | INFO `target="network" event="pq_carrier_authenticated" peer account` in the `NetworkEvent::PqCarrierAuthenticated` handler — the swarm emitted no log for this event, and it is the only path that binds a carrier to an account for validator-side routing |
| `crates/cli/tests/aft_e2e.rs` | `include!("aft_e2e_parts/quv_status_squat.rs")`; `NetworkEventRecord` gains `account` and `error` |
| `crates/cli/tests/aft_e2e_parts/quv_status_squat.rs` | NEW: `test_aft_quv_status_squat_first_contact_keeps_genuine_carriers` |
| `.github/scripts/check_aft_m16q_process_evidence.py` | `--status-squat` mode: `validate_status_squat`, `validate_status_squat_components`, `status_squat_self_test` |

`crates/cli/tests/proof_verification_e2e.rs` also calls `TestValidator::launch`
but is gated on `consensus-poa,…,malicious-bin` and was already out of date
with the signature (28 arguments against 30 before this slice); untouched.

## The fixture

4-validator strict-PQ ClassicBft cluster, `with_validator_pqc_keypairs` so
C = index 0's ML-DSA account is known before build; B = index 1 is launched
with `IOI_TESTING_AFT_STATUS_CLAIMED_ACCOUNT_HEX=<C>` via
`with_validator_orchestration_env(1, …)`. Three unowned domains
(`status-squat/warmup-1`, `warmup-2`, `measured`; standard preparation,
generous quota), three manifests bound to C's endpoint key, registered from
C, admission waited on every process (B: 300 s budget, it follows by block
sync only). Warm-up: up to two recorded, unasserted operations on C's
executor. Measured: one operation on C's executor, a diagnostic
`[M16Q-STATUS-SQUAT-OBSERVED]` row, then the instructed assertion
`require_executed_nonportable_quv_receipt(&response, &configured, &configured)`
(all four members valid), then in-window log assertions (override WARN on B,
no override elsewhere, refusal/loss of B's claim on every other process, no
`pq_carrier_authenticated` for B with C's account), then
`[M16Q-STATUS-SQUAT] first_contact=true …`.

Env: as the siblings except `IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS=10`
(B never joins strict-PQ consensus, every view it leads times out) and
`IOI_TEST_READY_HEIGHT_LAG_MAX=64` (B follows only by block sync).

## Run outcome: assertion FAILED as instructed; not an infrastructure failure

```
IOI_AFT_BENCH_TRACE_DIR=<this dir>/squat-components IOI_TEST_ORCH_RUST_LOG=info,quv=debug,network=debug \
  cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
  test_aft_quv_status_squat_first_contact_keeps_genuine_carriers -- --exact --nocapture > squat.log 2>&1
  # exit 101 (squat.exit.txt); 19:33:39Z → 19:46:14Z; test 741.97 s of which cluster build 672.4 s; ONE run, no retry
python3 .github/scripts/check_aft_m16q_process_evidence.py --status-squat squat.log --components squat-components
  # exit 1 (squat-checker-output.txt): "expected exactly one status-squat expectation row and one result row" — no result row was printed because the assertion failed first
python3 .github/scripts/check_aft_m16q_process_evidence.py --self-test
  # exit 0 (checker-self-test-squat.txt): status_squat {"negative_cases": 34, "positive_cases": 2}
```

Load note: a different session started `cargo test --workspace --offline -j 4`
(toolchain 1.97.1) 8 s after this launch and ran concurrently; load average
3–5 throughout. Timing fields below are therefore not qualified numbers; the
failure is not timing-related.

Observed lines (squat.log):

```
[M16Q-STATUS-SQUAT-EXPECT] first_contact=true configuration=f32fb811… network=41e2eb9b… claimed_account=8f513344f7272adadf4b317429c4e03e3a02397a0f4c836ff163f1fbe58cb8ee claimant_account=85bfa019c60b2fd21f86611332ccef2f10b7f96cbd2529f757f2895673a296f6 claimed_process=0 claimant_process=1 claimed_peer=12D3KooWPMGkwnXNKBT7dqK3CncpodYSYQeJmKPdwHVEj2m2DToj claimant_peer=12D3KooWDUeKQMdkqzUUJ2MHRoM5QEjvyJy8FeLhhTpw4PQsJVa4 measured_domain=… manifests=3 build_elapsed_ms=672366
[M16Q-STATUS-SQUAT-REGISTRATION] manifests=3 last_committed_height=17 admitted_height=19
[M16Q-STATUS-SQUAT-WARMUP] attempt=1 slot=1 outcome=executed_incomplete_coverage members_valid=3 valid_members=8f513344…,9a1e3d74…,bc3d6d94… elapsed_ms=6548
[M16Q-STATUS-SQUAT-WARMUP] attempt=2 slot=2 outcome=executed_incomplete_coverage members_valid=3 valid_members=8f513344…,9a1e3d74…,bc3d6d94… elapsed_ms=5999
[M16Q-STATUS-SQUAT-OBSERVED] members_configured=4 members_valid=3 valid_members=8f513344…,9a1e3d74…,bc3d6d94… claimed_replied=true claimant_replied=false elapsed_ms=6463
Error: QUV audit member coverage differs for effect status-squat-measured nonce=62ee6ec4…: configured_count=4 …; reply_count=3 …; reply_elapsed_ms=[477, 1100, 1439]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 19 filtered out; finished in 741.97s
```

The measured operation EXECUTED with three valid replies: C's own
(`8f513344…`, `claimed_replied=true`) and both genuine third members. The
only missing reply is B's (`85bfa019…`, `claimant_replied=false`) — in both
warm-ups and the measured effect. `[M16Q-STATUS-SQUAT]` was never printed
because the instructed all-four assertion precedes it.

## Component-log evidence (squat-components/, full run incl. launch)

| log | local peer | role | override WARNs | status responses | refusals of B's peer | `pq_carrier_authenticated` |
|---|---|---|---|---|---|---|
| validator-20100-orch.log | 12D3KooWDUeK… | B (claimant) | 137, first 19:40:32.904393 | 137, first 19:40:32.904408 | — | none |
| validator-20000-orch.log | 12D3KooWPMGk… | C (claimed) | 0 | 139 | 70 × `PQ peer enrollment aliases the local endpoint` | (third-A, `9a1e3d74`), (third-B, `bc3d6d94`) |
| validator-20200-orch.log | 12D3KooWE6wi… | third A | 0 | 112 | 41 × `conflicts with an authenticated carrier for the rooted account`; B's client hellos refused (`scope mismatch` ×2, then `no rooted PQ channel enrollment`) | (C, `8f513344`) at 19:42:47.237, (third-B, `bc3d6d94`) |
| validator-20300-orch.log | 12D3KooWAtkp… | third B | 0 | 60 | 19 × `conflicts with an authenticated carrier…`; 3 × `pq_provisional_enrollment_lost` for B | (C, `8f513344`) at 19:44:46.947, (third-A, `9a1e3d74`) |

- B's override WARN precedes B's first status response by 15 µs; every one of
  B's 137 status responses carried the claim. No `…_invalid` record anywhere.
- B was never authenticated under ANY account on any process (zero
  `pq_carrier_authenticated` with B's peer id); in particular never under C's.
- C's carrier authenticated under C's account on both genuine third
  processes. C's own process refused B's claim 70 times as an alias of the
  local endpoint.
- First-contact window, exactly the finding's steps 1–4, on third-B
  (validator-20300): B connected 19:44:44.976 (37 ms before C); B's claim
  was provisionally enrolled and lost three times (19:44:46.290 – .944,
  B's handshake cannot prove C's key); genuine C authenticated at
  19:44:46.947; from then on B's claim is refused as conflicting with the
  authenticated carrier. On third-A the order was C then B; B's hello was
  refused with `scope mismatch` before C authenticated at 19:42:47.237.
  The squatter never held C's carrier at any point at which a QUV push was
  routed, and the genuine carrier's proof evicted the claim.

## Assessment (reported, not ruled)

This is NOT the finding's failure mode: C's reply was neither lost nor
routed to B, and B was never bound under C's account. The instructed
`members_valid=4` is unattainable by construction for this trace: the ONLY
path that binds a carrier to an account is status hint + strict-PQ proof of
that account's rooted ML-DSA key, and a process that names C in every status
response never presents its own account B, so no peer can ever bind B's
carrier under B, C's verifier has no route for its push to B
(`peer_for_account(B) = None`), and B cannot reply. B excludes itself; the
operation still executes on the three honest replies. The assertion was left
as instructed and the run was not repeated (the outcome is deterministic,
not infrastructural). Owner-reversible suggestion: for the first-contact
trace, assert valid = configured minus the claimant (3) plus the four
absence/presence log rules already in the fixture, and keep the all-four
assertion for the retained-enrollment case above. Nothing here closes 007.

## Runner lines (not added to `run_aft_m16q_qualification.sh`; reported)

```
  run_process_phase quv_status_squat \
    env IOI_TEST_ORCH_RUST_LOG=info,quv=debug,network=debug cargo test --locked -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_quv_status_squat_first_contact_keeps_genuine_carriers -- --exact --nocapture
  require_tests_ran quv_status_squat
  run_phase quv_status_squat_evidence python3 .github/scripts/check_aft_m16q_process_evidence.py --status-squat "${OUTPUT_DIR}/quv_status_squat.log" --components "${OUTPUT_DIR}/quv_status_squat-components"
```

(and `crates/cli/tests/aft_e2e_parts/quv_status_squat.rs` in the runner's
sha256 manifest list next to `quv_flood.rs`). With the assertion as
instructed this phase fails today.

## Other commands

```
cargo check --locked -p ioi-cli --tests --features consensus-aft,vm-wasm,state-iavl   # Finished; only pre-existing warnings
cargo check -p ioi-validator --features consensus-aft                                  # Finished
rustfmt --edition 2021 --check cluster.rs validator.rs events.rs backend.rs             # clean
```

## sha256 (final tree, follow-up)

```
9457f2d21023612257d48e8cb4883fe773e20e6371fdd9d1f9108a092c6c6adc  crates/validator/src/standard/orchestration/sync.rs
4c44905e56747d17e614f6f3f67b84559de0bb19a951ec66a4cedd1b095ac5ed  crates/validator/src/standard/orchestration/events.rs
3c928074550628cfc5b0b1b0b5a30c1549adc60f855e8730bf2dabc942a08540  crates/cli/tests/aft_e2e.rs
80bb99b1c84391540f6100d58b375f4117cc8fa8082bed687338ef7e31031071  crates/cli/tests/aft_e2e_parts/quv_status_squat.rs
ca965cf58f15c556798b2dd40bf08ac3314ea69901f1fff99e0a2a9e4847b306  crates/cli/src/testing/backend.rs
6eadbbc08c1de228feff1db47973cbd824664e719725b54dd9e814a8a4be4b6c  crates/cli/src/testing/validator.rs
e05cbadb61d4273b5381021478adb5ec653fb9864b477128cdfa9f670439e69a  crates/cli/src/testing/cluster.rs
bf4fa0f4d49073cda97cfe97ea831650ba3e28ed32b5479cd4ba5ec36861ab4f  .github/scripts/check_aft_m16q_process_evidence.py

708dbd0477db76860ae41f172f22ae2463e7bd99afdfbb25ac088efa80f7387a  squat.log
d38638dbcfef9e6f51616dc9610a9a10fa0a7a9eeb087a30f722fd75eb7a3a50  squat-components/validator-20000-orch.log
2ce914c950e1f6fcf1802079ebf4169eaabca1c7a280f3d59322c2c4c3927a09  squat-components/validator-20100-orch.log
7b3b083e9068647947ffac2e09315baa9f553f56d8f97c0b6652332be502af80  squat-components/validator-20200-orch.log
cf3fd5099b47971d66705cc43bd8301cb368366a1ecf3f2033a2aa711dd80065  squat-components/validator-20300-orch.log
```

`sources/` was refreshed with byte copies of all eight files. The first
campaign's files (`single.log`, `components/`) and the sha256 of `sync.rs`,
`backend.rs` are unchanged from the section above; `aft_e2e.rs`,
`validator.rs` and the checker changed in this follow-up.

---

# Run 2 of the first-contact trace under the adopted ruling (2026-09-06)

Ruling (coordinator, adopting the assessment above): for the first-contact
trace the claimant is Byzantine by construction — it never presents its own
account, so no peer can bind it — and its own reply is not owed under the
theorem; every CORRECT member's reply is. Run 1's artifacts (`squat.log`,
`squat-components/`, `squat-checker-output.txt`, `squat.exit.txt`) are
retained unchanged as history.

## Changes

- `crates/cli/tests/aft_e2e_parts/quv_status_squat.rs`: `expected_valid =
  configured − {claimant}`; measured assertion is now
  `require_executed_nonportable_quv_receipt(&response, &configured, &expected_valid)`
  (EXACTLY the three correct members) plus explicit `claimed_replied == true`
  and `claimant_replied == false`; the in-window log rules now require the
  claimant to be `pq_carrier_authenticated` under NO account (was: not under
  the claimed account); warm-up is still recorded/unasserted but its expected
  outcome is that same set (`executed_expected_coverage`), so no extra attempt
  is spent; row format changed (below).
- `.github/scripts/check_aft_m16q_process_evidence.py` `--status-squat`:
  requires one EXPECT, one OBSERVED and one result row; result row
  `members_configured=4 members_valid=3 claimant_excluded=true
  claimed_replied=true claimant_authenticated_any=0 refusing_processes=3
  override_warnings≥1 result=executed`; OBSERVED row cross-checked
  (exactly three distinct 64-hex members, claimed account present, claimant
  absent, `claimed_replied=true`, `claimant_replied=false`); component rule
  now rejects any `pq_carrier_authenticated` for the claimant's peer under
  ANY account. Self-test `status_squat {"negative_cases": 45, "positive_cases": 2}`
  (new negatives include: `members_valid=4` with the claimant listed —
  a bound squatter; claimed account missing from the reply set /
  `claimed_replied=false`; `claimant_excluded=false`; `claimant_replied=true`;
  duplicate member in the set; `members_configured=3`; claimant authenticated
  under its own account in a component log). Whole self-test exit 0
  (`checker-self-test-squat.txt`).

## Commands, exit codes, elapsed

```
cargo check --locked -p ioi-cli --tests --features consensus-aft,vm-wasm,state-iavl     # Finished
python3 .github/scripts/check_aft_m16q_process_evidence.py --self-test                    # exit 0
IOI_AFT_BENCH_TRACE_DIR=<this dir>/squat-run2-components IOI_TEST_ORCH_RUST_LOG=info,quv=debug,network=debug \
  cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
  test_aft_quv_status_squat_first_contact_keeps_genuine_carriers -- --exact --nocapture > squat-run2.log 2>&1
                                    # exit 0 (squat-run2.exit.txt); 19:51:58Z → 20:01:41Z; test 579.46 s, cluster build 516.4 s; ONE run
python3 .github/scripts/check_aft_m16q_process_evidence.py --status-squat squat-run2.log --components squat-run2-components
                                    # exit 0 (squat-run2-checker-output.json)
```

The other session's workspace build had finished before launch (no cargo /
rustc processes; load 3.7 at launch, 6.2 at the end — the box was otherwise
idle apart from this campaign).

## Observed evidence line (squat-run2.log)

```
[M16Q-STATUS-SQUAT] first_contact=true claimed_account=7f4520998ced44d51df997c9041c5b3a93cc3564405a95c5b49a1267174ae84e claimant_process=1 claimant_peer=12D3KooWGdLrk3ztssFXGUGL9B8fm2LCnERwLJwE35SxocnBeGwP members_configured=4 members_valid=3 claimant_excluded=true claimed_replied=true override_warnings=38 refusing_processes=3 refusal_reasons=pq_peer_enrollment_refused:PQ_peer_enrollment_aliases_the_local_endpoint|pq_peer_enrollment_refused:PQ_peer_enrollment_conflicts_with_an_authenticated_carrier_for_the_rooted_account claimant_authenticated_any=0 warmup_attempts=1 events_during_measured=7 elapsed_ms=5663 max_valid_reply_elapsed_ms=475 qualified_envelope_ms=4500 result=executed
```

Supporting rows:

```
[M16Q-STATUS-SQUAT-EXPECT] first_contact=true configuration=667ccf4a… network=f242c6b0… claimed_account=7f452099…ae84e claimant_account=3366543f…7c72 claimed_process=0 claimant_process=1 claimed_peer=12D3KooWGDtZ1G3sgxtvZgCfHXpFynNDCBubjAkcdXE4NUHrViTi claimant_peer=12D3KooWGdLrk3ztssFXGUGL9B8fm2LCnERwLJwE35SxocnBeGwP measured_domain=abbb22f3… manifests=3 build_elapsed_ms=516435
[M16Q-STATUS-SQUAT-REGISTRATION] manifests=3 last_committed_height=16 admitted_height=18
[M16Q-STATUS-SQUAT-WARMUP] attempt=1 slot=1 outcome=executed_expected_coverage members_valid=3 valid_members=7f452099…,f00578dd…,f7a4328a… elapsed_ms=6462
[M16Q-STATUS-SQUAT-OBSERVED] members_configured=4 members_valid=3 valid_members=7f452099…,f00578dd…,f7a4328a… claimed_replied=true claimant_replied=false elapsed_ms=5663
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 19 filtered out; finished in 579.46s
```

Checker summary: `members_valid 3`, `valid_members` = {7f452099… (C), f00578dd…, f7a4328a…}, `claimant_excluded true`, `override_warnings 38` (row) / 136 in components = 136 status responses from the claimant, `claimant_log validator-20100`, `claimed_log validator-20000`, `refusing_logs` = all three other logs, `claimed_carrier_authenticated_in` = validator-20200 and validator-20300.

## Component-log evidence (squat-run2-components/, full run incl. launch)

| log | role | override WARNs | status responses | refusals of B's peer | `pq_carrier_authenticated` |
|---|---|---|---|---|---|
| validator-20100 | B (claimant) | 136, first 19:55:59.537360 | 136, first 19:55:59.537376 | — | none (under any account) |
| validator-20000 | C (claimed) | 0 | 133 | 71 × `aliases the local endpoint` | third-A `f00578dd`, third-B `f7a4328a` |
| validator-20200 | third A | 0 | 109 | 40 × `conflicts with an authenticated carrier…` | C `7f452099` at 19:58:18.092, third-B |
| validator-20300 | third B | 0 | 56 | 17 × `conflicts with an authenticated carrier…` + 3 × `pq_provisional_enrollment_lost` | third-A, C `7f452099` at 20:00:20.525 |

First-contact window on validator-20300: B and C connected in the same
millisecond (20:00:18.768); B's claim for C was provisionally enrolled and
lost three times (20:00:20.044 – .524; B's handshake cannot prove C's key);
genuine C authenticated at 20:00:20.525; every later claim by B refused as
conflicting with the authenticated carrier. The squatter never held C's
carrier at any point at which a push was routed, C's reply was present in
warm-up and measured operations, and B was never bound anywhere.

## Runner lines (unchanged from the section above; the phase now passes)

```
  run_process_phase quv_status_squat \
    env IOI_TEST_ORCH_RUST_LOG=info,quv=debug,network=debug cargo test --locked -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl \
    test_aft_quv_status_squat_first_contact_keeps_genuine_carriers -- --exact --nocapture
  require_tests_ran quv_status_squat
  run_phase quv_status_squat_evidence python3 .github/scripts/check_aft_m16q_process_evidence.py --status-squat "${OUTPUT_DIR}/quv_status_squat.log" --components "${OUTPUT_DIR}/quv_status_squat-components"
```

## sha256 (final tree after run 2)

```
9457f2d21023612257d48e8cb4883fe773e20e6371fdd9d1f9108a092c6c6adc  crates/validator/src/standard/orchestration/sync.rs
4c44905e56747d17e614f6f3f67b84559de0bb19a951ec66a4cedd1b095ac5ed  crates/validator/src/standard/orchestration/events.rs
3c928074550628cfc5b0b1b0b5a30c1549adc60f855e8730bf2dabc942a08540  crates/cli/tests/aft_e2e.rs
3f15da7b10b5587735c3d91d4027b523aa8fddecb8df973240d367bb825d2b49  crates/cli/tests/aft_e2e_parts/quv_status_squat.rs
ca965cf58f15c556798b2dd40bf08ac3314ea69901f1fff99e0a2a9e4847b306  crates/cli/src/testing/backend.rs
6eadbbc08c1de228feff1db47973cbd824664e719725b54dd9e814a8a4be4b6c  crates/cli/src/testing/validator.rs
e05cbadb61d4273b5381021478adb5ec653fb9864b477128cdfa9f670439e69a  crates/cli/src/testing/cluster.rs
8c0a22c293f7032a766241882d0262c323546b29532b41a902adc19f80a2c4ae  .github/scripts/check_aft_m16q_process_evidence.py

0a7759c3095f3d8ea1011ef3a164f62da553aa5aeb34a79de441a1c26f8168e4  squat-run2.log
81c4b2ff5bdd5c5d453d01c5705e4619a463ca9b8ceba3bc54111371b2ab8bca  squat-run2-components/validator-20000-orch.log
319a8332aabd298712c0cf77809bdfdc165eb6e358d20ff93ae90f86398f6098  squat-run2-components/validator-20100-orch.log
dc94104bd47e3d287a9bc8914b3773b94888817e055bd2ca0142ed6dcea6ae35  squat-run2-components/validator-20200-orch.log
84e503f527641d54a487426c05ca944651f408ec8971511298af6fbb037f858d  squat-run2-components/validator-20300-orch.log
```

`sources/` refreshed for `quv_status_squat.rs` and the checker (the other
six files are unchanged since the previous section). Nothing here closes
finding 007; the first-contact trace now has passing process-level evidence
under the adopted expectation, and the retained-enrollment case above keeps
its all-four assertion.
