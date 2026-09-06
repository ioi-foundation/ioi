# M17Q R2 — rooted per-identity PUSHQUERY admission quota (QUV-M17Q-006)

Date: 2026-09-06. Worktree: `/home/heathledger/Documents/ioi/repos/ioi`, HEAD `24a9888e3`
with a large uncommitted in-progress AFT QUV remediation from other agents. This directory
records one repair slice only; it does not describe any finding as closed.

## What changed

- `ioi_types::app::QuvPushAdmissionPolicyV0 { max_requests_per_identity: u32, window_millis: u64 }`
  (`crates/types/src/app/query_unanimity.rs`), with `is_valid(delta_rt_millis)`:
  both fields nonzero, `max_requests_per_identity <= QUV_MAX_PUSH_REQUESTS_PER_IDENTITY_V0 (4096)`,
  `window_millis >= delta_rt_millis`.
- Required field `AftQuvDomainPolicyV0::push_admission` (`crates/types/src/config/mod.rs`), no serde
  default; validated in `OrchestrationConfig::validate` (error message extended).
- `POLICY_ROOT_DOMAIN_V0` bumped to `ioi/aft/quv-policy/v8-push-admission`; `quv_policy_root`
  takes `push_admission` as its last parameter, refuses an invalid quota with
  `InvalidRootedContext`, and commits it in the canonical tuple immediately after `authority_slots`
  (`crates/consensus/src/aft/query_unanimity.rs`). `PreparationPolicyWitness` in `member_delta.rs`
  carries the field so the journal witness remains the exact preimage of the commitment.
- Validator push path (`crates/validator/src/standard/orchestration/quv.rs`, `dispatch_push_query`):
  before the `aft_quv_push_inflight` insert, if a provisioned policy resolves for
  `query.candidate.slot.domain_id`, the sliding window for `(domain, requester)` in
  `MainLoopContext::aft_quv_push_admission` is consulted via the pure helpers
  `admit_push_within_quota` / `admit_push_within_quota_for`. A request beyond the quota is dropped
  with `warn!(target: "quv", ..., "Dropped QUV PUSHQUERY beyond the rooted per-identity admission quota")`,
  `SwarmCommand::CompleteQuvPush` is sent, and the store is not touched. Unknown domains skip the
  quota; the existing later refusal is unchanged. Table capped at
  `QUV_PUSH_ADMISSION_TABLE_MAX_ENTRIES = 4096` keys by evicting the key whose newest admission is oldest.
- All 22 `quv_policy_root(` call sites and all 9 `AftQuvDomainPolicyV0 { .. }` literals updated;
  fixtures use `{ max_requests_per_identity: 64, window_millis: <delta_rt of that fixture> }`.

Ownership deviation: `crates/validator/src/standard/orchestration/lifecycle.rs` received one line
(`aft_quv_push_admission: BTreeMap::new(),`) because `MainLoopContext` is constructed there as a
struct literal; a new field cannot be added without it.

## New tests

- `ioi-types`: `config::tests::quv_policy_requires_exact_authority_and_durable_roots` extended
  (missing `push_admission` refused at decode, unknown sub-field refused, four invalid quotas refused
  at validate, two valid quotas accepted).
- `ioi-consensus`: `aft::query_unanimity::tests::policy_root_binds_push_admission_and_refuses_invalid_quota`;
  `policy_root_binds_authority_and_complete_timing_bounds` re-pinned to the v8 fixture root.
- `ioi-validator`: `standard::orchestration::quv::tests::push_quota_admits_up_to_limit_then_drops_until_window_slides`,
  `push_quota_keys_are_independent_per_domain_and_account`,
  `push_quota_table_is_capped_by_evicting_the_stalest_key`.

## Independent root vector (`policy_vector.py`, `policy_vector.json`)

Derived from `m17q-r1-receipt-admission-2026-09-06/policy_vector.py` (the v7 vector; the
consequence-profile directory holds the older v6 form). Fixture: domain `[3;32]`, Owned, owner
`[9;32]`, delta_rt 1000, continuation 50, `Fixed{1, [77;32]}`, `Independent{2, 1020, 1000000}`,
operation_service 1050, authority_slots 256, push_admission `{64, 1000}` encoded as SCALE
`u32 LE ++ u64 LE` directly after `authority_slots`.

| source | root |
| --- | --- |
| Rust `quv_policy_root` (test `policy_root_binds_authority_and_complete_timing_bounds`, first run printed the new value as the failing `left`) | `ae67b82d343da98afd762f34c1ae28d4b0b265ef885c878e4dc43a136fcaa2ea` |
| Python `policy_vector.py` `policy_root` | `ae67b82d343da98afd762f34c1ae28d4b0b265ef885c878e4dc43a136fcaa2ea` |
| Python `without_push_admission` (quota omitted from its tuple position) | `62191909f9900ad9a0717f3804c6dcff3e924fdbdfd0f6c8c66cd21f68058aef` |
| Rust with `push_admission,` deleted from the tuple (control B, failing `left`) | `62191909f9900ad9a0717f3804c6dcff3e924fdbdfd0f6c8c66cd21f68058aef` |

Both directions agree byte-for-byte.

## Removed-rule controls (`controls/`)

Control A — delete the quota rule in the pure helper (`if window.len() >= max { return false }`,
`controls/controlA-mutation.diff`), run
`cargo test -p ioi-validator --features consensus-aft --lib standard::orchestration::quv::tests::push_quota`:
`push_quota_admits_up_to_limit_then_drops_until_window_slides` FAILED,
`push_quota_keys_are_independent_per_domain_and_account` FAILED,
`push_quota_table_is_capped_by_evicting_the_stalest_key` ok (it does not depend on the rule) —
`1 passed; 2 failed` (`controls/controlA-output.txt`). Source restored from a saved copy;
`sha256sum` before/after identical (`cbf1faee…4fd6`, `controls/controlA-{before,after}.sha`) and
`git diff --stat` identical before/after.

Control B — delete `push_admission,` from the hash tuple (`controls/controlB-mutation.diff`), run
`cargo test -p ioi-consensus --features aft --lib policy_root`:
`policy_root_binds_authority_and_complete_timing_bounds` FAILED and
`policy_root_binds_push_admission_and_refuses_invalid_quota` FAILED — `3 passed; 2 failed`
(`controls/controlB-output.txt`). Restored; `sha256sum` identical (`20923564…02ff`). The
`git diff --stat` before/after differed only in `crates/agentgres/src/consequence.rs` and
`crates/networking/src/libp2p/swarm.rs`, which other agents were editing concurrently; the
consensus file line count was unchanged.

Nonclaim: neither control exercises the wiring of the helper into `dispatch_push_query`; no
cluster test drives a live PUSHQUERY flood against the quota in this slice.

## Commands and results

| command | result |
| --- | --- |
| `cargo fmt -p ioi-types -p ioi-consensus -p ioi-validator` | modified only the three files edited in those crates |
| `cargo test -p ioi-types --lib config` | 14 passed; 0 failed |
| `cargo test -p ioi-consensus --features aft --lib policy_root` | 5 passed; 0 failed (`controls/consensus-policy-root-tests.txt`) |
| `cargo test -p ioi-validator --features consensus-aft --lib standard::orchestration::quv::` | 27 passed; 0 failed (`controls/validator-quv-tests.txt`) |
| `cargo check --locked -p ioi-cli --tests --features consensus-aft,vm-wasm,state-iavl` | Finished, exit 0 (`controls/cli-check.txt`) |
| `python3 policy_vector.py` | prints `ae67b82d…a2ea`, writes `policy_vector.json` |

`cargo fmt -p ioi-cli` was not run: the e2e fixture files carry pre-existing unformatted regions
owned by other agents.

## Source hashes

See `SHA256SUMS` (sha256sum of every file changed by this slice plus the vector script/output).

### Root re-pin after profile extension (2026-09-06, integrator)

After this slice landed, two further rooted fields were added under the same
v8 domain tag: `QuvConsequenceStorageProfileV0` gained `CLAIM_INDEX_FILES=2`
and `CLAIM_INDEX_FILE_BYTES=4096` (stable-key claim index, 15 storage fields),
and `QuvConsequenceAdmissionProfileV0` gained `WAITING_PER_PRINCIPAL=1`
(5 admission fields). `policy_vector.py` was updated in place; the fixture root
is now `0905e843345dcc036bc0e85cff6a49c66f4c6e891c00c2d38414062f2416619d`
(Python) and the consensus test `policy_root_binds_push_admission_and_refuses_invalid_quota`
pins the same value from Rust. The `ae67b82d…a2ea` / `62191909…8aef` values in
the tables above are the pre-extension vectors and remain valid controls for
the quota-omission comparison at that revision only.
