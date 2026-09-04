# M15Q QUV handoff restart and ceremony — local evidence

Date: 2026-09-04

Status: **PASS for the complete production handoff/restart/ceremony slice at
code commit `ce34c31a9`; together with executor/T10 commit `bd1e91a6d`, M15Q
is COMPLETE LOCALLY and M17Q review remains required.** This is local
implementation evidence, not independent review or a production/public QUV
claim.

## Implemented slice

The disjoint-root release fixture now uses the operator-facing
`cli aft quv-handoff` ceremony instead of directly signing and copying source
bytes in the test. Its `inspect`, `sign`, `verify`, and `install` commands:

- decode only bounded canonical SCALE handoff envelopes;
- re-run structural old-root/successor/boundary validation;
- derive and exact-match the rooted ML-DSA owner identity;
- sign and verify the typed candidate-authority message;
- refuse replacement by default and install through a mode-0600,
  fsync-before-rename, parent-directory-fsync sequence; and
- emit an audit object fixed to `disposition=candidate_input_only`,
  `portable_final_receipt=false`, and
  `process_local_authorization_present=false`.

Those bytes remain candidate input. They cannot construct a
`QuvOnlineAuthorizationV0`, change a local install gate, or activate a
successor.

After the release fixture completes four independent successor-side live QUV
operations and advances under the completely disjoint successor root, it now
kills one successor's orchestration process without stopping its workload
process. Startup:

1. recognizes either the old configuration root or the exact successor root
   from canonical state;
2. uses the configured source only to locate the old-root-scoped local store;
3. opens and rollback-authenticates the separately anchored store;
4. exact-matches the complete originally installed candidate and handoff,
   including owner-signature and boundary-evidence bytes;
5. independently rechecks the canonical historical boundary block and state
   root; and
6. restores successor networking, membership, signing-fence, QUV-member, and
   production authority from that local gate.

Recovery never sends a new `PUSHQUERY` and never replays a cached QUV
transcript. It also does not replay the historical old-root QC into a consensus
engine rooted only with the successor key epoch: that QC was authenticated in
the original live ceremony, and the durable gate is the process-local record
of that completed operation. The restart rechecks the exact canonical boundary
and gate instead of inventing pruned historical key state.

Restart reconciliation now reads a separate workload execution cursor. Public
AFT status remains collapse-demoted and is not used as raw execution state.
The internal cursor has no finality meaning and cannot authorize a block or
effect.

The completed matrix additionally covers the two durable install files and
both membership geometries:

- a successor is restarted before any signed source or installed authority
  exists and remains inactive;
- a process-test seam exits after the next handoff state has been atomically
  persisted but before its separately rooted rollback anchor advances;
- `DurableQuvHandoffV0::open` recovers only that exact one-generation
  state-ahead/anchor-behind window;
- restoring the captured generation-zero state against the advanced anchor is
  refused as rollback/fork rather than treated as a crash window;
- a four-old/four-successor disjoint-root fixture activates all successors,
  restarts one from its exact durable gate, executes the real QUV-to-T10 path,
  and refuses retired credentials; and
- a four-old/four-successor fixture with one member in both roots proves that
  the retained member performs its own live QUV operation, can finish after
  other successors have already produced descendants, and later recovers the
  same successor-scoped gate.

Late overlapping-root authorization uses the immutable handoff boundary block
cached when the old member observes its verified QC. The boundary is validation
context, not authority. The source QC is independently verified against the
old rooted ML-DSA set and threshold. Different valid aggregate QCs for the same
height/view/block are not required to have identical serialized bytes. A
focused negative test mutates a QC and then recomputes the owner's outer
signature; the invalid QC is still refused, so owner authority cannot launder
forged ordering evidence.

## Failures found during the process drill

The process test found and preserved three fail-closed integration defects
before the passing run:

1. consumed `ValidatorSetsV1.next` state initially left restart unable to
   locate the old-root handoff store;
2. public collapse-demoted status falsely reported that the workload was
   behind the Agentgres admission cursor; and
3. replaying the old height-2 QC against successor keys active from height 3
   failed with `consensus key ... is not active until height 3, but the quorum
   is for height 2`.

The repairs do not relax gate matching or synthesize authority. A dedicated
test-harness restart event log retains QUV activation/refusal diagnostics so a
future process failure cannot be hidden by ordinary sync-log volume.

## Reproduction and result

```text
cargo test -p ioi-consensus --features aft \
  live_authorization_is_consumed_into_rollback_anchored_successor_activation \
  --lib

cargo test -p ioi-validator --features consensus-aft \
  handoff_source_requires_old_owner_signature_and_exact_staged_set --lib

RUST_TEST_THREADS=1 cargo test -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_quv_disjoint_successors_install_live_handoff_before_activation \
  -- --nocapture

RUST_TEST_THREADS=1 cargo test -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_quv_overlapping_member_installs_and_recovers_the_same_live_handoff \
  -- --nocapture

cargo check -p ioi-cli --lib --bin cli
cargo run -q -p ioi-cli --bin cli -- aft quv-handoff --help
cargo build --locked -p ioi-node --bin hypervisor-daemon
cargo tree -p ioi-node --edges normal | \
  rg '^ioi-(consensus|validator) v'
git diff --check
```

Observed results:

- rollback-anchored install/recovery test: 1 passed;
- rooted source/QC validation test: 1 passed in 8.06 seconds;
- eight-process release handoff/restart positive test: 1 passed in 417.21
  seconds at `252e03573`;
- expanded eight-process positive/negative restart matrix: 1 passed in 267.93
  seconds at `fc7c9b926`; this includes source-signature substitution, a missing
  state/anchor half after expiry, and retired-old-key refusal;
- final eight-process disjoint-root crash/recovery/QUV-to-T10 matrix: 1 passed
  in 355.49 seconds at `ce34c31a9`;
- seven-process one-member-overlap handoff/restart matrix: 1 passed in 426.76
  seconds at `ce34c31a9`;
- CLI library/binary compile and command-surface smoke: pass; and
- default-feature Hypervisor daemon build: pass in 209.43 seconds with peak RSS
  5,467,988 KiB; its resolved normal dependency tree contains no
  `ioi-consensus` or `ioi-validator` package; and
- formatting/diff check: pass.

The process assertion requires both the explicit
`Recovered QUV successor authority from its durable local install gate` event
and at least two further heights after restart. Process survival or workload
sync alone does not satisfy the test.

## Gate disposition

This slice closes the active-successor restart, pre-install restart,
state-before-anchor crash recovery, explicit rollback restoration,
source-substitution, missing-gate-after-expiry, retired-old-key,
operator-ceremony, and overlapping/disjoint-root obligations. Any future
post-retirement observer role still requires separately rooted observer
credentials; the tested old validator key correctly regains no authority.

The executor-to-members-to-T10 obligation is closed by code commit
`bd1e91a6d`; see `m15q-quv-executor-t10-local-evidence-2026-09-04.md`.
Accordingly M15Q is complete locally and M16Q becomes the sole critical path.
Fresh M17Q review has not begun. `portable_final_receipt=false` remains
mandatory.
