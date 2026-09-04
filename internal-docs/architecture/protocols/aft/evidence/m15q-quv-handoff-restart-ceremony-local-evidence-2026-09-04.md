# M15Q QUV handoff restart and ceremony — local evidence

Date: 2026-09-04

Status: **PASS for the post-install process-restart and operator-ceremony
slice at commits `252e03573` and `fc7c9b926`; M15Q remains open.** This is local implementation
evidence, not independent review or a production/public QUV claim.

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

cargo check -p ioi-validator \
  --features consensus-aft,vm-wasm,state-iavl

RUST_TEST_THREADS=1 cargo test -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_quv_disjoint_successors_install_live_handoff_before_activation \
  -- --nocapture

cargo check -p ioi-cli --lib --bin cli
cargo run -q -p ioi-cli --bin cli -- aft quv-handoff --help
git diff --check
```

Observed results:

- rollback-anchored install/recovery test: 1 passed;
- validator compile: pass;
- eight-process release handoff/restart positive test: 1 passed in 417.21
  seconds at `252e03573`;
- expanded eight-process positive/negative restart matrix: 1 passed in 267.93
  seconds at `fc7c9b926`; this includes source-signature substitution, a missing
  state/anchor half after expiry, and retired-old-key refusal;
- CLI library/binary compile and command-surface smoke: pass; and
- formatting/diff check: pass.

The process assertion requires both the explicit
`Recovered QUV successor authority from its durable local install gate` event
and at least two further heights after restart. Process survival or workload
sync alone does not satisfy the test.

## Remaining M15Q work

This slice closes the active-successor restart, source-substitution,
missing-gate-after-expiry, retired-old-key, and basic operator-ceremony cases.
M15Q still requires:

- fail-closed process restarts during the pre-install/in-flight durable
  boundaries, explicit rollback-image restoration, and the overlapping-root
  case;
- any future post-retirement observer role to use separately rooted observer
  credentials; the tested old validator key correctly regains no authority.

The executor-to-members-to-T10 obligation was subsequently closed by code
commit `bd1e91a6d`; see
`m15q-quv-executor-t10-local-evidence-2026-09-04.md`.

M16Q and fresh M17Q review have not begun. `portable_final_receipt=false`
remains mandatory.
