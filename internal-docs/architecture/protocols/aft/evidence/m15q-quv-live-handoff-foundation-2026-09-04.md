# M15Q QUV live-handoff foundation — local evidence

Date: 2026-09-04

Status: local implementation evidence only. The live Q-EA7 coordinator is now
implemented, but process-level reconfiguration qualification, the complete
effect path, M15Q, and M16Q remain open. This artifact does not authorize a
production claim.

## Implemented boundary

The QUV implementation now has a typed `QuvConfigurationHandoffV0` payload
that commits:

- the network and exact old configuration root;
- the complete canonical successor validator set and its ML-DSA keys;
- an adjacent old-authority expiry and successor activation height;
- the exact predecessor candidate;
- the final old-root state height and block hash; and
- the complete application state-root bytes.

The handoff domain is derived from the network, old root, successor root, and
activation height. The payload hash commits the whole transition. Structural
validation requires a sorted, nonempty-weight, all-ML-DSA successor set of at
most 1,024 members and requires both `state_height` and old-authority expiry to
equal `activation_height - 1`.

`DurableQuvHandoffV0` consumes the non-exportable process-local result of a
live QUV operation. Before installing, it checks the authorization's old root,
network, derived handoff domain, activation slot, predecessor, and payload hash
against the typed payload and checks the locally observed state height, block,
and root byte-for-byte. It then persists the exact transition behind a
separate custody-key-authenticated monotone anchor. Recovery permits activation
only for that exact local successor and transition. Replacing the installed
state with its valid pre-install image is detected as rollback.

Ordinary validator-set promotion is not a substitute for this operation. The
validator now refuses a changed QUV configuration at the pre-publication seam
and again before strict-PQ manager replacement. An unchanged root continues;
non-QUV profiles retain their existing rotation behavior. This is a temporary
fail-closed admission gate until the positive live-overlap coordinator is
implemented and qualified.

The strict-PQ session manager now also has a distinct handoff-only successor
capability. A receiver rooted in the old set admits only `QUV PUSHQUERY` from
such an identity; a pre-active successor admits only `QUV REPLY` from an old
configured member. Successor-to-successor records and every consensus,
fallback, ordinary effect, or reply sent by a successor-only endpoint are
refused after authenticated decryption and before dispatch. Reclassifying an
enrollment tears down its live session. This is transport confinement only;
canonical successor derivation and runtime orchestration remain required.

Startup now derives a pre-active successor role only from the canonical
`ValidatorSetsV1.next` value while the old set is still effective. The local
PQ endpoint account is separate from `local_validator_account_id`: a
successor-only process advertises and authenticates its staged ML-DSA account,
but has no local validator account, signing fence, hash-asynchronous journal,
QUV member store, vote, or proposal authority. Old members classify accounts
that exist only in the staged set as handoff-only; successors classify old
members as configured reply sources. An overlapping unchanged-key member stays
an old active member. An overlapping account whose key changes is refused
because the current account-key registry cannot authenticate both keys without
substitution risk.

The runtime configuration also names an optional
`aft_quv_handoff_source`: one canonical SCALE-encoded, owner-signed typed
handoff envelope. Configuration validation requires a nonblank source and an
independently provisioned QUV policy. The source bytes are explicitly not an
authorization receipt.

The runtime now loads that source from a bounded regular file, verifies its
canonical encoding, exact old and staged roots, provisioned policy, handoff
shape, and old-owner ML-DSA signature, and admits a staged request only when
its candidate equals the authenticated source. Before the final old-root
header is published, the source must also bind that exact block height, hash,
and state root. This check makes the source an authenticated candidate input;
it does not create authorization.

Each local successor runs its own nonce-fresh online QUV operation at the
source-bound state boundary, consumes the process-local result directly into
its rollback-anchored handoff store, reconstructs and verifies every successor
key from canonical state, and only then replaces the PQ manager, consensus
membership, signing fence, and durable QUV member service. The producer refuses
successor blocks until its locally installed PQ configuration equals the exact
effective root. Old-only finalizers retain old-root member service instead of
rotating on behalf of a successor.

Restart after installation is also fail-closed: a QUV transition remains
transport-rooted in `ValidatorSetsV1.current` even after `next` is effective,
and successor authority remains absent until the durable local gate is checked
against the canonical historical boundary block. If the tip has advanced, the
coordinator may recover an existing install but may not create a retroactive
online authorization. A missing, rolled-back, or mismatched gate therefore
cannot acquire authority by restarting.

## Reproduced checks

```text
cargo test -p ioi-consensus --features aft --lib aft::query_unanimity::tests
cargo test -p ioi-networking handoff_only_successor_is_cryptographically_connected_but_authority_isolated -- --nocapture
cargo test -p ioi-networking --lib
cargo test -p ioi-validator staged_pq_identity_has_transport_without_old_root_authority -- --nocapture
cargo test -p ioi-validator quv_post_activation_restart_stays_on_old_root_until_local_gate_recovers -- --nocapture
cargo test -p ioi-validator handoff_source_requires_old_owner_signature_and_exact_staged_set -- --nocapture
cargo test -p ioi-types quv_policy_requires_exact_authority_and_durable_roots -- --nocapture
cargo test -p ioi-validator quv_rotation_refuses_every_unqualified_configuration_change -- --nocapture
cargo test -p ioi-validator pq_rotation_is_preflighted_before_header_authority_or_durability -- --nocapture
cargo check -p ioi-validator
```

Observed QUV protocol result: 10 passed, including exact two-root/state
binding, process-local authorization consumption, restart recovery, and
external-anchor rollback detection. The networking library passed 16 tests,
including the handoff-only endpoint-capability matrix.

The validator library also passed all 251 tests after the coordinator was
added. Compiler output contained only the repository's existing warnings.

## Remaining Q-EA7 qualification obligations

1. Demonstrate source preparation and distribution before the exact final
   old-root header in the real multi-process fixture; the current file input is
   authenticated but operator-provisioned.
2. Demonstrate disjoint and overlapping successors executing their own live
   operation against all old members, including self-delivery for overlap.
3. Keep old-root member service reachable through the complete rooted
   request/durable-processing/response/clock interval and refuse activation if
   that interval or old-root expiry cannot be met.
4. Exercise restart before source load, during the online operation, after
   durable install, after manager replacement, and after the tip advances.
5. Exercise overlapping and disjoint sets, opposite-order conflicting
   handoffs, member restart, rollback, expiry edges, request flood, executor
   crash windows, and mixed-domain isolation in real processes.

The handoff transcript remains audit material only. It cannot replace the
process-local live operation or create portable finality.
