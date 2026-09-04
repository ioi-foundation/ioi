# M15Q QUV live-handoff foundation — local evidence

Date: 2026-09-04

Status: local implementation evidence only. Q-EA7, M15Q, and M16Q remain
open. This artifact does not authorize configuration rotation or a production
claim.

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

## Reproduced checks

```text
cargo test -p ioi-consensus --features aft --lib aft::query_unanimity::tests
cargo test -p ioi-networking handoff_only_successor_is_cryptographically_connected_but_authority_isolated -- --nocapture
cargo test -p ioi-networking --lib
cargo test -p ioi-validator quv_rotation_refuses_every_unqualified_configuration_change -- --nocapture
cargo test -p ioi-validator pq_rotation_is_preflighted_before_header_authority_or_durability -- --nocapture
cargo check -p ioi-validator
```

Observed QUV protocol result: 10 passed, including exact two-root/state
binding, process-local authorization consumption, restart recovery, and
external-anchor rollback detection. The networking library passed 16 tests,
including the handoff-only endpoint-capability matrix.

## Remaining Q-EA7 obligations

1. Define and implement the canonical source of the owner-signed handoff
   candidate; it may not be synthesized from silence or inferred from a
   validator-set update.
2. Derive and enroll successor identities into the implemented handoff-only
   strict-PQ capability from canonical staged membership.
3. Let successor-only processes query every old member and self-deliver only
   when they also belong to the old set.
4. Keep old-root member service reachable through the complete rooted
   request/durable-processing/response/clock interval and refuse activation if
   that interval or old-root expiry cannot be met.
5. Install the complete state and predecessor before enabling any successor
   vote, proposal, QUV reply, or irreversible effect authority.
6. Exercise overlapping and disjoint sets, opposite-order conflicting
   handoffs, member restart, rollback, expiry edges, request flood, executor
   crash windows, and mixed-domain isolation in real processes.

The handoff transcript remains audit material only. It cannot replace the
process-local live operation or create portable finality.
