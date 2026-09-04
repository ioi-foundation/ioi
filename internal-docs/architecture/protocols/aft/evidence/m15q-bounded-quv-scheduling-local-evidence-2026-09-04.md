# M15Q bounded QUV scheduling — local evidence

Date: 2026-09-04

Status: local implementation evidence only. This does not close Q-A9, M15Q, or
M16Q and does not authorize a production or public timing claim.

## Implemented boundary

The `aft_quv_v0` runtime now isolates timing-critical work from ordinary node
traffic in both directions:

- a dedicated bounded swarm-command lane carries operation begin/end,
  `PUSHQUERY`, replies, and ingress-slot completion;
- a dedicated bounded network-event lane feeds a separate validator task;
- the verifier's `delta_rt` interval begins only after the swarm acknowledges a
  fresh operation-scoped reply-admission epoch;
- at most one push per authenticated rooted requester occupies member work;
- at most the first authenticated reply per rooted member is admitted during
  one live verifier operation;
- one executor operation may be live per process;
- configured QUV membership is capped at 1,024 members in v0;
- the durable PQ outbox preserves 1,024 normal slots plus two QUV-reserved
  slots per recipient and selects QUV before older normal traffic; and
- QUV traffic remains strict-PQ-only and configuration scoped.

The event channel has capacity `2n_max`; the command channel has capacity
`3n_max + 2`: one outbound query per member, one reply and one ingress-slot
completion per concurrently admitted requester, and begin/end control. With
one admitted request and reply per rooted identity, local queue occupancy is
finite. A correct member emits one valid reply, so ignoring
later duplicates from one Byzantine identity does not weaken Q-S1. M16Q must
still measure the complete request, durable processing, response, and clock
envelope under adversarial load before Q-A3/Q-A9 can be marked qualified.

## Reproduced checks

The following passed from the repository root after formatting:

```text
cargo check -p ioi-networking
cargo check -p ioi-validator
cargo check -p ioi-node --features validator-mode,validator-bins --bin ioi-validator --bin orchestration
cargo check -p ioi-node --features local-mode --bin ioi-local
cargo check -p ioi-node --features provider-mode --bin ioi-provider
cargo check -p ioi-node --features bridge-mode --bin ioi-bridge
cargo test -p ioi-networking protected_payload_routes_only_after_aead_and_type_agreement -- --nocapture
cargo test -p ioi-networking quv_uses_reserved_priority_ahead_of_normal_consensus_outbox -- --nocapture
cargo test -p ioi-networking --lib
cargo test -p ioi-consensus --features aft --lib aft::query_unanimity::tests
```

Observed targeted results:

- authenticated protected-payload routing and duplicate push/reply admission:
  1 passed;
- QUV reserved-priority durable outbox: 1 passed;
- full networking unit suite: 15 passed;
- QUV protocol unit suite: 8 passed;
- all five node binary/profile checks above completed successfully.

Warnings were pre-existing generated naming, unused import, and dead-code
warnings; no new error or test failure remained.

## Remaining gate work

1. Build a real multi-process executor-to-members-to-Agentgres scenario and
   demonstrate that no irreversible call begins from a cached transcript.
2. Implement and exercise Q-EA7 live-overlap reconfiguration before old-root
   expiry.
3. Run M16Q saturation and adversarial timing campaigns. Measure the oldest
   normal request already in flight, PQ handshake/session readiness, durable
   storage latency, scheduler delay, response delivery, and clock skew inside
   the provisioned `delta_rt`.
4. Fail closed if the measured deployment envelope cannot satisfy the rooted
   bound; never downgrade to an offline or portable certificate.
