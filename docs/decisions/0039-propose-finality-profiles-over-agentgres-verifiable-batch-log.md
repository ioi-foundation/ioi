# ADR 0039: Propose Finality Profiles Over The Agentgres Verifiable Batch Log

- Status: Proposed — design only; no runtime authority change
- Date: 2026-08-28
- Owners: Agentgres / ordering and finality / wallet.network authority
- Refines if accepted: ADRs 0003 and 0038 and the ordering/finality profiles
- Confidence: supported for review by the M04.9 parity experiment; not accepted
  architecture and not implementation authority

## Context

The M04.9 experiment compared the current one-validator AFT authority path with
the existing immediate Solo path through the same wallet admission, execution,
IAVL state, Redb durability, receipt, restart, and authority abstractions. Six
release-mode runs independently configured ordering profile, scheduler ticker
plus genesis block floor, and polling interval with provenance. Every run
accepted the same 27-operation target-scope sequence, passed 15/15 fail-closed
semantic checks, and reproduced all nine room-child families after restart with
status/operations/latest sequence `200/21/20`.

The descriptive run-level client medians were Solo/AFT 907/1,481 ms at the
1,000 ms scheduler/block configuration with 25 ms polling, 106/1,324 ms at the
100 ms configuration with 25 ms polling, and an effectively null 1,003/1,004
ms at the 1,000 ms configuration with 500 ms polling. The first pair's
ordering/finalization medians were 48/60 ms. Independent fresh chains produced
different depth/version sample mixes, and depth-matched buckets do not preserve
all aggregate comparisons. Proposal wait and event-driven transaction
completion are not separately measured, realized proposal spacing was
unavailable, and the client phase is polling-quantized. These values are
descriptive rather than matched causal estimates. Semantic and restart parity,
not an uncontrolled latency delta, establishes sufficient grounds to review
single-authority ordering as a deployment profile rather than a second spine.

The fixture has one validator and exercises no cross-node ordering. It says
nothing about either engine with peers and does not qualify the replicated,
witnessed, AFT-with-peers, or external-finality profiles proposed below. Those
profiles require their own parity, fault, and transition evidence.

ADR 0038's AFT repair remains valid. The pre-repair quadratic canonical-collapse
rewalk was a usage defect, not an inherent BFT cost. AFT is still the control
and remains necessary wherever mutually distrusting authority owners require
shared finality. Latency alone does not authorize deleting or demoting it.

Agentgres already defines one operation-backed domain-truth spine. The design
question is therefore how that spine can express different ordering and
finality obligations without changing the state, receipt, replay, or authority
contracts underneath it.

## Proposed decision

If accepted after adversarial review and implementation evidence, Agentgres
will expose ordering/finality as a versioned deployment profile over one
cryptographically agile append-only batch log. This ADR is only a proposal. It
does not select a default, change any running path, or authorize a migration.

### One log and one authority spine

Agentgres remains the only durable operation-ordering spine. Each atomic batch
checkpoint must bind:

- the exact inclusive operation range and corresponding individual-receipt
  range;
- the preceding checkpoint identifier;
- the resulting state-map root and state version;
- the receipt root and receipt algorithm/version; and
- the ordering/finality profile and version that authorized the batch.

Batching may amortize append, root-construction, signing, and fsync work only
when every operation retains an individually verifiable authority receipt and
the recovery and ACK boundary remains atomic. No ACK may precede the required
append, state root, individual receipt, and durable linearization point for the
selected profile.

Content-addressed storage may hold immutable payload bytes referenced by the
log. CAS does not order operations, establish freshness or revocation, resolve
conflicts, or become authority. A missing or mismatched payload fails closed.

### Versioned finality certificates

The batch-checkpoint envelope may carry a versioned finality certificate with
one of these profiles:

1. `single_authority`: one admitted authority signer orders and durably commits
   the batch;
2. `replicated_cft`: replicas under one authority root provide crash-fault
   tolerance and availability;
3. `witnessed_threshold`: independent witnesses or a threshold policy attest
   to a checkpoint under an explicit witness contract;
4. `aft`: mutually distrusting validators establish adversarial finality; or
5. `external_finality`: an explicitly named external system finalizes the
   checkpoint under a versioned verifier contract.

Every profile uses the same Agentgres operation log, state abstraction,
individual receipt semantics, restart/replay rules, and one-spine ownership.
Changing profiles must be an admitted log operation with an unambiguous
cutover; no dual-authority interval is allowed. The current AFT path remains
the preserved control until a separate accepted decision and implementation
gate authorize any deployment default.

### Obligations remain separate

A checkpoint or finality certificate answers only its declared ordering and
finality claim. Protocols and verifiers must separately identify and prove:

- inclusion of an exact operation or receipt;
- consistency with the preceding admitted history;
- freshness relative to an accepted observation or witness policy;
- revocation status at the claimed state version;
- correctness of authority admission;
- payload availability and content integrity; and
- fail-closed cross-scope proof consumption and adjudication.

A signed head alone does not prove non-equivocation, freshness, revocation
status, admission correctness, or present authority. Witnessing can contribute
to a non-equivocation or freshness policy only when the witness set, quorum,
observation rules, and failure behavior are explicit and verifiable.

### Receipt compatibility and portable proofs

`ReceiptCheckpoint` v1 remains the linear
`ioi.receipt-hash-chain-jcs-sha256.v1` contract. This proposal does not silently
replace it with a Merkle tree or change `ReceiptProofBundle` v1.

A versioned successor that carries batch inclusion, history consistency, state
root, and finality-certificate material is the natural portable-proof follow-on.
It requires an offline verifier and adversarial fixtures before admission. It
is not implemented by this ADR, and it is not the already-implemented M03.5
portable v3 authority-grant verifier.

Cryptographic agility applies to hashes, signatures, receipt roots, and
certificate verification through the repository's existing crypto ownership
boundaries. No specific replacement state tree or proof system is selected.

## Evidence and gates before acceptance

The proposal may advance only after all of the following are mechanized:

- exact crash points around append, batch/root construction, state update,
  receipt creation, certificate signing, and fsync;
- deterministic recovery that either admits the whole checkpoint or none of
  it, with no ACK before durable recovery can reproduce the result;
- rejection of stale, missing, forged, reordered, replayed, and conflicting
  checkpoint, receipt, payload, state, and finality evidence;
- an event-driven transaction completion identity or an explicit decision to
  retain polling, with the two costs measured separately;
- repeated release-host baselines and a planted-delay mutation before any
  numeric latency tripwire;
- profile transition tests proving there is no dual-authority interval; and
- portable verification fixtures for every claim a successor proof bundle
  makes.

The M04.9 evidence is recorded in
[`m04-9-ordering-finality-parity-profile.v1.json`](../architecture/_meta/evidence/m04-9-ordering-finality-parity-profile.v1.json).
It supports proposing this direction, not accepting it.

## Options explicitly not reopened

JMT remains stopped until incremental commit, proof, persistence/restart,
pruning, and historical-anchor parity are proven through `StateManager`.
Fractal partitioning remains stopped until measured need and fail-closed
cross-partition proof consumption plus adjudication exist. Neither option is a
prerequisite for finality profiles, and this proposal grants neither option
implementation authority.

## Consequences if accepted later

- Deployments could match finality work to the trust relationship while
  retaining one Agentgres history and one receipt/state contract.
- AFT would remain available for mutually distrusting owners without imposing
  it as an unreviewed requirement on single-authority deployments.
- Checkpoint batching could amortize durability work without converting a
  batch root into the only user-visible receipt.
- Portable verification would gain explicit, separable claims instead of
  treating a signature as proof of current authority.
- The certificate and proof versioning surface would add protocol complexity
  and require migration, compatibility, and downgrade-resistance evidence.

## Rejection and reversal

Rejecting this proposal leaves ADR 0038 and the current AFT control unchanged.
If it is later accepted, any deployment-profile change remains reversible only
through an admitted transition operation whose recovery and finality rules are
defined by the then-accepted protocol. No implementation may cite this
Proposed ADR alone as authority to change the runtime spine.
