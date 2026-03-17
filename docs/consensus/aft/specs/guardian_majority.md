# GuardianMajority Fault Model

This document defines the production fault model for `AftSafetyMode::GuardianMajority`.

## Thought Experiment: The Republic of Inconvenient Paperwork

Imagine a republic where every city council loves issuing decrees and at least some of them are absolutely willing to contradict themselves before lunch. To keep the bureaucracy from eating itself, each council decree is only valid if three things happen:

- the council approves it
- the city's independent seal-keepers produce a threshold certificate for that exact decree
- the sealed decree is posted to the public gazette so everyone can later prove what was actually issued

Now a dishonest council tries the classic trick: publish two conflicting decrees for the same hour and hope different neighbors obey different papers. In this republic, that fails unless enough seal-keepers also misbehave to certify both versions, or the gazette and registry can be subverted badly enough that everyone reads a different official history.

That is the intuition behind Aft Fault Tolerance. We do not assume participants stop lying. We assume durable agreement emerges because every finalized statement must pass through overlapping certification thresholds and shared evidence that later verifiers can re-check.

## Scope

`GuardianMajority` is not classical `3f+1` BFT. It is a composed model:

- validator replicas still run the Aft deterministic message flow
- block proposals are additionally bound to a per-validator guardian committee
- a proposal is valid only if it carries a registered guardian committee certificate
- committee certificates use majority thresholds and non-equivocation assumptions at the guardian layer

The production claim is therefore:

> No two conflicting blocks can both finalize for the same `(height, view)` if registered guardian committees satisfy their threshold and non-equivocation assumptions, the registry state used for verification is current, and validators only finalize blocks carrying valid guardian certificates.

## Actors

- Validator: runs consensus, networking, state transition, and block verification.
- Guardian member: signs committee decisions for exactly one validator committee.
- Guardian committee: the registered `t-of-n` set protecting one validator.
- Registry: on-chain source of truth for committee manifests, epochs, and accepted policy roots.
- Transparency log: append-only witness log anchoring committee decisions and egress receipts.

## Safety Assumptions

### Validator faults

- Byzantine validators may send arbitrary blocks, votes, and view-change messages.
- A validator cannot cause a valid proposal in `GuardianMajority` without a guardian committee certificate that verifies against the current on-chain manifest.

### Guardian member faults

- Honest guardian members never sign two different payloads for the same consensus slot.
- The runtime enforces slot locking over `(height, view)` before issuing a committee certificate.
- For a committee with threshold `t` and size `n`, conflicting certificates for the same slot require enough equivocators to cover the minimum quorum intersection, so the executable bound is `f < 2t - n`.
- Consequence: odd-sized simple-majority committees (`n = 2k + 1`, `t = k + 1`) tolerate zero equivocating guardian members at the committee layer, while even-sized majority committees tolerate one.

### Committee threshold assumptions

- Production committees must use majority thresholds: `t = floor(n / 2) + 1`.
- Majority thresholds guarantee pairwise quorum intersection.
- The committee certificate verifier rejects:
  - wrong manifest hash
  - wrong epoch
  - wrong decision hash
  - signer indexes outside the manifest
  - duplicate signer indexes
  - insufficient signer count
  - invalid aggregated BLS signatures

### Registry and log assumptions

- Verifiers read the current committee manifest from chain state using `guardian_registry_committee_key(manifest_hash)`.
- Safety requires the manifest view used for verification to be current for the block epoch.
- The transparency log is an accountability layer, not a substitute for threshold safety. It proves issued decisions and supports slashing after the fact.

### Liveness assumptions

- Enough validators remain network-reachable to form consensus quorums.
- Enough guardian committee members remain reachable to satisfy the committee threshold.
- The registry state and witness-log checkpoints are eventually available to validators.

## What The Current Executable Model Checks

The production verification stack now has two executable layers:

- the Rust simulators in `simulator.rs` and `network_simulator.rs`
- the bounded TLA+ model in `formal/aft/guardian_majority/`

Together they confirm:

- majority quorums always intersect
- majority committees cannot produce conflicting certificates when the equivocating guardian budget is below the minimum quorum intersection `2t - n`
- odd-sized majority committees fail with a single equivocator, which means production safety must rely on stronger non-equivocation guarantees than thresholding alone for those committee sizes
- non-majority thresholds admit conflicts even without equivocation
- finalization remains slot-safe across epoch adoption, registry rollback, guardian outage, and checkpoint-admissibility state transitions in the bounded model

The formal surface for the production path is now split:

- `formal/aft/guardian_majority/GuardianMajorityProof.tla` proves the unbounded safety kernel in TLAPS.
- `formal/aft/guardian_majority/GuardianMajority.tla` model-checks richer bounded operational scenarios in TLC.

That means the production safety core is no longer only a bounded executable model. The remaining non-claim is liveness: the repository still does not claim a full asynchronous liveness proof under all registry, log, and outage schedules.

## Explicit Non-Claims

- This mode does not claim to "break `3f+1`" in the classical Byzantine model.
- This mode does not claim confidentiality of arbitrary computation against a hostile kernel or hypervisor.
- This mode does not yet prove unbounded liveness under registry rollback, transparency-log outage, or cross-provider common-mode bugs.
