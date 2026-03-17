# GuardianMajority

`GuardianMajority` is the production consensus mode in the Aft Fault Tolerance family.

Canonical prose specs:

- [`guardian_majority.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/guardian_majority.md)
- [`nested_guardian.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/nested_guardian.md)

It replaces the old single-device non-equivocation story with:

- per-validator guardian committees
- registered committee manifests
- threshold certificates for proposal slots
- anchored transparency-log checkpoints
- explicit registry and epoch state

## Core Safety Model

A proposal is only valid when:

- the producer carries a valid guardian committee certificate for the slot
- the committee manifest is registered for the active epoch
- the committee threshold is a strict majority
- registry and checkpoint state are current

In NestedGuardian mode, a valid witness committee certificate must also match the
deterministic on-chain witness assignment for the slot.

## Liveness Model

The protocol retains redundant gossip paths and deterministic leader/view progression, but
liveness is intentionally secondary to safety when guardian committees, registry state, or
required checkpoints are degraded.

## Accountability

Safety violations are attributable to certificate-level evidence:

- conflicting guardian certificates
- conflicting witness certificates
- stale-registry participation
- checkpoint inconsistency
