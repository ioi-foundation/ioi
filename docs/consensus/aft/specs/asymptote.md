# Asymptote

`Asymptote` is the scalable two-tier finality mode in the Aft Fault
Tolerance family.

## Core Idea

`GuardianMajority` remains the hot path for ordering and base block commitment.
`Asymptote` adds a second sealing plane that upgrades a slot from `BaseFinal` to
`SealedFinal` without changing the underlying block identity.

The model is:

- `BaseFinal`: validator majority QC plus guardian committee certificate.
- `SealedFinal`: `BaseFinal` plus either:
  - stratum-scoped witness certificates, registry state, and transparency-log proofs, or
  - equal-authority observer certificates sampled from the validator set plus veto-collapse
    semantics and transparency-log proofs.
- irreversible effects can additionally carry a proof-carrying `SealObject`
  that binds the committed intent, guardian slot metadata, policy hash, and a
  replay-safe nullifier into a compact verifier-friendly envelope.

This keeps chain progression fast while reserving stronger settlement guarantees
for irreversible effects.

## Slot States

- `Pending`
- `BaseFinal`
- `Sealing`
- `Abort`
- `SealedFinal`
- `Escalated`
- `Invalid`

All honest nodes must derive the same state from the same admissible evidence.

## Evidence Collapse

The slot-local collapse function is implemented as deterministic verification of
the canonical evidence set:

- guardian quorum certificate
- validator QC
- witness certificates or equal-authority observer certificates
- registry policy and epoch seed
- transparency-log checkpoints and append-only proofs
- optional divergence or veto signals

The runtime accepts `BaseFinal` blocks immediately for throughput. It then
collects sealing evidence asynchronously and republishes the same block with a
`sealed_finality_proof` once either:

- the required certification strata have each contributed a valid witness certificate, or
- every sampled equal-authority observer assignment has contributed a valid `ok` certificate and
  no valid veto proof exists.

For the equal-authority observer path, the collapse rule is intentionally
veto-dominant:

- `SealedFinal` if `BaseFinal` holds, the deterministic observation round is complete,
  every sampled observer assignment returned a valid `ok` certificate, and no valid
  veto proof exists.
- `Abort` if any valid veto proof exists for the slot.
- `Pending` otherwise.

This keeps slot effects deterministic: ambiguity collapses to `Abort`, not to
heuristic retry or partial settlement.

## Witness Assignment

Witness committees are selected deterministically per required certification
stratum from the active witness set by combining:

- epoch seed
- producer account id
- slot `(height, view)`
- reassignment depth
- witness stratum id
- witness manifest hash

Assignments are unique and ordered. `Asymptote` requires one committee per
configured certification stratum on the sealing path.

Equal-authority observer assignments are selected deterministically from the
active validator set by combining:

- epoch seed
- producer account id
- slot `(height, view)`
- observer round
- observer account id

The producer is excluded from its own observer pool. Observer assignments are
globally unique within the slot.

## Equal-Authority Veto-Collapse

The equal-authority path uses sampled validators as ephemeral observers. Each
sampled observer emits one guardian-backed verdict:

- `ok`
- `veto`

A `veto` is only admissible when it includes objective, locally verifiable
evidence such as conflicting guardian certificates or invalid log / checkpoint
bindings.

The implementation and proof surface treat the observer path as a deterministic
close-and-veto protocol:

- every sampled assignment must be accounted for in the `observer_close_certificate`
- an observer verdict is slot-scoped and assignment-scoped
- a valid veto proof dominates any candidate sealed effect for that slot
- a sealed effect is admissible only if the close certificate is complete and
  the admitted observer verdict set contains no veto

This keeps effects deterministic even when non-equivocation becomes messy:
ambiguity collapses to `Abort`, not to heuristic retry.

## Equal-Authority Theorem Shape

The machine-checked AFT formal model proves the deterministic part of the
equal-authority observer rule:

- base certificates are unique per slot
- sealed certificates are unique per slot
- a complete observer close certificate cannot coexist with an admissible veto
  for the same slot
- therefore no irreversible effect is released from a slot that contains a
  valid observer veto

The `99%`-style story is an analytical bound layered on top of that
deterministic kernel. Let:

- `h` be the honest fraction of equal-authority validators
- `A_s^j` be the sampled observer committee for slot `s` and round `j`
- `k_j = |A_s^j|`
- `p_beacon_bias` be the probability the slot-sampling beacon is biased enough
  to miss the intended observer distribution
- `p_veto_suppression` be the probability a valid veto proof is fully suppressed
  once an honest observer has it

Then the unsafe sealed-finality probability for slot `s` is bounded by:

```text
P_unsafe(s) <= p_beacon_bias * p_veto_suppression * Π_j (1 - h)^(k_j)
```

For equal committee size `k` repeated across `r` independent rounds:

```text
P_unsafe(s) <= p_beacon_bias * p_veto_suppression * (1 - h)^(k r)
```

The formal TLA+/TLAPS model proves the deterministic collapse and
abort-dominance rules. The probability bound above is the external sampling
argument that turns that deterministic kernel into a configurable `99%+`
compromise-resistance statement for sealed effects.

## Sealed Effects

The secure-egress control plane can now require a `FinalityTier` for each
effect:

- `BaseFinal`: fast path
- `SealedFinal`: requires a valid `SealedFinalityProof`

For proof-enabled irreversible effects, the guardian emits a `SealObject`
inside the canonical receipt. The current reference implementation uses a
`HashBindingV1` proof family:

- `EffectIntent` commits the external effect before execution
- `EffectPublicInputs` bind the committed guardian counter, trace, measurement,
  and replay nullifier
- `EffectProofEnvelope` is a compact verifier-specific proof blob
- `SealObject` packages verifier metadata, canonical intent, public inputs, and
  proof bytes

This keeps the ordering lane sparse while allowing every validator or gateway
to verify the same small effect seal locally.

High-risk effects are expected to require `SealedFinal` under the configured
epoch policy.

## Policy

The on-chain `AsymptotePolicy` controls:

- required witness strata
- escalation witness strata
- equal-authority observer rounds
- equal-authority observer committee size
- max reassignment depth
- checkpoint freshness
- finality tier for high-risk effects

## Non-Claim

`Asymptote` should be described as:

- deterministic evidence collapse over layered cryptographic witnesses
- high-confidence resistance to undetected conflicting finalization

It should not be described as a classical unconditional “99% Byzantine fault
tolerance” theorem.

It is instead:

- a deterministic equal-authority observation-and-collapse protocol for sealed effects, plus
- an explicit probabilistic bound that depends on honest observer sampling,
  veto availability, and veto deliverability.
