# ADR 0045: Adopt Evidence-Qualified Economic Assurance

- Status: Accepted and implemented for the M6 offline proof boundary
- Date: 2026-09-03
- Owners: AFT assurance, accountability, collateral policy
- Refines: ADR 0041 guarantee-vector collateral coordinate
- Confidence: formal, negative, arbitrary-precision, and mutation gates pass;
  validator-supply economics remain outside the result

## Context

Attribution identifies parties implicated by objective fault evidence. It does
not establish that their nominal bonds are distinct, still locked, free of
other claims, governed by the same enforceable predicate, or valuable enough
to deter an adversary. Multiplying a configured bond amount by a signer count
can therefore double-count shared collateral and conceal expiry, encumbrance,
or oracle assumptions.

## Decision

### 1. Economic assurance is an offline proof, not a configured number

`EconomicAssuranceV1` is independently recomputed from transferable
accountability evidence and a committed `BondSnapshotV1`. It carries one
native asset and exact amount, configuration and collateral-set commitments,
snapshot root and height, lock and challenge horizons, evidence predicate,
slashing-contract identity, and optional visible valuation assumptions.

### 2. Only distinct, fully eligible lots count

Every bond and underlying collateral identifier must be unique. Every counted
lot must belong to a member named by the evidence, be exclusively bound to the
implicated configuration, accept the exact objective predicate under the same
slashing contract, be locked through the challenge horizon, and have no
withdrawal or active encumbrance. All implicated members require coverage.
Different native assets are never summed.

### 3. Silence has no price

Withholding or absence of a signature is not objective slashing evidence and
produces no collateral floor. A separate future mechanism may price a behavior
only if it supplies sound, transferable evidence for that exact behavior.

### 4. Policies consume an opaque verified coordinate

The verifier recomputes arbitrary-precision base-unit sums and requires the
entire claimed assurance to match. Only its opaque output can add the
collateral coordinate to `VerifiedGuaranteeV1`. Policies name an exact asset
and minimum amount; joins take the higher amount only for the same asset and
refuse cross-asset comparison.

## Consequences

- AFT can state T11: an exact evidence-qualified distinct collateral floor.
- T9 now states maximal attribution without manufacturing an `n × bond`
  monetary claim.
- Oracle assumptions are portable and visible but never inflate the native
  amount established by the proof.
- T8 remains open. T11 says nothing about token value, adversarial acquisition
  cost, bribery, liquidity, validator supply, or configuration-capture
  probability.

## Rejected alternatives

### Sum configured bonds by signer count

Rejected because shared, reused, expired, withdrawn, or encumbered collateral
can make the nominal sum uncollectible.

### Convert mixed assets through an implicit spot price

Rejected because the oracle and validity horizon would become hidden theorem
premises. Native proofs remain separate; optional valuation metadata is
explicit.

### Price withholding from a timeout

Rejected because delay, loss, crash, and malicious silence are observationally
indistinguishable under the protocol's asynchronous paths.
