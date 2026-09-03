# M6 economic-assurance release-gate evidence — 2026-09-03

## Scope

This gate covers the offline-verifiable minimum distinct slashable collateral
implicated by objective accountability evidence. It does not price withholding,
token value, corruption supply, acquisition cost, or configuration capture.

## Implemented surface

- `AccountabilityEvidenceV1` binds the exact configuration, signed-fault
  behavior and predicate, transferable evidence commitment, implicated member
  set, and challenge horizon.
- `BondSnapshotV1` roots canonically ordered bonds including unique bond and
  underlying-lot identities, owner, asset, amount, exclusive configuration,
  lock interval, challenge horizon, predicate, contract, encumbrances, and
  withdrawal state.
- `EconomicAssuranceVerifierV1` independently recomputes the snapshot root,
  distinct collateral-set root, arbitrary-precision base-unit sum, member
  coverage, minimum lock horizon, and complete claim.
- `VerifiedEconomicAssuranceV1` is opaque and is the only path that attaches a
  collateral coordinate to `VerifiedGuaranteeV1`.
- `GuaranteeRequirementsV1` supports an exact-asset minimum floor; policy joins
  take the arbitrary-precision maximum only for matching assets.
- Optional valuation/oracle assumptions are committed and validity checked but
  never alter the native-unit floor.

## Adversarial and negative evidence

The focused corpus rejects:

- duplicate bond identifiers and duplicate underlying collateral lots;
- shared configuration assignments;
- unlocked or challenge-horizon-expired bonds;
- active encumbrances and pending withdrawal;
- unimplicated owners or missing implicated-member coverage;
- mixed assets and slashing contracts;
- mismatched predicates, forged amounts, and stale valuation assumptions;
- withholding/silence as an unpriceable behavior.

Mutation calibration changed the underlying-lot insertion guard to an
always-false branch. The duplicate-lot test failed with exit 101, returning a
claim mismatch instead of the required duplicate-lot refusal. The clean guard
was restored.

## Formal evidence

`DistinctCollateralFloor.tla` checks that only eligible lots enter the counted
set, a lot contributes at most once, and rejected duplicate/ineligible
presentations cannot change the floor.

```text
33 states generated, 8 distinct states found, depth 4
Model checking completed. No error has been found.
```

The formal census passes with 39 modules: 26 executed and 13 explicitly
manual-discharge modules.

## Verification commands

```text
cargo test -p ioi-types economic_assurance --lib
cargo test -p ioi-types --lib
java -cp .internal/formal-cache/tools/tla/tla2tools.jar tlc2.TLC -cleanup -deadlock -config DistinctCollateralFloor.cfg DistinctCollateralFloor.tla
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/check_aft_theorem_assumes.sh
bash .github/scripts/check_aft_claim_discipline.sh
cargo fmt --all -- --check
git diff --check
```

Focused economic-assurance result: 7 passed, 0 failed. Authoritative complete
types-library result: 458 passed, 0 failed in 654.21 seconds.

## Claim boundary

T11 establishes an evidence-qualified native collateral floor and pairs with
L-C. It does not close T8's cheapest-capture/supply lower bound. Withholding and
silence remain unpriced unless a future mechanism supplies independently sound
evidence for that exact behavior.
