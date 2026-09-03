# Distinct collateral floor model

`DistinctCollateralFloor.tla` is the bounded M6 model for the economic-
assurance verifier. It checks that only eligible lots enter the floor, each
underlying lot contributes at most once, and duplicate/ineligible submissions
cannot increase the reported amount.

The Rust verifier additionally checks exact configuration ownership, member
coverage, native asset and slashing-contract equality, lock and challenge
horizons, encumbrances, withdrawal state, canonical arbitrary-precision
amounts, and exact claim recomputation. Silence and withholding are refused as
unpriceable inputs.
