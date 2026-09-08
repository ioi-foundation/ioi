# Typed-refusal process rerun: FAILED

The frozen local source passed all four sole-correct placements. Saturation
then returned an executed receipt whose configured/responding member coverage
differed from the exact expected sets. The harness failed rather than treating
partial coverage or arbitrary failure as qualification. Conflict and unrelated
cases were not reached. The raw log did not identify which member was absent
or whether configuration/duplicate checks caused the mismatch; that diagnosis
remains open. The source and log hashes matched at terminal verification.

This is a qualification failure, not a counterexample establishing that the
interactive target is impossible. In particular, end-to-end timely reachability
and reply delivery under the restart/saturation schedule have not been
established. The previous passing run does not override this result. Exact
coverage must remain required. Diagnostic changes and a new attributable run
are needed before attributing a cause or proposing a timing/admission repair.
