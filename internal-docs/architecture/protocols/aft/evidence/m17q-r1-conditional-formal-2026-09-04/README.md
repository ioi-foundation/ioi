# Conditional formal kernels — 2026-09-04

Status: existing conditional kernels revalidated; R1 finding 005 remains OPEN.

The mandatory targeted runner phases passed from this dirty development tree:
TLAPS discharged all 75 obligations in QueryUnanimityProof and all 16 in
QueryUnanimityCompositionProof. TLC checked the abstract T10
AtMostOnceExternalization model: 66 generated states, 42 distinct states,
search depth 8, no error. Source hashes, exact commands, exit codes, times,
raw logs, tool versions, and core tool artifact hashes are retained here.

These proofs assume the snapshot/admission/mutation premises named in their
modules. They do not prove the runtime establishes those premises. The T10
model is bounded and assumes its durable call-issued state; this run is not
runtime crash/refinement evidence. Durable expected-head advancement,
authenticated recovery, process-local continuation consumption, handoff and
production T10 transition refinement remain open. The prior local consequence
and process work does not turn these conditional proofs into an end-to-end
implementation theorem. Full clean R2 and fresh independent review remain
required; portable_final_receipt=false remains fixed.
