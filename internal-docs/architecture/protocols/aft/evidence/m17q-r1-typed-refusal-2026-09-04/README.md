# Typed QUV conflict refusal — 2026-09-04

Status: local regressions/default build passed; process rerun FAILED; finding 004 remains OPEN.

The completion channel now carries anyhow errors while preserving the typed
QUV cause. The public RPC maps only QuvError::ConflictDisclosed to Aborted with
`ioi-quv-refusal: conflict-disclosed-v0`. Other failures remain FailedPrecondition
without that marker. The campaign requires both code and marker and never
classifies message text. This is a diagnostic signal, not conflict proof or
portable authorization. Internal executors and handoff also retain typed errors.

The client assertion regression passed, including context-wrapped typed status,
same-text ordinary errors, absent/unknown markers, and wrong codes. Server
mapping and default-feature checks are recorded in checks.json as they finish.
The server regression distinguishes actual typed conflict (including context)
from no-valid-replies, ordinary same-text errors, and an I/O error containing
that text. The full M16Q runner now includes both regressions.

The earlier development process campaign passed with message-based refusal
classification. Its result is retained in the adjacent production-participation
bundle and does not qualify this changed candidate. A full process rerun,
remaining mutation/refinement/load gates, clean R2, and independent review of
the final immutable candidate are still required. No finding is closed.

## Feature-gate repair

The first server/client regressions passed, but default-feature compilation
failed because the helper had an explicit consensus-aft gate while its RPC
caller is unconditional. That failure and its source hashes remain in
checks.json/default_validator.log. The helper now follows its caller's
compilation scope; its test is available in all test builds. Results for this
repair are recorded separately in checks-cfg-repair.json and corresponding logs.
This does not introduce an additional consensus dependency or authority path.

All three feature-gate repair checks passed. The fresh production campaign
and completeness check are running in `process-rerun/`; no terminal process
result is claimed until its command and checker both finish successfully.

## Saturation qualification failure

The fresh process run terminated with failure: four sole-correct cases passed,
but saturation returned a receipt with incorrect expected member coverage.
Its evidence is in process-rerun/. A diagnostic rerun is active in
process-diagnostics/, using unchanged coverage assertions and richer error
output (effect, expected/observed members, counts, and reply timings). Neither
the earlier pass nor a subsequent intermittent pass may disposition this
unexplained failure. Full correct-member reachability/delivery under the
restart/saturation schedule remains unqualified.

The enriched-error repetition subsequently passed, including one accepted
conflict effect and one structured rejection with one durable record. Because
no transport/scheduling rule changed, this does not resolve the earlier
failure. A new run in process-transport-diagnostics/ enables explicit
quv/network diagnostics; its logging cost precludes treating it as performance
admission evidence. The recorded failure remains an open qualification issue.
