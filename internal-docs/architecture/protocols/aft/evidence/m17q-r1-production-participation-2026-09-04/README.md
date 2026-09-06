# R1 production participation and resource checks — 2026-09-04

Status: local process validation passed; finding 004 remains OPEN.

The production campaign already compares exact configured and responding
member sets, including duplicate refusal, for every accepted sole-correct,
saturation, conflict, and unrelated-domain operation. The conflict case now
also reads each executor's actual durable external register before and after
both requests. Fixtures must start without records. Rejected effects must
remain absent; accepted effects must have the exact admitted manifest and a
stored record equal to the receipt, with valid endpoint evidence. These checks
observe durable register outcomes; they are not instrumentation proving that
no transient invocation occurred.

`check.json` records the exact command, dirty base and source/lockfile hashes.
`process.log` retains the running campaign's raw output. A missing exit code
means no terminal result has been recorded. This is a local development run,
not clean full M16Q R2 qualification.

The existing conflict helper still matches an error message, not a structured
protocol refusal code. That remains a qualification gap even if this run
passes. Full process mutation coverage, transition refinement, timing/load
qualification, clean R2, and immutable-candidate independent review remain
required. No finding is closed by these added assertions alone.

## Runner completeness gate

`check_aft_m16q_process_evidence.py` now requires four distinct sole-correct
member/process placements, four completed saturation operations, bounded reply
observations, both conflict outcomes with durable resource assertions, and an
executed unrelated-domain operation. It also requires the process test to have
completed without failure or being ignored. The runner retains its JSON result
and input-log hash. Two complete synthetic fixtures pass and 21 missing,
duplicate, mistimed, or inconsistent fixtures are rejected. These are parser
tests, not production qualification or cryptographic validation of log text.
The process test's exact member-set and endpoint-evidence assertions remain
necessary. Full R2 must run both the process test and this completeness gate.

## Prepared follow-up, not applied

`prepared-typed-refusal.patch` preserves the verifier's typed error through the
completion channel, maps only `QuvError::ConflictDisclosed` to an Aborted RPC
status with `ioi-quv-refusal: conflict-disclosed-v0`, and makes the campaign
check that structured status. Other boundary failures remain distinct.
This marker is diagnostic, not authority or a transferable conflict proof.
The patch was formatted and passed `git apply --check`; it has not been applied,
compiled, or qualified. Its JSON records the source preimages and patch hash.
Server/client positive and negative regressions are now included in the
prepared patch: typed conflict, same-text ordinary errors, absent/wrong markers,
and wrong status codes. They have not run. Apply and validate the follow-up
after the current run reaches a recorded terminal result.

## Recorded local result

The single selected process test passed. All four sole-correct placements
executed (latest valid replies 253–259 ms); all four saturation operations
executed (maximum 2458 ms), within the declared 4000 ms reply envelope. Both
concurrent conflicting effects were rejected with zero durable records; the
unrelated effect then executed. The completeness checker passed against this
exact log, and source/log hashes matched before the follow-up was applied.
This run still used message-based conflict classification. It does not qualify
the subsequent typed-refusal patch, sustained flooding, runtime refinement,
or full clean R2. It does not count the two rejections as effect liveness.

After that terminal result was retained, the prepared typed-refusal patch was
applied. Its separate validation is in `../m17q-r1-typed-refusal-2026-09-04/`.
Prepared status statements above describe its state before that application.
