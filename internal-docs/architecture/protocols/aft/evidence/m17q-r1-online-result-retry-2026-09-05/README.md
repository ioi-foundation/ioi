# Online same-effect result retries — local validation passed

Both production entry points rederive committed admission, check exact candidate
binding, then handle existing outcomes before starting live QUV. Authorized and
Claimed still need a fresh operation. InFlight and Unknown use lookup-only
reconciliation. Executed and Reconciled return the unchanged recorded receipt
only when current resource lookup exactly matches its recorded result (including
absence). Lookup ambiguity or mismatch refuses the result without rewriting the
receipt or calling the resource mutation operation. Absence is not execution.

Admission comparison now accepts every receipt phase only when manifest,
achieved guarantee and initial authorization evidence exactly match today's
independently derived admission. Execution eligibility remains restricted to
Authorized/Claimed. The result-only path never consumes a continuation, supplies
new mutation authority, or converts its audit into a portable final receipt.

Current admission fences still apply to retries. Result retrieval after fence
expiry and queue-wide fairness remain open; no broader availability claim is
made. Durable storage/authentication and the resource contract remain assumptions.

The initial local suite passed after fixing a test-only non-Clone binding error.
A preliminary process run was deliberately interrupted during compilation after
review identified the need for terminal resource lookup validation. Its logs and
explicit interruption remain under process/. This is not a qualification failure
or pass. The corrected source passed under validated-process/.

The new local regression covers successful execution, ambiguous mutation and a
before-call crash, readmission after reopen, changed admission and expired-fence
refusal, lookup-only reconciliation, unchanged terminal receipts, ambiguous
lookup and resource-state mismatch. The production campaign now repeats the
same RPC in each sole-correct placement and requires identical receipt bytes;
the checker requires all four replay assertions. All R1 findings remain open
pending complete qualification and immutable independent review.

The corrected consequence subset (19 tests), validator check, and full Agentgres
library suite (106 tests, zero ignored) passed. The production campaign and its mandatory evidence checker passed. All four
sole-correct placements returned byte-identical terminal receipts in 15–16 ms.
The concurrent workload passed exact member coverage, with a 2078 ms maximum
valid reply, a 193.032 ms verifier-start spread and 4806.968 ms of bounded common
overlap. Both conflicting requests received typed refusals and left zero resource
records; unrelated execution passed. All 24 recorded source hashes matched at
completion. These local results do not establish clean M16Q R2 or close R1.
