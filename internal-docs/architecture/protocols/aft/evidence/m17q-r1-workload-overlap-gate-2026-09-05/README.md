# Receipt-bound workload overlap gate — local validation passed

The production workload now emits verifier nonces extracted from its already
checked consequence audits. The full M16Q runner requires four distinct nonces
and exactly one accepted start/finish lifecycle for each in four retained
orchestration logs. Missing, duplicated, malformed, failed, reordered, or
nonoverlapping lifecycle evidence fails the gate. Start and finish must come
from the same component. The runner enables the required debug events explicitly.

This measures overlapping verifier intervals using same-host UTC logs. It is
not a protocol monotonic deadline proof, storage/queue saturation proof, or an
authorization input. Receipt/member and rooted reply-envelope checks remain in
the production test. Debug capture overhead remains a qualification cost.

The checker self-test covers one overlapping fixture and 23 negative fixtures,
in addition to the existing two positive and 21 negative campaign fixtures.
The production campaign passed; started.json and check.json bind its command
and sources. All four sole-correct placements and workload member coverage
passed. The latest valid workload reply arrived at 2232 ms. One conflict request
executed and one received a typed refusal; exactly one resource record existed,
and the rejected resource remained unchanged. Unrelated execution passed.

The original overlap checker passed, then review tightened interval accounting
to cap each end at start plus the declared 5000 ms. Rechecking the same raw logs
with that stricter checker passed: start spread 116.737 ms, common bounded
overlap 4883.263 ms. A negative fixture rejects delayed finish logs that would
otherwise manufacture overlap. bounded-overlap-checks.json binds this final
checker version and its results; the earlier checker outputs remain historical.
No historical raw evidence has been rewritten to contain the new nonce field.
The earlier missing-member failure remains unresolved, and no R1 finding or R2
admission is closed by this gate.
