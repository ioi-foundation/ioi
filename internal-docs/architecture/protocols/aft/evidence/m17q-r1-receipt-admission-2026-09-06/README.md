# Receipt admission and v7 profile evidence

The scoped collector passes on unchanged selected source hashes in started.json
and sources/. It ran 84 QUV core tests (one separately qualified benchmark
excluded), eight profile tests, 15 runtime-finality, 24 QUV runtime, two executor
tests, CLI compilation, formatting, syntax and the 630-state receipt FIFO model
with its expected non-FIFO counterexample. The pressure checker self-test has
one positive and 30 negative cases. The exact test logs control all counts.

Two shared-capacity production controls fail the intended regression; the root
field-omission control fails the independent golden fixture. Both scripts restore
source. Development failures (missing public constant docs, not successful
mutation evidence) and pre-rooted controls are retained under development/.
Policy v7 fixture: 5d93a2ea9a59eb1a306918647b4c8565e7a9656b15c32635666e48560b3ae58d.
Schema-9/AFTCR001 formats do not change; old provisioning roots do not migrate.

pressure-process/ is a separate live campaign; its completed.json and strict
checker disposition determine the outcome. Do not infer a passing process result
from compilation or this README. That campaign captures a broader source archive,
source hashes, toolchain, command and environment overrides. Both campaigns use
working-tree sources and are not clean immutable R2 qualification.

The gate bounds receipt waiters and protects active-operation reopening.
Worst-case non-owner holder service, both reopen costs, pre-gate transport/auth,
aggregate manifests, physical/RAM/retention bounds and complete refinement remain
open. See the protocol/end-to-end specification Assumes. All 13 whole R1 findings
remain OPEN; M16Q R2 unqualified; M17Q REPAIR_REQUIRED; M18Q NOT_ADMITTED.


2026-09-06 v7 receipt pressure/restart outcome: the source-bound campaign in
`evidence/m17q-r1-receipt-admission-2026-09-06/pressure-process/` passes after
1068.80 seconds including release-node compilation and provisioning. Three
consecutive slots include exactly four expected correct members, with maximum
valid replies 394/646/495 ms against the unchanged 4000-ms envelope. An unrelated
same-executor effect completes while 120 exact parent-result replays run across
5773 ms; the child remains in its required readiness wait. Restart before slot
three preserves exact terminal recovery and the required positive child wait.
The strict checker passes with unchanged captured source hashes and complete
service-release evidence. A broader source archive, toolchain, command,
environment overrides and component hashes are retained. This is finite scoped
working-tree evidence, not clean R2 or a worst-case resource/service proof. All
whole R1 findings remain OPEN; M17Q REPAIR_REQUIRED; M18Q NOT_ADMITTED.
