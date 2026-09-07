# PQ timeout drill: bootstrap-window timeout evidence (2026-09-07)

Scope: an over-determined assertion in the four-validator PQ timeout/restart
drill (`test_aft_pq_four_validator_timeout_quorum_and_restart`, mandatory
M16Q phase `pq_ordering_restart`). It is not an R1 finding, it changes no
runtime code, theorem, premise, policy root, schema, deadline, envelope or
bound, and it is retained because it failed the second clean M16Q R2 run on
`f41ba3b41` after every other phase, including all QUV gates, had passed.

## Observation (`failed-clean-run-phase/`)

Run `20260907T074926Z-f41ba3b416ac` (moved out of the tree; the failing phase
is retained here gzipped with `phase-results.tsv`, `commit.txt` and
`environment.txt`): 61 phases passed in 7230 s (formal corpus 2835 s;
single-correct 659 s; flood 601 s; status squat 198 s; disjoint handoff 336 s
and overlap 280 s with evidence maxima 721 ms and 697 ms; consecutive
readiness 419 s; hash-async process 1101 s; the new `quv_successor_root_gate`
phase). `pq_ordering_restart` then failed after 272 s with

```
Error: block 2 carried timeout evidence for unexpected height 2
```

`components/` shows the cause. The four validators launched serially at
09:45:57, 09:46:31, 09:47:04 and 09:47:40 (their key encryption is
serialized; 33–36 s apart). Consensus starts once the bootstrap peer set is
satisfied: height 1 was proposed at 09:47:14 by the second validator. The
round-robin leader for height 2 was the fourth validator, which had not
launched, so the 30 s view timeout fired at 09:47:52 on the three running
nodes; they exchanged scoped ML-DSA timeout votes (`Scoped AFT timeout vote
H=2 V=1`), and the view-1 leader proposed block 2 at 09:47:57 carrying the
exact-q=3 scoped certificate for height 2. The drill itself (baseline 5,
scheduled leader failure at height 8) ran correctly afterwards: the retained
log shows the height-8 view-1 proposal with its scoped certificate.

The fixture asserted that every scoped certificate found in blocks
`1..=timeout_height+1` names `timeout_height`. A certificate for a
late-launched leader before the drill baseline is the protocol working, not
the scheduled fault; the engine already refuses a certificate that does not
authorize the proposal's own slot (`runtime.rs`: `certificate.height !=
header.height` fails verification). Whether the pre-baseline timeout occurs
depends on the random account ordering that picks the height-2 leader and on
the launch stagger against the 30 s timeout, so the phase was timing-dependent
before this change. The retained 2026-09-04 run also shows height-4 timeout
votes; it passed only because those votes did not form an embedded
certificate.

## Repair

`crates/cli/tests/aft_e2e.rs`: for every block carrying a scoped
certificate the drill now requires `certificate.height == height` (a
strictly stronger protocol check than before), prints and records a
pre-baseline certificate as bootstrap-window evidence, and rejects any
certificate in the drill window (`height > baseline`) at a height other than
`timeout_height`. The exact-q=3 vote count, ML-DSA producer suite, absence of
legacy unscoped evidence, the mandatory certificate at `timeout_height`, the
exact-q parent quorum and the restart continuation are unchanged. No
deadline, timeout, envelope or fixture bound changed; the 30 s view timeout
and 240 s harness deadline are as before.

## Controls and measurement

- Removed-rule/process control: `failed-clean-run-phase/` is the exact
  campaign the previous assertion rejected; its block 2 certificate is for
  height 2 (equal to its block height) and its drill-window certificate is
  at height 8, so the corrected assertion accepts it and the previous one
  does not.
- `drill-process/`: the drill passed standalone on the corrected fixture
  (exit 0, 399.16 s; baseline 6, timeout height 9, failed leader index 1).
  Validators launched at 09:53:40, 09:54:08, 09:54:37 and 09:55:10 (28–33 s
  apart); this run happened to select a running leader for every bootstrap
  height, so no pre-baseline certificate occurred and the bootstrap-window
  branch was not exercised by this campaign. The full clean R2 run on the
  committed fixture is the qualification evidence.
- Measured launch stagger on this host: 28–36 s per validator against the
  30 s view timeout. This is recorded as a cost of the serialized fixture
  launch, not as a protocol timing claim.

## What this does and does not establish

It removes one timing-dependent false failure from a mandatory phase and
strengthens the certificate/slot check. It does not qualify the PQ ordering
profile beyond the drill's recorded scope and it does not change any QUV
disposition.
