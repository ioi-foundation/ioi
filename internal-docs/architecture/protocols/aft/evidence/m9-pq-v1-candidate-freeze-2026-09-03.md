# M9 PQ v1 candidate freeze — 2026-09-03

Status: **LOCAL CANDIDATE GATES PASS; IMMUTABLE REVIEW REF CREATED**.

This record closes M9 only. It does not close the independent-review gate,
release AFT PQ v1, admit an adaptive-security claim, or establish the target
`f = n - 1` consensus theorem.

## Candidate binding

- Repository: `ioi-foundation/ioi`.
- Starting baseline: `ef20d4ff5a7e486ece3dc3410d9c7e6d6eda9eba`.
- Candidate ref: annotated tag
  `aft-pq-v1-review-candidate-2026-09-03`.
- Exact candidate commit: resolve the tag and copy the resulting full commit
  hash into the owner/reviewer commissioning record and final report.
- Audit scope: `../packets/P4.5a-external-audit.md`.

The commit cannot contain its own commit hash. The annotated tag is therefore
the immutable binding outside the candidate contents. Editing this record to
insert the resolved hash would create a different candidate and invalidate the
tagged review scope.

## Reconciliation performed before freezing

- T5d is no longer represented as responsive succession. The surviving
  positive result is scheduled, formation-time-fenced safety; the responsive
  all-but-one liveness claim remains refuted.
- New lower bound L-S pairs T5d by proving that responsive succession cannot
  infer inaction from silence. T8 is the only remaining `L-OPEN` row and is not
  used to make a frontier-completeness or generic cost-to-violate claim.
- The theorem surface, pairing table, claim adjudication, yellow paper,
  residual notes, formal census, and implementation ledger agree on that
  boundary.
- P4.5a and the execution plan use an annotated tag/commissioning record rather
  than the impossible requirement that a commit self-record its own hash.

## Integrated release reproduction

Command:

```text
bash scripts/run_aft_m8_release_demo.sh
```

Result: **PASS, one uninterrupted exit-0 run on the candidate contents**.

- Real four-validator PQ hash-async fallback, virtual block admission,
  canonical agreement, cold restart, and native-child resumption: 1 / 1 in
  585.42 seconds.
- PQ checkpoint issuer without downgrade: 1 / 1 in 86.25 seconds.
- Portable assurance positive and mutation corpus: 5 / 5 in 283.71 seconds.
- Consequence crash/reconciliation and mixed-domain corpus: 12 / 12.
- External Python clean room accepted the complete receipt and rejected all
  seven validly re-enveloped inner forgeries.
- Independent RustCrypto interoperability oracle: ML-DSA-44 and
  SLH-DSA-SHA2-128s both passed.
- Formal census: 40 modules = 27 executed + 13 explicitly manual.
- TLAPS: all 1,015 obligations across nine proof modules passed.
- TLC: every registered configuration passed with no error. The largest model,
  `CanonicalOrderingRetrievability`, exhausted 632,887,809 generated /
  66,846,976 distinct states to depth 39 in 28 minutes 17 seconds.
  `MembershipTransition` exhausted 21,764,161 generated / 1,254,528 distinct
  states to depth 22 in 1 minute 45 seconds.
- Cross-domain non-interference completed at 41 generated / 10 distinct states,
  depth 6; the generated 11-step boundary-ring trace replay also passed.

The first post-reconciliation attempt exposed a test-harness defect after the
protocol assertions had passed: restart readiness sampled four 10-second RPCs
sequentially, consuming its 180-second budget despite every validator
continuing to produce within one block of the others. Readiness now samples
status and shared-block RPCs concurrently, then compares block hashes in stable
validator order. The targeted test binary compiled, and the complete repeated
drill passed startup, shared-history verification, fallback, restart, and
forward progress. This is a harness reliability fix, not a relaxed consensus
criterion.

## Other reproduced candidate gates

- `cargo metadata --locked --no-deps` — PASS.
- `cargo fmt --all -- --check` — PASS.
- `git diff --check` — PASS.
- theorem-assumption gate — PASS, 28 theorem/lower-bound blocks.
- claim-discipline gate — PASS.
- production-authorization census — PASS, exactly one external mutation
  owner.
- formal census-only gate — PASS, 40 = 27 + 13.
- formal harness smoke lane — PASS; it restores pre-existing `TLAPS.tla`
  links and removes temporary links, leaving no machine-specific generated
  symlink delta in the candidate checkout.
- affected workspace suites — PASS: types 459 / 459, crypto 63 / 63,
  networking 13 / 13, consensus 229 / 229, finality 57 / 57, Agentgres 99 /
  99, validator 260 / 260.
- locked Hypervisor daemon check — PASS; its default graph remains free of
  consensus, validator, and terminal-seal dependencies.
- locked validator distribution, portable receipt verifier, and minimal
  finality checks — PASS.
- yellow paper — regenerated successfully at 147 pages.
- fuzz corpus paths are marked as binary so Git does not normalize or
  whitespace-rewrite opaque seed bytes.

Host/toolchain for this reproduction: Linux
`6.17.9-76061709-generic` x86_64; `rustc 1.93.1
(01f6ddf75 2026-02-11)`; `cargo 1.93.1 (083ac5135 2025-12-15)`; TLC
`2026.08.11.125311` and the repository-pinned TLAPS bundle.

## Open release blocker and deterministic handoff

M10 is the sole critical-path milestone. The owner must identify and engage an
independent human reviewer satisfying P4.5a, then provide an attributable
commissioning record naming the full commit resolved by the candidate tag,
reviewer identity/qualifications, independence disclosure, scope, and dates.
The final report must name that same commit and dispose every finding. No local
agent, clean room, interoperability oracle, or proof assistant substitutes for
this review.

If any security-relevant candidate content changes, create a new commit and
new candidate tag, mark this evidence stale for the affected surface, and
require delta or full re-review. While M10 awaits owner action, M11/M12 research
may proceed without changing the tagged PQ v1 candidate.
