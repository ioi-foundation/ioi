# M5 event-substrate retained gate bytes

All gates produced by fresh detached processes in a DEDICATED DETACHED WORKTREE
at the exact commit, with `CARGO_INCREMENTAL=0`. Every log carries
`IOI_MEASURED_COMMIT` in its own bytes, and `check-claims-coverage` refuses any
log that declares no commit, or a commit that is neither the packet HEAD nor an
ANCESTOR of it whose entire measured-to-HEAD delta is retained evidence. Both
clauses bind: tree equality is not history.

- measured commit: `0c92fa66eb318bcac3a19475f8a400e839635c76`
- this evidence commit is its child, and the delta between them is evidence
  ONLY — which is the condition the fixpoint rule requires.

| file | gate | result |
|---|---|---|
| m4-aggregate.log | M4 outcome-room system spine | 98/98 PASS (exit 0) |
| m4-activation.log | M4 GoalRun activation plane | 44/44 PASS (exit 0) |
| m5-genericity.log | M5 event-substrate genericity | 63/63 PASS (exit 0) |
| agentgres-tests.log | agentgres lib tests | 50/50 PASS (exit 0) |
| boundary-tests.log | injection boundary + stream homing | 2/2 PASS (exit 0) |
| m0.log | M0 supplied-snapshot check | 1603 entries, exit verified (exit 0) |
| check-estate.log | estate integrity | PASS (exit 0) |
| attestation-chain.log | anchor append-only + bindings resolve | PASS (exit 0) |
| pre-next-leg-gates.log | pre-next-leg gate pin + propagation | PASS (exit 0) |
| claims-coverage.log | the packet validator itself | PASS 7/7 (exit 0) |
| attestation-integration.log | committed head-rewrite attack must be REFUSED | PASS (exit 0) |

## Supplied build inputs

`node_modules` and `target` are symlinked from the main checkout.

**CORRECTION (bytes quoted, per the R5 template).** This paragraph previously
asserted: *"Every source byte under test is the worktree's own checkout; only
build inputs are shared."* **That was false when written.** The
declared-surface proof runner imported its predicate through an ABSOLUTE
shared-checkout path, so at least one verdict-owning source byte came from
outside the worktree — the assertion was a claim about isolation that the
runner itself violated. It is true now only because that runner is withdrawn
from the tree entirely; the remaining gates resolve their sources relative to
the worktree. The claim is stated as conditional-on-inspection rather than
assumed, because "only build inputs are shared" is exactly the kind of closure
a label can assert and nobody computes.
Named because each has produced a failure that reads as a regression and is not
one: missing `ajv`, root filesystem exhaustion from unbounded incremental cache,
and the verifiers' in-worktree binary lookup that `CARGO_TARGET_DIR` does not
satisfy.

## Ops constraint in force

`CARGO_INCREMENTAL=0` for gate runs. Unbounded incremental cache reached 352G
and drove the root filesystem to 100%, failing the wallet fixture with exit 101
— a poisoned signal that reads as a code regression.

## No census this round, by ruling

`b2f5a3b2a` moved zero `.rs` files and zero reviewed entries, and M0 is green at
HEAD. The rule, now explicit: **entry review ⇒ epoch append; artifact refresh ⇏
epoch.** A tool-only commit needs at most regeneration, and a green `--check`
needs nothing. The attempt to append anyway was refused by the chain — see the
dispositions entry, which records that the control refused its own director's
sequence.

## ADMISSIBILITY OF THIS PACKET

**Every log here is admissible under the STRICT rule** — ancestor plus
evidence-only delta. Nothing was carried forward. The Rust gates were
remeasured at this commit rather than inherited, so no novel admissibility
argument appears anywhere in the literal's dependency chain.

**The declared-input-surface mechanism is WITHDRAWN** (Codex option (b)) and is
not in this tree. The literal's dependency chain is substrate + pin fix + the
strict measured-commit rule, and nothing else. It is filed as
`m0-gate-input-closure-successor` carrying both Codex attacks as acceptance
tests, and debuts under its own review or not at all.

## The validator measures the EVIDENCE commit, not the measurement commit

`claims-coverage.log` is the eleventh transcript and the only one whose
measured commit differs from the other ten — deliberately, and the difference
is the finding.

Run detached at `0c92fa66e`, the measurement HEAD shared by the other ten, the
validator returns **FAIL 0/7**. That verdict is CORRECT: at that commit the
retained logs are the previous round's, and they do not measure it. The
validator's input is the retained evidence itself, which by construction lands
one commit later. It therefore cannot be green at the measurement HEAD — its
inputs do not exist there yet.

Run detached at `3eec9e5fb`, the commit that carries the evidence it validates,
it returns **PASS 7/7**. **CORRECTION (bytes quoted).** This paragraph previously read: *"Both runs are
retained in this repository's history; the transcript kept here is the
meaningful one."* **That was false when written.** The FAIL run had no retained
bytes at all — its verdict existed only as prose in this very file, quoted by
the author. A quotation is not a transcript. That is
`validator-verdict-unretained` applied to the negative control, written into
the paragraph explaining the class, in the same round the class was named.

What is true now: **both runs are retained as bytes.** The PASS run is
`claims-coverage.log`, the eleventh transcript. The FAIL run is
`negative-control/claims-coverage-at-0c92fa66e.txt`, carrying its measured
commit, its environment, and `IOI_EXIT_CODE=1` in its own bytes — following the
`flake-evidence/` precedent, in a subdirectory, as `.txt`, so it enters no
transcript set any gate enumerates. Verified: claims-coverage, check-estate,
attestation-chain and M0 all remain green with it present.

The offset claim therefore no longer rests on narration. *"The validator cannot
be green at the measurement HEAD"* is a proposition with retained evidence on
both sides: PASS bytes where its inputs exist, FAIL bytes where they do not.

**Ledger addition: a negative control is subject to the retention rule exactly
as an affirmative verdict is — a refusal you cannot produce bytes for is a
refusal that did not happen.**

This is the fixpoint that produced the ancestor-plus-evidence-only rule,
reappearing one level up: a validator of retained evidence is always one commit
behind the thing it measures. Stating it here rather than quietly measuring at
the convenient commit, because "measured at the same HEAD as the others" would
have been a claim about this log that is false.

**Ledger: `validator-verdict-unretained`** — the closing instance of the
recorded-verdict family, distinguished by the verdict being TRUE. `PASS 7/7`
was reported in the gates table with no transcript behind it. Truth without
bytes and falsehood without bytes are indistinguishable to every future reader,
which is the whole reason the class exists.
