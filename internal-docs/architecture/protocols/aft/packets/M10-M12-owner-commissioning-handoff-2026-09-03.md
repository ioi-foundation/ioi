# M10/M12 owner commissioning handoff — 2026-09-03

Status: **CANDIDATES PUBLISHED AND PUBLIC REQUESTS OPEN; REVIEWER ASSIGNMENT
AND REPORTS PENDING**.

This is the exact handoff for the two independent reviews that local agents
cannot honestly perform. M10 remains the sole critical-path milestone. The M12
theorem review may run concurrently, but it cannot unlock production work
unless it returns `REFUTED` with a construction that survives the M11 task.

Public outreach:

- M10 security review: <https://github.com/ioi-foundation/ioi/issues/357>
- M12 theorem review: <https://github.com/ioi-foundation/ioi/issues/358>

Both requests are open and unassigned. Opening them is not review evidence.

## 1. Immutable candidates

### M10 implementation, cryptography, and claim review

- annotated tag: `aft-pq-v1-review-candidate-2026-09-03`
- candidate commit: `09aaf34b63c8fa8520c4de014a6d72f6360f7e16`
- tag object: `3db5f4d08fb5819ab586982f0be60be626ed527b`
- packet: `P4.5a-external-audit.md`
- local freeze evidence:
  `../evidence/m9-pq-v1-candidate-freeze-2026-09-03.md`

The reviewer must check out this tag, not `master`. Later research commits are
not part of the M10 candidate.

### M12 theorem and prior-art review

- annotated tag:
  `aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03`
- candidate commit: `225f56992392054251d6337608c4695deb7d00e3`
- tag object: `8f83ecfec1e9ba15213dea4a94d2d2b6394648dd`
- packet: `M12-maximal-visibility-theorem-review.md`
- local evidence: `../evidence/m11-m12-maximal-visibility-2026-09-03.md`

The predecessor tag
`aft-maximal-visibility-lower-bound-candidate-2026-09-03` remains retained at
commit `60d16ef41d1d2b876c8644fe4fb5d0d1dbcaec3f`. It was superseded after the
primary-source attack clarified nontrivial validity, fixed common inputs, and
role-switch timing. Do not commission a new review against the predecessor.

## 2. Publication choice

The owner published `master` and both operative candidate tags on 2026-09-03.
Remote refs were read back and matched the commit and tag-object hashes in
Section 1. The commands below are retained as reproduction/transfer guidance;
they are no longer an outstanding action.

The smallest remote disclosure that lets reviewers fetch immutable candidates
without moving `master` is:

```text
git push origin \
  refs/tags/aft-pq-v1-review-candidate-2026-09-03 \
  refs/tags/aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03
```

If the owner has separately approved bringing `master` current, review the
local commits and then use:

```text
git push origin master
git push origin \
  refs/tags/aft-pq-v1-review-candidate-2026-09-03 \
  refs/tags/aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03
```

Do not force-push, move either tag, or substitute a branch name for the exact
candidate in a review report. A private signed bundle or read-only mirror is
also acceptable if public disclosure is premature, provided the reviewer
records the same commit and tag-object hashes.

For private transfer, generate and independently clone-check both Git bundles
plus their manifest and checksums with:

```text
output_dir="$(mktemp -d)"
bash .github/scripts/prepare_aft_review_bundles.sh "${output_dir}"
(cd "${output_dir}" && sha256sum --check --strict SHA256SUMS)
```

The generated directory contains one bundle per review so the M10 reviewer
does not receive later research code by accident. Transfer through an
owner-approved channel; the script does not upload or disclose anything.
The local two-run reproduction and fail-closed checks are recorded in
`../evidence/m10-m12-review-bundle-reproduction-2026-09-03.md`.

## 3. Reviewer assignments

The owner records the following before work begins.

### M10 reviewer

```text
name / organization:
contact:
relevant cryptography, Rust, distributed-systems qualifications:
independence and conflict disclosure:
engagement date:
candidate commit and tag object independently resolved:
secure report-return channel:
```

### M12 reviewer

```text
name / organization:
contact:
relevant distributed-computing theory qualifications:
independence and conflict disclosure:
engagement date:
candidate commit and tag object independently resolved:
secure report-return channel:
```

The reviewers must not have authored the candidate. They select their own
methods, add independent attacks, and report adverse findings and failed
attacks. The same person should not cover both engagements unless the owner
documents why that person is independently qualified for both scopes and why
combining them does not weaken review.

## 4. Required returned evidence

### M10

- authenticity-verifiable final report naming the exact M10 commit, tag object,
  provider versions, reviewer, and independence disclosure;
- complete stable-ID finding ledger with severity and disposition;
- independent reproduction transcript and reviewer-chosen attacks;
- exact remediation commit for every fix and explicit delta/full-retest scope;
- no unresolved critical/high finding before release admission.

### M12

- attributable final report naming the exact R2 commit and tag object;
- one primary disposition: `UPHELD`, `REPAIR_REQUIRED`, or `REFUTED`;
- direct treatment of all eleven packet questions and every required attack;
- an independently selected proof method or concrete counterexample protocol;
- an audit of the dated prior-art matrix, including omitted constructions;
- the reviewer's own formalization or a precise explanation of why another
  formal method is more appropriate.

Internal agents, TLC/TLAPS, interoperability oracles, and clean-room programs
remain supporting evidence. None may be entered in the reviewer identity
fields.

## 5. Resume rules

1. Store returned reports and raw transcripts without rewriting objections.
2. Verify signatures/authenticity, candidate hashes, and reviewer independence.
3. Enter every finding in the implementation ledger before remediation.
4. Any candidate change invalidates affected evidence and creates a new
   immutable tag; never move an existing tag.
5. M10 closes only after the P4.5a acceptance conditions hold.
6. `UPHELD` at M12 records `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS` and requires an
   explicit owner choice of a property or assumption to change.
7. `REPAIR_REQUIRED` creates an R3 theorem candidate and reviewer retest.
8. `REFUTED` must include a concrete construction; local work then resumes the
   `PASS_CONSTRUCTION` campaign. M13 remains locked until that construction is
   modeled, executable, and reviewed.

Until evidence is returned, do not release PQ v1, print the maximal headline,
or begin a maximal production implementation.
