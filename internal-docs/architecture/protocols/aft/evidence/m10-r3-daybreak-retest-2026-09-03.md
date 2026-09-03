# M10 R3 Daybreak remediation retest

Status: `FAIL / REPAIR_REQUIRED` for the exact R3 candidate. This is an
owner-authorized automated review under ADR 0049, not human peer review,
professional assurance, institutional certification, or cryptographic
certification.

Date: 2026-09-03.

## Reviewer and independence

Reviewer: context-isolated OpenAI Codex agent using
`gpt-daybreak-blue-latest`, task `/root/aft_independent_review/m10_daybreak`.
The reviewer stated that it did not author the implementation or proofs, had no
known financial or organizational conflict, selected independent checks, was
not instructed to suppress findings, and reported all findings and limits.

## Immutable target

```text
tag:                aft-pq-v1-review-candidate-r3-2026-09-03
annotated tag object: bfb2cd6b3fe2e6bb5c6f5ada6515a970f2bf2cb7
commit:             0235264693c1906b32d9e0bf0a3d7a3d1ef78e7c
tag message:        AFT PQ v1 review candidate R3
review clone:       /tmp/ioi-m10-r3-audit.PitJbC/audit
```

The reviewer used a fresh `git clone --no-hardlinks --no-checkout`, detached at
the annotated tag, did not modify the shared checkout, and reported the final
source status clean. The tag is annotated and unsigned.

## Finding disposition

| ID | Prior severity | R3 state | Disposition |
|---|---:|---|---|
| AFT-M10-001 | high | closed | tracked clean-room verifier, corpus, and trust material reproduced |
| AFT-M10-002 | high | closed by claim correction | receipt is post-consequence evidence, not circular authorization |
| AFT-M10-003 | medium | **open** | integrated four-validator cold restart failed before post-restart height 7 |
| AFT-M10-004 | medium | closed | key-store suite/header validation and authentication retained |
| AFT-M10-005 | medium | closed within scope | zeroizing lifecycle retained; provider/side-channel limits remain |
| AFT-M10-006 | medium | closed | failed strict-PQ rotation now retires old manager and legacy authority |
| AFT-M10-007 | medium | closed | independent Python/Rust full-vector differential corpus agreed |

There are no unresolved critical or high findings. Gate 15 nevertheless fails
because the exact integrated release artifact is not reproducible through its
required restart transition.

## AFT-M10-003 detail

The exact fixture built and launched four validators and four encrypted signer
processes, reached shared-tip readiness, crossed height 5, exercised hash
fallback, and reached the metrics assertions. During cold restart only two
signer-encryption events appeared before signer readiness timed out:

```text
Error: Timed out waiting for ioi-signer. Stderr:
FAILED
test result: FAILED. 0 passed; 1 failed
finished in 1313.69s
elapsed=1767.79 exit=101
```

The run did not demonstrate post-restart height 7. The trace does not establish
a consensus-safety failure; it is a release reproducibility and child-process
diagnostic defect.

Required repair:

- make all four signer processes reliably ready during cold restart under the
  supported release-test load;
- preserve child exit status and useful stderr on readiness failure;
- fix readiness/resource handling instead of relying on the current 20-second
  default; and
- freeze a new immutable candidate and repeat the complete
  height-5/restart/height-7 fixture under independent retest.

## Commands reported by the reviewer

| Command/surface | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `git diff --check` | pass |
| theorem-assumption check | pass, 28 theorem blocks |
| claim-discipline check | pass |
| production-authorization census | pass, one modeled mutation owner |
| formal census | pass, 44 modules: 31 executable + 13 manual |
| `ioi-networking` library | pass, 14/14 |
| portable-assurance filtered suite | pass, 5/5; complete receipt/trust and ten negatives |
| PQ interop tool | pass |
| clean-room verifier help and committed corpus | pass |
| independent Python/Rust ten-case differential corpus | pass, both rejected 10/10 |
| exact four-validator hash-fallback/restart fixture | **fail 101**, elapsed 1767.79 seconds |

The clean-room complete receipt was 1,078,375 bytes and the trust object 3,078
bytes. The reviewer observed the pinned PQ provider versions recorded in the R3
candidate and restated that provider correctness, side-channel resistance,
adaptive corruption, arbitrary delivery, snapshot-safe custody, generic
external resources, and successful post-restart height 7 were not established.

## Gate result

`AFT-M10-006` and `AFT-M10-007` are closed. `AFT-M10-003` remains open.
Therefore M1, M8, M10, and full release admission remain incomplete for R3.
