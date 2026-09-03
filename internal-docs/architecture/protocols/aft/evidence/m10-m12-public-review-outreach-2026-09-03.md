# M10/M12 public independent-review outreach — 2026-09-03

Status: **PUBLIC REQUESTS OPEN; NO REVIEWER ASSIGNED; NO REVIEW PERFORMED**.

The repository owner authorized publication and reviewer outreach. This record
proves that the immutable candidates and requests are remotely accessible. It
does not satisfy either independent-review gate.

## Published repository state

- Repository: <https://github.com/ioi-foundation/ioi>
- Remote `master` immediately after request-text publication:
  `61a24b12f94c431f4d4cad1e5b267f16171be217`
- M10 remote annotated-tag object:
  `3db5f4d08fb5819ab586982f0be60be626ed527b`
- M10 dereferenced commit:
  `09aaf34b63c8fa8520c4de014a6d72f6360f7e16`
- M12 R2 remote annotated-tag object:
  `8f83ecfec1e9ba15213dea4a94d2d2b6394648dd`
- M12 R2 dereferenced commit:
  `225f56992392054251d6337608c4695deb7d00e3`

The remote refs were independently read back with `git ls-remote`, including
peeled `^{}` commit refs. Neither candidate tag was moved.

## Public requests

| Gate | GitHub issue | Opened by | State at verification | Labels | Assignees |
|---|---|---|---|---|---|
| M10 independent PQ/security review | [#357](https://github.com/ioi-foundation/ioi/issues/357) | `NoCentralHub` | `OPEN` | `help wanted`, `independent-review` | none |
| M12 independent theorem review | [#358](https://github.com/ioi-foundation/ioi/issues/358) | `NoCentralHub` | `OPEN` | `help wanted`, `independent-review` | none |

The issue bodies name the exact tag, commit, tag object, packet, qualification
requirements, independence disclosure, expected response, and the prohibition
on treating automation as independent human review. No compensation or private
term was promised.

## Gate effect

The publication blocker is closed. The engagement/evidence blocker remains:

- M10 needs a qualified independent reviewer to be selected, disclose
  conflicts, complete P4.5a, and return an attributable report with no
  unresolved critical/high finding before release admission.
- M12 needs a qualified independent theorist to be selected and return
  `UPHELD`, `REPAIR_REQUIRED`, or `REFUTED` with the evidence required by the
  packet.

Until then, M10 remains the sole critical path, M12 remains unadjudicated, and
M13–M18 remain locked.
