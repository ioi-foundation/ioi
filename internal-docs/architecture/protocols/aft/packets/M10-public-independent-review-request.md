# AFT M10: independent PQ v1 security review request

AFT needs an independent security review of its immutable post-quantum v1
candidate before release admission. This is a public request for a qualified
human reviewer; repository automation, internal agents, and existing
clean-room/interoperability tools do not satisfy the independence gate.

## Immutable target

- Candidate tag:
  [`aft-pq-v1-review-candidate-2026-09-03`](https://github.com/ioi-foundation/ioi/tree/aft-pq-v1-review-candidate-2026-09-03)
- Commit:
  [`09aaf34b63c8fa8520c4de014a6d72f6360f7e16`](https://github.com/ioi-foundation/ioi/commit/09aaf34b63c8fa8520c4de014a6d72f6360f7e16)
- Annotated-tag object:
  `3db5f4d08fb5819ab586982f0be60be626ed527b`
- Full scope and reproduction packet:
  [`P4.5a-external-audit.md`](https://github.com/ioi-foundation/ioi/blob/aft-pq-v1-review-candidate-2026-09-03/internal-docs/architecture/protocols/aft/packets/P4.5a-external-audit.md)

Review the tag, not `master`. Any remediation will create a new immutable
candidate and an explicit delta/full-retest scope; this tag will not move.

## Reviewer qualifications and independence

The reviewer should demonstrate relevant experience in applied cryptography,
Rust security, distributed systems, protocol serialization, or closely related
work. A proposal must disclose organizational/personal relationships with the
implementation team and any other conflict that could affect independence.

The final report must name the reviewer, exact candidate, methods, all findings
including disputed findings, and independent reproduction results. Findings
use stable identifiers and the severity/disposition format in P4.5a. Release
admission requires no unresolved critical or high finding.

## How to respond

Comment on the GitHub issue created from this request with:

1. reviewer name and relevant qualifications;
2. independence/conflict disclosure;
3. proposed scope and method, including independently chosen attacks;
4. expected schedule and preferred report-authentication method; and
5. whether any compensation or private coordination is required.

Do not include secrets in the issue. No compensation, confidentiality, or
engagement term is implied until explicitly agreed by the repository owner.
