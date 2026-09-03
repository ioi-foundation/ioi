# AFT M12: independent maximal-visibility theorem review request

AFT needs an independent distributed-computing theorem review before deciding
whether its proposed relay-free `f=n-1` consensus target is constructible or
impossible under the fixed constraints. The local R2 candidate argues a
role-switching lower bound. The reviewer is asked to defeat it with a concrete
construction if possible, not merely endorse the prose.

This is a public request for a qualified human theorist. Internal agents, TLC,
TLAPS, literature summaries, or implementation tests are supporting evidence
and do not satisfy the independence gate.

## Immutable target

- Candidate tag:
  [`aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03`](https://github.com/ioi-foundation/ioi/tree/aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03)
- Commit:
  [`225f56992392054251d6337608c4695deb7d00e3`](https://github.com/ioi-foundation/ioi/commit/225f56992392054251d6337608c4695deb7d00e3)
- Annotated-tag object:
  `8f83ecfec1e9ba15213dea4a94d2d2b6394648dd`
- Exact task:
  [`maximal_consensus_task.md`](https://github.com/ioi-foundation/ioi/blob/aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03/internal-docs/architecture/protocols/aft/specs/maximal_consensus_task.md)
- Lower-bound candidate:
  [`maximal_visibility_viability.md`](https://github.com/ioi-foundation/ioi/blob/aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03/internal-docs/architecture/protocols/aft/specs/maximal_visibility_viability.md)
- Complete review packet:
  [`M12-maximal-visibility-theorem-review.md`](https://github.com/ioi-foundation/ioi/blob/aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03/internal-docs/architecture/protocols/aft/packets/M12-maximal-visibility-theorem-review.md)

Review the tag, not `master`. The candidate is not an admitted impossibility
result, novelty claim, or permission to weaken validity/effect liveness.

## Required disposition

The attributable final report returns exactly one primary disposition:

- `UPHELD`: task and L-MAX are sound in their stated scope;
- `REPAIR_REQUIRED`: identify exact ambiguity/proof gap and retest needed; or
- `REFUTED`: provide a concrete construction satisfying every M11 requirement
  without a trusted publisher, relay, oracle, TEE, external consensus,
  consensus-powerful unmodeled object, or bounded-resource substitution.

The packet contains eleven required questions, named construction attacks,
bounded reproduction commands, and the exact standard for each disposition.

## Reviewer qualifications and independence

The reviewer should demonstrate research expertise in distributed computing,
Byzantine agreement/broadcast, shared-object computability, cryptographic
protocols, or closely related theory. A proposal must disclose relationships
with the implementation team and any conflict that could affect independence.

## How to respond

Comment on the GitHub issue created from this request with:

1. reviewer name, affiliation, and relevant publications or qualifications;
2. independence/conflict disclosure;
3. intended proof method and at least one candidate escape to attack;
4. expected schedule and report-authentication method; and
5. whether any compensation or private coordination is required.

Do not include secrets in the issue. No compensation, confidentiality, or
engagement term is implied until explicitly agreed by the repository owner.
