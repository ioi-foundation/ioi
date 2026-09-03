# M12 R2 context-isolated Daybreak review — 2026-09-03

Disposition: **`REPAIR_REQUIRED`**.

This record preserves every substantive finding returned against annotated
tag `aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03`.

## Reviewer and provenance

- Reviewer: OpenAI `gpt-daybreak-blue-latest`, automated reviewer task
  `/root/aft_independent_review/m12_daybreak`.
- Review environment: no-hardlinks disposable clone at
  `/tmp/aft-m12-daybreak-m7rqGq/audit`.
- Annotated tag object:
  `8f83ecfec1e9ba15213dea4a94d2d2b6394648dd`.
- Dereferenced commit:
  `225f56992392054251d6337608c4695deb7d00e3`.
- Relationship/conflict: no known authorship, relationship, financial
  interest, or conflict.
- Limitation: wholly machine-generated. Under ADR 0049 the repository owner
  accepts it for the owner-controlled M12 gate. It is not human academic peer
  review, institutional certification, or external professional assurance.

The reviewer selected its own proof method, ran the supplied bounded models,
built an independent Boolean formulation, audited the cited constructions,
and attempted concrete escapes.

## Executive conclusion

The reviewer found the core L-MAX role-switch argument sound within its
intended participant-only, deterministic-offline-verifier scope. It found no
counterexample construction. An independent Boolean enumerator for `n=2..8`
found zero assignments satisfying both solo-input liveness and role-switch
safety. The disposition was nevertheless `REPAIR_REQUIRED`, because the R2
normative task accidentally required authorization of both members of a
conflicting pair submitted together, contradicting transferable non-conflict
even with no Byzantine faults.

## Findings and required repairs

### F1 — Normative effect-liveness contradiction

R2 required a fixed context with two conflicting externally valid values and
required authorization for every valid correctly submitted effect, but gave
effect liveness no conflict exception. Submitting both `X` and `Y` therefore
required authorizing both while transferable non-conflict prohibited that.

Required repair: add a separately identified, externally valid rooted
conflict/policy exception; forbid local arrival order, silence, or unmodeled
external state from defining it; and retain explicit liveness when exactly one
valid non-`Abort` effect is submitted while the other `n-1` members remain
silent.

Response: applied in R3 to `maximal_consensus_task.md`, represented by
`ConflictQualifiedLiveness.tla`, and included in the focused harness.

### F2 — Selector, freshness, and consequence-resource boundary

R2 did not say exactly whether verifier freshness was rooted, embedded in the
proof, or passed separately. It also permitted a downstream atomic resource
outside `P` without explicitly forbidding its receipt from becoming a proof
selector.

Required repair: every freshness input must be independently rooted or
explicitly supplied to `Verify` and held common in paired runs. No non-member
service may select, close, order, or make an authorization canonical. The
idempotency resource is downstream after acceptance, and its receipt is not a
verification input; otherwise it must be named as the external selector.

Response: applied in R3 to both normative task and theorem premises. The
negative `ExternalSelectorMutation.tla` model now makes the boundary
executable.

### F3 — `Support(pi)` was not literally exhaustive

R2 recorded only configured-member acts, omitting authenticated client bytes,
public setup/randomness, storage/publication receipts, clocks, chains,
notaries, executors, and resources. Replayable common bytes do not defeat the
proof; a non-reproducible output that selects acceptance is external
authority.

Required repair: split the abstraction into `SupportP(pi)` for configured
member acts, `Common(pi)` for replayable rooted/public prerequisites held
fixed, and `ExternalSupport(pi)` for required non-member selecting acts. State
L-MAX after conditioning on `Common` with `ExternalSupport(pi) = {}`.

Response: applied in R3 throughout the generalized model and proof.

### F4 — Prior-art reproducibility defects

The Geeq source was mutable; the atomic-register row lacked a primary link;
the DAG-Rider row overextended the PQ description without emphasizing the
global-perfect-coin liveness assumption; and the Bracha row called the cited
broader Byzantine-agreement paper an RBC paper rather than identifying its
broadcast filter.

Response: R3 pins the dated author-hosted Geeq v2 PDF and SHA-256, links the
repository T10 model, narrows the DAG-Rider PQ/liveness language, and precisely
describes Bracha's source relationship.

## Scope and attempted counterexample

The review confirmed that L-MAX covers arbitrary finite participant-generated
proof formats, static `n-1` Byzantine assignments, all three named synchrony
profiles, randomized liveness with unconditional safety, and deterministic
offline verification under fixed roots and common prerequisites. It does not
cover non-conflicting/CRDT-only tasks, local-only decisions, a known trusted
writer, probabilistic safety, online verification against a named
linearizable history service, trusted clocks/TEEs/erasure/chains/notaries, or
bounded adversarial resources.

Its direct attempted construction accepted a configured member's signature on
`DECIDE(root, instance, predecessor, v)`. That permits solo progress but lets a
Byzantine role-switched member produce the conflicting proof. A predetermined
writer loses liveness when silent, a predetermined value loses nontrivial
effect validity, and all-member signatures lose silent-peer liveness.

The reviewer tested escape families based on synchronous and asynchronous BA,
RBC/ACS/DAGs, CRDTs and append-only sets, availability certificates and DAS,
first-publication/CAS, failure detectors, clocks/leases/VDFs/key erasure,
PoW/PoS/deposits, chains/notaries/storage, the downstream atomic register,
NIZKs/accumulators, and verifier-local caches. It found that each either
weakens a required property, needs a quorum/resource assumption, or imports
the selecting authority excluded by the task.

## R2 reproduction

- Formal census: 42 modules = 29 executed + 13 manual.
- `n=2`: 256 distinct acceptance-family states; no invariant error.
- `n=3`: 65,536 distinct acceptance-family states; no invariant error.
- Expected `RoleSwitchConflict` counterexample observed at depth 3.
- Independent Boolean enumerator digest:
  `06ff7b00f043e0f62ecdb1f958caa3276c28d9eb30ca0d7bbb3a61ba4a66bab0`.
- For each `n=2..8`, exactly one assignment met solo liveness and zero met
  solo liveness together with role-switch safety.

## Required retest

The same reviewer must evaluate a new immutable R3 candidate containing all
four repairs and the requested models. The report must return `UPHELD`,
`REPAIR_REQUIRED`, or `REFUTED`. An `UPHELD` result closes M12 only as
`PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`; it cannot authorize M13-M18 or the
maximal protocol headline.
