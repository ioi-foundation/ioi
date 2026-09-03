# M12 R3 exact Daybreak retest — 2026-09-03

Disposition: **`UPHELD`**.

## Provenance

- Reviewer: `gpt-daybreak-blue-latest`, automated OpenAI reasoning agent.
- Independence: no known authorship relationship or conflict; all work ran in
  fresh disposable clone `/tmp/aft-m12-r3-daybreak-n2NgrD/audit`; the shared
  repository was not written.
- Candidate: annotated tag
  `aft-maximal-visibility-lower-bound-candidate-r3-2026-09-03`.
- Tag object: `36969888c3213159acd6fcc97d383a783954d87c`.
- Commit: `0a6fe27723af7854c3747178c7e2f6d2a65201ec`.
- Limitation: this is an automated independent review accepted for the
  owner-controlled gate under ADR 0049. It is not human academic peer review,
  institutional certification, or professional assurance.

## Repair verification

| R2 finding | R3 verification |
|---|---|
| F1: conflicting submissions made effect liveness self-contradictory | Closed. The task permits only a rooted externally valid conflict/policy rejection, forbids arrival/silence authority, and retains exact singleton authorization with all peers silent. L-MAX uses those singleton runs. |
| F2: freshness and downstream resource boundary ambiguous | Closed. Freshness is rooted or explicitly passed and held common. Non-reproducible freshness is external authority. The atomic register remains downstream; feeding its receipt into verification moves it into external support. |
| F3: `Support(pi)` omitted non-member prerequisites | Closed. R3 partitions configured-member `SupportP(pi)`, replayable `Common(pi)`, and selecting `ExternalSupport(pi)`. |
| F4: prior-art reproducibility and wording | Closed. Bracha and DAG-Rider are qualified, the atomic row links the T10 model, and the dated Geeq PDF digest independently reproduces as `238dc57170e337256301c97818ff57ec0c42e9b24c3f5dea2bb0b926a94e880d`. |

The reviewer found the repaired task coherent: solo `X` and solo `Y` must each
progress in their respective executions, while a joint conflicting submission
need not authorize both.

## Required reproduction

```text
bash .github/scripts/run_aft_formal_checks.sh --census-only
census OK: 44 modules = 31 executed + 13 manifest-marked (manual)
```

The focused run returned:

- `n=2`: 512 generated / 256 distinct states, depth 1, no error;
- `n=3`: 131,072 generated / 65,536 distinct states, depth 1, no error;
- `ConflictQualifiedLiveness`: 6 generated / 3 distinct states, depth 1,
  no error;
- expected `RoleSwitchConflict` / `ExternalNonConflict` counterexample; and
- expected `ExternalSelectorMutation` / `ParticipantOnlyVerifier`
  counterexample.

The direct role-switch trace reached the expected state containing both
`[signer |-> p0, decision |-> XValue]` and
`[signer |-> p1, decision |-> YValue]`. The selector mutation held replayable
`ClientPayload` common and changed `externalSupport` from `{}` to
`{ExternalCasReceipt}`.

## Independent formalization

The reviewer independently enumerated Boolean acceptance assignments for
every sole-member proof token:

```text
A[p,v] := verifier accepts p's solo-execution proof for value v
Liveness := all A[p,X] and A[p,Y]
Safety := for every p != q:
          not(A[p,X] and A[q,Y])
          and not(A[p,Y] and A[q,X])
```

For `n=2..8`, exactly one assignment met solo liveness and zero assignments
met solo liveness together with role-switch safety. Checker SHA-256:
`3f69cce9469b7fbd4cd08eb715fc189f3d9f47aaf791d8bbedc7ad0a4d4778f5`.
The reviewer also confirmed the three conflict-qualified joint outcomes and
that the external-CAS escape is safe only by adding selector authority.

## Theorem re-evaluation

The reviewer confirmed all eleven packet questions:

1. The repaired task prevents singleton-agreement vacuity while keeping
   termination, inclusion, effect liveness, availability, and verification
   distinct.
2. Transferable non-conflict remains the minimum for independently executable
   irreversible bearer authorization. Accountability or resource-scoped CAS
   are meaningful weaker properties but change consequence semantics.
3. The three-way prerequisite partition is sound: replayable client/public
   material is common; any non-reproducible selecting service is external.
4. The role switch preserves roots, instance, common client/freshness
   material, proof bytes, and an admissible fault assignment.
5. Almost-sure termination permits fixing a positive-probability finite random
   prefix; unconditional safety must cover it.
6. Synchrony, Dolev–Strong, authenticated/reliable broadcast, randomized
   asynchronous agreement, and crash failure detectors provide no
   transferable participant-only distinguishing bit at this fault bound.
7. A canonical public state distinguishes the runs only through a replayable
   member output or a non-member selector such as linearizable publication,
   trusted time, TEE, chain, or bounded resource.
8. The result covers arbitrary finite participant-generated proofs, all named
   timing profiles, and randomized liveness with unconditional safety. It
   excludes external selectors, known trusted writers, bounded-resource
   models, probabilistic safety, and non-conflicting/CRDT-only tasks.
9. The `n=2` argument generalizes to arbitrary `n`: choose distinct `a,b` and
   leave every remaining Byzantine member silent.
10. Every escape changes a limb: remove solo effect liveness, weaken
    transferable safety, identify a trusted writer, add a linearizable
    selector, eliminate conflicts, reduce the fault bound, or add trusted
    time/hardware/resource assumptions.
11. The repaired prior-art rows accurately state their task and assumption
    differences; no omitted construction was found that changes L-MAX under
    the repaired scope.

## Concrete escape attacks

The reviewer retried singleton signatures, fixed identities/values,
all-member/quorum closure, Dolev–Strong, append-only sets and CRDTs,
content-addressing and availability certificates, first-seen/CAS, local and
common randomness, leases/VDFs/key evolution, PoW/PoS/deposits, external
chains/relays/notaries/storage, downstream CAS, and NIZKs/accumulators.

Each either permits the two role-switched proofs, loses singleton liveness,
proves inclusion rather than canonical closure, weakens a task property, or
imports an excluded selecting authority. No concrete protocol satisfies every
repaired M11 property under the excluded-authority constraints.

## Gate result and limits

The bounded models and enumerator are supporting evidence; the general result
rests on the role-switch proof. R3 is **UPHELD**, so M12 closes as
`PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`. Only `PASS_CONSTRUCTION` could unlock
M13-M18. The target maximal protocol and headline remain unauthorized until
the owner explicitly changes at least one required property or permits and
names a stronger assumption.
