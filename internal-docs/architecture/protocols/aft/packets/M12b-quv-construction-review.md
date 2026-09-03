# M12b QUV construction-review commission

Status: commissioning packet; exact tag fields are populated at candidate
freeze. Review is automated under ADR 0049 and must not be represented as human
peer review or external certification.

## Candidate identity

```text
tag: aft-quv-v0-construction-candidate-2026-09-03
tag_object: resolve from the annotated tag at commissioning time
commit: resolve by dereferencing that exact tag at commissioning time
```

The reviewer must clone or detach at the exact annotated tag, record the
resolved tag object and commit, and refuse to review a mutable branch head.
The commit cannot contain its own future hash, so the commissioning record and
annotated tag provide the self-reference-free binding.

## Required reading

- `docs/decisions/0050-split-aft-m12-offline-and-interactive-visibility.md`
- `internal-docs/architecture/protocols/aft/specs/maximal_consensus_task.md`
- `internal-docs/architecture/protocols/aft/specs/maximal_visibility_viability.md`
- `internal-docs/architecture/protocols/aft/specs/query_unanimity_verification.md`
- `internal-docs/architecture/protocols/aft/formal/maximal_visibility/quv_timed_model_r3.py`
- `internal-docs/architecture/protocols/aft/formal/maximal_visibility/quv_timed_results_r3.json`
- `internal-docs/architecture/protocols/aft/evidence/m12b-quv-r3-local-evidence-2026-09-03.md`
- ADRs 0041, 0048, and 0049

## Required reproduction

```text
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/run_aft_formal_checks.sh --maximal-visibility-only
bash .github/scripts/run_aft_formal_checks.sh --quv-only
```

The review must compare regenerated QUV JSON structurally to the committed
expectation and report runtime, environment, and artifact hashes.

## Adversarial questions

The reviewer must try to defeat, not merely restate, the candidate:

1. Is the arbitrary-`n` serialization argument valid with multiple correct
   members processing concurrent candidates in different orders?
2. Does the verifier wait rule necessarily include a correct response, or does
   it smuggle in a trusted delivery assertion, correct-member oracle, or
   unmodeled clock?
3. Are request delivery, queueing/admission, durable I/O, response delivery,
   and clock error all charged inside the safety-critical bound?
4. Can authenticated Byzantine flooding prevent the correct member from
   satisfying that bound while remaining inside the declared adversary model?
5. Can a reply be signed before persistence, rolled back after restart, served
   from a stale replica, or garbage-collected while authority remains live?
6. Do nonce, configuration, network, domain, slot, predecessor, authority mode,
   candidate, and snapshot bindings prevent every cross-context replay?
7. Can two executors accept conflicts if an owner equivocates before, during,
   or after either verification operation?
8. Is the unowned first-winner rule safe with multiple correct members and
   honestly described as vetoable rather than fair/live under conflict?
9. Can QUV be called Byzantine consensus under the M11 task, or only an online
   per-slot authorization primitive pending M13Q?
10. Does any receipt, cached transcript, recovery path, reconfiguration, or
    long-range verifier accidentally claim portable finality?
11. Are the Python search reductions sound, the state space complete as
    described, and mutation expectations non-vacuous?
12. Does QUV remain participant-only and relay-free when deployed, including
    routing, membership discovery, and executor connectivity?

The reviewer should add countermodels, mutations, or proof obligations wherever
the supplied set is incomplete.

## Required disposition

Return exactly one principal disposition:

- `PASS_CONSTRUCTION` — the construction and its exact assumptions survive,
  permitting M13Q theorem work;
- `REPAIR_REQUIRED` — findings are specific and remediable; or
- `REJECT_CONSTRUCTION` — a counterexample defeats the proposed class or the
  required assumptions contradict the stated target.

Every finding must have an ID, severity, affected assumption/theorem, evidence,
and required repair. A pass admits only M12b; it does not complete M13Q-M18Q or
authorize a production/public consensus claim.
