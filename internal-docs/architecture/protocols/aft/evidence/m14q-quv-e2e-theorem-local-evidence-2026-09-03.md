# M14Q QUV end-to-end theorem local evidence

Status: local theorem/composition evidence; M17Q independent review remains
release-blocking.

Date: 2026-09-03.

## Result

The M14Q theorem surface in
`specs/query_unanimity_end_to_end_theorems.md` lifts M13Q accepted-value
uniqueness through:

- next-slot, exact-predecessor durable histories;
- restart from a non-rollback durable head;
- executor-side QUV immediately before the T10 claim-before-call state; and
- live-overlap reconfiguration in which every correct new member verifies the
  handoff online against every correct old member before old-root expiry.

The resulting histories are prefix compatible and cannot authorize different
mutation candidates for one rooted slot. T10 plus the stable slot-derived
idempotency key gives at-most-once modeled external-resource mutation.

The handoff result is deliberately not portable. A client joining after old-
root expiry still needs an independently provisioned current root; historical
transcript bytes cannot prove the QUV timing fact.

## Reproduction

Command:

```text
bash .github/scripts/run_aft_formal_checks.sh --quv-theorem-only
```

Result:

```text
census OK: 46 modules = 33 executed + 13 manifest-marked (manual)
QueryUnanimityProof.tla: All 75 obligations proved.
QueryUnanimityCompositionProof.tla: All 16 obligations proved.
```

The existing T10 kernel was also reproduced directly:

```text
AtMostOnceExternalization.tla: 66 states generated, 42 distinct, depth 8;
no error found.
```

Pre-commit artifact hashes:

```text
436e7f4a318384b1edf2b6b902c3009f07f718fd772256f9b3aab2b7943d0d2f  formal/maximal_visibility/QueryUnanimityCompositionProof.tla
5d797d48edd0791b91b5fa640b7842895fe14f85ed895d257caf9c89404969e3  specs/query_unanimity_end_to_end_theorems.md
40f71146dbd28b6d84d4348ad43d9c7bc934089e579e959bc8339af78f927315  formal/consequence/AtMostOnceExternalization.tla
```

## Gate effect

This closes M14Q locally and opens M15Q implementation. It does not establish
production timing/capacity, process-level durability, portable finality, or a
classical exact-decision Byzantine-agreement claim. M16Q qualification and
M17Q independent review remain mandatory before M18Q admission.
